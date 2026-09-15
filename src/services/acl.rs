//! Path-scoped access control (ACL).
//!
//! Holds the explicit [`AclEntry`] grants (path → role for a user) and resolves
//! a caller's effective permissions *at a path*. A user's own
//! [`roles`](daygleve_schema::auth::User::roles) are treated as an implicit
//! grant at the root path `/`, so today's node-wide roles are just the root
//! scope of the same model; explicit entries add scoped grants below it.
//!
//! Entries are persisted (one JSON record each) and cached in memory for the
//! hot authentication path, mirroring [`crate::services::auth::AuthService`].

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

use daygleve_schema::auth::{Permission, Role};
use daygleve_schema::rbac::{AclEntry, PathGrant};

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::auth::effective_permissions;
use crate::services::store::JsonStore;
use crate::services::{new_id, now_ts};

pub struct AclService {
    store: JsonStore,
    entries: RwLock<HashMap<String, AclEntry>>,
    /// Serializes create/delete so a check-then-write stays consistent.
    mutate: tokio::sync::Mutex<()>,
}

impl AclService {
    pub fn new(config: Arc<Config>) -> Self {
        let store = JsonStore::new(&config.state_dir, "acl");
        Self {
            store,
            entries: RwLock::new(HashMap::new()),
            mutate: tokio::sync::Mutex::new(()),
        }
    }

    /// Load persisted entries into the cache. Called once at startup.
    pub async fn load(&self) -> ApiResult<()> {
        let existing: Vec<AclEntry> = self.store.list().await?;
        let mut cache = self.entries.write().expect("acl lock");
        for entry in existing {
            cache.insert(entry.id.clone(), entry);
        }
        Ok(())
    }

    /// Every entry, ordered by path then id for stable listing.
    pub fn list(&self) -> Vec<AclEntry> {
        let mut entries: Vec<AclEntry> = self
            .entries
            .read()
            .expect("acl lock")
            .values()
            .cloned()
            .collect();
        entries.sort_by(|a, b| a.path.cmp(&b.path).then(a.id.cmp(&b.id)));
        entries
    }

    /// The explicit entries granted to one user.
    pub fn entries_for_subject(&self, user_id: &str) -> Vec<AclEntry> {
        self.entries
            .read()
            .expect("acl lock")
            .values()
            .filter(|e| e.subject == user_id)
            .cloned()
            .collect()
    }

    /// Create an ACL entry. `path` is normalized; the role is granted to
    /// `subject` (whose username is captured for display).
    pub async fn create(
        &self,
        path: &str,
        subject: &str,
        subject_username: &str,
        role: Role,
        propagate: bool,
    ) -> ApiResult<AclEntry> {
        let path = normalize_path(path)?;
        let _guard = self.mutate.lock().await;
        // Collapse an exact duplicate (same subject/path/role/propagate) instead
        // of piling up identical grants.
        if let Some(existing) = self.entries.read().expect("acl lock").values().find(|e| {
            e.subject == subject && e.path == path && e.role == role && e.propagate == propagate
        }) {
            return Ok(existing.clone());
        }
        let entry = AclEntry {
            id: new_id(),
            path,
            subject: subject.to_string(),
            role,
            propagate,
            subject_username: Some(subject_username.to_string()),
            created_at: now_ts(),
        };
        self.store.put(&entry.id, &entry).await?;
        self.entries
            .write()
            .expect("acl lock")
            .insert(entry.id.clone(), entry.clone());
        Ok(entry)
    }

    /// Delete an ACL entry by id.
    pub async fn delete(&self, id: &str) -> ApiResult<()> {
        let _guard = self.mutate.lock().await;
        if !self.entries.read().expect("acl lock").contains_key(id) {
            return Err(AppError::not_found("acl entry not found"));
        }
        self.store.delete(id).await?;
        self.entries.write().expect("acl lock").remove(id);
        Ok(())
    }

    /// Remove every entry for a user (called when the account is deleted so no
    /// dangling grants remain).
    pub async fn remove_subject(&self, user_id: &str) -> ApiResult<()> {
        let _guard = self.mutate.lock().await;
        let ids: Vec<String> = self
            .entries
            .read()
            .expect("acl lock")
            .values()
            .filter(|e| e.subject == user_id)
            .map(|e| e.id.clone())
            .collect();
        for id in &ids {
            self.store.delete(id).await?;
        }
        let mut cache = self.entries.write().expect("acl lock");
        for id in &ids {
            cache.remove(id);
        }
        Ok(())
    }
}

/// The caller's effective path grants: an implicit root grant per role the user
/// holds, plus every explicit entry granted to them.
pub fn grants_for(user_roles: &[Role], entries: &[AclEntry]) -> Vec<PathGrant> {
    let mut grants: Vec<PathGrant> = user_roles
        .iter()
        .map(|role| PathGrant {
            path: "/".to_string(),
            role: *role,
            propagate: true,
        })
        .collect();
    grants.extend(entries.iter().map(|e| PathGrant {
        path: e.path.clone(),
        role: e.role,
        propagate: e.propagate,
    }));
    grants
}

/// Whether a grant on `grant_path` covers `target` given its `propagate` flag.
pub fn path_covers(grant_path: &str, target: &str, propagate: bool) -> bool {
    if grant_path == target {
        return true;
    }
    if !propagate {
        return false;
    }
    if grant_path == "/" {
        return true;
    }
    // Ancestor match on a path boundary, so `/vms` covers `/vms/1` but not
    // `/vms-other`.
    target.starts_with(&format!("{grant_path}/"))
}

/// The permission set the caller holds at `path`: the roles from every grant
/// that covers the path, mapped through the role→permission table.
pub fn effective_permissions_at(grants: &[PathGrant], path: &str) -> Vec<Permission> {
    let mut roles: Vec<Role> = Vec::new();
    for g in grants {
        if path_covers(&g.path, path, g.propagate) && !roles.contains(&g.role) {
            roles.push(g.role);
        }
    }
    effective_permissions(&roles)
}

/// Normalize and validate a resource path: ensure a single leading `/`, trim a
/// trailing `/` (except root), and reject traversal or control characters.
pub fn normalize_path(path: &str) -> ApiResult<String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(AppError::validation("path must not be empty"));
    }
    let with_root = if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    };
    // Collapse a trailing slash (but keep the bare root).
    let normalized = if with_root.len() > 1 {
        with_root.trim_end_matches('/').to_string()
    } else {
        with_root
    };
    if normalized.is_empty() {
        return Err(AppError::validation("path must not be empty"));
    }
    // The bare root has no segments to check.
    if normalized == "/" {
        return Ok(normalized);
    }
    for segment in normalized.split('/').skip(1) {
        if segment.is_empty() {
            return Err(AppError::validation("path must not contain empty segments"));
        }
        if segment == "." || segment == ".." {
            return Err(AppError::validation(
                "path must not contain . or .. segments",
            ));
        }
        if segment.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(AppError::validation(
                "path must not contain control characters or whitespace",
            ));
        }
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, role: Role, propagate: bool) -> AclEntry {
        AclEntry {
            id: new_id(),
            path: path.to_string(),
            subject: "u1".to_string(),
            role,
            propagate,
            subject_username: None,
            created_at: now_ts(),
        }
    }

    #[test]
    fn path_covers_rules() {
        assert!(path_covers("/", "/vms/1", true));
        assert!(path_covers("/vms", "/vms/1", true));
        assert!(path_covers("/vms", "/vms", true));
        assert!(!path_covers("/vms", "/vms/1", false));
        assert!(path_covers("/vms", "/vms", false));
        // Boundary: no substring false-positives.
        assert!(!path_covers("/vms", "/vms-other", true));
        assert!(!path_covers("/vms/1", "/vms", true));
    }

    #[test]
    fn root_roles_grant_everywhere() {
        let grants = grants_for(&[Role::Operator], &[]);
        let at_root = effective_permissions_at(&grants, "/");
        let at_vm = effective_permissions_at(&grants, "/vms/1");
        assert!(at_root.contains(&Permission::VmWrite));
        assert!(at_vm.contains(&Permission::VmWrite));
    }

    #[test]
    fn scoped_only_user_has_no_root_access() {
        // No root roles; a single scoped grant at /vms/1.
        let entries = vec![entry("/vms/1", Role::Operator, true)];
        let grants = grants_for(&[], &entries);
        assert!(effective_permissions_at(&grants, "/vms/1").contains(&Permission::VmWrite));
        // Nothing at the root or a sibling.
        assert!(effective_permissions_at(&grants, "/").is_empty());
        assert!(effective_permissions_at(&grants, "/vms/2").is_empty());
        assert!(effective_permissions_at(&grants, "/vms").is_empty());
    }

    #[test]
    fn viewer_at_collection_reads_but_not_writes() {
        let entries = vec![entry("/vms", Role::Viewer, true)];
        let grants = grants_for(&[], &entries);
        let at_item = effective_permissions_at(&grants, "/vms/9");
        assert!(at_item.contains(&Permission::VmRead));
        assert!(!at_item.contains(&Permission::VmWrite));
    }

    #[test]
    fn normalize_path_forms() {
        assert_eq!(normalize_path("/").unwrap(), "/");
        assert_eq!(normalize_path("vms").unwrap(), "/vms");
        assert_eq!(normalize_path("/vms/").unwrap(), "/vms");
        assert_eq!(normalize_path("/pools/prod/").unwrap(), "/pools/prod");
        assert!(normalize_path("").is_err());
        assert!(normalize_path("/vms/../etc").is_err());
        assert!(normalize_path("/vms//1").is_err());
        assert!(normalize_path("/vms/ a").is_err());
    }
}
