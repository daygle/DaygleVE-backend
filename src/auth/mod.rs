//! Request-time authentication & RBAC enforcement.
//!
//! [`AuthUser`] is an Axum extractor: any handler that names it in its
//! signature is guaranteed an authenticated caller. Permissions are resolved
//! per resource **path**: [`AuthUser::require_at`] checks a permission at a
//! given path (e.g. `/vms/abc`), and [`AuthUser::require`] is the node-scoped
//! shorthand for the root path `/`.
//!
//! A session caller carries its path-scoped grants (root roles plus explicit
//! ACL entries); an API-token caller carries a flat, node-wide permission set
//! (its owner-scoped subset) that the path does not narrow in this version.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use daygleve_schema::auth::{CurrentUser, Permission};

use crate::error::AppError;
use crate::services::acl::{effective_permissions_at, grants_for};
use crate::state::AppState;

/// An authenticated caller, extracted from the `Authorization: Bearer` header.
///
/// Fields: the resolved [`CurrentUser`], the bearer token, and the request's
/// **resource path** (derived from the URI, e.g. `/vms/abc`) that [`require`]
/// checks against by default.
#[derive(Clone)]
pub struct AuthUser(pub CurrentUser, pub(crate) String, pub(crate) String);

impl std::fmt::Debug for AuthUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthUser")
            .field("user", &self.0.user)
            .field("permissions", &self.0.permissions)
            .field("must_change_password", &self.0.must_change_password)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl AuthUser {
    /// Enforce that the caller holds `permission` at the **request's resource
    /// path** — derived from the URI (`/vms/{id}`, `/pools`, …), or `/` for
    /// node-scoped endpoints. This makes every existing `require` call
    /// path-aware without the handler passing a path explicitly; use
    /// [`require_at`](Self::require_at) to check a different path.
    pub fn require(&self, permission: Permission) -> Result<(), AppError> {
        self.require_at(permission, &self.2)
    }

    /// Enforce that the caller holds `permission` at `path`, else `403`. A
    /// session caller is resolved through its path-scoped grants; a grant-less
    /// caller (an API token) falls back to its flat, node-wide permission set.
    pub fn require_at(&self, permission: Permission, path: &str) -> Result<(), AppError> {
        let held = if self.0.grants.is_empty() {
            // API tokens carry a flat owner-scoped permission set; the path does
            // not narrow them in this version.
            self.0.permissions.contains(&permission)
        } else {
            effective_permissions_at(&self.0.grants, path).contains(&permission)
        };
        if held {
            Ok(())
        } else {
            Err(AppError::forbidden(format!(
                "missing permission {permission:?} at {path}"
            )))
        }
    }
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| AppError::unauthorized("missing bearer token"))?;

        // An API token (prefixed) resolves to its owner with the token's granted
        // permissions; anything else is a session token. API tokens never carry
        // the must-change-password gate — they are non-interactive.
        let current = if token.starts_with(crate::services::api_token::TOKEN_PREFIX) {
            let auth = state
                .services
                .api_tokens
                .authenticate(token)
                .await
                .ok_or_else(|| AppError::unauthorized("invalid or expired token"))?;
            let user = state
                .services
                .auth
                .user_by_id(&auth.user_id)
                .ok_or_else(|| AppError::unauthorized("token owner no longer exists"))?;
            CurrentUser {
                user,
                permissions: auth.permissions,
                must_change_password: false,
                // The second factor gates the interactive password login, not
                // API-token auth; surface the token owner's enrollment state
                // for display only.
                two_factor_enabled: state.services.auth.two_factor_enabled(&auth.user_id),
                // API-token callers use their flat permission set, not path
                // grants; leave grants empty so require_at falls back to it.
                grants: Vec::new(),
            }
        } else {
            // Session caller: enrich with path-scoped ACL grants and recompute
            // the effective (root-scope) permission set from them.
            let mut current = state.services.auth.authenticate(token)?;
            let entries = state.services.acl.entries_for_subject(&current.user.id);
            let grants = grants_for(&current.user.roles, &entries);
            current.permissions = effective_permissions_at(&grants, "/");
            current.grants = grants;
            current
        };
        let path = parts.uri.path();
        if current.must_change_password
            && !path.ends_with("/auth/me")
            && !path.ends_with("/auth/change-password")
            && !path.ends_with("/auth/logout")
        {
            return Err(AppError::forbidden(
                "change the initial password before using the control plane",
            ));
        }
        let resource_path = resource_path_for(path);
        Ok(AuthUser(current, token.to_string(), resource_path))
    }
}

/// Map a request URI path to the ACL resource path `require` checks against.
///
/// Scoped resources collapse to their item (or collection) path so a grant on
/// one VM/container/pool governs all of its sub-resources: `/vms/abc/power` and
/// `/vms/abc/snapshots/x` both resolve to `/vms/abc`. Every other endpoint is
/// node-scoped and resolves to the root `/`, where only a root grant (a
/// node-wide role) satisfies it. Unknown shapes fall back to `/`, which fails
/// safe — it can only deny a scoped-only caller, never widen access.
fn resource_path_for(uri_path: &str) -> String {
    // The extractor may see the path with or without the `/api/<version>` nest
    // prefix depending on routing; strip it when present.
    let mut p = uri_path;
    if let Some(rest) = p.strip_prefix("/api/") {
        p = rest
            .split_once('/')
            .map(|(_ver, after)| after)
            .unwrap_or("");
    }
    let segs: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
    match segs.as_slice() {
        ["vms", id, ..] => format!("/vms/{id}"),
        ["containers", id, ..] => format!("/containers/{id}"),
        ["pools", id, ..] => format!("/pools/{id}"),
        ["vms"] => "/vms".to_string(),
        ["containers"] => "/containers".to_string(),
        ["pools"] => "/pools".to_string(),
        _ => "/".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::resource_path_for;

    #[test]
    fn maps_scoped_and_node_paths() {
        // With and without the nest prefix.
        assert_eq!(resource_path_for("/api/v1/vms"), "/vms");
        assert_eq!(resource_path_for("/api/v1/vms/abc"), "/vms/abc");
        assert_eq!(resource_path_for("/vms/abc/power"), "/vms/abc");
        assert_eq!(
            resource_path_for("/api/v1/vms/abc/snapshots/s1"),
            "/vms/abc"
        );
        assert_eq!(resource_path_for("/containers/c1"), "/containers/c1");
        assert_eq!(resource_path_for("/api/v1/pools/prod"), "/pools/prod");
        assert_eq!(resource_path_for("/pools"), "/pools");
        // Node-scoped endpoints and unknown shapes resolve to root.
        assert_eq!(resource_path_for("/api/v1/network/firewall"), "/");
        assert_eq!(resource_path_for("/api/v1/users"), "/");
        assert_eq!(resource_path_for("/api/v1/acl"), "/");
        assert_eq!(resource_path_for("/api/v1/health"), "/");
    }
}
