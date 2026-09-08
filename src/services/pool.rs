//! Resource pools: named, lightweight groupings of guests.
//!
//! A pool is pure metadata — a name and an optional comment — persisted as a
//! JSON record. Membership is not stored here; each guest carries an optional
//! `pool` naming the pool it belongs to, so this service never mutates guests.
//! The pool name is the stable identifier and is immutable once created;
//! updates change only the comment. Deleting a pool that still has members is
//! rejected at the API layer, which is where guests are enumerable.

use std::sync::Arc;

use daygleve_schema::pool::{CreateResourcePoolRequest, ResourcePool, UpdateResourcePoolRequest};

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::store::JsonStore;
use crate::services::{new_id, now_ts, validate_pool_name};

pub struct PoolService {
    store: JsonStore,
}

impl PoolService {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            store: JsonStore::new(&config.state_dir, "pools"),
        }
    }

    /// All pool records, sorted by name for stable listing.
    pub async fn list(&self) -> ApiResult<Vec<ResourcePool>> {
        let mut pools: Vec<ResourcePool> = self.store.list().await?;
        pools.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(pools)
    }

    /// Fetch a pool by id, or 404.
    pub async fn get(&self, id: &str) -> ApiResult<ResourcePool> {
        self.store
            .get(id)
            .await?
            .ok_or_else(|| AppError::not_found(format!("pool {id}")))
    }

    /// Whether a pool with this (trimmed) name exists.
    pub async fn exists(&self, name: &str) -> ApiResult<bool> {
        let name = name.trim();
        Ok(self.list().await?.iter().any(|p| p.name == name))
    }

    /// Error unless a pool with this name exists. Used to vet a guest's pool
    /// assignment before it is persisted.
    pub async fn ensure_exists(&self, name: &str) -> ApiResult<()> {
        if self.exists(name).await? {
            Ok(())
        } else {
            Err(AppError::validation(format!(
                "resource pool {:?} does not exist",
                name.trim()
            )))
        }
    }

    /// Create a pool. The name is validated and must be unique.
    pub async fn create(&self, req: CreateResourcePoolRequest) -> ApiResult<ResourcePool> {
        let name = validate_pool_name(&req.name)?;
        if self.exists(&name).await? {
            return Err(AppError::conflict(format!(
                "resource pool {name:?} already exists"
            )));
        }
        let pool = ResourcePool {
            id: new_id(),
            name,
            comment: normalize_comment(req.comment),
            created_at: now_ts(),
            updated_at: None,
        };
        self.store.put(&pool.id, &pool).await?;
        Ok(pool)
    }

    /// Update a pool's comment. The name is immutable and cannot be changed.
    pub async fn update(
        &self,
        id: &str,
        req: UpdateResourcePoolRequest,
    ) -> ApiResult<ResourcePool> {
        let mut pool = self.get(id).await?;
        if let Some(comment) = req.comment {
            pool.comment = normalize_comment(Some(comment));
        }
        pool.updated_at = Some(now_ts());
        self.store.put(&pool.id, &pool).await?;
        Ok(pool)
    }

    /// Delete a pool, returning the removed record (so the caller can name it).
    /// The caller is responsible for confirming the pool has no members first.
    pub async fn delete(&self, id: &str) -> ApiResult<ResourcePool> {
        let pool = self.get(id).await?;
        self.store.delete(id).await?;
        Ok(pool)
    }
}

/// Trim a comment and drop it entirely when empty; cap its length.
fn normalize_comment(comment: Option<String>) -> Option<String> {
    comment
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
        .map(|c| c.chars().take(1024).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use daygleve_schema::pool::{CreateResourcePoolRequest, UpdateResourcePoolRequest};

    fn svc() -> PoolService {
        let dir = std::env::temp_dir().join(format!("daygleve-pool-test-{}", new_id()));
        let config = Arc::new(Config {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            cors_origins: vec![],
            default_pool: "tank".into(),
            web_root: None,
            state_dir: dir.clone(),
            iso_dir: dir.join("isos"),
            template_dir: dir.join("templates"),
            mounts_dir: dir.join("mounts"),
            max_upload_bytes: 16 * 1024 * 1024 * 1024,
            spice_listen: "127.0.0.1".to_string(),
            backup_dir: dir.join("backups"),
            token_ttl_secs: 3600,
            admin_password: None,
            tls_cert: None,
            tls_key: None,
            broker_socket: None,
        });
        PoolService::new(config)
    }

    #[tokio::test]
    async fn create_get_and_reject_duplicate() {
        let s = svc();
        let created = s
            .create(CreateResourcePoolRequest {
                name: "  prod ".to_string(),
                comment: Some("  production guests  ".to_string()),
            })
            .await
            .unwrap();
        // Name is trimmed; comment is trimmed.
        assert_eq!(created.name, "prod");
        assert_eq!(created.comment.as_deref(), Some("production guests"));

        let fetched = s.get(&created.id).await.unwrap();
        assert_eq!(fetched.name, "prod");
        assert!(s.exists("prod").await.unwrap());
        assert!(s.ensure_exists("prod").await.is_ok());
        assert!(s.ensure_exists("staging").await.is_err());

        // Duplicate (post-trim) name is a conflict.
        let dup = s
            .create(CreateResourcePoolRequest {
                name: "prod".to_string(),
                comment: None,
            })
            .await;
        assert!(dup.is_err());
    }

    #[tokio::test]
    async fn rejects_invalid_name() {
        let s = svc();
        assert!(s
            .create(CreateResourcePoolRequest {
                name: "bad name!".to_string(),
                comment: None,
            })
            .await
            .is_err());
        assert!(s
            .create(CreateResourcePoolRequest {
                name: "   ".to_string(),
                comment: None,
            })
            .await
            .is_err());
    }

    #[tokio::test]
    async fn update_changes_comment_only() {
        let s = svc();
        let p = s
            .create(CreateResourcePoolRequest {
                name: "web".to_string(),
                comment: Some("old".to_string()),
            })
            .await
            .unwrap();
        let updated = s
            .update(
                &p.id,
                UpdateResourcePoolRequest {
                    comment: Some("  ".to_string()),
                },
            )
            .await
            .unwrap();
        // Whitespace comment clears it; name is unchanged.
        assert_eq!(updated.name, "web");
        assert_eq!(updated.comment, None);
        assert!(updated.updated_at.is_some());
    }

    #[tokio::test]
    async fn delete_removes_record() {
        let s = svc();
        let p = s
            .create(CreateResourcePoolRequest {
                name: "gone".to_string(),
                comment: None,
            })
            .await
            .unwrap();
        let removed = s.delete(&p.id).await.unwrap();
        assert_eq!(removed.name, "gone");
        assert!(s.get(&p.id).await.is_err());
    }
}
