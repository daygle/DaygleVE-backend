//! Long-lived API tokens for programmatic access.
//!
//! Unlike the in-memory session tokens the auth service mints at login, API
//! tokens are persisted (JSON store) and survive restarts, so automation can
//! authenticate without a password. Each token is owned by a user and carries a
//! subset of that user's effective permissions — it can never grant more.
//!
//! The raw secret is shown once at creation and never stored: only its
//! SHA-256 is kept, so a leaked store cannot be replayed as bearer tokens. The
//! token is formatted `dgv_<64 hex chars>`; the `dgv_` prefix lets the auth
//! extractor route it to [`AcmeService`](super::acme)-style verification here
//! instead of the session table.

use std::sync::Arc;

use chrono::{Duration, Utc};
use daygleve_schema::api_token::{ApiToken, CreateApiTokenRequest};
use daygleve_schema::auth::Permission;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::store::JsonStore;
use crate::services::{new_id, now_ts};

/// Prefix every raw API token carries, so the auth layer can tell an API token
/// apart from a session token by inspection.
pub const TOKEN_PREFIX: &str = "dgv_";

/// A stored API token. The secret itself is never persisted — only its hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredApiToken {
    id: String,
    name: String,
    prefix: String,
    token_sha256: String,
    user_id: String,
    owner: String,
    permissions: Vec<Permission>,
    created_at: String,
    expires_at: Option<String>,
    last_used_at: Option<String>,
}

impl StoredApiToken {
    fn view(&self) -> ApiToken {
        ApiToken {
            id: self.id.clone(),
            name: self.name.clone(),
            prefix: self.prefix.clone(),
            permissions: self.permissions.clone(),
            owner: self.owner.clone(),
            created_at: self.created_at.clone(),
            expires_at: self.expires_at.clone(),
            last_used_at: self.last_used_at.clone(),
        }
    }

    fn is_expired(&self) -> bool {
        is_expired(self.expires_at.as_deref(), Utc::now())
    }
}

/// The identity a valid API token resolves to.
pub struct TokenAuth {
    pub user_id: String,
    pub permissions: Vec<Permission>,
}

/// Manages creation, listing, revocation and verification of API tokens.
pub struct ApiTokenService {
    store: JsonStore,
}

impl ApiTokenService {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            store: JsonStore::new(&config.state_dir, "api_tokens"),
        }
    }

    /// Create a token owned by `user_id`/`owner`, granting a subset of
    /// `owner_permissions`. Returns the raw secret (shown once) and the stored
    /// metadata view.
    pub async fn create(
        &self,
        user_id: &str,
        owner: &str,
        owner_permissions: &[Permission],
        req: CreateApiTokenRequest,
    ) -> ApiResult<(String, ApiToken)> {
        let name = req.name.trim();
        if name.is_empty() || name.len() > 64 || name.chars().any(|c| c.is_control()) {
            return Err(AppError::validation(
                "token name must be 1..=64 characters with no control characters",
            ));
        }

        // Scope the grant: empty means "all of mine"; otherwise every requested
        // permission must be one the caller already holds (no escalation).
        let permissions = if req.permissions.is_empty() {
            owner_permissions.to_vec()
        } else {
            for p in &req.permissions {
                if !owner_permissions.contains(p) {
                    return Err(AppError::forbidden(format!(
                        "cannot grant a permission you do not hold: {p:?}"
                    )));
                }
            }
            req.permissions.clone()
        };

        let expires_at = match req.expires_in_days {
            Some(0) => return Err(AppError::validation("expires_in_days must be >= 1")),
            Some(days) => Some((Utc::now() + Duration::days(days as i64)).to_rfc3339()),
            None => None,
        };

        let secret = mint_secret();
        let token = format!("{TOKEN_PREFIX}{secret}");
        let record = StoredApiToken {
            id: new_id(),
            name: name.to_string(),
            // Display prefix: the marker plus the first 8 secret chars.
            prefix: format!("{TOKEN_PREFIX}{}", &secret[..8]),
            token_sha256: sha256_hex(&token),
            user_id: user_id.to_string(),
            owner: owner.to_string(),
            permissions,
            created_at: now_ts(),
            expires_at,
            last_used_at: None,
        };
        self.store.put(&record.id, &record).await?;
        Ok((token, record.view()))
    }

    /// The tokens owned by `user_id`, newest first.
    pub async fn list_for(&self, user_id: &str) -> ApiResult<Vec<ApiToken>> {
        let mut tokens: Vec<StoredApiToken> = self.store.list().await?;
        tokens.retain(|t| t.user_id == user_id);
        tokens.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(tokens.iter().map(StoredApiToken::view).collect())
    }

    /// Revoke a token by id. Only the owner may delete their own token; a
    /// mismatched owner is reported as not-found so ids do not leak.
    pub async fn delete(&self, user_id: &str, id: &str) -> ApiResult<()> {
        match self.store.get::<StoredApiToken>(id).await? {
            Some(token) if token.user_id == user_id => {
                self.store.delete(id).await?;
                Ok(())
            }
            _ => Err(AppError::not_found("no such API token")),
        }
    }

    /// Verify a raw bearer token. Returns the identity it grants, or `None` when
    /// the token is unknown or expired. Best-effort refreshes `last_used_at`.
    pub async fn authenticate(&self, token: &str) -> Option<TokenAuth> {
        if !token.starts_with(TOKEN_PREFIX) {
            return None;
        }
        let hash = sha256_hex(token);
        let tokens: Vec<StoredApiToken> = self.store.list().await.ok()?;
        let record = tokens.into_iter().find(|t| t.token_sha256 == hash)?;
        if record.is_expired() {
            return None;
        }
        self.touch_last_used(&record).await;
        Some(TokenAuth {
            user_id: record.user_id.clone(),
            permissions: record.permissions.clone(),
        })
    }

    /// Update `last_used_at`, but at most once per hour per token, to bound
    /// write amplification on hot automation paths.
    async fn touch_last_used(&self, record: &StoredApiToken) {
        let now = Utc::now();
        let fresh = record.last_used_at.as_deref().is_some_and(|ts| {
            chrono::DateTime::parse_from_rfc3339(ts)
                .map(|prev| now.signed_duration_since(prev) < Duration::hours(1))
                .unwrap_or(false)
        });
        if fresh {
            return;
        }
        let mut updated = record.clone();
        updated.last_used_at = Some(now.to_rfc3339());
        // Best-effort: a failed refresh must never fail the request.
        let _ = self.store.put(&updated.id, &updated).await;
    }
}

/// A fresh 64-hex-char secret (32 bytes of OS randomness).
fn mint_secret() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Whether a token with the given optional RFC-3339 expiry is expired at `now`.
/// An unparseable expiry is treated as expired (fail closed).
fn is_expired(expires_at: Option<&str>, now: chrono::DateTime<Utc>) -> bool {
    match expires_at {
        None => false,
        Some(ts) => match chrono::DateTime::parse_from_rfc3339(ts) {
            Ok(exp) => exp.with_timezone(&Utc) <= now,
            Err(_) => true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use daygleve_schema::auth::Permission::*;

    fn svc() -> ApiTokenService {
        let dir = std::env::temp_dir().join(format!("daygleve-apitok-{}", new_id()));
        let config = Config {
            state_dir: dir,
            ..crate::config::Config::from_env()
        };
        ApiTokenService::new(Arc::new(config))
    }

    #[tokio::test]
    async fn create_scopes_permissions_and_hides_the_secret() {
        let s = svc();
        let owner_perms = vec![VmRead, VmWrite, StorageRead];
        // Empty request grants all of the owner's permissions.
        let (token, view) = s
            .create(
                "u1",
                "alice",
                &owner_perms,
                CreateApiTokenRequest {
                    name: "ci".to_string(),
                    permissions: vec![],
                    expires_in_days: None,
                },
            )
            .await
            .unwrap();
        assert!(token.starts_with(TOKEN_PREFIX));
        assert_eq!(view.permissions, owner_perms);
        assert!(view.prefix.starts_with(TOKEN_PREFIX));
        assert!(view.expires_at.is_none());

        // A subset is honored.
        let (_, view) = s
            .create(
                "u1",
                "alice",
                &owner_perms,
                CreateApiTokenRequest {
                    name: "read-only".to_string(),
                    permissions: vec![VmRead],
                    expires_in_days: Some(30),
                },
            )
            .await
            .unwrap();
        assert_eq!(view.permissions, vec![VmRead]);
        assert!(view.expires_at.is_some());

        // Escalation beyond the owner's permissions is rejected.
        let err = s
            .create(
                "u1",
                "alice",
                &owner_perms,
                CreateApiTokenRequest {
                    name: "escalate".to_string(),
                    permissions: vec![UserAdmin],
                    expires_in_days: None,
                },
            )
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn authenticate_matches_and_scopes_to_owner() {
        let s = svc();
        let (token, _) = s
            .create(
                "u1",
                "alice",
                &[VmRead, VmWrite],
                CreateApiTokenRequest {
                    name: "ci".to_string(),
                    permissions: vec![VmRead],
                    expires_in_days: None,
                },
            )
            .await
            .unwrap();

        let auth = s.authenticate(&token).await.expect("valid token");
        assert_eq!(auth.user_id, "u1");
        assert_eq!(auth.permissions, vec![VmRead]);

        // Wrong secret and non-prefixed tokens do not authenticate.
        assert!(s.authenticate("dgv_deadbeef").await.is_none());
        assert!(s.authenticate("session-style-token").await.is_none());
    }

    #[tokio::test]
    async fn delete_is_owner_scoped() {
        let s = svc();
        let (_, view) = s
            .create(
                "u1",
                "alice",
                &[VmRead],
                CreateApiTokenRequest {
                    name: "ci".to_string(),
                    permissions: vec![],
                    expires_in_days: None,
                },
            )
            .await
            .unwrap();
        // A different user cannot delete it.
        assert!(s.delete("u2", &view.id).await.is_err());
        assert_eq!(s.list_for("u1").await.unwrap().len(), 1);
        // The owner can.
        assert!(s.delete("u1", &view.id).await.is_ok());
        assert!(s.list_for("u1").await.unwrap().is_empty());
    }

    #[test]
    fn expiry_check_fails_closed() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(!is_expired(None, now));
        assert!(!is_expired(Some("2026-12-01T00:00:00Z"), now));
        assert!(is_expired(Some("2026-01-01T00:00:00Z"), now));
        assert!(is_expired(Some("garbage"), now));
    }
}
