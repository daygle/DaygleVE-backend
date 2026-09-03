//! Authentication + RBAC service.
//!
//! Issues opaque bearer tokens and resolves them back to a [`CurrentUser`] with
//! an effective permission set. Passwords are verified with argon2; tokens are
//! random 256-bit values with a real expiry (configurable TTL).
//!
//! Users are **persisted** to the JSON record store (`<state_dir>/users`) so
//! accounts, roles and password hashes survive a restart; an in-memory cache
//! fronts them for fast, lock-only reads on the hot authentication path. Bearer
//! tokens remain in-memory by design — sessions are ephemeral, so they simply
//! reset on restart and clients re-authenticate. On first start (empty store) a
//! single `admin` account is seeded from configuration and flagged to force a
//! password change when it is still on the default password.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use chrono::{DateTime, Duration, Utc};
use daygleve_schema::auth::{
    ChangePasswordRequest, CreateUserRequest, CurrentUser, LoginRequest, LoginResponse, Permission,
    Role, UpdateUserRequest, User,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::store::JsonStore;
use crate::services::{new_id, now_ts};

/// Minimum length enforced for any password set through the API.
const MIN_PASSWORD_LEN: usize = 8;

/// A user plus its (server-only) password hash, as persisted on disk.
#[derive(Clone, Serialize, Deserialize)]
struct StoredUser {
    user: User,
    password_hash: String,
    /// True while the account is still on a seeded/temporary password.
    #[serde(default)]
    must_change_password: bool,
}

/// A live bearer-token session.
struct Session {
    user_id: String,
    expires_at: DateTime<Utc>,
}

pub struct AuthService {
    store: JsonStore,
    config: Arc<Config>,
    tokens: RwLock<HashMap<String, Session>>,
    users: RwLock<HashMap<String, StoredUser>>,
    token_ttl_secs: u64,
}

impl AuthService {
    pub fn new(config: Arc<Config>) -> Self {
        let store = JsonStore::new(&config.state_dir, "users");
        Self {
            store,
            token_ttl_secs: config.token_ttl_secs,
            config,
            tokens: RwLock::new(HashMap::new()),
            users: RwLock::new(HashMap::new()),
        }
    }

    /// Load persisted users into the in-memory cache; seed an initial admin when
    /// the store is empty (first boot). Called once at startup.
    pub async fn load_or_seed(&self) -> ApiResult<()> {
        let existing: Vec<StoredUser> = self.store.list().await?;
        if !existing.is_empty() {
            let mut cache = self.users.write().expect("user lock");
            for stored in existing {
                cache.insert(stored.user.id.clone(), stored);
            }
            return Ok(());
        }

        // First boot: seed the admin from configuration. Force a password change
        // if it is still on the built-in default.
        let password_hash = hash_password(&self.config.admin_password)
            .map_err(|e| AppError::internal(format!("failed to hash admin password: {e}")))?;
        let must_change_password = self.config.admin_password == "daygleve";
        if must_change_password {
            tracing::warn!(
                "admin seeded with the default password; you will be required to change it on first login (or set DAYGLEVE_ADMIN_PASSWORD)"
            );
        }
        let admin = StoredUser {
            user: User {
                id: new_id(),
                username: "admin".to_string(),
                roles: vec![Role::Admin],
                created_at: now_ts(),
                last_login_at: None,
            },
            password_hash,
            must_change_password,
        };
        self.store.put(&admin.user.id, &admin).await?;
        self.users
            .write()
            .expect("user lock")
            .insert(admin.user.id.clone(), admin);
        Ok(())
    }

    pub fn login(&self, req: LoginRequest) -> ApiResult<LoginResponse> {
        // Snapshot the id + hash under a read lock, then run the CPU-heavy
        // argon2 verification with no lock held, so concurrent logins aren't
        // serialized behind each other's hashing.
        let (user_id, hash) = {
            let users = self.users.read().expect("user lock");
            let stored = users
                .values()
                .find(|u| u.user.username == req.username)
                .ok_or_else(|| AppError::unauthorized("invalid credentials"))?;
            (stored.user.id.clone(), stored.password_hash.clone())
        };

        verify_password(&req.password, &hash)?;

        let now = Utc::now();
        let user = {
            let mut users = self.users.write().expect("user lock");
            let stored = users
                // A concurrent deletion between verify and here: keep the same
                // "invalid credentials" message (don't hint at the race).
                .get_mut(&user_id)
                .ok_or_else(|| AppError::unauthorized("invalid credentials"))?;
            stored.user.last_login_at = Some(now.to_rfc3339());
            stored.user.clone()
        };

        // Clamp before the i64 cast so an absurd TTL can't overflow into a
        // negative (already-expired) lifetime.
        let ttl = self.token_ttl_secs.min(i64::MAX as u64) as i64;
        let expires_at = now + Duration::seconds(ttl);
        let token = mint_token();
        self.tokens.write().expect("token lock").insert(
            token.clone(),
            Session {
                user_id: user.id.clone(),
                expires_at,
            },
        );

        Ok(LoginResponse {
            token,
            expires_at: expires_at.to_rfc3339(),
            user,
        })
    }

    /// Resolve a bearer token to the caller and their effective permissions.
    /// Expired tokens are rejected and evicted.
    pub fn authenticate(&self, token: &str) -> ApiResult<CurrentUser> {
        let user_id = {
            let tokens = self.tokens.read().expect("token lock");
            match tokens.get(token) {
                None => return Err(AppError::unauthorized("invalid or expired token")),
                Some(session) if session.expires_at <= Utc::now() => None,
                Some(session) => Some(session.user_id.clone()),
            }
        };

        let user_id = match user_id {
            Some(id) => id,
            None => {
                // Token was present but expired: evict and reject.
                self.tokens.write().expect("token lock").remove(token);
                return Err(AppError::unauthorized("invalid or expired token"));
            }
        };

        let (user, must_change_password) = self
            .users
            .read()
            .expect("user lock")
            .get(&user_id)
            .map(|s| (s.user.clone(), s.must_change_password))
            .ok_or_else(|| AppError::unauthorized("unknown user"))?;

        let permissions = effective_permissions(&user.roles);
        Ok(CurrentUser {
            user,
            permissions,
            must_change_password,
        })
    }

    /// All user accounts (without secrets), ordered by username.
    pub fn list_users(&self) -> Vec<User> {
        let mut users: Vec<User> = self
            .users
            .read()
            .expect("user lock")
            .values()
            .map(|s| s.user.clone())
            .collect();
        users.sort_by(|a, b| a.username.cmp(&b.username));
        users
    }

    /// Create a new user account.
    pub async fn create_user(&self, req: CreateUserRequest) -> ApiResult<User> {
        let username = req.username.trim();
        if username.is_empty() {
            return Err(AppError::validation("username must not be empty"));
        }
        if req.roles.is_empty() {
            return Err(AppError::validation("at least one role is required"));
        }
        if req.password.len() < MIN_PASSWORD_LEN {
            return Err(AppError::validation(format!(
                "password must be at least {MIN_PASSWORD_LEN} characters"
            )));
        }
        // Usernames are unique (case-insensitive).
        if self
            .users
            .read()
            .expect("user lock")
            .values()
            .any(|s| s.user.username.eq_ignore_ascii_case(username))
        {
            return Err(AppError::conflict("a user with that name already exists"));
        }

        let password_hash = hash_password(&req.password)
            .map_err(|e| AppError::internal(format!("failed to hash password: {e}")))?;
        let stored = StoredUser {
            user: User {
                id: new_id(),
                username: username.to_string(),
                roles: req.roles,
                created_at: now_ts(),
                last_login_at: None,
            },
            password_hash,
            must_change_password: false,
        };
        self.store.put(&stored.user.id, &stored).await?;
        let user = stored.user.clone();
        self.users
            .write()
            .expect("user lock")
            .insert(user.id.clone(), stored);
        Ok(user)
    }

    /// Update a user's roles and/or reset their password (admin action).
    pub async fn update_user(&self, id: &str, req: UpdateUserRequest) -> ApiResult<User> {
        let mut stored = self
            .users
            .read()
            .expect("user lock")
            .get(id)
            .cloned()
            .ok_or_else(|| AppError::not_found("user not found"))?;

        if let Some(roles) = req.roles {
            if roles.is_empty() {
                return Err(AppError::validation("at least one role is required"));
            }
            // Don't let the last administrator lose their admin role.
            let removes_admin =
                stored.user.roles.contains(&Role::Admin) && !roles.contains(&Role::Admin);
            if removes_admin && self.admin_count() <= 1 {
                return Err(AppError::conflict(
                    "cannot remove the admin role from the last administrator",
                ));
            }
            stored.user.roles = roles;
        }
        if let Some(password) = req.password {
            if password.len() < MIN_PASSWORD_LEN {
                return Err(AppError::validation(format!(
                    "password must be at least {MIN_PASSWORD_LEN} characters"
                )));
            }
            stored.password_hash = hash_password(&password)
                .map_err(|e| AppError::internal(format!("failed to hash password: {e}")))?;
            stored.must_change_password = false;
        }

        self.store.put(id, &stored).await?;
        let user = stored.user.clone();
        self.users
            .write()
            .expect("user lock")
            .insert(id.to_string(), stored);
        Ok(user)
    }

    /// Delete a user account and revoke its sessions.
    pub async fn delete_user(&self, id: &str) -> ApiResult<()> {
        {
            let users = self.users.read().expect("user lock");
            let target = users
                .get(id)
                .ok_or_else(|| AppError::not_found("user not found"))?;
            if target.user.roles.contains(&Role::Admin) && self.admin_count() <= 1 {
                return Err(AppError::conflict("cannot delete the last administrator"));
            }
        }
        self.store.delete(id).await?;
        self.users.write().expect("user lock").remove(id);
        // Revoke any live sessions for the deleted user.
        self.tokens
            .write()
            .expect("token lock")
            .retain(|_, s| s.user_id != id);
        Ok(())
    }

    /// Change the caller's own password after verifying the current one.
    pub async fn change_password(
        &self,
        user_id: &str,
        req: ChangePasswordRequest,
    ) -> ApiResult<()> {
        if req.new_password.len() < MIN_PASSWORD_LEN {
            return Err(AppError::validation(format!(
                "password must be at least {MIN_PASSWORD_LEN} characters"
            )));
        }
        let mut stored = self
            .users
            .read()
            .expect("user lock")
            .get(user_id)
            .cloned()
            .ok_or_else(|| AppError::unauthorized("unknown user"))?;
        verify_password(&req.current_password, &stored.password_hash)?;

        stored.password_hash = hash_password(&req.new_password)
            .map_err(|e| AppError::internal(format!("failed to hash password: {e}")))?;
        stored.must_change_password = false;
        self.store.put(user_id, &stored).await?;
        self.users
            .write()
            .expect("user lock")
            .insert(user_id.to_string(), stored);
        Ok(())
    }

    /// Number of accounts currently holding the admin role.
    fn admin_count(&self) -> usize {
        self.users
            .read()
            .expect("user lock")
            .values()
            .filter(|s| s.user.roles.contains(&Role::Admin))
            .count()
    }
}

/// Hash a plaintext password with argon2id, producing a PHC string.
fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

/// Verify a plaintext password against a stored PHC hash.
fn verify_password(password: &str, hash: &str) -> ApiResult<()> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| AppError::internal(format!("bad password hash: {e}")))?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| AppError::unauthorized("invalid credentials"))
}

/// A random 256-bit token, hex-encoded.
fn mint_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Map a set of roles to the flattened, de-duplicated permission set the RBAC
/// layer enforces at the API boundary.
pub fn effective_permissions(roles: &[Role]) -> Vec<Permission> {
    use Permission::*;
    let mut perms: Vec<Permission> = Vec::new();
    for role in roles {
        let granted: &[Permission] = match role {
            Role::Admin => &[
                VmRead,
                VmWrite,
                VmPower,
                LxcRead,
                LxcWrite,
                LxcPower,
                StorageRead,
                StorageWrite,
                NetworkRead,
                NetworkWrite,
                GpuRead,
                GpuWrite,
                MetricsRead,
                UserAdmin,
            ],
            Role::Operator => &[
                VmRead,
                VmWrite,
                VmPower,
                LxcRead,
                LxcWrite,
                LxcPower,
                StorageRead,
                StorageWrite,
                NetworkRead,
                NetworkWrite,
                GpuRead,
                GpuWrite,
                MetricsRead,
            ],
            Role::Viewer => &[
                VmRead,
                LxcRead,
                StorageRead,
                NetworkRead,
                GpuRead,
                MetricsRead,
            ],
        };
        for p in granted {
            if !perms.contains(p) {
                perms.push(*p);
            }
        }
    }
    perms
}

#[cfg(test)]
mod tests {
    use super::*;
    use daygleve_schema::auth::{CreateUserRequest, Role};

    fn test_config(dir: &std::path::Path) -> Arc<Config> {
        Arc::new(Config {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            cors_origins: vec![],
            default_pool: "tank".into(),
            web_root: None,
            state_dir: dir.to_path_buf(),
            iso_dir: dir.join("isos"),
            mounts_dir: dir.join("mounts"),
            token_ttl_secs: 3600,
            admin_password: "changeme123".into(),
        })
    }

    #[tokio::test]
    async fn users_persist_and_last_admin_is_protected() {
        let dir = std::env::temp_dir().join(format!("daygleve-auth-test-{}", new_id()));

        let svc = AuthService::new(test_config(&dir));
        svc.load_or_seed().await.unwrap();
        assert_eq!(svc.list_users().len(), 1, "seeds one admin");

        let op = svc
            .create_user(CreateUserRequest {
                username: "op".into(),
                password: "password1".into(),
                roles: vec![Role::Operator],
            })
            .await
            .unwrap();
        assert_eq!(svc.list_users().len(), 2);

        // Duplicate username (case-insensitive) and short passwords are rejected.
        assert!(svc
            .create_user(CreateUserRequest {
                username: "OP".into(),
                password: "password1".into(),
                roles: vec![Role::Operator],
            })
            .await
            .is_err());
        assert!(svc
            .create_user(CreateUserRequest {
                username: "z".into(),
                password: "short".into(),
                roles: vec![Role::Viewer],
            })
            .await
            .is_err());

        // A fresh service instance loads the same users from disk.
        let svc2 = AuthService::new(test_config(&dir));
        svc2.load_or_seed().await.unwrap();
        assert_eq!(svc2.list_users().len(), 2, "users survive a restart");

        // Deleting a non-admin is fine; deleting the last admin is refused.
        svc2.delete_user(&op.id).await.unwrap();
        assert_eq!(svc2.list_users().len(), 1);
        let admin_id = svc2.list_users()[0].id.clone();
        assert!(svc2.delete_user(&admin_id).await.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
