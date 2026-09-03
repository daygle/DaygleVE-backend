//! Authentication + RBAC service.
//!
//! Issues opaque bearer tokens and resolves them back to a [`CurrentUser`] with
//! an effective permission set. Passwords are verified with argon2; tokens are
//! random 256-bit values with a real expiry (configurable TTL). The user store
//! and token table are in-memory: a single `admin` account is seeded at
//! startup from configuration, and sessions reset on restart. Persisting users
//! to disk is the remaining follow-up.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use chrono::{DateTime, Duration, Utc};
use daygleve_schema::auth::{CurrentUser, LoginRequest, LoginResponse, Permission, Role, User};
use rand_core::{OsRng, RngCore};

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::{new_id, now_ts};

/// A user plus its (server-only) password hash.
struct StoredUser {
    user: User,
    password_hash: String,
}

/// A live bearer-token session.
struct Session {
    user_id: String,
    expires_at: DateTime<Utc>,
}

pub struct AuthService {
    tokens: RwLock<HashMap<String, Session>>,
    users: RwLock<HashMap<String, StoredUser>>,
    token_ttl_secs: u64,
}

impl AuthService {
    pub fn new(config: Arc<Config>) -> Self {
        let password_hash = hash_password(&config.admin_password)
            .unwrap_or_else(|e| panic!("failed to hash seeded admin password: {e}"));

        if config.admin_password == "daygleve" {
            tracing::warn!(
                "admin account seeded with the default password; set DAYGLEVE_ADMIN_PASSWORD"
            );
        }

        let admin = User {
            id: new_id(),
            username: "admin".to_string(),
            roles: vec![Role::Admin],
            created_at: now_ts(),
            last_login_at: None,
        };
        let mut users = HashMap::new();
        users.insert(
            admin.id.clone(),
            StoredUser {
                user: admin,
                password_hash,
            },
        );

        Self {
            tokens: RwLock::new(HashMap::new()),
            users: RwLock::new(users),
            token_ttl_secs: config.token_ttl_secs,
        }
    }

    pub fn login(&self, req: LoginRequest) -> ApiResult<LoginResponse> {
        let mut users = self.users.write().expect("user lock");
        let stored = users
            .values_mut()
            .find(|u| u.user.username == req.username)
            .ok_or_else(|| AppError::unauthorized("invalid credentials"))?;

        verify_password(&req.password, &stored.password_hash)?;

        let now = Utc::now();
        stored.user.last_login_at = Some(now.to_rfc3339());
        let user = stored.user.clone();
        drop(users);

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

        let user = self
            .users
            .read()
            .expect("user lock")
            .get(&user_id)
            .map(|s| s.user.clone())
            .ok_or_else(|| AppError::unauthorized("unknown user"))?;

        let permissions = effective_permissions(&user.roles);
        Ok(CurrentUser { user, permissions })
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
