//! Authentication + RBAC service.
//!
//! Issues opaque bearer tokens and resolves them back to a [`CurrentUser`] with
//! an effective permission set. TODO(auth): replace the in-memory user store
//! and token map with a persistent user DB and signed/expiring tokens (JWT or
//! server-side sessions), and hash passwords with argon2.

use std::collections::HashMap;
use std::sync::RwLock;

use daygleve_schema::auth::{CurrentUser, LoginRequest, LoginResponse, Permission, Role, User};

use crate::error::{ApiResult, AppError};
use crate::services::{new_id, now_ts};

pub struct AuthService {
    /// token -> user id
    tokens: RwLock<HashMap<String, String>>,
    /// user id -> user
    users: RwLock<HashMap<String, User>>,
}

impl AuthService {
    pub fn new() -> Self {
        // Seed a single development admin. TODO(auth): remove; provision the
        // first admin via an install step instead.
        let admin = User {
            id: new_id(),
            username: "admin".to_string(),
            roles: vec![Role::Admin],
            created_at: now_ts(),
            last_login_at: None,
        };
        let mut users = HashMap::new();
        users.insert(admin.id.clone(), admin);
        Self {
            tokens: RwLock::new(HashMap::new()),
            users: RwLock::new(users),
        }
    }

    pub fn login(&self, req: LoginRequest) -> ApiResult<LoginResponse> {
        // TODO(auth): verify the password hash for `req.username`.
        let users = self.users.read().expect("user lock");
        let user = users
            .values()
            .find(|u| u.username == req.username)
            .cloned()
            .ok_or_else(|| AppError::unauthorized("invalid credentials"))?;
        drop(users);

        let token = new_id();
        self.tokens
            .write()
            .expect("token lock")
            .insert(token.clone(), user.id.clone());

        Ok(LoginResponse {
            token,
            expires_at: now_ts(), // TODO(auth): real expiry (now + TTL).
            user,
        })
    }

    /// Resolve a bearer token to the caller and their effective permissions.
    pub fn authenticate(&self, token: &str) -> ApiResult<CurrentUser> {
        let tokens = self.tokens.read().expect("token lock");
        let user_id = tokens
            .get(token)
            .cloned()
            .ok_or_else(|| AppError::unauthorized("invalid or expired token"))?;
        drop(tokens);

        let user = self
            .users
            .read()
            .expect("user lock")
            .get(&user_id)
            .cloned()
            .ok_or_else(|| AppError::unauthorized("unknown user"))?;

        let permissions = effective_permissions(&user.roles);
        Ok(CurrentUser { user, permissions })
    }
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
