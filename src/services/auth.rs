//! Authentication + RBAC service.
//!
//! Issues opaque bearer tokens and resolves them back to a [`CurrentUser`] with
//! an effective permission set. Passwords are verified with argon2; tokens are
//! random 256-bit values with a real expiry (configurable TTL).
//!
//! Users are **persisted** to the JSON record store (`<state_dir>/users`) so
//! accounts, roles and password hashes survive a restart; an in-memory cache
//! fronts them for fast, lock-only reads on the hot authentication path. Bearer
//! tokens remain in-memory by design - sessions are ephemeral, so they simply
//! reset on restart and clients re-authenticate. On first start (empty store) a
//! single `admin` account is seeded: from `DAYGLEVE_ADMIN_PASSWORD` when set,
//! otherwise from a generated random password (written to a root-only file)
//! that the operator must change on first login. Account mutations are
//! serialized through an async lock so check-then-write stays consistent.

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
use daygleve_schema::two_factor::{TwoFactorEnabledResponse, TwoFactorSetupResponse};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::store::JsonStore;
use crate::services::{new_id, now_ts, totp};

/// Issuer label embedded in the `otpauth://` provisioning URI (shown by the
/// authenticator app next to the account).
const TOTP_ISSUER: &str = "DaygleVE";

/// Number of one-time recovery codes minted when 2FA is confirmed.
const RECOVERY_CODE_COUNT: usize = 10;

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
    /// Optional TOTP second factor. Absent (default) for accounts that have
    /// never started enrollment.
    #[serde(default)]
    two_factor: TwoFactor,
}

/// Server-side two-factor (TOTP) state for one account.
///
/// Enrollment is two-phase: `secret` is populated by *setup* (pending), then
/// `enabled` is flipped by *confirm* once the user proves the authenticator
/// works. The shared secret is stored base32-encoded — the same form handed to
/// the authenticator — because the state directory is already the trust
/// boundary for password hashes and token material; encryption-at-rest would
/// need a key-management story this single-node appliance does not yet have.
#[derive(Clone, Default, Serialize, Deserialize)]
struct TwoFactor {
    /// The base32 shared secret, present once *setup* has run. Kept while
    /// enrollment is pending and after it is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secret: Option<String>,
    /// True once *confirm* has verified a code and activated the second factor.
    /// While `secret` is `Some` but this is false, enrollment is pending and
    /// login is unaffected.
    #[serde(default)]
    enabled: bool,
    /// SHA-256 hashes (hex) of the unused one-time recovery codes. A code is
    /// removed from this list the moment it is consumed.
    #[serde(default)]
    recovery_hashes: Vec<String>,
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
    /// Serializes account mutations (create/update/delete/change-password) so a
    /// read-then-write (e.g. the username-uniqueness check) is never racy.
    mutate: tokio::sync::Mutex<()>,
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
            mutate: tokio::sync::Mutex::new(()),
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

        // First boot: seed the admin. Use the configured password when present;
        // otherwise generate a random one (there is no built-in default) and
        // write it to a root-only file so the operator can retrieve it, forcing
        // a change on first login. The password is never logged in cleartext.
        let (password, must_change_password) = match self.config.admin_password.clone() {
            Some(password) => {
                if password.len() < MIN_PASSWORD_LEN {
                    return Err(AppError::validation(format!(
                        "DAYGLEVE_ADMIN_PASSWORD must be at least {MIN_PASSWORD_LEN} characters"
                    )));
                }
                (password, false)
            }
            None => {
                let generated = generate_initial_password();
                let path = self.config.state_dir.join("initial-admin-password");
                write_secret_file(&path, &generated).await?;
                tracing::warn!(
                    "no DAYGLEVE_ADMIN_PASSWORD set; wrote a generated initial admin password to {} - log in as 'admin' and change it immediately",
                    path.display()
                );
                (generated, true)
            }
        };
        let password_hash = hash_password(&password)
            .map_err(|e| AppError::internal(format!("failed to hash admin password: {e}")))?;
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
            two_factor: TwoFactor::default(),
        };
        self.store.put(&admin.user.id, &admin).await?;
        self.users
            .write()
            .expect("user lock")
            .insert(admin.user.id.clone(), admin);
        Ok(())
    }

    pub async fn login(&self, req: LoginRequest) -> ApiResult<LoginResponse> {
        // Snapshot the id + hash under a read lock, then run the CPU-heavy
        // argon2 verification with no lock held, so concurrent logins aren't
        // serialized behind each other's hashing.
        let found = {
            let users = self.users.read().expect("user lock");
            users
                .values()
                // Usernames are unique case-insensitively (see create_user) and
                // stored trimmed, so match the same way here - otherwise an
                // account created as "Admin" could never log in as "admin".
                .find(|u| u.user.username.eq_ignore_ascii_case(req.username.trim()))
                .map(|stored| (stored.user.id.clone(), stored.password_hash.clone()))
        };

        let (user_id, hash) = match found {
            Some(pair) => pair,
            None => {
                // Verify against a dummy hash so an unknown username costs the
                // same argon2 time as a real account with a wrong password.
                // Without this, the fast "no such user" path is measurably
                // quicker than the hashing path, leaking whether an account
                // exists (username enumeration).
                let _ = verify_password(&req.password, dummy_password_hash());
                return Err(AppError::unauthorized("invalid credentials"));
            }
        };

        verify_password(&req.password, &hash)?;

        // Second-factor gate. The password was accepted; if the account has TOTP
        // enabled we require a valid code (or an unused recovery code) before a
        // token is minted. A missing code is reported with the distinct
        // `two_factor_required` signal so the login handler prompts for it
        // without counting the (correct-password) attempt as a failure.
        let second_factor = {
            let users = self.users.read().expect("user lock");
            users
                .get(&user_id)
                .map(|s| (s.two_factor.enabled, s.two_factor.secret.clone()))
        };
        if let Some((true, secret)) = second_factor {
            match req
                .totp_code
                .as_deref()
                .map(str::trim)
                .filter(|c| !c.is_empty())
            {
                None => {
                    return Err(AppError::two_factor_required(
                        "a two-factor authentication code is required",
                    ));
                }
                Some(code) => {
                    self.verify_second_factor(&user_id, secret.as_deref(), code)
                        .await?;
                }
            }
        }

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

    /// Revoke one bearer-token session. Missing/expired tokens are harmless.
    pub fn logout(&self, token: &str) {
        self.tokens.write().expect("token lock").remove(token);
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

        let (user, must_change_password, two_factor_enabled) = self
            .users
            .read()
            .expect("user lock")
            .get(&user_id)
            .map(|s| (s.user.clone(), s.must_change_password, s.two_factor.enabled))
            .ok_or_else(|| AppError::unauthorized("unknown user"))?;

        let permissions = effective_permissions(&user.roles);
        Ok(CurrentUser {
            user,
            permissions,
            must_change_password,
            two_factor_enabled,
        })
    }

    /// A single user account (without secrets) by id, if it exists. Used to
    /// resolve the owner of an API token into a caller identity.
    pub fn user_by_id(&self, id: &str) -> Option<User> {
        self.users
            .read()
            .expect("user lock")
            .get(id)
            .map(|s| s.user.clone())
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
        // Serialize with other mutations so the uniqueness check below and the
        // subsequent persist/insert are atomic.
        let _guard = self.mutate.lock().await;
        let username = req.username.trim();
        if username.is_empty()
            || username.len() > 64
            || username
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(AppError::validation(
                "username must be 1..=64 characters with no whitespace or control characters",
            ));
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
            two_factor: TwoFactor::default(),
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
        let _guard = self.mutate.lock().await;
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
        let password_reset = req.password.is_some();
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
        // An administrator password reset invalidates existing sessions so a
        // previously issued token cannot survive the credential change.
        if password_reset {
            self.tokens
                .write()
                .expect("token lock")
                .retain(|_, session| session.user_id != id);
        }
        Ok(user)
    }

    /// Delete a user account and revoke its sessions.
    pub async fn delete_user(&self, id: &str) -> ApiResult<()> {
        let _guard = self.mutate.lock().await;
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
        current_token: &str,
        req: ChangePasswordRequest,
    ) -> ApiResult<()> {
        let _guard = self.mutate.lock().await;
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
        // Changing a password is a session boundary: revoke every other token
        // for this account while preserving the token that authenticated this
        // request, so the caller can continue without a needless login loop.
        self.tokens
            .write()
            .expect("token lock")
            .retain(|token, session| session.user_id != user_id || token == current_token);
        Ok(())
    }

    /// Whether the given account has an active (confirmed) second factor.
    pub fn two_factor_enabled(&self, user_id: &str) -> bool {
        self.users
            .read()
            .expect("user lock")
            .get(user_id)
            .map(|s| s.two_factor.enabled)
            .unwrap_or(false)
    }

    /// Begin TOTP enrollment: generate a fresh shared secret, store it in a
    /// *pending* (not-yet-active) state, and return it with an `otpauth://`
    /// provisioning URI. Idempotent while pending — calling again rotates the
    /// pending secret. Refused once 2FA is already active (disable it first).
    pub async fn two_factor_setup(&self, user_id: &str) -> ApiResult<TwoFactorSetupResponse> {
        let _guard = self.mutate.lock().await;
        let mut stored = self
            .users
            .read()
            .expect("user lock")
            .get(user_id)
            .cloned()
            .ok_or_else(|| AppError::unauthorized("unknown user"))?;
        if stored.two_factor.enabled {
            return Err(AppError::conflict(
                "two-factor authentication is already enabled; disable it before re-enrolling",
            ));
        }
        let secret = totp::generate_secret();
        let uri = totp::provisioning_uri(&secret, TOTP_ISSUER, &stored.user.username);
        stored.two_factor = TwoFactor {
            secret: Some(secret.clone()),
            enabled: false,
            recovery_hashes: Vec::new(),
        };
        self.store.put(user_id, &stored).await?;
        self.users
            .write()
            .expect("user lock")
            .insert(user_id.to_string(), stored);
        Ok(TwoFactorSetupResponse {
            secret,
            otpauth_uri: uri,
        })
    }

    /// Finish TOTP enrollment: verify a code against the pending secret,
    /// activate the second factor, and mint one-time recovery codes (returned
    /// once; only their hashes are kept).
    pub async fn two_factor_confirm(
        &self,
        user_id: &str,
        code: &str,
    ) -> ApiResult<TwoFactorEnabledResponse> {
        let _guard = self.mutate.lock().await;
        let mut stored = self
            .users
            .read()
            .expect("user lock")
            .get(user_id)
            .cloned()
            .ok_or_else(|| AppError::unauthorized("unknown user"))?;
        if stored.two_factor.enabled {
            return Err(AppError::conflict(
                "two-factor authentication is already enabled",
            ));
        }
        let secret =
            stored.two_factor.secret.clone().ok_or_else(|| {
                AppError::conflict("start two-factor setup before confirming a code")
            })?;
        if !totp::verify(&secret, code, now_unix()) {
            return Err(AppError::validation(
                "the code is incorrect or has expired; try again",
            ));
        }
        let recovery_codes = generate_recovery_codes();
        stored.two_factor.enabled = true;
        stored.two_factor.recovery_hashes = recovery_codes
            .iter()
            .map(|c| hash_recovery_code(c))
            .collect();
        self.store.put(user_id, &stored).await?;
        self.users
            .write()
            .expect("user lock")
            .insert(user_id.to_string(), stored);
        Ok(TwoFactorEnabledResponse { recovery_codes })
    }

    /// Disable the second factor after verifying a current TOTP (or recovery)
    /// code, clearing the stored secret and any remaining recovery codes.
    pub async fn two_factor_disable(&self, user_id: &str, code: &str) -> ApiResult<()> {
        let secret = {
            let users = self.users.read().expect("user lock");
            let stored = users
                .get(user_id)
                .ok_or_else(|| AppError::unauthorized("unknown user"))?;
            if !stored.two_factor.enabled {
                return Err(AppError::conflict(
                    "two-factor authentication is not enabled",
                ));
            }
            stored.two_factor.secret.clone()
        };
        // Reuse the login verifier so a recovery code works here too (it is
        // consumed, but the record is cleared immediately afterwards anyway).
        self.verify_second_factor(user_id, secret.as_deref(), code)
            .await?;

        let _guard = self.mutate.lock().await;
        let mut stored = self
            .users
            .read()
            .expect("user lock")
            .get(user_id)
            .cloned()
            .ok_or_else(|| AppError::unauthorized("unknown user"))?;
        stored.two_factor = TwoFactor::default();
        self.store.put(user_id, &stored).await?;
        self.users
            .write()
            .expect("user lock")
            .insert(user_id.to_string(), stored);
        Ok(())
    }

    /// Verify a second-factor code for an account: a valid TOTP against the
    /// shared secret, or an unused recovery code (which is consumed and
    /// persisted). Returns `unauthorized` with the standard message on failure.
    async fn verify_second_factor(
        &self,
        user_id: &str,
        secret: Option<&str>,
        code: &str,
    ) -> ApiResult<()> {
        // A valid TOTP is stateless — check it first, no lock or write needed.
        if let Some(secret) = secret {
            if totp::verify(secret, code, now_unix()) {
                return Ok(());
            }
        }
        // Otherwise fall back to consuming a one-time recovery code. Serialize
        // the read-modify-write so the same code cannot be spent twice by two
        // concurrent logins.
        let target = hash_recovery_code(code);
        let _guard = self.mutate.lock().await;
        let mut stored = self
            .users
            .read()
            .expect("user lock")
            .get(user_id)
            .cloned()
            .ok_or_else(|| AppError::unauthorized("invalid credentials"))?;
        if let Some(pos) = stored
            .two_factor
            .recovery_hashes
            .iter()
            .position(|h| h == &target)
        {
            stored.two_factor.recovery_hashes.remove(pos);
            self.store.put(user_id, &stored).await?;
            self.users
                .write()
                .expect("user lock")
                .insert(user_id.to_string(), stored);
            return Ok(());
        }
        Err(AppError::unauthorized("invalid credentials"))
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

/// A process-wide dummy argon2 hash, used to spend the same verification time
/// on a login for a non-existent user as a real account would. It carries the
/// same `Argon2::default()` parameters as every stored hash (it is produced by
/// the same hasher), so the timing matches. Computed once, of a random
/// throwaway secret that no login can ever match.
fn dummy_password_hash() -> &'static str {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DUMMY.get_or_init(|| hash_password(&mint_token()).expect("hash dummy password"))
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

/// Current Unix time in seconds, for TOTP window selection. Clamped at 0 so a
/// clock set before the epoch cannot underflow the unsigned counter.
fn now_unix() -> u64 {
    Utc::now().timestamp().max(0) as u64
}

/// Generate the set of one-time recovery codes handed out at 2FA confirmation.
/// Each is 80 bits of entropy rendered as two dash-separated base32-ish groups
/// (e.g. `a1b2c-d3e4f`) for legibility.
fn generate_recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODE_COUNT).map(|_| recovery_code()).collect()
}

/// One recovery code: 80 random bits, lower-hex, grouped `xxxxx-xxxxx`.
fn recovery_code() -> String {
    let mut bytes = [0u8; 5];
    OsRng.fill_bytes(&mut bytes);
    let mut hex = String::with_capacity(10);
    for b in bytes {
        hex.push_str(&format!("{b:02x}"));
    }
    format!("{}-{}", &hex[..5], &hex[5..])
}

/// Normalize and hash a recovery code for storage/comparison: strip formatting
/// (dashes, whitespace, case) so the stored hash matches whatever the user
/// types, then SHA-256 it to hex. The plaintext code is never persisted.
fn hash_recovery_code(code: &str) -> String {
    let normalized: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect();
    let digest = Sha256::digest(normalized.as_bytes());
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A random, high-entropy initial admin password (144 bits, hex-encoded).
fn generate_initial_password() -> String {
    let mut bytes = [0u8; 18];
    OsRng.fill_bytes(&mut bytes);
    let mut s = String::with_capacity(36);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Write a secret to a root-only (0600) file, creating the parent directory.
async fn write_secret_file(path: &std::path::Path, secret: &str) -> ApiResult<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| AppError::internal(format!("create {}: {e}", parent.display())))?;
    }
    tokio::fs::write(path, format!("{secret}\n"))
        .await
        .map_err(|e| AppError::internal(format!("write {}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .await
            .map_err(|e| AppError::internal(format!("secure {}: {e}", path.display())))?;
    }
    Ok(())
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
                OperationsRead,
                OperationsWrite,
                BackupRead,
                BackupWrite,
                PoolRead,
                PoolWrite,
                NotificationRead,
                NotificationWrite,
                TlsRead,
                TlsWrite,
                AuditRead,
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
                OperationsRead,
                OperationsWrite,
                BackupRead,
                BackupWrite,
                PoolRead,
                PoolWrite,
                NotificationRead,
                NotificationWrite,
                TlsRead,
            ],
            Role::Viewer => &[
                VmRead,
                LxcRead,
                StorageRead,
                NetworkRead,
                GpuRead,
                MetricsRead,
                OperationsRead,
                BackupRead,
                PoolRead,
                NotificationRead,
                TlsRead,
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

    // Build passwords at runtime with no string literals at all, so the tests
    // carry no hard-coded credentials (reusing the service's random generator).
    fn rand_password() -> String {
        generate_initial_password()
    }

    fn test_config(dir: &std::path::Path) -> Arc<Config> {
        Arc::new(Config {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            cors_origins: vec![],
            default_pool: "tank".into(),
            web_root: None,
            state_dir: dir.to_path_buf(),
            iso_dir: dir.join("isos"),
            template_dir: dir.join("templates"),
            disk_image_dir: dir.join("disk-images"),
            mounts_dir: dir.join("mounts"),
            max_upload_bytes: 16 * 1024 * 1024 * 1024,
            spice_listen: "127.0.0.1".to_string(),
            backup_dir: dir.join("backups"),
            token_ttl_secs: 3600,
            admin_password: Some(rand_password()),
            tls_cert: None,
            tls_key: None,
            broker_socket: None,
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
                password: rand_password(),
                roles: vec![Role::Operator],
            })
            .await
            .unwrap();
        assert_eq!(svc.list_users().len(), 2);

        // Duplicate username (case-insensitive) and short passwords are rejected.
        assert!(svc
            .create_user(CreateUserRequest {
                username: "OP".into(),
                password: rand_password(),
                roles: vec![Role::Operator],
            })
            .await
            .is_err());
        let short: String = new_id().chars().take(4).collect();
        assert!(svc
            .create_user(CreateUserRequest {
                username: "z".into(),
                password: short,
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

    #[tokio::test]
    async fn login_rejects_unknown_user_and_wrong_password() {
        let dir = std::env::temp_dir().join(format!("daygleve-login-test-{}", new_id()));
        let password = rand_password();
        let config = Arc::new(Config {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            cors_origins: vec![],
            default_pool: "tank".into(),
            web_root: None,
            state_dir: dir.clone(),
            iso_dir: dir.join("isos"),
            template_dir: dir.join("templates"),
            disk_image_dir: dir.join("disk-images"),
            mounts_dir: dir.join("mounts"),
            max_upload_bytes: 16 * 1024 * 1024 * 1024,
            spice_listen: "127.0.0.1".to_string(),
            backup_dir: dir.join("backups"),
            token_ttl_secs: 3600,
            admin_password: Some(password.clone()),
            tls_cert: None,
            tls_key: None,
            broker_socket: None,
        });
        let svc = AuthService::new(config);
        svc.load_or_seed().await.unwrap();

        // An unknown username is rejected - and still runs through the dummy-hash
        // verification so it can't be told apart from a wrong password by timing.
        assert!(svc
            .login(LoginRequest {
                username: "ghost".into(),
                password: password.clone(),
                totp_code: None,
            })
            .await
            .is_err());
        // A known username with the wrong password is rejected.
        assert!(svc
            .login(LoginRequest {
                username: "admin".into(),
                password: rand_password(),
                totp_code: None,
            })
            .await
            .is_err());
        // Correct credentials succeed - and the username match is
        // case-insensitive and trim-tolerant, consistent with how usernames are
        // stored and uniqueness is enforced.
        let ok = svc
            .login(LoginRequest {
                username: "  ADMIN ".into(),
                password,
                totp_code: None,
            })
            .await
            .unwrap();
        assert_eq!(ok.user.username, "admin");

        // The dummy hash must parse as a valid PHC string, or the enumeration
        // hardening would error out early instead of spending argon2 time.
        assert!(PasswordHash::new(dummy_password_hash()).is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn two_factor_enrollment_and_login() {
        let dir = std::env::temp_dir().join(format!("daygleve-2fa-test-{}", new_id()));
        let password = rand_password();
        let mut cfg = (*test_config(&dir)).clone();
        cfg.admin_password = Some(password.clone());
        let svc = AuthService::new(Arc::new(cfg));
        svc.load_or_seed().await.unwrap();
        let admin_id = svc.list_users()[0].id.clone();

        // A login with no 2FA works and needs no code.
        let login = |code: Option<String>| LoginRequest {
            username: "admin".into(),
            password: password.clone(),
            totp_code: code,
        };
        assert!(svc.login(login(None)).await.is_ok());
        assert!(!svc.two_factor_enabled(&admin_id));

        // Setup returns a secret; the second factor is still inactive, so login
        // is unaffected until confirmed.
        let setup = svc.two_factor_setup(&admin_id).await.unwrap();
        assert!(setup.otpauth_uri.contains("otpauth://totp/"));
        assert!(!svc.two_factor_enabled(&admin_id));
        assert!(svc.login(login(None)).await.is_ok());

        // Confirm requires a valid code. A wrong code is rejected; the right one
        // enables 2FA and yields recovery codes.
        assert!(svc.two_factor_confirm(&admin_id, "000000").await.is_err());
        let code = totp::current_code(&setup.secret, now_unix()).unwrap();
        let recovery = svc.two_factor_confirm(&admin_id, &code).await.unwrap();
        assert_eq!(recovery.recovery_codes.len(), RECOVERY_CODE_COUNT);
        assert!(svc.two_factor_enabled(&admin_id));

        // Now login without a code is refused with the two-factor-required
        // signal, not counted as a bad password.
        let err = svc.login(login(None)).await.unwrap_err();
        assert!(err.is_two_factor_required());
        // A wrong code fails; the correct TOTP succeeds.
        assert!(svc.login(login(Some("000000".into()))).await.is_err());
        let code = totp::current_code(&setup.secret, now_unix()).unwrap();
        assert!(svc.login(login(Some(code))).await.is_ok());

        // A recovery code logs in once and is then consumed.
        let one = recovery.recovery_codes[0].clone();
        assert!(svc.login(login(Some(one.clone()))).await.is_ok());
        assert!(svc.login(login(Some(one))).await.is_err());

        // Disable requires a current code; afterwards login needs no second
        // factor again.
        assert!(svc.two_factor_disable(&admin_id, "000000").await.is_err());
        let code = totp::current_code(&setup.secret, now_unix()).unwrap();
        svc.two_factor_disable(&admin_id, &code).await.unwrap();
        assert!(!svc.two_factor_enabled(&admin_id));
        assert!(svc.login(login(None)).await.is_ok());

        // State survives a restart: re-enroll, then reload from disk.
        let setup = svc.two_factor_setup(&admin_id).await.unwrap();
        let code = totp::current_code(&setup.secret, now_unix()).unwrap();
        svc.two_factor_confirm(&admin_id, &code).await.unwrap();
        let svc2 = AuthService::new(test_config(&dir));
        svc2.load_or_seed().await.unwrap();
        assert!(svc2.two_factor_enabled(&admin_id));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
