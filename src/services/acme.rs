//! ACME (Let's Encrypt) automatic TLS certificate management.
//!
//! DaygleVE can obtain and renew a certificate for its own HTTPS listener from
//! an ACME certificate authority, solving the **HTTP-01** challenge on the
//! unauthenticated `/.well-known/acme-challenge/{token}` route (mounted in
//! [`crate::api`]). The obtained certificate is written to
//! `<state_dir>/acme/cert.pem` + `key.pem` and installed on the live listener,
//! then renewed automatically before expiry.
//!
//! Persistence layout under `<state_dir>/acme/`:
//! - `config.json` — the non-secret [`AcmeConfig`].
//! - `account.json` — the ACME account credentials (**secret**: account key).
//! - `cert.pem` / `key.pem` — the issued chain and its private key (**secret**).
//! - `meta.json` — issue/expiry timestamps, last error, installed-cert domains.
//!
//! Every path here is a compile-time-constant file name joined to the
//! configured ACME directory, so no request-controlled string reaches a
//! filesystem sink. The account key and private key never leave the node: the
//! API returns [`AcmeStatus`] and [`AcmeConfig`] only.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum_server::tls_rustls::RustlsConfig;
use chrono::{DateTime, Utc};
use daygleve_schema::acme::{AcmeConfig, AcmeState, AcmeStatus, UpdateAcmeConfigRequest};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use crate::config::Config;
use crate::error::{ApiResult, AppError};

/// File names under the ACME state directory.
const CONFIG_FILE: &str = "config.json";
const ACCOUNT_FILE: &str = "account.json";
const META_FILE: &str = "meta.json";
const CERT_FILE: &str = "cert.pem";
const KEY_FILE: &str = "key.pem";

/// Default renewal window: renew when fewer than this many days remain.
const DEFAULT_RENEWAL_DAYS: u32 = 30;
/// How often the background renewal task evaluates the certificate.
const RENEWAL_TICK: Duration = Duration::from_secs(6 * 60 * 60);
/// Cap on polling an order/authorization to become ready before giving up.
const ORDER_POLL_ATTEMPTS: usize = 30;
const ORDER_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Persisted account credentials plus the directory they belong to. A change of
/// directory URL invalidates the account, so the directory is stored alongside.
#[derive(Serialize, Deserialize)]
struct StoredAccount {
    directory_url: String,
    credentials: AccountCredentials,
}

/// Persisted certificate metadata (non-secret).
#[derive(Default, Serialize, Deserialize)]
struct CertMeta {
    domains: Vec<String>,
    issued_at: Option<String>,
    expires_at: Option<String>,
    last_renewal_at: Option<String>,
    last_error: Option<String>,
}

/// Manages the node's ACME certificate lifecycle.
pub struct AcmeService {
    dir: PathBuf,
    /// HTTP-01 challenge responses, keyed by challenge token. Populated for the
    /// duration of an order and read by the well-known route.
    challenges: RwLock<HashMap<String, String>>,
    /// Live TLS reload handle, set by `main` once the HTTPS listener is up.
    /// Renewal calls `reload_from_pem_file` on it for zero-downtime rotation.
    reload: RwLock<Option<RustlsConfig>>,
    /// Serializes issuance so a manual trigger and the scheduler never overlap.
    issuing: Mutex<()>,
}

impl AcmeService {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            dir: config.state_dir.join("acme"),
            challenges: RwLock::new(HashMap::new()),
            reload: RwLock::new(None),
            issuing: Mutex::new(()),
        }
    }

    fn config_path(&self) -> PathBuf {
        self.dir.join(CONFIG_FILE)
    }
    fn account_path(&self) -> PathBuf {
        self.dir.join(ACCOUNT_FILE)
    }
    fn meta_path(&self) -> PathBuf {
        self.dir.join(META_FILE)
    }
    /// Absolute path of the installed certificate chain (fullchain PEM).
    pub fn cert_path(&self) -> PathBuf {
        self.dir.join(CERT_FILE)
    }
    /// Absolute path of the installed private key (PEM).
    pub fn key_path(&self) -> PathBuf {
        self.dir.join(KEY_FILE)
    }

    /// The managed certificate + key paths to serve TLS from, when ACME is
    /// enabled and a certificate has been issued. `main` prefers these over the
    /// statically configured `DAYGLEVE_TLS_CERT`/`_KEY` at startup.
    pub async fn installed_tls_paths(&self) -> Option<(PathBuf, PathBuf)> {
        if self.config().await.enabled && self.cert_installed().await {
            Some((self.cert_path(), self.key_path()))
        } else {
            None
        }
    }

    /// The stored configuration, or a disabled default on a fresh node.
    pub async fn config(&self) -> AcmeConfig {
        match tokio::fs::read(self.config_path()).await {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|_| default_config()),
            Err(_) => default_config(),
        }
    }

    async fn meta(&self) -> CertMeta {
        match tokio::fs::read(self.meta_path()).await {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => CertMeta::default(),
        }
    }

    async fn write_meta(&self, meta: &CertMeta) -> ApiResult<()> {
        self.ensure_dir().await?;
        let bytes = serde_json::to_vec_pretty(meta)
            .map_err(|e| AppError::internal(format!("serialize acme meta: {e}")))?;
        tokio::fs::write(self.meta_path(), bytes)
            .await
            .map_err(|e| AppError::internal(format!("write acme meta: {e}")))
    }

    async fn ensure_dir(&self) -> ApiResult<()> {
        tokio::fs::create_dir_all(&self.dir)
            .await
            .map_err(|e| AppError::internal(format!("create acme dir: {e}")))
    }

    /// Whether an ACME account has been registered (credentials on disk).
    async fn account_registered(&self) -> bool {
        tokio::fs::metadata(self.account_path()).await.is_ok()
    }

    /// Whether a certificate is currently installed.
    async fn cert_installed(&self) -> bool {
        tokio::fs::metadata(self.cert_path()).await.is_ok()
            && tokio::fs::metadata(self.key_path()).await.is_ok()
    }

    /// The full status view for `GET /security/acme`.
    pub async fn status(&self) -> AcmeStatus {
        let config = self.config().await;
        let meta = self.meta().await;
        let installed = self.cert_installed().await;
        let state = if !config.enabled {
            AcmeState::Disabled
        } else if meta.last_error.is_some() && !installed {
            AcmeState::Error
        } else if installed {
            AcmeState::Active
        } else {
            AcmeState::Pending
        };
        AcmeStatus {
            config,
            state,
            certificate_domains: meta.domains,
            issued_at: meta.issued_at,
            expires_at: meta.expires_at,
            last_renewal_at: meta.last_renewal_at,
            last_error: meta.last_error,
            account_registered: self.account_registered().await,
        }
    }

    /// Validate and persist a new configuration. Does not issue synchronously;
    /// the caller can trigger issuance, or the scheduler picks it up.
    pub async fn update_config(&self, req: UpdateAcmeConfigRequest) -> ApiResult<AcmeConfig> {
        let config = validate_config(req)?;
        self.ensure_dir().await?;
        let bytes = serde_json::to_vec_pretty(&config)
            .map_err(|e| AppError::internal(format!("serialize acme config: {e}")))?;
        tokio::fs::write(self.config_path(), bytes)
            .await
            .map_err(|e| AppError::internal(format!("write acme config: {e}")))?;
        Ok(config)
    }

    /// The HTTP-01 challenge response for a token, if one is active.
    pub async fn challenge_response(&self, token: &str) -> Option<String> {
        self.challenges.read().await.get(token).cloned()
    }

    /// Register the live TLS reload handle so renewals rotate the cert without
    /// a restart. Called by `main` once the HTTPS listener is serving.
    pub async fn set_reload_handle(&self, handle: RustlsConfig) {
        *self.reload.write().await = Some(handle);
    }

    /// Kick off issuance in the background and return the current status
    /// (`state` becomes `Pending` while it runs). Used by the issue endpoint.
    pub async fn trigger_issue(self: &Arc<Self>) -> ApiResult<AcmeStatus> {
        let config = self.config().await;
        if !config.enabled {
            return Err(AppError::validation(
                "enable ACME and set at least one domain before issuing",
            ));
        }
        if config.domains.is_empty() {
            return Err(AppError::validation("configure at least one domain first"));
        }
        let this = self.clone();
        tokio::spawn(async move {
            if let Err(e) = this.run_issuance(&this.config().await).await {
                tracing::error!(error = ?e, "acme issuance failed");
            }
        });
        Ok(self.status().await)
    }

    /// Start the background renewal loop: on each tick, if ACME is enabled and
    /// the certificate is missing or within the renewal window, (re)issue it.
    pub fn start_scheduler(self: &Arc<Self>) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(RENEWAL_TICK);
            loop {
                tick.tick().await;
                let config = this.config().await;
                if !config.enabled || config.domains.is_empty() {
                    continue;
                }
                let due = match this.meta().await.expires_at {
                    Some(ref ts) => should_renew(ts, config.renewal_days, Utc::now()),
                    None => true, // never issued yet
                };
                if !this.cert_installed().await || due {
                    if let Err(e) = this.run_issuance(&config).await {
                        tracing::error!(error = ?e, "scheduled acme renewal failed");
                    }
                }
            }
        });
    }

    /// The full HTTP-01 issuance flow: register/reuse the account, place an
    /// order, answer each authorization's challenge, finalize with a fresh
    /// keypair, install the certificate, and hot-reload the listener.
    async fn run_issuance(self: &Arc<Self>, config: &AcmeConfig) -> ApiResult<()> {
        // Only one issuance at a time; a concurrent trigger simply returns.
        let _guard = match self.issuing.try_lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::info!("acme issuance already in progress; skipping");
                return Ok(());
            }
        };
        self.ensure_dir().await?;
        let result = self.issue_inner(config).await;
        // Record success or failure in the metadata either way.
        let mut meta = self.meta().await;
        match &result {
            Ok(installed) => {
                meta.domains = config.domains.clone();
                meta.issued_at = Some(installed.issued_at.clone());
                meta.expires_at = Some(installed.expires_at.clone());
                meta.last_renewal_at = Some(crate::services::now_ts());
                meta.last_error = None;
            }
            Err(e) => meta.last_error = Some(e.message().to_string()),
        }
        self.write_meta(&meta).await?;
        result.map(|_| ())
    }

    async fn issue_inner(&self, config: &AcmeConfig) -> ApiResult<InstalledCert> {
        let account = self.load_or_create_account(config).await?;

        let identifiers: Vec<Identifier> = config
            .domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();
        let mut order = account
            .new_order(&NewOrder {
                identifiers: &identifiers,
            })
            .await
            .map_err(|e| AppError::hypervisor(format!("acme new order: {e}")))?;

        // Answer every pending authorization's HTTP-01 challenge.
        let authorizations = order
            .authorizations()
            .await
            .map_err(|e| AppError::hypervisor(format!("acme authorizations: {e}")))?;
        let mut ready_urls = Vec::new();
        let mut tokens = Vec::new();
        for authz in &authorizations {
            match authz.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                other => {
                    return Err(AppError::hypervisor(format!(
                        "acme authorization in unexpected state {other:?}"
                    )))
                }
            }
            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Http01)
                .ok_or_else(|| AppError::hypervisor("acme server offered no http-01 challenge"))?;
            let key_auth = order.key_authorization(challenge);
            self.challenges
                .write()
                .await
                .insert(challenge.token.clone(), key_auth.as_str().to_string());
            tokens.push(challenge.token.clone());
            ready_urls.push(challenge.url.clone());
        }

        // Tell the CA every challenge is ready, then poll to Ready. Challenge
        // responses are cleared once the order leaves the authorization phase.
        let finalize = async {
            for url in &ready_urls {
                order
                    .set_challenge_ready(url)
                    .await
                    .map_err(|e| AppError::hypervisor(format!("acme set ready: {e}")))?;
            }
            self.poll_order_ready(&mut order).await?;

            // Finalize with a fresh keypair + CSR for exactly these domains.
            let params = rcgen::CertificateParams::new(config.domains.clone())
                .map_err(|e| AppError::internal(format!("acme csr params: {e}")))?;
            let key_pair = rcgen::KeyPair::generate()
                .map_err(|e| AppError::internal(format!("acme keypair: {e}")))?;
            let csr = params
                .serialize_request(&key_pair)
                .map_err(|e| AppError::internal(format!("acme csr: {e}")))?;
            order
                .finalize(csr.der())
                .await
                .map_err(|e| AppError::hypervisor(format!("acme finalize: {e}")))?;
            let cert_chain = self.poll_certificate(&mut order).await?;
            Ok::<_, AppError>((cert_chain, key_pair.serialize_pem()))
        }
        .await;

        // Always clear the served challenge tokens once we're done with them.
        {
            let mut store = self.challenges.write().await;
            for token in &tokens {
                store.remove(token);
            }
        }
        let (cert_chain, key_pem) = finalize?;

        self.install_cert(&cert_chain, &key_pem).await
    }

    /// Load a persisted account whose directory matches, else create a new one.
    async fn load_or_create_account(&self, config: &AcmeConfig) -> ApiResult<Account> {
        if let Ok(bytes) = tokio::fs::read(self.account_path()).await {
            if let Ok(stored) = serde_json::from_slice::<StoredAccount>(&bytes) {
                if stored.directory_url == config.directory_url {
                    return Account::from_credentials(stored.credentials)
                        .await
                        .map_err(|e| AppError::hypervisor(format!("acme account restore: {e}")));
                }
            }
        }
        let contact = format!("mailto:{}", config.contact_email);
        let (account, credentials) = Account::create(
            &NewAccount {
                contact: &[contact.as_str()],
                terms_of_service_agreed: config.terms_agreed,
                only_return_existing: false,
            },
            &config.directory_url,
            None,
        )
        .await
        .map_err(|e| AppError::hypervisor(format!("acme account create: {e}")))?;
        let stored = StoredAccount {
            directory_url: config.directory_url.clone(),
            credentials,
        };
        let bytes = serde_json::to_vec(&stored)
            .map_err(|e| AppError::internal(format!("serialize acme account: {e}")))?;
        tokio::fs::write(self.account_path(), bytes)
            .await
            .map_err(|e| AppError::internal(format!("write acme account: {e}")))?;
        Ok(account)
    }

    async fn poll_order_ready(&self, order: &mut instant_acme::Order) -> ApiResult<()> {
        for _ in 0..ORDER_POLL_ATTEMPTS {
            let state = order
                .refresh()
                .await
                .map_err(|e| AppError::hypervisor(format!("acme order refresh: {e}")))?;
            match state.status {
                OrderStatus::Ready | OrderStatus::Valid => return Ok(()),
                OrderStatus::Invalid => {
                    return Err(AppError::hypervisor(
                        "acme order became invalid (challenge validation failed)",
                    ))
                }
                OrderStatus::Pending | OrderStatus::Processing => {
                    tokio::time::sleep(ORDER_POLL_INTERVAL).await;
                }
            }
        }
        Err(AppError::hypervisor(
            "acme order did not become ready in time",
        ))
    }

    async fn poll_certificate(&self, order: &mut instant_acme::Order) -> ApiResult<String> {
        for _ in 0..ORDER_POLL_ATTEMPTS {
            match order
                .certificate()
                .await
                .map_err(|e| AppError::hypervisor(format!("acme certificate: {e}")))?
            {
                Some(pem) => return Ok(pem),
                None => tokio::time::sleep(ORDER_POLL_INTERVAL).await,
            }
        }
        Err(AppError::hypervisor(
            "acme certificate was not issued in time",
        ))
    }

    /// Write the chain + key to the managed paths and hot-reload the listener.
    async fn install_cert(&self, cert_chain: &str, key_pem: &str) -> ApiResult<InstalledCert> {
        let (issued_at, expires_at) = parse_cert_validity(cert_chain)?;
        tokio::fs::write(self.cert_path(), cert_chain)
            .await
            .map_err(|e| AppError::internal(format!("write acme cert: {e}")))?;
        tokio::fs::write(self.key_path(), key_pem)
            .await
            .map_err(|e| AppError::internal(format!("write acme key: {e}")))?;
        // Hot-reload the live listener if HTTPS is already up; a first-ever
        // issuance on an HTTP listener applies on the next restart instead.
        if let Some(handle) = self.reload.read().await.as_ref() {
            if let Err(e) = handle
                .reload_from_pem_file(self.cert_path(), self.key_path())
                .await
            {
                tracing::error!(error = %e, "acme cert written but live reload failed");
            } else {
                tracing::info!("acme certificate installed and live listener reloaded");
            }
        } else {
            tracing::info!(
                "acme certificate installed; restart to serve HTTPS if not already enabled"
            );
        }
        Ok(InstalledCert {
            issued_at,
            expires_at,
        })
    }
}

struct InstalledCert {
    issued_at: String,
    expires_at: String,
}

/// A disabled default configuration for a node that has never configured ACME.
fn default_config() -> AcmeConfig {
    AcmeConfig {
        enabled: false,
        directory_url: daygleve_schema::acme::LETS_ENCRYPT_PRODUCTION.to_string(),
        contact_email: String::new(),
        domains: Vec::new(),
        terms_agreed: false,
        renewal_days: DEFAULT_RENEWAL_DAYS,
    }
}

/// Validate an update request into a stored configuration. When ACME is being
/// enabled, the directory URL, contact, domains, and terms are all required.
fn validate_config(req: UpdateAcmeConfigRequest) -> ApiResult<AcmeConfig> {
    let renewal_days = req.renewal_days.unwrap_or(DEFAULT_RENEWAL_DAYS);
    if !(1..=89).contains(&renewal_days) {
        return Err(AppError::validation(
            "renewal_days must be between 1 and 89",
        ));
    }
    let directory_url = req.directory_url.trim().to_string();
    let contact_email = req.contact_email.trim().to_string();
    let domains: Vec<String> = req
        .domains
        .iter()
        .map(|d| d.trim().to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .collect();

    if req.enabled {
        if !directory_url.starts_with("https://") {
            return Err(AppError::validation(
                "directory_url must be an https:// URL",
            ));
        }
        if !is_email(&contact_email) {
            return Err(AppError::validation("contact_email is not a valid email"));
        }
        if domains.is_empty() {
            return Err(AppError::validation("at least one domain is required"));
        }
        for domain in &domains {
            if !is_domain(domain) {
                return Err(AppError::validation(format!("invalid domain: {domain:?}")));
            }
        }
        if !req.terms_agreed {
            return Err(AppError::validation(
                "you must agree to the CA terms of service to enable ACME",
            ));
        }
    }

    Ok(AcmeConfig {
        enabled: req.enabled,
        directory_url,
        contact_email,
        domains,
        terms_agreed: req.terms_agreed,
        renewal_days,
    })
}

/// Minimal email sanity check: a single `@` with non-empty local part and a
/// dotted domain, no spaces or control characters.
fn is_email(value: &str) -> bool {
    let mut parts = value.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty()
        && !value.chars().any(|c| c.is_whitespace() || c.is_control())
        && is_domain(domain)
}

/// Whether `value` is a syntactically valid DNS hostname (letters, digits,
/// hyphens per label; dot-separated; no wildcard, scheme, or path).
fn is_domain(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || !value.contains('.') {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// Whether a certificate expiring at `expires_at` (RFC-3339) should be renewed
/// now, i.e. fewer than `renewal_days` remain from `now`.
fn should_renew(expires_at: &str, renewal_days: u32, now: DateTime<Utc>) -> bool {
    match DateTime::parse_from_rfc3339(expires_at) {
        Ok(exp) => {
            let threshold = exp.with_timezone(&Utc) - chrono::Duration::days(renewal_days as i64);
            now >= threshold
        }
        // An unparseable expiry is treated as due so we recover by re-issuing.
        Err(_) => true,
    }
}

/// Extract (not_before, not_after) as RFC-3339 strings from the leaf of a PEM
/// certificate chain.
fn parse_cert_validity(pem_chain: &str) -> ApiResult<(String, String)> {
    use x509_parser::prelude::*;
    let (_, pem) = parse_x509_pem(pem_chain.as_bytes())
        .map_err(|e| AppError::internal(format!("parse issued cert pem: {e}")))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| AppError::internal(format!("parse issued cert: {e}")))?;
    let to_rfc3339 = |t: ASN1Time| -> ApiResult<String> {
        DateTime::<Utc>::from_timestamp(t.timestamp(), 0)
            .map(|dt| dt.to_rfc3339())
            .ok_or_else(|| AppError::internal("certificate validity timestamp out of range"))
    };
    let validity = cert.validity();
    Ok((
        to_rfc3339(validity.not_before)?,
        to_rfc3339(validity.not_after)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(enabled: bool, domains: &[&str]) -> UpdateAcmeConfigRequest {
        UpdateAcmeConfigRequest {
            enabled,
            directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".to_string(),
            contact_email: "admin@example.com".to_string(),
            domains: domains.iter().map(|d| d.to_string()).collect(),
            terms_agreed: true,
            renewal_days: None,
        }
    }

    #[test]
    fn valid_config_is_accepted_and_normalized() {
        let cfg = validate_config(req(true, &["Node.Example.COM", " "])).unwrap();
        assert_eq!(cfg.domains, vec!["node.example.com".to_string()]);
        assert_eq!(cfg.renewal_days, DEFAULT_RENEWAL_DAYS);
        assert!(cfg.enabled);
    }

    #[test]
    fn enabling_requires_domain_email_tos_and_https() {
        // No domains.
        assert!(validate_config(req(true, &[])).is_err());
        // Not agreed to TOS.
        let mut r = req(true, &["node.example.com"]);
        r.terms_agreed = false;
        assert!(validate_config(r).is_err());
        // Bad email.
        let mut r = req(true, &["node.example.com"]);
        r.contact_email = "notanemail".to_string();
        assert!(validate_config(r).is_err());
        // Non-https directory.
        let mut r = req(true, &["node.example.com"]);
        r.directory_url = "http://insecure/directory".to_string();
        assert!(validate_config(r).is_err());
        // Out-of-range renewal window.
        let mut r = req(true, &["node.example.com"]);
        r.renewal_days = Some(200);
        assert!(validate_config(r).is_err());
        // Invalid domain.
        assert!(validate_config(req(true, &["-bad-.example.com"])).is_err());
        assert!(validate_config(req(true, &["no-dot"])).is_err());
    }

    #[test]
    fn disabled_config_skips_strict_validation() {
        // A disabled config can be saved with empty fields (e.g. turning ACME
        // off) without tripping the enable-time requirements.
        let mut r = req(false, &[]);
        r.contact_email = String::new();
        r.terms_agreed = false;
        let cfg = validate_config(r).unwrap();
        assert!(!cfg.enabled);
    }

    #[test]
    fn domain_and_email_validators() {
        assert!(is_domain("example.com"));
        assert!(is_domain("a.b.c.example.com"));
        assert!(!is_domain("example"));
        assert!(!is_domain("-lead.example.com"));
        assert!(!is_domain("trail-.example.com"));
        assert!(!is_domain("has space.com"));
        assert!(is_email("admin@example.com"));
        assert!(!is_email("admin@localhost"));
        assert!(!is_email("two@@example.com"));
        assert!(!is_email("no-at-sign.com"));
    }

    #[test]
    fn renewal_is_due_inside_the_window() {
        let now = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        // Expires in 10 days, window is 30 → due.
        assert!(should_renew("2026-01-11T00:00:00Z", 30, now));
        // Expires in 60 days, window is 30 → not due.
        assert!(!should_renew("2026-03-02T00:00:00Z", 30, now));
        // Unparseable → treated as due (recover by re-issuing).
        assert!(should_renew("not-a-date", 30, now));
    }
}
