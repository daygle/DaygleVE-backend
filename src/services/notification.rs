//! Notification channels: deliver event alerts over email (SMTP) or an
//! outbound webhook.
//!
//! Channels are persisted as JSON records. The stored record keeps the channel
//! secret (SMTP password / webhook signing secret); it is never included in the
//! [`NotificationChannel`] view returned by the API. Other services emit events
//! through [`NotificationService::notify`], which delivers to every enabled
//! channel subscribed to that event on a detached task, so a slow or failing
//! transport never blocks the caller.

use std::sync::Arc;
use std::time::Duration;

use daygleve_schema::common::{ResourceId, Timestamp};
use daygleve_schema::notification::{
    CreateNotificationChannelRequest, EmailSettings, NotificationChannel, NotificationChannelKind,
    NotificationEvent, UpdateNotificationChannelRequest, WebhookSettings,
};
use hmac::{Hmac, Mac};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::{AsyncTransport, Message, Tokio1Executor};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::store::JsonStore;
use crate::services::{new_id, now_ts};

/// Persisted channel record - the schema view plus the write-only secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredChannel {
    id: ResourceId,
    name: String,
    kind: NotificationChannelKind,
    enabled: bool,
    events: Vec<NotificationEvent>,
    #[serde(default)]
    email: Option<EmailSettings>,
    #[serde(default)]
    webhook: Option<WebhookSettings>,
    #[serde(default)]
    secret: Option<String>,
    created_at: Timestamp,
    #[serde(default)]
    updated_at: Option<Timestamp>,
}

impl StoredChannel {
    /// The API-facing view, with the secret reduced to a presence flag.
    fn view(&self) -> NotificationChannel {
        NotificationChannel {
            id: self.id.clone(),
            name: self.name.clone(),
            kind: self.kind,
            enabled: self.enabled,
            events: self.events.clone(),
            email: self.email.clone(),
            webhook: self.webhook.clone(),
            has_secret: self.secret.is_some(),
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
        }
    }
}

pub struct NotificationService {
    store: JsonStore,
}

impl NotificationService {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            store: JsonStore::new(&config.state_dir, "notifications"),
        }
    }

    async fn stored(&self) -> ApiResult<Vec<StoredChannel>> {
        let mut channels: Vec<StoredChannel> = self.store.list().await?;
        channels.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(channels)
    }

    pub async fn list(&self) -> ApiResult<Vec<NotificationChannel>> {
        Ok(self
            .stored()
            .await?
            .iter()
            .map(StoredChannel::view)
            .collect())
    }

    async fn get_stored(&self, id: &str) -> ApiResult<StoredChannel> {
        self.store
            .get(id)
            .await?
            .ok_or_else(|| AppError::not_found(format!("notification channel {id}")))
    }

    pub async fn get(&self, id: &str) -> ApiResult<NotificationChannel> {
        Ok(self.get_stored(id).await?.view())
    }

    pub async fn create(
        &self,
        req: CreateNotificationChannelRequest,
    ) -> ApiResult<NotificationChannel> {
        let name = req.name.trim().to_string();
        if name.is_empty() {
            return Err(AppError::validation("channel name is required"));
        }
        validate_transport(req.kind, req.email.as_ref(), req.webhook.as_ref())?;
        let channel = StoredChannel {
            id: new_id(),
            name,
            kind: req.kind,
            enabled: req.enabled,
            events: dedup_events(req.events),
            email: req.email,
            webhook: req.webhook,
            secret: normalize_secret(req.secret),
            created_at: now_ts(),
            updated_at: None,
        };
        self.store.put(&channel.id, &channel).await?;
        Ok(channel.view())
    }

    pub async fn update(
        &self,
        id: &str,
        req: UpdateNotificationChannelRequest,
    ) -> ApiResult<NotificationChannel> {
        let mut channel = self.get_stored(id).await?;
        if let Some(name) = req.name {
            let name = name.trim().to_string();
            if name.is_empty() {
                return Err(AppError::validation("channel name is required"));
            }
            channel.name = name;
        }
        if let Some(enabled) = req.enabled {
            channel.enabled = enabled;
        }
        if let Some(events) = req.events {
            channel.events = dedup_events(events);
        }
        if req.email.is_some() {
            channel.email = req.email;
        }
        if req.webhook.is_some() {
            channel.webhook = req.webhook;
        }
        if let Some(secret) = req.secret {
            // An explicit empty string clears the stored secret.
            channel.secret = normalize_secret(Some(secret));
        }
        validate_transport(
            channel.kind,
            channel.email.as_ref(),
            channel.webhook.as_ref(),
        )?;
        channel.updated_at = Some(now_ts());
        self.store.put(&channel.id, &channel).await?;
        Ok(channel.view())
    }

    pub async fn delete(&self, id: &str) -> ApiResult<bool> {
        self.store.delete(id).await
    }

    /// Deliver a test message through one channel, surfacing any transport error
    /// synchronously so the UI's "send test" button can report success/failure.
    pub async fn send_test(&self, id: &str) -> ApiResult<()> {
        let channel = self.get_stored(id).await?;
        deliver(
            &channel,
            NotificationEvent::Test,
            "DaygleVE test notification",
            "This is a test notification from DaygleVE. If you received it, the channel works.",
        )
        .await
    }

    /// Emit an event to every enabled channel subscribed to it. Delivery runs on
    /// a detached task per channel; failures are logged, never propagated, so an
    /// emitting caller (a scheduler, a backup job) is never blocked or failed by
    /// a notification transport.
    pub async fn notify(&self, event: NotificationEvent, subject: String, body: String) {
        let channels = match self.stored().await {
            Ok(channels) => channels,
            Err(e) => {
                tracing::warn!(error = %e.message(), "could not read notification channels");
                return;
            }
        };
        for channel in channels {
            if !channel.enabled || !channel.events.contains(&event) {
                continue;
            }
            let subject = subject.clone();
            let body = body.clone();
            tokio::spawn(async move {
                if let Err(e) = deliver(&channel, event, &subject, &body).await {
                    tracing::warn!(
                        channel = %channel.id,
                        error = %e.message(),
                        "notification delivery failed"
                    );
                }
            });
        }
    }
}

/// Reject a channel whose transport settings don't match its kind.
fn validate_transport(
    kind: NotificationChannelKind,
    email: Option<&EmailSettings>,
    webhook: Option<&WebhookSettings>,
) -> ApiResult<()> {
    match kind {
        NotificationChannelKind::Email => {
            let email = email
                .ok_or_else(|| AppError::validation("email channel requires email settings"))?;
            if email.smtp_host.trim().is_empty() {
                return Err(AppError::validation("smtp_host is required"));
            }
            if email.from_address.trim().is_empty() {
                return Err(AppError::validation("from_address is required"));
            }
            if email.to_addresses.iter().all(|a| a.trim().is_empty()) {
                return Err(AppError::validation("at least one recipient is required"));
            }
        }
        NotificationChannelKind::Webhook => {
            let webhook = webhook
                .ok_or_else(|| AppError::validation("webhook channel requires webhook settings"))?;
            let url = webhook.url.trim();
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(AppError::validation("webhook url must be http(s)"));
            }
        }
    }
    Ok(())
}

fn dedup_events(events: Vec<NotificationEvent>) -> Vec<NotificationEvent> {
    let mut out = Vec::new();
    for e in events {
        if !out.contains(&e) {
            out.push(e);
        }
    }
    out
}

fn normalize_secret(secret: Option<String>) -> Option<String> {
    secret.filter(|s| !s.is_empty())
}

/// Deliver one message through the channel's transport.
async fn deliver(
    channel: &StoredChannel,
    event: NotificationEvent,
    subject: &str,
    body: &str,
) -> ApiResult<()> {
    match channel.kind {
        NotificationChannelKind::Email => {
            let settings = channel
                .email
                .as_ref()
                .ok_or_else(|| AppError::validation("email channel missing settings"))?;
            deliver_email(settings, channel.secret.as_deref(), subject, body).await
        }
        NotificationChannelKind::Webhook => {
            let settings = channel
                .webhook
                .as_ref()
                .ok_or_else(|| AppError::validation("webhook channel missing settings"))?;
            deliver_webhook(settings, channel.secret.as_deref(), event, subject, body).await
        }
    }
}

async fn deliver_email(
    settings: &EmailSettings,
    password: Option<&str>,
    subject: &str,
    body: &str,
) -> ApiResult<()> {
    let mut builder = Message::builder()
        .from(
            settings
                .from_address
                .parse()
                .map_err(|e| AppError::validation(format!("invalid from_address: {e}")))?,
        )
        .subject(subject)
        .header(ContentType::TEXT_PLAIN);
    for to in settings
        .to_addresses
        .iter()
        .filter(|a| !a.trim().is_empty())
    {
        builder = builder.to(to
            .parse()
            .map_err(|e| AppError::validation(format!("invalid recipient {to:?}: {e}")))?);
    }
    let message = builder
        .body(body.to_string())
        .map_err(|e| AppError::internal(format!("build email: {e}")))?;

    let mut transport = if settings.starttls {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&settings.smtp_host)
            .map_err(|e| AppError::internal(format!("smtp connect: {e}")))?
    } else {
        // Plain (or implicit-TLS-less) relay; used for a local/submission relay.
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&settings.smtp_host)
    }
    .port(settings.smtp_port)
    .timeout(Some(Duration::from_secs(20)));
    if let (Some(username), Some(password)) = (settings.smtp_username.as_ref(), password) {
        transport =
            transport.credentials(Credentials::new(username.to_string(), password.to_string()));
    }
    transport
        .build()
        .send(message)
        .await
        .map_err(|e| AppError::internal(format!("send email: {e}")))?;
    Ok(())
}

async fn deliver_webhook(
    settings: &WebhookSettings,
    secret: Option<&str>,
    event: NotificationEvent,
    subject: &str,
    body: &str,
) -> ApiResult<()> {
    let payload = serde_json::json!({
        "event": event,
        "subject": subject,
        "body": body,
        "timestamp": now_ts(),
    });
    let bytes = serde_json::to_vec(&payload)
        .map_err(|e| AppError::internal(format!("serialize webhook payload: {e}")))?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| AppError::internal(format!("build http client: {e}")))?;
    let mut request = client
        .post(settings.url.trim())
        .header("content-type", "application/json");
    if let Some(secret) = secret {
        // HMAC-SHA256 over the raw body so the receiver can verify authenticity.
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .map_err(|e| AppError::internal(format!("hmac init: {e}")))?;
        mac.update(&bytes);
        let signature = hex_encode(&mac.finalize().into_bytes());
        request = request.header("x-daygleve-signature", format!("sha256={signature}"));
    }
    let response = request
        .body(bytes)
        .send()
        .await
        .map_err(|e| AppError::internal(format!("webhook request failed: {e}")))?;
    if !response.status().is_success() {
        return Err(AppError::internal(format!(
            "webhook returned status {}",
            response.status()
        )));
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc() -> NotificationService {
        let dir = std::env::temp_dir().join(format!("daygleve-notif-test-{}", new_id()));
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
            admin_password: None,
            tls_cert: None,
            tls_key: None,
            broker_socket: None,
        });
        NotificationService::new(config)
    }

    fn webhook_req(secret: Option<&str>) -> CreateNotificationChannelRequest {
        CreateNotificationChannelRequest {
            name: "ops".to_string(),
            kind: NotificationChannelKind::Webhook,
            enabled: true,
            events: vec![
                NotificationEvent::BackupFailed,
                NotificationEvent::BackupFailed,
            ],
            email: None,
            webhook: Some(WebhookSettings {
                url: "https://example.com/hook".to_string(),
            }),
            secret: secret.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn secret_is_never_returned_but_tracked() {
        let s = svc();
        let created = s.create(webhook_req(Some("shh"))).await.unwrap();
        assert!(created.has_secret);
        // The view type has no field that could carry the secret; confirm the
        // stored record keeps it while the view only flags presence.
        let stored = s.get_stored(&created.id).await.unwrap();
        assert_eq!(stored.secret.as_deref(), Some("shh"));
        // Events de-duplicated.
        assert_eq!(created.events.len(), 1);
    }

    #[tokio::test]
    async fn rejects_mismatched_transport_and_bad_url() {
        let s = svc();
        // Webhook kind without webhook settings.
        let mut bad = webhook_req(None);
        bad.webhook = None;
        assert!(s.create(bad).await.is_err());
        // Bad URL scheme.
        let mut bad_url = webhook_req(None);
        bad_url.webhook = Some(WebhookSettings {
            url: "ftp://nope".to_string(),
        });
        assert!(s.create(bad_url).await.is_err());
    }

    #[tokio::test]
    async fn update_clears_secret_with_empty_string() {
        let s = svc();
        let created = s.create(webhook_req(Some("shh"))).await.unwrap();
        let updated = s
            .update(
                &created.id,
                UpdateNotificationChannelRequest {
                    name: None,
                    enabled: None,
                    events: None,
                    email: None,
                    webhook: None,
                    secret: Some(String::new()),
                },
            )
            .await
            .unwrap();
        assert!(!updated.has_secret);
    }
}
