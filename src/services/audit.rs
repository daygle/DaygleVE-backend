//! Security audit log.
//!
//! A persisted, append-only record of security-relevant control-plane actions
//! (authentication, account/role changes, API-token and TLS/ACME operations).
//! Events are emitted by the API layer via [`AuditService::record`] where the
//! acting caller is known, and read back newest-first by administrators. The
//! log is capped: once it exceeds [`MAX_EVENTS`], the oldest entries are pruned
//! so it cannot grow without bound.
//!
//! Records are written through [`JsonStore`], which already resolves its
//! directory through a canonicalize barrier, so no request-controlled string
//! reaches a filesystem sink here.

use std::sync::Arc;

use daygleve_schema::audit::{AuditEvent, AuditOutcome};

use crate::config::Config;
use crate::error::ApiResult;
use crate::services::store::JsonStore;
use crate::services::{new_id, now_ts};

/// Maximum number of audit events retained; older events are pruned on write.
const MAX_EVENTS: usize = 5000;

/// A new audit event to record. `id` and timestamp are assigned by the service.
#[derive(Debug, Clone)]
pub struct NewAuditEvent {
    pub actor_id: Option<String>,
    pub actor: String,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub outcome: AuditOutcome,
    pub message: Option<String>,
    pub source_ip: Option<String>,
}

impl Default for NewAuditEvent {
    fn default() -> Self {
        Self {
            actor_id: None,
            actor: "system".to_string(),
            action: String::new(),
            resource_type: None,
            resource_id: None,
            outcome: AuditOutcome::Success,
            message: None,
            source_ip: None,
        }
    }
}

/// Records and serves the audit log.
pub struct AuditService {
    store: JsonStore,
}

impl AuditService {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            store: JsonStore::new(&config.state_dir, "audit"),
        }
    }

    /// Append an event to the log. Best-effort: a persistence failure is logged
    /// but never propagated, so auditing can never break the audited action.
    pub async fn record(&self, event: NewAuditEvent) {
        let record = AuditEvent {
            id: new_id(),
            at: now_ts(),
            actor_id: event.actor_id,
            actor: event.actor,
            action: event.action,
            resource_type: event.resource_type,
            resource_id: event.resource_id,
            outcome: event.outcome,
            message: event.message,
            source_ip: event.source_ip,
        };
        if let Err(e) = self.store.put(&record.id, &record).await {
            tracing::warn!(error = %e.message(), action = %record.action, "failed to persist audit event");
            return;
        }
        self.prune().await;
    }

    /// The most recent `limit` events, newest first.
    pub async fn list(&self, limit: usize) -> ApiResult<Vec<AuditEvent>> {
        let mut events: Vec<AuditEvent> = self.store.list().await?;
        events.sort_by(|a, b| b.at.cmp(&a.at));
        events.truncate(limit);
        Ok(events)
    }

    /// Drop the oldest events beyond [`MAX_EVENTS`]. Best-effort.
    async fn prune(&self) {
        let mut events: Vec<AuditEvent> = match self.store.list().await {
            Ok(e) => e,
            Err(_) => return,
        };
        if events.len() <= MAX_EVENTS {
            return;
        }
        // Oldest first, then delete the overflow.
        events.sort_by(|a, b| a.at.cmp(&b.at));
        let overflow = events.len() - MAX_EVENTS;
        for stale in events.into_iter().take(overflow) {
            let _ = self.store.delete(&stale.id).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc() -> AuditService {
        let dir = std::env::temp_dir().join(format!("daygleve-audit-{}", new_id()));
        let config = Config {
            state_dir: dir,
            ..Config::from_env()
        };
        AuditService::new(Arc::new(config))
    }

    #[tokio::test]
    async fn records_and_lists_newest_first() {
        let s = svc();
        s.record(NewAuditEvent {
            actor: "alice".to_string(),
            action: "auth.login".to_string(),
            ..Default::default()
        })
        .await;
        // Ensure a distinct, later timestamp for the second event.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        s.record(NewAuditEvent {
            actor: "alice".to_string(),
            action: "user.create".to_string(),
            outcome: AuditOutcome::Success,
            resource_type: Some("user".to_string()),
            resource_id: Some("u2".to_string()),
            ..Default::default()
        })
        .await;

        let events = s.list(10).await.unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].action, "user.create");
        assert_eq!(events[1].action, "auth.login");
        assert_eq!(events[0].resource_id.as_deref(), Some("u2"));
    }

    #[tokio::test]
    async fn list_honors_the_limit() {
        let s = svc();
        for i in 0..5 {
            s.record(NewAuditEvent {
                actor: "sys".to_string(),
                action: format!("test.{i}"),
                ..Default::default()
            })
            .await;
        }
        assert_eq!(s.list(3).await.unwrap().len(), 3);
    }
}
