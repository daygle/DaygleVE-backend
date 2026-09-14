//! Metric-threshold alert rules: evaluate collected metrics against
//! user-defined thresholds and fire notifications through the channel system.
//!
//! Rules are persisted JSON records (same store pattern as notification
//! channels). [`AlertService::evaluate`] runs on the background metrics tick,
//! after [`MetricsService::collect_guests`] has refreshed the current-sample
//! view. A rule fires when its metric stays at or above the threshold for
//! `sustain_ticks` consecutive evaluations, and re-fires no more often than
//! `cooldown_secs`.

use std::collections::HashMap;
use std::sync::Arc;

use daygleve_schema::notification::{
    AlertMetric, AlertRule, AlertScope, CreateAlertRuleRequest, NotificationEvent,
    UpdateAlertRuleRequest,
};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::notification::NotificationService;
use crate::services::store::JsonStore;
use crate::services::{ensure_safe_id, new_id, now_ts};

/// One in-flight observation chain for a (rule, subject) pair. The subject is
/// the guest id, or `"pool:<name>"` for pool-capacity rules.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct BreachState {
    /// Consecutive evaluations at or above the threshold.
    ticks: u32,
    /// Last time a notification was sent for this chain (RFC-3339), if any.
    last_fired_at: Option<String>,
}

pub struct AlertService {
    store: JsonStore,
    notifications: Arc<NotificationService>,
    /// In-memory breach state keyed by `"<rule_id>|<subject>"`. Not persisted:
    /// a backend restart resets sustain streaks (the next sustained breach
    /// re-fires), which is the safe direction for an alerting system.
    breach: tokio::sync::Mutex<HashMap<String, BreachState>>,
}

/// Input observations for one evaluation tick.
pub struct Observations<'a> {
    /// Latest per-VM samples.
    pub vms: &'a [daygleve_schema::metrics::GuestMetrics],
    /// Latest per-container samples.
    pub containers: &'a [daygleve_schema::metrics::GuestMetrics],
    pub node_cpu_pct: f64,
    pub node_memory_used: u64,
    pub node_memory_total: u64,
    /// `(pool name, allocated, size)` per pool.
    pub pools: &'a [(String, u64, u64)],
}

impl AlertService {
    pub fn new(config: Arc<Config>, notifications: Arc<NotificationService>) -> Self {
        Self {
            store: JsonStore::new(&config.state_dir, "alert_rules"),
            notifications,
            breach: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    // --- rule CRUD ---------------------------------------------------------

    pub async fn list(&self) -> ApiResult<Vec<AlertRule>> {
        let mut rules: Vec<AlertRule> = self.store.list().await?;
        rules.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(rules)
    }

    pub async fn get(&self, id: &str) -> ApiResult<AlertRule> {
        self.get_stored(id).await
    }

    async fn get_stored(&self, id: &str) -> ApiResult<AlertRule> {
        self.store
            .get(id)
            .await?
            .ok_or_else(|| AppError::not_found(format!("alert rule {id} not found")))
    }

    pub async fn create(&self, req: CreateAlertRuleRequest) -> ApiResult<AlertRule> {
        validate_rule(
            &req.name,
            req.scope,
            req.guest_id.as_deref(),
            req.metric,
            req.threshold,
        )?;
        let rule = AlertRule {
            id: new_id(),
            name: req.name.trim().to_string(),
            enabled: req.enabled,
            scope: req.scope,
            guest_id: req.guest_id,
            metric: req.metric,
            threshold: req.threshold,
            sustain_ticks: req.sustain_ticks,
            cooldown_secs: req.cooldown_secs,
            created_at: now_ts(),
            updated_at: None,
        };
        self.store.put(&rule.id, &rule).await?;
        Ok(rule)
    }

    pub async fn update(&self, id: &str, req: UpdateAlertRuleRequest) -> ApiResult<AlertRule> {
        let mut rule = self.get_stored(id).await?;
        if let Some(name) = req.name {
            let name = name.trim().to_string();
            if name.is_empty() {
                return Err(AppError::validation("rule name is required"));
            }
            rule.name = name;
        }
        if let Some(enabled) = req.enabled {
            rule.enabled = enabled;
        }
        if let Some(guest_id) = req.guest_id {
            if let Some(id) = guest_id.as_deref() {
                ensure_safe_id(id)?;
            }
            rule.guest_id = guest_id;
        }
        if let Some(metric) = req.metric {
            rule.metric = metric;
        }
        if let Some(threshold) = req.threshold {
            rule.threshold = threshold;
        }
        if let Some(sustain) = req.sustain_ticks {
            rule.sustain_ticks = sustain;
        }
        if let Some(cooldown) = req.cooldown_secs {
            rule.cooldown_secs = cooldown;
        }
        validate_rule(
            &rule.name,
            rule.scope,
            rule.guest_id.as_deref(),
            rule.metric,
            rule.threshold,
        )?;
        rule.updated_at = Some(now_ts());
        self.store.put(&rule.id, &rule).await?;
        Ok(rule)
    }

    pub async fn delete(&self, id: &str) -> ApiResult<bool> {
        let deleted = self.store.delete(id).await?;
        if deleted {
            let mut breach = self.breach.lock().await;
            let prefix = format!("{id}|");
            breach.retain(|key, _| !key.starts_with(&prefix));
        }
        Ok(deleted)
    }

    // --- evaluation ---------------------------------------------------------

    /// Evaluate every enabled rule against the latest samples. Returns the
    /// number of notifications fired. Must be awaited on the background tick
    /// only - it mutates shared breach state.
    pub async fn evaluate(&self, obs: &Observations<'_>) -> ApiResult<usize> {
        let rules: Vec<AlertRule> = self.list().await?;
        let mut fired = 0usize;
        for rule in rules.iter().filter(|r| r.enabled) {
            let subjects = matching_subjects(rule, obs);
            for subject in subjects {
                let Some(value) = observe(rule, &subject, obs) else {
                    continue;
                };
                if self.record_and_maybe_fire(rule, &subject, value).await? {
                    fired += 1;
                }
            }
        }
        Ok(fired)
    }

    /// Advance the sustain counter for one observation and fire when the streak
    /// is long enough and the cooldown has elapsed.
    async fn record_and_maybe_fire(
        &self,
        rule: &AlertRule,
        subject: &str,
        value: f64,
    ) -> ApiResult<bool> {
        let key = format!("{}|{subject}", rule.id);
        let breached = value >= rule.threshold;
        let mut breach = self.breach.lock().await;
        let entry = breach.entry(key).or_default();
        if !breached {
            entry.ticks = 0;
            return Ok(false);
        }
        entry.ticks += 1;
        if entry.ticks < rule.sustain_ticks.max(1) {
            return Ok(false);
        }
        // Cooldown gate: compare against the last fire time for this chain.
        if let Some(last) = entry.last_fired_at.as_deref() {
            if !cooldown_elapsed(last, rule.cooldown_secs) {
                return Ok(false);
            }
        }
        entry.last_fired_at = Some(now_ts());
        let body = format!(
            "{} is at {:.1} (threshold {:.1}, sustained {} ticks).",
            describe_subject(subject),
            value,
            rule.threshold,
            entry.ticks
        );
        // Do not hold the breach lock across notification dispatch.
        let rule_id = rule.id.clone();
        let rule_name = rule.name.clone();
        drop(breach);
        self.notifications
            .notify(
                NotificationEvent::ThresholdBreached,
                format!("alert `{rule_name}` breached"),
                body,
            )
            .await;
        // The notify call is fire-and-forget per channel; nothing to await.
        let _ = rule_id;
        Ok(true)
    }
}

/// Guests (or pools) a rule applies to on this tick, as subject identifiers.
fn matching_subjects(rule: &AlertRule, obs: &Observations<'_>) -> Vec<String> {
    match rule.scope {
        AlertScope::Node => {
            if matches!(rule.metric, AlertMetric::PoolUsedPct) {
                match &rule.guest_id {
                    // A pool rule pinned to one pool name watches only that pool.
                    Some(name) => vec![format!("pool:{name}")],
                    None => obs
                        .pools
                        .iter()
                        .map(|(name, _, _)| format!("pool:{name}"))
                        .collect(),
                }
            } else {
                vec!["node".to_string()]
            }
        }
        AlertScope::Vm => match &rule.guest_id {
            Some(id) => vec![id.clone()],
            None => obs.vms.iter().map(|m| m.id.clone()).collect(),
        },
        AlertScope::Lxc => match &rule.guest_id {
            Some(id) => vec![id.clone()],
            None => obs.containers.iter().map(|m| m.id.clone()).collect(),
        },
    }
}

/// The observed value for one (rule, subject), or `None` when no fresh sample
/// exists (a stopped guest, a missing pool) - the rule silently skips.
fn observe(rule: &AlertRule, subject: &str, obs: &Observations<'_>) -> Option<f64> {
    fn guest<'a>(
        samples: &'a [daygleve_schema::metrics::GuestMetrics],
        subject: &str,
    ) -> Option<&'a daygleve_schema::metrics::GuestMetrics> {
        samples.iter().find(|m| m.id == subject)
    }
    match rule.metric {
        AlertMetric::CpuPct => match rule.scope {
            AlertScope::Node => Some(obs.node_cpu_pct),
            AlertScope::Vm => guest(obs.vms, subject).map(|m| m.cpu_pct),
            AlertScope::Lxc => guest(obs.containers, subject).map(|m| m.cpu_pct),
        },
        AlertMetric::MemoryPct => match rule.scope {
            AlertScope::Node => {
                if obs.node_memory_total == 0 {
                    None
                } else {
                    Some(obs.node_memory_used as f64 / obs.node_memory_total as f64 * 100.0)
                }
            }
            AlertScope::Vm => guest(obs.vms, subject).map(memory_pct),
            AlertScope::Lxc => guest(obs.containers, subject).map(memory_pct),
        },
        AlertMetric::DiskReadMibS => match rule.scope {
            AlertScope::Node => None,
            AlertScope::Vm => guest(obs.vms, subject)
                .map(|m| m.disk_read_bps)
                .map(bps_to_mib),
            AlertScope::Lxc => guest(obs.containers, subject)
                .map(|m| m.disk_read_bps)
                .map(bps_to_mib),
        },
        AlertMetric::DiskWriteMibS => match rule.scope {
            AlertScope::Node => None,
            AlertScope::Vm => guest(obs.vms, subject)
                .map(|m| m.disk_write_bps)
                .map(bps_to_mib),
            AlertScope::Lxc => guest(obs.containers, subject)
                .map(|m| m.disk_write_bps)
                .map(bps_to_mib),
        },
        AlertMetric::NetRxMibS => match rule.scope {
            AlertScope::Node => None,
            AlertScope::Vm => guest(obs.vms, subject)
                .map(|m| m.net_rx_bps)
                .map(bps_to_mib),
            AlertScope::Lxc => guest(obs.containers, subject)
                .map(|m| m.net_rx_bps)
                .map(bps_to_mib),
        },
        AlertMetric::NetTxMibS => match rule.scope {
            AlertScope::Node => None,
            AlertScope::Vm => guest(obs.vms, subject)
                .map(|m| m.net_tx_bps)
                .map(bps_to_mib),
            AlertScope::Lxc => guest(obs.containers, subject)
                .map(|m| m.net_tx_bps)
                .map(bps_to_mib),
        },
        AlertMetric::PoolUsedPct => {
            if rule.scope != AlertScope::Node {
                return None;
            }
            let name = subject.strip_prefix("pool:")?;
            obs.pools
                .iter()
                .find(|(pool, _, _)| pool == name)
                .and_then(|(_, allocated, size)| {
                    if *size == 0 {
                        None
                    } else {
                        Some(*allocated as f64 / *size as f64 * 100.0)
                    }
                })
        }
    }
}

fn memory_pct(m: &daygleve_schema::metrics::GuestMetrics) -> f64 {
    if m.memory_max_bytes == 0 {
        0.0
    } else {
        m.memory_used_bytes as f64 / m.memory_max_bytes as f64 * 100.0
    }
}

fn bps_to_mib(bps: u64) -> f64 {
    bps as f64 / (1024.0 * 1024.0)
}

fn describe_subject(subject: &str) -> String {
    if let Some(pool) = subject.strip_prefix("pool:") {
        format!("pool `{pool}`")
    } else {
        format!("guest `{subject}`")
    }
}

/// Whether `last_fired_at` (RFC-3339) is older than `cooldown` seconds.
/// Unparseable timestamps never re-fire (fail safe rather than spammy).
fn cooldown_elapsed(last_fired_at: &str, cooldown_secs: u64) -> bool {
    let Ok(last) = chrono::DateTime::parse_from_rfc3339(last_fired_at) else {
        return false;
    };
    let elapsed = chrono::Utc::now().signed_duration_since(last);
    elapsed.num_seconds() >= cooldown_secs as i64
}

fn validate_rule(
    name: &str,
    scope: AlertScope,
    guest_id: Option<&str>,
    metric: AlertMetric,
    threshold: f64,
) -> ApiResult<()> {
    if name.trim().is_empty() {
        return Err(AppError::validation("rule name is required"));
    }
    if !threshold.is_finite() || threshold < 0.0 {
        return Err(AppError::validation(
            "threshold must be a finite value >= 0",
        ));
    }
    // A pool-capacity rule only makes sense against node scope; guest metrics
    // only make sense against guest scopes.
    if matches!(metric, AlertMetric::PoolUsedPct) && scope != AlertScope::Node {
        return Err(AppError::validation(
            "pool_used_pct rules must use node scope",
        ));
    }
    if !matches!(metric, AlertMetric::PoolUsedPct) && scope == AlertScope::Node {
        return Err(AppError::validation(
            "cpu/memory/throughput rules must target vm or lxc scope; use pool_used_pct for node/pool rules",
        ));
    }
    if let Some(id) = guest_id {
        ensure_safe_id(id)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(metric: AlertMetric, threshold: f64) -> AlertRule {
        AlertRule {
            id: "r1".into(),
            name: "test".into(),
            enabled: true,
            scope: AlertScope::Vm,
            guest_id: None,
            metric,
            threshold,
            sustain_ticks: 1,
            cooldown_secs: 0,
            created_at: now_ts(),
            updated_at: None,
        }
    }

    fn sample(id: &str, cpu: f64, used: u64, max: u64) -> daygleve_schema::metrics::GuestMetrics {
        daygleve_schema::metrics::GuestMetrics {
            id: id.into(),
            timestamp: now_ts(),
            cpu_pct: cpu,
            memory_used_bytes: used,
            memory_max_bytes: max,
            disk_read_bps: 0,
            disk_write_bps: 0,
            net_rx_bps: 0,
            net_tx_bps: 0,
        }
    }

    fn obs<'a>(vms: &'a [daygleve_schema::metrics::GuestMetrics]) -> Observations<'a> {
        Observations {
            vms,
            containers: &[],
            node_cpu_pct: 0.0,
            node_memory_used: 0,
            node_memory_total: 0,
            pools: &[],
        }
    }

    #[test]
    fn observes_guest_cpu_and_memory_pct() {
        let vms = vec![sample("vm1", 90.0, 3_000_000_000, 4_000_000_000)];
        let o = obs(&vms);
        let r = rule(AlertMetric::CpuPct, 80.0);
        assert_eq!(observe(&r, "vm1", &o), Some(90.0));
        let r = rule(AlertMetric::MemoryPct, 70.0);
        let pct = observe(&r, "vm1", &o).unwrap();
        assert!((pct - 75.0).abs() < 0.01);
        // Missing guest -> no observation.
        assert_eq!(observe(&r, "ghost", &o), None);
    }

    #[test]
    fn pool_pct_reads_named_pool() {
        let vms = vec![];
        let pools = vec![("tank".to_string(), 800u64, 1000u64)];
        let o = Observations {
            vms: &vms,
            containers: &[],
            node_cpu_pct: 0.0,
            node_memory_used: 0,
            node_memory_total: 0,
            pools: &pools,
        };
        let mut r = rule(AlertMetric::PoolUsedPct, 75.0);
        r.scope = AlertScope::Node;
        assert_eq!(observe(&r, "pool:tank", &o), Some(80.0));
        assert_eq!(observe(&r, "pool:missing", &o), None);
    }

    #[test]
    fn validation_rejects_mismatched_scope_and_metric() {
        assert!(validate_rule("n", AlertScope::Node, None, AlertMetric::CpuPct, 1.0).is_err());
        assert!(validate_rule("n", AlertScope::Vm, None, AlertMetric::PoolUsedPct, 1.0).is_err());
        assert!(validate_rule("n", AlertScope::Vm, None, AlertMetric::CpuPct, -1.0).is_err());
        assert!(validate_rule(" ", AlertScope::Vm, None, AlertMetric::CpuPct, 1.0).is_err());
        assert!(validate_rule("n", AlertScope::Vm, None, AlertMetric::CpuPct, 1.0).is_ok());
    }

    #[test]
    fn cooldown_gate_blocks_recent_fires() {
        let now = chrono::Utc::now().to_rfc3339();
        assert!(!cooldown_elapsed(&now, 300));
        let old = (chrono::Utc::now() - chrono::Duration::seconds(301)).to_rfc3339();
        assert!(cooldown_elapsed(&old, 300));
        // Garbage timestamps never re-fire.
        assert!(!cooldown_elapsed("not-a-time", 0));
    }
}
