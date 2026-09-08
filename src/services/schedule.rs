//! Scheduled guest power actions.
//!
//! A [`PowerSchedule`] fires a power action against one guest on a cron
//! timetable. Records are persisted (JSON store) so schedules survive a
//! restart, and a background tick evaluates due schedules and drives the
//! existing power path. Cron expressions are standard 5-field and evaluated in
//! UTC.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use croner::Cron;
use daygleve_schema::lxc::LxcPowerAction;
use daygleve_schema::schedule::{
    CreatePowerScheduleRequest, PowerSchedule, PowerScheduleAction, ScheduleTarget,
    UpdatePowerScheduleRequest,
};
use daygleve_schema::vm::VmPowerAction;

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::store::JsonStore;
use crate::services::{new_id, now_ts, Services};

pub struct ScheduleService {
    store: JsonStore,
}

impl ScheduleService {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            store: JsonStore::new(&config.state_dir, "schedules"),
        }
    }

    /// Parse and validate a 5-field cron expression.
    fn parse_cron(expr: &str) -> ApiResult<Cron> {
        Cron::new(expr)
            .parse()
            .map_err(|e| AppError::validation(format!("invalid cron expression {expr:?}: {e}")))
    }

    /// Next firing strictly after `after`, as an RFC-3339 UTC string.
    fn next_after(cron: &Cron, after: DateTime<Utc>) -> Option<String> {
        cron.find_next_occurrence(&after, false)
            .ok()
            .map(|t| t.to_rfc3339())
    }

    /// All schedules, newest first.
    pub async fn list(&self) -> ApiResult<Vec<PowerSchedule>> {
        let mut schedules: Vec<PowerSchedule> = self.store.list().await?;
        schedules.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(schedules)
    }

    /// Schedules targeting a specific guest.
    pub async fn list_for(
        &self,
        kind: ScheduleTarget,
        target_id: &str,
    ) -> ApiResult<Vec<PowerSchedule>> {
        Ok(self
            .list()
            .await?
            .into_iter()
            .filter(|s| s.target_kind == kind && s.target_id == target_id)
            .collect())
    }

    pub async fn get(&self, id: &str) -> ApiResult<PowerSchedule> {
        self.store
            .get(id)
            .await?
            .ok_or_else(|| AppError::not_found(format!("schedule {id}")))
    }

    pub async fn create(&self, req: CreatePowerScheduleRequest) -> ApiResult<PowerSchedule> {
        let cron = Self::parse_cron(&req.cron)?;
        let now = Utc::now();
        let schedule = PowerSchedule {
            id: new_id(),
            target_kind: req.target_kind,
            target_id: req.target_id,
            action: req.action,
            cron: req.cron.trim().to_string(),
            enabled: req.enabled,
            description: normalize_description(req.description),
            last_run_at: None,
            last_result: None,
            next_run_at: if req.enabled {
                Self::next_after(&cron, now)
            } else {
                None
            },
            created_at: now_ts(),
            updated_at: None,
        };
        self.store.put(&schedule.id, &schedule).await?;
        Ok(schedule)
    }

    pub async fn update(
        &self,
        id: &str,
        req: UpdatePowerScheduleRequest,
    ) -> ApiResult<PowerSchedule> {
        let mut schedule = self.get(id).await?;
        if let Some(action) = req.action {
            schedule.action = action;
        }
        let mut cron_changed = false;
        if let Some(cron) = req.cron {
            Self::parse_cron(&cron)?;
            schedule.cron = cron.trim().to_string();
            cron_changed = true;
        }
        if let Some(enabled) = req.enabled {
            schedule.enabled = enabled;
        }
        if let Some(description) = req.description {
            schedule.description = normalize_description(Some(description));
        }
        // Recompute the next firing when the timetable changes or the schedule
        // is (re)enabled; clear it when disabled.
        if schedule.enabled {
            if cron_changed || schedule.next_run_at.is_none() {
                let cron = Self::parse_cron(&schedule.cron)?;
                schedule.next_run_at = Self::next_after(&cron, Utc::now());
            }
        } else {
            schedule.next_run_at = None;
        }
        schedule.updated_at = Some(now_ts());
        self.store.put(&schedule.id, &schedule).await?;
        Ok(schedule)
    }

    pub async fn delete(&self, id: &str) -> ApiResult<bool> {
        self.store.delete(id).await
    }

    /// Spawn the background evaluator. Ticks every 30s and fires any schedule
    /// whose next run is due.
    pub fn start_scheduler(self: &Arc<Self>, services: Arc<Services>) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            loop {
                tick.tick().await;
                if let Err(e) = this.run_due(&services).await {
                    tracing::warn!(error = ?e, "power schedule evaluation failed");
                }
            }
        });
    }

    /// Fire every enabled schedule whose next run is at or before now, then
    /// advance it to its next occurrence.
    async fn run_due(&self, services: &Services) -> ApiResult<()> {
        let now = Utc::now();
        for mut schedule in self.list().await? {
            if !schedule.enabled {
                continue;
            }
            let due = schedule
                .next_run_at
                .as_deref()
                .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
                .map(|t| t.with_timezone(&Utc) <= now)
                .unwrap_or(false);
            if !due {
                continue;
            }
            let result = execute(services, &schedule).await;
            tracing::info!(
                schedule = %schedule.id,
                target = %schedule.target_id,
                result = %result,
                "power schedule fired"
            );
            schedule.last_run_at = Some(now_ts());
            schedule.last_result = Some(result);
            schedule.next_run_at = match Self::parse_cron(&schedule.cron) {
                Ok(cron) => Self::next_after(&cron, now),
                Err(_) => None,
            };
            self.store.put(&schedule.id, &schedule).await?;
        }
        Ok(())
    }
}

/// Run one schedule's power action against its guest, returning a short outcome
/// string (`ok` or an error summary) recorded on the schedule.
async fn execute(services: &Services, schedule: &PowerSchedule) -> String {
    let outcome = match schedule.target_kind {
        ScheduleTarget::Vm => {
            let action = match schedule.action {
                PowerScheduleAction::Start => VmPowerAction::Start,
                PowerScheduleAction::Shutdown => VmPowerAction::Shutdown,
                PowerScheduleAction::Reboot => VmPowerAction::Reboot,
            };
            services
                .kvm
                .power(&schedule.target_id, action)
                .await
                .map(|_| ())
        }
        ScheduleTarget::Lxc => {
            let action = match schedule.action {
                PowerScheduleAction::Start => LxcPowerAction::Start,
                PowerScheduleAction::Shutdown => LxcPowerAction::Stop,
                PowerScheduleAction::Reboot => LxcPowerAction::Restart,
            };
            services
                .lxc
                .power(&schedule.target_id, action)
                .await
                .map(|_| ())
        }
    };
    match outcome {
        Ok(()) => "ok".to_string(),
        Err(e) => format!("error: {}", e.message()),
    }
}

/// Trim a description, dropping it when empty and capping its length.
fn normalize_description(description: Option<String>) -> Option<String> {
    description
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
        .map(|d| d.chars().take(256).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc() -> ScheduleService {
        let dir = std::env::temp_dir().join(format!("daygleve-sched-test-{}", new_id()));
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
        ScheduleService::new(config)
    }

    fn req(cron: &str) -> CreatePowerScheduleRequest {
        CreatePowerScheduleRequest {
            target_kind: ScheduleTarget::Vm,
            target_id: "vm-1".to_string(),
            action: PowerScheduleAction::Start,
            cron: cron.to_string(),
            enabled: true,
            description: None,
        }
    }

    #[tokio::test]
    async fn create_computes_next_run_and_rejects_bad_cron() {
        let s = svc();
        let created = s.create(req("0 18 * * 5")).await.unwrap();
        assert!(created.enabled);
        assert!(created.next_run_at.is_some());

        assert!(s.create(req("not a cron")).await.is_err());
    }

    #[tokio::test]
    async fn disabled_schedule_has_no_next_run() {
        let s = svc();
        let mut r = req("*/5 * * * *");
        r.enabled = false;
        let created = s.create(r).await.unwrap();
        assert!(!created.enabled);
        assert!(created.next_run_at.is_none());

        // Enabling it recomputes a next run.
        let updated = s
            .update(
                &created.id,
                UpdatePowerScheduleRequest {
                    action: None,
                    cron: None,
                    enabled: Some(true),
                    description: None,
                },
            )
            .await
            .unwrap();
        assert!(updated.enabled);
        assert!(updated.next_run_at.is_some());
    }

    #[tokio::test]
    async fn list_for_filters_by_target() {
        let s = svc();
        s.create(req("0 0 * * *")).await.unwrap();
        let mut other = req("0 0 * * *");
        other.target_id = "vm-2".to_string();
        s.create(other).await.unwrap();

        let for_one = s.list_for(ScheduleTarget::Vm, "vm-1").await.unwrap();
        assert_eq!(for_one.len(), 1);
        assert_eq!(for_one[0].target_id, "vm-1");
    }
}
