//! Scheduled snapshots with retention.
//!
//! A [`SnapshotSchedule`] captures a snapshot of one guest on a cron timetable
//! and prunes older automatic snapshots so at most `keep` are retained. Records
//! persist (JSON store) so schedules survive a restart, and a background tick
//! fires due schedules. Automatic snapshots are named `auto-<timestamp>` so
//! retention only ever removes snapshots this feature created - manual
//! snapshots are never touched. Cron is standard 5-field, evaluated in UTC.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use croner::Cron;
use daygleve_schema::schedule::ScheduleTarget;
use daygleve_schema::snapshot_schedule::{
    CreateSnapshotScheduleRequest, SnapshotSchedule, UpdateSnapshotScheduleRequest,
};
use daygleve_schema::vm::{CreateVmSnapshotRequest, VmSnapshotType};

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::store::JsonStore;
use crate::services::{new_id, now_ts, Services};

/// Prefix marking a snapshot as created by a schedule (and thus subject to
/// retention pruning). Manual snapshots never use it.
const AUTO_PREFIX: &str = "auto-";

pub struct SnapshotScheduleService {
    store: JsonStore,
}

impl SnapshotScheduleService {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            store: JsonStore::new(&config.state_dir, "snapshot-schedules"),
        }
    }

    fn parse_cron(expr: &str) -> ApiResult<Cron> {
        Cron::new(expr)
            .parse()
            .map_err(|e| AppError::validation(format!("invalid cron expression {expr:?}: {e}")))
    }

    fn next_after(cron: &Cron, after: DateTime<Utc>) -> Option<String> {
        cron.find_next_occurrence(&after, false)
            .ok()
            .map(|t| t.to_rfc3339())
    }

    pub async fn list(&self) -> ApiResult<Vec<SnapshotSchedule>> {
        let mut schedules: Vec<SnapshotSchedule> = self.store.list().await?;
        schedules.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(schedules)
    }

    pub async fn list_for(
        &self,
        kind: ScheduleTarget,
        target_id: &str,
    ) -> ApiResult<Vec<SnapshotSchedule>> {
        Ok(self
            .list()
            .await?
            .into_iter()
            .filter(|s| s.target_kind == kind && s.target_id == target_id)
            .collect())
    }

    pub async fn get(&self, id: &str) -> ApiResult<SnapshotSchedule> {
        self.store
            .get(id)
            .await?
            .ok_or_else(|| AppError::not_found(format!("snapshot schedule {id}")))
    }

    pub async fn create(&self, req: CreateSnapshotScheduleRequest) -> ApiResult<SnapshotSchedule> {
        let cron = Self::parse_cron(&req.cron)?;
        let schedule = SnapshotSchedule {
            id: new_id(),
            target_kind: req.target_kind,
            target_id: req.target_id,
            cron: req.cron.trim().to_string(),
            keep: req.keep,
            enabled: req.enabled,
            description: normalize_description(req.description),
            last_run_at: None,
            last_result: None,
            next_run_at: if req.enabled {
                Self::next_after(&cron, Utc::now())
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
        req: UpdateSnapshotScheduleRequest,
    ) -> ApiResult<SnapshotSchedule> {
        let mut schedule = self.get(id).await?;
        let mut cron_changed = false;
        if let Some(cron) = req.cron {
            Self::parse_cron(&cron)?;
            schedule.cron = cron.trim().to_string();
            cron_changed = true;
        }
        if let Some(keep) = req.keep {
            schedule.keep = keep;
        }
        if let Some(enabled) = req.enabled {
            schedule.enabled = enabled;
        }
        if let Some(description) = req.description {
            schedule.description = normalize_description(Some(description));
        }
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

    /// Spawn the background evaluator (30s tick).
    pub fn start_scheduler(self: &Arc<Self>, services: Arc<Services>) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            loop {
                tick.tick().await;
                if let Err(e) = this.run_due(&services).await {
                    tracing::warn!(error = ?e, "snapshot schedule evaluation failed");
                }
            }
        });
    }

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
            let result = capture_and_prune(services, &schedule, now).await;
            tracing::info!(
                schedule = %schedule.id,
                target = %schedule.target_id,
                result = %result,
                "snapshot schedule fired"
            );
            if result.starts_with("error") {
                services
                    .notifications
                    .notify(
                        daygleve_schema::notification::NotificationEvent::SnapshotFailed,
                        "Scheduled snapshot failed".to_string(),
                        format!(
                            "Scheduled snapshot of {} failed: {}",
                            schedule.target_id, result
                        ),
                    )
                    .await;
            }
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

/// Capture an `auto-<timestamp>` snapshot of the guest and prune older automatic
/// snapshots beyond the schedule's `keep`. Returns a short outcome string.
async fn capture_and_prune(
    services: &Services,
    schedule: &SnapshotSchedule,
    now: DateTime<Utc>,
) -> String {
    let name = format!("{AUTO_PREFIX}{}", now.format("%Y%m%d-%H%M%S"));
    match schedule.target_kind {
        ScheduleTarget::Vm => {
            capture_and_prune_vm(services, &schedule.target_id, &name, schedule.keep).await
        }
        ScheduleTarget::Lxc => {
            capture_and_prune_lxc(services, &schedule.target_id, &name, schedule.keep).await
        }
    }
}

async fn capture_and_prune_vm(services: &Services, id: &str, name: &str, keep: u32) -> String {
    let req = CreateVmSnapshotRequest {
        name: name.to_string(),
        description: Some("scheduled snapshot".to_string()),
        snapshot_type: VmSnapshotType::Disk,
    };
    if let Err(e) = services.kvm.create_snapshot(id, req).await {
        return format!("error: {}", e.message());
    }
    // Prune: keep the newest `keep` automatic snapshots.
    if keep == 0 {
        return "ok".to_string();
    }
    let snapshots = match services.kvm.list_snapshots(id).await {
        Ok(s) => s,
        Err(e) => return format!("ok (prune failed: {})", e.message()),
    };
    let mut autos: Vec<String> = snapshots
        .into_iter()
        .map(|s| s.name)
        .filter(|n| n.starts_with(AUTO_PREFIX))
        .collect();
    // Names embed a sortable timestamp, so lexical descending == newest first.
    autos.sort();
    autos.reverse();
    let mut pruned = 0u32;
    for old in autos.into_iter().skip(keep as usize) {
        if services.kvm.delete_snapshot(id, &old).await.is_ok() {
            pruned += 1;
        }
    }
    if pruned > 0 {
        format!("ok (pruned {pruned})")
    } else {
        "ok".to_string()
    }
}

async fn capture_and_prune_lxc(services: &Services, id: &str, name: &str, keep: u32) -> String {
    if let Err(e) = services
        .lxc
        .snapshot(id, name, Some("scheduled snapshot"))
        .await
    {
        return format!("error: {}", e.message());
    }
    if keep == 0 {
        return "ok".to_string();
    }
    let snapshots = match services.lxc.list_snapshots(id).await {
        Ok(s) => s,
        Err(e) => return format!("ok (prune failed: {})", e.message()),
    };
    let mut autos: Vec<String> = snapshots
        .into_iter()
        .map(|s| s.name)
        .filter(|n| n.starts_with(AUTO_PREFIX))
        .collect();
    autos.sort();
    autos.reverse();
    let mut pruned = 0u32;
    for old in autos.into_iter().skip(keep as usize) {
        if services.lxc.delete_snapshot(id, &old).await.is_ok() {
            pruned += 1;
        }
    }
    if pruned > 0 {
        format!("ok (pruned {pruned})")
    } else {
        "ok".to_string()
    }
}

fn normalize_description(description: Option<String>) -> Option<String> {
    description
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
        .map(|d| d.chars().take(256).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc() -> SnapshotScheduleService {
        let dir = std::env::temp_dir().join(format!("daygleve-snapsched-test-{}", new_id()));
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
        SnapshotScheduleService::new(config)
    }

    fn req(cron: &str, keep: u32) -> CreateSnapshotScheduleRequest {
        CreateSnapshotScheduleRequest {
            target_kind: ScheduleTarget::Vm,
            target_id: "vm-1".to_string(),
            cron: cron.to_string(),
            keep,
            enabled: true,
            description: None,
        }
    }

    #[tokio::test]
    async fn create_computes_next_run_and_rejects_bad_cron() {
        let s = svc();
        let created = s.create(req("0 3 * * *", 7)).await.unwrap();
        assert_eq!(created.keep, 7);
        assert!(created.next_run_at.is_some());
        assert!(s.create(req("nope", 1)).await.is_err());
    }

    #[tokio::test]
    async fn update_changes_retention_and_timetable() {
        let s = svc();
        let created = s.create(req("0 3 * * *", 7)).await.unwrap();
        let updated = s
            .update(
                &created.id,
                UpdateSnapshotScheduleRequest {
                    cron: Some("0 4 * * 0".to_string()),
                    keep: Some(3),
                    enabled: None,
                    description: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.keep, 3);
        assert_eq!(updated.cron, "0 4 * * 0");
        assert!(updated.next_run_at.is_some());
    }

    #[tokio::test]
    async fn list_for_filters_by_target() {
        let s = svc();
        s.create(req("0 0 * * *", 1)).await.unwrap();
        let mut other = req("0 0 * * *", 1);
        other.target_id = "vm-2".to_string();
        s.create(other).await.unwrap();
        let for_one = s.list_for(ScheduleTarget::Vm, "vm-1").await.unwrap();
        assert_eq!(for_one.len(), 1);
    }
}
