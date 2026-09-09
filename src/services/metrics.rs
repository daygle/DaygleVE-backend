//! Metrics service: node-level resource sampling from `/proc` and `/sys`.
//!
//! Rates (CPU %, disk and network throughput) require two samples, so [`node`]
//! takes a short delta window. Counters that are absolute (memory, load,
//! uptime) are read once. On a non-Linux/dev host the pseudo-files are absent
//! and the corresponding fields read as zero.
//!
//! [`node`]: MetricsService::node

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use daygleve_schema::lxc::LxcSummary;
use daygleve_schema::metrics::{
    GuestMetrics, GuestMetricsSample, MetricsEvent, MetricsScope, NodeMetrics,
};
use daygleve_schema::vm::VmSummary;
use tokio::fs;

use crate::error::ApiResult;
use crate::services::command;
use crate::services::store::JsonStore;
use crate::services::{ensure_safe_id, new_id, now_ts};

/// Delta window for rate calculations.
const SAMPLE_WINDOW: Duration = Duration::from_millis(200);

/// How long a minted SSE stream ticket stays valid. Short: the browser mints a
/// fresh one for every (re)connection.
const STREAM_TICKET_TTL: Duration = Duration::from_secs(30);
/// Guest samples are collected often enough for dashboards but retained for a
/// bounded operational history. The JSON store keeps this dependency-free on
/// appliance installations; the API also exposes Prometheus text for external
/// long-term retention.
const GUEST_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const MAX_GUEST_SAMPLES: usize = 50_000;

/// A pending SSE stream ticket, minted for an already-authenticated caller so
/// the long-lived bearer token never has to travel in the stream URL.
struct StreamTicket {
    user_id: String,
    expires_at: Instant,
}

#[derive(Clone, Copy, Default)]
struct GuestCounters {
    cpu_time_ns: u64,
    read_bytes: u64,
    write_bytes: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    sampled_at: Option<Instant>,
}

pub struct MetricsService {
    /// The last sample and when it was taken, shared so concurrent SSE streams
    /// reuse one sampling pass instead of each paying the ~200ms window. An
    /// async mutex is held across the refresh so only one sampler runs at a
    /// time (no thundering herd of concurrent samples).
    cache: tokio::sync::Mutex<Option<(Instant, NodeMetrics)>>,
    /// Live stream tickets, keyed by the opaque ticket value.
    stream_tickets: RwLock<HashMap<String, StreamTicket>>,
    /// Durable guest history and an in-memory latest view for fast API/SSE reads.
    history: JsonStore,
    current: RwLock<HashMap<String, GuestMetricsSample>>,
    counters: tokio::sync::Mutex<HashMap<String, GuestCounters>>,
}

impl MetricsService {
    pub fn new() -> Self {
        Self {
            cache: tokio::sync::Mutex::new(None),
            stream_tickets: RwLock::new(HashMap::new()),
            history: JsonStore::new(std::path::Path::new("/var/lib/daygleve"), "metrics"),
            current: RwLock::new(HashMap::new()),
            counters: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Mint a short-lived, one-time ticket authorizing an SSE metrics stream for
    /// `user_id`. The caller must already hold `MetricsRead`; the ticket lets the
    /// browser open `EventSource` without putting its bearer token in the URL.
    /// Returns the ticket and its RFC-3339 expiry.
    pub fn mint_stream_ticket(&self, user_id: &str) -> (String, String) {
        let ticket = new_id();
        let now = Instant::now();
        {
            let mut tickets = self.stream_tickets.write().expect("stream ticket lock");
            // Opportunistically drop expired tickets so the map can't grow
            // unbounded from tickets that were minted but never redeemed.
            tickets.retain(|_, t| t.expires_at > now);
            tickets.insert(
                ticket.clone(),
                StreamTicket {
                    user_id: user_id.to_string(),
                    expires_at: now + STREAM_TICKET_TTL,
                },
            );
        }
        let expires_at = (chrono::Utc::now()
            + chrono::Duration::from_std(STREAM_TICKET_TTL).unwrap())
        .to_rfc3339();
        (ticket, expires_at)
    }

    /// Validate and consume a stream ticket, returning the user id it was minted
    /// for. One-time: the ticket is removed on success, so the browser mints a
    /// fresh one for every reconnection.
    pub fn redeem_stream_ticket(&self, ticket: &str) -> Option<String> {
        let mut tickets = self.stream_tickets.write().expect("stream ticket lock");
        match tickets.get(ticket) {
            Some(t) if t.expires_at > Instant::now() => {
                let user_id = t.user_id.clone();
                tickets.remove(ticket);
                Some(user_id)
            }
            _ => None,
        }
    }

    /// Replace the default history store with one rooted at the application
    /// state directory. `Services` calls this immediately after construction.
    pub fn with_history_dir(mut self, state_dir: &std::path::Path) -> Self {
        self.history = JsonStore::new(state_dir, "metrics");
        self
    }

    /// Latest retained/current guest samples, sorted by scope and id.
    pub fn current_guests(&self) -> Vec<GuestMetricsSample> {
        let mut samples: Vec<_> = self
            .current
            .read()
            .expect("metrics current lock")
            .values()
            .cloned()
            .collect();
        samples.sort_by(|a, b| {
            format!("{:?}:{}", a.scope, a.metrics.id)
                .cmp(&format!("{:?}:{}", b.scope, b.metrics.id))
        });
        samples
    }

    /// Read retained guest history, optionally narrowed by scope, guest, and
    /// RFC-3339 time bounds. Timestamps sort lexically because they are emitted
    /// in canonical RFC-3339 form.
    pub async fn history(
        &self,
        scope: Option<MetricsScope>,
        guest_id: Option<&str>,
        from: Option<&str>,
        to: Option<&str>,
    ) -> ApiResult<Vec<GuestMetricsSample>> {
        if let Some(id) = guest_id {
            ensure_safe_id(id)?;
        }
        let mut samples: Vec<GuestMetricsSample> = self.history.list().await?;
        samples.retain(|sample| {
            scope.is_none_or(|wanted| sample.scope == wanted)
                && guest_id.is_none_or(|id| sample.metrics.id == id)
                && from.is_none_or(|at| sample.metrics.timestamp.as_str() >= at)
                && to.is_none_or(|at| sample.metrics.timestamp.as_str() <= at)
        });
        samples.sort_by(|a, b| a.metrics.timestamp.cmp(&b.metrics.timestamp));
        Ok(samples)
    }

    /// Prometheus/OpenMetrics-compatible text export for guest samples. Values
    /// are gauges for the latest point-in-time values; external systems provide
    /// durable long-term retention by scraping this endpoint.
    pub async fn prometheus(&self) -> ApiResult<String> {
        let samples = self.current_guests();
        let mut out = String::new();
        out.push_str("# TYPE daygleve_guest_cpu_percent gauge\n");
        out.push_str("# TYPE daygleve_guest_memory_bytes gauge\n");
        for sample in samples {
            let scope = match sample.scope {
                MetricsScope::Vm => "vm",
                MetricsScope::Lxc => "lxc",
                MetricsScope::Node => continue,
            };
            let id = prometheus_label(&sample.metrics.id);
            out.push_str(&format!(
                "daygleve_guest_cpu_percent{{scope=\"{scope}\",guest_id=\"{id}\"}} {}\n",
                sample.metrics.cpu_pct
            ));
            out.push_str(&format!(
                "daygleve_guest_memory_bytes{{scope=\"{scope}\",guest_id=\"{id}\"}} {}\n",
                sample.metrics.memory_used_bytes
            ));
            out.push_str(&format!(
                "daygleve_guest_memory_max_bytes{{scope=\"{scope}\",guest_id=\"{id}\"}} {}\n",
                sample.metrics.memory_max_bytes
            ));
            out.push_str(&format!("daygleve_guest_disk_read_bytes_per_second{{scope=\"{scope}\",guest_id=\"{id}\"}} {}\n", sample.metrics.disk_read_bps));
            out.push_str(&format!("daygleve_guest_disk_write_bytes_per_second{{scope=\"{scope}\",guest_id=\"{id}\"}} {}\n", sample.metrics.disk_write_bps));
            out.push_str(&format!("daygleve_guest_network_receive_bytes_per_second{{scope=\"{scope}\",guest_id=\"{id}\"}} {}\n", sample.metrics.net_rx_bps));
            out.push_str(&format!("daygleve_guest_network_transmit_bytes_per_second{{scope=\"{scope}\",guest_id=\"{id}\"}} {}\n", sample.metrics.net_tx_bps));
        }
        Ok(out)
    }

    /// Sample all persisted guests, update the live view, and append samples to
    /// bounded history. Host tools are optional on development machines: a
    /// missing virsh/cgroup tree yields zero-valued guest counters rather than
    /// taking down the metrics loop.
    pub async fn collect_guests(
        &self,
        vms: &[VmSummary],
        containers: &[LxcSummary],
    ) -> ApiResult<Vec<MetricsEvent>> {
        let mut events = Vec::with_capacity(1 + vms.len() + containers.len());
        events.push(MetricsEvent {
            scope: MetricsScope::Node,
            node: Some(self.node().await),
            guest: None,
        });
        for vm in vms {
            let stats = vm_domstats(&vm.id).await;
            let metrics = self
                .make_guest_metrics(
                    MetricsScope::Vm,
                    &vm.id,
                    vm.memory_mib.saturating_mul(1024 * 1024),
                    vm.vcpus.max(1),
                    stats,
                )
                .await?;
            let sample = GuestMetricsSample {
                scope: MetricsScope::Vm,
                metrics: metrics.clone(),
            };
            self.record_sample(&sample).await?;
            events.push(MetricsEvent {
                scope: MetricsScope::Vm,
                node: None,
                guest: Some(metrics),
            });
        }
        for ct in containers {
            let stats = lxc_cgroup_stats(&ct.name, ct.memory_mib.saturating_mul(1024 * 1024)).await;
            let metrics = self
                .make_guest_metrics(
                    MetricsScope::Lxc,
                    &ct.id,
                    ct.memory_mib.saturating_mul(1024 * 1024),
                    ct.vcpus.max(1),
                    stats,
                )
                .await?;
            let sample = GuestMetricsSample {
                scope: MetricsScope::Lxc,
                metrics: metrics.clone(),
            };
            self.record_sample(&sample).await?;
            events.push(MetricsEvent {
                scope: MetricsScope::Lxc,
                node: None,
                guest: Some(metrics),
            });
        }
        self.prune_history().await?;
        Ok(events)
    }

    async fn make_guest_metrics(
        &self,
        scope: MetricsScope,
        id: &str,
        memory_max_bytes: u64,
        vcpus: u32,
        stats: RawGuestStats,
    ) -> ApiResult<GuestMetrics> {
        let key = format!("{:?}:{id}", scope);
        let now = Instant::now();
        let mut counters = self.counters.lock().await;
        let previous = counters.insert(
            key,
            GuestCounters {
                cpu_time_ns: stats.cpu_time_ns,
                read_bytes: stats.read_bytes,
                write_bytes: stats.write_bytes,
                rx_bytes: stats.rx_bytes,
                tx_bytes: stats.tx_bytes,
                sampled_at: Some(now),
            },
        );
        let (dt, previous) = previous
            .and_then(|p| {
                p.sampled_at
                    .map(|at| (now.duration_since(at).as_secs_f64(), p))
            })
            .unwrap_or((0.0, GuestCounters::default()));
        let per_second = |before: u64, after: u64| {
            if dt <= 0.0 {
                0
            } else {
                ((after.saturating_sub(before) as f64) / dt).round() as u64
            }
        };
        let cpu_pct = if dt > 0.0 {
            ((stats.cpu_time_ns.saturating_sub(previous.cpu_time_ns) as f64)
                / (dt * 1_000_000_000.0 * vcpus as f64)
                * 100.0)
                .clamp(0.0, 100.0)
        } else {
            0.0
        };
        Ok(GuestMetrics {
            id: id.to_string(),
            timestamp: now_ts(),
            cpu_pct,
            memory_used_bytes: stats.memory_used_bytes.min(memory_max_bytes),
            memory_max_bytes,
            disk_read_bps: per_second(previous.read_bytes, stats.read_bytes),
            disk_write_bps: per_second(previous.write_bytes, stats.write_bytes),
            net_rx_bps: per_second(previous.rx_bytes, stats.rx_bytes),
            net_tx_bps: per_second(previous.tx_bytes, stats.tx_bytes),
        })
    }

    async fn record_sample(&self, sample: &GuestMetricsSample) -> ApiResult<()> {
        let key = format!("{:?}:{}", sample.scope, sample.metrics.id);
        self.current
            .write()
            .expect("metrics current lock")
            .insert(key, sample.clone());
        self.history.put(&history_key(sample), sample).await
    }

    async fn prune_history(&self) -> ApiResult<()> {
        let mut samples: Vec<GuestMetricsSample> = self.history.list().await?;
        let cutoff = (chrono::Utc::now() - chrono::Duration::from_std(GUEST_RETENTION).unwrap())
            .to_rfc3339();
        samples.sort_by(|a, b| b.metrics.timestamp.cmp(&a.metrics.timestamp));
        for (index, sample) in samples.into_iter().enumerate() {
            if sample.metrics.timestamp < cutoff || index >= MAX_GUEST_SAMPLES {
                let _ = self.history.delete(&history_key(&sample)).await?;
            }
        }

        Ok(())
    }

    /// Current node metrics. A sample newer than `CACHE_TTL` is reused, so N
    /// connected dashboards share one sampling pass per interval rather than N.
    pub async fn node(&self) -> NodeMetrics {
        const CACHE_TTL: Duration = Duration::from_millis(1500);
        // Hold the lock across the refresh: a caller that arrives mid-sample
        // waits, then finds the just-written fresh sample instead of starting
        // its own.
        let mut guard = self.cache.lock().await;
        if let Some((at, sample)) = guard.as_ref() {
            if at.elapsed() < CACHE_TTL {
                return sample.clone();
            }
        }
        let sample = self.sample_now().await;
        *guard = Some((Instant::now(), sample.clone()));
        sample
    }

    /// Take a fresh node sample (~200ms rate window).
    async fn sample_now(&self) -> NodeMetrics {
        let disks = whole_disks().await;

        let a = Sample::take(&disks).await;
        let started = Instant::now();
        tokio::time::sleep(SAMPLE_WINDOW).await;
        let b = Sample::take(&disks).await;

        // Use the real elapsed time (sleep drift + the cost of the second read),
        // not the nominal window, so rates aren't systematically skewed.
        let dt = started.elapsed().as_secs_f64();
        let cpu_total_delta = b.cpu_total.saturating_sub(a.cpu_total);
        let cpu_busy_delta = b.cpu_busy.saturating_sub(a.cpu_busy);
        let cpu_pct = if cpu_total_delta > 0 {
            (cpu_busy_delta as f64 / cpu_total_delta as f64) * 100.0
        } else {
            0.0
        };

        let (mem_total, mem_avail, swap_total, swap_free) = meminfo().await;
        let load_average = loadavg().await;

        NodeMetrics {
            timestamp: now_ts(),
            cpu_pct,
            cpu_count: cpu_count().await,
            load_average,
            memory_total_bytes: mem_total,
            memory_used_bytes: mem_total.saturating_sub(mem_avail),
            swap_total_bytes: swap_total,
            swap_used_bytes: swap_total.saturating_sub(swap_free),
            disk_read_bps: rate(a.disk_read_sectors, b.disk_read_sectors, dt) * 512,
            disk_write_bps: rate(a.disk_write_sectors, b.disk_write_sectors, dt) * 512,
            net_rx_bps: rate(a.net_rx, b.net_rx, dt),
            net_tx_bps: rate(a.net_tx, b.net_tx, dt),
            uptime_seconds: uptime().await,
        }
    }
}

fn prometheus_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn history_key(sample: &GuestMetricsSample) -> String {
    let scope = match sample.scope {
        MetricsScope::Vm => "vm",
        MetricsScope::Lxc => "lxc",
        MetricsScope::Node => "node",
    };
    format!(
        "{}-{}-{}",
        scope,
        sample.metrics.id,
        sample
            .metrics
            .timestamp
            .replace([':', '+'], "-")
            .replace('T', "t")
    )
}

#[derive(Debug, Clone, Copy, Default)]
struct RawGuestStats {
    cpu_time_ns: u64,
    memory_used_bytes: u64,
    read_bytes: u64,
    write_bytes: u64,
    rx_bytes: u64,
    tx_bytes: u64,
}

/// Sample a libvirt domain using the stable machine-readable domstats output.
async fn vm_domstats(id: &str) -> RawGuestStats {
    let out = match command::run_optional(
        "virsh",
        &[
            "-c",
            "qemu:///system",
            "domstats",
            "--vcpu",
            "--balloon",
            "--block",
            "--interface",
            id,
        ],
    )
    .await
    {
        Ok(Some(out)) => out,
        _ => return RawGuestStats::default(),
    };
    let mut stats = RawGuestStats::default();
    for line in out.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        let value = value.trim().parse::<u64>().unwrap_or(0);
        if key.ends_with("cpu.time") {
            stats.cpu_time_ns = stats.cpu_time_ns.saturating_add(value);
        } else if key.ends_with("balloon.current") {
            stats.memory_used_bytes = value.saturating_mul(1024);
        } else if key.contains("block.") && key.ends_with("rd.bytes") {
            stats.read_bytes = stats.read_bytes.saturating_add(value);
        } else if key.contains("block.") && key.ends_with("wr.bytes") {
            stats.write_bytes = stats.write_bytes.saturating_add(value);
        } else if key.contains("net.") && key.ends_with("rx.bytes") {
            stats.rx_bytes = stats.rx_bytes.saturating_add(value);
        } else if key.contains("net.") && key.ends_with("tx.bytes") {
            stats.tx_bytes = stats.tx_bytes.saturating_add(value);
        }
    }
    stats
}

/// Sample a container's cgroup v2 counters. LXC installations differ in their
/// cgroup path, so probe the two standard layouts and fall back to v1 files.
async fn lxc_cgroup_stats(name: &str, memory_max_bytes: u64) -> RawGuestStats {
    if ensure_safe_id(name).is_err() {
        return RawGuestStats::default();
    }
    let roots = [
        std::path::PathBuf::from("/sys/fs/cgroup/lxc").join(name),
        std::path::PathBuf::from("/sys/fs/cgroup/lxc.payload").join(name),
    ];
    for root in roots {
        if fs::metadata(&root).await.is_err() {
            continue;
        }
        let memory = match read_u64_file(&root.join("memory.current")).await {
            Some(value) => Some(value),
            None => read_u64_file(&root.join("memory.usage_in_bytes")).await,
        };

        let cpu = parse_cpu_stat(&root.join("cpu.stat")).await;
        let (read_bytes, write_bytes) = parse_io_stat(&root.join("io.stat")).await;
        let (rx_bytes, tx_bytes) = container_net_bytes(name).await;
        return RawGuestStats {
            cpu_time_ns: cpu,
            memory_used_bytes: memory.unwrap_or(0).min(memory_max_bytes),
            read_bytes,
            write_bytes,
            rx_bytes,
            tx_bytes,
        };
    }
    RawGuestStats::default()
}

async fn read_u64_file(path: &std::path::Path) -> Option<u64> {
    fs::read_to_string(path).await.ok()?.trim().parse().ok()
}

async fn parse_cpu_stat(path: &std::path::Path) -> u64 {
    let text = fs::read_to_string(path).await.unwrap_or_default();
    text.lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("usage_usec"))
                .then(|| fields.next()?.parse::<u64>().ok())
                .flatten()
        })
        .unwrap_or(0)
        .saturating_mul(1000)
}

async fn parse_io_stat(path: &std::path::Path) -> (u64, u64) {
    let text = fs::read_to_string(path).await.unwrap_or_default();
    let mut read: u64 = 0;
    let mut write: u64 = 0;
    for line in text.lines() {
        for field in line.split_whitespace() {
            if let Some(value) = field.strip_prefix("rbytes=") {
                read = read.saturating_add(value.parse::<u64>().unwrap_or(0));
            }
            if let Some(value) = field.strip_prefix("wbytes=") {
                write = write.saturating_add(value.parse::<u64>().unwrap_or(0));
            }
        }
    }
    (read, write)
}

async fn container_net_bytes(name: &str) -> (u64, u64) {
    let pid = match command::run_optional("lxc-info", &["-n", name, "-pH"]).await {
        Ok(Some(value)) => value.trim().parse::<u32>().ok(),
        _ => None,
    };
    let Some(pid) = pid else {
        return (0, 0);
    };
    let text = fs::read_to_string(format!("/proc/{pid}/net/dev"))
        .await
        .unwrap_or_default();
    let mut rx: u64 = 0;
    let mut tx: u64 = 0;
    for line in text.lines().skip(2) {
        let Some((_, values)) = line.split_once(':') else {
            continue;
        };
        let fields: Vec<&str> = values.split_whitespace().collect();
        if fields.len() >= 9 {
            rx = rx.saturating_add(fields[0].parse::<u64>().unwrap_or(0));
            tx = tx.saturating_add(fields[8].parse::<u64>().unwrap_or(0));
        }
    }
    (rx, tx)
}

/// One point-in-time read of the counters that feed rate calculations.
struct Sample {
    cpu_busy: u64,
    cpu_total: u64,
    disk_read_sectors: u64,
    disk_write_sectors: u64,
    net_rx: u64,
    net_tx: u64,
}

impl Sample {
    async fn take(disks: &[String]) -> Self {
        let (cpu_busy, cpu_total) = cpu_times().await;
        let (disk_read_sectors, disk_write_sectors) = disk_sectors(disks).await;
        let (net_rx, net_tx) = net_bytes().await;
        Self {
            cpu_busy,
            cpu_total,
            disk_read_sectors,
            disk_write_sectors,
            net_rx,
            net_tx,
        }
    }
}

/// `(delta / seconds)` as a rounded integer, saturating on counter resets.
fn rate(a: u64, b: u64, secs: f64) -> u64 {
    if secs <= 0.0 {
        return 0;
    }
    (b.saturating_sub(a) as f64 / secs).round() as u64
}

/// Aggregate `(busy, total)` CPU jiffies from the `cpu` line of `/proc/stat`.
async fn cpu_times() -> (u64, u64) {
    let stat = fs::read_to_string("/proc/stat").await.unwrap_or_default();
    let Some(line) = stat.lines().find(|l| l.starts_with("cpu ")) else {
        return (0, 0);
    };
    let vals: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .map(|t| t.parse().unwrap_or(0))
        .collect();
    // user nice system idle iowait irq softirq steal ...
    let idle = vals.get(3).copied().unwrap_or(0) + vals.get(4).copied().unwrap_or(0);
    let total: u64 = vals.iter().sum();
    (total.saturating_sub(idle), total)
}

/// `(MemTotal, MemAvailable, SwapTotal, SwapFree)` in bytes from `/proc/meminfo`.
async fn meminfo() -> (u64, u64, u64, u64) {
    let text = fs::read_to_string("/proc/meminfo")
        .await
        .unwrap_or_default();
    let get = |key: &str| -> u64 {
        text.lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u64>().ok())
            .map(|kb| kb * 1024)
            .unwrap_or(0)
    };
    (
        get("MemTotal:"),
        get("MemAvailable:"),
        get("SwapTotal:"),
        get("SwapFree:"),
    )
}

async fn loadavg() -> [f64; 3] {
    let text = fs::read_to_string("/proc/loadavg")
        .await
        .unwrap_or_default();
    let mut it = text.split_whitespace();
    let mut parse = || it.next().and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
    [parse(), parse(), parse()]
}

async fn uptime() -> u64 {
    fs::read_to_string("/proc/uptime")
        .await
        .ok()
        .and_then(|s| s.split_whitespace().next().map(str::to_string))
        .and_then(|s| s.parse::<f64>().ok())
        .map(|f| f as u64)
        .unwrap_or(0)
}

async fn cpu_count() -> u32 {
    let text = fs::read_to_string("/proc/cpuinfo")
        .await
        .unwrap_or_default();
    let n = text.lines().filter(|l| l.starts_with("processor")).count();
    if n > 0 {
        n as u32
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1)
    }
}

/// Names of whole-disk block devices (partitions and virtual devices excluded)
/// from `/sys/block`.
async fn whole_disks() -> Vec<String> {
    let mut out = Vec::new();
    let mut rd = match fs::read_dir("/sys/block").await {
        Ok(rd) => rd,
        Err(_) => return out,
    };
    while let Ok(Some(entry)) = rd.next_entry().await {
        if let Some(name) = entry.file_name().to_str() {
            if name.starts_with("loop")
                || name.starts_with("ram")
                || name.starts_with("zram")
                || name.starts_with("dm-")
                || name.starts_with("sr")
            {
                continue;
            }
            out.push(name.to_string());
        }
    }
    out
}

/// Aggregate `(sectors_read, sectors_written)` for the given whole disks from
/// `/proc/diskstats`.
async fn disk_sectors(disks: &[String]) -> (u64, u64) {
    let text = fs::read_to_string("/proc/diskstats")
        .await
        .unwrap_or_default();
    let mut read = 0u64;
    let mut written = 0u64;
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        if !disks.iter().any(|d| d == f[2]) {
            continue;
        }
        read += f[5].parse::<u64>().unwrap_or(0);
        written += f[9].parse::<u64>().unwrap_or(0);
    }
    (read, written)
}

/// Aggregate `(rx_bytes, tx_bytes)` across host interfaces (excluding loopback).
async fn net_bytes() -> (u64, u64) {
    let mut rx = 0u64;
    let mut tx = 0u64;
    let mut rd = match fs::read_dir("/sys/class/net").await {
        Ok(rd) => rd,
        Err(_) => return (0, 0),
    };
    while let Ok(Some(entry)) = rd.next_entry().await {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "lo" {
            continue;
        }
        let base = entry.path().join("statistics");
        rx += read_counter(&base.join("rx_bytes")).await;
        tx += read_counter(&base.join("tx_bytes")).await;
    }
    (rx, tx)
}

async fn read_counter(path: &std::path::Path) -> u64 {
    fs::read_to_string(path)
        .await
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}
