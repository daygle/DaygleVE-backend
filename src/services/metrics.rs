//! Metrics service: node-level resource sampling from `/proc` and `/sys`.
//!
//! Rates (CPU %, disk and network throughput) require two samples, so [`node`]
//! takes a short delta window. Counters that are absolute (memory, load,
//! uptime) are read once. On a non-Linux/dev host the pseudo-files are absent
//! and the corresponding fields read as zero.
//!
//! [`node`]: MetricsService::node

use std::time::{Duration, Instant};

use daygleve_schema::metrics::NodeMetrics;
use tokio::fs;

use crate::services::now_ts;

/// Delta window for rate calculations.
const SAMPLE_WINDOW: Duration = Duration::from_millis(200);

pub struct MetricsService {
    /// The last sample and when it was taken, shared so concurrent SSE streams
    /// reuse one sampling pass instead of each paying the ~200ms window.
    cache: std::sync::Mutex<Option<(Instant, NodeMetrics)>>,
}

impl MetricsService {
    pub fn new() -> Self {
        Self {
            cache: std::sync::Mutex::new(None),
        }
    }

    /// Current node metrics. A sample newer than `CACHE_TTL` is reused, so N
    /// connected dashboards share one sampling pass per interval rather than N.
    pub async fn node(&self) -> NodeMetrics {
        const CACHE_TTL: Duration = Duration::from_millis(1500);
        if let Some((at, sample)) = self.cache.lock().unwrap().as_ref() {
            if at.elapsed() < CACHE_TTL {
                return sample.clone();
            }
        }
        let sample = self.sample_now().await;
        *self.cache.lock().unwrap() = Some((Instant::now(), sample.clone()));
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
