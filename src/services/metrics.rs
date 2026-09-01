//! Metrics service: node- and guest-level resource sampling.
//!
//! TODO(metrics): sample `/proc`, cgroups and libvirt/lxc stats on an interval
//! and fan out to SSE subscribers. Scaffold returns a single point-in-time
//! snapshot with zeroed counters.

use daygleve_schema::metrics::NodeMetrics;

use crate::services::now_ts;

pub struct MetricsService;

impl MetricsService {
    pub fn new() -> Self {
        Self
    }

    /// Current node metrics snapshot.
    pub fn node(&self) -> NodeMetrics {
        // TODO(metrics): read /proc/stat, /proc/meminfo, /proc/loadavg, etc.
        NodeMetrics {
            timestamp: now_ts(),
            cpu_pct: 0.0,
            cpu_count: num_cpus(),
            load_average: [0.0, 0.0, 0.0],
            memory_total_bytes: 0,
            memory_used_bytes: 0,
            swap_total_bytes: 0,
            swap_used_bytes: 0,
            disk_read_bps: 0,
            disk_write_bps: 0,
            net_rx_bps: 0,
            net_tx_bps: 0,
            uptime_seconds: 0,
        }
    }
}

/// Best-effort logical CPU count without extra dependencies.
fn num_cpus() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}
