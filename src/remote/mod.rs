use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;
use uuid::Uuid;

use crate::app::safe_lock;
use crate::collectors::connections::ConnectionCollector;
use crate::collectors::health::HealthProber;
use crate::collectors::traffic::InterfaceTraffic;

mod queue;
use queue::{Backoff, SnapshotQueue};

/// Wire-format version sent in every envelope. Bump on a breaking change to the
/// payload shape; the backend uses it to route/validate. New optional fields
/// don't require a bump (consumers tolerate them via `#[serde(default)]`).
const SCHEMA_VERSION: u32 = 1;

/// How often a fresh snapshot is enqueued for delivery. The capture side
/// (`update`) refreshes the latest-slot every tick; we sample it at this
/// cadence so ingest volume is independent of the UI refresh rate.
const ENQUEUE_INTERVAL: Duration = Duration::from_secs(15);

/// Bounded backlog. At one snapshot / 15s this is ~8.3h of buffering across a
/// backend outage before the oldest data is shed.
const QUEUE_CAP: usize = 2000;

/// Max snapshots per POST when draining a backlog after reconnect.
const BATCH_MAX: usize = 50;

/// Sender-loop granularity. Small enough that retry backoff is responsive,
/// large enough to be effectively free.
const LOOP_TICK: Duration = Duration::from_millis(250);

/// How the backend's response to an ingest POST is classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendOutcome {
    /// 2xx — the batch was accepted; remove it from the queue.
    Ack,
    /// 4xx (auth/schema) — the batch will never succeed; drop it so a poison
    /// payload can't wedge the queue forever. Still paced by backoff.
    Poison,
    /// 5xx / 408 / 429 / transport — transient; keep the batch and back off.
    Retry,
}

/// Map an HTTP status code to a send outcome. Factored out for unit testing
/// without standing up a network.
fn outcome_for_status(code: u16) -> SendOutcome {
    match code {
        200..=299 => SendOutcome::Ack,
        // Retry the genuinely transient client codes.
        408 | 429 => SendOutcome::Retry,
        // Other 4xx are our fault (bad key, bad schema) — don't retry forever.
        400..=499 => SendOutcome::Poison,
        // 5xx and anything else: assume the backend will recover.
        _ => SendOutcome::Retry,
    }
}

/// Cheap entropy for backoff jitter — low bits of the wall clock. No RNG dep,
/// and good enough to desynchronize a reconnecting fleet's retries.
fn jitter_entropy() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0)
}

/// Directories to persist the agent's stable `host_id`, in preference order.
/// Config dir is ideal for interactive use; cache dir is the fallback (the
/// systemd unit guarantees it writable via XDG_CACHE_HOME + CacheDirectory).
fn host_id_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(d) = dirs::config_dir() {
        dirs.push(d.join("netwatch"));
    }
    if let Some(d) = dirs::cache_dir() {
        dirs.push(d.join("netwatch"));
    }
    dirs
}

/// Load the persisted agent `host_id`, or generate and persist a new one.
///
/// Previously the daemon minted a fresh UUID every start, so each restart
/// registered a brand-new host in the cloud (fleet churn / duplicates). A
/// stable, persisted identity fixes that.
fn load_or_create_host_id() -> Uuid {
    host_id_in_dirs(&host_id_dirs())
}

/// Inner, dependency-injected form of [`load_or_create_host_id`] for testing:
/// reads `host_id` from the first dir that has a valid one, else generates a
/// new id and writes it to the first writable dir.
fn host_id_in_dirs(dirs: &[PathBuf]) -> Uuid {
    for dir in dirs {
        if let Ok(s) = std::fs::read_to_string(dir.join("host_id")) {
            if let Ok(id) = Uuid::parse_str(s.trim()) {
                return id;
            }
        }
    }

    let id = Uuid::new_v4();
    for dir in dirs {
        if std::fs::create_dir_all(dir).is_ok()
            && std::fs::write(dir.join("host_id"), id.to_string()).is_ok()
        {
            return id;
        }
    }

    tracing::warn!(
        target: "netwatch::remote",
        "could not persist host_id; using an ephemeral id (this host will re-register on restart)"
    );
    id
}

pub struct RemoteConfig {
    pub url: String,
    pub api_key: String,
}

pub struct RemotePublisher {
    config: RemoteConfig,
    host_id: Uuid,
    /// Latest snapshot produced by the capture side, overwritten each tick.
    snapshot_data: Arc<Mutex<Option<serde_json::Value>>>,
    /// Durable backlog drained by the sender thread.
    queue: Arc<SnapshotQueue>,
    /// Liveness attestation included in each envelope. The daemon supervisor
    /// flips this false when a collector thread has panicked.
    collectors_ok: Arc<AtomicBool>,
    /// Set by [`shutdown`](Self::shutdown) to ask the sender thread to do a
    /// final bounded drain and exit.
    shutdown: Arc<AtomicBool>,
    /// Sender-thread handle, joined on shutdown for a clean flush.
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl RemotePublisher {
    pub fn new(config: RemoteConfig) -> Self {
        Self {
            config,
            host_id: load_or_create_host_id(),
            snapshot_data: Arc::new(Mutex::new(None)),
            queue: Arc::new(SnapshotQueue::new(QUEUE_CAP)),
            collectors_ok: Arc::new(AtomicBool::new(true)),
            shutdown: Arc::new(AtomicBool::new(false)),
            handle: Mutex::new(None),
        }
    }

    /// Report collector liveness to the backend. The daemon calls this each
    /// tick (false once a collector thread has panicked) so a stalled agent
    /// surfaces as "data stale" rather than silently going quiet.
    pub fn set_collectors_ok(&self, ok: bool) {
        self.collectors_ok.store(ok, Ordering::Relaxed);
    }

    pub fn start(&self) {
        let url = self.config.url.trim_end_matches('/').to_string();
        let api_key = self.config.api_key.clone();
        let host_id = self.host_id;
        let data = self.snapshot_data.clone();
        let queue = self.queue.clone();
        let collectors_ok = self.collectors_ok.clone();
        let shutdown = self.shutdown.clone();

        let handle = thread::spawn(move || {
            let host_info = collect_host_info(host_id);
            let endpoint = format!("{}/api/v1/ingest", url);
            let mut backoff = Backoff::new(Duration::from_millis(500), Duration::from_secs(60));

            // Enqueue immediately on first available snapshot, then on cadence.
            let mut last_enqueue: Option<Instant> = None;
            // Earliest time a send attempt is permitted (advanced by backoff).
            let mut next_send_at = Instant::now();

            loop {
                thread::sleep(LOOP_TICK);
                let now = Instant::now();

                // Graceful shutdown: one final bounded drain, then exit so the
                // daemon's join() returns promptly even if the backend is slow.
                if shutdown.load(Ordering::Relaxed) {
                    final_drain(
                        &endpoint,
                        &api_key,
                        &host_info,
                        &collectors_ok,
                        &queue,
                        Duration::from_secs(5),
                    );
                    return;
                }

                // 1. Sample the latest snapshot into the durable queue on cadence.
                let due = match last_enqueue {
                    None => true,
                    Some(t) => now.duration_since(t) >= ENQUEUE_INTERVAL,
                };
                if due {
                    let snapshot = {
                        let lock = safe_lock(&data, "remote::ingest_loop");
                        lock.clone()
                    };
                    if let Some(snapshot) = snapshot {
                        queue.push(snapshot);
                        last_enqueue = Some(now);
                    }
                }

                // 2. Drain the backlog, honoring the backoff window.
                if queue.is_empty() || now < next_send_at {
                    continue;
                }

                match try_flush_once(&endpoint, &api_key, &host_info, &collectors_ok, &queue) {
                    Some(SendOutcome::Ack) => {
                        backoff.reset();
                        next_send_at = now;
                    }
                    // Poison batch is dropped inside try_flush_once; pace the drain
                    // so a persistent 4xx doesn't spin.
                    Some(SendOutcome::Poison) | Some(SendOutcome::Retry) => {
                        next_send_at = now + backoff.fail(jitter_entropy());
                    }
                    None => {}
                }
            }
        });

        *self.handle.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
    }

    /// Ask the sender thread to flush and stop, blocking until it finishes its
    /// final drain (bounded by its own internal deadline) or `timeout` elapses.
    pub fn shutdown(&self, timeout: Duration) {
        // Make sure the most recent snapshot is in the durable queue first.
        let latest = {
            let lock = safe_lock(&self.snapshot_data, "remote::shutdown");
            lock.clone()
        };
        if let Some(snapshot) = latest {
            self.queue.push(snapshot);
        }
        self.shutdown.store(true, Ordering::Relaxed);

        let handle = self.handle.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(handle) = handle {
            // The sender thread caps its own drain at 5s; we wait a touch longer
            // before giving up so a slow-but-working backend can finish.
            let deadline = Instant::now() + timeout;
            while !handle.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(50));
            }
            if handle.is_finished() {
                let _ = handle.join();
            } else {
                let queued = self.queue.len();
                tracing::warn!(target: "netwatch::remote", queued, "shutdown drain timed out; abandoning buffered snapshots");
            }
        }
    }

    pub fn update(
        &self,
        interfaces: &[InterfaceTraffic],
        health: &HealthProber,
        connections: &ConnectionCollector,
    ) {
        let ifaces: Vec<serde_json::Value> = interfaces
            .iter()
            .map(|i| {
                json!({
                    "name": i.name,
                    "is_up": true,
                    "rx_bytes": i.rx_bytes_total,
                    "tx_bytes": i.tx_bytes_total,
                    "rx_bytes_delta": (i.rx_rate as u64),
                    "tx_bytes_delta": (i.tx_rate as u64),
                    "rx_packets": i.rx_packets,
                    "tx_packets": i.tx_packets,
                    "rx_errors": i.rx_errors,
                    "tx_errors": i.tx_errors,
                    "rx_drops": i.rx_drops,
                    "tx_drops": i.tx_drops,
                })
            })
            .collect();

        let health_json = {
            let status = health.status();
            json!({
                "gateway_rtt_ms": status.gateway_rtt_ms,
                "gateway_loss_pct": status.gateway_loss_pct,
                "dns_rtt_ms": status.dns_rtt_ms,
                "dns_loss_pct": status.dns_loss_pct,
            })
        };

        let conn_count = connections.connections().len() as u32;

        let tcp_states = collect_tcp_states(connections);
        let system = collect_system_metrics();
        let disk_usage = collect_disk_usage();

        let snapshot = json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "interfaces": ifaces,
            "health": health_json,
            "connection_count": conn_count,
            "system": system,
            "disk_usage": disk_usage,
            "tcp_time_wait": tcp_states.0,
            "tcp_close_wait": tcp_states.1,
        });

        *safe_lock(&self.snapshot_data, "remote::collect_snapshot::store") = Some(snapshot);
    }
}

/// Attempt to send one batch from the head of the queue.
///
/// Returns `None` if there was nothing to send, otherwise the classified
/// outcome. On `Ack` the batch is removed; on `Poison` it is dropped (and
/// logged) so a bad payload can't wedge the queue; on `Retry` it is left in
/// place for the next attempt. Shared by the steady-state loop and the
/// shutdown drain so both speak the identical wire format.
fn try_flush_once(
    endpoint: &str,
    api_key: &str,
    host_info: &serde_json::Value,
    collectors_ok: &AtomicBool,
    queue: &SnapshotQueue,
) -> Option<SendOutcome> {
    if queue.is_empty() {
        return None;
    }
    let batch = queue.peek_batch(BATCH_MAX);
    let body = json!({
        "schema_version": SCHEMA_VERSION,
        "agent_version": format!("netwatch-tui/{}", env!("CARGO_PKG_VERSION")),
        "host": host_info,
        "snapshots": batch,
        "agent_health": {
            "collectors_ok": collectors_ok.load(Ordering::Relaxed),
            "dropped_count": queue.dropped(),
            "queue_depth": queue.len(),
        },
    });

    let result = ureq::post(endpoint)
        .set("Authorization", &format!("Bearer {}", api_key))
        .set("Content-Type", "application/json")
        .send_json(body);

    let outcome = match &result {
        Ok(_) => SendOutcome::Ack,
        Err(ureq::Error::Status(code, _)) => outcome_for_status(*code),
        // Transport-level (DNS, connect, TLS, timeout) — transient.
        Err(ureq::Error::Transport(_)) => SendOutcome::Retry,
    };

    match outcome {
        SendOutcome::Ack => queue.remove(batch.len()),
        SendOutcome::Poison => {
            if let Err(e) = &result {
                tracing::warn!(target: "netwatch::remote", endpoint = %endpoint, error = %e, batch = batch.len(), "dropping unacceptable ingest batch (4xx)");
            }
            queue.remove(batch.len());
        }
        SendOutcome::Retry => {
            if let Err(e) = &result {
                tracing::warn!(target: "netwatch::remote", endpoint = %endpoint, error = %e, queued = queue.len(), "ingest POST failed; will retry");
            }
        }
    }
    Some(outcome)
}

/// Best-effort final flush on shutdown: send batches back-to-back until the
/// queue empties or `budget` elapses. Retries here are short and unjittered —
/// we're racing a deadline to avoid losing the last few snapshots, not pacing a
/// reconnecting fleet.
fn final_drain(
    endpoint: &str,
    api_key: &str,
    host_info: &serde_json::Value,
    collectors_ok: &AtomicBool,
    queue: &SnapshotQueue,
    budget: Duration,
) {
    let deadline = Instant::now() + budget;
    while !queue.is_empty() && Instant::now() < deadline {
        if let Some(SendOutcome::Retry) =
            try_flush_once(endpoint, api_key, host_info, collectors_ok, queue)
        {
            thread::sleep(Duration::from_millis(200));
        }
    }
    if !queue.is_empty() {
        tracing::warn!(target: "netwatch::remote", queued = queue.len(), "final drain incomplete at shutdown deadline");
    }
}

fn collect_host_info(host_id: Uuid) -> serde_json::Value {
    let hostname = run_cmd("hostname", &[]);
    let kernel = run_cmd("uname", &["-r"]);

    let (os, cpu_model, cpu_cores, memory_total) = if cfg!(target_os = "macos") {
        let os = Some("macOS".to_string());
        let cpu = run_cmd("sysctl", &["-n", "machdep.cpu.brand_string"]);
        let cores: Option<u32> = run_cmd("sysctl", &["-n", "hw.ncpu"]).and_then(|s| s.parse().ok());
        let mem: Option<u64> =
            run_cmd("sysctl", &["-n", "hw.memsize"]).and_then(|s| s.parse().ok());
        (os, cpu, cores, mem)
    } else {
        let os = std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|s| {
                s.lines().find(|l| l.starts_with("PRETTY_NAME=")).map(|l| {
                    l.trim_start_matches("PRETTY_NAME=")
                        .trim_matches('"')
                        .to_string()
                })
            });
        let cpu = std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split(':').nth(1))
                .map(|s| s.trim().to_string())
        });
        let cores: Option<u32> = run_cmd("nproc", &[]).and_then(|s| s.parse().ok());
        let mem = std::fs::read_to_string("/proc/meminfo").ok().and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse::<u64>().ok())
                .map(|kb| kb * 1024)
        });
        (os, cpu, cores, mem)
    };

    json!({
        "host_id": host_id,
        "hostname": hostname,
        "os": os,
        "kernel": kernel,
        "cpu_model": cpu_model,
        "cpu_cores": cpu_cores,
        "memory_total_bytes": memory_total,
    })
}

fn collect_system_metrics() -> serde_json::Value {
    if cfg!(target_os = "macos") {
        collect_system_macos()
    } else {
        collect_system_linux()
    }
}

fn collect_system_macos() -> serde_json::Value {
    let load = run_cmd("sysctl", &["-n", "vm.loadavg"]).unwrap_or_default();
    let loads: Vec<f64> = load
        .trim_matches(|c: char| c == '{' || c == '}')
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect();

    let mem_total: Option<u64> =
        run_cmd("sysctl", &["-n", "hw.memsize"]).and_then(|s| s.parse().ok());

    let vm_stat = run_cmd("vm_stat", &[]).unwrap_or_default();
    let page_size: u64 = 16384; // Apple Silicon default
    let mut free_pages: u64 = 0;
    let mut active_pages: u64 = 0;
    let mut inactive_pages: u64 = 0;
    let mut speculative_pages: u64 = 0;
    let mut wired_pages: u64 = 0;

    for line in vm_stat.lines() {
        let val = || -> Option<u64> {
            line.split(':')
                .nth(1)?
                .trim()
                .trim_end_matches('.')
                .parse()
                .ok()
        };
        if line.starts_with("Pages free") {
            free_pages = val().unwrap_or(0);
        }
        if line.starts_with("Pages active") {
            active_pages = val().unwrap_or(0);
        }
        if line.starts_with("Pages inactive") {
            inactive_pages = val().unwrap_or(0);
        }
        if line.starts_with("Pages speculative") {
            speculative_pages = val().unwrap_or(0);
        }
        if line.starts_with("Pages wired") {
            wired_pages = val().unwrap_or(0);
        }
    }

    let available = (free_pages + inactive_pages + speculative_pages) * page_size;
    let used = (active_pages + wired_pages) * page_size;

    let cpu_pct = run_cmd(
        "sh",
        &[
            "-c",
            "top -l 1 -n 0 2>/dev/null | grep 'CPU usage' | awk '{print $3}' | tr -d '%'",
        ],
    )
    .and_then(|s| s.parse::<f64>().ok());

    let swap = run_cmd("sysctl", &["-n", "vm.swapusage"]).unwrap_or_default();
    let swap_total: Option<u64> = swap
        .split_whitespace()
        .zip(swap.split_whitespace().skip(1))
        .find(|(_, v)| v.contains('M') || v.contains('G'))
        .and_then(|(_, v)| parse_size(v));
    let swap_used: Option<u64> = {
        let parts: Vec<&str> = swap.split("used =").collect();
        parts
            .get(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(parse_size)
    };

    json!({
        "cpu_usage_pct": cpu_pct,
        "memory_total_bytes": mem_total,
        "memory_used_bytes": used,
        "memory_available_bytes": available,
        "load_avg_1m": loads.first(),
        "load_avg_5m": loads.get(1),
        "load_avg_15m": loads.get(2),
        "swap_total_bytes": swap_total,
        "swap_used_bytes": swap_used,
    })
}

fn collect_system_linux() -> serde_json::Value {
    let loadavg = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let loads: Vec<f64> = loadavg
        .split_whitespace()
        .take(3)
        .filter_map(|s| s.parse().ok())
        .collect();

    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mem_val = |key: &str| -> Option<u64> {
        meminfo
            .lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u64>().ok())
            .map(|kb| kb * 1024)
    };

    let mem_total = mem_val("MemTotal:");
    let mem_available = mem_val("MemAvailable:");
    let mem_used = match (mem_total, mem_available) {
        (Some(t), Some(a)) => Some(t - a),
        _ => None,
    };
    let swap_total = mem_val("SwapTotal:");
    let swap_free = mem_val("SwapFree:");
    let swap_used = match (swap_total, swap_free) {
        (Some(t), Some(f)) => Some(t - f),
        _ => None,
    };

    let stat = std::fs::read_to_string("/proc/stat").unwrap_or_default();
    let cpu_pct = stat.lines().next().and_then(|line| {
        let vals: Vec<u64> = line
            .split_whitespace()
            .skip(1)
            .filter_map(|s| s.parse().ok())
            .collect();
        if vals.len() >= 4 {
            let total: u64 = vals.iter().sum();
            let idle = vals[3];
            if total > 0 {
                Some(((total - idle) as f64 / total as f64) * 100.0)
            } else {
                None
            }
        } else {
            None
        }
    });

    json!({
        "cpu_usage_pct": cpu_pct,
        "memory_total_bytes": mem_total,
        "memory_used_bytes": mem_used,
        "memory_available_bytes": mem_available,
        "load_avg_1m": loads.first(),
        "load_avg_5m": loads.get(1),
        "load_avg_15m": loads.get(2),
        "swap_total_bytes": swap_total,
        "swap_used_bytes": swap_used,
    })
}

fn collect_disk_usage() -> Vec<serde_json::Value> {
    let output = run_cmd("df", &["-k"]).unwrap_or_default();
    output
        .lines()
        .skip(1)
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                return None;
            }
            let device = parts[0];
            if device.starts_with("devfs") || device == "map" || device.starts_with("none") {
                return None;
            }
            let mount_hint = parts.last().unwrap_or(&"");
            if mount_hint.starts_with("/Volumes/")
                || mount_hint.starts_with("/System/Volumes/")
                || mount_hint.starts_with("/private/")
            {
                return None;
            }
            let total: u64 = parts[1].parse::<u64>().ok()? * 1024;
            let used: u64 = parts[2].parse::<u64>().ok()? * 1024;
            let available: u64 = parts[3].parse::<u64>().ok()? * 1024;
            let mount = if cfg!(target_os = "macos") && parts.len() >= 9 {
                parts[8..].join(" ")
            } else {
                parts.last()?.to_string()
            };
            if total == 0 {
                return None;
            }
            let pct = (used as f64 / total as f64) * 100.0;
            Some(json!({
                "mount_point": mount,
                "device": device,
                "total_bytes": total,
                "used_bytes": used,
                "available_bytes": available,
                "usage_pct": pct,
            }))
        })
        .collect()
}

fn collect_tcp_states(connections: &ConnectionCollector) -> (u32, u32) {
    let conns = connections.connections();
    let mut time_wait = 0u32;
    let mut close_wait = 0u32;
    for conn in conns.iter() {
        match conn.state.as_str() {
            "TIME_WAIT" | "TIME-WAIT" => time_wait += 1,
            "CLOSE_WAIT" | "CLOSE-WAIT" => close_wait += 1,
            _ => {}
        }
    }
    (time_wait, close_wait)
}

fn run_cmd(cmd: &str, args: &[&str]) -> Option<String> {
    std::process::Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(v) = s.strip_suffix('M') {
        v.parse::<f64>().ok().map(|v| (v * 1024.0 * 1024.0) as u64)
    } else if let Some(v) = s.strip_suffix('G') {
        v.parse::<f64>()
            .ok()
            .map(|v| (v * 1024.0 * 1024.0 * 1024.0) as u64)
    } else {
        s.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_id_persists_across_calls() {
        let dir = std::env::temp_dir().join(format!("nw-hostid-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let dirs = vec![dir.clone()];

        let first = host_id_in_dirs(&dirs);
        // A second call must return the SAME id (read back from disk), not a new
        // one — this is the fleet-churn fix.
        let second = host_id_in_dirs(&dirs);
        assert_eq!(first, second, "host_id must be stable across restarts");
        assert!(dir.join("host_id").exists(), "host_id file must be written");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn host_id_falls_back_to_second_writable_dir() {
        // First candidate is an unwritable path (a file, so create_dir_all fails);
        // the id must still be generated and persisted to the second dir.
        let base = std::env::temp_dir().join(format!("nw-hostid-fb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let blocker = base.join("blocker");
        std::fs::write(&blocker, b"x").unwrap(); // a file where a dir is expected
        let good = base.join("good");

        let id = host_id_in_dirs(&[blocker.join("netwatch"), good.clone()]);
        assert!(good.join("host_id").exists());
        assert_eq!(host_id_in_dirs(&[good.clone()]), id);

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn status_classification() {
        assert_eq!(outcome_for_status(200), SendOutcome::Ack);
        assert_eq!(outcome_for_status(202), SendOutcome::Ack);
        // Auth / schema problems are our fault — don't retry forever.
        assert_eq!(outcome_for_status(400), SendOutcome::Poison);
        assert_eq!(outcome_for_status(401), SendOutcome::Poison);
        assert_eq!(outcome_for_status(404), SendOutcome::Poison);
        // Transient client codes are retryable.
        assert_eq!(outcome_for_status(408), SendOutcome::Retry);
        assert_eq!(outcome_for_status(429), SendOutcome::Retry);
        // Server errors recover.
        assert_eq!(outcome_for_status(500), SendOutcome::Retry);
        assert_eq!(outcome_for_status(503), SendOutcome::Retry);
    }
}
