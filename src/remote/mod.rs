use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
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

/// Classify a POST that failed. The shared agent reports 4xx and 5xx as
/// `StatusCode`. Anything else is transient: DNS, connect, TLS, a timeout,
/// or a 307 or 308 that ureq will not resend a body to.
fn outcome_for_error(e: &ureq::Error) -> SendOutcome {
    match e {
        ureq::Error::StatusCode(code) => outcome_for_status(*code),
        _ => SendOutcome::Retry,
    }
}

/// Entropy for backoff jitter, uniform over all of `u64` as
/// [`Backoff::fail`] needs. The wall clock hashed by a fresh `RandomState`,
/// whose keys come from the OS and differ on every call, so agents that
/// start together still spread their retries. No RNG dependency. The
/// sub-second nanoseconds alone, used before, stay under 10^9 and kept every
/// delay under a second.
fn jitter_entropy() -> u64 {
    use std::hash::BuildHasher;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::collections::hash_map::RandomState::new().hash_one(now)
}

/// Refuse a remote URL before anything is sent to it, and return the form of
/// it to send to. Every POST carries the API key in its Authorization
/// header, so over http:// anyone on the path can copy the key along with
/// the snapshots. That needs `--insecure-remote`. A scheme that is neither,
/// or a URL ureq cannot send to, is refused outright, rather than failing
/// every POST later. The URL itself is left out of the errors, since it can
/// carry credentials of its own.
pub fn check_url(url: &str, allow_insecure: bool) -> anyhow::Result<String> {
    // The scheme is case-insensitive here as it is to ureq, so `HTTP://` is
    // http too.
    let parsed = url::Url::parse(url).map_err(|e| anyhow::anyhow!("invalid remote URL: {e}"))?;
    match parsed.scheme() {
        "https" => {}
        "http" if allow_insecure => {}
        "http" => anyhow::bail!(
            "remote URL is http://, which sends the API key in cleartext; \
             use https://, or pass --insecure-remote to allow it"
        ),
        other => anyhow::bail!("remote URL must be https://, not {other}://"),
    }
    // The url crate drops a tab or newline anywhere in the URL, such as the
    // one a secret file ends with, and encodes a space or a non-ASCII host.
    // ureq 2 parsed with it and sent what it made of the URL. ureq 3 parses
    // with http::Uri, which refuses all of those, so it is given the url
    // crate's form, and anything it still refuses is refused here.
    let url = String::from(parsed);
    ureq::http::Uri::try_from(ingest_endpoint(&url))
        .map_err(|e| anyhow::anyhow!("invalid remote URL: {e}"))?;
    Ok(url)
}

/// Where batches are POSTed under the remote URL.
fn ingest_endpoint(url: &str) -> String {
    format!("{}/api/v1/ingest", url.trim_end_matches('/'))
}

/// `url` as the log may show it: scheme, host, port and path. A user name,
/// password or query token in the URL stays out of a file that outlives the
/// session and gets attached to bug reports.
fn redacted(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(parsed) => format!("{}{}", parsed.origin().ascii_serialization(), parsed.path()),
        Err(_) => "(unparsable URL)".into(),
    }
}

pub struct RemoteConfig {
    /// As [`check_url`] returns it.
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
    handle: Mutex<Option<crate::sandbox::worker::WorkerHandle>>,
    /// Where the sender's backoff jitter comes from; tests fix it.
    jitter: fn() -> u64,
}

impl RemotePublisher {
    pub fn new(config: RemoteConfig) -> Self {
        Self {
            config,
            host_id: Uuid::new_v4(),
            snapshot_data: Arc::new(Mutex::new(None)),
            queue: Arc::new(SnapshotQueue::new(QUEUE_CAP)),
            collectors_ok: Arc::new(AtomicBool::new(true)),
            shutdown: Arc::new(AtomicBool::new(false)),
            handle: Mutex::new(None),
            jitter: jitter_entropy,
        }
    }

    /// Report collector liveness to the backend. The daemon calls this each
    /// tick (false once a collector thread has panicked) so a stalled agent
    /// surfaces as "data stale" rather than silently going quiet.
    pub fn set_collectors_ok(&self, ok: bool) {
        self.collectors_ok.store(ok, Ordering::Relaxed);
    }

    pub fn start(&self) {
        let endpoint = ingest_endpoint(&self.config.url);
        let api_key = self.config.api_key.clone();
        let host_id = self.host_id;
        let data = self.snapshot_data.clone();
        let queue = self.queue.clone();
        let collectors_ok = self.collectors_ok.clone();
        let shutdown = self.shutdown.clone();
        let jitter = self.jitter;

        let handle = crate::sandbox::worker::spawn("remote", move || {
            let host_info = collect_host_info(host_id);
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
                if shutdown.load(Ordering::Relaxed) || crate::sandbox::worker::stopping() {
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

                match try_flush_once(
                    &endpoint,
                    &api_key,
                    &host_info,
                    &collectors_ok,
                    &queue,
                    None,
                ) {
                    Some(SendOutcome::Ack) => {
                        backoff.reset();
                        next_send_at = now;
                    }
                    // Poison batch is dropped inside try_flush_once; pace the drain
                    // so a persistent 4xx doesn't spin. The wait runs from when
                    // the attempt ended: a POST that took its whole timeout would
                    // otherwise use up the wait it was owed.
                    Some(SendOutcome::Poison) | Some(SendOutcome::Retry) => {
                        next_send_at = Instant::now() + backoff.fail(jitter());
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
                "gateway_loss_pct": status.gateway_loss.pct(),
                "dns_rtt_ms": status.dns_rtt_ms,
                "dns_loss_pct": status.dns_loss.pct(),
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
/// shutdown drain so both speak the identical wire format. With a
/// `deadline`, the request as a whole gives up at that instant, not just
/// each read or write within it.
fn try_flush_once(
    endpoint: &str,
    api_key: &str,
    host_info: &serde_json::Value,
    collectors_ok: &AtomicBool,
    queue: &SnapshotQueue,
    deadline: Option<Instant>,
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

    let mut request = crate::http::agent()
        .post(endpoint)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json");
    if let Some(deadline) = deadline {
        request = request
            .config()
            .timeout_global(Some(deadline.saturating_duration_since(Instant::now())))
            .build();
    }
    // Compact, as ureq 2's send_json wrote it. ureq 3's pretty-prints, which
    // would grow every batch by its indentation.
    let result = request.send(body.to_string());

    let outcome = match &result {
        Ok(_) => SendOutcome::Ack,
        Err(e) => outcome_for_error(e),
    };

    match outcome {
        SendOutcome::Ack => queue.remove(batch.len()),
        SendOutcome::Poison => {
            if let Err(e) = &result {
                tracing::warn!(target: "netwatch::remote", endpoint = %redacted(endpoint), error = %e, batch = batch.len(), "dropping unacceptable ingest batch (4xx)");
            }
            queue.remove(batch.len());
        }
        SendOutcome::Retry => {
            if let Err(e) = &result {
                tracing::warn!(target: "netwatch::remote", endpoint = %redacted(endpoint), error = %e, queued = queue.len(), "ingest POST failed; will retry");
            }
        }
    }
    Some(outcome)
}

/// Best-effort final flush on shutdown: send batches back-to-back until the
/// queue empties or `budget` elapses. Retries here are short and unjittered —
/// we're racing a deadline to avoid losing the last few snapshots, not pacing a
/// reconnecting fleet. Each request is cut off at the deadline too, so a
/// backend that stops answering mid-request can't hold shutdown open.
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
        if let Some(SendOutcome::Retry) = try_flush_once(
            endpoint,
            api_key,
            host_info,
            collectors_ok,
            queue,
            Some(deadline),
        ) {
            thread::sleep(
                Duration::from_millis(200).min(deadline.saturating_duration_since(Instant::now())),
            );
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

    #[test]
    fn failed_posts_are_classified_by_status_or_retried() {
        use ureq::Error as E;
        assert_eq!(outcome_for_error(&E::StatusCode(401)), SendOutcome::Poison);
        assert_eq!(outcome_for_error(&E::StatusCode(429)), SendOutcome::Retry);
        assert_eq!(outcome_for_error(&E::StatusCode(503)), SendOutcome::Retry);
        for transient in [
            E::Timeout(ureq::Timeout::Global),
            E::HostNotFound,
            E::RedirectFailed,
            E::Io(std::io::ErrorKind::ConnectionRefused.into()),
        ] {
            assert_eq!(outcome_for_error(&transient), SendOutcome::Retry);
        }
    }

    /// Answer one ingest POST with `status` and hand back the request head,
    /// lowercased, and the body.
    fn ingest_once(status: &'static str) -> (String, thread::JoinHandle<(String, String)>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/api/v1/ingest", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            while !buf.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                buf.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&buf).to_ascii_lowercase();
            let len = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).unwrap();
            let reply =
                format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(reply.as_bytes());
            (head, String::from_utf8(body).unwrap())
        });
        (endpoint, server)
    }

    /// The real round trip through the shared agent: 2xx acknowledges, a 4xx
    /// drops the batch, a 5xx keeps it.
    #[test]
    fn the_backend_status_decides_what_happens_to_the_batch() {
        for (status, outcome, left) in [
            ("202 Accepted", SendOutcome::Ack, 0),
            ("401 Unauthorized", SendOutcome::Poison, 0),
            ("503 Service Unavailable", SendOutcome::Retry, 1),
        ] {
            let (endpoint, server) = ingest_once(status);
            let queue = SnapshotQueue::new(QUEUE_CAP);
            queue.push(json!({"n": 1}));
            let got = try_flush_once(
                &endpoint,
                "key",
                &json!({}),
                &AtomicBool::new(true),
                &queue,
                Some(Instant::now() + Duration::from_secs(5)),
            );
            assert_eq!(got, Some(outcome), "{status}");
            assert_eq!(queue.len(), left, "{status}");
            let (head, body) = server.join().unwrap();
            assert!(head.starts_with("post /api/v1/ingest "), "{head}");
            assert!(head.contains("authorization: bearer key\r\n"), "{head}");
            assert!(
                head.contains("content-type: application/json\r\n"),
                "{head}"
            );
            // The envelope, compact on one line as it always was.
            assert!(!body.contains('\n'), "{body}");
            let envelope: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(envelope["schema_version"], SCHEMA_VERSION);
            assert_eq!(envelope["snapshots"], json!([{"n": 1}]));
        }
    }

    #[test]
    fn remote_url_must_be_https_unless_cleartext_is_asked_for() {
        for url in ["https://cloud.example.com", "HTTPS://cloud.example.com/"] {
            assert!(check_url(url, false).is_ok(), "{url}");
            assert!(check_url(url, true).is_ok(), "{url}");
        }
        // The scheme is case-insensitive to ureq, so it must be here too.
        for url in ["http://cloud.example.com", "HTTP://10.0.0.1:8080/"] {
            let err = check_url(url, false).unwrap_err().to_string();
            assert!(err.contains("--insecure-remote"), "{url}: {err}");
            assert!(check_url(url, true).is_ok(), "{url}");
        }
        // Neither https nor http, or no URL at all: no flag makes these work.
        for url in [
            "ftp://cloud.example.com",
            "cloud.example.com",
            "https://",
            "",
        ] {
            assert!(check_url(url, true).is_err(), "{url}");
        }
    }

    /// Each worked under ureq 2, which parsed the URL as check_url does.
    /// ureq 3's http::Uri refuses every one of them as given.
    #[test]
    fn the_remote_url_is_sent_as_the_url_crate_reads_it() {
        for (given, sent) in [
            (
                "https://ingest.example.com\n",
                "https://ingest.example.com/",
            ),
            (
                "https://ingest.example.com\t/base/\r\n",
                "https://ingest.example.com/base/",
            ),
            (
                "https://ingest.example.com/a b",
                "https://ingest.example.com/a%20b",
            ),
            ("https://bücher.example", "https://xn--bcher-kva.example/"),
        ] {
            assert!(ureq::http::Uri::try_from(ingest_endpoint(given)).is_err());
            let url = check_url(given, false).unwrap();
            assert_eq!(url, sent, "{given:?}");
            assert!(ureq::http::Uri::try_from(ingest_endpoint(&url)).is_ok());
        }
    }

    /// The trailing newline of a file-backed secret, end to end.
    #[test]
    fn a_remote_url_with_a_trailing_newline_still_delivers() {
        let (endpoint, server) = ingest_once("202 Accepted");
        let base = endpoint.strip_suffix("/api/v1/ingest").unwrap();
        let url = check_url(&format!("{base}\n"), true).unwrap();
        let queue = SnapshotQueue::new(QUEUE_CAP);
        queue.push(json!({"n": 1}));
        let got = try_flush_once(
            &ingest_endpoint(&url),
            "key",
            &json!({}),
            &AtomicBool::new(true),
            &queue,
            Some(Instant::now() + Duration::from_secs(5)),
        );
        assert_eq!(got, Some(SendOutcome::Ack));
        assert!(queue.is_empty());
        let (head, _) = server.join().unwrap();
        assert!(head.starts_with("post /api/v1/ingest "), "{head}");
    }

    /// What the `fmt` layer writes, kept for the test to read.
    #[derive(Clone, Default)]
    struct LogCapture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for LogCapture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The log file outlives the session and gets attached to bug reports,
    /// so a failed POST names the backend without the credentials a URL can
    /// carry. http:// here only because the test server has no TLS.
    #[test]
    fn ingest_failure_log_omits_userinfo_and_query() {
        let capture = LogCapture::default();
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let mut hosts = Vec::new();
        tracing::subscriber::with_default(subscriber, || {
            for status in ["401 Unauthorized", "503 Service Unavailable"] {
                let (endpoint, server) = ingest_once(status);
                let host = endpoint
                    .strip_prefix("http://")
                    .and_then(|e| e.strip_suffix("/api/v1/ingest"))
                    .unwrap()
                    .to_string();
                let url = check_url(&format!("http://u:secret@{host}/?t=tok"), true).unwrap();
                let queue = SnapshotQueue::new(QUEUE_CAP);
                queue.push(json!({"n": 1}));
                try_flush_once(
                    &ingest_endpoint(&url),
                    "key",
                    &json!({}),
                    &AtomicBool::new(true),
                    &queue,
                    Some(Instant::now() + Duration::from_secs(5)),
                );
                server.join().unwrap();
                hosts.push(host);
            }
        });
        let log = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert!(log.contains("dropping unacceptable ingest batch"), "{log}");
        assert!(log.contains("will retry"), "{log}");
        for host in hosts {
            assert!(log.contains(&format!("http://{host}/")), "{log}");
        }
        assert!(!log.contains("secret"), "{log}");
        assert!(!log.contains("tok"), "{log}");
    }

    #[test]
    fn the_logged_url_keeps_only_the_host_and_path() {
        for (url, logged) in [
            (
                "https://agent:s3cret@cloud.example.com/api/v1/ingest",
                "https://cloud.example.com/api/v1/ingest",
            ),
            (
                "https://cloud.example.com:8443/base/?token=s3cret#s3cret",
                "https://cloud.example.com:8443/base/",
            ),
            (
                "http://agent@[2001:db8::1]:8080/?t=s3cret/api/v1/ingest",
                "http://[2001:db8::1]:8080/",
            ),
            ("https://agent:s3cret@", "(unparsable URL)"),
        ] {
            assert_eq!(redacted(url), logged, "{url}");
        }
    }

    #[test]
    fn a_refused_remote_url_is_not_echoed() {
        for url in [
            "http://agent:s3cret@cloud.example.com",
            "ftp://agent:s3cret@cloud.example.com",
        ] {
            let err = check_url(url, false).unwrap_err().to_string();
            assert!(!err.contains("s3cret"), "{err}");
        }
    }

    /// A backend that accepts the POST and never answers. The shared agent's
    /// 10 s read timeout alone would outlast the drain's budget.
    #[test]
    fn final_drain_stops_at_its_deadline_when_the_backend_goes_quiet() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/api/v1/ingest", listener.local_addr().unwrap());
        let _silent = thread::spawn(move || {
            let held: Vec<_> = listener.incoming().take(8).collect();
            drop(held);
        });
        let queue = SnapshotQueue::new(QUEUE_CAP);
        queue.push(json!({"n": 1}));

        let started = Instant::now();
        final_drain(
            &endpoint,
            "key",
            &json!({}),
            &AtomicBool::new(true),
            &queue,
            Duration::from_millis(300),
        );
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(queue.len(), 1, "an unanswered batch stays queued");
    }

    /// Review R5: the entropy the sender really uses covers the whole of
    /// `u64`, so its delays reach past a second. The sub-second nanoseconds
    /// it returned before kept every delay under one, whatever the ceiling.
    #[test]
    fn production_jitter_spreads_retries_past_a_second() {
        let draws: Vec<u64> = (0..64).map(|_| jitter_entropy()).collect();
        assert!(draws.iter().any(|&e| e >= 1 << 63), "{draws:?}");
        assert!(draws.iter().any(|&e| e < 1 << 63), "{draws:?}");

        let mut backoff = Backoff::new(Duration::from_millis(500), Duration::from_secs(60));
        let longest = (0..20)
            .map(|_| backoff.fail(jitter_entropy()))
            .max()
            .unwrap();
        assert!(longest > Duration::from_secs(1), "{longest:?}");
    }

    /// Review R5: against a backend that answers every POST with a 503
    /// after 700 ms, the sender waits each backoff ceiling in turn, counted
    /// from when the answer came. It timed the wait from before the POST, so
    /// a slow answer used up part of the wait. The batch stays queued, and
    /// shutdown still returns on time.
    #[test]
    fn sender_paces_retries_to_a_failing_backend() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        // When each POST arrived and when its answer went out.
        let posts = Arc::new(Mutex::new(Vec::<(Instant, Instant)>::new()));
        let seen = posts.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                    head.push(byte[0]);
                }
                let len = String::from_utf8_lossy(&head)
                    .to_ascii_lowercase()
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:").map(str::to_owned))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                let _ = stream.read_exact(&mut vec![0u8; len]);
                let arrived = Instant::now();
                thread::sleep(Duration::from_millis(700));
                let _ = stream.write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                seen.lock().unwrap().push((arrived, Instant::now()));
            }
        });

        let mut publisher = RemotePublisher::new(RemoteConfig {
            url,
            api_key: "key".into(),
        });
        // Every draw takes the whole ceiling, so the waits are known.
        publisher.jitter = || u64::MAX;
        *publisher.snapshot_data.lock().unwrap() = Some(json!({"n": 1}));
        publisher.start();

        let deadline = Instant::now() + Duration::from_secs(30);
        while posts.lock().unwrap().len() < 4 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
        }
        let posts = posts.lock().unwrap().clone();
        assert!(posts.len() >= 4, "{} POSTs in 30 s", posts.len());
        for (i, ceiling) in [500, 1_000, 2_000].into_iter().enumerate() {
            let wait = posts[i + 1].0 - posts[i].1;
            assert!(
                wait >= Duration::from_millis(ceiling),
                "wait {i} was {wait:?}, ceiling {ceiling} ms"
            );
        }
        assert_eq!(publisher.queue.len(), 1, "a 503 keeps the batch");

        let started = Instant::now();
        publisher.shutdown(Duration::from_secs(1));
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
