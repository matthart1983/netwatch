use serde::Serialize;
use std::collections::HashMap;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::connections::Connection;
use super::traffic::InterfaceTraffic;

/// Drop a process's accumulated byte totals after this much inactivity.
/// Without pruning, long sessions would leak entries for every (process, pid)
/// pair ever observed — PIDs cycle, so the keyset is effectively unbounded.
const PROCESS_TOTALS_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
struct ProcessTotals {
    rx_bytes: u64,
    tx_bytes: u64,
    last_seen: Instant,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessBandwidth {
    pub process_name: String,
    pub pid: Option<u32>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_rate: f64,
    pub tx_rate: f64,
    pub connection_count: u32,
    /// Min RTT (ms) across this process's TCP connections — derived from
    /// `Connection.kernel_rtt_us`. None when no kernel RTT data is available.
    pub rtt_ms: Option<f64>,
    /// CPU%, populated from a background `ps` poll. None until the first
    /// poll completes (or when the platform doesn't support the sampler).
    pub cpu_percent: Option<f64>,
}

pub struct ProcessBandwidthCollector {
    ranked: Vec<ProcessBandwidth>,
    /// CPU% per-pid cache, populated by a background `ps` thread on a slow
    /// tick. The mutex is short-lived; reads are O(1) lookups.
    cpu_cache: Arc<Mutex<HashMap<u32, f64>>>,
    cpu_busy: Arc<AtomicBool>,
    /// Per-(process, pid) cumulative bytes, integrated from observed
    /// rates each tick (`bytes += rate * elapsed`). Survives ticks where
    /// the current rate is 0, so the Stats "TOP PROCESSES" panel keeps
    /// showing historical traffic instead of flashing empty every time
    /// a flow goes idle. Pruned after PROCESS_TOTALS_TTL of inactivity.
    process_totals: HashMap<(String, Option<u32>), ProcessTotals>,
    /// Timestamp of the previous `update()` call; used to integrate rate
    /// into bytes since the last tick. `None` on first call (no elapsed
    /// time to integrate over).
    last_tick: Option<Instant>,
}

impl Default for ProcessBandwidthCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessBandwidthCollector {
    pub fn new() -> Self {
        Self {
            ranked: Vec::new(),
            cpu_cache: Arc::new(Mutex::new(HashMap::new())),
            cpu_busy: Arc::new(AtomicBool::new(false)),
            process_totals: HashMap::new(),
            last_tick: None,
        }
    }

    pub fn update(&mut self, connections: &[Connection], _interfaces: &[InterfaceTraffic]) {
        let now = Instant::now();
        let elapsed = self
            .last_tick
            .map(|t| now.duration_since(t).as_secs_f64())
            .unwrap_or(0.0);
        self.last_tick = Some(now);

        // Aggregate per-(process, pid) state from the ESTABLISHED connections.
        // Rates come from the packet capture path (conn.rx_rate / tx_rate are
        // populated by RateState in connections.rs when a stream's bytes are
        // moving). RTT is the min across the process's TCP conns.
        let mut process_conns: HashMap<(String, Option<u32>), u32> = HashMap::new();
        let mut process_rx_rate: HashMap<(String, Option<u32>), f64> = HashMap::new();
        let mut process_tx_rate: HashMap<(String, Option<u32>), f64> = HashMap::new();
        let mut process_rtt: HashMap<(String, Option<u32>), f64> = HashMap::new();
        let mut total_active: u32 = 0;

        for conn in connections {
            // Skip server-side sockets (LISTEN) and fully closed sockets —
            // they have no current peer traffic by definition. Everything
            // else counts: TCP ESTABLISHED / TIME_WAIT / CLOSE_WAIT /
            // FIN_WAIT_*, and UDP (which lsof and procfs report with an
            // empty state). This is what was hiding the bulk of browser
            // traffic (QUIC over UDP), DNS resolvers, mDNS responders,
            // and every other UDP service from the Processes tab.
            if conn.state == "LISTEN" || conn.state == "CLOSED" {
                continue;
            }
            let name = conn
                .process_name
                .clone()
                .unwrap_or_else(|| format!("pid:{}", conn.pid.map_or(0, |p| p)));
            let key = (name, conn.pid);
            *process_conns.entry(key.clone()).or_insert(0) += 1;
            total_active += 1;
            if let Some(rx) = conn.rx_rate {
                *process_rx_rate.entry(key.clone()).or_insert(0.0) += rx;
            }
            if let Some(tx) = conn.tx_rate {
                *process_tx_rate.entry(key.clone()).or_insert(0.0) += tx;
            }
            if let Some(rtt_us) = conn.kernel_rtt_us {
                let rtt_ms = rtt_us / 1000.0;
                process_rtt
                    .entry(key)
                    .and_modify(|v| {
                        if rtt_ms < *v {
                            *v = rtt_ms;
                        }
                    })
                    .or_insert(rtt_ms);
            }
        }

        // Integrate per-process rates into cumulative byte totals. Even
        // when the current rate is 0, the previously-accumulated total
        // persists, so the "TOP PROCESSES" panel shows historical traffic
        // instead of flashing empty every time a flow goes idle.
        if elapsed > 0.0 {
            for (key, &rx_rate) in &process_rx_rate {
                if rx_rate <= 0.0 {
                    continue;
                }
                let entry =
                    self.process_totals
                        .entry(key.clone())
                        .or_insert_with(|| ProcessTotals {
                            rx_bytes: 0,
                            tx_bytes: 0,
                            last_seen: now,
                        });
                entry.rx_bytes = entry.rx_bytes.saturating_add((rx_rate * elapsed) as u64);
                entry.last_seen = now;
            }
            for (key, &tx_rate) in &process_tx_rate {
                if tx_rate <= 0.0 {
                    continue;
                }
                let entry =
                    self.process_totals
                        .entry(key.clone())
                        .or_insert_with(|| ProcessTotals {
                            rx_bytes: 0,
                            tx_bytes: 0,
                            last_seen: now,
                        });
                entry.tx_bytes = entry.tx_bytes.saturating_add((tx_rate * elapsed) as u64);
                entry.last_seen = now;
            }
        }

        // Prune stale entries so the totals map doesn't grow unbounded
        // across PID churn over a long-running session.
        self.process_totals
            .retain(|_, t| now.duration_since(t.last_seen) < PROCESS_TOTALS_TTL);

        if total_active == 0 {
            self.ranked.clear();
            return;
        }

        let cpu_cache = self.cpu_cache.lock().unwrap().clone();

        let mut ranked: Vec<ProcessBandwidth> = process_conns
            .into_iter()
            .map(|((process_name, pid), count)| {
                let key = (process_name.clone(), pid);
                let rx_rate = process_rx_rate.get(&key).copied().unwrap_or(0.0);
                let tx_rate = process_tx_rate.get(&key).copied().unwrap_or(0.0);
                let (rx_bytes, tx_bytes) = self
                    .process_totals
                    .get(&key)
                    .map(|t| (t.rx_bytes, t.tx_bytes))
                    .unwrap_or((0, 0));
                let rtt_ms = process_rtt.get(&key).copied();
                let cpu_percent = pid.and_then(|p| cpu_cache.get(&p).copied());
                ProcessBandwidth {
                    process_name,
                    pid,
                    rx_bytes,
                    tx_bytes,
                    rx_rate,
                    tx_rate,
                    connection_count: count,
                    rtt_ms,
                    cpu_percent,
                }
            })
            .collect();

        ranked.sort_by(|a, b| {
            let bw_b = b.rx_rate + b.tx_rate;
            let bw_a = a.rx_rate + a.tx_rate;
            bw_b.partial_cmp(&bw_a).unwrap_or(std::cmp::Ordering::Equal)
        });

        self.ranked = ranked;
    }

    pub fn ranked(&self) -> &[ProcessBandwidth] {
        &self.ranked
    }

    /// Spawn a background `ps` poll to refresh the CPU% cache. Coalesces — if
    /// a previous poll is still running, this is a no-op. Call from the app
    /// loop on a slow tick (~5s).
    pub fn refresh_cpu(&self) {
        if self.cpu_busy.load(Ordering::SeqCst) {
            return;
        }
        self.cpu_busy.store(true, Ordering::SeqCst);
        let cache = Arc::clone(&self.cpu_cache);
        let busy = Arc::clone(&self.cpu_busy);
        thread::spawn(move || {
            if let Some(pid_cpu) = sample_cpu() {
                *cache.lock().unwrap() = pid_cpu;
            }
            busy.store(false, Ordering::SeqCst);
        });
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn sample_cpu() -> Option<HashMap<u32, f64>> {
    let output = Command::new("ps")
        .args(["-A", "-o", "pid=,pcpu="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut map: HashMap<u32, f64> = HashMap::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let pid: Option<u32> = parts.next().and_then(|s| s.parse().ok());
        let cpu: Option<f64> = parts.next().and_then(|s| s.parse().ok());
        if let (Some(pid), Some(cpu)) = (pid, cpu) {
            map.insert(pid, cpu);
        }
    }
    Some(map)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn sample_cpu() -> Option<HashMap<u32, f64>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn make_conn(name: &str, pid: u32, state: &str) -> Connection {
        make_conn_rated(name, pid, state, None, None)
    }

    fn make_conn_rated(
        name: &str,
        pid: u32,
        state: &str,
        rx: Option<f64>,
        tx: Option<f64>,
    ) -> Connection {
        Connection {
            protocol: "TCP".into(),
            local_addr: "127.0.0.1:8080".into(),
            remote_addr: "10.0.0.1:443".into(),
            state: state.into(),
            pid: Some(pid),
            process_name: Some(name.into()),
            kernel_rtt_us: None,
            rx_rate: rx,
            tx_rate: tx,
            attribution: Default::default(),
            app_protocol: None,
            retransmits: 0,
            out_of_order: 0,
        }
    }

    fn make_interface(rx_rate: f64, tx_rate: f64) -> InterfaceTraffic {
        InterfaceTraffic {
            name: "en0".into(),
            rx_rate,
            tx_rate,
            rx_bytes_total: 1_000_000,
            tx_bytes_total: 500_000,
            rx_packets: 0,
            tx_packets: 0,
            rx_errors: 0,
            tx_errors: 0,
            rx_drops: 0,
            tx_drops: 0,
            rx_history: VecDeque::new(),
            tx_history: VecDeque::new(),
        }
    }

    #[test]
    fn empty_connections_produces_empty_ranking() {
        let mut collector = ProcessBandwidthCollector::new();
        collector.update(&[], &[make_interface(1000.0, 500.0)]);
        assert!(collector.ranked().is_empty());
    }

    #[test]
    fn listen_and_closed_connections_are_ignored() {
        // LISTEN / CLOSED carry no current peer traffic by definition,
        // so they should never produce a Processes-tab entry. Every
        // other state — TIME_WAIT, CLOSE_WAIT, UDP with empty state,
        // etc. — should pass through (regression test for the
        // pre-v0.21.2 behaviour where ESTABLISHED-only filtering hid
        // all UDP / QUIC processes).
        let mut collector = ProcessBandwidthCollector::new();
        let conns = vec![
            make_conn("nginx", 1, "LISTEN"),
            make_conn("ssh", 2, "CLOSED"),
        ];
        collector.update(&conns, &[make_interface(0.0, 0.0)]);
        assert!(collector.ranked().is_empty());
    }

    #[test]
    fn udp_and_time_wait_connections_count_toward_processes() {
        let mut collector = ProcessBandwidthCollector::new();
        let conns = vec![
            // UDP from lsof/procfs has empty state.
            make_conn("firefox", 100, ""),
            // TCP states other than ESTABLISHED still represent flows
            // the process is involved in.
            make_conn("ssh", 200, "TIME_WAIT"),
        ];
        collector.update(&conns, &[make_interface(0.0, 0.0)]);
        let names: std::collections::HashSet<&str> = collector
            .ranked()
            .iter()
            .map(|p| p.process_name.as_str())
            .collect();
        assert!(names.contains("firefox"), "UDP process should be ranked");
        assert!(names.contains("ssh"), "TIME_WAIT process should be ranked");
    }

    #[test]
    fn single_process_gets_its_own_rate() {
        let mut collector = ProcessBandwidthCollector::new();
        let conns = vec![make_conn_rated(
            "firefox",
            100,
            "ESTABLISHED",
            Some(1000.0),
            Some(500.0),
        )];
        collector.update(&conns, &[make_interface(1000.0, 500.0)]);
        assert_eq!(collector.ranked().len(), 1);
        let p = &collector.ranked()[0];
        assert_eq!(p.process_name, "firefox");
        assert!((p.rx_rate - 1000.0).abs() < 0.01);
        assert!((p.tx_rate - 500.0).abs() < 0.01);
        assert_eq!(p.connection_count, 1);
    }

    #[test]
    fn rates_aggregated_per_process_from_per_connection_rates() {
        // Three firefox connections (300/200/100 rx) + one curl (250 rx).
        // Real aggregation should give firefox 600, curl 250 — not equal
        // shares of the interface total like the old count-fraction model.
        let mut collector = ProcessBandwidthCollector::new();
        let conns = vec![
            make_conn_rated("firefox", 100, "ESTABLISHED", Some(300.0), Some(100.0)),
            make_conn_rated("firefox", 100, "ESTABLISHED", Some(200.0), Some(50.0)),
            make_conn_rated("firefox", 100, "ESTABLISHED", Some(100.0), Some(50.0)),
            make_conn_rated("curl", 200, "ESTABLISHED", Some(250.0), Some(0.0)),
        ];
        collector.update(&conns, &[make_interface(9999.0, 9999.0)]);
        let firefox = collector
            .ranked()
            .iter()
            .find(|p| p.process_name == "firefox")
            .unwrap();
        let curl = collector
            .ranked()
            .iter()
            .find(|p| p.process_name == "curl")
            .unwrap();
        assert_eq!(firefox.connection_count, 3);
        assert_eq!(curl.connection_count, 1);
        assert!((firefox.rx_rate - 600.0).abs() < 0.01);
        assert!((firefox.tx_rate - 200.0).abs() < 0.01);
        assert!((curl.rx_rate - 250.0).abs() < 0.01);
    }

    #[test]
    fn processes_without_rates_show_zero_not_fake_equal_share() {
        // Regression for the "all processes show identical RX" bug. When
        // no per-connection rates are available (no packet capture path,
        // Linux non-sudo, etc.) each process should report 0 rather than
        // an equal slice of total interface bandwidth.
        let mut collector = ProcessBandwidthCollector::new();
        let conns = vec![
            make_conn("firefox", 100, "ESTABLISHED"),
            make_conn("curl", 200, "ESTABLISHED"),
            make_conn("sshd", 300, "ESTABLISHED"),
        ];
        collector.update(&conns, &[make_interface(1000.0, 500.0)]);
        for p in collector.ranked() {
            assert_eq!(
                p.rx_rate, 0.0,
                "{} should have 0 rate when no per-connection data exists",
                p.process_name
            );
            assert_eq!(p.tx_rate, 0.0, "{} should have 0 tx rate", p.process_name);
            assert_eq!(p.rx_bytes, 0, "{} should have 0 bytes", p.process_name);
        }
    }

    #[test]
    fn bytes_accumulate_across_ticks_even_when_rate_drops_to_zero() {
        // Regression for the "TOP PROCESSES flashes then empties" bug. We
        // tick once with traffic, sleep so the next tick has measurable
        // elapsed, tick again with the rate gone to zero. The accumulated
        // bytes should persist instead of resetting (and the panel
        // therefore stays populated between bursts).
        let mut collector = ProcessBandwidthCollector::new();
        // First tick: rate=1000 B/s; sets last_tick but no accumulation
        // (elapsed=0 on the very first tick).
        let conns1 = vec![make_conn_rated(
            "firefox",
            100,
            "ESTABLISHED",
            Some(1000.0),
            Some(500.0),
        )];
        collector.update(&conns1, &[make_interface(0.0, 0.0)]);

        std::thread::sleep(Duration::from_millis(100));

        // Second tick: rate still 1000; some elapsed time passed so we
        // accumulate a non-zero count. The exact byte count is timing-
        // sensitive (CI runners can stall the sleep for hundreds of ms),
        // so we assert the *invariant* — that any accumulation happened —
        // rather than a specific byte range that flakes under load.
        collector.update(&conns1, &[make_interface(0.0, 0.0)]);
        let rx_bytes_after_first_burst = collector.ranked()[0].rx_bytes;
        assert!(
            rx_bytes_after_first_burst > 0,
            "expected non-zero rx_bytes after a burst, got {}",
            rx_bytes_after_first_burst
        );

        // Third tick: rate drops to 0. Cumulative bytes must persist.
        let conns2 = vec![make_conn_rated(
            "firefox",
            100,
            "ESTABLISHED",
            Some(0.0),
            Some(0.0),
        )];
        std::thread::sleep(Duration::from_millis(50));
        collector.update(&conns2, &[make_interface(0.0, 0.0)]);
        let firefox_after = &collector.ranked()[0];
        assert_eq!(
            firefox_after.rx_bytes, rx_bytes_after_first_burst,
            "cumulative bytes should persist when rate drops to zero",
        );
        assert_eq!(firefox_after.rx_rate, 0.0);
    }

    #[test]
    fn ranked_sorted_by_total_bandwidth_descending() {
        let mut collector = ProcessBandwidthCollector::new();
        let conns = vec![
            make_conn_rated("curl", 200, "ESTABLISHED", Some(100.0), Some(50.0)),
            make_conn_rated("firefox", 100, "ESTABLISHED", Some(500.0), Some(200.0)),
            make_conn_rated("firefox", 100, "ESTABLISHED", Some(300.0), Some(100.0)),
        ];
        collector.update(&conns, &[make_interface(9999.0, 9999.0)]);
        assert_eq!(collector.ranked()[0].process_name, "firefox");
        assert_eq!(collector.ranked()[1].process_name, "curl");
    }
}
