//! Prometheus `/metrics` + `/healthz` exporter (netwatch cloud Workstream C).
//!
//! Exposes the same aggregate signals the remote agent streams — interface
//! throughput, link health (gateway/DNS RTT + loss), and connection/TCP-state
//! counts — in Prometheus exposition format so an SRE can scrape netwatch into
//! Prometheus/Grafana/VictoriaMetrics with zero glue. This is the "speaks
//! OpenTelemetry" on-ramp: the default port (9464) is the OpenTelemetry
//! Prometheus exporter convention, and metric names/units follow Prometheus
//! base-unit conventions (`_bytes`, `_seconds`, `_ratio`, `_total`).
//!
//! Deliberately AGGREGATE only. Per-flow forensics (SNI/JA4/process) is
//! high-cardinality and belongs in the flow-event/OTLP stream, not in metrics —
//! shipping it here would reproduce exactly the cardinality-driven bill-shock we
//! position against. The HTTP listener is hand-rolled (no axum/hyper) to keep
//! the dependency surface minimal; it only serves two tiny GET endpoints.

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::app::safe_lock;
use crate::collectors::connections::ConnectionCollector;
use crate::collectors::health::HealthProber;
use crate::collectors::packets::PacketCollector;
use crate::collectors::traffic::InterfaceTraffic;

/// Default bind address — loopback only (never expose metrics to the network by
/// default), on the OpenTelemetry Prometheus exporter's conventional port.
pub const DEFAULT_METRICS_ADDR: &str = "127.0.0.1:9464";

/// Prometheus text exposition content type (format version 0.0.4).
const PROM_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Longest request line read, terminator included. A scrape's is a few dozen
/// bytes; without a cap a client could send one endless line into memory.
const MAX_REQUEST_LINE: u64 = 8 * 1024;

/// Time a client gets to send its whole request line. A deadline for the
/// line, not a timeout per read, so dribbling one byte every few seconds
/// can't hold a connection open.
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);

/// Connections served at once. Each has its own thread; past this a new
/// connection is closed unanswered rather than given another.
const MAX_CONNECTIONS: usize = 16;

#[derive(Clone, Default)]
pub struct InterfaceMetrics {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_bytes_per_sec: u64,
    pub tx_bytes_per_sec: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_drops: u64,
    pub tx_drops: u64,
}

/// The packet capture's counts since it opened, as of libpcap's last poll
/// (once a second). u64 totals built from libpcap's wrapping u32 counters,
/// so they keep climbing past four billion packets.
#[derive(Clone, Copy, Default)]
pub struct CaptureMetrics {
    pub received: u64,
    /// Kernel-buffer drops plus interface/driver drops.
    pub dropped: u64,
    /// Packets the dissectors decoded. A frame in a framing they do not read
    /// is listed as `Raw` but not counted.
    pub decoded: u64,
}

impl CaptureMetrics {
    fn of(packets: &PacketCollector) -> Self {
        let (received, dropped, decoded) = packets.capture_totals();
        Self {
            received,
            dropped,
            decoded,
        }
    }
}

/// A point-in-time snapshot of the aggregate metrics, refreshed each tick and
/// rendered to Prometheus text on scrape.
#[derive(Clone, Default)]
pub struct MetricsSnapshot {
    pub interfaces: Vec<InterfaceMetrics>,
    pub gateway_rtt_ms: Option<f64>,
    pub gateway_loss_pct: Option<f64>,
    pub dns_rtt_ms: Option<f64>,
    pub dns_loss_pct: Option<f64>,
    pub connection_count: u64,
    pub tcp_time_wait: u64,
    pub tcp_close_wait: u64,
    /// `None` while no capture is running, as when the daemon could not open
    /// one. Zeros would read as a capture that sees no traffic.
    pub capture: Option<CaptureMetrics>,
    /// Cumulative egress-policy violations per process (post-cooldown, so it
    /// tracks the alert stream). Low-cardinality by construction: only
    /// processes with a declared rule in `egress-policy.toml` can appear.
    pub policy_violations: Vec<(String, u64)>,
}

pub struct MetricsExporter {
    addr: String,
    snapshot: Arc<Mutex<Option<MetricsSnapshot>>>,
    collectors_ok: Arc<AtomicBool>,
    /// Connections being served now, at most [`MAX_CONNECTIONS`].
    active: Arc<AtomicUsize>,
}

impl MetricsExporter {
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            snapshot: Arc::new(Mutex::new(None)),
            collectors_ok: Arc::new(AtomicBool::new(true)),
            active: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Refresh the exported snapshot from the live collectors. Mirrors the data
    /// the remote agent gathers so scrape and stream agree.
    pub fn update(
        &self,
        interfaces: &[InterfaceTraffic],
        health: &HealthProber,
        connections: &ConnectionCollector,
        packets: &PacketCollector,
        policy_violations: Vec<(String, u64)>,
    ) {
        let ifaces = interfaces
            .iter()
            .map(|i| InterfaceMetrics {
                name: i.name.clone(),
                rx_bytes: i.rx_bytes_total,
                tx_bytes: i.tx_bytes_total,
                rx_bytes_per_sec: i.rx_rate as u64,
                tx_bytes_per_sec: i.tx_rate as u64,
                rx_packets: i.rx_packets,
                tx_packets: i.tx_packets,
                rx_errors: i.rx_errors,
                tx_errors: i.tx_errors,
                rx_drops: i.rx_drops,
                tx_drops: i.tx_drops,
            })
            .collect();

        let status = health.status();
        let conns = connections.connections();
        let (mut time_wait, mut close_wait) = (0u64, 0u64);
        for c in conns.iter() {
            match c.state.as_str() {
                "TIME_WAIT" | "TIME-WAIT" => time_wait += 1,
                "CLOSE_WAIT" | "CLOSE-WAIT" => close_wait += 1,
                _ => {}
            }
        }

        let snap = MetricsSnapshot {
            interfaces: ifaces,
            gateway_rtt_ms: status.gateway_rtt_ms,
            gateway_loss_pct: status.gateway_loss.pct(),
            dns_rtt_ms: status.dns_rtt_ms,
            dns_loss_pct: status.dns_loss.pct(),
            connection_count: conns.len() as u64,
            tcp_time_wait: time_wait,
            tcp_close_wait: close_wait,
            capture: packets.is_capturing().then(|| CaptureMetrics::of(packets)),
            policy_violations,
        };

        *safe_lock(&self.snapshot, "metrics::update") = Some(snap);
    }

    /// Reflect collector liveness in the `netwatch_collectors_ok` gauge.
    pub fn set_collectors_ok(&self, ok: bool) {
        self.collectors_ok.store(ok, Ordering::Relaxed);
    }

    /// Bind and start serving in a background thread. Logs and returns without
    /// panicking if the address can't be bound — like logging, the exporter is
    /// best-effort and must never take down the agent.
    pub fn start(&self) {
        let listener = match TcpListener::bind(&self.addr) {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(target: "netwatch::metrics", addr = %self.addr, error = %e, "could not bind metrics endpoint; export disabled");
                return;
            }
        };
        tracing::info!(target: "netwatch::metrics", addr = %self.addr, "metrics endpoint listening (/metrics, /healthz)");
        if let Some(warning) = listener
            .local_addr()
            .ok()
            .and_then(|addr| exposure_warning(&addr))
        {
            // The daemon's stderr is its journal; the log file alone is
            // somewhere nobody looks at startup.
            eprintln!("netwatch: {warning}");
            tracing::warn!(target: "netwatch::metrics", "{warning}");
        }
        self.serve(listener);
    }

    fn serve(&self, listener: TcpListener) {
        if let Err(error) = listener.set_nonblocking(true) {
            tracing::warn!(%error, "metrics listener nonblocking setup failed");
            return;
        }
        let snapshot = self.snapshot.clone();
        let collectors_ok = self.collectors_ok.clone();
        let active = self.active.clone();
        crate::sandbox::worker::spawn("metrics-listener", move || {
            while !crate::sandbox::worker::stopping() {
                let stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(25));
                        continue;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "metrics accept failed");
                        break;
                    }
                };
                let Some(slot) = ConnectionSlot::claim(&active) else {
                    tracing::debug!(target: "netwatch::metrics", "connection limit reached; refusing");
                    drop(stream);
                    continue;
                };
                let snapshot = snapshot.clone();
                let collectors_ok = collectors_ok.clone();
                // One short-lived thread per connection so a slow client can't
                // block scrapes; connections are closed after a single request.
                crate::sandbox::worker::spawn("metrics-client", move || {
                    let _slot = slot;
                    handle_conn(stream, &snapshot, &collectors_ok)
                });
            }
        });
    }
}

/// The startup warning for a listener anyone on the network can scrape, or
/// `None` on loopback. The endpoint has no authentication.
fn exposure_warning(addr: &std::net::SocketAddr) -> Option<String> {
    (!addr.ip().is_loopback()).then(|| {
        format!(
            "metrics endpoint on {addr} is reachable from the network and has no \
             authentication; bind to 127.0.0.1 unless a firewall limits who can reach it"
        )
    })
}

/// One of the [`MAX_CONNECTIONS`] places, given back when dropped, so a
/// handler that panics still frees its place.
struct ConnectionSlot(Arc<AtomicUsize>);

impl ConnectionSlot {
    fn claim(active: &Arc<AtomicUsize>) -> Option<Self> {
        active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_CONNECTIONS).then_some(n + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(active)))
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Reads from a client until a fixed deadline. Each read's timeout is the
/// time left, so the deadline holds however the client paces its bytes.
struct DeadlineReader<'a> {
    stream: &'a TcpStream,
    deadline: Instant,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(left))?;
        self.stream.read(buf)
    }
}

fn handle_conn(
    stream: TcpStream,
    snapshot: &Arc<Mutex<Option<MetricsSnapshot>>>,
    collectors_ok: &Arc<AtomicBool>,
) {
    // Everywhere but Linux an accepted socket inherits the listener's
    // non-blocking flag, and the deadline below needs blocking reads.
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_write_timeout(Some(REQUEST_DEADLINE));

    // Read only the request line; we don't need headers or a body for GET.
    let mut request_line = String::new();
    {
        let reader = DeadlineReader {
            stream: &stream,
            deadline: Instant::now() + REQUEST_DEADLINE,
        };
        let mut reader = BufReader::new(reader).take(MAX_REQUEST_LINE);
        if reader.read_line(&mut request_line).is_err() {
            return;
        }
    }
    if request_line.is_empty() {
        return;
    }
    if !request_line.ends_with('\n') {
        // Cut off at the cap (or the client hung up mid-line, and won't
        // read this anyway).
        respond(
            &stream,
            "414 URI Too Long",
            "text/plain; charset=utf-8",
            "request line too long\n",
        );
        return;
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");
    let path = route_path(path);

    let (status, content_type, body) = match (method, path) {
        ("GET", "/metrics") => {
            let snap = safe_lock(snapshot, "metrics::scrape").clone();
            let ok = collectors_ok.load(Ordering::Relaxed);
            (
                "200 OK",
                PROM_CONTENT_TYPE,
                render_prometheus(snap.as_ref(), ok),
            )
        }
        // Process-liveness probe (k8s liveness / systemd). Degradation is
        // observable via the netwatch_collectors_ok metric, not here.
        ("GET", "/healthz") => ("200 OK", "text/plain; charset=utf-8", "ok\n".to_string()),
        ("GET", _) => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found\n".to_string(),
        ),
        _ => (
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            "method not allowed\n".to_string(),
        ),
    };

    respond(&stream, status, content_type, &body);
}

fn respond(mut stream: &TcpStream, status: &str, content_type: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

/// Strip the query string from a request target, leaving just the path.
fn route_path(target: &str) -> &str {
    target.split('?').next().unwrap_or(target)
}

/// Escape a Prometheus label value per the exposition format.
fn escape_label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Render a snapshot to Prometheus text exposition format. A `None` snapshot
/// (no tick has run yet) still emits the agent-level gauges so a scrape never
/// returns empty.
pub fn render_prometheus(snap: Option<&MetricsSnapshot>, collectors_ok: bool) -> String {
    let mut o = String::with_capacity(4096);

    o.push_str("# HELP netwatch_up Whether the netwatch agent process is running.\n");
    o.push_str("# TYPE netwatch_up gauge\n");
    o.push_str("netwatch_up 1\n");

    o.push_str(
        "# HELP netwatch_collectors_ok Whether all collectors are healthy (0 = a collector thread has panicked).\n",
    );
    o.push_str("# TYPE netwatch_collectors_ok gauge\n");
    let _ = writeln!(o, "netwatch_collectors_ok {}", u8::from(collectors_ok));

    o.push_str("# HELP netwatch_build_info Agent build information.\n");
    o.push_str("# TYPE netwatch_build_info gauge\n");
    let _ = writeln!(
        o,
        "netwatch_build_info{{version=\"{}\"}} 1",
        escape_label(env!("CARGO_PKG_VERSION"))
    );

    let Some(s) = snap else {
        return o;
    };

    // --- Interfaces -------------------------------------------------------
    if !s.interfaces.is_empty() {
        // Each metric: one HELP/TYPE, then all per-interface series.
        let counter =
            |o: &mut String, name: &str, help: &str, pick: &dyn Fn(&InterfaceMetrics) -> u64| {
                let _ = writeln!(o, "# HELP {name} {help}");
                let _ = writeln!(o, "# TYPE {name} counter");
                for i in &s.interfaces {
                    let _ = writeln!(
                        o,
                        "{name}{{interface=\"{}\"}} {}",
                        escape_label(&i.name),
                        pick(i)
                    );
                }
            };
        let gauge =
            |o: &mut String, name: &str, help: &str, pick: &dyn Fn(&InterfaceMetrics) -> u64| {
                let _ = writeln!(o, "# HELP {name} {help}");
                let _ = writeln!(o, "# TYPE {name} gauge");
                for i in &s.interfaces {
                    let _ = writeln!(
                        o,
                        "{name}{{interface=\"{}\"}} {}",
                        escape_label(&i.name),
                        pick(i)
                    );
                }
            };

        counter(
            &mut o,
            "netwatch_interface_receive_bytes_total",
            "Total bytes received on the interface.",
            &|i| i.rx_bytes,
        );
        counter(
            &mut o,
            "netwatch_interface_transmit_bytes_total",
            "Total bytes transmitted on the interface.",
            &|i| i.tx_bytes,
        );
        counter(
            &mut o,
            "netwatch_interface_receive_packets_total",
            "Total packets received on the interface.",
            &|i| i.rx_packets,
        );
        counter(
            &mut o,
            "netwatch_interface_transmit_packets_total",
            "Total packets transmitted on the interface.",
            &|i| i.tx_packets,
        );
        counter(
            &mut o,
            "netwatch_interface_receive_errors_total",
            "Total receive errors on the interface.",
            &|i| i.rx_errors,
        );
        counter(
            &mut o,
            "netwatch_interface_transmit_errors_total",
            "Total transmit errors on the interface.",
            &|i| i.tx_errors,
        );
        counter(
            &mut o,
            "netwatch_interface_receive_drops_total",
            "Total dropped received packets on the interface.",
            &|i| i.rx_drops,
        );
        counter(
            &mut o,
            "netwatch_interface_transmit_drops_total",
            "Total dropped transmitted packets on the interface.",
            &|i| i.tx_drops,
        );
        gauge(
            &mut o,
            "netwatch_interface_receive_bytes_per_second",
            "Current receive throughput on the interface.",
            &|i| i.rx_bytes_per_sec,
        );
        gauge(
            &mut o,
            "netwatch_interface_transmit_bytes_per_second",
            "Current transmit throughput on the interface.",
            &|i| i.tx_bytes_per_sec,
        );
    }

    // --- Link health ------------------------------------------------------
    let mut gauge_opt = |name: &str, help: &str, ty: &str, value: Option<f64>| {
        let _ = writeln!(o, "# HELP {name} {help}");
        let _ = writeln!(o, "# TYPE {name} {ty}");
        if let Some(v) = value {
            let _ = writeln!(o, "{name} {v}");
        }
    };
    gauge_opt(
        "netwatch_gateway_rtt_seconds",
        "Round-trip time to the default gateway.",
        "gauge",
        s.gateway_rtt_ms.map(|ms| ms / 1000.0),
    );
    gauge_opt(
        "netwatch_gateway_loss_ratio",
        "Packet loss ratio to the default gateway (0-1).",
        "gauge",
        s.gateway_loss_pct.map(|p| p / 100.0),
    );
    gauge_opt(
        "netwatch_dns_rtt_seconds",
        "Round-trip time to the primary DNS resolver.",
        "gauge",
        s.dns_rtt_ms.map(|ms| ms / 1000.0),
    );
    gauge_opt(
        "netwatch_dns_loss_ratio",
        "Packet loss ratio to the primary DNS resolver (0-1).",
        "gauge",
        s.dns_loss_pct.map(|p| p / 100.0),
    );

    // --- Connections ------------------------------------------------------
    o.push_str("# HELP netwatch_connections Current number of tracked connections.\n");
    o.push_str("# TYPE netwatch_connections gauge\n");
    let _ = writeln!(o, "netwatch_connections {}", s.connection_count);

    o.push_str("# HELP netwatch_tcp_connections Current TCP connections by state.\n");
    o.push_str("# TYPE netwatch_tcp_connections gauge\n");
    let _ = writeln!(
        o,
        "netwatch_tcp_connections{{state=\"time_wait\"}} {}",
        s.tcp_time_wait
    );
    let _ = writeln!(
        o,
        "netwatch_tcp_connections{{state=\"close_wait\"}} {}",
        s.tcp_close_wait
    );

    // --- Packet capture ---------------------------------------------------
    // HELP and TYPE always, a sample only while a capture runs.
    let capture = s.capture.as_ref();
    for (name, help, value) in [
        (
            "netwatch_capture_packets_received_total",
            "Packets libpcap received since the capture opened.",
            capture.map(|c| c.received),
        ),
        (
            "netwatch_capture_packets_dropped_total",
            "Packets libpcap dropped since the capture opened, in its kernel buffer or by the interface or driver.",
            capture.map(|c| c.dropped),
        ),
        (
            "netwatch_capture_packets_decoded_total",
            "Packets netwatch decoded since the capture opened. Frames in a framing it does not decode, listed as Raw, are not counted.",
            capture.map(|c| c.decoded),
        ),
    ] {
        let _ = writeln!(o, "# HELP {name} {help}");
        let _ = writeln!(o, "# TYPE {name} counter");
        if let Some(v) = value {
            let _ = writeln!(o, "{name} {v}");
        }
    }

    // --- Egress policy linter --------------------------------------------
    if !s.policy_violations.is_empty() {
        o.push_str(
            "# HELP netwatch_policy_violations_total Egress policy violations detected per process (post-cooldown; observe → promote → warn).\n",
        );
        o.push_str("# TYPE netwatch_policy_violations_total counter\n");
        for (process, count) in &s.policy_violations {
            let _ = writeln!(
                o,
                "netwatch_policy_violations_total{{process=\"{}\"}} {}",
                escape_label(process),
                count
            );
        }
    }

    o
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> MetricsSnapshot {
        MetricsSnapshot {
            interfaces: vec![InterfaceMetrics {
                name: "en0".into(),
                rx_bytes: 1000,
                tx_bytes: 2000,
                rx_bytes_per_sec: 10,
                tx_bytes_per_sec: 20,
                rx_packets: 5,
                tx_packets: 6,
                rx_errors: 0,
                tx_errors: 0,
                rx_drops: 1,
                tx_drops: 0,
            }],
            gateway_rtt_ms: Some(12.0),
            gateway_loss_pct: Some(50.0),
            dns_rtt_ms: None,
            dns_loss_pct: None,
            connection_count: 7,
            tcp_time_wait: 3,
            tcp_close_wait: 1,
            capture: Some(CaptureMetrics {
                received: 9000,
                dropped: 12,
                decoded: 8800,
            }),
            policy_violations: vec![("curl".into(), 2)],
        }
    }

    const CAPTURE_COUNTERS: [&str; 3] = [
        "netwatch_capture_packets_received_total",
        "netwatch_capture_packets_dropped_total",
        "netwatch_capture_packets_decoded_total",
    ];

    /// The value of the unlabelled series `name`, if it has a sample.
    fn sample_value(out: &str, name: &str) -> Option<u64> {
        out.lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix(' '))
            .map(|v| v.parse().unwrap())
    }

    /// Feed `packets` to an exporter as `run_headless` does, and render what
    /// a scrape would get.
    fn update_and_scrape(packets: &PacketCollector) -> String {
        let exporter = MetricsExporter::new("127.0.0.1:0");
        let connections = ConnectionCollector::new(Arc::clone(&packets.stream_tracker));
        exporter.update(&[], &HealthProber::new(), &connections, packets, Vec::new());
        let snap = safe_lock(&exporter.snapshot, "metrics::test").clone();
        render_prometheus(Some(&snap.unwrap()), true)
    }

    #[test]
    fn renders_capture_counters() {
        let out = render_prometheus(Some(&sample()), true);
        for (name, value) in CAPTURE_COUNTERS.into_iter().zip([9000, 12, 8800]) {
            assert!(out.contains(&format!("# HELP {name} ")), "{name}");
            assert!(out.contains(&format!("# TYPE {name} counter\n")), "{name}");
            assert_eq!(sample_value(&out, name), Some(value), "{name}");
        }
    }

    /// With no capture running, as when the daemon lacks permission to open
    /// one, the counters have no sample. A zero would read as a quiet
    /// network.
    #[test]
    fn capture_counters_have_no_sample_without_a_capture() {
        let snap = MetricsSnapshot {
            capture: None,
            ..sample()
        };
        let out = render_prometheus(Some(&snap), true);
        for name in CAPTURE_COUNTERS {
            assert!(out.contains(&format!("# TYPE {name} counter\n")), "{name}");
            assert_eq!(sample_value(&out, name), None, "{name}");
        }

        let out = update_and_scrape(&PacketCollector::new());
        for name in CAPTURE_COUNTERS {
            assert_eq!(sample_value(&out, name), None, "not capturing: {name}");
        }
    }

    /// What `run_headless` does each tick: a running capture's totals reach
    /// the scrape through `update()`.
    #[test]
    fn update_exports_a_running_capture_s_totals() {
        let packets = PacketCollector::new();
        packets.mark_capturing_for_test();
        let mut last = pcap::Stat {
            received: 0,
            dropped: 0,
            if_dropped: 0,
        };
        let reading = pcap::Stat {
            received: 9000,
            dropped: 10,
            if_dropped: 2,
        };
        packets.stats.record_poll_for_test(&mut last, reading, 8800);
        let out = update_and_scrape(&packets);
        assert_eq!(
            CAPTURE_COUNTERS.map(|name| sample_value(&out, name)),
            [Some(9000), Some(12), Some(8800)]
        );
    }

    /// libpcap counts in u32, which wraps within the hour at 1.2M packets a
    /// second. The counters carry the collector's u64 totals past the wrap.
    #[test]
    fn capture_counters_climb_across_a_libpcap_wrap() {
        let packets = PacketCollector::new();
        let reading = |received, dropped| pcap::Stat {
            received,
            dropped,
            if_dropped: 0,
        };
        let scrape = |packets: &PacketCollector| {
            let snap = MetricsSnapshot {
                capture: Some(CaptureMetrics::of(packets)),
                ..sample()
            };
            let out = render_prometheus(Some(&snap), true);
            CAPTURE_COUNTERS.map(|name| sample_value(&out, name).unwrap())
        };
        let mut last = reading(0, 0);
        // Two polls to near the top of the range: one that moved 2^31 or
        // more would read as the counter going back.
        let stats = &packets.stats;
        stats.record_poll_for_test(&mut last, reading(u32::MAX / 2, u32::MAX / 2), 100);
        stats.record_poll_for_test(&mut last, reading(u32::MAX - 999, u32::MAX - 9), 200);
        let before = scrape(&packets);
        assert_eq!(
            before,
            [u64::from(u32::MAX) - 999, u64::from(u32::MAX) - 9, 200]
        );

        stats.record_poll_for_test(&mut last, reading(1000, 10), 300);
        let after = scrape(&packets);
        assert_eq!(
            after,
            [u64::from(u32::MAX) + 1001, u64::from(u32::MAX) + 11, 300]
        );
        assert!(before.iter().zip(after).all(|(b, a)| a > *b));
    }

    /// observability-export.md's table is the list of metric names and
    /// types that 1.0 keeps, so a metric added, renamed or retyped without
    /// the doc fails here.
    #[test]
    fn the_documented_metrics_are_the_ones_served() {
        let doc = include_str!("../docs/observability-export.md");
        let mut documented: Vec<(&str, &str)> = doc
            .lines()
            .filter_map(|line| {
                let mut cells = line.strip_prefix("| `")?.split('|');
                let name = cells.next()?.split(['`', '{']).next()?;
                let kind = cells.next()?.trim();
                name.starts_with("netwatch_").then_some((name, kind))
            })
            .collect();
        // Every family the exporter can serve has a series in the sample.
        let out = render_prometheus(Some(&sample()), true);
        let mut served: Vec<(&str, &str)> = out
            .lines()
            .filter_map(|line| {
                let mut words = line.strip_prefix("# TYPE ")?.split(' ');
                Some((words.next()?, words.next()?))
            })
            .collect();
        documented.sort_unstable();
        served.sort_unstable();
        assert_eq!(documented, served);
    }

    #[test]
    fn renders_policy_violation_counter_per_process() {
        let out = render_prometheus(Some(&sample()), true);
        assert!(out.contains("# TYPE netwatch_policy_violations_total counter"));
        assert!(out.contains("netwatch_policy_violations_total{process=\"curl\"} 2"));
    }

    #[test]
    fn renders_agent_gauges_even_without_snapshot() {
        let out = render_prometheus(None, true);
        assert!(out.contains("netwatch_up 1"));
        assert!(out.contains("netwatch_collectors_ok 1"));
        assert!(out.contains("netwatch_build_info{version="));
    }

    #[test]
    fn collectors_ok_reflects_flag() {
        assert!(render_prometheus(None, false).contains("netwatch_collectors_ok 0"));
    }

    #[test]
    fn renders_interface_and_health_series() {
        let s = sample();
        let out = render_prometheus(Some(&s), true);
        assert!(out.contains("netwatch_interface_receive_bytes_total{interface=\"en0\"} 1000"));
        assert!(out.contains("netwatch_interface_transmit_bytes_per_second{interface=\"en0\"} 20"));
        // ms → seconds conversion.
        assert!(out.contains("netwatch_gateway_rtt_seconds 0.012"));
        // pct → ratio conversion.
        assert!(out.contains("netwatch_gateway_loss_ratio 0.5"));
        assert!(out.contains("netwatch_connections 7"));
        assert!(out.contains("netwatch_tcp_connections{state=\"time_wait\"} 3"));
    }

    #[test]
    fn absent_health_metric_emits_help_but_no_sample() {
        let s = sample();
        let out = render_prometheus(Some(&s), true);
        // dns_rtt is None: the HELP/TYPE appear, but no sample line (which would
        // start with the metric name; HELP/TYPE lines start with '#').
        assert!(out.contains("# TYPE netwatch_dns_rtt_seconds gauge"));
        assert!(!out
            .lines()
            .any(|l| l.starts_with("netwatch_dns_rtt_seconds ")));
    }

    #[test]
    fn each_metric_declared_type_once() {
        let out = render_prometheus(Some(&sample()), true);
        let n = out
            .matches("# TYPE netwatch_interface_receive_bytes_total ")
            .count();
        assert_eq!(n, 1, "metric TYPE must be declared exactly once");
    }

    #[test]
    fn label_escaping() {
        assert_eq!(escape_label("a\"b\\c"), "a\\\"b\\\\c");
    }

    #[test]
    fn route_strips_query_string() {
        assert_eq!(route_path("/metrics?foo=bar"), "/metrics");
        assert_eq!(route_path("/healthz"), "/healthz");
    }

    #[test]
    fn warns_only_when_reachable_beyond_loopback() {
        for addr in ["127.0.0.1:9464", "[::1]:9464"] {
            assert_eq!(exposure_warning(&addr.parse().unwrap()), None, "{addr}");
        }
        for addr in ["0.0.0.0:9464", "[::]:9464", "192.0.2.10:9464"] {
            let warning = exposure_warning(&addr.parse().unwrap()).expect(addr);
            assert!(warning.contains("no authentication"), "{warning}");
        }
    }

    /// Serve on an ephemeral loopback port, as `start` does on its address.
    fn serve_ephemeral() -> (MetricsExporter, std::net::SocketAddr) {
        let exporter = MetricsExporter::new("127.0.0.1:0");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        exporter.serve(listener);
        (exporter, addr)
    }

    /// Send `request` and read until the server hangs up. A reset reads as
    /// whatever arrived before it.
    fn exchange(addr: std::net::SocketAddr, request: &[u8]) -> String {
        let mut stream = TcpStream::connect(addr).unwrap();
        // macOS refuses setsockopt with EINVAL once the peer has closed,
        // which the server may already have done to a refused connection.
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = stream.write_all(request);
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        response
    }

    fn wait_for_active(exporter: &MetricsExporter, want: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while exporter.active.load(Ordering::Acquire) != want {
            assert!(Instant::now() < deadline, "never reached {want} active");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn request_line_is_capped_at_8_kib() {
        let (_exporter, addr) = serve_ephemeral();
        let tail = " HTTP/1.1\r\n";
        let path = "a".repeat(MAX_REQUEST_LINE as usize - "GET /".len() - tail.len());
        let at_cap = format!("GET /{path}{tail}");
        assert_eq!(at_cap.len() as u64, MAX_REQUEST_LINE);
        assert!(exchange(addr, at_cap.as_bytes()).starts_with("HTTP/1.1 404"));
        // As many bytes with no end of line: the cap ends the read, not the
        // client, and the line is refused.
        let endless = "a".repeat(MAX_REQUEST_LINE as usize);
        assert!(exchange(addr, endless.as_bytes()).starts_with("HTTP/1.1 414"));
    }

    /// Slowloris: clients that send their request a byte at a time and never
    /// finish it. Each keeps its place only until the request deadline, and
    /// while all places are taken a new connection is closed unanswered.
    #[test]
    fn slow_clients_are_cut_off_at_the_deadline_and_capped() {
        let (exporter, addr) = serve_ephemeral();
        let started = Instant::now();
        // The read timeout is set before the server can hang up: macOS
        // refuses setsockopt with EINVAL on a socket whose peer has closed.
        let slow: Vec<TcpStream> = (0..MAX_CONNECTIONS)
            .map(|_| {
                let client = TcpStream::connect(addr).unwrap();
                client
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                client
            })
            .collect();
        wait_for_active(&exporter, MAX_CONNECTIONS);

        let refused_at = Instant::now();
        let refused = exchange(addr, b"GET /healthz HTTP/1.1\r\n");
        assert!(!refused.starts_with("HTTP/1.1"), "{refused}");
        assert!(refused_at.elapsed() < Duration::from_secs(2));

        let writers: Vec<TcpStream> = slow.iter().map(|s| s.try_clone().unwrap()).collect();
        std::thread::spawn(move || {
            for _ in 0..50 {
                for mut writer in &writers {
                    let _ = writer.write_all(b"G");
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        });
        for mut client in slow {
            // End of stream or a reset: either way the server hung up.
            let read = client.read(&mut [0u8; 64]);
            assert!(!matches!(read, Ok(n) if n > 0), "{read:?}");
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed >= REQUEST_DEADLINE - Duration::from_millis(500)
                && elapsed < REQUEST_DEADLINE * 2,
            "{elapsed:?}"
        );

        wait_for_active(&exporter, 0);
        assert!(exchange(addr, b"GET /healthz HTTP/1.1\r\n").starts_with("HTTP/1.1 200"));
    }
}
