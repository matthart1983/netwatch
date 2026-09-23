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
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::app::safe_lock;
use crate::collectors::connections::ConnectionCollector;
use crate::collectors::health::HealthProber;
use crate::collectors::traffic::InterfaceTraffic;

/// Default bind address — loopback only (never expose metrics to the network by
/// default), on the OpenTelemetry Prometheus exporter's conventional port.
pub const DEFAULT_METRICS_ADDR: &str = "127.0.0.1:9464";

/// Prometheus text exposition content type (format version 0.0.4).
const PROM_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

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
    /// Cumulative egress-policy violations per process (post-cooldown, so it
    /// tracks the alert stream). Low-cardinality by construction: only
    /// processes with a declared rule in `egress-policy.toml` can appear.
    pub policy_violations: Vec<(String, u64)>,
}

pub struct MetricsExporter {
    addr: String,
    snapshot: Arc<Mutex<Option<MetricsSnapshot>>>,
    collectors_ok: Arc<AtomicBool>,
}

impl MetricsExporter {
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            snapshot: Arc::new(Mutex::new(None)),
            collectors_ok: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Refresh the exported snapshot from the live collectors. Mirrors the data
    /// the remote agent gathers so scrape and stream agree.
    pub fn update(
        &self,
        interfaces: &[InterfaceTraffic],
        health: &HealthProber,
        connections: &ConnectionCollector,
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

        if let Err(error) = listener.set_nonblocking(true) {
            tracing::warn!(%error, "metrics listener nonblocking setup failed");
            return;
        }
        let snapshot = self.snapshot.clone();
        let collectors_ok = self.collectors_ok.clone();
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
                let snapshot = snapshot.clone();
                let collectors_ok = collectors_ok.clone();
                // One short-lived thread per connection so a slow client can't
                // block scrapes; connections are closed after a single request.
                crate::sandbox::worker::spawn("metrics-client", move || {
                    handle_conn(stream, &snapshot, &collectors_ok)
                });
            }
        });
    }
}

fn handle_conn(
    stream: TcpStream,
    snapshot: &Arc<Mutex<Option<MetricsSnapshot>>>,
    collectors_ok: &Arc<AtomicBool>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

    // Read only the request line; we don't need headers or a body for GET.
    let mut request_line = String::new();
    {
        let mut reader = BufReader::new(&stream);
        if reader.read_line(&mut request_line).is_err() {
            return;
        }
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

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = (&stream).write_all(response.as_bytes());
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
            policy_violations: vec![("curl".into(), 2)],
        }
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
}
