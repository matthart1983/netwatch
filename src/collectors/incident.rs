use super::connections::Connection;
use super::health::HealthStatus;
use super::network_intel::{Alert, DnsAnalytics};
use super::packets::{export_pcap, CapturedPacket, ExpertSeverity};
use super::process_bandwidth::ProcessBandwidth;
use super::traffic::InterfaceTraffic;
use chrono::{DateTime, Duration, Local, Utc};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_WINDOW_SECS: i64 = 300;
const MAX_RECORDED_PACKETS: usize = 20_000;
const MAX_SNAPSHOTS: usize = 600;
const MAX_ALERT_EVENTS: usize = 200;
const TOP_PROCESS_COUNT: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecorderState {
    Off,
    Armed,
    Frozen,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthSnapshot {
    pub timestamp: String,
    pub gateway_rtt_ms: Option<f64>,
    pub gateway_loss_pct: f64,
    pub dns_rtt_ms: Option<f64>,
    pub dns_loss_pct: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionSnapshot {
    pub timestamp: String,
    pub connections: Vec<Connection>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceSnapshot {
    pub name: String,
    pub rx_rate: f64,
    pub tx_rate: f64,
    pub rx_bytes_total: u64,
    pub tx_bytes_total: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_drops: u64,
    pub tx_drops: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BandwidthSnapshot {
    pub timestamp: String,
    pub interfaces: Vec<InterfaceSnapshot>,
    pub top_processes: Vec<ProcessBandwidth>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsSnapshot {
    pub timestamp: String,
    pub total_queries: u64,
    pub total_responses: u64,
    pub nxdomain_count: u64,
    pub latency_buckets: [u64; 8],
    pub top_domains: Vec<(String, u32)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertEventSnapshot {
    pub timestamp: String,
    pub severity: String,
    pub category: String,
    pub message: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
struct IncidentManifest {
    version: u32,
    state: String,
    window_seconds: i64,
    armed_at: Option<String>,
    frozen_at: Option<String>,
    freeze_reason: Option<String>,
    packet_count: usize,
    connection_snapshots: usize,
    health_snapshots: usize,
    bandwidth_snapshots: usize,
    dns_snapshots: usize,
    alert_events: usize,
}

#[derive(Debug, Clone)]
struct TimedPacket {
    observed_at: DateTime<Utc>,
    packet: CapturedPacket,
}

#[derive(Debug, Clone)]
struct TimedSnapshot<T> {
    observed_at: DateTime<Utc>,
    value: T,
}

pub struct IncidentRecorder {
    state: RecorderState,
    window: Duration,
    armed_at: Option<DateTime<Utc>>,
    frozen_at: Option<DateTime<Utc>>,
    freeze_reason: Option<String>,
    last_packet_id: u64,
    last_alert_history_len: usize,
    packets: VecDeque<TimedPacket>,
    connection_snapshots: VecDeque<TimedSnapshot<ConnectionSnapshot>>,
    health_snapshots: VecDeque<TimedSnapshot<HealthSnapshot>>,
    bandwidth_snapshots: VecDeque<TimedSnapshot<BandwidthSnapshot>>,
    dns_snapshots: VecDeque<TimedSnapshot<DnsSnapshot>>,
    alert_events: VecDeque<TimedSnapshot<AlertEventSnapshot>>,
}

impl Default for IncidentRecorder {
    fn default() -> Self {
        Self::new()
    }
}

impl IncidentRecorder {
    pub fn new() -> Self {
        Self {
            state: RecorderState::Off,
            window: Duration::seconds(DEFAULT_WINDOW_SECS),
            armed_at: None,
            frozen_at: None,
            freeze_reason: None,
            last_packet_id: 0,
            last_alert_history_len: 0,
            packets: VecDeque::new(),
            connection_snapshots: VecDeque::new(),
            health_snapshots: VecDeque::new(),
            bandwidth_snapshots: VecDeque::new(),
            dns_snapshots: VecDeque::new(),
            alert_events: VecDeque::new(),
        }
    }

    pub fn state(&self) -> RecorderState {
        self.state
    }

    pub fn is_off(&self) -> bool {
        self.state == RecorderState::Off
    }

    pub fn is_armed(&self) -> bool {
        self.state == RecorderState::Armed
    }

    pub fn is_frozen(&self) -> bool {
        self.state == RecorderState::Frozen
    }

    pub fn window_label(&self) -> String {
        let secs = self.window.num_seconds();
        if secs % 60 == 0 {
            format!("{}m", secs / 60)
        } else {
            format!("{}s", secs)
        }
    }

    pub fn freeze_reason(&self) -> Option<&str> {
        self.freeze_reason.as_deref()
    }

    pub fn arm(&mut self) {
        self.clear();
        self.state = RecorderState::Armed;
        self.armed_at = Some(Utc::now());
    }

    pub fn disarm(&mut self) {
        self.clear();
        self.state = RecorderState::Off;
        self.armed_at = None;
    }

    pub fn freeze(&mut self, reason: impl Into<String>) -> Result<(), String> {
        if !self.is_armed() {
            return Err("Flight recorder is not armed".to_string());
        }
        self.state = RecorderState::Frozen;
        self.frozen_at = Some(Utc::now());
        self.freeze_reason = Some(reason.into());
        Ok(())
    }

    pub fn prime_current_packets(&mut self, packets: &[CapturedPacket]) {
        self.last_packet_id = packets.last().map(|pkt| pkt.id).unwrap_or(0);
    }

    pub fn prime_alert_cursor(&mut self, alert_history_len: usize) {
        self.last_alert_history_len = alert_history_len;
    }

    pub fn record(
        &mut self,
        packets: &[CapturedPacket],
        connections: &[Connection],
        health: &HealthStatus,
        interfaces: &[InterfaceTraffic],
        processes: &[ProcessBandwidth],
        dns: &DnsAnalytics,
        alert_history: &[Alert],
    ) {
        if !self.is_armed() {
            return;
        }
        self.record_at(
            Utc::now(),
            packets,
            connections,
            health,
            interfaces,
            processes,
            dns,
            alert_history,
        );
    }

    pub fn export_bundle(&self, base_dir: &Path) -> Result<PathBuf, String> {
        if self.is_off() {
            return Err("Flight recorder is off".to_string());
        }

        let export_time = self.frozen_at.or(self.armed_at).unwrap_or_else(Utc::now);
        let stamp = DateTime::<Local>::from(export_time)
            .format("%Y%m%d_%H%M%S")
            .to_string();
        let dir = base_dir.join(format!("netwatch_incident_{stamp}"));
        fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create incident directory {}: {e}", dir.display()))?;

        let manifest = IncidentManifest {
            version: 1,
            state: match self.state {
                RecorderState::Off => "off",
                RecorderState::Armed => "armed",
                RecorderState::Frozen => "frozen",
            }
            .to_string(),
            window_seconds: self.window.num_seconds(),
            armed_at: self.armed_at.map(format_timestamp),
            frozen_at: self.frozen_at.map(format_timestamp),
            freeze_reason: self.freeze_reason.clone(),
            packet_count: self.packets.len(),
            connection_snapshots: self.connection_snapshots.len(),
            health_snapshots: self.health_snapshots.len(),
            bandwidth_snapshots: self.bandwidth_snapshots.len(),
            dns_snapshots: self.dns_snapshots.len(),
            alert_events: self.alert_events.len(),
        };

        write_json(&dir.join("manifest.json"), &manifest)?;
        write_json(
            &dir.join("connections.json"),
            &snapshot_values(&self.connection_snapshots),
        )?;
        write_json(
            &dir.join("health.json"),
            &snapshot_values(&self.health_snapshots),
        )?;
        write_json(
            &dir.join("bandwidth.json"),
            &snapshot_values(&self.bandwidth_snapshots),
        )?;
        write_json(&dir.join("dns.json"), &snapshot_values(&self.dns_snapshots))?;
        write_json(
            &dir.join("alerts.json"),
            &snapshot_values(&self.alert_events),
        )?;
        fs::write(dir.join("summary.md"), self.build_summary())
            .map_err(|e| format!("Failed to write summary.md: {e}"))?;

        if !self.packets.is_empty() {
            let packets: Vec<CapturedPacket> =
                self.packets.iter().map(|p| p.packet.clone()).collect();
            let pcap_path = dir.join("packets.pcap");
            export_pcap(&packets, &pcap_path.to_string_lossy())
                .map_err(|e| format!("Failed to write packets.pcap: {e}"))?;
        }

        Ok(dir)
    }

    fn record_at(
        &mut self,
        now: DateTime<Utc>,
        packets: &[CapturedPacket],
        connections: &[Connection],
        health: &HealthStatus,
        interfaces: &[InterfaceTraffic],
        processes: &[ProcessBandwidth],
        dns: &DnsAnalytics,
        alert_history: &[Alert],
    ) {
        self.record_new_packets(now, packets);
        self.record_alerts(now, alert_history);
        push_snapshot(
            &mut self.connection_snapshots,
            now,
            ConnectionSnapshot {
                timestamp: format_timestamp(now),
                connections: connections.to_vec(),
            },
        );
        push_snapshot(
            &mut self.health_snapshots,
            now,
            HealthSnapshot {
                timestamp: format_timestamp(now),
                gateway_rtt_ms: health.gateway_rtt_ms,
                gateway_loss_pct: health.gateway_loss_pct,
                dns_rtt_ms: health.dns_rtt_ms,
                dns_loss_pct: health.dns_loss_pct,
            },
        );
        push_snapshot(
            &mut self.bandwidth_snapshots,
            now,
            BandwidthSnapshot {
                timestamp: format_timestamp(now),
                interfaces: interfaces.iter().map(InterfaceSnapshot::from).collect(),
                top_processes: processes.iter().take(TOP_PROCESS_COUNT).cloned().collect(),
            },
        );
        push_snapshot(
            &mut self.dns_snapshots,
            now,
            DnsSnapshot {
                timestamp: format_timestamp(now),
                total_queries: dns.total_queries,
                total_responses: dns.total_responses,
                nxdomain_count: dns.nxdomain_count,
                latency_buckets: dns.latency_buckets,
                top_domains: dns.top_domains.clone(),
            },
        );
        self.prune(now);
    }

    fn record_new_packets(&mut self, now: DateTime<Utc>, packets: &[CapturedPacket]) {
        let mut last_packet_id = self.last_packet_id;
        for packet in packets {
            if packet.id <= last_packet_id {
                continue;
            }
            last_packet_id = packet.id;
            self.packets.push_back(TimedPacket {
                observed_at: now,
                packet: packet.clone(),
            });
        }
        self.last_packet_id = last_packet_id;
        while self.packets.len() > MAX_RECORDED_PACKETS {
            self.packets.pop_front();
        }
    }

    fn record_alerts(&mut self, now: DateTime<Utc>, alert_history: &[Alert]) {
        let skip = if alert_history.len() >= self.last_alert_history_len {
            self.last_alert_history_len
        } else {
            0
        };

        for alert in alert_history.iter().skip(skip) {
            self.alert_events.push_back(TimedSnapshot {
                observed_at: now,
                value: AlertEventSnapshot {
                    timestamp: format_timestamp(now),
                    severity: alert_severity_label(alert),
                    category: alert.category.label().to_string(),
                    message: alert.message.clone(),
                    detail: alert.detail.clone(),
                },
            });
        }
        self.last_alert_history_len = alert_history.len();

        while self.alert_events.len() > MAX_ALERT_EVENTS {
            self.alert_events.pop_front();
        }
    }

    fn prune(&mut self, now: DateTime<Utc>) {
        let cutoff = now - self.window;
        prune_queue(&mut self.packets, cutoff, |item| item.observed_at);
        prune_queue(&mut self.connection_snapshots, cutoff, |item| {
            item.observed_at
        });
        prune_queue(&mut self.health_snapshots, cutoff, |item| item.observed_at);
        prune_queue(&mut self.bandwidth_snapshots, cutoff, |item| {
            item.observed_at
        });
        prune_queue(&mut self.dns_snapshots, cutoff, |item| item.observed_at);
        prune_queue(&mut self.alert_events, cutoff, |item| item.observed_at);
    }

    fn build_summary(&self) -> String {
        let mut out = String::new();
        let total_packets = self.packets.len();
        let mut protocol_counts: HashMap<String, usize> = HashMap::new();
        let mut error_count = 0usize;
        let mut warning_count = 0usize;

        for packet in &self.packets {
            *protocol_counts
                .entry(packet.packet.protocol.clone())
                .or_insert(0) += 1;
            match packet.packet.expert {
                ExpertSeverity::Error => error_count += 1,
                ExpertSeverity::Warn => warning_count += 1,
                _ => {}
            }
        }

        let mut top_protocols: Vec<(String, usize)> = protocol_counts.into_iter().collect();
        top_protocols.sort_by(|a, b| b.1.cmp(&a.1));

        let latest_health = self.health_snapshots.back().map(|s| &s.value);
        let latest_dns = self.dns_snapshots.back().map(|s| &s.value);
        let latest_bandwidth = self.bandwidth_snapshots.back().map(|s| &s.value);
        let latest_connections = self.connection_snapshots.back().map(|s| &s.value);

        out.push_str("# NetWatch Incident Bundle\n\n");
        out.push_str("## Capture Window\n\n");
        out.push_str(&format!("- Window: `{}`\n", self.window_label()));
        if let Some(armed_at) = self.armed_at {
            out.push_str(&format!("- Armed: `{}`\n", format_timestamp(armed_at)));
        }
        if let Some(frozen_at) = self.frozen_at {
            out.push_str(&format!("- Frozen: `{}`\n", format_timestamp(frozen_at)));
        }
        if let Some(reason) = &self.freeze_reason {
            out.push_str(&format!("- Trigger: `{}`\n", reason));
        }
        out.push_str(&format!("- Packets retained: `{}`\n", total_packets));
        out.push_str(&format!(
            "- Connection snapshots: `{}`  Health snapshots: `{}`  Alert events: `{}`\n\n",
            self.connection_snapshots.len(),
            self.health_snapshots.len(),
            self.alert_events.len()
        ));

        out.push_str("## Traffic Signals\n\n");
        out.push_str(&format!("- Expert errors: `{}`\n", error_count));
        out.push_str(&format!("- Expert warnings: `{}`\n", warning_count));
        if top_protocols.is_empty() {
            out.push_str("- Top protocols: none captured\n");
        } else {
            let top = top_protocols
                .iter()
                .take(5)
                .map(|(proto, count)| format!("{} ({})", proto, count))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("- Top protocols: {}\n", top));
        }
        out.push('\n');

        out.push_str("## Health\n\n");
        if let Some(health) = latest_health {
            out.push_str(&format!(
                "- Gateway: RTT {}  Loss {:.0}%\n",
                format_rtt(health.gateway_rtt_ms),
                health.gateway_loss_pct
            ));
            out.push_str(&format!(
                "- DNS: RTT {}  Loss {:.0}%\n",
                format_rtt(health.dns_rtt_ms),
                health.dns_loss_pct
            ));
        } else {
            out.push_str("- No health samples captured\n");
        }
        out.push('\n');

        out.push_str("## Top Processes\n\n");
        if let Some(bandwidth) = latest_bandwidth {
            if bandwidth.top_processes.is_empty() {
                out.push_str("- No process bandwidth snapshot available\n");
            } else {
                for process in bandwidth.top_processes.iter().take(5) {
                    out.push_str(&format!(
                        "- `{}` (pid `{}`): RX `{:.1} KB/s`, TX `{:.1} KB/s`, conns `{}`\n",
                        process.process_name,
                        process
                            .pid
                            .map(|pid| pid.to_string())
                            .unwrap_or_else(|| "—".to_string()),
                        process.rx_rate / 1000.0,
                        process.tx_rate / 1000.0,
                        process.connection_count
                    ));
                }
            }
        } else {
            out.push_str("- No bandwidth samples captured\n");
        }
        out.push('\n');

        out.push_str("## Top Remote Endpoints\n\n");
        if let Some(connections) = latest_connections {
            let mut counts: HashMap<String, usize> = HashMap::new();
            for conn in &connections.connections {
                *counts.entry(conn.remote_addr.clone()).or_insert(0) += 1;
            }
            if counts.is_empty() {
                out.push_str("- No active connections in latest snapshot\n");
            } else {
                let mut endpoints: Vec<(String, usize)> = counts.into_iter().collect();
                endpoints.sort_by(|a, b| b.1.cmp(&a.1));
                for (remote, count) in endpoints.into_iter().take(5) {
                    out.push_str(&format!("- `{}` — {} connections\n", remote, count));
                }
            }
        } else {
            out.push_str("- No connection snapshots captured\n");
        }
        out.push('\n');

        out.push_str("## DNS\n\n");
        if let Some(dns) = latest_dns {
            out.push_str(&format!(
                "- Queries: `{}`  Responses: `{}`  NXDOMAIN: `{}`\n",
                dns.total_queries, dns.total_responses, dns.nxdomain_count
            ));
            if dns.top_domains.is_empty() {
                out.push_str("- Top domains: none\n");
            } else {
                let domains = dns
                    .top_domains
                    .iter()
                    .take(5)
                    .map(|(domain, count)| format!("{} ({})", domain, count))
                    .collect::<Vec<_>>()
                    .join(", ");
                out.push_str(&format!("- Top domains: {}\n", domains));
            }
        } else {
            out.push_str("- No DNS samples captured\n");
        }
        out.push('\n');

        out.push_str("## Alert Timeline\n\n");
        if self.alert_events.is_empty() {
            out.push_str("- No alert events captured\n");
        } else {
            for alert in self.alert_events.iter().rev().take(10).rev() {
                out.push_str(&format!(
                    "- `{}` {} / {} — {} ({})\n",
                    alert.value.timestamp,
                    alert.value.severity,
                    alert.value.category,
                    alert.value.message,
                    alert.value.detail
                ));
            }
        }

        out
    }

    fn clear(&mut self) {
        self.freeze_reason = None;
        self.frozen_at = None;
        self.last_packet_id = 0;
        self.last_alert_history_len = 0;
        self.packets.clear();
        self.connection_snapshots.clear();
        self.health_snapshots.clear();
        self.bandwidth_snapshots.clear();
        self.dns_snapshots.clear();
        self.alert_events.clear();
    }
}

impl From<&InterfaceTraffic> for InterfaceSnapshot {
    fn from(value: &InterfaceTraffic) -> Self {
        Self {
            name: value.name.clone(),
            rx_rate: value.rx_rate,
            tx_rate: value.tx_rate,
            rx_bytes_total: value.rx_bytes_total,
            tx_bytes_total: value.tx_bytes_total,
            rx_errors: value.rx_errors,
            tx_errors: value.tx_errors,
            rx_drops: value.rx_drops,
            tx_drops: value.tx_drops,
        }
    }
}

fn prune_queue<T, F>(queue: &mut VecDeque<T>, cutoff: DateTime<Utc>, observed_at: F)
where
    F: Fn(&T) -> DateTime<Utc>,
{
    while queue
        .front()
        .map(|item| observed_at(item) < cutoff)
        .unwrap_or(false)
    {
        queue.pop_front();
    }
}

fn push_snapshot<T>(queue: &mut VecDeque<TimedSnapshot<T>>, now: DateTime<Utc>, value: T) {
    queue.push_back(TimedSnapshot {
        observed_at: now,
        value,
    });
    while queue.len() > MAX_SNAPSHOTS {
        queue.pop_front();
    }
}

fn snapshot_values<T: Clone>(queue: &VecDeque<TimedSnapshot<T>>) -> Vec<T> {
    queue.iter().map(|item| item.value.clone()).collect()
}

fn format_timestamp(timestamp: DateTime<Utc>) -> String {
    DateTime::<Local>::from(timestamp)
        .format("%Y-%m-%d %H:%M:%S %Z")
        .to_string()
}

fn format_rtt(rtt: Option<f64>) -> String {
    rtt.map(|value| format!("{value:.1}ms"))
        .unwrap_or_else(|| "—".to_string())
}

fn alert_severity_label(alert: &Alert) -> String {
    format!("{:?}", alert.severity)
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let file =
        fs::File::create(path).map_err(|e| format!("Failed to create {}: {e}", path.display()))?;
    serde_json::to_writer_pretty(file, value)
        .map_err(|e| format!("Failed to write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn make_packet(id: u64, protocol: &str, expert: ExpertSeverity) -> CapturedPacket {
        CapturedPacket {
            id,
            timestamp: "12:00:00.000".into(),
            src_ip: "127.0.0.1".into(),
            dst_ip: "10.0.0.1".into(),
            src_host: None,
            dst_host: None,
            protocol: protocol.into(),
            length: 64,
            src_port: Some(12345),
            dst_port: Some(443),
            info: "test packet".into(),
            details: Vec::new(),
            payload_text: String::new(),
            raw_hex: String::new(),
            raw_ascii: String::new(),
            raw_bytes: vec![0, 1, 2, 3],
            stream_index: Some(1),
            tcp_flags: Some(0x02),
            expert,
            timestamp_ns: 1,
        }
    }

    fn make_connection() -> Connection {
        Connection {
            protocol: "TCP".into(),
            local_addr: "127.0.0.1:12345".into(),
            remote_addr: "10.0.0.1:443".into(),
            state: "ESTABLISHED".into(),
            pid: Some(4242),
            process_name: Some("curl".into()),
            kernel_rtt_us: Some(12_000.0),
            rx_rate: None,
            tx_rate: None,
        }
    }

    fn make_health() -> HealthStatus {
        HealthStatus {
            gateway_rtt_ms: Some(2.5),
            gateway_loss_pct: 0.0,
            dns_rtt_ms: Some(14.0),
            dns_loss_pct: 0.0,
            gateway_rtt_history: VecDeque::new(),
            dns_rtt_history: VecDeque::new(),
        }
    }

    fn make_interface() -> InterfaceTraffic {
        InterfaceTraffic {
            name: "en0".into(),
            rx_rate: 1000.0,
            tx_rate: 500.0,
            rx_bytes_total: 100_000,
            tx_bytes_total: 50_000,
            rx_packets: 10,
            tx_packets: 8,
            rx_errors: 0,
            tx_errors: 0,
            rx_drops: 0,
            tx_drops: 0,
            rx_history: VecDeque::new(),
            tx_history: VecDeque::new(),
        }
    }

    fn make_process() -> ProcessBandwidth {
        ProcessBandwidth {
            process_name: "curl".into(),
            pid: Some(4242),
            rx_bytes: 100_000,
            tx_bytes: 50_000,
            rx_rate: 1000.0,
            tx_rate: 500.0,
            connection_count: 1,
            rtt_ms: None,
            cpu_percent: None,
        }
    }

    #[test]
    fn old_data_is_pruned_when_window_expires() {
        let mut recorder = IncidentRecorder::new();
        recorder.arm();

        let now = Utc::now();
        recorder.record_at(
            now,
            &[make_packet(1, "TCP", ExpertSeverity::Chat)],
            &[make_connection()],
            &make_health(),
            &[make_interface()],
            &[make_process()],
            &DnsAnalytics::default(),
            &[],
        );
        recorder.record_at(
            now + Duration::seconds(DEFAULT_WINDOW_SECS + 1),
            &[make_packet(2, "DNS", ExpertSeverity::Warn)],
            &[make_connection()],
            &make_health(),
            &[make_interface()],
            &[make_process()],
            &DnsAnalytics::default(),
            &[],
        );

        assert_eq!(recorder.packets.len(), 1);
        assert_eq!(recorder.packets.front().unwrap().packet.id, 2);
    }

    #[test]
    fn export_bundle_writes_summary_manifest_and_pcap() {
        let mut recorder = IncidentRecorder::new();
        recorder.arm();
        recorder.record_at(
            Utc::now(),
            &[make_packet(1, "DNS", ExpertSeverity::Error)],
            &[make_connection()],
            &make_health(),
            &[make_interface()],
            &[make_process()],
            &DnsAnalytics {
                total_queries: 1,
                total_responses: 1,
                nxdomain_count: 1,
                latency_buckets: [0; 8],
                top_domains: vec![("example.com".into(), 1)],
            },
            &[],
        );
        recorder.freeze("manual freeze").unwrap();

        let root =
            std::env::temp_dir().join(format!("netwatch_incident_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let bundle = recorder.export_bundle(&root).unwrap();
        assert!(bundle.join("summary.md").exists());
        assert!(bundle.join("manifest.json").exists());
        assert!(bundle.join("packets.pcap").exists());

        let summary = fs::read_to_string(bundle.join("summary.md")).unwrap();
        assert!(summary.contains("NetWatch Incident Bundle"));
        assert!(summary.contains("manual freeze"));

        let _ = fs::remove_dir_all(&root);
    }
}
