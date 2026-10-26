use super::connections::Connection;
use super::health::HealthStatus;
use super::network_intel::{Alert, DnsAnalytics};
use super::packets::export::{self, ExportSummary, Format};
use super::packets::{CapturedPacket, ExpertSeverity};
use super::process_bandwidth::ProcessBandwidth;
use super::traffic::InterfaceTraffic;
use chrono::{DateTime, Duration, Local, Utc};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

const DEFAULT_WINDOW_SECS: i64 = 300;
const MAX_RECORDED_PACKETS: usize = 20_000;
/// What the recorded packets may hold, as [`TimedPacket::held_bytes`]
/// counts it. Under bulk traffic, where one GSO frame can be 64 KiB, this
/// rather than the count is what limits the recorder.
const MAX_RECORDED_PACKET_BYTES: usize = 64 << 20;
const MAX_SNAPSHOTS: usize = 600;
/// Connection rows all the snapshots may hold together, about 55 MB at the
/// usual 1.1 KB a row. A host with 10,000 connections fills it in five
/// snapshots. `summary.md` and REFERENCE write the number out.
const MAX_CONNECTION_ROWS: usize = 50_000;
/// What the snapshots may hold together, as [`connection_held_bytes`]
/// counts it. Rows of the usual size reach [`MAX_CONNECTION_ROWS`] first.
/// A row carries its flow's classification, and the peer picks the SNI or
/// request path in it, so 1,024 rows, as many flows as the stream tracker
/// classifies, can hold 8 MB.
const MAX_CONNECTION_BYTES: usize = 64 << 20;
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
    /// `None` when the probe had not completed or could not be sent.
    pub gateway_loss_pct: Option<f64>,
    pub dns_rtt_ms: Option<f64>,
    pub dns_loss_pct: Option<f64>,
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
    packet_export: ExportSummary,
    packet_artifacts: Vec<String>,
    packet_annotations: bool,
    capture_limitations: String,
    last_capture_status: Option<CaptureStatus>,
    state: String,
    window_seconds: i64,
    armed_at: Option<String>,
    frozen_at: Option<String>,
    freeze_reason: Option<String>,
    packet_count: usize,
    connection_snapshots: usize,
    connection_rows_dropped: usize,
    health_snapshots: usize,
    bandwidth_snapshots: usize,
    dns_snapshots: usize,
    alert_events: usize,
}

/// Latest capture-session sample, not the incident window's loss total.
#[derive(Debug, Clone, Serialize)]
pub struct CaptureStatus {
    pub session: String,
    pub sampled_at_utc_ms: u64,
    pub drops: Option<u64>,
}

#[derive(Debug, Clone)]
struct TimedPacket {
    observed_at: DateTime<Utc>,
    packet: CapturedPacket,
}

impl TimedPacket {
    /// What this copy costs against [`MAX_RECORDED_PACKET_BYTES`]: the
    /// captured bytes and the text decoded from them, the flow's
    /// classification included. The fixed part counts too, or a flood of
    /// tiny frames would look free.
    fn held_bytes(&self) -> usize {
        let p = &self.packet;
        let host = |name: &Option<String>| name.as_ref().map_or(0, String::len);
        std::mem::size_of::<Self>()
            + p.timestamp.len()
            + p.src_ip.len()
            + p.dst_ip.len()
            + host(&p.src_host)
            + host(&p.dst_host)
            + p.protocol.len()
            + p.info.len()
            + p.details
                .iter()
                .map(|line| std::mem::size_of::<String>() + line.len())
                .sum::<usize>()
            + p.payload_text.len()
            + p.raw_bytes.len()
            + p.decrypted_plaintext.as_ref().map_or(0, Vec::len)
            + p.app_protocol
                .as_ref()
                .map_or(0, super::packets::label_bytes)
            + p.annotation
                .as_ref()
                .map_or(0, |_| std::mem::size_of::<export::PacketAnnotation>())
    }
}

/// What a connection row costs against [`MAX_CONNECTION_BYTES`]: the struct,
/// its text and its flow's classification.
fn connection_held_bytes(conn: &Connection) -> usize {
    let text = |s: &Option<String>| s.as_ref().map_or(0, String::len);
    let evidence = &conn.evidence;
    std::mem::size_of::<Connection>()
        + conn.protocol.len()
        + conn.local_addr.len()
        + conn.remote_addr.len()
        + conn.state.len()
        + text(&conn.process_name)
        + evidence.process.as_ref().map_or(0, |p| {
            p.session.len() + p.start_token.len() + text(&p.executable) + text(&p.network_namespace)
        })
        + text(&evidence.corroborated_by)
        + evidence.flow.as_ref().map_or(0, |f| {
            f.session.len()
                + f.protocol.len()
                + f.local.len()
                + f.remote.len()
                + text(&f.network_namespace)
        })
        + conn
            .app_protocol
            .as_ref()
            .map_or(0, super::packets::label_bytes)
}

#[derive(Debug, Clone)]
struct TimedSnapshot<T> {
    observed_at: DateTime<Utc>,
    value: T,
}

#[derive(Clone)]
pub struct IncidentRecorder {
    last_capture_status: Option<CaptureStatus>,
    state: RecorderState,
    window: Duration,
    armed_at: Option<DateTime<Utc>>,
    frozen_at: Option<DateTime<Utc>>,
    freeze_reason: Option<String>,
    last_packet_id: u64,
    /// Monotonic timestamp of the most recently recorded alert. Cursoring
    /// on the alert's own `Instant` (rather than the history length) is
    /// robust to `alert_history` being a bounded ring buffer: once it hits
    /// its cap the length stops growing, so a length cursor would `skip`
    /// the whole slice and silently drop every new alert from the bundle.
    last_recorded_alert_at: Option<std::time::Instant>,
    packets: VecDeque<TimedPacket>,
    connection_snapshots: VecDeque<TimedSnapshot<ConnectionSnapshot>>,
    /// When each snapshot the row budget dropped was taken, and its rows.
    /// They leave with the window, like the snapshots they stood for.
    dropped_connection_rows: Vec<(DateTime<Utc>, usize)>,
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
            last_capture_status: None,
            state: RecorderState::Off,
            window: Duration::seconds(DEFAULT_WINDOW_SECS),
            armed_at: None,
            frozen_at: None,
            freeze_reason: None,
            last_packet_id: 0,
            last_recorded_alert_at: None,
            packets: VecDeque::new(),
            connection_snapshots: VecDeque::new(),
            dropped_connection_rows: Vec::new(),
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

    /// Sample the capture's session and libpcap drop count while armed, for
    /// the manifest. Frozen, the sample stays the one from the window.
    pub fn record_capture_status(&mut self, session: Option<String>, drops: Option<u64>) {
        if self.is_armed() {
            self.last_capture_status = session.map(|session| CaptureStatus {
                session,
                sampled_at_utc_ms: super::attribution::utc_ms(),
                drops,
            });
        }
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

    /// Skip alerts that already existed when the recorder armed, so a
    /// bundle only captures alerts raised during the incident window.
    pub fn prime_alert_cursor(&mut self, last_alert_at: Option<std::time::Instant>) {
        self.last_recorded_alert_at = last_alert_at;
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

    /// What a bundle's packet files would hold, for the export preview.
    pub fn packet_preview(&self) -> ExportSummary {
        export::preview_iter(self.packets.iter().map(|p| &p.packet))
    }

    /// Write the bundle into `base_dir`, with packet comments on.
    pub fn export_bundle(&self, base_dir: &Path) -> Result<PathBuf, String> {
        self.export_bundle_options(base_dir, true, &AtomicBool::new(false))
    }

    /// Write the bundle into `base_dir` and return its directory. Setting
    /// `cancel` stops the write and removes everything written so far.
    pub fn export_bundle_options(
        &self,
        base_dir: &Path,
        annotations: bool,
        cancel: &AtomicBool,
    ) -> Result<PathBuf, String> {
        if self.is_off() {
            return Err("Flight recorder is off".to_string());
        }

        let export_time = self.frozen_at.or(self.armed_at).unwrap_or_else(Utc::now);
        let stamp = DateTime::<Local>::from(export_time)
            .format("%Y%m%d_%H%M%S")
            .to_string();
        // Build the bundle in a private directory of its own and rename it
        // into place only once every file is written, so a failure or a
        // cancel never leaves a half-written bundle that looks complete. The
        // id keeps two exports of the same frozen window apart.
        crate::owner_only::create_dir_all(base_dir).map_err(|e| {
            format!(
                "Failed to create export directory {}: {e}",
                base_dir.display()
            )
        })?;
        let id = uuid::Uuid::new_v4().simple().to_string();
        let final_dir = base_dir.join(format!("netwatch_incident_{stamp}_{}", &id[..8]));
        let dir = base_dir.join(format!(".netwatch_incident_{id}.tmp"));
        crate::owner_only::dir_builder()
            .create(&dir)
            .map_err(|e| format!("Failed to create incident directory {}: {e}", dir.display()))?;
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        let packets: Vec<&CapturedPacket> = self.packets.iter().map(|p| &p.packet).collect();
        let mut packet_export = export::preview(&packets);
        let mut artifacts = Vec::new();
        if packet_export.packets > 0 {
            packet_export = export::export_capture(
                &packets,
                &dir.join("packets.pcapng"),
                Format::PcapNg,
                annotations,
                cancel,
            )?;
            artifacts.push("packets.pcapng".into());
            // Classic PCAP has one link type per file and 32-bit seconds; a
            // capture it cannot hold is only in the PCAPNG, never refused.
            if export::fits_pcap(&packets) {
                export::export_capture(
                    &packets,
                    &dir.join("packets.pcap"),
                    Format::Pcap,
                    false,
                    cancel,
                )?;
                artifacts.push("packets.pcap".into());
            }
        }
        if cancel.load(Ordering::Relaxed) {
            return Err("Export cancelled".into());
        }

        let manifest = IncidentManifest {
            version: 2,
            packet_export,
            packet_artifacts: artifacts,
            packet_annotations: annotations,
            last_capture_status: self.last_capture_status.clone(),
            capture_limitations: "Retained packets only; not a complete wire capture. last_capture_status is the latest sample, not an incident-window loss total; its drops count from the last capture start, so they include any earlier session that ended when the stream indexes ran out. Unknown ownership is not resolved at export. Comments contain bracketed socket observations, not proof of packet ownership. Packet bytes and incident JSON are not redacted. Session keys and separately decrypted plaintext are excluded.".into(),
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
            connection_rows_dropped: self.connection_rows_dropped(),
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
        create_new(&dir.join("summary.md"))
            .and_then(|mut file| file.write_all(self.build_summary().as_bytes()))
            .map_err(|e| format!("Failed to write summary.md: {e}"))?;

        if cancel.load(Ordering::Relaxed) {
            return Err("Export cancelled".into());
        }
        std::fs::rename(&dir, &final_dir).map_err(|e| {
            format!(
                "Failed to publish incident bundle {}: {e}",
                final_dir.display()
            )
        })?;
        Ok(final_dir)
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
                gateway_loss_pct: health.gateway_loss.pct(),
                dns_rtt_ms: health.dns_rtt_ms,
                dns_loss_pct: health.dns_loss.pct(),
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
        self.thin_connection_snapshots(now);
    }

    fn record_new_packets(&mut self, now: DateTime<Utc>, packets: &[CapturedPacket]) {
        // A live packet gains its socket owner a poll after it was captured,
        // by when the recorder already holds a copy, so the copy catches up
        // here. Only while armed: a frozen incident never consults live owners.
        let annotations: HashMap<_, _> = packets
            .iter()
            .filter_map(|p| p.annotation.as_ref().map(|a| (p.id, a)))
            .collect();
        if let Some(oldest) = annotations.keys().min().copied() {
            for saved in self
                .packets
                .iter_mut()
                .rev()
                .take_while(|saved| saved.packet.id >= oldest)
            {
                if saved.packet.annotation.is_none() {
                    if let Some(annotation) = annotations.get(&saved.packet.id) {
                        saved.packet.annotation = Some((*annotation).clone());
                    }
                }
            }
        }
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
        // Oldest first, until both the count and the bytes fit.
        let mut held: usize = self.packets.iter().map(TimedPacket::held_bytes).sum();
        while self.packets.len() > MAX_RECORDED_PACKETS || held > MAX_RECORDED_PACKET_BYTES {
            let Some(oldest) = self.packets.pop_front() else {
                break;
            };
            held -= oldest.held_bytes();
        }
    }

    /// Keep the connection snapshots within [`MAX_CONNECTION_ROWS`] and
    /// [`MAX_CONNECTION_BYTES`]. Every snapshot kept is whole, since a
    /// snapshot missing rows would read as connections that had closed, and
    /// the newest is always kept, even alone over the budget. Older ones go
    /// one at a time, each time the one whose loss leaves the shortest gap,
    /// with the window's start standing in for the snapshot before the
    /// oldest. While three or more fit, up to 16,666 rows each at the usual
    /// row size, those left stay spread across the window. With two, the
    /// older one's age cycles from a second to the whole window, and past
    /// 25,000 rows only the newest is left. The choice goes by time, not
    /// size, so a snapshot from a short burst of connections is usually
    /// dropped as soon as a newer one is taken.
    fn thin_connection_snapshots(&mut self, now: DateTime<Utc>) {
        let start = now - self.window;
        let held = |rows: &[Connection]| rows.iter().map(connection_held_bytes).sum::<usize>();
        let mut rows: usize = self
            .connection_snapshots
            .iter()
            .map(|s| s.value.connections.len())
            .sum();
        let mut bytes: usize = self
            .connection_snapshots
            .iter()
            .map(|s| held(&s.value.connections))
            .sum();
        while (rows > MAX_CONNECTION_ROWS || bytes > MAX_CONNECTION_BYTES)
            && self.connection_snapshots.len() > 1
        {
            let snapshots = &self.connection_snapshots;
            let gap_without = |i: usize| {
                let before = if i == 0 {
                    start
                } else {
                    snapshots[i - 1].observed_at
                };
                snapshots[i + 1].observed_at - before
            };
            let Some(dropped) = (0..snapshots.len() - 1)
                .min_by_key(|&i| gap_without(i))
                .and_then(|i| self.connection_snapshots.remove(i))
            else {
                break;
            };
            rows -= dropped.value.connections.len();
            bytes -= held(&dropped.value.connections);
            self.dropped_connection_rows
                .push((dropped.observed_at, dropped.value.connections.len()));
        }
    }

    /// Rows the row budget dropped from snapshots still in the window.
    fn connection_rows_dropped(&self) -> usize {
        self.dropped_connection_rows
            .iter()
            .map(|(_, rows)| rows)
            .sum()
    }

    fn record_alerts(&mut self, now: DateTime<Utc>, alert_history: &[Alert]) {
        // Record every alert newer than the cursor. Comparing the alert's
        // own monotonic timestamp survives `alert_history` sliding once it
        // reaches its ring-buffer cap, where a length-based cursor breaks.
        let cursor = self.last_recorded_alert_at;
        let mut newest = cursor;
        for alert in alert_history
            .iter()
            .filter(|a| cursor.is_none_or(|c| a.timestamp > c))
        {
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
            newest = Some(match newest {
                Some(n) if n >= alert.timestamp => n,
                _ => alert.timestamp,
            });
        }
        self.last_recorded_alert_at = newest;

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
        self.dropped_connection_rows
            .retain(|(observed_at, _)| *observed_at >= cutoff);
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
        top_protocols.sort_by_key(|b| std::cmp::Reverse(b.1));

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
            "- Connection snapshots: `{}`  Health snapshots: `{}`  Alert events: `{}`\n",
            self.connection_snapshots.len(),
            self.health_snapshots.len(),
            self.alert_events.len()
        ));
        let rows_dropped = self.connection_rows_dropped();
        if rows_dropped > 0 {
            // The newest snapshot is kept whole even over the budget, so
            // this says what the rows went for, not that the bundle fits.
            out.push_str(&format!(
                "- Connection rows dropped: `{}` (whole older snapshots, for the budget of 50,000 rows and 64 MiB)\n",
                rows_dropped
            ));
        }
        out.push('\n');

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
                "- Gateway: RTT {}  Loss {}\n",
                format_rtt(health.gateway_rtt_ms),
                format_loss(health.gateway_loss_pct)
            ));
            out.push_str(&format!(
                "- DNS: RTT {}  Loss {}\n",
                format_rtt(health.dns_rtt_ms),
                format_loss(health.dns_loss_pct)
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
                endpoints.sort_by_key(|b| std::cmp::Reverse(b.1));
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
        self.last_capture_status = None;
        self.freeze_reason = None;
        self.frozen_at = None;
        self.last_packet_id = 0;
        self.last_recorded_alert_at = None;
        self.packets.clear();
        self.connection_snapshots.clear();
        self.dropped_connection_rows.clear();
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

fn format_loss(pct: Option<f64>) -> String {
    pct.map(|p| format!("{p:.0}%"))
        .unwrap_or_else(|| "unmeasured".into())
}

fn format_rtt(rtt: Option<f64>) -> String {
    rtt.map(|value| format!("{value:.1}ms"))
        .unwrap_or_else(|| "—".to_string())
}

fn alert_severity_label(alert: &Alert) -> String {
    format!("{:?}", alert.severity)
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let file = create_new(path).map_err(|e| format!("Failed to create {}: {e}", path.display()))?;
    // Unbuffered, serde writes each token on its own: 50,000 connection
    // rows took about 12 million write calls.
    let mut writer = std::io::BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value)
        .and_then(|()| writer.flush().map_err(serde_json::Error::io))
        .map_err(|e| format!("Failed to write {}: {e}", path.display()))
}

/// A new owner-only file in the bundle's private directory. `create_new`,
/// because nothing should be there yet: an existing file means something
/// else is writing the same bundle.
fn create_new(path: &Path) -> std::io::Result<std::fs::File> {
    crate::owner_only::file_options()
        .create_new(true)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpi::AppProtocol;
    use std::collections::VecDeque;
    use std::fs;

    fn make_packet(id: u64, protocol: &str, expert: ExpertSeverity) -> CapturedPacket {
        CapturedPacket {
            capture: Some(export::CaptureMetadata {
                session: "test".into(),
                interface: "test".into(),
                link_type: 1,
                timestamp_ns: 1_700_000_000_000_000_000,
                original_len: 64,
            }),
            annotation: None,
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
            raw_bytes: vec![0, 1, 2, 3],
            stream_index: Some(1),
            tcp_flags: Some(0x02),
            tcp_seq: None,
            expert,
            timestamp_ns: 1,
            app_protocol: None,
            decrypted_plaintext: None,
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
            handshake_rtt_us: Some(12_000.0),
            rx_rate: None,
            tx_rate: None,
            attribution: Default::default(),
            evidence: Default::default(),
            app_protocol: None,
            retransmits: 0,
            out_of_order: 0,
        }
    }

    fn make_health() -> HealthStatus {
        HealthStatus {
            completed: Default::default(),
            gateway_rtt_ms: Some(2.5),
            gateway_loss: super::super::health::Loss::Measured(0.0),
            dns_rtt_ms: Some(14.0),
            dns_loss: super::super::health::Loss::Measured(0.0),
            internet_rtt_ms: Some(18.0),
            internet_loss: super::super::health::Loss::Measured(0.0),
            gateway_rtt_history: VecDeque::new(),
            dns_rtt_history: VecDeque::new(),
            internet_rtt_history: VecDeque::new(),
            dns_probe_history: VecDeque::new(),
            dns_cross: None,
            dns_cross_history: VecDeque::new(),
            nat: None,
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
            signal_dbm: None,
            tx_retries: None,
            rx_history: VecDeque::new(),
            tx_history: VecDeque::new(),
            sample_times: Default::default(),
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

    fn make_alert(base: std::time::Instant, secs: u64, msg: &str) -> Alert {
        use crate::collectors::network_intel::{AlertCategory, AlertSeverity};
        Alert {
            severity: AlertSeverity::Warning,
            category: AlertCategory::Beaconing,
            message: msg.to_string(),
            detail: String::new(),
            timestamp: base + std::time::Duration::from_secs(secs),
        }
    }

    #[test]
    fn new_alerts_recorded_after_history_ring_slides() {
        // Regression: the alert cursor was length-based, so once
        // `alert_history` reached its ring-buffer cap (length stops
        // growing) every new alert was skipped from the bundle. With a
        // timestamp cursor, alerts recorded after the window slides still
        // land. Model the slide with constant-length windows.
        let mut recorder = IncidentRecorder::new();
        recorder.arm();
        let base = std::time::Instant::now();
        let now = Utc::now();

        let window1 = [
            make_alert(base, 1, "a1"),
            make_alert(base, 2, "a2"),
            make_alert(base, 3, "a3"),
        ];
        recorder.record_alerts(now, &window1);
        assert_eq!(recorder.alert_events.len(), 3);

        // Ring slid: dropped the oldest, appended a4. Same length.
        let window2 = [
            make_alert(base, 2, "a2"),
            make_alert(base, 3, "a3"),
            make_alert(base, 4, "a4"),
        ];
        recorder.record_alerts(now, &window2);
        assert_eq!(
            recorder.alert_events.len(),
            4,
            "the new alert after the slide must still be recorded"
        );
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

    fn record_packets(recorder: &mut IncidentRecorder, packets: &[CapturedPacket]) {
        recorder.record_at(
            Utc::now(),
            packets,
            &[],
            &make_health(),
            &[],
            &[],
            &DnsAnalytics::default(),
            &[],
        );
    }

    fn scratch(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "netwatch_incident_{name}_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn manifest(bundle: &Path) -> serde_json::Value {
        serde_json::from_slice(&fs::read(bundle.join("manifest.json")).unwrap()).unwrap()
    }

    /// A packet's socket owner is resolved a poll after capture, when the
    /// recorder already holds its copy; the copy must pick it up.
    #[test]
    fn a_late_annotation_reaches_the_recorded_copy() {
        let mut recorder = IncidentRecorder::new();
        recorder.arm();
        let packet = make_packet(1, "TCP", ExpertSeverity::Chat);
        record_packets(&mut recorder, std::slice::from_ref(&packet));
        assert_eq!(recorder.packet_preview().annotated, 0);
        let mut later = packet;
        later.annotation = Some(Box::new(export::PacketAnnotation {
            process: super::super::attribution::ProcessIdentity {
                session: "run".into(),
                pid: 4242,
                start_token: "1".into(),
                executable: None,
                network_namespace: None,
            },
            process_name: Some("curl".into()),
            source: Default::default(),
            before_utc_ms: 1,
            after_utc_ms: 2,
            flow_generation: 1,
            capture_generation: 1,
            direction: export::Direction::Outbound,
        }));
        let next = make_packet(2, "TCP", ExpertSeverity::Chat);
        record_packets(&mut recorder, &[later, next]);
        let preview = recorder.packet_preview();
        assert_eq!((preview.packets, preview.annotated), (2, 1));
    }

    /// A capture classic PCAP cannot hold, with two link types or a time
    /// past its 32-bit seconds, is bundled as PCAPNG only, not refused.
    #[test]
    fn a_capture_pcap_cannot_hold_bundles_pcapng_only() {
        for mixed in [true, false] {
            let mut recorder = IncidentRecorder::new();
            recorder.arm();
            let mut second = make_packet(2, "Raw", ExpertSeverity::Chat);
            let meta = second.capture.as_mut().unwrap();
            if mixed {
                meta.link_type = 101;
            } else {
                meta.timestamp_ns = (u64::from(u32::MAX) + 1) * 1_000_000_000;
            }
            let mut demo = make_packet(3, "DNS", ExpertSeverity::Chat);
            demo.capture = None;
            record_packets(
                &mut recorder,
                &[make_packet(1, "TCP", ExpertSeverity::Chat), second, demo],
            );
            recorder.freeze("mixed").unwrap();
            let root = scratch("mixed");
            let bundle = recorder.export_bundle(&root).unwrap();
            assert!(bundle.join("packets.pcapng").exists(), "{mixed}");
            assert!(!bundle.join("packets.pcap").exists(), "{mixed}");
            let manifest = manifest(&bundle);
            assert_eq!(
                manifest["packet_artifacts"],
                serde_json::json!(["packets.pcapng"])
            );
            assert_eq!(manifest["packet_export"]["packets"], 2);
            assert_eq!(manifest["packet_export"]["omitted"], 1);
            assert_eq!(manifest["packet_annotations"], true);
            let _ = fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn capture_status_is_sampled_only_while_armed() {
        let mut recorder = IncidentRecorder::new();
        recorder.record_capture_status(Some("before".into()), Some(9));
        recorder.arm();
        recorder.record_capture_status(Some("session-1".into()), Some(3));
        recorder.freeze("drops").unwrap();
        recorder.record_capture_status(Some("after".into()), Some(7));
        let root = scratch("status");
        let bundle = recorder
            .export_bundle_options(&root, false, &AtomicBool::new(false))
            .unwrap();
        let manifest = manifest(&bundle);
        assert_eq!(manifest["last_capture_status"]["session"], "session-1");
        assert_eq!(manifest["last_capture_status"]["drops"], 3);
        assert_eq!(manifest["packet_annotations"], false);
        // No packets: no packet files, and the manifest says so.
        assert_eq!(manifest["packet_artifacts"], serde_json::json!([]));
        assert!(!bundle.join("packets.pcapng").exists());
        let _ = fs::remove_dir_all(&root);
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
        assert!(bundle.join("packets.pcapng").exists());
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(bundle.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["version"], 2);
        assert_eq!(manifest["packet_export"]["packets"], 1);
        assert_eq!(manifest["connection_rows_dropped"], 0);
        assert!(manifest["last_capture_status"].is_null());
        let second = recorder.export_bundle(&root).unwrap();
        assert_ne!(bundle, second);
        let cancelled = AtomicBool::new(true);
        assert!(recorder
            .export_bundle_options(&root, true, &cancelled)
            .is_err());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);

        let summary = fs::read_to_string(bundle.join("summary.md")).unwrap();
        assert!(summary.contains("NetWatch Incident Bundle"));
        assert!(summary.contains("manual freeze"));

        // Addresses, hostnames and packet bytes: only the owner may open
        // them, whether or not the sandbox ran.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&bundle), 0o700);
            for entry in fs::read_dir(&bundle).unwrap() {
                let path = entry.unwrap().path();
                assert_eq!(mode(&path), 0o600, "{}", path.display());
            }
        }

        let _ = fs::remove_dir_all(&root);
    }

    /// Bulk traffic with GSO captures 64 KiB frames, and 20,000 of them
    /// would be over a gigabyte. The byte budget stops the recorder well
    /// before the count does, dropping the oldest first, while small frames
    /// still stop at the count.
    #[test]
    fn recorder_evicts_packets_by_bytes() {
        let mut recorder = IncidentRecorder::new();
        recorder.arm();
        let held = |recorder: &IncidentRecorder| -> usize {
            recorder.packets.iter().map(TimedPacket::held_bytes).sum()
        };
        let mut id = 0;
        for _ in 0..20 {
            let batch: Vec<_> = (0..100)
                .map(|_| {
                    id += 1;
                    let mut packet = make_packet(id, "TCP", ExpertSeverity::Chat);
                    packet.raw_bytes = vec![0xab; 65_000];
                    packet
                })
                .collect();
            record_packets(&mut recorder, &batch);
            assert!(held(&recorder) <= MAX_RECORDED_PACKET_BYTES);
        }
        let kept = recorder.packets.len() as u64;
        let frame = recorder.packets[0].held_bytes();
        assert!(kept < 2_000, "{kept} of 2,000 frames kept");
        assert!(held(&recorder) + frame > MAX_RECORDED_PACKET_BYTES);
        let ids: Vec<u64> = recorder.packets.iter().map(|p| p.packet.id).collect();
        assert_eq!(ids, (2_001 - kept..=2_000).collect::<Vec<_>>());

        recorder.arm();
        let small: Vec<_> = (1..=25_000)
            .map(|id| make_packet(id, "DNS", ExpertSeverity::Chat))
            .collect();
        record_packets(&mut recorder, &small);
        assert_eq!(recorder.packets.len(), MAX_RECORDED_PACKETS);
        assert_eq!(recorder.packets[0].packet.id, 5_001);
        assert!(held(&recorder) < MAX_RECORDED_PACKET_BYTES);
    }

    /// Every packet of a flow carries the flow's classification, empty ACKs
    /// included, so one long SNI or request path from a peer is held once
    /// per packet. The byte budget counts it.
    #[test]
    fn recorder_counts_app_protocol_against_the_byte_budget() {
        let mut recorder = IncidentRecorder::new();
        recorder.arm();
        let long = || Some("a".repeat(8_192));
        let classified: Vec<_> = (1..=20_000u64)
            .map(|id| {
                let mut packet = make_packet(id, "TCP", ExpertSeverity::Chat);
                packet.app_protocol = Some(match id % 3 {
                    0 => AppProtocol::Tls {
                        sni: long(),
                        alpn: None,
                        ech: false,
                        ja4: None,
                    },
                    1 => AppProtocol::Quic {
                        sni: long(),
                        ech: false,
                        ja4: None,
                    },
                    _ => AppProtocol::Http {
                        method: "GET".into(),
                        host: None,
                        path: long(),
                        status: None,
                    },
                });
                packet
            })
            .collect();
        record_packets(&mut recorder, &classified);
        let held: usize = recorder.packets.iter().map(TimedPacket::held_bytes).sum();
        let kept = recorder.packets.len() as u64;
        assert!(held <= MAX_RECORDED_PACKET_BYTES, "{} MiB held", held >> 20);
        assert!(kept < 10_000, "{kept} of 20,000 packets kept");
        let ids: Vec<u64> = recorder.packets.iter().map(|p| p.packet.id).collect();
        assert_eq!(ids, (20_001 - kept..=20_000).collect::<Vec<_>>());
    }

    /// A host with 10,000 connections, recorded for the whole window,
    /// would hold 3 million rows. The snapshots stay within the row budget:
    /// the newest whole every tick, older ones dropped whole and the rest
    /// spread across the window, and the bundle says how many rows went.
    /// Run for twice the window, so dropped rows also age out with it.
    #[test]
    fn armed_recorder_with_10k_rows_stays_within_row_budget() {
        let mut recorder = IncidentRecorder::new();
        recorder.arm();
        let table: Vec<Connection> = (0..10_000u32)
            .map(|i| Connection {
                local_addr: format!("10.0.{}.{}:{}", i >> 8, i & 0xff, 40_000 + i % 20_000),
                ..make_connection()
            })
            .collect();
        let start = Utc::now();
        let ticks = 600;
        let mut dropped = 0;
        for tick in 0..ticks {
            let now = start + Duration::seconds(tick);
            recorder.record_at(
                now,
                &[],
                &table,
                &make_health(),
                &[],
                &[],
                &DnsAnalytics::default(),
                &[],
            );
            let rows: usize = recorder
                .connection_snapshots
                .iter()
                .map(|s| s.value.connections.len())
                .sum();
            assert!(rows <= MAX_CONNECTION_ROWS, "tick {tick}: {rows} rows");
            let newest = recorder.connection_snapshots.back().unwrap();
            assert_eq!(newest.observed_at, now);
            assert_eq!(newest.value.connections.len(), table.len());
            // One snapshot a second, so the window holds those from the
            // last 300 seconds and the one on its edge.
            let taken = (tick.min(recorder.window.num_seconds()) + 1) as usize;
            dropped = (taken - recorder.connection_snapshots.len()) * table.len();
            assert_eq!(recorder.connection_rows_dropped(), dropped, "tick {tick}");
        }

        let kept = &recorder.connection_snapshots;
        assert_eq!(kept.len(), MAX_CONNECTION_ROWS / table.len());
        let whole = |rows: &[Connection]| {
            rows.iter()
                .map(|c| &c.local_addr)
                .eq(table.iter().map(|c| &c.local_addr))
        };
        assert!(kept.iter().all(|s| whole(&s.value.connections)));
        // No stretch of the window, its start included, goes without a
        // snapshot for more than twice the even spacing.
        let even = recorder.window / kept.len() as i32;
        let mut before = start + Duration::seconds(ticks - 1) - recorder.window;
        for snapshot in kept {
            let gap = snapshot.observed_at - before;
            assert!(gap <= even * 2, "{}s gap", gap.num_seconds());
            before = snapshot.observed_at;
        }
        assert_eq!(dropped, 296 * table.len());

        recorder.freeze("busy host").unwrap();
        let root = scratch("rows");
        let bundle = recorder
            .export_bundle_options(&root, false, &AtomicBool::new(false))
            .unwrap();
        let manifest = manifest(&bundle);
        assert_eq!(manifest["connection_snapshots"], 5);
        assert_eq!(manifest["connection_rows_dropped"], dropped);
        let summary = fs::read_to_string(bundle.join("summary.md")).unwrap();
        assert!(
            summary.contains(&format!("Connection rows dropped: `{dropped}`")),
            "{summary}"
        );
        let snapshots: Vec<serde_json::Value> =
            serde_json::from_slice(&fs::read(bundle.join("connections.json")).unwrap()).unwrap();
        assert_eq!(snapshots.len(), 5);
        for snapshot in &snapshots {
            assert!(snapshot["timestamp"].is_string());
            assert_eq!(snapshot["connections"].as_array().unwrap().len(), 10_000);
        }
        let _ = fs::remove_dir_all(&root);
    }

    /// Every row of a classified flow carries the flow's SNI or request
    /// path, which the peer picks. 1,024 rows, as many flows as the stream
    /// tracker classifies, are far inside the row budget, but at 8 KB of
    /// text each the window would hold 2.7 GB. The byte budget counts it,
    /// and the snapshots it leaves stay whole and spread across the window.
    #[test]
    fn recorder_counts_row_classification_against_the_byte_budget() {
        let mut recorder = IncidentRecorder::new();
        recorder.arm();
        let long = || Some("a".repeat(8_192));
        let table: Vec<Connection> = (0..1_024u32)
            .map(|i| Connection {
                remote_addr: format!("203.0.113.7:{}", 40_000 + i),
                app_protocol: Some(if i % 2 == 0 {
                    AppProtocol::Tls {
                        sni: long(),
                        alpn: None,
                        ech: false,
                        ja4: None,
                    }
                } else {
                    AppProtocol::Http {
                        method: "GET".into(),
                        host: None,
                        path: long(),
                        status: None,
                    }
                }),
                ..make_connection()
            })
            .collect();
        let snapshot_bytes: usize = table.iter().map(connection_held_bytes).sum();
        let held = |recorder: &IncidentRecorder| -> usize {
            recorder
                .connection_snapshots
                .iter()
                .flat_map(|s| s.value.connections.iter())
                .map(connection_held_bytes)
                .sum()
        };
        let start = Utc::now();
        let ticks = 600;
        for tick in 0..ticks {
            let now = start + Duration::seconds(tick);
            recorder.record_at(
                now,
                &[],
                &table,
                &make_health(),
                &[],
                &[],
                &DnsAnalytics::default(),
                &[],
            );
            assert!(
                held(&recorder) <= MAX_CONNECTION_BYTES,
                "tick {tick}: {} MiB held",
                held(&recorder) >> 20
            );
            let newest = recorder.connection_snapshots.back().unwrap();
            assert_eq!(newest.observed_at, now);
            assert_eq!(newest.value.connections.len(), table.len());
            let taken = (tick.min(recorder.window.num_seconds()) + 1) as usize;
            assert_eq!(
                recorder.connection_rows_dropped(),
                (taken - recorder.connection_snapshots.len()) * table.len(),
                "tick {tick}"
            );
        }

        // The bytes, not the rows, are what stopped it.
        let kept = &recorder.connection_snapshots;
        assert_eq!(kept.len(), MAX_CONNECTION_BYTES / snapshot_bytes);
        assert!(kept.len() * table.len() < MAX_CONNECTION_ROWS / 4);
        assert!(kept
            .iter()
            .all(|s| s.value.connections.len() == table.len()));
        let even = recorder.window / kept.len() as i32;
        let mut before = start + Duration::seconds(ticks - 1) - recorder.window;
        for snapshot in kept {
            let gap = snapshot.observed_at - before;
            assert!(gap <= even * 2, "{}s gap", gap.num_seconds());
            before = snapshot.observed_at;
        }
    }

    /// The newest snapshot stays whole even when it alone is over the row
    /// budget, and the summary does not then say the bundle is within it.
    /// Arming again starts the count of dropped rows afresh.
    #[test]
    fn newest_snapshot_over_the_row_budget_stays_whole() {
        let mut recorder = IncidentRecorder::new();
        recorder.arm();
        let table = vec![make_connection(); 60_000];
        let start = Utc::now();
        for tick in 0..2 {
            recorder.record_at(
                start + Duration::seconds(tick),
                &[],
                &table,
                &make_health(),
                &[],
                &[],
                &DnsAnalytics::default(),
                &[],
            );
        }
        assert_eq!(recorder.connection_snapshots.len(), 1);
        assert_eq!(
            recorder.connection_snapshots[0].observed_at,
            start + Duration::seconds(1)
        );
        assert_eq!(
            recorder.connection_snapshots[0].value.connections.len(),
            60_000
        );
        assert_eq!(recorder.connection_rows_dropped(), 60_000);
        let summary = recorder.build_summary();
        assert!(
            summary.contains(
                "- Connection rows dropped: `60000` (whole older snapshots, for the budget of 50,000 rows and 64 MiB)\n"
            ),
            "{summary}"
        );
        recorder.arm();
        assert_eq!(recorder.connection_rows_dropped(), 0);
    }
}
