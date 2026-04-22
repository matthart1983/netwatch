use crate::collectors::config::ConfigCollector;
use crate::collectors::connections::{Connection, ConnectionCollector, ConnectionTimeline};
use crate::collectors::geo::GeoCache;
use crate::collectors::health::HealthProber;
use crate::collectors::incident::IncidentRecorder;
use crate::collectors::network_intel::{
    AlertSeverity, ConnAttemptEvent, InterfaceRateEvent, NetworkIntelCollector,
};
use crate::collectors::packets::PacketCollector;
use crate::collectors::process_bandwidth::ProcessBandwidthCollector;
use crate::collectors::traceroute::TracerouteRunner;
use crate::collectors::traffic::TrafficCollector;
use crate::collectors::whois::WhoisCache;
use crate::config::NetwatchConfig;
use crate::ebpf::EbpfStatus;
use crate::event::{AppEvent, EventHandler};
use crate::platform::{self, InterfaceInfo};
use crate::theme::Theme;
use crate::ui;
use anyhow::Result;
use crossterm::event::{KeyCode, KeyModifiers, MouseButton, MouseEventKind};
use ratatui::prelude::*;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::Arc;

const RTT_SPARKLINE_SAMPLES: usize = 20;
const PAGE_SCROLL: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimelineWindow {
    Min1,
    Min5,
    Min15,
    Min30,
    Hour1,
}

impl TimelineWindow {
    pub fn seconds(&self) -> u64 {
        match self {
            Self::Min1 => 60,
            Self::Min5 => 300,
            Self::Min15 => 900,
            Self::Min30 => 1800,
            Self::Hour1 => 3600,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Min1 => "1m",
            Self::Min5 => "5m",
            Self::Min15 => "15m",
            Self::Min30 => "30m",
            Self::Hour1 => "1h",
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Min1 => Self::Min5,
            Self::Min5 => Self::Min15,
            Self::Min15 => Self::Min30,
            Self::Min30 => Self::Hour1,
            Self::Hour1 => Self::Min1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirectionFilter {
    Both,
    AtoB,
    BtoA,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tab {
    Dashboard,
    Connections,
    Interfaces,
    Packets,
    Stats,
    Topology,
    Timeline,
    Processes,
    Insights,
}

use crate::sort::{SortColumn, TabSortState};

pub fn sort_columns_for_tab(tab: Tab) -> &'static [SortColumn] {
    match tab {
        Tab::Dashboard => crate::ui::dashboard::COLUMNS,
        Tab::Connections => crate::ui::connections::COLUMNS,
        Tab::Interfaces => crate::ui::interfaces::COLUMNS,
        Tab::Processes => crate::ui::processes::COLUMNS,
        _ => &[],
    }
}

pub fn default_sort_states() -> HashMap<Tab, TabSortState> {
    let mut m = HashMap::new();
    m.insert(Tab::Dashboard, crate::ui::dashboard::DEFAULT_SORT);
    m.insert(Tab::Connections, crate::ui::connections::DEFAULT_SORT);
    m.insert(Tab::Interfaces, crate::ui::interfaces::DEFAULT_SORT);
    m.insert(Tab::Processes, crate::ui::processes::DEFAULT_SORT);
    m
}

/// Per-tab scroll positions and selection state.
pub struct UiScrollState {
    pub connection_scroll: usize,
    pub packet_scroll: usize,
    pub packet_selected: Option<u64>,
    pub stream_scroll: usize,
    pub stats_scroll: usize,
    pub help_scroll: usize,
    pub topology_scroll: usize,
    pub traceroute_scroll: usize,
    pub timeline_scroll: usize,
    pub process_scroll: usize,
    pub insights_scroll: usize,
}

impl Default for UiScrollState {
    fn default() -> Self {
        Self {
            connection_scroll: 0,
            packet_scroll: 0,
            packet_selected: None,
            stream_scroll: 0,
            stats_scroll: 0,
            help_scroll: 0,
            topology_scroll: 0,
            traceroute_scroll: 0,
            timeline_scroll: 0,
            process_scroll: 0,
            insights_scroll: 0,
        }
    }
}

pub struct App {
    pub traffic: TrafficCollector,
    pub interface_info: Vec<InterfaceInfo>,
    pub connection_collector: ConnectionCollector,
    pub config_collector: ConfigCollector,
    pub health_prober: HealthProber,
    pub packet_collector: PacketCollector,
    pub selected_interface: Option<usize>,
    pub paused: bool,
    pub current_tab: Tab,
    pub scroll: UiScrollState,
    pub sort_states: HashMap<Tab, TabSortState>,
    pub packet_follow: bool,
    pub capture_interface: String,
    pub stream_view_open: bool,
    pub stream_view_index: Option<u32>,
    pub stream_direction_filter: StreamDirectionFilter,
    pub stream_hex_mode: bool,
    pub packet_filter_input: bool,
    pub packet_filter_text: String,
    pub packet_filter_active: Option<String>,
    pub connection_filter_input: bool,
    pub connection_filter_text: String,
    pub connection_filter_active: Option<String>,
    pub export_status: Option<String>,
    export_status_tick: u32,
    pub bpf_filter_active: Option<String>,
    pub incident_recorder: IncidentRecorder,
    pub show_help: bool,
    pub geo_cache: GeoCache,
    pub show_geo: bool,
    pub whois_cache: WhoisCache,
    pub bookmarks: HashSet<u64>,
    pub traceroute_runner: TracerouteRunner,
    pub traceroute_view_open: bool,
    pub connection_timeline: ConnectionTimeline,
    pub timeline_window: TimelineWindow,
    pub network_intel: NetworkIntelCollector,
    intel_last_pkt_id: u64,
    pub ebpf_status: EbpfStatus,
    #[allow(dead_code)]
    pub rtt_monitor: crate::ebpf::rtt_monitor::RttMonitor,
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub conn_tracker: Option<crate::ebpf::conn_tracker::ConnTracker>,
    info_tick: u32,
    conn_tick: u32,
    health_tick: u32,
    pub user_config: NetwatchConfig,
    pub last_area: Rect,
    /// Per-remote-IP RTT history for sparklines (keyed by remote IP string)
    pub rtt_history: HashMap<String, VecDeque<f64>>,
    rtt_sampled_streams: HashSet<u32>,
    pub theme: Theme,
    pub process_bandwidth: ProcessBandwidthCollector,
    pub insights_collector: Option<crate::collectors::insights::InsightsCollector>,
    pub sort_picker: crate::ui::sort_picker::SortPickerState,
    pub show_settings: bool,
    pub settings_cursor: usize,
    pub settings_editing: bool,
    pub settings_edit_buf: String,
    pub settings_status: Option<String>,
    settings_status_tick: u32,
    incident_capture_started: bool,
}

impl App {
    fn new() -> Self {
        let user_config = NetwatchConfig::load();
        let interface_info = platform::collect_interface_info().unwrap_or_default();
        let mut config_collector = ConfigCollector::new();
        config_collector.update();

        // Use config capture_interface if set, otherwise auto-detect
        let capture_interface = if !user_config.capture_interface.is_empty() {
            user_config.capture_interface.clone()
        } else {
            Self::pick_capture_interface(&interface_info)
        };

        // Apply BPF filter from config
        let bpf_filter_active = if user_config.bpf_filter.is_empty() {
            None
        } else {
            Some(user_config.bpf_filter.clone())
        };

        let theme = crate::theme::by_name(&user_config.theme);

        let insights_collector = if user_config.insights_enabled {
            Some(crate::collectors::insights::InsightsCollector::new(
                &user_config.insights_model,
                &user_config.insights_endpoint,
            ))
        } else {
            None
        };

        let mut network_intel = NetworkIntelCollector::new();
        network_intel.set_bandwidth_threshold(user_config.alerts.bandwidth_threshold);

        let mut packet_collector = PacketCollector::new();
        // Start ambient packet capture so the Connections view can show
        // per-connection rates. If this fails (no sudo, no interface), the
        // error surfaces on the Packets tab and rate columns stay blank.
        packet_collector.start_capture(&capture_interface, bpf_filter_active.as_deref());
        let connection_collector =
            ConnectionCollector::new(Arc::clone(&packet_collector.stream_tracker));

        Self {
            traffic: TrafficCollector::new(),
            interface_info,
            connection_collector,
            config_collector,
            health_prober: HealthProber::new(),
            packet_collector,
            selected_interface: None,
            paused: false,
            current_tab: user_config.tab(),
            scroll: UiScrollState::default(),
            sort_states: default_sort_states(),
            packet_follow: user_config.packet_follow,
            capture_interface,
            stream_view_open: false,
            stream_view_index: None,
            stream_direction_filter: StreamDirectionFilter::Both,
            stream_hex_mode: false,
            packet_filter_input: false,
            packet_filter_text: String::new(),
            packet_filter_active: None,
            connection_filter_input: false,
            connection_filter_text: String::new(),
            connection_filter_active: None,
            export_status: None,
            export_status_tick: 0,
            bpf_filter_active,
            incident_recorder: IncidentRecorder::new(),
            show_help: false,
            geo_cache: GeoCache::with_mmdb(&user_config.geoip_db, &user_config.geoip_asn_db),
            show_geo: user_config.show_geo,
            whois_cache: WhoisCache::new(),
            bookmarks: HashSet::new(),
            traceroute_runner: TracerouteRunner::new(),
            traceroute_view_open: false,
            connection_timeline: ConnectionTimeline::new(),
            timeline_window: user_config.timeline_window_enum(),
            network_intel,
            intel_last_pkt_id: 0,
            ebpf_status: Self::init_ebpf_status(),
            rtt_monitor: crate::ebpf::rtt_monitor::RttMonitor::new(),
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            conn_tracker: crate::ebpf::conn_tracker::ConnTracker::new().ok(),
            info_tick: 0,
            conn_tick: 0,
            health_tick: 0,
            user_config,
            last_area: Rect::default(),
            rtt_history: HashMap::new(),
            rtt_sampled_streams: HashSet::new(),
            theme,
            process_bandwidth: ProcessBandwidthCollector::new(),
            insights_collector,
            show_settings: false,
            settings_cursor: 0,
            settings_editing: false,
            settings_edit_buf: String::new(),
            settings_status: None,
            settings_status_tick: 0,
            incident_capture_started: false,
            sort_picker: Default::default(),
        }
    }

    pub fn sort_column_index(&self, tab: Tab) -> Option<usize> {
        self.sort_states.get(&tab).map(|s| s.column)
    }

    pub fn sort_indicator(&self, tab: Tab, col: usize) -> &str {
        if self.sort_column_index(tab) == Some(col) {
            let ascending = self
                .sort_states
                .get(&tab)
                .map(|s| s.ascending)
                .unwrap_or(true);
            if ascending {
                " ▲"
            } else {
                " ▼"
            }
        } else {
            ""
        }
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    fn init_ebpf_status() -> EbpfStatus {
        // Status determined after conn_tracker initialization attempt.
        // Updated in new() based on conn_tracker.is_some().
        EbpfStatus::Active
    }

    #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
    fn init_ebpf_status() -> EbpfStatus {
        EbpfStatus::NotCompiled
    }

    fn pick_capture_interface(info: &[InterfaceInfo]) -> String {
        // Prefer UP interfaces with an IPv4 address, skip loopback
        info.iter()
            .find(|i| i.is_up && i.ipv4.is_some() && i.name != "lo0" && i.name != "lo")
            .or_else(|| {
                info.iter()
                    .find(|i| i.is_up && i.name != "lo0" && i.name != "lo")
            })
            .map(|i| i.name.clone())
            .unwrap_or_else(|| "en0".to_string())
    }

    fn capturable_interfaces(&self) -> Vec<String> {
        self.interface_info
            .iter()
            .filter(|i| i.is_up)
            .map(|i| i.name.clone())
            .collect()
    }

    fn cycle_capture_interface(&mut self) {
        let ifaces = self.capturable_interfaces();
        if ifaces.is_empty() {
            return;
        }
        let current_idx = ifaces.iter().position(|n| *n == self.capture_interface);
        let next_idx = match current_idx {
            Some(i) => (i + 1) % ifaces.len(),
            None => 0,
        };
        self.capture_interface = ifaces[next_idx].clone();
    }

    fn arm_incident_recorder(&mut self) {
        self.incident_recorder.arm();
        {
            let packets = self.packet_collector.get_packets();
            self.incident_recorder.prime_current_packets(&packets);
        }
        self.incident_recorder
            .prime_alert_cursor(self.network_intel.alert_history().len());

        self.incident_capture_started = false;
        if !self.packet_collector.is_capturing() {
            let iface = self.capture_interface.clone();
            let bpf = self.bpf_filter_active.clone();
            self.packet_collector.start_capture(&iface, bpf.as_deref());
            self.incident_capture_started = self.packet_collector.is_capturing();
        }

        self.sync_incident_recorder();
        self.export_status = Some(format!(
            "Flight recorder armed ({})",
            self.incident_recorder.window_label()
        ));
        self.export_status_tick = 0;
    }

    fn disarm_incident_recorder(&mut self) {
        self.incident_recorder.disarm();
        if self.incident_capture_started && self.packet_collector.is_capturing() {
            self.packet_collector.stop_capture();
        }
        self.incident_capture_started = false;
        self.export_status = Some("Flight recorder disarmed".to_string());
        self.export_status_tick = 0;
    }

    fn freeze_incident_recorder(&mut self, reason: &str) {
        if !self.incident_recorder.is_armed() {
            return;
        }
        self.sync_incident_recorder();
        match self.incident_recorder.freeze(reason) {
            Ok(()) => {
                if self.incident_capture_started && self.packet_collector.is_capturing() {
                    self.packet_collector.stop_capture();
                }
                self.incident_capture_started = false;
                self.export_status = Some(format!("Incident frozen: {reason}"));
            }
            Err(err) => {
                self.export_status = Some(err);
            }
        }
        self.export_status_tick = 0;
    }

    fn export_incident_bundle(&mut self) {
        if self.incident_recorder.is_off() {
            self.export_status = Some("Arm the flight recorder first with Shift+R".to_string());
            self.export_status_tick = 0;
            return;
        }

        if self.incident_recorder.is_armed() {
            self.freeze_incident_recorder("manual export");
        }

        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        match self.incident_recorder.export_bundle(Path::new(&home)) {
            Ok(path) => {
                self.export_status = Some(format!("Incident bundle saved to {}", path.display()));
            }
            Err(err) => {
                self.export_status = Some(format!("Incident export failed: {err}"));
            }
        }
        self.export_status_tick = 0;
    }

    fn sync_incident_recorder(&mut self) {
        if !self.incident_recorder.is_armed() {
            return;
        }

        let connections = self
            .connection_collector
            .connections
            .lock()
            .unwrap()
            .clone();
        let health = self.health_prober.status.lock().unwrap();
        let packets = self.packet_collector.get_packets();
        let dns = self.network_intel.dns_analytics();
        let alert_history: Vec<_> = self.network_intel.alert_history().iter().cloned().collect();

        let interfaces = self.traffic.interfaces();
        self.incident_recorder.record(
            &packets,
            &connections,
            &health,
            &interfaces,
            self.process_bandwidth.ranked(),
            &dns,
            &alert_history,
        );
    }

    fn auto_freeze_reason(&self) -> Option<String> {
        if !self.incident_recorder.is_armed() {
            return None;
        }

        self.network_intel
            .active_alerts()
            .iter()
            .find(|alert| matches!(alert.severity, AlertSeverity::Critical))
            .map(|alert| format!("critical {} alert", alert.category.label().to_lowercase()))
    }

    fn tick(&mut self) {
        // Clear export status after 5 ticks
        if self.export_status.is_some() {
            self.export_status_tick += 1;
            if self.export_status_tick >= 5 {
                self.export_status = None;
                self.export_status_tick = 0;
            }
        }

        if self.settings_status.is_some() {
            self.settings_status_tick += 1;
            if self.settings_status_tick >= 5 {
                self.settings_status = None;
                self.settings_status_tick = 0;
            }
        }

        if self.paused {
            return;
        }
        self.traffic.update();

        // Refresh interface info every ~10 ticks (10s at 1s tick rate)
        self.info_tick += 1;
        if self.info_tick >= 10 {
            self.info_tick = 0;
            if let Ok(info) = platform::collect_interface_info() {
                self.interface_info = info;
            }
            self.config_collector.update();
        }

        // Refresh connections every ~2 ticks (2s)
        self.conn_tick += 1;
        if self.conn_tick >= 2 {
            self.conn_tick = 0;
            self.connection_collector.update();
            let conns = self.connection_collector.connections.lock().unwrap();
            self.connection_timeline.update(&conns);
            let interfaces = self.traffic.interfaces();
            self.process_bandwidth.update(&conns, &interfaces);
        }

        // Drain eBPF connection events and update RTT monitor
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        if let Some(ref tracker) = self.conn_tracker {
            let events = tracker.drain_events();
            if !events.is_empty() {
                let samples: Vec<crate::ebpf::rtt_monitor::RttSample> = events
                    .iter()
                    .filter_map(|_evt| {
                        // Only process state_change events with RTT info
                        // In a full implementation, RTT comes from tcp_probe,
                        // not conn events. This is a placeholder for the wiring.
                        None
                    })
                    .collect();
                if !samples.is_empty() {
                    self.rtt_monitor.process_samples(&samples);
                }
            }
        }

        // Feed network intelligence from new packets
        self.feed_network_intel();

        // Sample RTT from TCP handshakes for sparklines
        self.sample_rtt_from_streams();

        // Feed interface rates to bandwidth alerts
        let interfaces = self.traffic.interfaces();
        for iface in &interfaces {
            self.network_intel.on_interface_rate(InterfaceRateEvent {
                iface: iface.name.clone(),
                rx_bps: iface.rx_rate as u64,
                tx_bps: iface.tx_rate as u64,
            });
        }

        // Tick network intel (housekeeping)
        self.network_intel.tick();

        self.sync_incident_recorder();
        if let Some(reason) = self.auto_freeze_reason() {
            self.freeze_incident_recorder(&reason);
        }

        // Refresh health every ~5 ticks (5s)
        self.health_tick += 1;
        if self.health_tick >= 5 {
            self.health_tick = 0;
            let gateway = self.config_collector.config.gateway.clone();
            let dns = self.config_collector.config.dns_servers.first().cloned();
            self.health_prober.probe(gateway.as_deref(), dns.as_deref());
        }

        // Feed AI insights collector with a fresh network snapshot
        if let Some(ref collector) = self.insights_collector {
            let packets = self.packet_collector.get_packets();
            let conns = self
                .connection_collector
                .connections
                .lock()
                .unwrap()
                .clone();
            let health = self.health_prober.status.lock().unwrap().clone();
            let interfaces = self.traffic.interfaces();
            let (rx_bps, tx_bps) = interfaces.iter().fold((0.0f64, 0.0f64), |(rx, tx), i| {
                (rx + i.rx_rate, tx + i.tx_rate)
            });
            let rx_str = crate::ui::widgets::format_bytes_rate(rx_bps);
            let tx_str = crate::ui::widgets::format_bytes_rate(tx_bps);
            let snapshot = crate::collectors::insights::NetworkSnapshot::build(
                &packets, &conns, &health, &rx_str, &tx_str,
            );
            collector.submit_snapshot(snapshot);
        }
    }

    fn sample_rtt_from_streams(&mut self) {
        let streams = self.packet_collector.get_all_streams();
        for stream in &streams {
            if self.rtt_sampled_streams.contains(&stream.index) {
                continue;
            }
            if let Some(ref hs) = stream.handshake {
                if let Some(rtt_ms) = hs.syn_to_syn_ack_ms() {
                    self.rtt_sampled_streams.insert(stream.index);
                    // Key by the remote IP (addr_b is typically the server)
                    let remote_ip = &stream.key.addr_b.0;
                    let history = self
                        .rtt_history
                        .entry(remote_ip.clone())
                        .or_insert_with(|| VecDeque::with_capacity(RTT_SPARKLINE_SAMPLES + 1));
                    history.push_back(rtt_ms);
                    if history.len() > RTT_SPARKLINE_SAMPLES {
                        history.pop_front();
                    }
                }
            }
        }
    }

    fn feed_network_intel(&mut self) {
        use crate::collectors::network_intel::{DnsQueryEvent, DnsResponseEvent};

        let packets = self.packet_collector.get_packets();
        for pkt in packets.iter() {
            if pkt.id <= self.intel_last_pkt_id {
                continue;
            }
            self.intel_last_pkt_id = pkt.id;

            // Feed connection attempts (TCP SYN)
            if let Some(flags) = pkt.tcp_flags {
                if flags & crate::collectors::packets::TCP_FLAG_SYN != 0
                    && flags & crate::collectors::packets::TCP_FLAG_ACK == 0
                {
                    // SYN without ACK = connection attempt
                    if let (Some(dst_port), true) = (pkt.dst_port, !pkt.dst_ip.is_empty()) {
                        self.network_intel.on_conn_attempt(ConnAttemptEvent {
                            src_ip: pkt.src_ip.clone(),
                            dst_ip: pkt.dst_ip.clone(),
                            dst_port,
                        });
                    }
                }
            }

            // Feed DNS events
            if pkt.protocol == "DNS" || pkt.protocol == "mDNS" {
                if pkt.info.contains("Query") {
                    // Extract qname from info: "DNS Query A example.com"
                    let qname = pkt
                        .info
                        .split_whitespace()
                        .skip(2)
                        .last()
                        .unwrap_or("")
                        .to_string();
                    if !qname.is_empty() {
                        self.network_intel.on_dns_query(DnsQueryEvent {
                            txid: (pkt.id & 0xFFFF) as u16,
                            client_ip: pkt.src_ip.clone(),
                            server_ip: pkt.dst_ip.clone(),
                            qname,
                        });
                    }
                } else if pkt.info.contains("Response") {
                    let rcode = if pkt.info.contains("NXDOMAIN") { 3 } else { 0 };
                    self.network_intel.on_dns_response(DnsResponseEvent {
                        txid: (pkt.id & 0xFFFF) as u16,
                        client_ip: pkt.dst_ip.clone(),
                        server_ip: pkt.src_ip.clone(),
                        rcode,
                    });
                }
            }
        }
    }
}

fn parse_addr_parts(addr: &str) -> (Option<String>, Option<String>) {
    if addr == "*:*" || addr.is_empty() {
        return (None, None);
    }
    if let Some(bracket_end) = addr.rfind("]:") {
        let ip = addr[1..bracket_end].to_string();
        let port = addr[bracket_end + 2..].to_string();
        (Some(ip), Some(port))
    } else if let Some(colon) = addr.rfind(':') {
        let ip = &addr[..colon];
        let port = &addr[colon + 1..];
        let ip = if ip == "*" {
            None
        } else {
            Some(ip.to_string())
        };
        let port = if port == "*" {
            None
        } else {
            Some(port.to_string())
        };
        (ip, port)
    } else {
        (Some(addr.to_string()), None)
    }
}

fn build_connection_filter(conn: &Connection) -> String {
    let (remote_ip, remote_port) = parse_addr_parts(&conn.remote_addr);

    let mut parts = Vec::new();

    if let Some(ip) = remote_ip {
        parts.push(ip);
    }

    if let Some(port) = remote_port {
        if port.parse::<u16>().is_ok() {
            parts.push(format!("port {port}"));
        }
    }

    parts.join(" and ")
}

pub async fn run<B: Backend>(
    terminal: &mut Terminal<B>,
    remote: Option<&crate::remote::RemotePublisher>,
) -> Result<()> {
    let mut app = App::new();
    let tick_rate = app.user_config.refresh_rate_ms.clamp(100, 5000);
    let mut events = EventHandler::new(tick_rate);

    // Initial data collection
    app.traffic.update();
    app.connection_collector.update();
    {
        let conns = app.connection_collector.connections.lock().unwrap();
        app.connection_timeline.update(&conns);
    }
    let gateway = app.config_collector.config.gateway.clone();
    let dns = app.config_collector.config.dns_servers.first().cloned();
    app.health_prober.probe(gateway.as_deref(), dns.as_deref());

    // Event loop design:
    //   1. Render  — draw current app state to the terminal
    //   2. Wait    — block on the next AppEvent (key, mouse, or tick)
    //   3. Key/Mouse → update app state directly (synchronous, no I/O)
    //   4. Tick    → app.tick() refreshes all collectors and feeds background threads
    // Each iteration is: render → wait → handle → repeat.
    // Collectors run on background threads and share state via Arc<Mutex<T>>.
    loop {
        terminal.draw(|f| {
            let area = f.size();
            app.last_area = area;
            match app.current_tab {
                Tab::Dashboard => ui::dashboard::render(f, &app, area),
                Tab::Connections => ui::connections::render(f, &app, area),
                Tab::Interfaces => ui::interfaces::render(f, &app, area),
                Tab::Packets => ui::packets::render(f, &app, area),
                Tab::Stats => ui::stats::render(f, &app, area),
                Tab::Topology => ui::topology::render(f, &app, area),
                Tab::Timeline => ui::timeline::render(f, &app, area),
                Tab::Processes => ui::processes::render(f, &app, area),
                Tab::Insights => ui::insights::render(f, &app, area),
            }
            if app.show_help {
                ui::help::render(f, &app, area);
            }
            if app.show_settings {
                ui::settings::render(f, &app, area);
            }
            if app.sort_picker.is_open() {
                ui::sort_picker::render(
                    f,
                    &app.sort_picker,
                    sort_columns_for_tab(app.current_tab),
                    app.sort_states.get(&app.current_tab),
                    &app.theme,
                    area,
                );
            }
        })?;

        match events.next().await? {
            AppEvent::Key(key) => {
                if handle_key(&mut app, key) {
                    app.packet_collector.stop_capture();
                    return Ok(());
                }
            }
            AppEvent::Mouse(mouse) => {
                handle_mouse(&mut app, mouse);
            }
            AppEvent::Tick => {
                app.tick();
                if let Some(publisher) = remote {
                    publisher.update(
                        &app.traffic.interfaces(),
                        &app.health_prober,
                        &app.connection_collector,
                    );
                }
            }
        }
    }
}

/// Clamp a scroll position after applying a signed delta.
/// `max` is the highest allowed index (inclusive).
fn clamp_scroll(current: usize, delta: isize, max: usize) -> usize {
    ((current as isize + delta).max(0) as usize).min(max)
}

fn handle_mouse(app: &mut App, mouse: crossterm::event::MouseEvent) {
    let col = mouse.column;
    let row = mouse.row;
    let area = app.last_area;

    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            // Header row: click on tabs (row 0 or 1 within header area)
            if row < 3 {
                if let Some(tab) = ui::widgets::tab_at_column(col, app.user_config.insights_enabled)
                {
                    app.current_tab = tab;
                    return;
                }
            }

            // Content area: click to select a row
            // Header is 3 rows, footer is 3 rows, content borders add 1+1
            let content_top = 3 + 1; // header + table border top
            let content_bottom = area.height.saturating_sub(3); // above footer
            if row >= content_top && row < content_bottom {
                let clicked_row = (row - content_top) as usize;
                match app.current_tab {
                    Tab::Connections if !app.traceroute_view_open => {
                        // Account for table header row
                        if clicked_row > 0 {
                            let visible_row = clicked_row - 1;
                            let max = app
                                .connection_collector
                                .connections
                                .lock()
                                .unwrap()
                                .len()
                                .saturating_sub(1);
                            let idx = (app.scroll.connection_scroll + visible_row).min(max);
                            app.scroll.connection_scroll = idx;
                        }
                    }
                    Tab::Packets if !app.stream_view_open => {
                        if clicked_row > 0 {
                            let visible_row = clicked_row - 1;
                            let packets = app.packet_collector.get_packets();
                            let scroll_base = if app.packet_follow {
                                let visible_height =
                                    (content_bottom - content_top).saturating_sub(1) as usize;
                                packets.len().saturating_sub(visible_height)
                            } else {
                                app.scroll.packet_scroll
                            };
                            let idx = scroll_base + visible_row;
                            if let Some(pkt) = packets.get(idx) {
                                app.packet_follow = false;
                                app.scroll.packet_scroll = idx;
                                app.scroll.packet_selected = Some(pkt.id);
                            }
                        }
                    }
                    Tab::Topology if !app.traceroute_view_open => {
                        if clicked_row > 0 {
                            app.scroll.topology_scroll = app
                                .scroll
                                .topology_scroll
                                .saturating_sub(0)
                                .max(clicked_row - 1);
                        }
                    }
                    Tab::Timeline => {
                        if clicked_row > 0 {
                            app.scroll.timeline_scroll = clicked_row - 1;
                        }
                    }
                    Tab::Processes => {
                        if clicked_row > 0 {
                            let visible_row = clicked_row - 1;
                            let max = app.process_bandwidth.ranked().len().saturating_sub(1);
                            let idx = (app.scroll.process_scroll + visible_row).min(max);
                            app.scroll.process_scroll = idx;
                        }
                    }
                    _ => {}
                }
            }
        }
        MouseEventKind::ScrollUp => {
            scroll_tab(app, -3);
            if app.show_help {
                app.scroll.help_scroll = clamp_scroll(app.scroll.help_scroll, -3, usize::MAX);
            }
        }
        MouseEventKind::ScrollDown => {
            scroll_tab(app, 3);
            if app.show_help {
                app.scroll.help_scroll += 3;
            }
        }
        _ => {}
    }
}

/// Apply a scroll delta to whichever list the active tab displays.
/// `delta` is signed: negative = scroll up, positive = scroll down.
/// Bounded scrolling (where a max is known) clamps at the last item;
/// unbounded lists (Stats, Timeline, Insights) are left unclamped.
fn scroll_tab(app: &mut App, delta: isize) {
    match app.current_tab {
        Tab::Connections => {
            if app.traceroute_view_open {
                app.scroll.traceroute_scroll =
                    clamp_scroll(app.scroll.traceroute_scroll, delta, usize::MAX);
            } else {
                let max = app
                    .connection_collector
                    .connections
                    .lock()
                    .unwrap()
                    .len()
                    .saturating_sub(1);
                app.scroll.connection_scroll =
                    clamp_scroll(app.scroll.connection_scroll, delta, max);
            }
        }
        Tab::Packets => {
            if app.stream_view_open {
                app.scroll.stream_scroll =
                    clamp_scroll(app.scroll.stream_scroll, delta, usize::MAX);
            } else {
                app.packet_follow = false;
                let packets = app.packet_collector.get_packets();
                let max = packets.len().saturating_sub(1);
                app.scroll.packet_scroll = clamp_scroll(app.scroll.packet_scroll, delta, max);
                if let Some(pkt) = packets.get(app.scroll.packet_scroll) {
                    app.scroll.packet_selected = Some(pkt.id);
                }
            }
        }
        Tab::Stats => {
            app.scroll.stats_scroll = clamp_scroll(app.scroll.stats_scroll, delta, usize::MAX);
        }
        Tab::Topology => {
            if app.traceroute_view_open {
                app.scroll.traceroute_scroll =
                    clamp_scroll(app.scroll.traceroute_scroll, delta, usize::MAX);
            } else {
                app.scroll.topology_scroll =
                    clamp_scroll(app.scroll.topology_scroll, delta, usize::MAX);
            }
        }
        Tab::Timeline => {
            app.scroll.timeline_scroll =
                clamp_scroll(app.scroll.timeline_scroll, delta, usize::MAX);
        }
        Tab::Processes => {
            let max = app.process_bandwidth.ranked().len().saturating_sub(1);
            app.scroll.process_scroll = clamp_scroll(app.scroll.process_scroll, delta, max);
        }
        Tab::Insights => {
            app.scroll.insights_scroll =
                clamp_scroll(app.scroll.insights_scroll, delta, usize::MAX);
        }
        Tab::Dashboard | Tab::Interfaces => {
            let max = app.traffic.interface_count().saturating_sub(1);
            app.selected_interface = match (app.selected_interface, delta < 0) {
                (Some(0) | None, true) => None,
                (None, false) => Some(0_usize.min(max)),
                (Some(i), _) => Some(clamp_scroll(i, delta, max)),
            };
        }
    }
}

// ── Key event handlers ─────────────────────────────────────────────────────
//
// The event loop in `run()` delegates to `handle_key`, which routes to one
// of four mode-specific handlers depending on which overlay is active.
// Returns `true` if the application should exit.

fn handle_key(app: &mut App, key: crossterm::event::KeyEvent) -> bool {
    // Overlays intercept first
    if app.show_help {
        return handle_help_key(app, key);
    }
    if app.show_settings {
        return handle_settings_key(app, key);
    }
    if app.sort_picker.is_open() {
        // auto-close if tab changed to a non-sortable tab (e.g. via mouse)
        if sort_columns_for_tab(app.current_tab).is_empty() {
            app.sort_picker.close();
        } else {
            let cols = sort_columns_for_tab(app.current_tab);
            let action = app.sort_picker.handle_key(key, cols);
            match action {
                ui::sort_picker::PickerAction::Select(col_idx) => {
                    let tab = app.current_tab;
                    app.sort_states
                        .entry(tab)
                        .and_modify(|s| s.column = col_idx)
                        .or_insert(TabSortState {
                            column: col_idx,
                            ascending: true,
                        });
                }
                ui::sort_picker::PickerAction::ToggleDirection => {
                    let tab = app.current_tab;
                    if let Some(state) = app.sort_states.get_mut(&tab) {
                        state.ascending = !state.ascending;
                    }
                }
                ui::sort_picker::PickerAction::Close | ui::sort_picker::PickerAction::None => {}
            }
            return false;
        }
    }
    // Text input modes
    if app.packet_filter_input && app.current_tab == Tab::Packets {
        handle_filter_input(app, key);
        return false;
    }
    if app.connection_filter_input && app.current_tab == Tab::Connections {
        handle_connection_filter_input(app, key);
        return false;
    }
    handle_main_key(app, key)
}

fn handle_help_key(app: &mut App, key: crossterm::event::KeyEvent) -> bool {
    match key.code {
        KeyCode::Char('?') | KeyCode::Esc => {
            app.show_help = false;
            app.scroll.help_scroll = 0;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.scroll.help_scroll = app.scroll.help_scroll.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.scroll.help_scroll += 1;
        }
        KeyCode::Char('q') => return true,
        _ => {}
    }
    false
}

fn handle_settings_key(app: &mut App, key: crossterm::event::KeyEvent) -> bool {
    if app.settings_editing {
        match key.code {
            KeyCode::Enter => {
                let value = app.settings_edit_buf.clone();
                let cursor = app.settings_cursor;
                match ui::settings::apply_edit(&mut app.user_config, cursor, &value) {
                    Ok(()) => {
                        app.show_geo = app.user_config.show_geo;
                        app.packet_follow = app.user_config.packet_follow;
                        app.timeline_window = app.user_config.timeline_window_enum();
                        app.theme = crate::theme::by_name(&app.user_config.theme);
                        if (ui::settings::cursor::AI_INSIGHTS..=ui::settings::cursor::AI_ENDPOINT)
                            .contains(&cursor)
                        {
                            app.insights_collector = if app.user_config.insights_enabled {
                                Some(crate::collectors::insights::InsightsCollector::new(
                                    &app.user_config.insights_model,
                                    &app.user_config.insights_endpoint,
                                ))
                            } else {
                                None
                            };
                            if !app.user_config.insights_enabled && app.current_tab == Tab::Insights
                            {
                                app.current_tab = Tab::Dashboard;
                            }
                        }
                        app.settings_status = Some("✓ Applied".into());
                        app.settings_status_tick = 0;
                    }
                    Err(msg) => {
                        app.settings_status = Some(format!("✗ {}", msg));
                        app.settings_status_tick = 0;
                    }
                }
                app.settings_editing = false;
            }
            KeyCode::Esc => {
                app.settings_editing = false;
            }
            KeyCode::Backspace => {
                app.settings_edit_buf.pop();
            }
            KeyCode::Char(c) => {
                app.settings_edit_buf.push(c);
            }
            _ => {}
        }
    } else {
        match key.code {
            KeyCode::Esc => {
                app.show_settings = false;
            }
            KeyCode::Char('q') => return true,
            KeyCode::Up | KeyCode::Char('k') => {
                app.settings_cursor = app.settings_cursor.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if app.settings_cursor + 1 < ui::settings::SETTINGS_COUNT {
                    app.settings_cursor += 1;
                }
            }
            KeyCode::Left | KeyCode::Right | KeyCode::Char('h') | KeyCode::Char('l')
                if app.settings_cursor == ui::settings::cursor::THEME =>
            {
                let names = crate::theme::THEME_NAMES;
                let current = names
                    .iter()
                    .position(|&n| n == app.user_config.theme)
                    .unwrap_or(0);
                let forward = matches!(key.code, KeyCode::Right | KeyCode::Char('l'));
                let next = if forward {
                    (current + 1) % names.len()
                } else {
                    (current + names.len() - 1) % names.len()
                };
                app.user_config.theme = names[next].to_string();
                app.theme = crate::theme::by_name(names[next]);
                app.settings_status = Some(format!("Theme: {}", names[next]));
                app.settings_status_tick = 0;
            }
            KeyCode::Left | KeyCode::Right | KeyCode::Char('h') | KeyCode::Char('l')
                if app.settings_cursor == ui::settings::cursor::DEFAULT_TAB =>
            {
                let names = ui::settings::TAB_NAMES;
                let current = names
                    .iter()
                    .position(|&n| n == app.user_config.default_tab)
                    .unwrap_or(0);
                let forward = matches!(key.code, KeyCode::Right | KeyCode::Char('l'));
                let next = if forward {
                    (current + 1) % names.len()
                } else {
                    (current + names.len() - 1) % names.len()
                };
                app.user_config.default_tab = names[next].to_string();
                app.settings_status = Some(format!("Default tab: {}", names[next]));
                app.settings_status_tick = 0;
            }
            KeyCode::Enter => {
                app.settings_editing = true;
                app.settings_edit_buf =
                    ui::settings::get_edit_value(&app.user_config, app.settings_cursor);
            }
            KeyCode::Char('S') => match app.user_config.save() {
                Ok(()) => {
                    let path = NetwatchConfig::path()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default();
                    app.settings_status = Some(format!("✓ Saved to {}", path));
                    app.settings_status_tick = 0;
                }
                Err(e) => {
                    app.settings_status = Some(format!("✗ Save failed: {}", e));
                    app.settings_status_tick = 0;
                }
            },
            _ => {}
        }
    }
    false
}

fn handle_filter_input(app: &mut App, key: crossterm::event::KeyEvent) {
    match key.code {
        KeyCode::Enter => {
            app.packet_filter_input = false;
            if app.packet_filter_text.trim().is_empty() {
                app.packet_filter_active = None;
            } else {
                app.packet_filter_active = Some(app.packet_filter_text.clone());
            }
        }
        KeyCode::Esc => {
            app.packet_filter_input = false;
            app.packet_filter_text = app.packet_filter_active.clone().unwrap_or_default();
        }
        KeyCode::Backspace => {
            app.packet_filter_text.pop();
        }
        KeyCode::Char(c) => {
            app.packet_filter_text.push(c);
        }
        _ => {}
    }
}

fn handle_connection_filter_input(app: &mut App, key: crossterm::event::KeyEvent) {
    match key.code {
        KeyCode::Enter => {
            app.connection_filter_input = false;
            if app.connection_filter_text.trim().is_empty() {
                app.connection_filter_active = None;
            } else {
                app.connection_filter_active = Some(app.connection_filter_text.clone());
            }
            app.scroll.connection_scroll = 0;
        }
        KeyCode::Esc => {
            app.connection_filter_input = false;
            app.connection_filter_text = app.connection_filter_active.clone().unwrap_or_default();
        }
        KeyCode::Backspace => {
            app.connection_filter_text.pop();
        }
        KeyCode::Char(c) => {
            app.connection_filter_text.push(c);
        }
        _ => {}
    }
}

/// Handles keys during normal navigation (no overlay active, no text input mode).
/// Returns `true` if the application should exit.
fn handle_main_key(app: &mut App, key: crossterm::event::KeyEvent) -> bool {
    match key.code {
        KeyCode::Char('q') => return true,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
        KeyCode::Char('?') => {
            app.show_help = !app.show_help;
            app.scroll.help_scroll = 0;
        }
        KeyCode::Char('g') => app.show_geo = !app.show_geo,
        KeyCode::Char('t') if app.current_tab != Tab::Timeline => {
            let names = crate::theme::THEME_NAMES;
            let current = names.iter().position(|&n| n == app.theme.name).unwrap_or(0);
            let next = (current + 1) % names.len();
            app.user_config.theme = names[next].to_string();
            app.theme = crate::theme::by_name(names[next]);
        }
        KeyCode::Char(',') => {
            app.show_settings = !app.show_settings;
            app.settings_editing = false;
            if app.show_settings && app.current_tab == Tab::Insights {
                app.settings_cursor = ui::settings::cursor::AI_INSIGHTS;
            }
        }
        KeyCode::Char('p') => app.paused = !app.paused,
        KeyCode::Char('r') => {
            app.traffic.update();
            if let Ok(info) = crate::platform::collect_interface_info() {
                app.interface_info = info;
            }
            app.connection_collector.update();
            app.config_collector.update();
            let gateway = app.config_collector.config.gateway.clone();
            let dns = app.config_collector.config.dns_servers.first().cloned();
            app.health_prober.probe(gateway.as_deref(), dns.as_deref());
        }
        KeyCode::Char('R') => match app.incident_recorder.state() {
            crate::collectors::incident::RecorderState::Off => {
                app.arm_incident_recorder();
            }
            crate::collectors::incident::RecorderState::Armed => {
                app.disarm_incident_recorder();
            }
            crate::collectors::incident::RecorderState::Frozen => {
                app.arm_incident_recorder();
            }
        },
        KeyCode::Char('F') => {
            app.freeze_incident_recorder("manual freeze");
        }
        KeyCode::Char('E') => {
            app.export_incident_bundle();
        }
        KeyCode::Char('1') => app.current_tab = Tab::Dashboard,
        KeyCode::Char('2') => app.current_tab = Tab::Connections,
        KeyCode::Char('3') => app.current_tab = Tab::Interfaces,
        KeyCode::Char('4') => app.current_tab = Tab::Packets,
        KeyCode::Char('5') => app.current_tab = Tab::Stats,
        KeyCode::Char('6') => app.current_tab = Tab::Topology,
        KeyCode::Char('7') => app.current_tab = Tab::Timeline,
        KeyCode::Char('8') => app.current_tab = Tab::Processes,
        KeyCode::Char('9') if app.user_config.insights_enabled => {
            app.current_tab = Tab::Insights;
        }
        // Stream view controls (intercept before other Packets keys)
        KeyCode::Esc if app.current_tab == Tab::Packets && app.stream_view_open => {
            app.stream_view_open = false;
            app.stream_view_index = None;
            app.scroll.stream_scroll = 0;
        }
        KeyCode::Char('h') if app.current_tab == Tab::Packets && app.stream_view_open => {
            app.stream_hex_mode = !app.stream_hex_mode;
        }
        KeyCode::Char('a') if app.current_tab == Tab::Insights => {
            if let Some(ref collector) = app.insights_collector {
                let packets = app.packet_collector.get_packets();
                let conns = app.connection_collector.connections.lock().unwrap().clone();
                let health = app.health_prober.status.lock().unwrap().clone();
                let interfaces = app.traffic.interfaces();
                let (rx_bps, tx_bps) = interfaces.iter().fold((0.0f64, 0.0f64), |(rx, tx), i| {
                    (rx + i.rx_rate, tx + i.tx_rate)
                });
                let rx_str = crate::ui::widgets::format_bytes_rate(rx_bps);
                let tx_str = crate::ui::widgets::format_bytes_rate(tx_bps);
                let snapshot = crate::collectors::insights::NetworkSnapshot::build(
                    &packets, &conns, &health, &rx_str, &tx_str,
                );
                collector.submit_snapshot(snapshot);
            }
        }
        KeyCode::Char('a') if app.current_tab == Tab::Packets && app.stream_view_open => {
            app.stream_direction_filter = StreamDirectionFilter::Both;
        }
        KeyCode::Right if app.current_tab == Tab::Packets && app.stream_view_open => {
            app.stream_direction_filter = StreamDirectionFilter::AtoB;
        }
        KeyCode::Left if app.current_tab == Tab::Packets && app.stream_view_open => {
            app.stream_direction_filter = StreamDirectionFilter::BtoA;
        }
        KeyCode::Up | KeyCode::Char('k')
            if app.current_tab == Tab::Packets && app.stream_view_open =>
        {
            app.scroll.stream_scroll = app.scroll.stream_scroll.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j')
            if app.current_tab == Tab::Packets && app.stream_view_open =>
        {
            app.scroll.stream_scroll += 1;
        }
        KeyCode::Char('s') if app.current_tab == Tab::Packets && !app.stream_view_open => {
            if let Some(sel_id) = app.scroll.packet_selected {
                let packets = app.packet_collector.get_packets();
                if let Some(pkt) = packets.iter().find(|p| p.id == sel_id) {
                    if pkt.stream_index.is_some() {
                        app.stream_view_open = true;
                        app.stream_view_index = pkt.stream_index;
                        app.scroll.stream_scroll = 0;
                        app.stream_direction_filter = StreamDirectionFilter::Both;
                        app.stream_hex_mode = false;
                    }
                }
            }
        }
        KeyCode::Char('c') if app.current_tab == Tab::Packets => {
            if app.packet_collector.is_capturing() {
                app.packet_collector.stop_capture();
            } else {
                let iface = app.capture_interface.clone();
                let bpf = app.bpf_filter_active.as_deref();
                app.packet_collector.start_capture(&iface, bpf);
            }
        }
        KeyCode::Char('i') if app.current_tab == Tab::Packets => {
            if !app.packet_collector.is_capturing() {
                app.cycle_capture_interface();
            }
        }
        KeyCode::Char('x') if app.current_tab == Tab::Packets => {
            app.packet_collector.clear();
            app.scroll.packet_scroll = 0;
            app.scroll.packet_selected = None;
            app.bookmarks.clear();
        }
        KeyCode::Char('m') if app.current_tab == Tab::Packets && !app.stream_view_open => {
            if let Some(sel_id) = app.scroll.packet_selected {
                if !app.bookmarks.remove(&sel_id) {
                    app.bookmarks.insert(sel_id);
                }
            }
        }
        KeyCode::Char('n') if app.current_tab == Tab::Packets && !app.stream_view_open => {
            let packets = app.packet_collector.get_packets();
            let current_id = app.scroll.packet_selected.unwrap_or(0);
            if let Some((idx, pkt)) = packets
                .iter()
                .enumerate()
                .find(|(_, p)| p.id > current_id && app.bookmarks.contains(&p.id))
            {
                app.scroll.packet_selected = Some(pkt.id);
                app.scroll.packet_scroll = idx;
                app.packet_follow = false;
            }
        }
        KeyCode::Char('N') if app.current_tab == Tab::Packets && !app.stream_view_open => {
            let packets = app.packet_collector.get_packets();
            let current_id = app.scroll.packet_selected.unwrap_or(u64::MAX);
            if let Some((idx, pkt)) = packets
                .iter()
                .enumerate()
                .rev()
                .find(|(_, p)| p.id < current_id && app.bookmarks.contains(&p.id))
            {
                app.scroll.packet_selected = Some(pkt.id);
                app.scroll.packet_scroll = idx;
                app.packet_follow = false;
            }
        }
        KeyCode::Char('f') if app.current_tab == Tab::Packets => {
            app.packet_follow = !app.packet_follow;
        }
        KeyCode::Char('w') if app.current_tab == Tab::Packets => {
            use crate::collectors::packets::{export_pcap, matches_packet, parse_filter};
            let packets = app.packet_collector.get_packets();
            let filtered: Vec<_>;
            let to_export: &[_] = if let Some(ref ft) = app.packet_filter_active {
                if let Some(expr) = parse_filter(ft) {
                    filtered = packets
                        .iter()
                        .filter(|p| matches_packet(&expr, p))
                        .cloned()
                        .collect();
                    &filtered
                } else {
                    &packets
                }
            } else {
                &packets
            };
            let ts = chrono::Local::now().format("%Y%m%d_%H%M%S");
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            let path = format!("{home}/netwatch_capture_{ts}.pcap");
            match export_pcap(to_export, &path) {
                Ok(n) => {
                    app.export_status = Some(format!("Saved {n} packets to {path}"));
                }
                Err(e) => {
                    app.export_status = Some(format!("Export failed: {e}"));
                }
            }
            app.export_status_tick = 0;
        }
        KeyCode::Char('W') if app.current_tab == Tab::Packets && !app.stream_view_open => {
            if let Some(sel_id) = app.scroll.packet_selected {
                let packets = app.packet_collector.get_packets();
                if let Some(pkt) = packets.iter().find(|p| p.id == sel_id) {
                    app.whois_cache.request(&pkt.src_ip);
                    app.whois_cache.request(&pkt.dst_ip);
                }
            }
        }
        KeyCode::Char('W') if app.current_tab == Tab::Connections => {
            let mut conns = app.connection_collector.connections.lock().unwrap().clone();
            let sort_st = app.sort_states.get(&Tab::Connections);
            crate::ui::connections::sort(
                &mut conns,
                sort_st.map(|s| s.column).unwrap_or(0),
                sort_st.map(|s| s.ascending).unwrap_or(true),
            );
            if let Some(conn) = conns.get(app.scroll.connection_scroll) {
                let (remote_ip, _) = parse_addr_parts(&conn.remote_addr);
                if let Some(ip) = remote_ip {
                    app.whois_cache.request(&ip);
                }
            }
        }
        KeyCode::Char('T') if app.current_tab == Tab::Connections && !app.traceroute_view_open => {
            let mut conns = app.connection_collector.connections.lock().unwrap().clone();
            let sort_st = app.sort_states.get(&Tab::Connections);
            crate::ui::connections::sort(
                &mut conns,
                sort_st.map(|s| s.column).unwrap_or(0),
                sort_st.map(|s| s.ascending).unwrap_or(true),
            );
            if let Some(conn) = conns.get(app.scroll.connection_scroll) {
                let (remote_ip, _) = parse_addr_parts(&conn.remote_addr);
                if let Some(ip) = remote_ip {
                    app.traceroute_runner.run(&ip);
                    app.traceroute_view_open = true;
                    app.scroll.traceroute_scroll = 0;
                }
            }
        }
        KeyCode::Esc if app.current_tab == Tab::Connections && app.traceroute_view_open => {
            app.traceroute_view_open = false;
            app.traceroute_runner.clear();
        }
        KeyCode::Char('/') if app.current_tab == Tab::Connections && !app.traceroute_view_open => {
            app.connection_filter_input = true;
            app.connection_filter_text = app.connection_filter_active.clone().unwrap_or_default();
        }
        KeyCode::Esc
            if app.current_tab == Tab::Connections
                && !app.traceroute_view_open
                && app.connection_filter_active.is_some() =>
        {
            app.connection_filter_active = None;
            app.connection_filter_text.clear();
            app.scroll.connection_scroll = 0;
        }
        KeyCode::Char('e')
            if app.current_tab == Tab::Connections || app.current_tab == Tab::Processes =>
        {
            let conns = app.connection_collector.connections.lock().unwrap().clone();
            let ts = chrono::Local::now().format("%Y%m%d_%H%M%S");
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            let json_path = format!("{home}/netwatch_connections_{ts}.json");
            let csv_path = format!("{home}/netwatch_connections_{ts}.csv");
            match crate::collectors::connections::export_json(&conns, &json_path) {
                Ok(n) => {
                    let _ = crate::collectors::connections::export_csv(&conns, &csv_path);
                    app.export_status = Some(format!("Exported {n} connections to JSON + CSV"));
                }
                Err(e) => {
                    app.export_status = Some(format!("Export failed: {e}"));
                }
            }
            app.export_status_tick = 0;
        }
        KeyCode::Char('s') => {
            let tab = app.current_tab;
            let keys = sort_columns_for_tab(tab);
            if !keys.is_empty() {
                let current_col = app.sort_states.get(&tab).map(|s| s.column).unwrap_or(0);
                app.sort_picker.open(current_col, keys.len());
            }
        }
        KeyCode::Char('S') => {
            let tab = app.current_tab;
            if let Some(state) = app.sort_states.get_mut(&tab) {
                state.ascending = !state.ascending;
            }
        }
        KeyCode::Char('t') if app.current_tab == Tab::Timeline => {
            app.timeline_window = app.timeline_window.next();
        }
        KeyCode::Enter if app.current_tab == Tab::Timeline => {
            let window_secs = app.timeline_window.seconds();
            let now = std::time::Instant::now();
            let window_start = now - std::time::Duration::from_secs(window_secs);
            let mut sorted: Vec<&crate::collectors::connections::TrackedConnection> = app
                .connection_timeline
                .tracked
                .iter()
                .filter(|t| t.last_seen >= window_start)
                .collect();
            sorted.sort_by(|a, b| {
                b.is_active
                    .cmp(&a.is_active)
                    .then_with(|| a.first_seen.cmp(&b.first_seen))
            });
            if let Some(tracked) = sorted.get(app.scroll.timeline_scroll) {
                let (remote_ip, _) = parse_addr_parts(&tracked.key.remote_addr);
                if let Some(ip) = remote_ip {
                    app.packet_filter_text = ip.clone();
                    app.packet_filter_active = Some(ip);
                    app.packet_filter_input = false;
                    app.scroll.packet_scroll = 0;
                    app.packet_follow = false;
                    app.current_tab = Tab::Connections;
                }
            }
        }
        KeyCode::Enter if app.current_tab == Tab::Connections => {
            let mut conns = app.connection_collector.connections.lock().unwrap().clone();
            let sort_st = app.sort_states.get(&Tab::Connections);
            crate::ui::connections::sort(
                &mut conns,
                sort_st.map(|s| s.column).unwrap_or(0),
                sort_st.map(|s| s.ascending).unwrap_or(true),
            );
            if let Some(conn) = conns.get(app.scroll.connection_scroll) {
                let filter = build_connection_filter(conn);
                app.packet_filter_text = filter.clone();
                app.packet_filter_active = Some(filter);
                app.packet_filter_input = false;
                app.scroll.packet_scroll = 0;
                app.packet_follow = false;
                app.current_tab = Tab::Packets;
            }
        }
        KeyCode::Enter if app.current_tab == Tab::Topology && !app.traceroute_view_open => {
            let remote_ips = top_remote_ips(app);
            if let Some((ip, _)) = remote_ips.get(app.scroll.topology_scroll) {
                app.packet_filter_text = ip.clone();
                app.packet_filter_active = Some(ip.clone());
                app.packet_filter_input = false;
                app.scroll.packet_scroll = 0;
                app.packet_follow = false;
                app.current_tab = Tab::Connections;
            }
        }
        KeyCode::Char('T') if app.current_tab == Tab::Topology && !app.traceroute_view_open => {
            let remote_ips = top_remote_ips(app);
            if let Some((ip, _)) = remote_ips.get(app.scroll.topology_scroll) {
                app.traceroute_runner.run(ip);
                app.traceroute_view_open = true;
                app.scroll.traceroute_scroll = 0;
            }
        }
        KeyCode::Esc if app.current_tab == Tab::Topology && app.traceroute_view_open => {
            app.traceroute_view_open = false;
            app.traceroute_runner.clear();
        }
        KeyCode::Enter if app.current_tab == Tab::Packets => {
            let packets = app.packet_collector.get_packets();
            if !packets.is_empty() {
                let visible_height = 20usize;
                let total = packets.len();
                let offset = if app.packet_follow && total > visible_height {
                    total - visible_height
                } else {
                    app.scroll
                        .packet_scroll
                        .min(total.saturating_sub(visible_height))
                };
                if let Some(pkt) = packets.get(offset) {
                    app.scroll.packet_selected = Some(pkt.id);
                }
            }
        }
        KeyCode::Up | KeyCode::Char('k') => scroll_tab(app, -1),
        KeyCode::Down | KeyCode::Char('j') => scroll_tab(app, 1),
        KeyCode::PageUp => scroll_tab(app, -(PAGE_SCROLL as isize)),
        KeyCode::PageDown => scroll_tab(app, PAGE_SCROLL as isize),
        KeyCode::Char('/') if app.current_tab == Tab::Packets && !app.stream_view_open => {
            app.packet_filter_input = true;
            app.packet_filter_text = app.packet_filter_active.clone().unwrap_or_default();
        }
        KeyCode::Esc
            if app.current_tab == Tab::Packets
                && !app.stream_view_open
                && app.packet_filter_active.is_some() =>
        {
            app.packet_filter_active = None;
            app.packet_filter_text.clear();
        }
        _ => {}
    }
    false
}

/// Returns remote IPs ranked by connection count, used by Topology tab actions.
fn top_remote_ips(app: &App) -> Vec<(String, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    let conns = app.connection_collector.connections.lock().unwrap();
    for conn in conns.iter() {
        let (remote_ip, _) = parse_addr_parts(&conn.remote_addr);
        if let Some(ip) = remote_ip {
            *counts.entry(ip).or_insert(0) += 1;
        }
    }
    let mut remote_ips: Vec<(String, usize)> = counts.into_iter().collect();
    remote_ips.sort_by(|a, b| b.1.cmp(&a.1));
    remote_ips
}
#[cfg(test)]
pub(crate) fn sort_connections(conns: &mut [Connection], column: usize) {
    crate::ui::connections::sort(conns, column, true);
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::process_bandwidth::ProcessBandwidth;
    use crate::collectors::traffic::InterfaceTraffic;
    use crate::sort::*;

    // look up a column index by name for readable test assertions
    fn col(tab: Tab, name: &str) -> usize {
        sort_columns_for_tab(tab)
            .iter()
            .position(|c| c.name == name)
            .unwrap_or_else(|| panic!("no column {:?} in {:?}", name, tab))
    }

    fn conn(process: Option<&str>) -> Connection {
        Connection {
            protocol: "TCP".into(),
            local_addr: "127.0.0.1:0".into(),
            remote_addr: "0.0.0.0:0".into(),
            state: "ESTABLISHED".into(),
            pid: None,
            process_name: process.map(|s| s.to_string()),
            kernel_rtt_us: None,
            rx_rate: None,
            tx_rate: None,
        }
    }

    #[test]
    fn process_name_sort_is_case_insensitive() {
        // Mixed-case names should interleave in dictionary order regardless of
        // case — on macOS this is the common case ("Finder", "facetime",
        // "kernel_task") and byte-wise sort scatters them.
        let mut conns = vec![
            conn(Some("finder")),
            conn(Some("Apple")),
            conn(Some("zoom")),
            conn(Some("Brave")),
        ];
        sort_connections(&mut conns, col(Tab::Connections, "Process"));
        let order: Vec<_> = conns
            .iter()
            .map(|c| c.process_name.as_deref().unwrap())
            .collect();
        assert_eq!(order, vec!["Apple", "Brave", "finder", "zoom"]);
    }

    #[test]
    fn process_name_sort_is_stable_on_case_only_difference() {
        // When two names differ only in case, lowercase wins the tiebreaker
        // (byte-wise cmp: 'A' < 'a'), but the important property is that the
        // order is deterministic frame-to-frame.
        let mut a = vec![conn(Some("finder")), conn(Some("Finder"))];
        let mut b = vec![conn(Some("Finder")), conn(Some("finder"))];
        sort_connections(&mut a, col(Tab::Connections, "Process"));
        sort_connections(&mut b, col(Tab::Connections, "Process"));
        let names = |v: &[Connection]| -> Vec<String> {
            v.iter().map(|c| c.process_name.clone().unwrap()).collect()
        };
        assert_eq!(names(&a), names(&b));
    }

    // -- cmp_ip_addr --

    #[test]
    fn ip_sort_ipv4_numeric_ordering() {
        use std::cmp::Ordering;
        assert_eq!(cmp_ip_addr("1.2.3.4:80", "10.0.0.1:80"), Ordering::Less);
        assert_eq!(
            cmp_ip_addr("10.0.0.1:80", "192.168.1.1:443"),
            Ordering::Less
        );
        assert_eq!(
            cmp_ip_addr("192.168.1.1:80", "1.2.3.4:80"),
            Ordering::Greater
        );
    }

    #[test]
    fn ip_sort_same_ip_port_tiebreaker() {
        use std::cmp::Ordering;
        assert_eq!(cmp_ip_addr("1.2.3.4:80", "1.2.3.4:443"), Ordering::Less);
        assert_eq!(cmp_ip_addr("1.2.3.4:443", "1.2.3.4:80"), Ordering::Greater);
        assert_eq!(cmp_ip_addr("1.2.3.4:80", "1.2.3.4:80"), Ordering::Equal);
    }

    #[test]
    fn ip_sort_ipv6_ordering() {
        use std::cmp::Ordering;
        assert_eq!(cmp_ip_addr("[::1]:80", "[::2]:80"), Ordering::Less);
        assert_eq!(cmp_ip_addr("[fe80::1]:80", "[fe80::2]:80"), Ordering::Less);
    }

    #[test]
    fn ip_sort_ipv4_before_ipv6() {
        use std::cmp::Ordering;
        assert_eq!(cmp_ip_addr("1.2.3.4:80", "[::1]:80"), Ordering::Less);
        assert_eq!(cmp_ip_addr("[::1]:80", "1.2.3.4:80"), Ordering::Greater);
    }

    #[test]
    fn ip_sort_wildcard_and_empty_sort_first() {
        use std::cmp::Ordering;
        assert_eq!(cmp_ip_addr("*:*", "1.2.3.4:80"), Ordering::Less);
        assert_eq!(cmp_ip_addr("", "1.2.3.4:80"), Ordering::Less);
        assert_eq!(cmp_ip_addr("*:*", "*:*"), Ordering::Equal);
        assert_eq!(cmp_ip_addr("1.2.3.4:80", "*:*"), Ordering::Greater);
    }

    // -- cmp_case_insensitive --

    #[test]
    fn case_insensitive_basic_ordering() {
        use std::cmp::Ordering;
        assert_eq!(cmp_case_insensitive("apple", "Banana"), Ordering::Less);
        assert_eq!(cmp_case_insensitive("Banana", "apple"), Ordering::Greater);
        assert_eq!(cmp_case_insensitive("Apple", "apple"), Ordering::Less);
        assert_eq!(cmp_case_insensitive("apple", "Apple"), Ordering::Greater);
    }

    // -- cmp_f64 --

    #[test]
    fn f64_cmp_basic() {
        use std::cmp::Ordering;
        assert_eq!(cmp_f64(1.0, 2.0), Ordering::Less);
        assert_eq!(cmp_f64(2.0, 1.0), Ordering::Greater);
        assert_eq!(cmp_f64(3.14, 3.14), Ordering::Equal);
    }

    #[test]
    fn f64_cmp_nan_sorts_after_everything() {
        use std::cmp::Ordering;
        // total_cmp places NaN after infinity
        assert_eq!(cmp_f64(f64::NAN, 1.0), Ordering::Greater);
        assert_eq!(cmp_f64(1.0, f64::NAN), Ordering::Less);
        assert_eq!(cmp_f64(f64::NAN, f64::NAN), Ordering::Equal);
    }

    // -- sort_connections --

    fn conn_full(
        process: Option<&str>,
        pid: Option<u32>,
        local: &str,
        remote: &str,
        rx: Option<f64>,
        tx: Option<f64>,
    ) -> Connection {
        Connection {
            protocol: "TCP".into(),
            local_addr: local.into(),
            remote_addr: remote.into(),
            state: "ESTABLISHED".into(),
            pid,
            process_name: process.map(|s| s.to_string()),
            kernel_rtt_us: None,
            rx_rate: rx,
            tx_rate: tx,
        }
    }

    #[test]
    fn sort_connections_by_pid() {
        let mut conns = vec![
            conn_full(None, Some(300), "0:0", "0:0", None, None),
            conn_full(None, Some(100), "0:0", "0:0", None, None),
            conn_full(None, None, "0:0", "0:0", None, None),
            conn_full(None, Some(200), "0:0", "0:0", None, None),
        ];
        sort_connections(&mut conns, col(Tab::Connections, "PID"));
        let pids: Vec<_> = conns.iter().map(|c| c.pid).collect();
        assert_eq!(pids, vec![None, Some(100), Some(200), Some(300)]);
    }

    #[test]
    fn sort_connections_by_remote_addr_uses_numeric_ip() {
        let mut conns = vec![
            conn_full(None, None, "0:0", "192.168.1.1:443", None, None),
            conn_full(None, None, "0:0", "1.2.3.4:80", None, None),
            conn_full(None, None, "0:0", "10.0.0.1:80", None, None),
        ];
        sort_connections(&mut conns, col(Tab::Connections, "Remote Address"));
        let addrs: Vec<_> = conns.iter().map(|c| c.remote_addr.as_str()).collect();
        assert_eq!(addrs, vec!["1.2.3.4:80", "10.0.0.1:80", "192.168.1.1:443"]);
    }

    #[test]
    fn sort_connections_by_rate_descending() {
        let mut conns = vec![
            conn_full(None, None, "0:0", "0:0", Some(100.0), Some(50.0)),
            conn_full(None, None, "0:0", "0:0", Some(500.0), Some(500.0)),
            conn_full(None, None, "0:0", "0:0", None, None),
            conn_full(None, None, "0:0", "0:0", Some(200.0), Some(100.0)),
        ];
        crate::ui::connections::sort(&mut conns, col(Tab::Connections, "Down/Up"), false);
        let totals: Vec<f64> = conns
            .iter()
            .map(|c| c.rx_rate.unwrap_or(0.0) + c.tx_rate.unwrap_or(0.0))
            .collect();
        assert_eq!(totals, vec![1000.0, 300.0, 150.0, 0.0]);
    }

    #[test]
    fn sort_connections_by_rate_ascending() {
        let mut conns = vec![
            conn_full(None, None, "0:0", "0:0", Some(500.0), Some(500.0)),
            conn_full(None, None, "0:0", "0:0", None, None),
            conn_full(None, None, "0:0", "0:0", Some(100.0), Some(50.0)),
        ];
        crate::ui::connections::sort(&mut conns, col(Tab::Connections, "Down/Up"), true);
        let totals: Vec<f64> = conns
            .iter()
            .map(|c| c.rx_rate.unwrap_or(0.0) + c.tx_rate.unwrap_or(0.0))
            .collect();
        assert_eq!(totals, vec![0.0, 150.0, 1000.0]);
    }

    // -- tab configuration --

    #[test]
    fn each_sortable_tab_has_keys() {
        let sortable = [
            Tab::Dashboard,
            Tab::Connections,
            Tab::Interfaces,
            Tab::Processes,
        ];
        for tab in &sortable {
            assert!(
                !sort_columns_for_tab(*tab).is_empty(),
                "{:?} should have sort columns",
                tab
            );
        }
    }

    #[test]
    fn non_sortable_tabs_have_no_keys() {
        let non_sortable = [
            Tab::Packets,
            Tab::Stats,
            Tab::Topology,
            Tab::Timeline,
            Tab::Insights,
        ];
        for tab in &non_sortable {
            assert!(
                sort_columns_for_tab(*tab).is_empty(),
                "{:?} should have no sort columns",
                tab
            );
        }
    }

    #[test]
    fn default_sort_column_is_zero() {
        for (tab, state) in &default_sort_states() {
            if *tab == Tab::Processes {
                // processes default to "Total Rate" (column 5) descending
                assert_eq!(
                    state.column, 5,
                    "Processes default column should be 5 (Total Rate)"
                );
            } else {
                assert_eq!(state.column, 0, "{:?} default column should be 0", tab);
            }
        }
    }

    #[test]
    fn default_sort_states_are_ascending() {
        for (tab, state) in &default_sort_states() {
            if *tab == Tab::Processes {
                // processes default to descending (top bandwidth first)
                assert!(!state.ascending, "Processes default should be descending");
            } else {
                assert!(state.ascending, "{:?} default should be ascending", tab);
            }
        }
    }

    #[test]
    fn every_connection_column_has_a_comparator() {
        // sorting by a column with no comparator arm silently falls through
        // to Ordering::Equal — this test catches that by verifying the sort
        // actually reorders data for every column
        let make = || {
            let mut a = conn_full(
                Some("zz"),
                Some(300),
                "10.0.0.1:80",
                "192.168.1.1:443",
                Some(100.0),
                Some(50.0),
            );
            a.protocol = "UDP".into();
            a.state = "LISTEN".into();
            let mut b = conn_full(
                Some("aa"),
                Some(100),
                "1.2.3.4:80",
                "10.0.0.1:80",
                Some(500.0),
                Some(500.0),
            );
            b.protocol = "TCP".into();
            b.state = "ESTABLISHED".into();
            vec![a, b]
        };
        for (i, col) in sort_columns_for_tab(Tab::Connections).iter().enumerate() {
            let mut data = make();
            crate::ui::connections::sort(&mut data, i, true);
            let mut rev = make();
            crate::ui::connections::sort(&mut rev, i, false);
            assert_ne!(
                data.iter()
                    .map(|c| c.process_name.as_deref().unwrap_or(""))
                    .collect::<Vec<_>>(),
                rev.iter()
                    .map(|c| c.process_name.as_deref().unwrap_or(""))
                    .collect::<Vec<_>>(),
                "column {:?} (index {}) sort has no effect — missing comparator?",
                col.name,
                i
            );
        }
    }

    // -- sort_connections_directed: ascending vs descending --

    #[test]
    fn sort_connections_descending_reverses_ascending() {
        let mut asc = vec![
            conn_full(Some("bravo"), None, "0:0", "0:0", None, None),
            conn_full(Some("alpha"), None, "0:0", "0:0", None, None),
            conn_full(Some("charlie"), None, "0:0", "0:0", None, None),
        ];
        let mut desc = asc.clone();
        crate::ui::connections::sort(&mut asc, col(Tab::Connections, "Process"), true);
        crate::ui::connections::sort(&mut desc, col(Tab::Connections, "Process"), false);
        let asc_names: Vec<_> = asc
            .iter()
            .map(|c| c.process_name.as_deref().unwrap())
            .collect();
        let desc_names: Vec<_> = desc
            .iter()
            .map(|c| c.process_name.as_deref().unwrap())
            .collect();
        assert_eq!(asc_names, vec!["alpha", "bravo", "charlie"]);
        assert_eq!(desc_names, vec!["charlie", "bravo", "alpha"]);
    }

    // -- sort_interfaces --

    fn iface(name: &str, rx_rate: f64, tx_rate: f64) -> InterfaceTraffic {
        InterfaceTraffic {
            name: name.into(),
            rx_rate,
            tx_rate,
            rx_bytes_total: 0,
            tx_bytes_total: 0,
            rx_packets: 0,
            tx_packets: 0,
            rx_errors: 0,
            tx_errors: 0,
            rx_drops: 0,
            tx_drops: 0,
            rx_history: std::collections::VecDeque::new(),
            tx_history: std::collections::VecDeque::new(),
        }
    }

    #[test]
    fn sort_interfaces_by_name() {
        let mut ifaces = vec![
            iface("en0", 0.0, 0.0),
            iface("awdl0", 0.0, 0.0),
            iface("lo0", 0.0, 0.0),
        ];
        crate::ui::interfaces::sort_interfaces(
            &mut ifaces,
            Tab::Dashboard,
            col(Tab::Dashboard, "Interface"),
            true,
            &[],
        );
        let names: Vec<_> = ifaces.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["awdl0", "en0", "lo0"]);
    }

    #[test]
    fn sort_interfaces_by_rx_rate_descending() {
        let mut ifaces = vec![
            iface("a", 100.0, 0.0),
            iface("b", 500.0, 0.0),
            iface("c", 200.0, 0.0),
        ];
        crate::ui::interfaces::sort_interfaces(
            &mut ifaces,
            Tab::Dashboard,
            col(Tab::Dashboard, "Rx Rate"),
            false,
            &[],
        );
        let rates: Vec<f64> = ifaces.iter().map(|i| i.rx_rate).collect();
        assert_eq!(rates, vec![500.0, 200.0, 100.0]);
    }

    #[test]
    fn sort_interfaces_by_status_with_info() {
        use crate::platform::InterfaceInfo;
        let info = vec![
            InterfaceInfo {
                name: "en0".into(),
                ipv4: None,
                ipv6: None,
                mac: None,
                mtu: None,
                is_up: true,
            },
            InterfaceInfo {
                name: "en1".into(),
                ipv4: None,
                ipv6: None,
                mac: None,
                mtu: None,
                is_up: false,
            },
            InterfaceInfo {
                name: "lo0".into(),
                ipv4: None,
                ipv6: None,
                mac: None,
                mtu: None,
                is_up: true,
            },
        ];
        let mut ifaces = vec![
            iface("en1", 0.0, 0.0),
            iface("en0", 0.0, 0.0),
            iface("lo0", 0.0, 0.0),
        ];
        crate::ui::interfaces::sort_interfaces(
            &mut ifaces,
            Tab::Dashboard,
            col(Tab::Dashboard, "Status"),
            true,
            &info,
        );
        let names: Vec<_> = ifaces.iter().map(|i| i.name.as_str()).collect();
        // is_up=false sorts before is_up=true in ascending
        assert_eq!(names[0], "en1");
    }

    #[test]
    fn every_dashboard_column_has_a_comparator() {
        use crate::platform::InterfaceInfo;
        let info = vec![
            InterfaceInfo {
                name: "zz".into(),
                ipv4: Some("10.0.0.1".into()),
                ipv6: Some("fe80::2".into()),
                mac: Some("ff:ff:ff:ff:ff:ff".into()),
                mtu: Some(9000),
                is_up: true,
            },
            InterfaceInfo {
                name: "aa".into(),
                ipv4: Some("1.2.3.4".into()),
                ipv6: Some("fe80::1".into()),
                mac: Some("00:00:00:00:00:00".into()),
                mtu: Some(1500),
                is_up: false,
            },
        ];
        let make = || {
            let mut a = iface("zz", 500.0, 500.0);
            a.rx_bytes_total = 10000;
            a.tx_bytes_total = 10000;
            let mut b = iface("aa", 100.0, 100.0);
            b.rx_bytes_total = 1000;
            b.tx_bytes_total = 1000;
            vec![a, b]
        };
        for (i, col) in sort_columns_for_tab(Tab::Dashboard).iter().enumerate() {
            let mut data = make();
            crate::ui::interfaces::sort_interfaces(&mut data, Tab::Dashboard, i, true, &info);
            let mut rev = make();
            crate::ui::interfaces::sort_interfaces(&mut rev, Tab::Dashboard, i, false, &info);
            assert_ne!(
                data.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
                rev.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
                "Dashboard column {:?} (index {}) has no comparator",
                col.name,
                i
            );
        }
    }

    #[test]
    fn every_interfaces_column_has_a_comparator() {
        use crate::platform::InterfaceInfo;
        let info = vec![
            InterfaceInfo {
                name: "zz".into(),
                ipv4: Some("10.0.0.1".into()),
                ipv6: Some("fe80::2".into()),
                mac: Some("ff:ff:ff:ff:ff:ff".into()),
                mtu: Some(9000),
                is_up: true,
            },
            InterfaceInfo {
                name: "aa".into(),
                ipv4: Some("1.2.3.4".into()),
                ipv6: Some("fe80::1".into()),
                mac: Some("00:00:00:00:00:00".into()),
                mtu: Some(1500),
                is_up: false,
            },
        ];
        let make = || {
            let mut a = iface("zz", 500.0, 500.0);
            a.rx_packets = 1000;
            a.tx_packets = 1000;
            a.rx_errors = 10;
            a.tx_errors = 10;
            let mut b = iface("aa", 100.0, 100.0);
            b.rx_packets = 100;
            b.tx_packets = 100;
            b.rx_errors = 1;
            b.tx_errors = 1;
            vec![a, b]
        };
        for (i, col) in sort_columns_for_tab(Tab::Interfaces).iter().enumerate() {
            let mut data = make();
            crate::ui::interfaces::sort_interfaces(&mut data, Tab::Interfaces, i, true, &info);
            let mut rev = make();
            crate::ui::interfaces::sort_interfaces(&mut rev, Tab::Interfaces, i, false, &info);
            assert_ne!(
                data.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
                rev.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
                "Interfaces column {:?} (index {}) has no comparator",
                col.name,
                i
            );
        }
    }

    // -- sort_processes --

    #[test]
    fn every_processes_column_has_a_comparator() {
        let make = || {
            vec![
                ProcessBandwidth {
                    process_name: "zz".into(),
                    pid: Some(300),
                    connection_count: 10,
                    rx_rate: 500.0,
                    tx_rate: 500.0,
                    rx_bytes: 10000,
                    tx_bytes: 10000,
                },
                ProcessBandwidth {
                    process_name: "aa".into(),
                    pid: Some(100),
                    connection_count: 1,
                    rx_rate: 100.0,
                    tx_rate: 50.0,
                    rx_bytes: 1000,
                    tx_bytes: 1000,
                },
            ]
        };
        for (i, col) in sort_columns_for_tab(Tab::Processes).iter().enumerate() {
            let mut data = make();
            crate::ui::processes::sort(&mut data, i, true);
            let mut rev = make();
            crate::ui::processes::sort(&mut rev, i, false);
            assert_ne!(
                data.iter()
                    .map(|p| p.process_name.as_str())
                    .collect::<Vec<_>>(),
                rev.iter()
                    .map(|p| p.process_name.as_str())
                    .collect::<Vec<_>>(),
                "Processes column {:?} (index {}) has no comparator",
                col.name,
                i
            );
        }
    }

    #[test]
    fn sort_processes_by_name() {
        let mut procs = vec![
            ProcessBandwidth {
                process_name: "zoom".into(),
                pid: None,
                connection_count: 0,
                rx_rate: 0.0,
                tx_rate: 0.0,
                rx_bytes: 0,
                tx_bytes: 0,
            },
            ProcessBandwidth {
                process_name: "Apple".into(),
                pid: None,
                connection_count: 0,
                rx_rate: 0.0,
                tx_rate: 0.0,
                rx_bytes: 0,
                tx_bytes: 0,
            },
            ProcessBandwidth {
                process_name: "brave".into(),
                pid: None,
                connection_count: 0,
                rx_rate: 0.0,
                tx_rate: 0.0,
                rx_bytes: 0,
                tx_bytes: 0,
            },
        ];
        crate::ui::processes::sort(&mut procs, col(Tab::Processes, "Process"), true);
        let names: Vec<_> = procs.iter().map(|p| p.process_name.as_str()).collect();
        assert_eq!(names, vec!["Apple", "brave", "zoom"]);
    }

    #[test]
    fn sort_processes_by_total_rate_descending() {
        let mut procs = vec![
            ProcessBandwidth {
                process_name: "a".into(),
                pid: None,
                connection_count: 0,
                rx_rate: 100.0,
                tx_rate: 50.0,
                rx_bytes: 0,
                tx_bytes: 0,
            },
            ProcessBandwidth {
                process_name: "b".into(),
                pid: None,
                connection_count: 0,
                rx_rate: 500.0,
                tx_rate: 500.0,
                rx_bytes: 0,
                tx_bytes: 0,
            },
        ];
        crate::ui::processes::sort(&mut procs, col(Tab::Processes, "Total Rate"), false);
        let names: Vec<_> = procs.iter().map(|p| p.process_name.as_str()).collect();
        assert_eq!(names, vec!["b", "a"]);
    }

    // -- apply_direction --

    #[test]
    fn apply_direction_ascending_preserves_order() {
        use std::cmp::Ordering;
        assert_eq!(apply_direction(Ordering::Less, true), Ordering::Less);
        assert_eq!(apply_direction(Ordering::Greater, true), Ordering::Greater);
    }

    #[test]
    fn apply_direction_descending_reverses_order() {
        use std::cmp::Ordering;
        assert_eq!(apply_direction(Ordering::Less, false), Ordering::Greater);
        assert_eq!(apply_direction(Ordering::Greater, false), Ordering::Less);
        assert_eq!(apply_direction(Ordering::Equal, false), Ordering::Equal);
    }
}
