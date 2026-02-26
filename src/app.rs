use crate::collectors::config::ConfigCollector;
use crate::collectors::connections::{Connection, ConnectionCollector};
use crate::collectors::geo::GeoCache;
use crate::collectors::whois::WhoisCache;
use crate::collectors::health::HealthProber;
use crate::collectors::packets::PacketCollector;
use crate::collectors::traffic::TrafficCollector;
use crate::event::{AppEvent, EventHandler};
use crate::platform::{self, InterfaceInfo};
use crate::ui;
use anyhow::Result;
use crossterm::event::{KeyCode, KeyModifiers};
use std::collections::HashSet;
use ratatui::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirectionFilter {
    Both,
    AtoB,
    BtoA,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Connections,
    Interfaces,
    Packets,
    Stats,
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
    pub connection_scroll: usize,
    pub sort_column: usize,
    pub packet_scroll: usize,
    pub packet_selected: Option<u64>,
    pub packet_follow: bool,
    pub capture_interface: String,
    pub stream_view_open: bool,
    pub stream_view_index: Option<u32>,
    pub stream_scroll: usize,
    pub stream_direction_filter: StreamDirectionFilter,
    pub stream_hex_mode: bool,
    pub packet_filter_input: bool,
    pub packet_filter_text: String,
    pub packet_filter_active: Option<String>,
    pub export_status: Option<String>,
    export_status_tick: u32,
    pub bpf_filter_input: bool,
    pub bpf_filter_text: String,
    pub bpf_filter_active: Option<String>,
    pub stats_scroll: usize,
    pub show_help: bool,
    pub help_scroll: usize,
    pub geo_cache: GeoCache,
    pub show_geo: bool,
    pub whois_cache: WhoisCache,
    pub bookmarks: HashSet<u64>,
    info_tick: u32,
    conn_tick: u32,
    health_tick: u32,
}

impl App {
    fn new() -> Self {
        let interface_info = platform::collect_interface_info().unwrap_or_default();
        let mut config_collector = ConfigCollector::new();
        config_collector.update();

        // Pick the best default capture interface: first UP interface with an IPv4 address
        // that isn't loopback
        let capture_interface = Self::pick_capture_interface(&interface_info);

        Self {
            traffic: TrafficCollector::new(),
            interface_info,
            connection_collector: ConnectionCollector::new(),
            config_collector,
            health_prober: HealthProber::new(),
            packet_collector: PacketCollector::new(),
            selected_interface: None,
            paused: false,
            current_tab: Tab::Dashboard,
            connection_scroll: 0,
            sort_column: 0,
            packet_scroll: 0,
            packet_selected: None,
            packet_follow: true,
            capture_interface,
            stream_view_open: false,
            stream_view_index: None,
            stream_scroll: 0,
            stream_direction_filter: StreamDirectionFilter::Both,
            stream_hex_mode: false,
            packet_filter_input: false,
            packet_filter_text: String::new(),
            packet_filter_active: None,
            export_status: None,
            export_status_tick: 0,
            bpf_filter_input: false,
            bpf_filter_text: String::new(),
            bpf_filter_active: None,
            stats_scroll: 0,
            show_help: false,
            help_scroll: 0,
            geo_cache: GeoCache::new(),
            show_geo: true,
            whois_cache: WhoisCache::new(),
            bookmarks: HashSet::new(),
            info_tick: 0,
            conn_tick: 0,
            health_tick: 0,
        }
    }

    fn pick_capture_interface(info: &[InterfaceInfo]) -> String {
        // Prefer UP interfaces with an IPv4 address, skip loopback
        info.iter()
            .find(|i| i.is_up && i.ipv4.is_some() && i.name != "lo0" && i.name != "lo")
            .or_else(|| info.iter().find(|i| i.is_up && i.name != "lo0" && i.name != "lo"))
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

    fn tick(&mut self) {
        // Clear export status after 5 ticks
        if self.export_status.is_some() {
            self.export_status_tick += 1;
            if self.export_status_tick >= 5 {
                self.export_status = None;
                self.export_status_tick = 0;
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
        }

        // Refresh health every ~5 ticks (5s)
        self.health_tick += 1;
        if self.health_tick >= 5 {
            self.health_tick = 0;
            let gateway = self.config_collector.config.gateway.clone();
            let dns = self.config_collector.config.dns_servers.first().cloned();
            self.health_prober
                .probe(gateway.as_deref(), dns.as_deref());
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
        let ip = if ip == "*" { None } else { Some(ip.to_string()) };
        let port = if port == "*" { None } else { Some(port.to_string()) };
        (ip, port)
    } else {
        (Some(addr.to_string()), None)
    }
}

fn build_connection_filter(conn: &Connection) -> String {
    let (remote_ip, remote_port) = parse_addr_parts(&conn.remote_addr);

    let mut parts = Vec::new();

    let proto = conn.protocol.to_lowercase();
    if proto == "tcp" || proto == "udp" {
        parts.push(proto);
    }

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

pub async fn run<B: Backend>(terminal: &mut Terminal<B>) -> Result<()> {
    let mut app = App::new();
    let mut events = EventHandler::new(1000);

    // Initial data collection
    app.traffic.update();
    app.connection_collector.update();
    let gateway = app.config_collector.config.gateway.clone();
    let dns = app.config_collector.config.dns_servers.first().cloned();
    app.health_prober
        .probe(gateway.as_deref(), dns.as_deref());

    loop {
        terminal.draw(|f| {
            let area = f.size();
            match app.current_tab {
                Tab::Dashboard => ui::dashboard::render(f, &app, area),
                Tab::Connections => ui::connections::render(f, &app, area),
                Tab::Interfaces => ui::interfaces::render(f, &app, area),
                Tab::Packets => ui::packets::render(f, &app, area),
                Tab::Stats => ui::stats::render(f, &app, area),
            }
            if app.show_help {
                ui::help::render(f, &app, area);
            }
        })?;

        match events.next().await? {
            AppEvent::Key(key) => {
                // Help overlay — intercept keys first
                if app.show_help {
                    match key.code {
                        KeyCode::Char('?') | KeyCode::Esc => {
                            app.show_help = false;
                            app.help_scroll = 0;
                        }
                        KeyCode::Up => {
                            app.help_scroll = app.help_scroll.saturating_sub(1);
                        }
                        KeyCode::Down => {
                            app.help_scroll += 1;
                        }
                        KeyCode::Char('q') => {
                            app.packet_collector.stop_capture();
                            return Ok(());
                        }
                        _ => {}
                    }
                    continue;
                }
                // Filter input mode — capture all keys
                if app.packet_filter_input && app.current_tab == Tab::Packets {
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
                        KeyCode::Backspace => { app.packet_filter_text.pop(); }
                        KeyCode::Char(c) => { app.packet_filter_text.push(c); }
                        _ => {}
                    }
                    continue;
                }
                // BPF filter input mode — capture all keys
                if app.bpf_filter_input && app.current_tab == Tab::Packets {
                    match key.code {
                        KeyCode::Enter => {
                            app.bpf_filter_input = false;
                            if app.bpf_filter_text.trim().is_empty() {
                                app.bpf_filter_active = None;
                            } else {
                                app.bpf_filter_active = Some(app.bpf_filter_text.clone());
                            }
                        }
                        KeyCode::Esc => {
                            app.bpf_filter_input = false;
                            app.bpf_filter_text = app.bpf_filter_active.clone().unwrap_or_default();
                        }
                        KeyCode::Backspace => { app.bpf_filter_text.pop(); }
                        KeyCode::Char(c) => { app.bpf_filter_text.push(c); }
                        _ => {}
                    }
                    continue;
                }
                match key.code {
                KeyCode::Char('q') => {
                    app.packet_collector.stop_capture();
                    return Ok(());
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.packet_collector.stop_capture();
                    return Ok(());
                }
                KeyCode::Char('?') => {
                    app.show_help = !app.show_help;
                    app.help_scroll = 0;
                }
                KeyCode::Char('g') => app.show_geo = !app.show_geo,
                KeyCode::Char('p') => app.paused = !app.paused,
                KeyCode::Char('r') => {
                    app.traffic.update();
                    if let Ok(info) = platform::collect_interface_info() {
                        app.interface_info = info;
                    }
                    app.connection_collector.update();
                    app.config_collector.update();
                    let gateway = app.config_collector.config.gateway.clone();
                    let dns = app.config_collector.config.dns_servers.first().cloned();
                    app.health_prober
                        .probe(gateway.as_deref(), dns.as_deref());
                }
                KeyCode::Char('1') => app.current_tab = Tab::Dashboard,
                KeyCode::Char('2') => app.current_tab = Tab::Connections,
                KeyCode::Char('3') => app.current_tab = Tab::Interfaces,
                KeyCode::Char('4') => app.current_tab = Tab::Packets,
                KeyCode::Char('5') => app.current_tab = Tab::Stats,
                // Stream view controls (intercept before other Packets keys)
                KeyCode::Esc if app.current_tab == Tab::Packets && app.stream_view_open => {
                    app.stream_view_open = false;
                    app.stream_view_index = None;
                    app.stream_scroll = 0;
                }
                KeyCode::Char('h') if app.current_tab == Tab::Packets && app.stream_view_open => {
                    app.stream_hex_mode = !app.stream_hex_mode;
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
                KeyCode::Up if app.current_tab == Tab::Packets && app.stream_view_open => {
                    app.stream_scroll = app.stream_scroll.saturating_sub(1);
                }
                KeyCode::Down if app.current_tab == Tab::Packets && app.stream_view_open => {
                    app.stream_scroll += 1;
                }
                KeyCode::Char('s') if app.current_tab == Tab::Packets && !app.stream_view_open => {
                    if let Some(sel_id) = app.packet_selected {
                        let packets = app.packet_collector.get_packets();
                        if let Some(pkt) = packets.iter().find(|p| p.id == sel_id) {
                            if pkt.stream_index.is_some() {
                                app.stream_view_open = true;
                                app.stream_view_index = pkt.stream_index;
                                app.stream_scroll = 0;
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
                KeyCode::Char('b') if app.current_tab == Tab::Packets && !app.packet_collector.is_capturing() && !app.stream_view_open => {
                    app.bpf_filter_input = true;
                    app.bpf_filter_text = app.bpf_filter_active.clone().unwrap_or_default();
                }
                KeyCode::Char('i') if app.current_tab == Tab::Packets => {
                    if !app.packet_collector.is_capturing() {
                        app.cycle_capture_interface();
                    }
                }
                KeyCode::Char('x') if app.current_tab == Tab::Packets => {
                    app.packet_collector.clear();
                    app.packet_scroll = 0;
                    app.packet_selected = None;
                    app.bookmarks.clear();
                }
                KeyCode::Char('m') if app.current_tab == Tab::Packets && !app.stream_view_open => {
                    if let Some(sel_id) = app.packet_selected {
                        if !app.bookmarks.remove(&sel_id) {
                            app.bookmarks.insert(sel_id);
                        }
                    }
                }
                KeyCode::Char('n') if app.current_tab == Tab::Packets && !app.stream_view_open => {
                    // Jump to next bookmark after current selection
                    let packets = app.packet_collector.get_packets();
                    let current_id = app.packet_selected.unwrap_or(0);
                    if let Some((idx, pkt)) = packets.iter().enumerate()
                        .find(|(_, p)| p.id > current_id && app.bookmarks.contains(&p.id))
                    {
                        app.packet_selected = Some(pkt.id);
                        app.packet_scroll = idx;
                        app.packet_follow = false;
                    }
                }
                KeyCode::Char('N') if app.current_tab == Tab::Packets && !app.stream_view_open => {
                    // Jump to previous bookmark before current selection
                    let packets = app.packet_collector.get_packets();
                    let current_id = app.packet_selected.unwrap_or(u64::MAX);
                    if let Some((idx, pkt)) = packets.iter().enumerate().rev()
                        .find(|(_, p)| p.id < current_id && app.bookmarks.contains(&p.id))
                    {
                        app.packet_selected = Some(pkt.id);
                        app.packet_scroll = idx;
                        app.packet_follow = false;
                    }
                }
                KeyCode::Char('f') if app.current_tab == Tab::Packets => {
                    app.packet_follow = !app.packet_follow;
                }
                KeyCode::Char('w') if app.current_tab == Tab::Packets => {
                    use crate::collectors::packets::{export_pcap, parse_filter, matches_packet};
                    let packets = app.packet_collector.get_packets();
                    let filtered: Vec<_>;
                    let to_export: &[_] = if let Some(ref ft) = app.packet_filter_active {
                        if let Some(expr) = parse_filter(ft) {
                            filtered = packets.iter().filter(|p| matches_packet(&expr, p)).cloned().collect();
                            &filtered
                        } else {
                            &*packets
                        }
                    } else {
                        &*packets
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
                    // Trigger whois lookup for selected packet's IPs
                    if let Some(sel_id) = app.packet_selected {
                        let packets = app.packet_collector.get_packets();
                        if let Some(pkt) = packets.iter().find(|p| p.id == sel_id) {
                            app.whois_cache.request(&pkt.src_ip);
                            app.whois_cache.request(&pkt.dst_ip);
                        }
                    }
                }
                KeyCode::Char('W') if app.current_tab == Tab::Connections => {
                    // Trigger whois lookup for selected connection's remote IP
                    let mut conns = app.connection_collector.connections.lock().unwrap().clone();
                    match app.sort_column {
                        0 => conns.sort_by(|a, b| a.process_name.as_deref().unwrap_or("").cmp(b.process_name.as_deref().unwrap_or(""))),
                        1 => conns.sort_by(|a, b| a.pid.cmp(&b.pid)),
                        2 => conns.sort_by(|a, b| a.protocol.cmp(&b.protocol)),
                        3 => conns.sort_by(|a, b| a.state.cmp(&b.state)),
                        4 => conns.sort_by(|a, b| a.local_addr.cmp(&b.local_addr)),
                        5 => conns.sort_by(|a, b| a.remote_addr.cmp(&b.remote_addr)),
                        _ => {}
                    }
                    if let Some(conn) = conns.get(app.connection_scroll) {
                        let (remote_ip, _) = parse_addr_parts(&conn.remote_addr);
                        if let Some(ip) = remote_ip {
                            app.whois_cache.request(&ip);
                        }
                    }
                }
                KeyCode::Char('s') => {
                    if app.current_tab == Tab::Connections {
                        app.sort_column = (app.sort_column + 1) % 6;
                    }
                }
                KeyCode::Enter if app.current_tab == Tab::Connections => {
                    let mut conns = app.connection_collector.connections.lock().unwrap().clone();
                    match app.sort_column {
                        0 => conns.sort_by(|a, b| a.process_name.as_deref().unwrap_or("").cmp(b.process_name.as_deref().unwrap_or(""))),
                        1 => conns.sort_by(|a, b| a.pid.cmp(&b.pid)),
                        2 => conns.sort_by(|a, b| a.protocol.cmp(&b.protocol)),
                        3 => conns.sort_by(|a, b| a.state.cmp(&b.state)),
                        4 => conns.sort_by(|a, b| a.local_addr.cmp(&b.local_addr)),
                        5 => conns.sort_by(|a, b| a.remote_addr.cmp(&b.remote_addr)),
                        _ => {}
                    }
                    if let Some(conn) = conns.get(app.connection_scroll) {
                        let filter = build_connection_filter(conn);
                        app.packet_filter_text = filter.clone();
                        app.packet_filter_active = Some(filter);
                        app.packet_filter_input = false;
                        app.packet_scroll = 0;
                        app.packet_follow = false;
                        app.current_tab = Tab::Packets;
                    }
                }
                KeyCode::Enter if app.current_tab == Tab::Packets => {
                    let packets = app.packet_collector.get_packets();
                    if !packets.is_empty() {
                        let visible_height = 20usize; // approximate
                        let total = packets.len();
                        let offset = if app.packet_follow && total > visible_height {
                            total - visible_height
                        } else {
                            app.packet_scroll.min(total.saturating_sub(visible_height))
                        };
                        // Select the packet at current scroll position
                        if let Some(pkt) = packets.get(offset) {
                            app.packet_selected = Some(pkt.id);
                        }
                    }
                }
                KeyCode::Up => match app.current_tab {
                    Tab::Connections => {
                        app.connection_scroll = app.connection_scroll.saturating_sub(1);
                    }
                    Tab::Packets => {
                        app.packet_follow = false;
                        app.packet_scroll = app.packet_scroll.saturating_sub(1);
                        // Update selection to follow cursor
                        let packets = app.packet_collector.get_packets();
                        if let Some(pkt) = packets.get(app.packet_scroll) {
                            app.packet_selected = Some(pkt.id);
                        }
                    }
                    Tab::Stats => {
                        app.stats_scroll = app.stats_scroll.saturating_sub(1);
                    }
                    _ => {
                        app.selected_interface = match app.selected_interface {
                            Some(0) | None => None,
                            Some(i) => Some(i - 1),
                        };
                    }
                },
                KeyCode::Down => match app.current_tab {
                    Tab::Connections => {
                        let max = app
                            .connection_collector
                            .connections
                            .lock()
                            .unwrap()
                            .len()
                            .saturating_sub(1);
                        if app.connection_scroll < max {
                            app.connection_scroll += 1;
                        }
                    }
                    Tab::Packets => {
                        app.packet_follow = false;
                        let packets = app.packet_collector.get_packets();
                        let max = packets.len().saturating_sub(1);
                        if app.packet_scroll < max {
                            app.packet_scroll += 1;
                        }
                        if let Some(pkt) = packets.get(app.packet_scroll) {
                            app.packet_selected = Some(pkt.id);
                        }
                    }
                    Tab::Stats => {
                        app.stats_scroll += 1;
                    }
                    _ => {
                        let max = app.traffic.interfaces.len().saturating_sub(1);
                        app.selected_interface = match app.selected_interface {
                            None => Some(0),
                            Some(i) if i < max => Some(i + 1),
                            other => other,
                        };
                    }
                },
                KeyCode::Char('/') if app.current_tab == Tab::Packets && !app.stream_view_open => {
                    app.packet_filter_input = true;
                    app.packet_filter_text = app.packet_filter_active.clone().unwrap_or_default();
                }
                KeyCode::Esc if app.current_tab == Tab::Packets && !app.stream_view_open && app.packet_filter_active.is_some() => {
                    app.packet_filter_active = None;
                    app.packet_filter_text.clear();
                }
                _ => {}
            }
            },
            AppEvent::Tick => {
                app.tick();
            }
        }
    }
}
