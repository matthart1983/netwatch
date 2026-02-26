use crate::collectors::config::ConfigCollector;
use crate::collectors::connections::ConnectionCollector;
use crate::collectors::health::HealthProber;
use crate::collectors::packets::PacketCollector;
use crate::collectors::traffic::TrafficCollector;
use crate::event::{AppEvent, EventHandler};
use crate::platform::{self, InterfaceInfo};
use crate::ui;
use anyhow::Result;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Connections,
    Interfaces,
    Packets,
}

pub struct App {
    pub traffic: TrafficCollector,
    pub interface_info: Vec<InterfaceInfo>,
    pub connection_collector: ConnectionCollector,
    pub config_collector: ConfigCollector,
    pub health_prober: HealthProber,
    pub packet_collector: PacketCollector,
    pub selected_interface: usize,
    pub paused: bool,
    pub current_tab: Tab,
    pub connection_scroll: usize,
    pub sort_column: usize,
    pub packet_scroll: usize,
    pub packet_selected: Option<u64>,
    pub packet_follow: bool,
    pub capture_interface: String,
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
            selected_interface: 0,
            paused: false,
            current_tab: Tab::Dashboard,
            connection_scroll: 0,
            sort_column: 0,
            packet_scroll: 0,
            packet_selected: None,
            packet_follow: true,
            capture_interface,
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
            }
        })?;

        match events.next().await? {
            AppEvent::Key(key) => match key.code {
                KeyCode::Char('q') => {
                    app.packet_collector.stop_capture();
                    return Ok(());
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.packet_collector.stop_capture();
                    return Ok(());
                }
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
                KeyCode::Char('c') if app.current_tab == Tab::Packets => {
                    if app.packet_collector.is_capturing() {
                        app.packet_collector.stop_capture();
                    } else {
                        let iface = app.capture_interface.clone();
                        app.packet_collector.start_capture(&iface);
                    }
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
                }
                KeyCode::Char('f') if app.current_tab == Tab::Packets => {
                    app.packet_follow = !app.packet_follow;
                }
                KeyCode::Char('s') => {
                    if app.current_tab == Tab::Connections {
                        app.sort_column = (app.sort_column + 1) % 6;
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
                    _ => {
                        if app.selected_interface > 0 {
                            app.selected_interface -= 1;
                        }
                    }
                },
                KeyCode::Down => match app.current_tab {
                    Tab::Connections => {
                        let max = app
                            .connection_collector
                            .connections
                            .len()
                            .saturating_sub(1);
                        if app.connection_scroll < max {
                            app.connection_scroll += 1;
                        }
                    }
                    Tab::Packets => {
                        app.packet_follow = false;
                        let max = app
                            .packet_collector
                            .get_packets()
                            .len()
                            .saturating_sub(1);
                        if app.packet_scroll < max {
                            app.packet_scroll += 1;
                        }
                        let packets = app.packet_collector.get_packets();
                        if let Some(pkt) = packets.get(app.packet_scroll) {
                            app.packet_selected = Some(pkt.id);
                        }
                    }
                    _ => {
                        if app.selected_interface + 1 < app.traffic.interfaces.len() {
                            app.selected_interface += 1;
                        }
                    }
                },
                _ => {}
            },
            AppEvent::Tick => {
                app.tick();
            }
        }
    }
}
