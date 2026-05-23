use crate::app::{sort_columns_for_tab, App, InterfaceFilter, Tab};
use crate::collectors::traffic::InterfaceTraffic;
use crate::sort::{
    apply_direction, cmp_case_insensitive, cmp_f64, cmp_ip, SortColumn, TabSortState,
};
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph},
};

pub const COLUMNS: &[SortColumn] = &[
    SortColumn { name: "Iface" },
    SortColumn { name: "IP" },
    SortColumn { name: "Role" },
    SortColumn { name: "RX/s" },
    SortColumn { name: "TX/s" },
    SortColumn { name: "RX Total" },
    SortColumn { name: "TX Total" },
];

pub const DEFAULT_SORT: TabSortState = TabSortState {
    column: 3, // RX/s desc by default
    ascending: false,
};

pub fn sort_interfaces(
    interfaces: &mut [InterfaceTraffic],
    tab: Tab,
    column: usize,
    ascending: bool,
    interface_info: &[crate::platform::InterfaceInfo],
) {
    let cols = sort_columns_for_tab(tab);
    let col_name = cols.get(column).map(|c| c.name).unwrap_or("");

    interfaces.sort_by(|a, b| {
        let info_a = interface_info.iter().find(|i| i.name == a.name);
        let info_b = interface_info.iter().find(|i| i.name == b.name);
        let ord = match col_name {
            "Interface" | "Name" | "Iface" => cmp_case_insensitive(&a.name, &b.name),
            "IP Address" | "IPv4" | "IP" => {
                let ip_a = info_a.and_then(|i| i.ipv4.as_deref()).unwrap_or("");
                let ip_b = info_b.and_then(|i| i.ipv4.as_deref()).unwrap_or("");
                cmp_ip(ip_a, ip_b)
            }
            "Role" => cmp_case_insensitive(
                role_for_iface(&a.name, interface_info),
                role_for_iface(&b.name, interface_info),
            ),
            "RX/s" | "Rx Rate" | "RX B/s" => cmp_f64(a.rx_rate, b.rx_rate),
            "TX/s" | "Tx Rate" | "TX B/s" => cmp_f64(a.tx_rate, b.tx_rate),
            "RX Total" | "Rx Total" => a.rx_bytes_total.cmp(&b.rx_bytes_total),
            "TX Total" | "Tx Total" => a.tx_bytes_total.cmp(&b.tx_bytes_total),
            _ => std::cmp::Ordering::Equal,
        };
        apply_direction(ord, ascending)
    });
}

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header
            Constraint::Length(2),  // chip row
            Constraint::Min(8),     // table
            Constraint::Length(13), // detail panel
            Constraint::Length(3),  // footer
        ])
        .split(area);

    widgets::render_header(f, app, chunks[0]);
    render_chip_row(f, app, chunks[1]);

    // Interfaces tab needs to filter+sort, so we materialize a mutable copy
    // here. Once per render of the Interfaces tab is the budget; the Arc on
    // the read path keeps the other 99% of callers cheap.
    let mut filtered: Vec<InterfaceTraffic> = (*app.traffic.interfaces()).clone();
    apply_filter(&mut filtered, app);
    if let Some(state) = app.ui.sort_states.get(&Tab::Interfaces) {
        sort_interfaces(
            &mut filtered,
            Tab::Interfaces,
            state.column,
            state.ascending,
            &app.interface_info,
        );
    }

    render_interfaces_table(f, app, &filtered, chunks[2]);
    render_detail_panel(f, app, &filtered, chunks[3]);
    render_footer(f, app, chunks[4]);
}

fn apply_filter(interfaces: &mut Vec<InterfaceTraffic>, app: &App) {
    interfaces.retain(|i| {
        let info = app.interface_info.iter().find(|info| info.name == i.name);
        let is_up = info.map(|inf| inf.is_up).unwrap_or(false);
        let has_traffic = crate::ui::widgets::interface_recently_active(i);
        let role = role_for(&i.name, info.and_then(|inf| inf.is_wireless));
        match app.ui.interface_filter {
            InterfaceFilter::Active => is_up && has_traffic,
            InterfaceFilter::All => true,
            // `ethernet/wifi` is the unknown-platform fallback — include it so
            // the Wi-Fi chip still works when detection isn't available.
            InterfaceFilter::Wifi => role == "wifi" || role == "ethernet/wifi",
            InterfaceFilter::Vpn => role == "vpn",
            InterfaceFilter::Idle => !has_traffic,
        }
    });
}

fn render_chip_row(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let interfaces = app.traffic.interfaces();

    let counts = chip_counts(&interfaces, app);
    let chips: [(InterfaceFilter, usize); 5] = [
        (InterfaceFilter::Active, counts.active),
        (InterfaceFilter::All, counts.all),
        (InterfaceFilter::Wifi, counts.wifi),
        (InterfaceFilter::Vpn, counts.vpn),
        (InterfaceFilter::Idle, counts.idle),
    ];

    let mut spans: Vec<Span> = vec![Span::styled(" show  ", Style::default().fg(t.text_muted))];

    for (filter, count) in chips.iter() {
        let label = match filter {
            InterfaceFilter::Wifi | InterfaceFilter::Vpn => filter.label().to_string(),
            _ => format!("{} {}", filter.label(), count),
        };
        let active = *filter == app.ui.interface_filter;
        if active {
            spans.push(Span::styled(
                format!(" {} ", label),
                Style::default()
                    .fg(t.text_primary)
                    .bg(t.selection_bg)
                    .bold(),
            ));
        } else {
            spans.push(Span::styled(
                format!(" {} ", label),
                Style::default().fg(t.text_secondary),
            ));
        }
        spans.push(Span::raw(" "));
    }

    spans.push(Span::raw("  "));
    spans.push(Span::styled("f cycles", Style::default().fg(t.text_muted)));

    let row1 = Line::from(spans);
    let row2 = Line::from(vec![Span::raw("")]);

    f.render_widget(Paragraph::new(vec![row1, row2]), area);
}

struct ChipCounts {
    active: usize,
    all: usize,
    wifi: usize,
    vpn: usize,
    idle: usize,
}

fn chip_counts(interfaces: &[InterfaceTraffic], app: &App) -> ChipCounts {
    let mut counts = ChipCounts {
        active: 0,
        all: interfaces.len(),
        wifi: 0,
        vpn: 0,
        idle: 0,
    };
    for i in interfaces {
        let info = app.interface_info.iter().find(|info| info.name == i.name);
        let is_up = info.map(|inf| inf.is_up).unwrap_or(false);
        let has_traffic = crate::ui::widgets::interface_recently_active(i);
        let role = role_for(&i.name, info.and_then(|inf| inf.is_wireless));
        if is_up && has_traffic {
            counts.active += 1;
        }
        if role == "wifi" || role == "ethernet/wifi" {
            counts.wifi += 1;
        }
        if role == "vpn" {
            counts.vpn += 1;
        }
        if !has_traffic {
            counts.idle += 1;
        }
    }
    counts
}

fn render_interfaces_table(f: &mut Frame, app: &App, interfaces: &[InterfaceTraffic], area: Rect) {
    let t = &app.theme;

    let counts = chip_counts(&app.traffic.interfaces(), app);
    let title_right = format!(" {} active  {} idle  0 down ", counts.active, counts.idle);
    let block = Block::default()
        .title(Line::from(Span::styled(
            " INTERFACES ",
            Style::default().fg(t.brand).bold(),
        )))
        .title(
            Line::from(Span::styled(title_right, Style::default().fg(t.text_muted)))
                .alignment(Alignment::Right),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.border));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 2 {
        return;
    }

    // Column header
    let header_line = build_header_line(app);
    let header_area = Rect {
        x: inner.x + 1,
        y: inner.y,
        width: inner.width.saturating_sub(2),
        height: 1,
    };
    f.render_widget(Paragraph::new(header_line), header_area);

    let max_rows = inner.height.saturating_sub(1) as usize;
    for (i, iface) in interfaces.iter().take(max_rows).enumerate() {
        render_interface_row(f, app, inner, i, iface);
    }

    if interfaces.is_empty() {
        let empty_area = Rect {
            x: inner.x + 2,
            y: inner.y + 1,
            width: inner.width.saturating_sub(2),
            height: 1,
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  No interfaces match this filter (press f to cycle)",
                Style::default().fg(t.text_muted),
            ))),
            empty_area,
        );
    }
}

fn build_header_line(app: &App) -> Line<'static> {
    let t = &app.theme;
    let header_text = "  IFACE     IP                  ROLE        RX/s        TX/s      RX TOTAL    TX TOTAL    TRAFFIC  60s";
    Line::from(Span::styled(
        header_text.to_string(),
        Style::default().fg(t.text_muted),
    ))
}

fn render_interface_row(f: &mut Frame, app: &App, inner: Rect, i: usize, iface: &InterfaceTraffic) {
    let t = &app.theme;
    let info = app.interface_info.iter().find(|inf| inf.name == iface.name);
    let ip = info
        .and_then(|inf| inf.ipv4.clone())
        .unwrap_or_else(|| "—".into());
    let is_up = info.map(|inf| inf.is_up).unwrap_or(false);
    let has_traffic = crate::ui::widgets::interface_recently_active(iface);
    let active = is_up && has_traffic;
    let dot_color = if active {
        t.status_good
    } else if is_up {
        t.text_muted
    } else {
        t.status_error
    };
    let main_color = if active { t.text_primary } else { t.text_muted };

    let row_y = inner.y + 1 + i as u16;
    let selected = app.ui.selected_interface == Some(i);

    let row_area = Rect {
        x: inner.x + 1,
        y: row_y,
        width: inner.width.saturating_sub(2),
        height: 1,
    };

    let line = Line::from(vec![
        Span::styled(
            if selected { "▸ " } else { "● " },
            Style::default().fg(if selected { t.brand } else { dot_color }),
        ),
        Span::styled(
            format!("{:<9}", iface.name),
            Style::default().fg(main_color),
        ),
        Span::styled(format!(" {:<19}", ip), Style::default().fg(main_color)),
        Span::styled(
            format!(
                " {:<11}",
                role_for(&iface.name, info.and_then(|inf| inf.is_wireless))
            ),
            Style::default().fg(if active { t.brand } else { t.text_muted }),
        ),
        Span::styled(
            format!(" {:>10}", widgets::format_bytes_rate(iface.rx_rate)),
            Style::default().fg(if active { t.rx_rate } else { t.text_muted }),
        ),
        Span::raw(" "),
        Span::styled(
            format!(" {:>9}", widgets::format_bytes_rate(iface.tx_rate)),
            Style::default().fg(if active { t.tx_rate } else { t.text_muted }),
        ),
        Span::raw(" "),
        Span::styled(
            format!(" {:>7}", widgets::format_bytes_total(iface.rx_bytes_total)),
            Style::default().fg(main_color),
        ),
        Span::raw(" "),
        Span::styled(
            format!(" {:>7}", widgets::format_bytes_total(iface.tx_bytes_total)),
            Style::default().fg(main_color),
        ),
        Span::raw("  "),
    ]);

    let para = if selected {
        Paragraph::new(line).style(Style::default().bg(t.selection_bg))
    } else {
        Paragraph::new(line)
    };
    f.render_widget(para, row_area);

    // Sparkline at end of row, only for active
    if active && row_area.width > 90 {
        let spark_x = row_area.x + 90;
        let spark_w = row_area.width.saturating_sub(91);
        if spark_w > 4 {
            let spark_area = Rect {
                x: spark_x,
                y: row_y,
                width: spark_w,
                height: 1,
            };
            let history: Vec<u64> = iface.rx_history.iter().copied().collect();
            let padded = pad_history(&history, spark_w as usize);
            crate::graph::render(
                f,
                spark_area,
                &padded,
                app.graph_style,
                t.rx_rate,
                t.status_warn,
                app.graph_opts(),
            );
        }
    }
}

fn render_detail_panel(f: &mut Frame, app: &App, interfaces: &[InterfaceTraffic], area: Rect) {
    let t = &app.theme;
    let selected = app
        .ui
        .selected_interface
        .and_then(|i| interfaces.get(i))
        .or_else(|| interfaces.first());

    let title_left = match selected {
        Some(iface) => format!(" {}  DETAIL ", iface.name),
        None => " DETAIL ".to_string(),
    };
    let mtu = selected
        .and_then(|i| {
            app.interface_info
                .iter()
                .find(|inf| inf.name == i.name)
                .and_then(|inf| inf.mtu)
        })
        .map(|m| format!("MTU {}", m))
        .unwrap_or_default();
    let role = selected
        .map(|i| role_for_iface(&i.name, &app.interface_info))
        .unwrap_or("");
    let title_right = if !role.is_empty() || !mtu.is_empty() {
        format!(" {}  {}   ↑↓ to switch ", role, mtu)
    } else {
        " ↑↓ to switch ".to_string()
    };

    let block = Block::default()
        .title(Line::from(Span::styled(
            title_left,
            Style::default().fg(t.status_warn).bold(),
        )))
        .title(
            Line::from(Span::styled(title_right, Style::default().fg(t.text_muted)))
                .alignment(Alignment::Right),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.border));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 4 {
        return;
    }

    let Some(iface) = selected else {
        let hint_area = Rect {
            x: inner.x + 2,
            y: inner.y + 1,
            width: inner.width.saturating_sub(2),
            height: 1,
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "↑↓ to select an interface",
                Style::default().fg(t.text_muted),
            ))),
            hint_area,
        );
        return;
    };

    let info = app.interface_info.iter().find(|i| i.name == iface.name);

    // Split detail panel: left meta column (~48 cells) + right chart
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(48), Constraint::Min(0)])
        .split(inner);

    render_detail_meta(f, app, cols[0], iface, info);
    render_detail_chart(f, app, cols[1], iface);
}

fn render_detail_meta(
    f: &mut Frame,
    app: &App,
    area: Rect,
    _iface: &InterfaceTraffic,
    info: Option<&crate::platform::InterfaceInfo>,
) {
    let t = &app.theme;

    let mac = info
        .and_then(|i| i.mac.clone())
        .unwrap_or_else(|| "—".into());
    let gateway = app
        .config_collector
        .config
        .gateway
        .clone()
        .unwrap_or_else(|| "—".into());
    let dns = app.config_collector.config.dns_servers.join(", ");
    let dns = if dns.is_empty() {
        "—".to_string()
    } else {
        dns
    };
    // Snapshot the interfaces once and reuse for both lookups to avoid two
    // refcount bumps + two lookups when one of each suffices.
    let traffic_snapshot = app.traffic.interfaces();
    let errors: u64 = info
        .map(|inf| inf.name.as_str())
        .and_then(|n| {
            traffic_snapshot
                .iter()
                .find(|i| i.name == n)
                .map(|i| i.rx_errors + i.tx_errors)
        })
        .unwrap_or(0);
    let drops: u64 = info
        .map(|inf| inf.name.as_str())
        .and_then(|n| {
            traffic_snapshot
                .iter()
                .find(|i| i.name == n)
                .map(|i| i.rx_drops + i.tx_drops)
        })
        .unwrap_or(0);

    let label_w = 12usize;
    let rows: Vec<(&str, String, Color)> = vec![
        ("SSID", "—".to_string(), t.text_muted),
        ("link rate", "—".to_string(), t.text_muted),
        ("MAC", mac, t.text_primary),
        ("gateway", gateway, t.text_primary),
        ("DNS", dns, t.text_primary),
        (
            "errors",
            errors.to_string(),
            if errors == 0 {
                t.status_good
            } else {
                t.status_warn
            },
        ),
        (
            "drops",
            drops.to_string(),
            if drops == 0 {
                t.status_good
            } else {
                t.status_warn
            },
        ),
        ("collisions", "0".to_string(), t.status_good),
        ("uptime", "—".to_string(), t.text_muted),
    ];

    let lines: Vec<Line> = rows
        .into_iter()
        .map(|(label, val, val_color)| {
            Line::from(vec![
                Span::styled(
                    format!(" {:<width$}", label, width = label_w),
                    Style::default().fg(t.text_muted),
                ),
                Span::styled(val, Style::default().fg(val_color)),
            ])
        })
        .collect();

    f.render_widget(Paragraph::new(lines), area);
}

fn render_detail_chart(f: &mut Frame, app: &App, area: Rect, iface: &InterfaceTraffic) {
    let t = &app.theme;
    if area.height < 4 {
        return;
    }

    // Header line: ● RX rate    ● TX rate    peak/avg
    let rx_hist: Vec<u64> = iface.rx_history.iter().copied().collect();
    let tx_hist: Vec<u64> = iface.tx_history.iter().copied().collect();
    let peak_rx = *rx_hist.iter().max().unwrap_or(&0);
    let _peak_tx = *tx_hist.iter().max().unwrap_or(&0);
    let avg_rx = if !rx_hist.is_empty() {
        rx_hist.iter().sum::<u64>() / rx_hist.len() as u64
    } else {
        0
    };

    let header_area = Rect {
        x: area.x + 1,
        y: area.y,
        width: area.width.saturating_sub(2),
        height: 1,
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("● RX ", Style::default().fg(t.rx_rate)),
            Span::styled(
                widgets::format_bytes_rate(iface.rx_rate),
                Style::default().fg(t.rx_rate).bold(),
            ),
            Span::raw("    "),
            Span::styled("● TX ", Style::default().fg(t.tx_rate)),
            Span::styled(
                widgets::format_bytes_rate(iface.tx_rate),
                Style::default().fg(t.tx_rate).bold(),
            ),
            Span::raw("    "),
            Span::styled(
                format!(
                    "peak {}  avg {}",
                    widgets::format_bytes_rate(peak_rx as f64),
                    widgets::format_bytes_rate(avg_rx as f64),
                ),
                Style::default().fg(t.text_muted),
            ),
        ])),
        header_area,
    );

    let chart_h = area.height.saturating_sub(2);
    if chart_h < 2 {
        return;
    }
    let rx_h = chart_h / 2;
    let tx_h = chart_h - rx_h;
    let chart_w = area.width.saturating_sub(2);

    let rx_area = Rect {
        x: area.x + 1,
        y: area.y + 1,
        width: chart_w,
        height: rx_h,
    };
    let tx_area = Rect {
        x: area.x + 1,
        y: area.y + 1 + rx_h,
        width: chart_w,
        height: tx_h,
    };

    let rx_padded = pad_history(&rx_hist, chart_w as usize);
    crate::graph::render(
        f,
        rx_area,
        &rx_padded,
        app.graph_style,
        t.rx_rate,
        t.status_warn,
        app.graph_opts(),
    );

    let tx_padded = pad_history(&tx_hist, chart_w as usize);
    crate::graph::render(
        f,
        tx_area,
        &tx_padded,
        app.graph_style,
        t.tx_rate,
        t.status_warn,
        app.graph_opts(),
    );

    // x-axis line
    let axis_y = area.y + area.height - 1;
    let axis_area = Rect {
        x: area.x + 1,
        y: axis_y,
        width: chart_w,
        height: 1,
    };
    let axis_w = chart_w as usize;
    let mut axis = String::from("-60s");
    let mid_pad = axis_w.saturating_sub(11) / 2;
    axis.push_str(&" ".repeat(mid_pad));
    axis.push_str("-30s");
    let used = axis.chars().count();
    let end_pad = axis_w.saturating_sub(used + 3);
    axis.push_str(&" ".repeat(end_pad));
    axis.push_str("now");
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            axis,
            Style::default().fg(t.text_muted),
        ))),
        axis_area,
    );
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let hints = vec![
        Span::styled("f", Style::default().fg(app.theme.key_hint).bold()),
        Span::raw(":Filter  "),
        Span::styled("s", Style::default().fg(app.theme.key_hint).bold()),
        Span::raw(":Sort  "),
        Span::styled("a", Style::default().fg(app.theme.key_hint).bold()),
        Span::raw(":Analyze"),
    ];
    widgets::render_footer(f, app, area, hints);
}

// ── helpers ─────────────────────────────────────────────────

/// Classify an interface for display. Special-purpose interfaces are
/// recognized by name (loopback, VPN tunnels, bridges, Apple-specific virtual
/// links); for physical adapters we consult the OS-provided wireless flag
/// rather than guessing from the name prefix. macOS in particular hands out
/// `en*` to both Wi-Fi and USB-Ethernet adapters, so name alone is wrong.
///
/// `is_wireless == None` means the platform layer couldn't tell — we fall
/// back to the hedged `ethernet/wifi` label for `en*`/`wlan*` names so
/// behaviour matches the pre-detection world for unsupported platforms.
pub fn role_for(name: &str, is_wireless: Option<bool>) -> &'static str {
    if name == "lo0" || name == "lo" {
        return "loopback";
    }
    if name.starts_with("utun") || name.starts_with("tun") || name.starts_with("wg") {
        return "vpn";
    }
    if name.starts_with("anpi") {
        return "apple";
    }
    if name.starts_with("ap") {
        return "ap";
    }
    if name.starts_with("bridge") {
        return "bridge";
    }
    if name.starts_with("awdl") {
        return "awdl";
    }
    if name.starts_with("llw") {
        return "llw";
    }
    match is_wireless {
        Some(true) => "wifi",
        Some(false) => "ethernet",
        None => {
            if name.starts_with("en") || name.starts_with("wlan") || name.starts_with("wlp") {
                "ethernet/wifi"
            } else {
                "—"
            }
        }
    }
}

/// Convenience: look up the role from `interface_info` by name. Returns the
/// `None`-fallback role when the interface isn't in the slice.
pub fn role_for_iface(
    name: &str,
    interface_info: &[crate::platform::InterfaceInfo],
) -> &'static str {
    let is_wireless = interface_info
        .iter()
        .find(|i| i.name == name)
        .and_then(|i| i.is_wireless);
    role_for(name, is_wireless)
}

fn pad_history(data: &[u64], target_width: usize) -> Vec<u64> {
    if target_width == 0 {
        return Vec::new();
    }
    if data.len() >= target_width {
        return data[data.len() - target_width..].to_vec();
    }
    let mut padded = vec![0u64; target_width - data.len()];
    padded.extend_from_slice(data);
    padded
}

#[cfg(test)]
mod tests {
    use super::role_for;

    #[test]
    fn role_for_uses_wireless_flag_over_name_prefix() {
        // The bug from issue #30: USB-Ethernet adapters land on `en*` names
        // but are wired. With the OS-provided flag we now classify correctly.
        assert_eq!(role_for("en0", Some(true)), "wifi");
        assert_eq!(role_for("en7", Some(false)), "ethernet");
        assert_eq!(role_for("wlan0", Some(true)), "wifi");
    }

    #[test]
    fn role_for_special_names_ignore_wireless_flag() {
        // Loopback / VPN / bridge classification is name-driven; even if a
        // platform mislabels them, we shouldn't promote them to wifi/ethernet.
        assert_eq!(role_for("lo0", Some(true)), "loopback");
        assert_eq!(role_for("utun3", Some(false)), "vpn");
        assert_eq!(role_for("bridge0", Some(false)), "bridge");
        assert_eq!(role_for("awdl0", None), "awdl");
        assert_eq!(role_for("anpi0", None), "apple");
    }

    #[test]
    fn role_for_unknown_wireless_falls_back_to_hedge() {
        // When the platform can't tell us, keep the pre-detection behavior so
        // the Wi-Fi filter chip still matches `en*`/`wlan*` adapters.
        assert_eq!(role_for("en0", None), "ethernet/wifi");
        assert_eq!(role_for("wlan0", None), "ethernet/wifi");
        assert_eq!(role_for("somethingelse", None), "—");
    }
}
