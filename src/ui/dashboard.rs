use crate::app::App;
use crate::ebpf::EbpfStatus;
use crate::sort::{SortColumn, TabSortState};
use crate::theme::Theme;
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table},
};

pub const COLUMNS: &[SortColumn] = &[
    SortColumn { name: "Interface" },
    SortColumn { name: "IP Address" },
    SortColumn { name: "Rx Rate" },
    SortColumn { name: "Tx Rate" },
    SortColumn { name: "Rx Total" },
    SortColumn { name: "Tx Total" },
    SortColumn { name: "Status" },
];

pub const DEFAULT_SORT: TabSortState = TabSortState {
    column: 0,
    ascending: true,
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chart_height = if app.selected_interface.is_some() {
        5
    } else {
        10
    };
    let alert_count = app.network_intel.active_alert_count();
    let alert_height = if alert_count > 0 {
        (alert_count as u16).min(3) + 2
    } else {
        0
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),            // header
            Constraint::Length(alert_height), // alerts (0 if none)
            Constraint::Min(6),               // interface table
            Constraint::Length(chart_height), // bandwidth graph or per-iface sparkline
            Constraint::Length(7),            // top connections
            Constraint::Length(4),            // health status
            Constraint::Length(4),            // latency heatmap
            Constraint::Length(3),            // footer
        ])
        .split(area);

    // sort interfaces once, share between table and sparkline so
    // selected_interface index refers to the same sorted order
    let mut sorted_interfaces = app.traffic.interfaces();
    let sort_state = app.sort_states.get(&crate::app::Tab::Dashboard);
    if let Some(state) = sort_state {
        crate::ui::interfaces::sort_interfaces(
            &mut sorted_interfaces,
            crate::app::Tab::Dashboard,
            state.column,
            state.ascending,
            &app.interface_info,
        );
    }

    render_header(f, app, chunks[0]);
    if alert_count > 0 {
        render_alerts(f, app, chunks[1]);
    }
    render_interface_table(f, app, &sorted_interfaces, chunks[2]);
    if app.selected_interface.is_some() {
        render_sparkline(f, app, &sorted_interfaces, chunks[3]);
    } else {
        render_bandwidth_graph(f, app, chunks[3]);
    }
    render_top_connections(f, app, chunks[4]);
    render_health(f, app, chunks[5]);
    render_latency_heatmap(f, app, chunks[6]);
    render_footer(f, app, chunks[7]);
}

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    widgets::render_header(f, app, area);
}

fn render_alerts(f: &mut Frame, app: &App, area: Rect) {
    use crate::collectors::network_intel::AlertSeverity;

    let alerts = app.network_intel.active_alerts();
    let lines: Vec<Line> = alerts
        .iter()
        .take(3)
        .map(|alert| {
            let (icon, style) = match alert.severity {
                AlertSeverity::Critical => {
                    ("● ", Style::default().fg(app.theme.status_error).bold())
                }
                AlertSeverity::Warning => ("▲ ", Style::default().fg(app.theme.status_warn)),
            };
            Line::from(vec![
                Span::styled(icon, style),
                Span::styled(alert.category.label(), style),
                Span::raw(": "),
                Span::styled(
                    alert.message.clone(),
                    Style::default().fg(app.theme.text_primary),
                ),
                Span::raw("  "),
                Span::styled(
                    alert.detail.clone(),
                    Style::default().fg(app.theme.text_muted),
                ),
            ])
        })
        .collect();

    let alert_widget = Paragraph::new(lines).block(
        Block::default()
            .title(format!(" ⚠ Alerts ({}) ", alerts.len()))
            .title_style(Style::default().fg(app.theme.status_warn).bold())
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.status_warn)),
    );
    f.render_widget(alert_widget, area);
}

fn render_interface_table(
    f: &mut Frame,
    app: &App,
    interfaces: &[crate::collectors::traffic::InterfaceTraffic],
    area: Rect,
) {
    let tab = crate::app::Tab::Dashboard;
    let header = widgets::sort_header_row(app, tab, COLUMNS);

    let rows: Vec<Row> = interfaces
        .iter()
        .enumerate()
        .map(|(i, iface)| {
            let ip = app
                .interface_info
                .iter()
                .find(|info| info.name == iface.name)
                .and_then(|info| info.ipv4.clone())
                .unwrap_or_else(|| "—".to_string());

            let is_up = app
                .interface_info
                .iter()
                .find(|info| info.name == iface.name)
                .map(|info| info.is_up)
                .unwrap_or(false);

            let status_style = if is_up {
                Style::default().fg(app.theme.status_good)
            } else {
                Style::default().fg(app.theme.status_error)
            };

            let selected = app.selected_interface == Some(i);
            let row_style = if selected {
                Style::default().bg(app.theme.selection_bg)
            } else {
                Style::default()
            };

            let name_cell = if selected {
                Cell::from(format!("► {}", iface.name))
            } else {
                Cell::from(format!("  {}", iface.name))
            };

            Row::new(vec![
                name_cell,
                Cell::from(ip),
                Cell::from(widgets::format_bytes_rate_padded(iface.rx_rate))
                    .style(Style::default().fg(app.theme.rx_rate)),
                Cell::from(widgets::format_bytes_rate_padded(iface.tx_rate))
                    .style(Style::default().fg(app.theme.tx_rate)),
                Cell::from(widgets::format_bytes_total_padded(iface.rx_bytes_total)),
                Cell::from(widgets::format_bytes_total_padded(iface.tx_bytes_total)),
                Cell::from(if is_up { "UP" } else { "DOWN" }).style(status_style),
            ])
            .style(row_style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Length(16),
            Constraint::Length(14),
            Constraint::Length(14),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(6),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(" Interfaces ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border)),
    );

    f.render_widget(table, area);
}

fn render_sparkline(
    f: &mut Frame,
    app: &App,
    sorted_interfaces: &[crate::collectors::traffic::InterfaceTraffic],
    area: Rect,
) {
    // look up from the sorted list so the sparkline matches the highlighted row
    let selected = app
        .selected_interface
        .and_then(|i| sorted_interfaces.get(i));

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    if let Some(iface) = selected {
        let rx_spark = Sparkline::default()
            .block(
                Block::default()
                    .title(format!(" RX {} ", iface.name))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(app.theme.border)),
            )
            .data(iface.rx_history.as_slices().0)
            .style(Style::default().fg(app.theme.rx_rate));

        let tx_spark = Sparkline::default()
            .block(
                Block::default()
                    .title(format!(" TX {} ", iface.name))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(app.theme.border)),
            )
            .data(iface.tx_history.as_slices().0)
            .style(Style::default().fg(app.theme.tx_rate));

        f.render_widget(rx_spark, chunks[0]);
        f.render_widget(tx_spark, chunks[1]);
    } else {
        let empty = Paragraph::new("No interface selected").block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(app.theme.border)),
        );
        f.render_widget(empty, area);
    }
}

fn render_bandwidth_graph(f: &mut Frame, app: &App, area: Rect) {
    let interfaces = app.traffic.interfaces();
    let active: Vec<_> = interfaces
        .iter()
        .filter(|i| {
            app.interface_info
                .iter()
                .find(|info| info.name == i.name)
                .map(|info| info.is_up && info.name != "lo0" && info.name != "lo")
                .unwrap_or(false)
        })
        .collect();

    if active.is_empty() {
        let empty = Paragraph::new(" No active interfaces")
            .style(Style::default().fg(app.theme.text_muted))
            .block(
                Block::default()
                    .title(" Bandwidth ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(app.theme.border)),
            );
        f.render_widget(empty, area);
        return;
    }

    // Aggregate RX and TX history across all active interfaces
    let max_len = active.iter().map(|i| i.rx_history.len()).max().unwrap_or(0);
    let mut agg_rx = vec![0u64; max_len];
    let mut agg_tx = vec![0u64; max_len];
    for iface in &active {
        for (t, &val) in iface.rx_history.iter().enumerate() {
            agg_rx[t] += val;
        }
        for (t, &val) in iface.tx_history.iter().enumerate() {
            agg_tx[t] += val;
        }
    }

    // Current aggregate rates
    let total_rx: f64 = active.iter().map(|i| i.rx_rate).sum();
    let total_tx: f64 = active.iter().map(|i| i.tx_rate).sum();

    let iface_names: String = active
        .iter()
        .map(|i| i.name.as_str())
        .collect::<Vec<_>>()
        .join("+");

    // Split into RX sparkline (top) and TX sparkline (bottom)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let rx_title = format!(
        " ▼ RX {} — {} (last 60s) ",
        iface_names,
        widgets::format_bytes_rate(total_rx),
    );
    let rx_spark = Sparkline::default()
        .block(
            Block::default()
                .title(rx_title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(app.theme.border)),
        )
        .data(&agg_rx)
        .style(Style::default().fg(app.theme.rx_rate));
    f.render_widget(rx_spark, chunks[0]);

    let tx_title = format!(
        " ▲ TX {} — {} (last 60s) ",
        iface_names,
        widgets::format_bytes_rate(total_tx),
    );
    let tx_spark = Sparkline::default()
        .block(
            Block::default()
                .title(tx_title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(app.theme.border)),
        )
        .data(&agg_tx)
        .style(Style::default().fg(app.theme.tx_rate));
    f.render_widget(tx_spark, chunks[1]);
}

fn render_top_connections(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        Cell::from("Process").style(Style::default().fg(app.theme.brand).bold()),
        Cell::from("Proto").style(Style::default().fg(app.theme.brand).bold()),
        Cell::from("State").style(Style::default().fg(app.theme.brand).bold()),
        Cell::from("Remote").style(Style::default().fg(app.theme.brand).bold()),
    ])
    .height(1);

    let max_rows = (area.height as usize).saturating_sub(3).max(1);
    let conns = app.connection_collector.connections.lock().unwrap();
    let rows: Vec<Row> = conns
        .iter()
        .filter(|c| c.state == "ESTABLISHED")
        .take(max_rows)
        .map(|conn| {
            Row::new(vec![
                Cell::from(conn.process_name.as_deref().unwrap_or("—").to_string()),
                Cell::from(conn.protocol.clone()),
                Cell::from(conn.state.clone()).style(Style::default().fg(app.theme.status_good)),
                Cell::from(conn.remote_addr.clone()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(16),
            Constraint::Length(6),
            Constraint::Length(14),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(" Top Connections ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border)),
    );

    f.render_widget(table, area);
}

fn render_health(f: &mut Frame, app: &App, area: Rect) {
    let hs = app.health_prober.status.lock().unwrap();

    let gw_rtt = hs
        .gateway_rtt_ms
        .map(|r| format!("{:.1}ms", r))
        .unwrap_or_else(|| "—".to_string());

    let dns_rtt = hs
        .dns_rtt_ms
        .map(|r| format!("{:.1}ms", r))
        .unwrap_or_else(|| "—".to_string());

    let gw_style = if hs.gateway_loss_pct < 1.0 {
        Style::default().fg(app.theme.status_good)
    } else if hs.gateway_loss_pct < 50.0 {
        Style::default().fg(app.theme.status_warn)
    } else {
        Style::default().fg(app.theme.status_error)
    };

    let dns_style = if hs.dns_loss_pct < 1.0 {
        Style::default().fg(app.theme.status_good)
    } else if hs.dns_loss_pct < 50.0 {
        Style::default().fg(app.theme.status_warn)
    } else {
        Style::default().fg(app.theme.status_error)
    };

    let gw_label = app
        .config_collector
        .config
        .gateway
        .as_deref()
        .unwrap_or("—");

    let interfaces = app.traffic.interfaces();
    let total_errors: u64 = interfaces.iter().map(|i| i.rx_errors + i.tx_errors).sum();

    let total_drops: u64 = interfaces.iter().map(|i| i.rx_drops + i.tx_drops).sum();

    let ebpf_span = match &app.ebpf_status {
        EbpfStatus::Active => {
            Span::styled("eBPF: ● active", Style::default().fg(app.theme.status_good))
        }
        EbpfStatus::Unavailable(reason) => Span::styled(
            format!("eBPF: ⚠ {reason}"),
            Style::default().fg(app.theme.status_warn),
        ),
        EbpfStatus::NotCompiled => {
            Span::styled("eBPF: off", Style::default().fg(app.theme.text_muted))
        }
    };

    let line1 = Line::from(vec![
        Span::raw(" GW "),
        Span::raw(gw_label.to_string()),
        Span::raw("  "),
        Span::styled("●", gw_style),
        Span::raw(" "),
        Span::styled(gw_rtt, gw_style),
        Span::raw(format!("  {:.0}% loss", hs.gateway_loss_pct)),
        Span::raw("   │  DNS  "),
        Span::styled("●", dns_style),
        Span::raw(" "),
        Span::styled(dns_rtt, dns_style),
        Span::raw(format!("  {:.0}% loss", hs.dns_loss_pct)),
    ]);

    let line2 = Line::from(vec![
        Span::raw(format!(" Errors: {}  Drops: {}", total_errors, total_drops)),
        Span::raw("   │  "),
        ebpf_span,
    ]);

    let health = Paragraph::new(vec![line1, line2]).block(
        Block::default()
            .title(" Health ")
            .title_style(Style::default().fg(app.theme.brand))
            .borders(Borders::LEFT)
            .border_style(Style::default().fg(app.theme.brand)),
    );

    f.render_widget(health, area);
}

fn rtt_heatmap_spans(history: &[Option<f64>], width: usize, t: &Theme) -> Vec<Span<'static>> {
    if history.is_empty() {
        return vec![Span::styled(
            " No data yet".to_string(),
            Style::default().fg(t.text_muted),
        )];
    }

    // Find max RTT for scaling
    let max_rtt = history
        .iter()
        .filter_map(|r| *r)
        .fold(0.0f64, f64::max)
        .max(1.0);

    // Use the last `width` samples
    let start = history.len().saturating_sub(width);
    let slice = &history[start..];

    slice
        .iter()
        .map(|sample| {
            match sample {
                None => Span::styled("▮", Style::default().fg(t.status_error)),
                Some(rtt) => {
                    let ratio = (*rtt / max_rtt).min(1.0);
                    let color = if ratio < 0.3 {
                        t.status_good
                    } else if ratio < 0.6 {
                        t.status_warn
                    } else if ratio < 0.85 {
                        Color::Rgb(255, 165, 0) // orange
                    } else {
                        t.status_error
                    };
                    // Use block characters with varying fill for fine granularity
                    let block = match ((ratio * 7.0) as u8).min(7) {
                        0 => '▁',
                        1 => '▂',
                        2 => '▃',
                        3 => '▄',
                        4 => '▅',
                        5 => '▆',
                        6 => '▇',
                        _ => '█',
                    };
                    Span::styled(block.to_string(), Style::default().fg(color))
                }
            }
        })
        .collect()
}

fn render_latency_heatmap(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" Latency Heatmap ")
        .title_style(Style::default().fg(app.theme.brand))
        .borders(Borders::LEFT)
        .border_style(Style::default().fg(app.theme.brand));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 2 {
        return;
    }

    let avail_width = inner.width.saturating_sub(12) as usize; // reserve label space

    let hs = app.health_prober.status.lock().unwrap();

    // Gateway row
    let mut gw_spans: Vec<Span> = vec![Span::styled(
        " GW  ",
        Style::default().fg(app.theme.brand).bold(),
    )];
    gw_spans.extend(rtt_heatmap_spans(
        hs.gateway_rtt_history.as_slices().0,
        avail_width,
        &app.theme,
    ));
    if let Some(rtt) = hs.gateway_rtt_ms {
        gw_spans.push(Span::styled(
            format!(" {:.1}ms", rtt),
            Style::default().fg(app.theme.text_primary),
        ));
    }
    let gw_line = Line::from(gw_spans);

    // DNS row
    let mut dns_spans: Vec<Span> = vec![Span::styled(
        " DNS ",
        Style::default().fg(app.theme.brand).bold(),
    )];
    dns_spans.extend(rtt_heatmap_spans(
        hs.dns_rtt_history.as_slices().0,
        avail_width,
        &app.theme,
    ));
    if let Some(rtt) = hs.dns_rtt_ms {
        dns_spans.push(Span::styled(
            format!(" {:.1}ms", rtt),
            Style::default().fg(app.theme.text_primary),
        ));
    }
    let dns_line = Line::from(dns_spans);

    let content = Paragraph::new(vec![gw_line, dns_line]);
    f.render_widget(content, inner);
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let hints = vec![
        Span::styled("s", Style::default().fg(app.theme.key_hint).bold()),
        Span::raw(":Sort  "),
        Span::styled("p", Style::default().fg(app.theme.key_hint).bold()),
        Span::raw(":Pause  "),
        Span::styled("r", Style::default().fg(app.theme.key_hint).bold()),
        Span::raw(":Refresh  "),
        Span::styled(",", Style::default().fg(app.theme.key_hint).bold()),
        Span::raw(":Settings"),
    ];
    widgets::render_footer(f, app, area, hints);
}
