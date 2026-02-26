use crate::app::App;
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table},
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chart_height = if app.selected_interface.is_some() { 5 } else { 10 };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),            // header
            Constraint::Min(6),              // interface table
            Constraint::Length(chart_height), // bandwidth graph or per-iface sparkline
            Constraint::Length(7),            // top connections
            Constraint::Length(3),            // health status
            Constraint::Length(4),            // latency heatmap
            Constraint::Length(3),            // footer
        ])
        .split(area);

    render_header(f, chunks[0]);
    render_interface_table(f, app, chunks[1]);
    if app.selected_interface.is_some() {
        render_sparkline(f, app, chunks[2]);
    } else {
        render_bandwidth_graph(f, app, chunks[2]);
    }
    render_top_connections(f, app, chunks[3]);
    render_health(f, app, chunks[4]);
    render_latency_heatmap(f, app, chunks[5]);
    render_footer(f, chunks[6]);
}

fn render_header(f: &mut Frame, area: Rect) {
    let now = chrono::Local::now().format("%H:%M:%S").to_string();
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" NetWatch ", Style::default().fg(Color::Cyan).bold()),
        Span::raw("│ "),
        Span::styled("[1] Dashboard", Style::default().fg(Color::Yellow).bold()),
        Span::raw("  [2] Connections  [3] Interfaces  [4] Packets  [5] Stats"),
        Span::raw("  │ "),
        Span::styled(now, Style::default().fg(Color::DarkGray)),
    ]))
    .block(Block::default().borders(Borders::BOTTOM).border_style(Style::default().fg(Color::DarkGray)));
    f.render_widget(header, area);
}

fn render_interface_table(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        Cell::from("Interface").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("IP Address").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("RX Rate").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("TX Rate").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("RX Total").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("TX Total").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Status").style(Style::default().fg(Color::Cyan).bold()),
    ])
    .height(1);

    let rows: Vec<Row> = app
        .traffic
        .interfaces
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
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Red)
            };

            let row_style = if app.selected_interface == Some(i) {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(iface.name.clone()),
                Cell::from(ip),
                Cell::from(widgets::format_bytes_rate(iface.rx_rate)).style(Style::default().fg(Color::Green)),
                Cell::from(widgets::format_bytes_rate(iface.tx_rate)).style(Style::default().fg(Color::Blue)),
                Cell::from(widgets::format_bytes_total(iface.rx_bytes_total)),
                Cell::from(widgets::format_bytes_total(iface.tx_bytes_total)),
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
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    f.render_widget(table, area);
}

fn render_sparkline(f: &mut Frame, app: &App, area: Rect) {
    let selected = app.selected_interface.and_then(|i| app.traffic.interfaces.get(i));

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
                    .border_style(Style::default().fg(Color::DarkGray)),
            )
            .data(iface.rx_history.as_slices().0)
            .style(Style::default().fg(Color::Green));

        let tx_spark = Sparkline::default()
            .block(
                Block::default()
                    .title(format!(" TX {} ", iface.name))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            )
            .data(iface.tx_history.as_slices().0)
            .style(Style::default().fg(Color::Blue));

        f.render_widget(rx_spark, chunks[0]);
        f.render_widget(tx_spark, chunks[1]);
    } else {
        let empty = Paragraph::new("No interface selected")
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)));
        f.render_widget(empty, area);
    }
}

fn render_bandwidth_graph(f: &mut Frame, app: &App, area: Rect) {
    let active: Vec<_> = app
        .traffic
        .interfaces
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
            .style(Style::default().fg(Color::DarkGray))
            .block(
                Block::default()
                    .title(" Bandwidth ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
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

    let iface_names: String = active.iter().map(|i| i.name.as_str()).collect::<Vec<_>>().join("+");

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
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .data(&agg_rx)
        .style(Style::default().fg(Color::Green));
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
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .data(&agg_tx)
        .style(Style::default().fg(Color::Blue));
    f.render_widget(tx_spark, chunks[1]);
}

fn render_top_connections(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        Cell::from("Process").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Proto").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("State").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Remote").style(Style::default().fg(Color::Cyan).bold()),
    ])
    .height(1);

    let conns = app.connection_collector.connections.lock().unwrap();
    let rows: Vec<Row> = conns
        .iter()
        .filter(|c| c.state == "ESTABLISHED")
        .take(5)
        .map(|conn| {
            Row::new(vec![
                Cell::from(conn.process_name.as_deref().unwrap_or("—").to_string()),
                Cell::from(conn.protocol.clone()),
                Cell::from(conn.state.clone()).style(Style::default().fg(Color::Green)),
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
            .border_style(Style::default().fg(Color::DarkGray)),
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
        Style::default().fg(Color::Green)
    } else if hs.gateway_loss_pct < 50.0 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::Red)
    };

    let dns_style = if hs.dns_loss_pct < 1.0 {
        Style::default().fg(Color::Green)
    } else if hs.dns_loss_pct < 50.0 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::Red)
    };

    let gw_label = app
        .config_collector
        .config
        .gateway
        .as_deref()
        .unwrap_or("—");

    let total_errors: u64 = app
        .traffic
        .interfaces
        .iter()
        .map(|i| i.rx_errors + i.tx_errors)
        .sum();

    let health = Paragraph::new(Line::from(vec![
        Span::raw(" GW "),
        Span::raw(gw_label),
        Span::raw(": "),
        Span::styled(gw_rtt, gw_style),
        Span::raw(format!(" ({:.0}% loss)", hs.gateway_loss_pct)),
        Span::raw("  │  DNS: "),
        Span::styled(dns_rtt, dns_style),
        Span::raw(format!(" ({:.0}% loss)", hs.dns_loss_pct)),
        Span::raw(format!("  │  Errors: {}", total_errors)),
    ]))
    .block(
        Block::default()
            .title(" Health ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    f.render_widget(health, area);
}

fn rtt_heatmap_spans(history: &[Option<f64>], width: usize) -> Vec<Span<'static>> {
    if history.is_empty() {
        return vec![Span::styled(
            " No data yet".to_string(),
            Style::default().fg(Color::DarkGray),
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
                None => Span::styled("▮", Style::default().fg(Color::Red)),
                Some(rtt) => {
                    let ratio = (*rtt / max_rtt).min(1.0);
                    let color = if ratio < 0.3 {
                        Color::Green
                    } else if ratio < 0.6 {
                        Color::Yellow
                    } else if ratio < 0.85 {
                        Color::Rgb(255, 165, 0) // orange
                    } else {
                        Color::Red
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
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 2 {
        return;
    }

    let avail_width = inner.width.saturating_sub(12) as usize; // reserve label space

    let hs = app.health_prober.status.lock().unwrap();

    // Gateway row
    let mut gw_spans: Vec<Span> = vec![
        Span::styled(" GW  ", Style::default().fg(Color::Cyan).bold()),
    ];
    gw_spans.extend(rtt_heatmap_spans(hs.gateway_rtt_history.as_slices().0, avail_width));
    if let Some(rtt) = hs.gateway_rtt_ms {
        gw_spans.push(Span::styled(
            format!(" {:.1}ms", rtt),
            Style::default().fg(Color::White),
        ));
    }
    let gw_line = Line::from(gw_spans);

    // DNS row
    let mut dns_spans: Vec<Span> = vec![
        Span::styled(" DNS ", Style::default().fg(Color::Cyan).bold()),
    ];
    dns_spans.extend(rtt_heatmap_spans(hs.dns_rtt_history.as_slices().0, avail_width));
    if let Some(rtt) = hs.dns_rtt_ms {
        dns_spans.push(Span::styled(
            format!(" {:.1}ms", rtt),
            Style::default().fg(Color::White),
        ));
    }
    let dns_line = Line::from(dns_spans);

    let content = Paragraph::new(vec![gw_line, dns_line]);
    f.render_widget(content, inner);
}

fn render_footer(f: &mut Frame, area: Rect) {
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" q", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Quit  "),
        Span::styled("↑↓", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Select  "),
        Span::styled("p", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Pause  "),
        Span::styled("r", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Refresh  "),
        Span::styled("1-5", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Tab  "),
        Span::styled("g", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Geo  "),
        Span::styled("?", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Help"),
    ]))
    .block(Block::default().borders(Borders::TOP).border_style(Style::default().fg(Color::DarkGray)));
    f.render_widget(footer, area);
}
