use crate::app::App;
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Bar, BarChart, BarGroup, Block, Borders, Cell, Paragraph, Row, Sparkline, Table},
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chart_height = if app.selected_interface.is_none() { 10 } else { 5 };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),            // header
            Constraint::Min(6),              // interface table
            Constraint::Length(chart_height), // sparkline or histogram
            Constraint::Length(7),            // top connections
            Constraint::Length(3),            // health status
            Constraint::Length(3),            // footer
        ])
        .split(area);

    render_header(f, chunks[0]);
    render_interface_table(f, app, chunks[1]);
    if app.selected_interface.is_none() {
        render_histogram(f, app, chunks[2]);
    } else {
        render_sparkline(f, app, chunks[2]);
    }
    render_top_connections(f, app, chunks[3]);
    render_health(f, app, chunks[4]);
    render_footer(f, chunks[5]);
}

fn render_header(f: &mut Frame, area: Rect) {
    let now = chrono::Local::now().format("%H:%M:%S").to_string();
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" NetWatch ", Style::default().fg(Color::Cyan).bold()),
        Span::raw("│ "),
        Span::styled("[1] Dashboard", Style::default().fg(Color::Yellow).bold()),
        Span::raw("  [2] Connections  [3] Interfaces  [4] Packets"),
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
            .data(&iface.rx_history)
            .style(Style::default().fg(Color::Green));

        let tx_spark = Sparkline::default()
            .block(
                Block::default()
                    .title(format!(" TX {} ", iface.name))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            )
            .data(&iface.tx_history)
            .style(Style::default().fg(Color::Blue));

        f.render_widget(rx_spark, chunks[0]);
        f.render_widget(tx_spark, chunks[1]);
    } else {
        let empty = Paragraph::new("No interface selected")
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)));
        f.render_widget(empty, area);
    }
}

const IFACE_COLORS: [Color; 8] = [
    Color::Green,
    Color::Blue,
    Color::Magenta,
    Color::Cyan,
    Color::Yellow,
    Color::Red,
    Color::LightGreen,
    Color::LightBlue,
];

fn format_scale_label(value: u64) -> String {
    if value >= 1_000_000 {
        format!("{:.0}G", value as f64 / 1_000_000.0)
    } else if value >= 1_000 {
        format!("{:.0}M", value as f64 / 1_000.0)
    } else {
        format!("{}K", value)
    }
}

fn render_histogram(f: &mut Frame, app: &App, area: Rect) {
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
        let empty = Paragraph::new("No active interfaces")
            .block(
                Block::default()
                    .title(" Throughput ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
        f.render_widget(empty, area);
        return;
    }

    // Build legend
    let legend: Vec<Span> = active
        .iter()
        .enumerate()
        .flat_map(|(idx, iface)| {
            vec![
                Span::styled("■ ", Style::default().fg(IFACE_COLORS[idx % IFACE_COLORS.len()])),
                Span::styled(
                    format!("{} ", iface.name),
                    Style::default().fg(Color::White),
                ),
            ]
        })
        .collect();

    let title = Line::from(
        std::iter::once(Span::raw(" Throughput (KB/s) "))
            .chain(legend)
            .collect::<Vec<Span>>(),
    );

    // Outer block for the whole widget (title, legend, border)
    let outer_block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    let inner = outer_block.inner(area);
    f.render_widget(outer_block, area);

    // Split inner area: scale labels on the left, bar chart on the right
    let scale_width = 7u16;
    let h_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(scale_width), Constraint::Min(1)])
        .split(inner);

    let scale_area = h_chunks[0];
    let chart_area = h_chunks[1];

    // Compute bar data and find max value for scale
    let chart_inner_width = chart_area.width as usize;
    let iface_count = active.len();
    let group_width = iface_count + 1;
    let num_slots = if group_width > 0 {
        (chart_inner_width / group_width).max(1).min(30)
    } else {
        10
    };

    let history_len = active
        .iter()
        .map(|i| i.rx_history.len())
        .max()
        .unwrap_or(0);
    let start = history_len.saturating_sub(num_slots);

    let mut max_val: u64 = 0;
    let groups: Vec<BarGroup> = (start..history_len)
        .map(|t| {
            let bars: Vec<Bar> = active
                .iter()
                .enumerate()
                .map(|(idx, iface)| {
                    let rx = iface.rx_history.get(t).copied().unwrap_or(0);
                    let tx = iface.tx_history.get(t).copied().unwrap_or(0);
                    let kbps = ((rx + tx) / 1024).max(if rx + tx > 0 { 1 } else { 0 });
                    if kbps > max_val {
                        max_val = kbps;
                    }
                    Bar::default()
                        .value(kbps)
                        .style(Style::default().fg(IFACE_COLORS[idx % IFACE_COLORS.len()]))
                })
                .collect();
            BarGroup::default().bars(&bars)
        })
        .collect();

    // Render Y-axis scale labels
    // The bar chart height is chart_area.height (bars grow upward from bottom)
    let bar_height = scale_area.height as usize;
    if bar_height > 0 && max_val > 0 {
        let num_labels = bar_height.min(5);
        for i in 0..num_labels {
            let frac = (num_labels - i) as f64 / num_labels as f64;
            let value = (max_val as f64 * frac) as u64;
            let label = format_scale_label(value);
            let y = scale_area.y + (i as u16 * scale_area.height / num_labels as u16);
            if y < scale_area.y + scale_area.height {
                let label_span = Span::styled(
                    format!("{:>6}", label),
                    Style::default().fg(Color::DarkGray),
                );
                let label_area = Rect::new(scale_area.x, y, scale_width, 1);
                f.render_widget(Paragraph::new(label_span), label_area);
            }
        }
        // Bottom label (0)
        let zero_area = Rect::new(
            scale_area.x,
            scale_area.y + scale_area.height.saturating_sub(1),
            scale_width,
            1,
        );
        f.render_widget(
            Paragraph::new(Span::styled(
                format!("{:>6}", "0"),
                Style::default().fg(Color::DarkGray),
            )),
            zero_area,
        );
    }

    // Render bar chart (no block — outer block already drawn)
    let mut chart = BarChart::default()
        .bar_width(1)
        .bar_gap(0)
        .group_gap(1);

    for group in &groups {
        chart = chart.data(group.clone());
    }

    f.render_widget(chart, chart_area);
}

fn render_top_connections(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        Cell::from("Process").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Proto").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("State").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Remote").style(Style::default().fg(Color::Cyan).bold()),
    ])
    .height(1);

    let rows: Vec<Row> = app
        .connection_collector
        .connections
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
    let hs = &app.health_prober.status;

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
        Span::styled("?", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Help"),
    ]))
    .block(Block::default().borders(Borders::TOP).border_style(Style::default().fg(Color::DarkGray)));
    f.render_widget(footer, area);
}
