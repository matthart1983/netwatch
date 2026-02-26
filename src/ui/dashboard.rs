use crate::app::App;
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table},
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header
            Constraint::Min(6),    // interface table
            Constraint::Length(5), // sparkline
            Constraint::Length(7), // top connections
            Constraint::Length(3), // health status
            Constraint::Length(3), // footer
        ])
        .split(area);

    render_header(f, chunks[0]);
    render_interface_table(f, app, chunks[1]);
    render_sparkline(f, app, chunks[2]);
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

            let row_style = if i == app.selected_interface {
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
    let selected = app.traffic.interfaces.get(app.selected_interface);

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
        Span::styled("1-4", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Tab"),
    ]))
    .block(Block::default().borders(Borders::TOP).border_style(Style::default().fg(Color::DarkGray)));
    f.render_widget(footer, area);
}
