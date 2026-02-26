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
            Constraint::Length(3), // header
            Constraint::Min(8),   // interface detail table
            Constraint::Length(5), // sparkline
            Constraint::Length(3), // footer
        ])
        .split(area);

    render_header(f, chunks[0]);
    render_detail_table(f, app, chunks[1]);
    render_sparkline(f, app, chunks[2]);
    render_footer(f, chunks[3]);
}

fn render_header(f: &mut Frame, area: Rect) {
    let now = chrono::Local::now().format("%H:%M:%S").to_string();
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" NetWatch ", Style::default().fg(Color::Cyan).bold()),
        Span::raw("│ "),
        Span::raw("[1] Dashboard  [2] Connections  "),
        Span::styled("[3] Interfaces", Style::default().fg(Color::Yellow).bold()),
        Span::raw("  │ "),
        Span::styled(now, Style::default().fg(Color::DarkGray)),
    ]))
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(header, area);
}

fn render_detail_table(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        Cell::from("Name").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("IPv4").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("IPv6").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("MAC").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("MTU").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("RX B/s").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("TX B/s").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("RX Pkts").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("TX Pkts").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Err/Drop").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Status").style(Style::default().fg(Color::Cyan).bold()),
    ])
    .height(1);

    let rows: Vec<Row> = app
        .traffic
        .interfaces
        .iter()
        .enumerate()
        .map(|(i, iface)| {
            let info = app
                .interface_info
                .iter()
                .find(|info| info.name == iface.name);

            let ipv4 = info
                .and_then(|i| i.ipv4.clone())
                .unwrap_or_else(|| "—".to_string());
            let ipv6 = info
                .and_then(|i| i.ipv6.clone())
                .unwrap_or_else(|| "—".to_string());
            let mac = info
                .and_then(|i| i.mac.clone())
                .unwrap_or_else(|| "—".to_string());
            let mtu = info
                .and_then(|i| i.mtu)
                .map(|m| m.to_string())
                .unwrap_or_else(|| "—".to_string());
            let is_up = info.map(|i| i.is_up).unwrap_or(false);

            let errors_drops = format!(
                "{}/{}",
                iface.rx_errors + iface.tx_errors,
                iface.rx_drops + iface.tx_drops
            );

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
                Cell::from(ipv4),
                Cell::from(ipv6),
                Cell::from(mac),
                Cell::from(mtu),
                Cell::from(widgets::format_bytes_rate(iface.rx_rate))
                    .style(Style::default().fg(Color::Green)),
                Cell::from(widgets::format_bytes_rate(iface.tx_rate))
                    .style(Style::default().fg(Color::Blue)),
                Cell::from(iface.rx_packets.to_string()),
                Cell::from(iface.tx_packets.to_string()),
                Cell::from(errors_drops),
                Cell::from(if is_up { "UP" } else { "DOWN" }).style(status_style),
            ])
            .style(row_style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(16),
            Constraint::Length(20),
            Constraint::Length(18),
            Constraint::Length(6),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(6),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(" Interface Details ")
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
        let empty = Paragraph::new("No interface selected").block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(empty, area);
    }
}

fn render_footer(f: &mut Frame, area: Rect) {
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" q", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Quit  "),
        Span::styled("↑↓", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Select  "),
        Span::styled("1-3", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Tab  "),
        Span::styled("p", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Pause  "),
        Span::styled("r", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Refresh"),
    ]))
    .block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(footer, area);
}
