use std::collections::HashMap;

use crate::app::App;
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header
            Constraint::Min(10),   // protocol hierarchy table
            Constraint::Length(3), // summary bar
            Constraint::Length(3), // footer
        ])
        .split(area);

    let packets = app.packet_collector.get_packets();
    let stats = compute_protocol_stats(&packets);

    render_header(f, chunks[0]);
    render_protocol_table(f, app, &stats, chunks[1]);
    render_summary(f, &stats, chunks[2]);
    render_footer(f, chunks[3]);
}

struct ProtocolStat {
    protocol: String,
    packets: u64,
    bytes: u64,
}

struct Stats {
    protocols: Vec<ProtocolStat>,
    total_packets: u64,
    total_bytes: u64,
}

fn compute_protocol_stats(packets: &[crate::collectors::packets::CapturedPacket]) -> Stats {
    let mut map: HashMap<String, (u64, u64)> = HashMap::new();
    for pkt in packets {
        let entry = map.entry(pkt.protocol.clone()).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += pkt.length as u64;
    }

    let total_packets: u64 = map.values().map(|(c, _)| c).sum();
    let total_bytes: u64 = map.values().map(|(_, b)| b).sum();

    let mut protocols: Vec<ProtocolStat> = map
        .into_iter()
        .map(|(protocol, (packets, bytes))| ProtocolStat {
            protocol,
            packets,
            bytes,
        })
        .collect();

    protocols.sort_by(|a, b| b.packets.cmp(&a.packets));

    Stats {
        protocols,
        total_packets,
        total_bytes,
    }
}

fn render_header(f: &mut Frame, area: Rect) {
    let now = chrono::Local::now().format("%H:%M:%S").to_string();
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" NetWatch ", Style::default().fg(Color::Cyan).bold()),
        Span::raw("│ "),
        Span::raw("[1] Dashboard  [2] Connections  [3] Interfaces  [4] Packets  "),
        Span::styled("[5] Stats", Style::default().fg(Color::Yellow).bold()),
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

fn bar_visual(pct: f64) -> String {
    let width = 16;
    let filled = ((pct / 100.0) * width as f64).round() as usize;
    let empty = width - filled;
    format!("{}{}", "█".repeat(filled), "░".repeat(empty))
}

fn render_protocol_table(f: &mut Frame, app: &App, stats: &Stats, area: Rect) {
    let header = Row::new(vec![
        Cell::from("Protocol").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Packets").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("% Packets").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Bytes").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("% Bytes").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Distribution").style(Style::default().fg(Color::Cyan).bold()),
    ])
    .height(1);

    let visible_height = area.height.saturating_sub(3) as usize;
    let total = stats.protocols.len();
    let offset = app.stats_scroll.min(total.saturating_sub(visible_height));

    let rows: Vec<Row> = stats
        .protocols
        .iter()
        .skip(offset)
        .take(visible_height)
        .map(|ps| {
            let pkt_pct = if stats.total_packets > 0 {
                ps.packets as f64 / stats.total_packets as f64 * 100.0
            } else {
                0.0
            };
            let byte_pct = if stats.total_bytes > 0 {
                ps.bytes as f64 / stats.total_bytes as f64 * 100.0
            } else {
                0.0
            };

            let proto_style = protocol_color(&ps.protocol);

            Row::new(vec![
                Cell::from(ps.protocol.clone()).style(proto_style),
                Cell::from(format!("{}", ps.packets)),
                Cell::from(format!("{:.1}%", pkt_pct)),
                Cell::from(widgets::format_bytes_total(ps.bytes)),
                Cell::from(format!("{:.1}%", byte_pct)),
                Cell::from(bar_visual(pkt_pct)).style(Style::default().fg(Color::Green)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Min(18),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(format!(" Protocol Hierarchy ({total}) "))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    f.render_widget(table, area);
}

fn render_summary(f: &mut Frame, stats: &Stats, area: Rect) {
    let summary = Paragraph::new(Line::from(vec![
        Span::styled(" Packets: ", Style::default().fg(Color::Cyan).bold()),
        Span::raw(format!("{}", stats.total_packets)),
        Span::raw("  │  "),
        Span::styled("Bytes: ", Style::default().fg(Color::Cyan).bold()),
        Span::raw(widgets::format_bytes_total(stats.total_bytes)),
        Span::raw("  │  "),
        Span::styled("Protocols: ", Style::default().fg(Color::Cyan).bold()),
        Span::raw(format!("{}", stats.protocols.len())),
    ]))
    .block(
        Block::default()
            .title(" Summary ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(summary, area);
}

fn render_footer(f: &mut Frame, area: Rect) {
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" q", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Quit  "),
        Span::styled("↑↓", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Scroll  "),
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
    .block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(footer, area);
}

fn protocol_color(proto: &str) -> Style {
    match proto {
        "TCP" => Style::default().fg(Color::Magenta),
        "UDP" => Style::default().fg(Color::Blue),
        "ICMP" | "ICMPv6" => Style::default().fg(Color::Yellow),
        "ARP" => Style::default().fg(Color::Cyan),
        "DNS" => Style::default().fg(Color::Green),
        _ => Style::default().fg(Color::White),
    }
}
