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
            Constraint::Min(8),    // protocol hierarchy table
            Constraint::Length(12), // handshake histogram
            Constraint::Length(3), // summary bar
            Constraint::Length(3), // footer
        ])
        .split(area);

    let packets = app.packet_collector.get_packets();
    let stats = compute_protocol_stats(&packets);

    render_header(f, chunks[0]);
    render_protocol_table(f, app, &stats, chunks[1]);
    render_handshake_histogram(f, app, chunks[2]);
    render_summary(f, &stats, chunks[3]);
    render_footer(f, chunks[4]);
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

fn render_handshake_histogram(f: &mut Frame, app: &App, area: Rect) {
    let streams = app.packet_collector.get_all_streams();

    // Collect completed handshake times
    let mut latencies: Vec<f64> = streams
        .iter()
        .filter_map(|s| s.handshake.as_ref())
        .filter_map(|hs| hs.total_ms())
        .collect();
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let total = latencies.len();

    if total == 0 {
        let empty = Paragraph::new(" No completed TCP handshakes yet")
            .style(Style::default().fg(Color::DarkGray))
            .block(
                Block::default()
                    .title(" Handshake Latency ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
        f.render_widget(empty, area);
        return;
    }

    // Buckets: <1ms, 1-5ms, 5-10ms, 10-50ms, 50-100ms, 100-500ms, >500ms
    let buckets: &[(&str, f64, f64)] = &[
        ("<1ms",     0.0,    1.0),
        ("1-5ms",    1.0,    5.0),
        ("5-10ms",   5.0,   10.0),
        ("10-50ms", 10.0,   50.0),
        ("50-100ms",50.0,  100.0),
        ("100-500", 100.0, 500.0),
        (">500ms",  500.0, f64::MAX),
    ];

    let counts: Vec<usize> = buckets
        .iter()
        .map(|(_, lo, hi)| {
            latencies.iter().filter(|&&v| v >= *lo && v < *hi).count()
        })
        .collect();

    let max_count = *counts.iter().max().unwrap_or(&1).max(&1);

    // Stats summary
    let min = latencies.first().copied().unwrap_or(0.0);
    let max_val = latencies.last().copied().unwrap_or(0.0);
    let avg = latencies.iter().sum::<f64>() / total as f64;
    let median = latencies[total / 2];
    let p95_idx = ((total as f64 * 0.95) as usize).min(total.saturating_sub(1));
    let p95 = latencies[p95_idx];

    let block = Block::default()
        .title(format!(
            " Handshake Latency ({total} connections) — min:{min:.1}ms  avg:{avg:.1}ms  med:{median:.1}ms  p95:{p95:.1}ms  max:{max_val:.1}ms "
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let avail_width = inner.width.saturating_sub(14) as usize; // label + count columns

    let lines: Vec<Line> = buckets
        .iter()
        .zip(counts.iter())
        .map(|((label, _, _), &count)| {
            let pct = if total > 0 { count as f64 / total as f64 * 100.0 } else { 0.0 };
            let bar_len = if max_count > 0 {
                (count as f64 / max_count as f64 * avail_width as f64).round() as usize
            } else {
                0
            };

            let color = if label.starts_with('<') || label.starts_with("1-") {
                Color::Green
            } else if label.starts_with("5-") || label.starts_with("10") {
                Color::Yellow
            } else if label.starts_with("50") {
                Color::Rgb(255, 165, 0)
            } else {
                Color::Red
            };

            Line::from(vec![
                Span::styled(format!(" {:>8} ", label), Style::default().fg(Color::White)),
                Span::styled("█".repeat(bar_len), Style::default().fg(color)),
                Span::styled(
                    if count > 0 { format!(" {} ({:.0}%)", count, pct) } else { String::new() },
                    Style::default().fg(Color::DarkGray),
                ),
            ])
        })
        .collect();

    let content = Paragraph::new(lines);
    f.render_widget(content, inner);
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
