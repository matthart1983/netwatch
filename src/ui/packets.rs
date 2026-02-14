use crate::app::App;
use crate::collectors::packets::{CapturedPacket, port_label};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header
            Constraint::Min(10),   // packet list
            Constraint::Length(16), // detail pane
            Constraint::Length(3), // footer
        ])
        .split(area);

    render_header(f, app, chunks[0]);
    let packets = app.packet_collector.get_packets();
    render_packet_list(f, app, &packets, chunks[1]);
    render_detail(f, app, &packets, chunks[2]);
    render_footer(f, app, chunks[3]);
}

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let now = chrono::Local::now().format("%H:%M:%S").to_string();
    let cap_status = if app.packet_collector.is_capturing() {
        Span::styled("● CAPTURING", Style::default().fg(Color::Red).bold())
    } else {
        Span::styled("○ STOPPED", Style::default().fg(Color::DarkGray))
    };

    let iface_name = app.capture_interface.as_str();

    let pkt_count = app.packet_collector.get_packets().len();

    let line1 = Line::from(vec![
        Span::styled(" NetWatch ", Style::default().fg(Color::Cyan).bold()),
        Span::raw("│ "),
        Span::raw("[1] Dashboard  [2] Connections  [3] Interfaces  "),
        Span::styled("[4] Packets", Style::default().fg(Color::Yellow).bold()),
        Span::raw("  │ "),
        cap_status,
        Span::raw(format!("  on {iface_name}  ({pkt_count} pkts)  ")),
        Span::styled(now, Style::default().fg(Color::DarkGray)),
    ]);

    let lines = if let Some(e) = app.packet_collector.get_error() {
        vec![
            line1,
            Line::from(vec![
                Span::raw(" ⚠ "),
                Span::styled(e, Style::default().fg(Color::Red).bold()),
            ]),
        ]
    } else {
        vec![line1]
    };

    let header = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(header, area);
}

fn render_packet_list(f: &mut Frame, app: &App, packets: &[CapturedPacket], area: Rect) {
    let header = Row::new(vec![
        Cell::from("#").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Time").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Source").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Destination").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Proto").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Len").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Info").style(Style::default().fg(Color::Cyan).bold()),
    ])
    .height(1);

    let visible_height = area.height.saturating_sub(3) as usize; // borders + header
    let total = packets.len();

    // Auto-scroll to bottom if following, otherwise use manual scroll
    let offset = if app.packet_follow && total > visible_height {
        total - visible_height
    } else {
        app.packet_scroll.min(total.saturating_sub(visible_height))
    };

    let rows: Vec<Row> = packets
        .iter()
        .skip(offset)
        .take(visible_height)
        .map(|pkt| {
            let proto_style = protocol_color(&pkt.protocol);
            let selected = app.packet_selected == Some(pkt.id);
            let row_style = if selected {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };

            // Use stored hostname, or try live cache lookup for late-resolved IPs
            let src_resolved = pkt.src_host.clone()
                .or_else(|| app.packet_collector.dns_cache.lookup(&pkt.src_ip));
            let dst_resolved = pkt.dst_host.clone()
                .or_else(|| app.packet_collector.dns_cache.lookup(&pkt.dst_ip));

            let src_label = src_resolved.as_deref().unwrap_or(&pkt.src_ip);
            let dst_label = dst_resolved.as_deref().unwrap_or(&pkt.dst_ip);

            let src_display = match pkt.src_port {
                Some(p) => {
                    let svc = port_label(p);
                    if svc != "—" { format!("{}:{} ({})", src_label, p, svc) }
                    else { format!("{}:{}", src_label, p) }
                }
                None => src_label.to_string(),
            };
            let dst_display = match pkt.dst_port {
                Some(p) => {
                    let svc = port_label(p);
                    if svc != "—" { format!("{}:{} ({})", dst_label, p, svc) }
                    else { format!("{}:{}", dst_label, p) }
                }
                None => dst_label.to_string(),
            };

            Row::new(vec![
                Cell::from(pkt.id.to_string()).style(Style::default().fg(Color::DarkGray)),
                Cell::from(pkt.timestamp.clone()),
                Cell::from(src_display),
                Cell::from(dst_display),
                Cell::from(pkt.protocol.clone()).style(proto_style),
                Cell::from(pkt.length.to_string()),
                Cell::from(pkt.info.clone()),
            ])
            .style(row_style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Length(13),
            Constraint::Length(30),
            Constraint::Length(30),
            Constraint::Length(7),
            Constraint::Length(5),
            Constraint::Min(30),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(format!(" Packets ({total}) "))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    f.render_widget(table, area);
}

fn render_detail(f: &mut Frame, app: &App, packets: &[CapturedPacket], area: Rect) {
    let selected_pkt = app
        .packet_selected
        .and_then(|id| packets.iter().find(|p| p.id == id));

    match selected_pkt {
        Some(pkt) => {
            let detail_height = (pkt.details.len() as u16 + 2).min(area.height.saturating_sub(4));
            let has_payload = !pkt.payload_text.is_empty();

            let rows = if has_payload {
                Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(detail_height),
                        Constraint::Min(3),
                        Constraint::Min(3),
                    ])
                    .split(area)
            } else {
                Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(detail_height),
                        Constraint::Min(4),
                    ])
                    .split(area)
            };

            // Protocol detail lines with color per layer
            let detail_lines: Vec<Line> = pkt.details.iter().map(|line| {
                let color = if line.starts_with("Frame:") {
                    Color::White
                } else if line.starts_with("Ethernet:") {
                    Color::Cyan
                } else if line.starts_with("IPv4:") || line.starts_with("IPv6:") {
                    Color::Green
                } else if line.starts_with("TCP:") || line.starts_with("UDP:") {
                    Color::Magenta
                } else if line.starts_with("ICMP") {
                    Color::Yellow
                } else {
                    Color::LightYellow
                };
                Line::from(Span::styled(format!("  {line}"), Style::default().fg(color)))
            }).collect();

            let proto_detail = Paragraph::new(detail_lines)
                .block(
                    Block::default()
                        .title(" Protocol Detail ")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::DarkGray)),
                );
            f.render_widget(proto_detail, rows[0]);

            if has_payload {
                // Payload content (readable text)
                let payload = Paragraph::new(pkt.payload_text.clone())
                    .style(Style::default().fg(Color::White))
                    .block(
                        Block::default()
                            .title(" Payload Content ")
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(Color::DarkGray)),
                    )
                    .wrap(Wrap { trim: false });
                f.render_widget(payload, rows[1]);

                // Hex + ASCII side by side
                let hex_ascii = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                    .split(rows[2]);

                render_hex_ascii(f, pkt, hex_ascii);
            } else {
                // Hex + ASCII side by side (no payload text)
                let hex_ascii = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                    .split(rows[1]);

                render_hex_ascii(f, pkt, hex_ascii);
            }
        }
        None => {
            let hint = Paragraph::new(" Select a packet with ↑↓ to inspect")
                .style(Style::default().fg(Color::DarkGray))
                .block(
                    Block::default()
                        .title(" Packet Detail ")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::DarkGray)),
                );
            f.render_widget(hint, area);
        }
    }
}

fn render_hex_ascii(f: &mut Frame, pkt: &CapturedPacket, chunks: std::rc::Rc<[Rect]>) {
    let hex = Paragraph::new(pkt.raw_hex.clone())
        .style(Style::default().fg(Color::Green))
        .block(
            Block::default()
                .title(" Hex Dump ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(hex, chunks[0]);

    let ascii = Paragraph::new(pkt.raw_ascii.clone())
        .style(Style::default().fg(Color::Yellow))
        .block(
            Block::default()
                .title(" ASCII ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(ascii, chunks[1]);
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let capture_key = if app.packet_collector.is_capturing() {
        "c:Stop"
    } else {
        "c:Capture"
    };

    let follow_indicator = if app.packet_follow {
        Span::styled(" [FOLLOW]", Style::default().fg(Color::Green).bold())
    } else {
        Span::raw("")
    };

    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" q", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Quit  "),
        Span::styled("c", Style::default().fg(Color::Yellow).bold()),
        Span::raw(format!(":{capture_key}  ")),
        Span::styled("i", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Interface  "),
        Span::styled("x", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Clear  "),
        Span::styled("↑↓", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Scroll  "),
        Span::styled("Enter", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Inspect  "),
        Span::styled("f", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Follow  "),
        Span::styled("1-4", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Tab"),
        follow_indicator,
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
