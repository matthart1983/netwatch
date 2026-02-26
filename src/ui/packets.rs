use crate::app::{App, StreamDirectionFilter};
use crate::collectors::packets::{CapturedPacket, ExpertSeverity, StreamDirection, parse_filter, matches_packet, port_label};
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

    let packets = app.packet_collector.get_packets();
    render_header(f, app, chunks[0], packets.len());
    render_packet_list(f, app, &packets, chunks[1]);
    if app.stream_view_open {
        render_stream_view(f, app, chunks[2]);
    } else {
        render_detail(f, app, &packets, chunks[2]);
    }
    render_footer(f, app, chunks[3]);
}

fn render_header(f: &mut Frame, app: &App, area: Rect, pkt_count: usize) {
    let now = chrono::Local::now().format("%H:%M:%S").to_string();
    let cap_status = if app.packet_collector.is_capturing() {
        Span::styled("● CAPTURING", Style::default().fg(Color::Red).bold())
    } else {
        Span::styled("○ STOPPED", Style::default().fg(Color::DarkGray))
    };

    let iface_name = app.capture_interface.as_str();

    let mut line1_spans = vec![
        Span::styled(" NetWatch ", Style::default().fg(Color::Cyan).bold()),
        Span::raw("│ "),
        Span::raw("[1] Dashboard  [2] Connections  [3] Interfaces  "),
        Span::styled("[4] Packets", Style::default().fg(Color::Yellow).bold()),
        Span::raw("  [5] Stats  [6] Topology  [7] Timeline  [8] Insights"),
        Span::raw("  │ "),
        cap_status,
        Span::raw(format!("  on {iface_name}  ({pkt_count} pkts)  ")),
    ];
    if let Some(ref bpf) = app.bpf_filter_active {
        line1_spans.push(Span::styled("BPF: ", Style::default().fg(Color::Yellow).bold()));
        line1_spans.push(Span::styled(bpf.clone(), Style::default().fg(Color::White)));
        line1_spans.push(Span::raw("  "));
    }
    line1_spans.push(Span::styled(now, Style::default().fg(Color::DarkGray)));
    let line1 = Line::from(line1_spans);

    let lines = if let Some(e) = app.packet_collector.get_error() {
        vec![
            line1,
            Line::from(vec![
                Span::raw(" ⚠ "),
                Span::styled(e, Style::default().fg(Color::Red).bold()),
            ]),
        ]
    } else if let Some(ref status) = app.export_status {
        vec![
            line1,
            Line::from(vec![
                Span::raw(" ✓ "),
                Span::styled(status.clone(), Style::default().fg(Color::Green).bold()),
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
        Cell::from("!").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("#").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Time").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Source").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Destination").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Proto").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Len").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Stream").style(Style::default().fg(Color::Cyan).bold()),
        Cell::from("Info").style(Style::default().fg(Color::Cyan).bold()),
    ])
    .height(1);

    // Apply display filter
    let filter_text = app.packet_filter_active.as_deref()
        .or(if app.packet_filter_input { Some(app.packet_filter_text.as_str()) } else { None });
    let filter_expr = filter_text.and_then(|t| parse_filter(t));

    let filtered: Vec<&CapturedPacket> = if let Some(ref expr) = filter_expr {
        packets.iter().filter(|p| matches_packet(expr, p)).collect()
    } else {
        packets.iter().collect()
    };

    let visible_height = area.height.saturating_sub(3) as usize;
    let total_all = packets.len();
    let total = filtered.len();

    let offset = if app.packet_follow && total > visible_height {
        total - visible_height
    } else {
        app.packet_scroll.min(total.saturating_sub(visible_height))
    };

    let rows: Vec<Row> = filtered
        .iter()
        .skip(offset)
        .take(visible_height)
        .map(|pkt| {
            let proto_style = protocol_color(&pkt.protocol);
            let selected = app.packet_selected == Some(pkt.id);
            let row_style = if selected {
                Style::default().bg(Color::DarkGray)
            } else {
                expert_row_style(pkt.expert)
            };

            let is_bookmarked = app.bookmarks.contains(&pkt.id);
            let (expert_icon, expert_style) = if is_bookmarked {
                ("★", Style::default().fg(Color::Yellow).bold())
            } else {
                expert_indicator(pkt.expert)
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

            let stream_label = pkt.stream_index
                .map(|i| format!("#{i}"))
                .unwrap_or_default();

            Row::new(vec![
                Cell::from(expert_icon).style(expert_style),
                Cell::from(pkt.id.to_string()).style(Style::default().fg(Color::DarkGray)),
                Cell::from(pkt.timestamp.clone()),
                Cell::from(src_display),
                Cell::from(dst_display),
                Cell::from(pkt.protocol.clone()).style(proto_style),
                Cell::from(pkt.length.to_string()),
                Cell::from(stream_label).style(Style::default().fg(Color::DarkGray)),
                Cell::from(pkt.info.clone()),
            ])
            .style(row_style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(2),
            Constraint::Length(6),
            Constraint::Length(13),
            Constraint::Length(28),
            Constraint::Length(28),
            Constraint::Length(7),
            Constraint::Length(5),
            Constraint::Length(7),
            Constraint::Min(25),
        ],
    )
    .header(header)
    .block({
        let bm_count = app.bookmarks.len();
        let bm_label = if bm_count > 0 {
            format!(" ★{bm_count}")
        } else {
            String::new()
        };
        let title = if filter_expr.is_some() {
            format!(" Packets ({total} / {total_all}){bm_label} ")
        } else {
            format!(" Packets ({total_all}){bm_label} ")
        };
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
    });

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

            // Geo info lines (if enabled)
            let mut geo_lines: Vec<Line> = Vec::new();
            if app.show_geo {
                for (label, ip) in [("Src", &pkt.src_ip), ("Dst", &pkt.dst_ip)] {
                    if let Some(geo) = app.geo_cache.lookup(ip) {
                        let loc = if geo.city.is_empty() {
                            format!("{} ({})", geo.country, geo.country_code)
                        } else {
                            format!("{}, {} ({})", geo.city, geo.country, geo.country_code)
                        };
                        let org = if geo.org.is_empty() { String::new() } else { format!(" — {}", geo.org) };
                        geo_lines.push(Line::from(Span::styled(
                            format!("  Geo {label}: {loc}{org}"),
                            Style::default().fg(Color::LightBlue),
                        )));
                    }
                }
            }

            // Whois info lines (on-demand)
            let mut whois_lines: Vec<Line> = Vec::new();
            for (label, ip) in [("Src", &pkt.src_ip), ("Dst", &pkt.dst_ip)] {
                if let Some(whois) = app.whois_cache.lookup(ip) {
                    let mut parts = Vec::new();
                    if !whois.net_name.is_empty() { parts.push(whois.net_name.clone()); }
                    if !whois.org.is_empty() { parts.push(whois.org.clone()); }
                    if !whois.net_range.is_empty() { parts.push(whois.net_range.clone()); }
                    if !whois.country.is_empty() { parts.push(whois.country.clone()); }
                    let summary = parts.join(" │ ");
                    whois_lines.push(Line::from(Span::styled(
                        format!("  Whois {label}: {summary}"),
                        Style::default().fg(Color::LightMagenta),
                    )));
                    if !whois.description.is_empty() {
                        whois_lines.push(Line::from(Span::styled(
                            format!("         {}", whois.description),
                            Style::default().fg(Color::DarkGray),
                        )));
                    }
                }
            }

            // Protocol detail lines with color per layer
            let mut detail_lines: Vec<Line> = pkt.details.iter().map(|line| {
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
            detail_lines.extend(geo_lines);
            detail_lines.extend(whois_lines);

            // TCP handshake timing (if this packet belongs to a stream with handshake data)
            if let Some(stream_idx) = pkt.stream_index {
                if let Some(stream) = app.packet_collector.get_stream(stream_idx) {
                    if let Some(ref hs) = stream.handshake {
                        let mut hs_parts = Vec::new();
                        if let Some(syn_sa) = hs.syn_to_syn_ack_ms() {
                            hs_parts.push(format!("SYN→SYN-ACK: {:.2}ms", syn_sa));
                        }
                        if let Some(sa_ack) = hs.syn_ack_to_ack_ms() {
                            hs_parts.push(format!("SYN-ACK→ACK: {:.2}ms", sa_ack));
                        }
                        if let Some(total) = hs.total_ms() {
                            hs_parts.push(format!("Total: {:.2}ms", total));
                        }
                        if !hs_parts.is_empty() {
                            detail_lines.push(Line::from(Span::styled(
                                format!("  ⏱ Handshake: {}", hs_parts.join("  │  ")),
                                Style::default().fg(Color::Green),
                            )));
                        }
                    }
                }
            }

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

fn render_stream_view(f: &mut Frame, app: &App, area: Rect) {
    let stream_index = match app.stream_view_index {
        Some(idx) => idx,
        None => {
            let hint = Paragraph::new(" No stream selected")
                .style(Style::default().fg(Color::DarkGray))
                .block(Block::default().title(" Stream View ").borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)));
            f.render_widget(hint, area);
            return;
        }
    };

    let stream = match app.packet_collector.get_stream(stream_index) {
        Some(s) => s,
        None => {
            let hint = Paragraph::new(format!(" Stream #{stream_index} not found"))
                .style(Style::default().fg(Color::Red))
                .block(Block::default().title(" Stream View ").borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)));
            f.render_widget(hint, area);
            return;
        }
    };

    let proto_str = if stream.key.protocol == crate::collectors::packets::StreamProtocol::Tcp {
        "TCP"
    } else {
        "UDP"
    };
    let (a_ip, a_port) = &stream.key.addr_a;
    let (b_ip, b_port) = &stream.key.addr_b;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // stream header
            Constraint::Min(5),   // stream content
            Constraint::Length(2), // stream status bar
        ])
        .split(area);

    // Header with direction filter indicators
    let dir_label = match app.stream_direction_filter {
        StreamDirectionFilter::Both => "[a] Both",
        StreamDirectionFilter::AtoB => "[→] A→B",
        StreamDirectionFilter::BtoA => "[←] B→A",
    };
    let mode_label = if app.stream_hex_mode { "Hex" } else { "Text" };
    let mut header_spans = vec![
        Span::styled(format!(" {proto_str} Stream #{stream_index} "), Style::default().fg(Color::Cyan).bold()),
        Span::raw(format!("── {a_ip}:{a_port} ↔ {b_ip}:{b_port}  ")),
        Span::styled(dir_label, Style::default().fg(Color::Yellow)),
        Span::raw("  "),
        Span::styled(format!("[h] {mode_label}"), Style::default().fg(Color::Yellow)),
    ];
    if let Some(ref hs) = stream.handshake {
        header_spans.push(Span::raw("  "));
        if let Some(total) = hs.total_ms() {
            header_spans.push(Span::styled(
                format!("⏱ {:.2}ms", total),
                Style::default().fg(Color::Green).bold(),
            ));
        } else if let Some(syn_sa) = hs.syn_to_syn_ack_ms() {
            header_spans.push(Span::styled(
                format!("⏱ SYN→SA {:.2}ms", syn_sa),
                Style::default().fg(Color::Yellow),
            ));
        } else {
            header_spans.push(Span::styled(
                "⏱ SYN…",
                Style::default().fg(Color::DarkGray),
            ));
        }
    }
    let header = Paragraph::new(Line::from(header_spans))
        .block(Block::default().borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::DarkGray)));
    f.render_widget(header, chunks[0]);

    // Build content lines
    let filtered_segments: Vec<_> = stream.segments.iter().filter(|seg| {
        match app.stream_direction_filter {
            StreamDirectionFilter::Both => true,
            StreamDirectionFilter::AtoB => seg.direction == StreamDirection::AtoB,
            StreamDirectionFilter::BtoA => seg.direction == StreamDirection::BtoA,
        }
    }).collect();

    let content_lines: Vec<Line> = if app.stream_hex_mode {
        // Hex mode: concatenated hex dump of all segment payloads
        let mut lines = Vec::new();
        for seg in &filtered_segments {
            let arrow = match seg.direction {
                StreamDirection::AtoB => "→",
                StreamDirection::BtoA => "←",
            };
            let arrow_color = match seg.direction {
                StreamDirection::AtoB => Color::Green,
                StreamDirection::BtoA => Color::Magenta,
            };
            for chunk in seg.payload.chunks(16) {
                let hex: String = chunk.iter().map(|b| format!("{b:02x} ")).collect();
                let ascii: String = chunk.iter().map(|&b| {
                    if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }
                }).collect();
                lines.push(Line::from(vec![
                    Span::styled(format!(" {arrow} "), Style::default().fg(arrow_color)),
                    Span::styled(format!("{:<50}", hex), Style::default().fg(Color::Green)),
                    Span::styled(ascii, Style::default().fg(Color::Yellow)),
                ]));
            }
        }
        lines
    } else {
        // Text mode: payload as readable text with direction arrows
        let mut lines = Vec::new();
        for seg in &filtered_segments {
            let arrow = match seg.direction {
                StreamDirection::AtoB => "→",
                StreamDirection::BtoA => "←",
            };
            let arrow_color = match seg.direction {
                StreamDirection::AtoB => Color::Green,
                StreamDirection::BtoA => Color::Magenta,
            };
            let text: String = seg.payload.iter().map(|&b| {
                if b.is_ascii_graphic() || b == b' ' || b == b'\t' { b as char }
                else if b == b'\n' || b == b'\r' { '\n' }
                else { '·' }
            }).collect();
            for text_line in text.lines() {
                lines.push(Line::from(vec![
                    Span::styled(format!(" {arrow} "), Style::default().fg(arrow_color)),
                    Span::raw(text_line.to_string()),
                ]));
            }
        }
        lines
    };

    let visible_height = chunks[1].height.saturating_sub(2) as usize;
    let total_lines = content_lines.len();
    let max_scroll = total_lines.saturating_sub(visible_height);
    let scroll = app.stream_scroll.min(max_scroll);

    let visible_lines: Vec<Line> = content_lines.into_iter()
        .skip(scroll)
        .take(visible_height)
        .collect();

    let content = Paragraph::new(visible_lines)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)))
        .wrap(Wrap { trim: false });
    f.render_widget(content, chunks[1]);

    // Status bar
    let mut status_spans = vec![
        Span::styled(format!(" {} packets", stream.packet_count), Style::default().fg(Color::White)),
        Span::raw(format!(", {} segments", filtered_segments.len())),
        Span::raw(" │ "),
        Span::styled("A→B: ", Style::default().fg(Color::Green)),
        Span::raw(format_bytes(stream.total_bytes_a_to_b)),
        Span::raw(" │ "),
        Span::styled("B→A: ", Style::default().fg(Color::Magenta)),
        Span::raw(format_bytes(stream.total_bytes_b_to_a)),
    ];
    if let Some(ref hs) = stream.handshake {
        status_spans.push(Span::raw(" │ "));
        if let Some(syn_sa) = hs.syn_to_syn_ack_ms() {
            status_spans.push(Span::styled(
                format!("SYN→SA:{:.1}ms ", syn_sa),
                Style::default().fg(Color::Cyan),
            ));
        }
        if let Some(sa_ack) = hs.syn_ack_to_ack_ms() {
            status_spans.push(Span::styled(
                format!("SA→ACK:{:.1}ms ", sa_ack),
                Style::default().fg(Color::Cyan),
            ));
        }
        if let Some(total) = hs.total_ms() {
            status_spans.push(Span::styled(
                format!("Total:{:.1}ms", total),
                Style::default().fg(Color::Green),
            ));
        }
    }
    status_spans.push(Span::raw(format!(" │ Lines: {total_lines} ")));
    let status = Paragraph::new(Line::from(status_spans))
        .block(Block::default().borders(Borders::TOP)
            .border_style(Style::default().fg(Color::DarkGray)));
    f.render_widget(status, chunks[2]);
}

fn format_bytes(b: u64) -> String {
    if b < 1024 { format!("{b} B") }
    else if b < 1024 * 1024 { format!("{:.1} KB", b as f64 / 1024.0) }
    else { format!("{:.1} MB", b as f64 / (1024.0 * 1024.0)) }
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    // Filter input mode — show editable filter bar
    if app.packet_filter_input {
        let filter_line = Line::from(vec![
            Span::styled(" / ", Style::default().fg(Color::Cyan).bold()),
            Span::raw(&app.packet_filter_text),
            Span::styled("█", Style::default().fg(Color::White)),
        ]);
        let bar = Paragraph::new(filter_line)
            .block(Block::default().borders(Borders::TOP)
                .border_style(Style::default().fg(Color::Yellow)));
        f.render_widget(bar, area);
        return;
    }

    // BPF filter input mode
    if app.bpf_filter_input {
        let filter_line = Line::from(vec![
            Span::styled(" BPF: ", Style::default().fg(Color::Magenta).bold()),
            Span::raw(&app.bpf_filter_text),
            Span::styled("█", Style::default().fg(Color::White)),
        ]);
        let bar = Paragraph::new(filter_line)
            .block(Block::default().borders(Borders::TOP)
                .border_style(Style::default().fg(Color::Magenta)));
        f.render_widget(bar, area);
        return;
    }

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

    let filter_indicator = if let Some(ref ft) = app.packet_filter_active {
        vec![
            Span::styled(" [FILTER: ", Style::default().fg(Color::Yellow).bold()),
            Span::styled(ft.clone(), Style::default().fg(Color::White)),
            Span::styled("]", Style::default().fg(Color::Yellow).bold()),
        ]
    } else {
        vec![]
    };

    let mut hints = if app.stream_view_open {
        vec![
            Span::styled(" Esc", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Close  "),
            Span::styled("↑↓", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Scroll  "),
            Span::styled("→←", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Direction  "),
            Span::styled("a", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Both  "),
            Span::styled("h", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Hex/Text"),
        ]
    } else {
        vec![
            Span::styled(" q", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Quit  "),
            Span::styled("a", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Analyze  "),
            Span::styled("c", Style::default().fg(Color::Yellow).bold()),
            Span::raw(format!(":{capture_key}  ")),
            Span::styled("/", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Filter  "),
            Span::styled("s", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Stream  "),
            Span::styled("b", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":BPF  "),
            Span::styled("w", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Save  "),
            Span::styled("f", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Follow  "),
            Span::styled("m", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Bookmark  "),
            Span::styled("n/N", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Next/Prev  "),
            Span::styled("W", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Whois  "),
            Span::styled("p", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Pause  "),
            Span::styled("r", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Refresh  "),
            Span::styled("1-8", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Tab  "),
            Span::styled("g", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Geo  "),
            Span::styled("?", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Help"),
            follow_indicator,
        ]
    };
    hints.extend(filter_indicator);

    let footer = Paragraph::new(Line::from(hints))
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

fn expert_indicator(severity: ExpertSeverity) -> (&'static str, Style) {
    match severity {
        ExpertSeverity::Error => ("●", Style::default().fg(Color::Red).bold()),
        ExpertSeverity::Warn  => ("▲", Style::default().fg(Color::Yellow)),
        ExpertSeverity::Note  => ("·", Style::default().fg(Color::Cyan)),
        ExpertSeverity::Chat  => (" ", Style::default()),
    }
}

fn expert_row_style(severity: ExpertSeverity) -> Style {
    match severity {
        ExpertSeverity::Error => Style::default().fg(Color::Red),
        ExpertSeverity::Warn  => Style::default().fg(Color::Yellow),
        _ => Style::default(),
    }
}
