use crate::app::{App, StreamDirectionFilter};
use crate::collectors::packets::{
    matches_packet, parse_filter, port_label, CapturedPacket, ExpertSeverity, StreamDirection,
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header
            Constraint::Min(10),    // packet list
            Constraint::Length(16), // detail pane
            Constraint::Length(3),  // footer
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
    let cap_status = if app.packet_collector.is_capturing() {
        Span::styled(
            "● CAPTURING",
            Style::default().fg(app.theme.status_error).bold(),
        )
    } else {
        Span::styled("○ STOPPED", Style::default().fg(app.theme.text_muted))
    };

    let iface_name = app.capture_interface.as_str();

    let mut extra = vec![
        Span::raw("  "),
        cap_status,
        Span::raw(format!("  on {iface_name}  ({pkt_count} pkts)")),
    ];
    if let Some(ref bpf) = app.bpf_filter_active {
        extra.push(Span::raw("  "));
        extra.push(Span::styled(
            "BPF: ",
            Style::default().fg(app.theme.key_hint).bold(),
        ));
        extra.push(Span::styled(
            bpf.clone(),
            Style::default().fg(app.theme.text_primary),
        ));
    }

    if let Some(e) = app.packet_collector.get_error() {
        let line1 = crate::ui::widgets::build_header_line(app, Some(extra));
        let lines = vec![
            line1,
            Line::from(vec![
                Span::raw(" ⚠ "),
                Span::styled(e, Style::default().fg(app.theme.status_error).bold()),
            ]),
        ];
        let header = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(app.theme.border)),
        );
        f.render_widget(header, area);
    } else if let Some(ref status) = app.export_status {
        let line1 = crate::ui::widgets::build_header_line(app, Some(extra));
        let lines = vec![
            line1,
            Line::from(vec![
                Span::raw(" ✓ "),
                Span::styled(
                    status.clone(),
                    Style::default().fg(app.theme.status_good).bold(),
                ),
            ]),
        ];
        let header = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(app.theme.border)),
        );
        f.render_widget(header, area);
    } else {
        crate::ui::widgets::render_header_with_extra(f, app, area, extra);
    }
}

fn truncate_info(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max - 1).collect();
        format!("{}…", truncated)
    }
}

fn render_packet_list(f: &mut Frame, app: &App, packets: &[CapturedPacket], area: Rect) {
    let header = Row::new(vec![
        Cell::from("!").style(Style::default().fg(app.theme.brand).bold()),
        Cell::from("#").style(Style::default().fg(app.theme.brand).bold()),
        Cell::from("Time").style(Style::default().fg(app.theme.brand).bold()),
        Cell::from("Source").style(Style::default().fg(app.theme.brand).bold()),
        Cell::from("Destination").style(Style::default().fg(app.theme.brand).bold()),
        Cell::from("Proto").style(Style::default().fg(app.theme.brand).bold()),
        Cell::from("Len").style(Style::default().fg(app.theme.brand).bold()),
        Cell::from("Stream").style(Style::default().fg(app.theme.brand).bold()),
        Cell::from("Info").style(Style::default().fg(app.theme.brand).bold()),
    ])
    .height(1);

    // Apply display filter
    let filter_text = app
        .packet_filter_active
        .as_deref()
        .or(if app.packet_filter_input {
            Some(app.packet_filter_text.as_str())
        } else {
            None
        });
    let filter_expr = filter_text.and_then(parse_filter);

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
        app.scroll
            .packet_scroll
            .min(total.saturating_sub(visible_height))
    };

    let rows: Vec<Row> = filtered
        .iter()
        .skip(offset)
        .take(visible_height)
        .map(|pkt| {
            let proto_style = protocol_color(&pkt.protocol, &app.theme);
            let selected = app.scroll.packet_selected == Some(pkt.id);
            let row_style = if selected {
                Style::default().bg(app.theme.selection_bg)
            } else {
                expert_row_style(pkt.expert, &app.theme)
            };

            let is_bookmarked = app.bookmarks.contains(&pkt.id);
            let (expert_icon, expert_style) = if is_bookmarked {
                ("★", Style::default().fg(app.theme.status_warn).bold())
            } else {
                expert_indicator(pkt.expert, &app.theme)
            };

            // Use stored hostname, or try live cache lookup for late-resolved IPs
            let src_resolved = pkt
                .src_host
                .clone()
                .or_else(|| app.packet_collector.dns_cache.lookup(&pkt.src_ip));
            let dst_resolved = pkt
                .dst_host
                .clone()
                .or_else(|| app.packet_collector.dns_cache.lookup(&pkt.dst_ip));

            let src_label = src_resolved.as_deref().unwrap_or(&pkt.src_ip);
            let dst_label = dst_resolved.as_deref().unwrap_or(&pkt.dst_ip);

            let src_display = match pkt.src_port {
                Some(p) => {
                    let svc = port_label(p);
                    if svc != "—" {
                        format!("{}:{} ({})", src_label, p, svc)
                    } else {
                        format!("{}:{}", src_label, p)
                    }
                }
                None => src_label.to_string(),
            };
            let dst_display = match pkt.dst_port {
                Some(p) => {
                    let svc = port_label(p);
                    if svc != "—" {
                        format!("{}:{} ({})", dst_label, p, svc)
                    } else {
                        format!("{}:{}", dst_label, p)
                    }
                }
                None => dst_label.to_string(),
            };

            let stream_label = pkt
                .stream_index
                .map(|i| format!("#{i}"))
                .unwrap_or_default();

            Row::new(vec![
                Cell::from(expert_icon).style(expert_style),
                Cell::from(pkt.id.to_string()).style(Style::default().fg(app.theme.text_muted)),
                Cell::from(pkt.timestamp.clone()),
                Cell::from(src_display),
                Cell::from(dst_display),
                Cell::from(pkt.protocol.clone()).style(proto_style),
                Cell::from(pkt.length.to_string()),
                Cell::from(stream_label).style(Style::default().fg(app.theme.text_muted)),
                Cell::from(truncate_info(&pkt.info, 40)),
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
            .title(Line::from(Span::styled(
                title,
                Style::default().fg(app.theme.brand).bold(),
            )))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border))
    });

    f.render_widget(table, area);
}

fn render_detail(f: &mut Frame, app: &App, packets: &[CapturedPacket], area: Rect) {
    let selected_pkt = app
        .scroll
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
                    .constraints([Constraint::Length(detail_height), Constraint::Min(4)])
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
                        let org = if geo.org.is_empty() {
                            String::new()
                        } else {
                            format!(" — {}", geo.org)
                        };
                        geo_lines.push(Line::from(Span::styled(
                            format!("  Geo {label}: {loc}{org}"),
                            Style::default().fg(app.theme.status_info),
                        )));
                    }
                }
            }

            // Whois info lines (on-demand)
            let mut whois_lines: Vec<Line> = Vec::new();
            for (label, ip) in [("Src", &pkt.src_ip), ("Dst", &pkt.dst_ip)] {
                if let Some(whois) = app.whois_cache.lookup(ip) {
                    let mut parts = Vec::new();
                    if !whois.net_name.is_empty() {
                        parts.push(whois.net_name.clone());
                    }
                    if !whois.org.is_empty() {
                        parts.push(whois.org.clone());
                    }
                    if !whois.net_range.is_empty() {
                        parts.push(whois.net_range.clone());
                    }
                    if !whois.country.is_empty() {
                        parts.push(whois.country.clone());
                    }
                    let summary = parts.join(" │ ");
                    whois_lines.push(Line::from(Span::styled(
                        format!("  Whois {label}: {summary}"),
                        Style::default().fg(Color::LightMagenta),
                    )));
                    if !whois.description.is_empty() {
                        whois_lines.push(Line::from(Span::styled(
                            format!("         {}", whois.description),
                            Style::default().fg(app.theme.text_muted),
                        )));
                    }
                }
            }

            // Protocol detail lines with color per layer
            let mut detail_lines: Vec<Line> = pkt
                .details
                .iter()
                .map(|line| {
                    let color = if line.starts_with("Frame:") {
                        app.theme.text_primary
                    } else if line.starts_with("Ethernet:") {
                        app.theme.brand
                    } else if line.starts_with("IPv4:") || line.starts_with("IPv6:") {
                        app.theme.status_good
                    } else if line.starts_with("TCP:") || line.starts_with("UDP:") {
                        Color::Magenta
                    } else if line.starts_with("ICMP") {
                        app.theme.status_warn
                    } else {
                        Color::LightYellow
                    };
                    Line::from(Span::styled(
                        format!("  {line}"),
                        Style::default().fg(color),
                    ))
                })
                .collect();
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
                                Style::default().fg(app.theme.status_good),
                            )));
                        }
                    }
                }
            }

            let proto_detail = Paragraph::new(detail_lines).block(
                Block::default()
                    .title(Line::from(Span::styled(
                        " Protocol Detail ",
                        Style::default().fg(app.theme.brand).bold(),
                    )))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(app.theme.border)),
            );
            f.render_widget(proto_detail, rows[0]);

            if has_payload {
                // Payload content (readable text)
                let payload = Paragraph::new(pkt.payload_text.clone())
                    .style(Style::default().fg(app.theme.text_primary))
                    .block(
                        Block::default()
                            .title(Line::from(Span::styled(
                                " Payload Content ",
                                Style::default().fg(app.theme.brand).bold(),
                            )))
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(app.theme.border)),
                    )
                    .wrap(Wrap { trim: false });
                f.render_widget(payload, rows[1]);

                // Hex + ASCII side by side
                let hex_ascii = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                    .split(rows[2]);

                render_hex_ascii(f, pkt, hex_ascii, &app.theme);
            } else {
                // Hex + ASCII side by side (no payload text)
                let hex_ascii = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                    .split(rows[1]);

                render_hex_ascii(f, pkt, hex_ascii, &app.theme);
            }
        }
        None => {
            let hint = Paragraph::new(" Select a packet with ↑↓ to inspect")
                .style(Style::default().fg(app.theme.text_muted))
                .block(
                    Block::default()
                        .title(Line::from(Span::styled(
                            " Packet Detail ",
                            Style::default().fg(app.theme.brand).bold(),
                        )))
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(app.theme.border)),
                );
            f.render_widget(hint, area);
        }
    }
}

fn render_hex_ascii(
    f: &mut Frame,
    pkt: &CapturedPacket,
    chunks: std::rc::Rc<[Rect]>,
    theme: &crate::theme::Theme,
) {
    let hex = Paragraph::new(pkt.raw_hex.clone())
        .style(Style::default().fg(theme.status_good))
        .block(
            Block::default()
                .title(Line::from(Span::styled(
                    " Hex Dump ",
                    Style::default().fg(theme.brand).bold(),
                )))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border)),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(hex, chunks[0]);

    let ascii = Paragraph::new(pkt.raw_ascii.clone())
        .style(Style::default().fg(theme.status_warn))
        .block(
            Block::default()
                .title(Line::from(Span::styled(
                    " ASCII ",
                    Style::default().fg(theme.brand).bold(),
                )))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border)),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(ascii, chunks[1]);
}

fn render_stream_view(f: &mut Frame, app: &App, area: Rect) {
    let stream_index = match app.stream_view_index {
        Some(idx) => idx,
        None => {
            let hint = Paragraph::new(" No stream selected")
                .style(Style::default().fg(app.theme.text_muted))
                .block(
                    Block::default()
                        .title(Line::from(Span::styled(
                            " Stream View ",
                            Style::default().fg(app.theme.brand).bold(),
                        )))
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(app.theme.border)),
                );
            f.render_widget(hint, area);
            return;
        }
    };

    let stream = match app.packet_collector.get_stream(stream_index) {
        Some(s) => s,
        None => {
            let hint = Paragraph::new(format!(" Stream #{stream_index} not found"))
                .style(Style::default().fg(app.theme.status_error))
                .block(
                    Block::default()
                        .title(Line::from(Span::styled(
                            " Stream View ",
                            Style::default().fg(app.theme.brand).bold(),
                        )))
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(app.theme.border)),
                );
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
            Constraint::Min(5),    // stream content
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
        Span::styled(
            format!(" {proto_str} Stream #{stream_index} "),
            Style::default().fg(app.theme.brand).bold(),
        ),
        Span::raw(format!("── {a_ip}:{a_port} ↔ {b_ip}:{b_port}  ")),
        Span::styled(dir_label, Style::default().fg(app.theme.key_hint)),
        Span::raw("  "),
        Span::styled(
            format!("[h] {mode_label}"),
            Style::default().fg(app.theme.key_hint),
        ),
    ];
    if let Some(ref hs) = stream.handshake {
        header_spans.push(Span::raw("  "));
        if let Some(total) = hs.total_ms() {
            header_spans.push(Span::styled(
                format!("⏱ {:.2}ms", total),
                Style::default().fg(app.theme.status_good).bold(),
            ));
        } else if let Some(syn_sa) = hs.syn_to_syn_ack_ms() {
            header_spans.push(Span::styled(
                format!("⏱ SYN→SA {:.2}ms", syn_sa),
                Style::default().fg(app.theme.status_warn),
            ));
        } else {
            header_spans.push(Span::styled(
                "⏱ SYN…",
                Style::default().fg(app.theme.text_muted),
            ));
        }
    }
    let header = Paragraph::new(Line::from(header_spans)).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(app.theme.border)),
    );
    f.render_widget(header, chunks[0]);

    // Build content lines
    let filtered_segments: Vec<_> = stream
        .segments
        .iter()
        .filter(|seg| match app.stream_direction_filter {
            StreamDirectionFilter::Both => true,
            StreamDirectionFilter::AtoB => seg.direction == StreamDirection::AtoB,
            StreamDirectionFilter::BtoA => seg.direction == StreamDirection::BtoA,
        })
        .collect();

    let content_lines: Vec<Line> = if app.stream_hex_mode {
        // Hex mode: concatenated hex dump of all segment payloads
        let mut lines = Vec::new();
        for seg in &filtered_segments {
            let arrow = match seg.direction {
                StreamDirection::AtoB => "→",
                StreamDirection::BtoA => "←",
            };
            let arrow_color = match seg.direction {
                StreamDirection::AtoB => app.theme.status_good,
                StreamDirection::BtoA => Color::Magenta,
            };
            for chunk in seg.payload.chunks(16) {
                let hex: String = chunk.iter().map(|b| format!("{b:02x} ")).collect();
                let ascii: String = chunk
                    .iter()
                    .map(|&b| {
                        if b.is_ascii_graphic() || b == b' ' {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                lines.push(Line::from(vec![
                    Span::styled(format!(" {arrow} "), Style::default().fg(arrow_color)),
                    Span::styled(
                        format!("{:<50}", hex),
                        Style::default().fg(app.theme.status_good),
                    ),
                    Span::styled(ascii, Style::default().fg(app.theme.status_warn)),
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
                StreamDirection::AtoB => app.theme.status_good,
                StreamDirection::BtoA => Color::Magenta,
            };
            let text: String = seg
                .payload
                .iter()
                .map(|&b| {
                    if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
                        b as char
                    } else if b == b'\n' || b == b'\r' {
                        '\n'
                    } else {
                        '·'
                    }
                })
                .collect();
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
    let scroll = app.scroll.stream_scroll.min(max_scroll);

    let visible_lines: Vec<Line> = content_lines
        .into_iter()
        .skip(scroll)
        .take(visible_height)
        .collect();

    let content = Paragraph::new(visible_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(app.theme.border)),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(content, chunks[1]);

    // Status bar
    let mut status_spans = vec![
        Span::styled(
            format!(" {} packets", stream.packet_count),
            Style::default().fg(app.theme.text_primary),
        ),
        Span::raw(format!(", {} segments", filtered_segments.len())),
        Span::raw(" │ "),
        Span::styled("A→B: ", Style::default().fg(app.theme.status_good)),
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
                Style::default().fg(app.theme.brand),
            ));
        }
        if let Some(sa_ack) = hs.syn_ack_to_ack_ms() {
            status_spans.push(Span::styled(
                format!("SA→ACK:{:.1}ms ", sa_ack),
                Style::default().fg(app.theme.brand),
            ));
        }
        if let Some(total) = hs.total_ms() {
            status_spans.push(Span::styled(
                format!("Total:{:.1}ms", total),
                Style::default().fg(app.theme.status_good),
            ));
        }
    }
    status_spans.push(Span::raw(format!(" │ Lines: {total_lines} ")));
    let status = Paragraph::new(Line::from(status_spans)).block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(app.theme.border)),
    );
    f.render_widget(status, chunks[2]);
}

fn format_bytes(b: u64) -> String {
    if b < 1024 {
        format!("{b} B")
    } else if b < 1024 * 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{:.1} MB", b as f64 / (1024.0 * 1024.0))
    }
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    // Filter input mode — show editable filter bar
    if app.packet_filter_input {
        let filter_line = Line::from(vec![
            Span::styled(" / ", Style::default().fg(app.theme.brand).bold()),
            Span::raw(&app.packet_filter_text),
            Span::styled("█", Style::default().fg(app.theme.text_primary)),
        ]);
        let bar = Paragraph::new(filter_line).block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(app.theme.key_hint)),
        );
        f.render_widget(bar, area);
        return;
    }

    let mut hints = if app.stream_view_open {
        vec![
            Span::styled("Esc", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Close  "),
            Span::styled("→←", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Direction  "),
            Span::styled("h", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Hex/Text"),
        ]
    } else {
        let capture_key = if app.packet_collector.is_capturing() {
            "Stop"
        } else {
            "Capture"
        };
        vec![
            Span::styled("c", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(format!(":{capture_key}  ")),
            Span::styled("/", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Filter  "),
            Span::styled("s", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Stream  "),
            Span::styled("f", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Follow"),
        ]
    };

    let follow_indicator = if app.packet_follow {
        Span::styled(
            " [FOLLOW]",
            Style::default().fg(app.theme.status_good).bold(),
        )
    } else {
        Span::raw("")
    };
    hints.push(follow_indicator);

    if let Some(ref ft) = app.packet_filter_active {
        hints.push(Span::styled(
            " [FILTER: ",
            Style::default().fg(app.theme.key_hint).bold(),
        ));
        hints.push(Span::styled(
            ft.clone(),
            Style::default().fg(app.theme.text_primary),
        ));
        hints.push(Span::styled(
            "]",
            Style::default().fg(app.theme.key_hint).bold(),
        ));
    }

    crate::ui::widgets::render_footer(f, app, area, hints);
}

fn protocol_color(proto: &str, theme: &crate::theme::Theme) -> Style {
    match proto {
        "TCP" => Style::default().fg(Color::Magenta),
        "UDP" => Style::default().fg(Color::Blue),
        "ICMP" | "ICMPv6" => Style::default().fg(theme.status_warn),
        "ARP" => Style::default().fg(theme.brand),
        "DNS" => Style::default().fg(theme.status_good),
        _ => Style::default().fg(theme.text_primary),
    }
}

fn expert_indicator(
    severity: ExpertSeverity,
    theme: &crate::theme::Theme,
) -> (&'static str, Style) {
    match severity {
        ExpertSeverity::Error => ("●", Style::default().fg(theme.status_error).bold()),
        ExpertSeverity::Warn => ("▲", Style::default().fg(theme.status_warn)),
        ExpertSeverity::Note => ("·", Style::default().fg(theme.status_info)),
        ExpertSeverity::Chat => (" ", Style::default()),
    }
}

fn expert_row_style(severity: ExpertSeverity, theme: &crate::theme::Theme) -> Style {
    match severity {
        ExpertSeverity::Error => Style::default().fg(theme.status_error),
        ExpertSeverity::Warn => Style::default().fg(theme.status_warn),
        _ => Style::default(),
    }
}
