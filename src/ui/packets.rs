use crate::app::{App, StreamDirectionFilter};
use crate::collectors::packets::{
    matches_packet, parse_filter, port_label, CapturedPacket, ExpertSeverity, FilterExpr,
    StreamDirection,
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    // Detail-pane sizing: in default mode the packet list takes most
    // of the screen and the detail pane is a fixed 16-line slot at the
    // bottom; in expanded mode (toggled with `d`) the detail pane
    // grows to ~75% of the middle area (with the list shrunk to 25%),
    // which is necessary when a packet has lots of DPI / JA4 / geo
    // output that overflows the default slot.
    let (list_constraint, detail_constraint) = if app.ui.packet_detail_expanded {
        (Constraint::Percentage(25), Constraint::Percentage(75))
    } else {
        (Constraint::Min(10), Constraint::Length(16))
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            list_constraint,       // packet list
            detail_constraint,     // detail pane
            Constraint::Length(3), // footer
        ])
        .split(area);

    let packets = app.packet_collector.get_packets();
    render_header(f, app, chunks[0], packets.len());
    render_packet_list(f, app, &packets, chunks[1]);
    if app.ui.stream_view_open {
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
    } else if let Some(ref status) = app.ui.export_status {
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

/// Build a plain-text representation of a packet's full detail block
/// suitable for clipboard paste. Mirrors what the on-screen Protocol
/// Detail pane shows, plus the JA4/ECH lines we surface for TLS/QUIC,
/// so a user can `y` a packet and paste the full breakdown into a
/// Slack/Jira/notes without screen-scraping the TUI.
pub fn format_packet_for_clipboard(pkt: &CapturedPacket) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(512);
    let _ = writeln!(
        s,
        "Packet #{} — {}  {}",
        pkt.id, pkt.timestamp, pkt.protocol
    );
    let src = match pkt.src_port {
        Some(p) => format!("{}:{}", pkt.src_ip, p),
        None => pkt.src_ip.clone(),
    };
    let dst = match pkt.dst_port {
        Some(p) => format!("{}:{}", pkt.dst_ip, p),
        None => pkt.dst_ip.clone(),
    };
    let _ = writeln!(s, "{src} → {dst}  ({} bytes)", pkt.length);
    s.push('\n');
    for line in &pkt.details {
        let _ = writeln!(s, "  {line}");
    }
    // DPI signal: SNI / ALPN / JA4 / ECH for TLS or QUIC.
    if let Some(app_proto) = &pkt.app_protocol {
        s.push('\n');
        let _ = writeln!(s, "  App: {}", app_protocol_summary(app_proto));
        let (ja4, ech) = match app_proto {
            crate::dpi::AppProtocol::Tls { ja4, ech, .. } => (ja4.as_deref(), *ech),
            crate::dpi::AppProtocol::Quic { ja4, ech, .. } => (ja4.as_deref(), *ech),
            _ => (None, false),
        };
        if let Some(j) = ja4 {
            let line = match crate::dpi::ja4_db::lookup(j) {
                Some(name) => format!("  JA4: {j} ({name})"),
                None => format!("  JA4: {j}"),
            };
            let _ = writeln!(s, "{line}");
        }
        if ech {
            let _ = writeln!(s, "  ECH: present (inner SNI hidden from observer)");
        }
    }
    // Full TLS-decrypted application data — untruncated, unlike the
    // on-screen preview, so `y` is the way to grab the complete payload.
    if let Some(pt) = &pkt.decrypted_plaintext {
        let is_quic = matches!(pkt.app_protocol, Some(crate::dpi::AppProtocol::Quic { .. }));
        s.push('\n');
        if is_quic {
            let _ = writeln!(s, "  ── QUIC 1-RTT decrypted ({} bytes) ──", pt.len());
        } else {
            let _ = writeln!(s, "  ── TLS decrypted ({} bytes) ──", pt.len());
        }
        s.push_str(&preview_decrypted_bytes(pt, pt.len()));
        if !s.ends_with('\n') {
            s.push('\n');
        }
        // Include the decompressed HTTP/3 body when we can recover one.
        if is_quic {
            if let Some(decoded) = crate::dpi::http3::try_decode_single_packet(pt) {
                let _ = writeln!(
                    s,
                    "  ── HTTP/3 stream {} · {} body ({} bytes) ──",
                    decoded.stream_id,
                    decoded.encoding.label(),
                    decoded.bytes.len()
                );
                s.push_str(&preview_decrypted_bytes(
                    &decoded.bytes,
                    decoded.bytes.len(),
                ));
                if !s.ends_with('\n') {
                    s.push('\n');
                }
            }
        }
    }
    s
}

fn app_protocol_summary(p: &crate::dpi::AppProtocol) -> String {
    use crate::dpi::AppProtocol::*;
    match p {
        Tls {
            sni: Some(h), alpn, ..
        } => match alpn {
            Some(a) => format!("HTTPS {h} (ALPN: {a})"),
            None => format!("HTTPS {h}"),
        },
        Tls { sni: None, .. } => "HTTPS (no SNI)".into(),
        Quic { sni: Some(h), .. } => format!("QUIC {h}"),
        Quic { sni: None, .. } => "QUIC (no SNI)".into(),
        Http {
            method,
            host: Some(h),
        } => format!("HTTP {method} {h}"),
        Http { method, .. } => format!("HTTP {method}"),
        Dns { qname, qtype } => format!("DNS {qname} (qtype={qtype})"),
        Ssh { version } => format!("SSH {version}"),
        Llmnr { qname, qtype } => format!("LLMNR {qname} (qtype={qtype})"),
        Mqtt { client_id: Some(c) } => format!("MQTT client_id={c}"),
        Mqtt { client_id: None } => "MQTT".into(),
        Stun { message_type } => format!("STUN {message_type}"),
        BitTorrent { info_hash: Some(h) } => format!("BitTorrent info_hash={h}"),
        BitTorrent { info_hash: None } => "BitTorrent".into(),
        NetBios { service } => format!("NetBIOS {service}"),
        Snmp {
            version,
            community: Some(c),
        } => format!("SNMP {version} community={c}"),
        Snmp { version, .. } => format!("SNMP {version}"),
        Ssdp {
            method,
            target: Some(t),
        } => format!("SSDP {method} {t}"),
        Ssdp { method, .. } => format!("SSDP {method}"),
        Ftp { command } => format!("FTP {command}"),
        Dhcp { op } => match op {
            1 => "DHCP Discover/Request".into(),
            2 => "DHCP Offer/ACK".into(),
            n => format!("DHCP op={n}"),
        },
        Ntp { version, mode } => format!("NTPv{version} {}", ntp_mode_label(*mode)),
    }
}

/// RFC 5905 NTP mode names (the low 3 bits of the first byte).
fn ntp_mode_label(mode: u8) -> &'static str {
    match mode {
        1 => "Symmetric Active",
        2 => "Symmetric Passive",
        3 => "Client",
        4 => "Server",
        5 => "Broadcast",
        6 => "Control",
        _ => "Unknown",
    }
}

/// Render decrypted TLS plaintext for the details panel. If the bytes
/// are valid UTF-8 we show them as-is (usually HTTP/2 framing — still
/// readable enough to see methods/paths/headers). Otherwise hex-dump
/// the first `max_bytes` so the user can at least eyeball binary
/// payloads. Truncated with an ellipsis when over `max_bytes`.
fn preview_decrypted_bytes(bytes: &[u8], max_bytes: usize) -> String {
    let trimmed = if bytes.len() > max_bytes {
        &bytes[..max_bytes]
    } else {
        bytes
    };
    match std::str::from_utf8(trimmed) {
        Ok(s) => {
            let mut out = s.replace(|c: char| c.is_control() && c != '\n', "·");
            if bytes.len() > max_bytes {
                out.push('…');
            }
            out
        }
        Err(_) => {
            // Hex dump, 16 bytes per line, ASCII gutter.
            let mut out = String::with_capacity(trimmed.len() * 4);
            for chunk in trimmed.chunks(16) {
                use std::fmt::Write;
                for b in chunk {
                    let _ = write!(out, "{:02x} ", b);
                }
                out.push_str("  ");
                for b in chunk {
                    out.push(if b.is_ascii_graphic() || *b == b' ' {
                        *b as char
                    } else {
                        '.'
                    });
                }
                out.push('\n');
            }
            if bytes.len() > max_bytes {
                out.push('…');
            }
            out
        }
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

/// The filter expression currently applied to the packet list — the
/// committed `packet_filter_active`, or the in-progress text while the user
/// is typing one. `None` means show all. Centralized so the list, the detail
/// pane, and scroll/selection all agree on which packets are visible (a
/// selection or scroll position outside this set must not render details).
pub fn effective_packet_filter(app: &App) -> Option<FilterExpr> {
    let text = app
        .ui
        .packet_filter_active
        .as_deref()
        .or(if app.ui.packet_filter_input {
            Some(app.ui.packet_filter_text.as_str())
        } else {
            None
        });
    text.and_then(parse_filter)
}

/// Packets visible under the active filter, in capture order. Borrows the
/// passed slice; callers hold the packet-store guard for its lifetime.
pub fn visible_packets<'a>(app: &App, packets: &'a [CapturedPacket]) -> Vec<&'a CapturedPacket> {
    match effective_packet_filter(app) {
        Some(expr) => packets
            .iter()
            .filter(|p| matches_packet(&expr, p))
            .collect(),
        None => packets.iter().collect(),
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

    // Apply display filter (shared with the detail pane and scroll/selection).
    let filter_expr = effective_packet_filter(app);
    let filtered: Vec<&CapturedPacket> = match &filter_expr {
        Some(expr) => packets.iter().filter(|p| matches_packet(expr, p)).collect(),
        None => packets.iter().collect(),
    };

    let visible_height = area.height.saturating_sub(3) as usize;
    let total_all = packets.len();
    let total = filtered.len();

    let offset = if app.ui.packet_follow && total > visible_height {
        total - visible_height
    } else {
        app.ui
            .scroll
            .packet_scroll
            .min(total.saturating_sub(visible_height))
    };

    // Number of rows that will actually be rendered — capped by the
    // visible window AND the filtered packet count. Used as the denominator
    // for the top-bright / bottom-dim row fade so the gradient spans the
    // actual visible region rather than the maximum window size.
    let rendered_rows = filtered.len().saturating_sub(offset).min(visible_height);
    let rows: Vec<Row> = filtered
        .iter()
        .skip(offset)
        .take(visible_height)
        .enumerate()
        .map(|(row_idx, pkt)| {
            let proto_style = protocol_color(&pkt.protocol, &app.theme);
            let selected = app.ui.scroll.packet_selected == Some(pkt.id);
            // Distinguish packets where netwatch successfully decrypted the
            // TLS application data — operators scanning a long list want to
            // see "I have plaintext for this one" without selecting every
            // row. Uses `status_good` (theme-aware green) so it works across
            // light/dark themes, and falls back to selection bg when the row
            // is the cursor.
            let decrypted = pkt.decrypted_plaintext.is_some();
            let row_style = if selected {
                Style::default().bg(app.theme.selection_bg)
            } else if decrypted {
                Style::default().fg(app.theme.status_good).bold()
            } else {
                expert_row_style(pkt.expert, &app.theme)
            };
            // Position-based fade alpha; selected row stays at full intensity
            // so it remains visually grounded regardless of where it sits.
            let row_alpha = if app.user_config.graph_fade && !selected {
                crate::graph::row_fade_alpha(row_idx, rendered_rows)
            } else {
                1.0
            };
            let fade = |s: Style| {
                if (row_alpha - 1.0).abs() < f32::EPSILON {
                    s
                } else if let Some(fg) = s.fg {
                    s.fg(crate::graph::fade_color(fg, app.theme.bg, row_alpha))
                } else {
                    s
                }
            };

            let is_bookmarked = app.caches.bookmarks.contains(&pkt.id);
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

            // Prefer the DPI-decoded info when we have a hostname —
            // turns generic "ACK" / "Length=64" rows into actionable
            // "HTTPS api.example.com" / "QUIC youtube.com" / "DNS
            // example.com" lines. Falls back to the L4 info otherwise.
            let info_text = match &pkt.app_protocol {
                // ECH-flagged TLS gets a distinct prefix so the user can
                // tell at a glance that the displayed SNI is the *outer*
                // SNI and the real destination is hidden from the network.
                Some(crate::dpi::AppProtocol::Tls {
                    sni: Some(host),
                    ech: true,
                    ..
                }) => format!("HTTPS-ECH {}", host),
                Some(crate::dpi::AppProtocol::Tls {
                    sni: None,
                    ech: true,
                    ..
                }) => "HTTPS-ECH".to_string(),
                Some(crate::dpi::AppProtocol::Tls {
                    sni: Some(host), ..
                }) => {
                    format!("HTTPS {}", host)
                }
                Some(crate::dpi::AppProtocol::Quic {
                    sni: Some(host),
                    ech: true,
                    ..
                }) => format!("QUIC-ECH {}", host),
                Some(crate::dpi::AppProtocol::Quic {
                    sni: None,
                    ech: true,
                    ..
                }) => "QUIC-ECH".to_string(),
                Some(crate::dpi::AppProtocol::Quic {
                    sni: Some(host), ..
                }) => {
                    format!("QUIC {}", host)
                }
                Some(crate::dpi::AppProtocol::Http {
                    method,
                    host: Some(h),
                }) => format!("HTTP {} {}", method, h),
                Some(crate::dpi::AppProtocol::Dns { qname, .. }) => format!("DNS {}", qname),
                Some(crate::dpi::AppProtocol::Ssh { version }) => version.clone(),
                Some(crate::dpi::AppProtocol::Llmnr { qname, .. }) => format!("LLMNR {}", qname),
                Some(crate::dpi::AppProtocol::Mqtt {
                    client_id: Some(c), ..
                }) => format!("MQTT {}", c),
                Some(crate::dpi::AppProtocol::Mqtt { client_id: None }) => "MQTT".to_string(),
                Some(crate::dpi::AppProtocol::Stun { message_type }) => {
                    format!("STUN {}", message_type)
                }
                Some(crate::dpi::AppProtocol::BitTorrent { .. }) => "BitTorrent".to_string(),
                Some(crate::dpi::AppProtocol::NetBios { service }) => {
                    format!("NetBIOS {}", service)
                }
                Some(crate::dpi::AppProtocol::Snmp { version, .. }) => format!("SNMP {}", version),
                Some(crate::dpi::AppProtocol::Ssdp {
                    method,
                    target: Some(t),
                }) => format!("SSDP {} {}", method, t),
                Some(crate::dpi::AppProtocol::Ssdp {
                    method,
                    target: None,
                }) => format!("SSDP {}", method),
                Some(crate::dpi::AppProtocol::Ftp { command }) => format!("FTP {}", command),
                _ => pkt.info.clone(),
            };
            // Append the decoded JA4 client name when known, so users
            // scanning the packet list see "HTTPS google.com (Chromium
            // Browser)" without having to select the packet. Covers
            // both TLS-over-TCP and QUIC (JA4Q). Only fires when the
            // bundled DB recognizes the fingerprint; unknown JA4s stay
            // quiet rather than dumping the raw 30-char hash into
            // every row.
            let ja4 = match &pkt.app_protocol {
                Some(crate::dpi::AppProtocol::Tls { ja4: Some(j), .. }) => Some(j.as_str()),
                Some(crate::dpi::AppProtocol::Quic { ja4: Some(j), .. }) => Some(j.as_str()),
                _ => None,
            };
            let info_text = match ja4.and_then(crate::dpi::ja4_db::lookup) {
                Some(label) => format!("{info_text} ({label})"),
                None => info_text,
            };
            // Color the INFO column by L7 app protocol so the eye can
            // group rows at a glance: HTTPS/QUIC cyan, HTTP green, DNS
            // brand, SSH yellow. Falls through to default when no DPI
            // result is attached.
            let info_style = match &pkt.app_protocol {
                Some(crate::dpi::AppProtocol::Tls { .. })
                | Some(crate::dpi::AppProtocol::Quic { .. })
                | Some(crate::dpi::AppProtocol::Mqtt { .. }) => {
                    Style::default().fg(app.theme.status_info)
                }
                Some(crate::dpi::AppProtocol::Http { .. })
                | Some(crate::dpi::AppProtocol::Ftp { .. }) => {
                    Style::default().fg(app.theme.status_good)
                }
                Some(crate::dpi::AppProtocol::Dns { .. })
                | Some(crate::dpi::AppProtocol::Llmnr { .. })
                | Some(crate::dpi::AppProtocol::Snmp { .. }) => {
                    Style::default().fg(app.theme.brand)
                }
                Some(crate::dpi::AppProtocol::Ssh { .. })
                | Some(crate::dpi::AppProtocol::Ssdp { .. })
                | Some(crate::dpi::AppProtocol::NetBios { .. }) => {
                    Style::default().fg(app.theme.status_warn)
                }
                Some(crate::dpi::AppProtocol::Stun { .. })
                | Some(crate::dpi::AppProtocol::BitTorrent { .. }) => {
                    Style::default().fg(app.theme.text_muted)
                }
                Some(crate::dpi::AppProtocol::Dhcp { .. })
                | Some(crate::dpi::AppProtocol::Ntp { .. }) => {
                    Style::default().fg(app.theme.status_warn)
                }
                None => Style::default(),
            };

            // For cells that previously didn't set an explicit fg, set
            // one to text_primary so fade actually has a color to dim.
            // Without this, those cells inherit the buffer default and
            // the fade only touches the cells with explicit colors —
            // looks visually inconsistent across the row.
            let unstyled_fg = fade(Style::default().fg(app.theme.text_primary));
            Row::new(vec![
                Cell::from(expert_icon).style(fade(expert_style)),
                Cell::from(pkt.id.to_string())
                    .style(fade(Style::default().fg(app.theme.text_muted))),
                Cell::from(pkt.timestamp.clone()).style(unstyled_fg),
                Cell::from(src_display).style(unstyled_fg),
                Cell::from(dst_display).style(unstyled_fg),
                Cell::from(pkt.protocol.clone()).style(fade(proto_style)),
                Cell::from(pkt.length.to_string()).style(unstyled_fg),
                Cell::from(stream_label).style(fade(Style::default().fg(app.theme.text_muted))),
                // Truncate well above the typical narrow-terminal column
                // width so ratatui's own column clipping handles narrow
                // cases, and wide terminals show the full string —
                // including the decoded JA4 client label suffix like
                // " (Chromium Browser)" which the older 40-char limit
                // cut off mid-word.
                Cell::from(truncate_info(&info_text, 120)).style(fade(info_style)),
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
        let bm_count = app.caches.bookmarks.len();
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
    // Only render the selected packet if it's within the active filter —
    // otherwise a stale selection (or a scroll position the filter excludes)
    // would render details for a packet not shown in the list.
    let filter = effective_packet_filter(app);
    let selected_pkt = app
        .ui
        .scroll
        .packet_selected
        .and_then(|id| packets.iter().find(|p| p.id == id))
        .filter(|p| filter.as_ref().is_none_or(|e| matches_packet(e, p)));

    match selected_pkt {
        Some(pkt) => {
            let has_payload = !pkt.payload_text.is_empty() || pkt.decrypted_plaintext.is_some();

            // Geo info lines (if enabled)
            let mut geo_lines: Vec<Line> = Vec::new();
            if app.ui.show_geo {
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

            // DPI-derived details: JA4 fingerprint + ECH flag for both
            // TLS-over-TCP and QUIC. The Info column already shows
            // SNI/ALPN; this section surfaces the per-flow fingerprint,
            // which is the part operators use for threat hunting and
            // matching against IOC feeds.
            let dpi_signal: Option<(Option<&str>, bool)> = match &pkt.app_protocol {
                Some(crate::dpi::AppProtocol::Tls { ja4, ech, .. }) => Some((ja4.as_deref(), *ech)),
                Some(crate::dpi::AppProtocol::Quic { ja4, ech, .. }) => {
                    Some((ja4.as_deref(), *ech))
                }
                _ => None,
            };
            if let Some((ja4, ech)) = dpi_signal {
                if ja4.is_some() || ech {
                    detail_lines.push(Line::from(Span::styled(
                        "  ── TLS decoded ──",
                        Style::default().fg(app.theme.status_info).bold(),
                    )));
                    if let Some(j) = ja4 {
                        // Append a friendly client name when the
                        // bundled JA4 DB knows this fingerprint, e.g.
                        // "JA4: t13d... (Chromium Browser)". Unknown
                        // fingerprints stay raw — empty label would be
                        // worse than no label.
                        let line = match crate::dpi::ja4_db::lookup(j) {
                            Some(name) => format!("  JA4: {j} ({name})"),
                            None => format!("  JA4: {j}"),
                        };
                        detail_lines.push(Line::from(Span::styled(
                            line,
                            Style::default().fg(app.theme.status_info),
                        )));
                    }
                    if ech {
                        detail_lines.push(Line::from(Span::styled(
                            "  ECH: present (inner SNI hidden from observer)",
                            Style::default().fg(app.theme.status_info),
                        )));
                    }
                }
            }

            // TLS/QUIC-decrypted application data (when SSLKEYLOGFILE
            // matched this flow). The detail pane only summarizes what we
            // recovered — the bytes themselves live in the Payload Content
            // pane below, so we don't duplicate them here.
            if let Some(pt) = &pkt.decrypted_plaintext {
                let is_quic =
                    matches!(pkt.app_protocol, Some(crate::dpi::AppProtocol::Quic { .. }));
                let label = if is_quic {
                    "  ── QUIC 1-RTT decrypted ──"
                } else {
                    "  ── TLS decrypted ──"
                };
                detail_lines.push(Line::from(Span::styled(
                    label,
                    Style::default().fg(app.theme.status_good).bold(),
                )));
                detail_lines.push(Line::from(Span::styled(
                    format!("  {} bytes plaintext", pt.len()),
                    Style::default().fg(app.theme.status_good),
                )));
                // Phase 3a: note when this QUIC packet carries an offset-0
                // HTTP/3 DATA body we decompressed (gzip/deflate/br). The
                // decoded bytes render in the Payload Content pane.
                if is_quic {
                    if let Some(decoded) = crate::dpi::http3::try_decode_single_packet(pt) {
                        detail_lines.push(Line::from(Span::styled(
                            format!(
                                "  HTTP/3 stream {} · {} body → {} bytes",
                                decoded.stream_id,
                                decoded.encoding.label(),
                                decoded.bytes.len()
                            ),
                            Style::default().fg(app.theme.status_good),
                        )));
                    }
                }
            }

            // QUIC frame breakdown — for UDP packets that look like a
            // v1/v2 Initial, decrypt and surface CRYPTO / PADDING /
            // PING frames as a quick decode of what's inside.
            if pkt.protocol.eq_ignore_ascii_case("UDP") && !pkt.raw_bytes.is_empty() {
                // Skip Ethernet + IP + UDP headers to get the QUIC
                // payload. extract_app_payload handles that; we reuse
                // the same path the capture loop does.
                let app_payload =
                    crate::collectors::packets::extract_udp_app_payload(&pkt.raw_bytes);
                if let Some(frames) = crate::dpi::quic::decode_initial_frame_summary(&app_payload) {
                    detail_lines.push(Line::from(Span::styled(
                        "  ── QUIC decoded ──",
                        Style::default().fg(app.theme.status_info).bold(),
                    )));
                    for line in frames {
                        detail_lines.push(Line::from(Span::styled(
                            format!("  {line}"),
                            Style::default().fg(app.theme.status_info),
                        )));
                    }
                }
            }

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

            // Size the detail pane to the lines we *actually have* —
            // including geo, whois, TLS-decoded, QUIC-decoded, and
            // handshake-timing extras appended above. The previous
            // implementation sized from `pkt.details.len()` only, so
            // the appended lines (JA4, ECH) were rendered into the
            // Paragraph but immediately clipped off the bottom.
            // Cap the Protocol Detail box so the Payload / Hex / ASCII
            // sub-dialogs below it stay on screen. Compact view caps at
            // `area - 4`; the expanded (`d`) 3/4 view has a large pane, so
            // bound the detail box to ~60% and keep showing the same
            // sub-dialogs as the main view. The decrypted payload lives in
            // the detail box, but the user still wants the other panes
            // visible alongside it rather than a protocol-only view.
            let detail_cap = if app.ui.packet_detail_expanded {
                (area.height * 3 / 5).max(5)
            } else {
                area.height.saturating_sub(4)
            };
            let detail_height = (detail_lines.len() as u16 + 2).min(detail_cap);
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
                // Payload content. For a TLS flow the on-wire payload is
                // ciphertext (so `payload_text` is just "[N bytes binary
                // data]"); when we decrypted it, show the actual plaintext
                // here instead and label the pane accordingly.
                let (payload_body, payload_title, payload_style) =
                    if let Some(pt) = &pkt.decrypted_plaintext {
                        let is_quic =
                            matches!(pkt.app_protocol, Some(crate::dpi::AppProtocol::Quic { .. }));
                        // For QUIC, surface the decompressed HTTP/3 body
                        // (Phase 3a) beneath the raw decrypted frames so the
                        // readable content is right here in one pane.
                        let mut body = preview_decrypted_bytes(pt, 16384);
                        let title = if is_quic {
                            if let Some(decoded) = crate::dpi::http3::try_decode_single_packet(pt) {
                                body.push_str(&format!(
                                    "\n── HTTP/3 stream {} · {} body ({} bytes) ──\n",
                                    decoded.stream_id,
                                    decoded.encoding.label(),
                                    decoded.bytes.len()
                                ));
                                body.push_str(&preview_decrypted_bytes(&decoded.bytes, 16384));
                            }
                            " Payload Content (QUIC 1-RTT decrypted) "
                        } else {
                            " Payload Content (TLS decrypted) "
                        };
                        (body, title, Style::default().fg(app.theme.status_good))
                    } else {
                        (
                            pkt.payload_text.clone(),
                            " Payload Content ",
                            Style::default().fg(app.theme.text_primary),
                        )
                    };
                let payload = Paragraph::new(payload_body)
                    .style(payload_style)
                    .block(
                        Block::default()
                            .title(Line::from(Span::styled(
                                payload_title,
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
    let stream_index = match app.ui.stream_view_index {
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
    let dir_label = match app.ui.stream_direction_filter {
        StreamDirectionFilter::Both => "[a] Both",
        StreamDirectionFilter::AtoB => "[→] A→B",
        StreamDirectionFilter::BtoA => "[←] B→A",
    };
    let mode_label = if app.ui.stream_hex_mode {
        "Hex"
    } else {
        "Text"
    };
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
        .filter(|seg| match app.ui.stream_direction_filter {
            StreamDirectionFilter::Both => true,
            StreamDirectionFilter::AtoB => seg.direction == StreamDirection::AtoB,
            StreamDirectionFilter::BtoA => seg.direction == StreamDirection::BtoA,
        })
        .collect();

    let content_lines: Vec<Line> = if app.ui.stream_hex_mode {
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
    let scroll = app.ui.scroll.stream_scroll.min(max_scroll);

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
    let retx_total = stream.retransmits_a_to_b + stream.retransmits_b_to_a;
    let ooo_total = stream.out_of_order_a_to_b + stream.out_of_order_b_to_a;
    if retx_total > 0 || ooo_total > 0 {
        status_spans.push(Span::raw(" │ "));
        if retx_total > 0 {
            status_spans.push(Span::styled(
                format!(
                    "RETX:{} (↑{} ↓{})",
                    retx_total, stream.retransmits_a_to_b, stream.retransmits_b_to_a
                ),
                Style::default().fg(app.theme.status_error),
            ));
        }
        if ooo_total > 0 {
            if retx_total > 0 {
                status_spans.push(Span::raw(" "));
            }
            status_spans.push(Span::styled(
                format!(
                    "OOO:{} (↑{} ↓{})",
                    ooo_total, stream.out_of_order_a_to_b, stream.out_of_order_b_to_a
                ),
                Style::default().fg(app.theme.status_warn),
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
    if app.ui.packet_filter_input {
        let filter_line = Line::from(vec![
            Span::styled(" / ", Style::default().fg(app.theme.brand).bold()),
            Span::raw(&app.ui.packet_filter_text),
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

    let mut hints = if app.ui.stream_view_open {
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

    let follow_indicator = if app.ui.packet_follow {
        Span::styled(
            " [FOLLOW]",
            Style::default().fg(app.theme.status_good).bold(),
        )
    } else {
        Span::raw("")
    };
    hints.push(follow_indicator);

    if let Some(ref ft) = app.ui.packet_filter_active {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::packets::{CapturedPacket, ExpertSeverity};

    fn pkt_with_decrypted(pt: Option<Vec<u8>>) -> CapturedPacket {
        CapturedPacket {
            id: 1,
            timestamp: "00:00:00.000".into(),
            src_ip: "1.1.1.1".into(),
            dst_ip: "2.2.2.2".into(),
            src_host: None,
            dst_host: None,
            protocol: "TCP".into(),
            length: 100,
            src_port: Some(12345),
            dst_port: Some(443),
            info: String::new(),
            details: vec!["TCP: 12345 -> 443".into()],
            payload_text: String::new(),
            raw_hex: String::new(),
            raw_ascii: String::new(),
            raw_bytes: vec![],
            stream_index: Some(0),
            tcp_flags: None,
            tcp_seq: None,
            expert: ExpertSeverity::Chat,
            timestamp_ns: 0,
            app_protocol: None,
            decrypted_plaintext: pt,
        }
    }

    #[test]
    fn clipboard_includes_full_decrypted_payload() {
        // A payload longer than the on-screen cap must still appear in full
        // on the clipboard — `y` is the "see the whole thing" affordance.
        let mut body = b"GET /verify HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        body.extend(std::iter::repeat(b'Z').take(4000));
        let out = format_packet_for_clipboard(&pkt_with_decrypted(Some(body.clone())));
        assert!(out.contains("── TLS decrypted (4043 bytes) ──"));
        assert!(out.contains("GET /verify HTTP/1.1"));
        assert!(out.contains("Host: example.com"));
        assert_eq!(out.matches('Z').count(), 4000, "full payload, untruncated");
    }

    #[test]
    fn clipboard_omits_section_without_decryption() {
        let out = format_packet_for_clipboard(&pkt_with_decrypted(None));
        assert!(!out.contains("TLS decrypted"));
    }

    #[test]
    fn preview_decrypted_full_is_untruncated_but_capped_truncates() {
        let bytes = vec![b'A'; 5000];
        let full = preview_decrypted_bytes(&bytes, bytes.len());
        assert!(!full.ends_with('…'));
        assert_eq!(full.len(), 5000);
        let capped = preview_decrypted_bytes(&bytes, 100);
        assert!(capped.ends_with('…'));
    }
}
