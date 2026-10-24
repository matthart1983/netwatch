use crate::app::{App, StreamDirectionFilter};
use crate::collectors::packets::{
    format_endpoint, matches_packet, parse_filter, port_label, CapturedPacket, ExpertSeverity,
    FilterExpr, StreamDirection,
};
use crate::ui::stream_context;
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
};

/// Below this the decode and the stream will not both fit, so the decode
/// takes the row on its own.
const STREAM_COLUMN_MIN_WIDTH: u16 = 120;

/// Split the lower pane into decode and stream columns.
///
/// **This depends on the area and nothing else** — in particular not on the
/// selected packet. That is the whole point of it being a function.
///
/// It used to reserve the stream column only when the selected packet had a
/// `stream_index`, so arrowing from a TCP packet onto an ARP or ICMP one made
/// the right-hand panel vanish and the decode double in width, re-wrapping
/// every line in it. Walking a capture is the primary thing an operator does
/// on this screen, and the screen rearranged itself under them on every
/// keypress. A panel that has nothing to say says so; it does not resize its
/// neighbour.
fn lower_panes(area: Rect) -> (Rect, Option<Rect>) {
    if area.width < STREAM_COLUMN_MIN_WIDTH {
        return (area, None);
    }
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);
    (cols[0], Some(cols[1]))
}

/// Split the decode column into protocol detail, payload and hex.
///
/// Fixed proportions, for the same reason as [`lower_panes`]: sizing the
/// protocol box to its own line count made the payload and hex boxes below it
/// slide up and down by several rows on every arrow keypress, because a dns
/// reply and a tcp ack do not decode to the same number of lines. The boxes
/// below have to stay where they are; a decode that overruns its box is a
/// smaller problem than three boxes that never sit still.
fn detail_rows(area: Rect) -> std::rc::Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area)
}

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
            Constraint::Length(1), // capture control strip
            list_constraint,       // packet list
            detail_constraint,     // detail pane
            Constraint::Length(3), // footer
        ])
        .split(area);

    let packets = app.packet_collector.get_packets();
    render_header(f, app, chunks[0], packets.len());
    render_capture_strip(f, app, &packets, chunks[1]);
    render_packet_list(f, app, &packets, chunks[2]);
    if app.ui.stream_view_open {
        // `s` opens the full conversation, which wants the whole row.
        render_stream_view(f, app, chunks[3]);
    } else {
        // Decode on the left, the flow it belongs to on the right. A decoded
        // packet without its stream is a sentence without the paragraph: the
        // reply is 41ms, and whether that matters is a property of the other
        // thirty-seven queries this resolver answered in the last minute.
        let (detail, stream) = lower_panes(chunks[3]);
        render_detail(f, app, &packets, detail);
        if let Some(stream) = stream {
            render_stream_summary(f, app, &packets, stream);
        }
    }
    render_footer(f, app, chunks[4]);
}

/// What the capture is doing, on its own row.
///
/// This used to be `● CAPTURING on eth0 (N pkts)` appended to the tab bar,
/// which is what clipped the bar's right corner to `● CA` / `○ ST` at 150
/// columns. It also never showed drops — and a packet list with no drop
/// counter cannot be trusted, because a filter matching nothing and a kernel
/// buffer overflowing look identical on screen.
fn render_capture_strip(f: &mut Frame, app: &App, packets: &[CapturedPacket], area: Rect) {
    let t = &app.theme;
    let capturing = app.packet_collector.is_capturing();
    let stats = &app.packet_collector.stats;

    let controls = vec![
        // In demo mode the list holds a recorded conversation, and the strip
        // is the only place that says so. Every other demo surface carries a
        // non-suppressible marker for the same reason: packets a viewer can
        // mistake for their own traffic are worse than no packets.
        if app.diagnose.is_demo() {
            crate::ui::widgets::Control::state("capture", "DEMO recorded conversation")
        } else if capturing {
            crate::ui::widgets::Control::state("capture", format!("● {}", app.capture_interface))
        } else {
            crate::ui::widgets::Control::state(
                "capture",
                format!("○ {} stopped", app.capture_interface),
            )
        },
        crate::ui::widgets::Control::state(
            "filter",
            match effective_packet_filter(app) {
                Some(_) => app
                    .ui
                    .packet_filter_active
                    .clone()
                    .unwrap_or_else(|| app.ui.packet_filter_text.clone()),
                None => "none".to_string(),
            },
        ),
    ];

    let shown = visible_packets(app, packets).len();
    let dropped = stats.dropped();
    let mut meta = vec![
        Span::styled(
            format!(
                "ring {} · {shown} shown · ",
                crate::collectors::packets::RING_CAPACITY
            ),
            Style::default().fg(t.text_muted),
        ),
        // Drops are the one number here that changes what the list means, so
        // they are the one number that takes a colour.
        Span::styled(
            format!("drops {dropped}"),
            Style::default().fg(if dropped > 0 {
                t.status_warn
            } else {
                t.text_muted
            }),
        ),
    ];
    if capturing {
        meta.push(Span::styled(
            format!(" · {} pkt/s", stats.rate_pps()),
            Style::default().fg(t.text_muted),
        ));
    }

    let hints = [
        crate::ui::widgets::hint("/", "filter"),
        crate::ui::widgets::hint("s", "stream"),
        crate::ui::widgets::hint(
            "x",
            if app.ui.packet_expert_only {
                "expert only ✓"
            } else {
                "expert only"
            },
        ),
        crate::ui::widgets::hint("c", if capturing { "stop" } else { "capture" }),
    ];

    crate::ui::widgets::render_control_strip(f, t, area, &controls, meta, &hints);
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

    // Capture state lives in the control strip below, not up here — this row
    // is the tab bar, and appending to it is what clipped its right corner.
    // The BPF filter is a capture-time filter rather than a display one, so it
    // still rides here where it cannot be confused with `/`.
    let _ = (cap_status, pkt_count);
    let mut extra: Vec<Span<'static>> = Vec::new();
    if let Some(ref bpf) = app.bpf_filter_active {
        extra.push(Span::raw("  "));
        extra.push(Span::styled(
            "bpf ",
            Style::default().fg(app.theme.key_hint).bold(),
        ));
        extra.push(Span::styled(
            bpf.clone(),
            Style::default().fg(app.theme.text_primary),
        ));
    }

    if let Some(e) = crate::ui::widgets::capture_failure(app) {
        let line1 = crate::ui::widgets::build_header_line(app, Some(extra));
        let lines = vec![line1, crate::ui::widgets::capture_failure_line(app, e)];
        let header = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(app.theme.border)),
        );
        f.render_widget(header, area);
    // No export-status branch here: the toast belongs to the footer, which
    // draws it for every tab. Packets used to render its own because the
    // header's copy was suppressed on this tab; with one owner, a second
    // copy is just the same sentence twice on one screen.
    } else {
        crate::ui::widgets::render_header_with_extra(f, app, area, extra);
    }
}

/// Build a plain-text representation of a packet's full detail block
/// suitable for clipboard paste. Mirrors what the on-screen Protocol
/// Detail pane shows, plus the JA4/ECH lines we surface for TLS/QUIC,
/// so a user can `y` a packet and paste the full breakdown into a
/// Slack/Jira/notes without screen-scraping the TUI.
pub fn format_packet_for_clipboard(
    pkt: &CapturedPacket,
    h3_bodies: &[crate::dpi::http3::DecodedBody],
) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(512);
    let _ = writeln!(
        s,
        "Packet #{} — {}  {}",
        pkt.id, pkt.timestamp, pkt.protocol
    );
    let src = match pkt.src_port {
        Some(p) => format_endpoint(&pkt.src_ip, p),
        None => pkt.src_ip.clone(),
    };
    let dst = match pkt.dst_port {
        Some(p) => format_endpoint(&pkt.dst_ip, p),
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
        // Include any decompressed HTTP/3 bodies (reassembled across packets).
        if is_quic {
            for decoded in h3_bodies {
                let _ = writeln!(
                    s,
                    "  ── HTTP/3 stream {} · {} body ({}) ──",
                    decoded.stream_id,
                    decoded.encoding.label(),
                    decoded.size_label()
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
            path,
            ..
        } => format!("HTTP {method} {h}{}", path.as_deref().unwrap_or("")),
        Http {
            status: Some(code), ..
        } => format!("HTTP {code}"),
        Http {
            method,
            host: None,
            path: Some(p),
            ..
        } => format!("HTTP {method} {p}"),
        Http { method, .. } => format!("HTTP {method}"),
        Dns {
            qname,
            qtype,
            rcode,
        } => match rcode {
            Some(rc) => format!(
                "DNS {qname} (qtype={qtype}, {})",
                crate::dpi::dns::rcode_label(*rc)
            ),
            None => format!("DNS {qname} (qtype={qtype})"),
        },
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
            let mut out = crate::ui::sanitize::display_multiline(s).into_owned();
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
    let expr = effective_packet_filter(app);
    packets
        .iter()
        .filter(|p| expr.as_ref().is_none_or(|e| matches_packet(e, p)))
        .filter(|p| !app.ui.packet_expert_only || is_expert(p))
        .collect()
}

/// Whether the expert classifier flagged this packet as something to look at.
///
/// `Chat` and `Note` are the ordinary run of a capture — a SYN, a DNS query, a
/// clean FIN. Only `Warn` and `Error` are findings, and they are what `x`
/// narrows to and `n` walks between.
pub fn is_expert(p: &CapturedPacket) -> bool {
    matches!(p.expert, ExpertSeverity::Warn | ExpertSeverity::Error)
}

/// A Source or Destination cell: the host (its resolved name, else its
/// address), then the port, bracketing an IPv6 address so the port is not
/// read as one more group of it, then the port's service when it has one.
fn endpoint_cell(host: &str, port: Option<u16>) -> String {
    let Some(port) = port else {
        return host.to_string();
    };
    let endpoint = format_endpoint(host, port);
    match port_label(port) {
        "—" => endpoint,
        svc => format!("{endpoint} ({svc})"),
    }
}

fn render_packet_list(f: &mut Frame, app: &App, packets: &[CapturedPacket], area: Rect) {
    let header = Row::new(
        [
            "!",
            "#",
            "time",
            "source",
            "destination",
            "proto",
            "len",
            "stream",
            "info",
        ]
        .map(|h| Cell::from(h).style(Style::default().fg(app.theme.text_muted))),
    )
    .height(1);

    // One definition of "visible", shared with the detail pane, the capture
    // strip and scroll/selection. Two of them meant a selection could land on
    // a packet the list was not drawing.
    let filtered = visible_packets(app, packets);

    let visible_height = area.height.saturating_sub(3) as usize;
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
                    s.fg(crate::graph::fade_color(
                        fg,
                        app.theme.bg,
                        row_alpha,
                        app.theme.defers_to_terminal(),
                    ))
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

            let src_display = endpoint_cell(src_label, pkt.src_port);
            let dst_display = endpoint_cell(dst_label, pkt.dst_port);

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
                    status: Some(code), ..
                }) => format!("HTTP {}", code),
                Some(crate::dpi::AppProtocol::Http {
                    method,
                    host: Some(h),
                    path,
                    ..
                }) => format!("HTTP {} {}{}", method, h, path.as_deref().unwrap_or("")),
                Some(crate::dpi::AppProtocol::Http {
                    method,
                    host: None,
                    path: Some(p),
                    ..
                }) => format!("HTTP {} {}", method, p),
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
            // `text_muted` on `selection_bg` is the one combination that does
            // not survive. The id and stream columns are both muted, so they
            // vanished on whichever row the cursor was on — the row the reader
            // is most likely to be looking at, and the one whose id they need
            // to quote. Lift them for the selected row only.
            let dim = |s: Style| fade(readable_when_selected(s, selected, &app.theme));
            Row::new(vec![
                Cell::from(expert_icon).style(fade(expert_style)),
                Cell::from(pkt.id.to_string())
                    .style(dim(Style::default().fg(app.theme.text_muted))),
                Cell::from(pkt.timestamp.clone()).style(unstyled_fg),
                Cell::from(src_display).style(unstyled_fg),
                Cell::from(dst_display).style(unstyled_fg),
                Cell::from(pkt.protocol.clone()).style(fade(proto_style)),
                Cell::from(pkt.length.to_string()).style(unstyled_fg),
                Cell::from(stream_label).style(dim(Style::default().fg(app.theme.text_muted))),
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
        // Counts and the filter now live in the capture strip; the panel's
        // metadata carries what the list itself found. `n` is advertised only
        // when there is somewhere for it to go.
        let t = &app.theme;
        let warns = filtered
            .iter()
            .filter(|p| p.expert == ExpertSeverity::Warn)
            .count();
        let errors = filtered
            .iter()
            .filter(|p| p.expert == ExpertSeverity::Error)
            .count();
        let mut meta = vec![
            Span::styled("expert: ", Style::default().fg(t.text_muted)),
            Span::styled(
                format!("{warns} warn"),
                Style::default().fg(if warns > 0 {
                    t.status_warn
                } else {
                    t.text_muted
                }),
            ),
            Span::styled(" · ", Style::default().fg(t.separator)),
            Span::styled(
                format!("{errors} error"),
                Style::default().fg(if errors > 0 {
                    t.status_error
                } else {
                    t.text_muted
                }),
            ),
        ];
        if warns + errors > 0 {
            meta.push(Span::styled("  ", Style::default()));
            meta.push(Span::styled("n", Style::default().fg(t.key_hint).bold()));
            meta.push(Span::styled(
                " next expert",
                Style::default().fg(t.text_muted),
            ));
        }
        if bm_count > 0 {
            meta.insert(
                0,
                Span::styled(format!("★{bm_count} · "), Style::default().fg(t.text_muted)),
            );
        }
        widgets::Panel::new("packets")
            .meta_styled(meta)
            .fit(area.width)
            .block(&app.theme)
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
                // Note any HTTP/3 bodies recovered for this flow — reassembled
                // across packets when the body spans more than one (Phase 3b).
                // The decoded bytes render in the Payload Content pane.
                if is_quic {
                    let bodies = app.packet_collector.quic_h3_bodies_for_packet(pkt);
                    for decoded in &bodies {
                        detail_lines.push(Line::from(Span::styled(
                            format!(
                                "  HTTP/3 stream {} · {} body → {}",
                                decoded.stream_id,
                                decoded.encoding.label(),
                                decoded.size_label()
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

            // DNS query→reply latency, against the resolver's own baseline.
            //
            // A reply that took 41ms is unremarkable on its own and alarming
            // when the resolver normally answers in 1.2 — and the packet list
            // is where a reader is looking when they want to know which. The
            // baseline is the same one the Diagnose tab reasons from, so the
            // two cannot disagree about what "slow" means here.
            if let Some(latency) = dns_reply_latency(pkt, packets) {
                detail_lines.push(Line::from(Span::styled(
                    "  timing",
                    Style::default().fg(app.theme.brand).bold(),
                )));
                detail_lines.push(Line::from(Span::styled(
                    format!(
                        "    query #{} {} → reply +{:.1}ms",
                        latency.query_id, latency.query_time, latency.ms
                    ),
                    Style::default().fg(app.theme.text_primary),
                )));

                let subject = pkt.src_ip.clone();
                if let Some(base) =
                    app.diagnose
                        .baselines
                        .get(&subject, "dns.rtt_p50")
                        .filter(|_| {
                            app.diagnose
                                .baselines
                                .readiness(&subject, "dns.rtt_p50")
                                .is_ready()
                        })
                {
                    let multiple = if base.mean > 0.0 {
                        latency.ms / base.mean
                    } else {
                        1.0
                    };
                    let color = if multiple >= 10.0 {
                        app.theme.status_error
                    } else if multiple >= 3.0 {
                        app.theme.status_warn
                    } else {
                        app.theme.text_muted
                    };
                    detail_lines.push(Line::from(vec![
                        Span::styled(
                            format!("    baseline {:.1}ms σ{:.1}", base.mean, base.sigma()),
                            Style::default().fg(app.theme.text_muted),
                        ),
                        Span::styled(
                            format!(" · {multiple:.0}× baseline"),
                            Style::default().fg(color),
                        ),
                    ]));
                }
            }

            // TCP handshake timing (if this packet belongs to a stream with handshake data)
            if let Some(stream) = app.packet_collector.get_stream_for_packet(pkt) {
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

            // Three boxes, always, at the same three heights. `d` expands
            // the whole column when a packet decodes to more lines than the
            // protocol box can hold — that is the affordance for a long
            // decode, rather than the box quietly growing and shoving the
            // payload and hex down the screen.
            let rows = detail_rows(area);

            // Titled with what it is decoding, the way the design names its
            // detail panes: `#29321 · dns reply` says more than "Protocol
            // Detail" and costs the same row.
            let proto_detail = Paragraph::new(detail_lines).block(
                widgets::Panel::styled(vec![
                    Span::styled(
                        format!("#{}", pkt.id),
                        Style::default().fg(app.theme.brand).bold(),
                    ),
                    Span::styled(
                        format!(" · {}", pkt.protocol.to_lowercase()),
                        Style::default().fg(app.theme.text_secondary),
                    ),
                ])
                .meta_styled(vec![
                    Span::styled(
                        format!("{} bytes  ", pkt.length),
                        Style::default().fg(app.theme.text_muted),
                    ),
                    Span::styled("y", Style::default().fg(app.theme.key_hint).bold()),
                    Span::styled(" copy", Style::default().fg(app.theme.text_muted)),
                ])
                .fit(rows[0].width)
                .block(&app.theme),
            );
            f.render_widget(proto_detail, rows[0]);

            {
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
                            // Surface the decompressed HTTP/3 body (reassembled
                            // across packets, Phase 3b) beneath the raw frames so
                            // the readable content is in one pane.
                            let bodies = app.packet_collector.quic_h3_bodies_for_packet(pkt);
                            for decoded in &bodies {
                                body.push_str(&format!(
                                    "\n── HTTP/3 stream {} · {} body ({}) ──\n",
                                    decoded.stream_id,
                                    decoded.encoding.label(),
                                    decoded.size_label()
                                ));
                                body.push_str(&preview_decrypted_bytes(&decoded.bytes, 16384));
                            }
                            " Payload Content (QUIC 1-RTT decrypted) "
                        } else {
                            " Payload Content (TLS decrypted) "
                        };
                        (body, title, Style::default().fg(app.theme.status_good))
                    } else if has_payload {
                        (
                            pkt.payload_text.clone(),
                            " Payload Content ",
                            Style::default().fg(app.theme.text_primary),
                        )
                    } else {
                        // The box stays; only its contents change. Saying
                        // "headers only" is information — it tells you the
                        // capture is not truncating anything — and it keeps
                        // the hex box below at a fixed row.
                        (
                            format!("headers only · {} bytes on the wire", pkt.length),
                            " Payload Content ",
                            Style::default().fg(app.theme.text_muted),
                        )
                    };
                let payload = Paragraph::new(payload_body)
                    .style(payload_style)
                    .block(
                        widgets::panel_block(&app.theme)
                            .title(Line::from(Span::styled(
                                payload_title,
                                Style::default().fg(app.theme.brand).bold(),
                            )))
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
            }
        }
        None => {
            let hint = Paragraph::new(" Select a packet with ↑↓ to inspect")
                .style(Style::default().fg(app.theme.text_muted))
                .block(
                    widgets::Panel::new("packet detail")
                        .fit(area.width)
                        .block(&app.theme),
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
            widgets::panel_block(theme)
                .title(Line::from(Span::styled(
                    " Hex Dump ",
                    Style::default().fg(theme.brand).bold(),
                )))
                .border_style(Style::default().fg(theme.border)),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(hex, chunks[0]);

    let ascii = Paragraph::new(pkt.raw_ascii.clone())
        .style(Style::default().fg(theme.status_warn))
        .block(
            widgets::panel_block(theme)
                .title(Line::from(Span::styled(
                    " ascii ",
                    Style::default().fg(theme.brand).bold(),
                )))
                .border_style(Style::default().fg(theme.border)),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(ascii, chunks[1]);
}

/// Build the stream-view content lines (hex or text) for `stream`, applying the
/// decrypted-only filter, the dim-the-handshake rule, and the direction filter.
/// When `focus_packet` is set, that packet's segment is highlighted and the
/// index of its first content line is returned, so the `s` open-stream handler
/// can scroll the view to the selected packet. Shared with `render_stream_view`
/// so both agree on line layout.
pub fn build_stream_lines(
    stream: &crate::collectors::packets::Stream,
    hex_mode: bool,
    dir: StreamDirectionFilter,
    focus_packet: Option<u64>,
    theme: &crate::theme::Theme,
) -> (Vec<Line<'static>>, Option<usize>, usize) {
    let has_dec = stream.segments.iter().any(|s| s.decrypted.is_some());
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut focus_first: Option<usize> = None;
    let mut shown_segments = 0usize;

    let segments = stream.segments.iter().filter(|seg| {
        (!has_dec || seg.decrypted.is_some())
            && match dir {
                StreamDirectionFilter::Both => true,
                StreamDirectionFilter::AtoB => seg.direction == StreamDirection::AtoB,
                StreamDirectionFilter::BtoA => seg.direction == StreamDirection::BtoA,
            }
    });

    for seg in segments {
        shown_segments += 1;
        let focus = focus_packet == Some(seg.packet_id);
        if focus && focus_first.is_none() {
            focus_first = Some(lines.len());
        }
        let arrow = match seg.direction {
            StreamDirection::AtoB => "→",
            StreamDirection::BtoA => "←",
        };
        let arrow_color = match seg.direction {
            StreamDirection::AtoB => theme.status_good,
            StreamDirection::BtoA => Color::Magenta,
        };
        let bytes = seg.decrypted.as_deref().unwrap_or(&seg.payload);
        // Dim raw (handshake / undecrypted) segments once a decrypted
        // conversation exists, so the plaintext reads clearly.
        let dim = has_dec && seg.decrypted.is_none();
        // The selected packet's segment gets a background highlight.
        let bg = |st: Style| if focus { st.bg(theme.highlight_bg) } else { st };

        if hex_mode {
            let (hex_color, ascii_color) = if dim {
                (theme.text_muted, theme.text_muted)
            } else {
                (theme.status_good, theme.status_warn)
            };
            for chunk in bytes.chunks(16) {
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
                    Span::styled(format!(" {arrow} "), bg(Style::default().fg(arrow_color))),
                    Span::styled(format!("{:<50}", hex), bg(Style::default().fg(hex_color))),
                    Span::styled(ascii, bg(Style::default().fg(ascii_color))),
                ]));
            }
        } else {
            let text_style = if dim {
                Style::default().fg(theme.text_muted)
            } else {
                Style::default()
            };
            // Show a tab as `·`, like every other control byte. ratatui
            // drops control characters from the text it lays out, so a raw
            // tab would vanish and `id\tname` would read as `idname`.
            let text: String = bytes
                .iter()
                .map(|&b| {
                    if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else if b == b'\n' || b == b'\r' {
                        '\n'
                    } else {
                        crate::ui::sanitize::REPLACEMENT
                    }
                })
                .collect();
            for text_line in text.lines() {
                lines.push(Line::from(vec![
                    Span::styled(format!(" {arrow} "), bg(Style::default().fg(arrow_color))),
                    Span::styled(text_line.to_string(), bg(text_style)),
                ]));
            }
        }
    }
    (lines, focus_first, shown_segments)
}

fn render_stream_view(f: &mut Frame, app: &App, area: Rect) {
    let stream_index = match app.ui.stream_view_index {
        Some(idx) => idx,
        None => {
            let hint = Paragraph::new(" No stream selected")
                .style(Style::default().fg(app.theme.text_muted))
                .block(
                    widgets::panel_block(&app.theme)
                        .title(Line::from(Span::styled(
                            " Stream View ",
                            Style::default().fg(app.theme.brand).bold(),
                        )))
                        .border_style(Style::default().fg(app.theme.border)),
                );
            f.render_widget(hint, area);
            return;
        }
    };

    let stream = match app
        .packet_collector
        .get_stream_in_session(stream_index, app.ui.stream_view_session.as_deref())
    {
        Some(s) => s,
        None => {
            let hint = Paragraph::new(format!(" Stream #{stream_index} not found"))
                .style(Style::default().fg(app.theme.status_error))
                .block(
                    widgets::panel_block(&app.theme)
                        .title(Line::from(Span::styled(
                            " Stream View ",
                            Style::default().fg(app.theme.brand).bold(),
                        )))
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
    let stream_has_decrypted = stream.segments.iter().any(|s| s.decrypted.is_some());
    let mut header_spans = vec![
        Span::styled(
            format!(" {proto_str} Stream #{stream_index} "),
            Style::default().fg(app.theme.brand).bold(),
        ),
        Span::raw(format!(
            "── {} ↔ {}  ",
            format_endpoint(a_ip, a_port),
            format_endpoint(b_ip, b_port)
        )),
        Span::styled(dir_label, Style::default().fg(app.theme.key_hint)),
        Span::raw("  "),
        Span::styled(
            format!("[h] {mode_label}"),
            Style::default().fg(app.theme.key_hint),
        ),
    ];
    if stream_has_decrypted {
        header_spans.push(Span::raw("  "));
        header_spans.push(Span::styled(
            "🔓 decrypted",
            Style::default().fg(app.theme.status_good).bold(),
        ));
    }
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

    // Build content lines. Once a stream has decrypted content, follow only the
    // decrypted conversation (the plaintext app-data segments) — the encrypted
    // handshake is omitted so the request/response flow reads cleanly, the way
    // Wireshark's "Follow HTTP Stream" does. The header still shows the 🔓
    // indicator and handshake timing, so that context isn't lost.
    // Build the content lines via the shared builder so the renderer and the
    // `s` open-stream handler agree on layout (the handler uses its returned
    // focus-line index to scroll to the selected packet).
    let (content_lines, _focus_first, shown_segments) = build_stream_lines(
        &stream,
        app.ui.stream_hex_mode,
        app.ui.stream_direction_filter,
        app.ui.stream_view_focus_packet,
        &app.theme,
    );

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
        .block(widgets::panel_block(&app.theme).border_style(Style::default().fg(app.theme.border)))
        .wrap(Wrap { trim: false });
    f.render_widget(content, chunks[1]);

    // Status bar
    let mut status_spans = vec![
        Span::styled(
            format!(" {} packets", stream.packet_count),
            Style::default().fg(app.theme.text_primary),
        ),
        Span::raw(format!(", {} segments", shown_segments)),
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

    use crate::ui::widgets::hint;
    // State rides in the label of the key that toggles it, rather than in a
    // `[FOLLOW]` / `[FILTER: …]` badge wedged among the keys. A footer is a
    // keymap; a bracketed status word in the middle of one reads as a key the
    // user cannot find.
    let hints = if app.ui.stream_view_open {
        vec![
            hint("esc", "close"),
            hint("←→", "direction"),
            hint("h", "hex/text"),
        ]
    } else {
        // `c` / `/` / `s` / `x` are advertised in the capture strip directly
        // above; repeating them here would spend the row twice on one keymap.
        let mut v = vec![hint("n", "next expert"), hint("i", "iface")];
        v.push(hint(
            "f",
            if app.ui.packet_follow {
                "follow stream"
            } else {
                "follow"
            },
        ));
        v.push(hint("w", "export capture"));
        v.push(hint("m", "mark"));
        if !app.caches.bookmarks.is_empty() {
            v.push(hint("][", "marks"));
        }
        v.push(hint("X", "clear"));
        v
    };

    crate::ui::widgets::render_footer(f, app, area, hints);
}

/// Lift a muted style so it stays legible on the selection background.
///
/// Muted grey is chosen to recede against the panel background; against
/// `selection_bg` it recedes all the way to invisible. Only muted is
/// promoted — a cell that already carries a status or protocol colour is
/// legible on the band and must keep the colour it is carrying.
fn readable_when_selected(base: Style, selected: bool, t: &crate::theme::Theme) -> Style {
    if selected && base.fg == Some(t.text_muted) {
        return base.fg(t.text_secondary);
    }
    base
}

/// The packet the cursor is on, if it is still in the visible set.
pub fn selected_packet<'a>(app: &App, packets: &'a [CapturedPacket]) -> Option<&'a CapturedPacket> {
    let id = app.ui.scroll.packet_selected?;
    visible_packets(app, packets)
        .into_iter()
        .find(|p| p.id == id)
}

/// The flow the selected packet belongs to: how much of it there is, how long
/// it took, and — when it is DNS — how this resolver has been behaving.
///
/// The resolver block is the reason this panel exists. One reply's latency is
/// an anecdote; `queries 38 · replies 38 · timeouts 0` with a p50 beside the
/// learned baseline is the finding, and it is available right here without
/// leaving the packet the reader is already looking at.
/// Rows the summary block above the ladder occupies: counters, timing, and
/// the `sequence` heading with its blank line.
const SUMMARY_ROWS: usize = 4;
/// Rows the dns resolver section occupies when the flow is dns.
const DNS_ROWS: usize = 4;

/// `1.2s`, `340ms` — a duration a reader does not have to convert.
fn format_duration_ms(ms: f64) -> String {
    if ms >= 1000.0 {
        format!("{:.1}s", ms / 1000.0)
    } else {
        format!("{ms:.0}ms")
    }
}

/// Columns a rung spends on everything except the label: the cursor marker,
/// the packet id, the offset, the direction arrow and the byte count.
const LADDER_FIXED_COLS: usize = 27;
/// Below this a label says nothing useful, so the panel gives it this much
/// even when that costs the note its spelled-out form.
const MIN_LABEL_COLS: usize = 10;

/// The sequence ladder: what happened, in order, around the selected packet.
///
/// This is the substance of the panel. A conversation is a sequence, and the
/// question an operator has when they select a packet mid-capture — "what is
/// this, and what happened either side of it" — is only answerable by showing
/// the neighbours. The selected rung is marked and the arrows point away from
/// whichever end opened the flow, so direction reads consistently down the
/// column instead of flipping with every packet's src/dst.
fn ladder_lines<'a>(
    convo: &stream_context::Conversation,
    t: &crate::theme::Theme,
    width: u16,
) -> Vec<Line<'a>> {
    use crate::ui::stream_context::Role;

    let mut out: Vec<Line> = vec![Line::raw("")];
    out.push(Line::from(vec![
        Span::styled("sequence", Style::default().fg(t.text_secondary)),
        Span::styled(
            match convo.position {
                Some(p) => format!("  packet {p} of {}", convo.total),
                None => format!("  {} packets", convo.total),
            },
            Style::default().fg(t.text_muted),
        ),
        // Say when the window is hiding something, so a ladder that starts at
        // "data" is not mistaken for a conversation with no handshake.
        Span::styled(
            match (convo.truncated_above, convo.truncated_below) {
                (true, true) => "  ⋯ trimmed both ends".to_string(),
                (true, false) => "  ⋯ earlier packets above".to_string(),
                (false, true) => "  ⋯ later packets below".to_string(),
                (false, false) => String::new(),
            },
            Style::default().fg(t.text_muted),
        ),
    ]));

    // Give the label whatever the fixed columns leave. A hard 20 threw away
    // the end of every dns summary on a panel with room to spare.
    //
    // The note has to be in the budget too, or a rung carrying "retransmit"
    // runs past the panel edge — and that is the rung most worth reading. On
    // a panel too narrow to spell it, the note keeps its column as a glyph
    // rather than being dropped: losing the label's tail costs less than
    // losing the fact that the segment was resent.
    let longest_note = convo
        .rungs
        .iter()
        .filter_map(|r| r.note)
        .map(|n| n.label().chars().count())
        .max();
    let (note_w, spell_notes) = match longest_note {
        None => (0, false),
        Some(n) => {
            let spelled = n + 2;
            if (width as usize) >= LADDER_FIXED_COLS + MIN_LABEL_COLS + spelled {
                (spelled, true)
            } else {
                (3, false)
            }
        }
    };
    let label_w = (width as usize)
        .saturating_sub(LADDER_FIXED_COLS + note_w)
        .clamp(MIN_LABEL_COLS, 44);

    for rung in &convo.rungs {
        let role_colour = if rung.role.is_alarming() {
            t.status_error
        } else if matches!(rung.role, Role::Syn | Role::SynAck | Role::Fin) {
            t.status_info
        } else if matches!(rung.role, Role::Ack | Role::Other) {
            t.text_muted
        } else {
            t.text_primary
        };
        // The cursor bar is the same mark the issue list and chronology use
        // for "this is the one you are on".
        let (marker, base) = if rung.selected {
            ("▌", Style::default().bg(t.selection_bg))
        } else {
            (" ", Style::default())
        };
        // Muted grey on the selection background is the one combination that
        // does not survive: the row the operator is looking at lost its id
        // and its timestamp.
        let gutter = if rung.selected {
            t.text_secondary
        } else {
            t.text_muted
        };

        let mut spans = vec![
            Span::styled(marker, Style::default().fg(t.brand).bold()),
            Span::styled(
                format!("#{:<6}", rung.packet_id),
                Style::default().fg(gutter),
            ),
            Span::styled(
                format!("{:>8}  ", format_offset(rung.offset_ms)),
                Style::default().fg(gutter),
            ),
            // Arrows point away from the initiator, so a column of → is one
            // side talking and an alternating column is a conversation.
            Span::styled(
                if rung.from_initiator { "→ " } else { "← " },
                Style::default().fg(if rung.from_initiator {
                    t.tx_rate
                } else {
                    t.rx_rate
                }),
            ),
            Span::styled(
                format!("{:<label_w$}", truncate_info(&rung.label, label_w)),
                Style::default().fg(role_colour),
            ),
            Span::styled(
                format!("{:>7}", format_bytes(rung.bytes as u64)),
                Style::default().fg(gutter),
            ),
        ];
        if let Some(note) = rung.note {
            spans.push(Span::styled(
                if spell_notes {
                    format!("  {}", note.label())
                } else {
                    format!("  {}", note.glyph())
                },
                Style::default().fg(t.status_warn),
            ));
        }
        out.push(Line::from(spans).style(base));
    }
    out
}

/// Draw the stream panel's body into its inner rect.
///
/// The wrap mode is the point of this function existing. `trim: true` strips
/// leading whitespace from every line, which ate the one-space gutter on each
/// unselected rung while the selected one's `▌` survived — shifting every
/// other row of the ladder left by a column, so the arrows no longer formed a
/// column and the ladder stopped reading as one. The rungs are formatted to
/// width already; nothing here wants re-trimming.
fn render_stream_body(f: &mut Frame, lines: Vec<Line>, inner: Rect) {
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        Rect {
            x: inner.x + 1,
            width: inner.width.saturating_sub(2),
            ..inner
        },
    );
}

/// Offsets from the conversation's first packet, at a resolution that keeps
/// a handshake legible without printing six decimals for a long flow.
fn format_offset(ms: f64) -> String {
    if ms >= 1000.0 {
        format!("+{:.2}s", ms / 1000.0)
    } else {
        format!("+{ms:.1}ms")
    }
}

fn render_stream_summary(f: &mut Frame, app: &App, packets: &[CapturedPacket], area: Rect) {
    let t = &app.theme;
    // The column is reserved whatever the selection, so every one of these
    // cases has to say something. Three bare `return`s left an unbordered
    // blank rectangle beside a fully drawn decode, which reads as a panel
    // that failed to load rather than one with nothing to report — and the
    // three cases are not the same fact: no selection, a packet that stands
    // alone, and a conversation that has aged out of the ring are three
    // different things for an operator to know.
    let selected = selected_packet(app, packets);
    let resolved = selected.and_then(|p| {
        app.packet_collector
            .get_stream_for_packet(p)
            .map(|s| (s.index, s))
    });

    let (Some(pkt), Some((idx, stream))) = (selected, resolved) else {
        let msg = match selected {
            None => "Select a packet with ↑↓ to see the conversation it belongs to.",
            Some(p) if p.stream_index.is_none() => {
                "This packet stands alone — arp, icmp and broadcast traffic are not \
                 part of a conversation."
            }
            Some(_) => "The conversation this packet belongs to has aged out of the ring.",
        };
        f.render_widget(
            Paragraph::new(msg)
                .style(Style::default().fg(t.text_muted))
                .wrap(Wrap { trim: true })
                .block(widgets::Panel::new("stream").fit(area.width).block(t)),
            area,
        );
        return;
    };

    let app_label = stream.app_protocol.as_ref().map(app_protocol_summary);

    // The ladder gets whatever rows are left after the summary block and the
    // dns section, so the panel never asks for more rungs than it can draw.
    let is_dns = matches!(pkt.protocol.as_str(), "DNS");
    let overhead = SUMMARY_ROWS + if is_dns { DNS_ROWS } else { 0 };
    let ladder_rows = (area.height as usize)
        .saturating_sub(2)
        .saturating_sub(overhead);

    let convo = stream_context::conversation(&stream, packets, idx, Some(pkt.id), ladder_rows);

    let title = vec![
        Span::styled(
            format!("stream #{idx}"),
            Style::default().fg(t.brand).bold(),
        ),
        Span::styled(
            match (&convo.initiator, &convo.peer) {
                // Naming the initiator first turns an unordered pair into the
                // sentence "this end called that one".
                (Some(a), Some(b)) => format!("  {a} → {b}"),
                _ => format!("  {} ↔ {}", stream.key.addr_a.0, stream.key.addr_b.0),
            },
            Style::default().fg(t.text_secondary),
        ),
    ];
    let inner = widgets::Panel::styled(title)
        .meta_styled(vec![
            Span::styled(
                stream_context::nature(&stream, convo.phase, app_label.as_deref()),
                Style::default().fg(if convo.phase == stream_context::Phase::Reset {
                    t.status_error
                } else {
                    t.text_muted
                }),
            ),
            Span::styled("  f", Style::default().fg(t.key_hint).bold()),
            Span::styled(" follow", Style::default().fg(t.text_muted)),
        ])
        .fit(area.width)
        .render(f, t, area);

    if inner.height == 0 {
        return;
    }

    // Counters first: how much, how long, and whether the flow is healthy.
    let mut counters = vec![
        Span::styled(
            format!("{} packets", stream.packet_count),
            Style::default().fg(t.text_primary),
        ),
        Span::styled(
            format!(
                "  ↑{} ↓{}",
                format_bytes(convo.bytes_out),
                format_bytes(convo.bytes_in)
            ),
            Style::default().fg(t.text_muted),
        ),
    ];
    if convo.duration_ms >= 1.0 {
        counters.push(Span::styled(
            format!("  over {}", format_duration_ms(convo.duration_ms)),
            Style::default().fg(t.text_muted),
        ));
    }
    // Retransmits and reordering are the two numbers that change whether you
    // trust the flow, so they take a colour and are named separately — a
    // resend and a reorder have different causes.
    for (n, label) in [
        (convo.retransmits, "retransmit"),
        (convo.out_of_order, "out of order"),
    ] {
        if n > 0 {
            counters.push(Span::styled(
                format!("  {n} {label}{}", if n == 1 { "" } else { "s" }),
                Style::default().fg(t.status_warn),
            ));
        }
    }
    let mut lines: Vec<Line> = vec![Line::from(counters)];

    // Timing: the dns round trip when we have it, the tcp handshake otherwise.
    let timing = match dns_reply_latency(pkt, packets) {
        Some(l) => Some((format!("{:.1}ms round trip", l.ms), t.text_primary)),
        None => stream.handshake.as_ref().and_then(|h| {
            h.total_ms().map(|ms| {
                let detail = match (h.syn_to_syn_ack_ms(), h.syn_ack_to_ack_ms()) {
                    (Some(a), Some(b)) => {
                        format!("{ms:.1}ms handshake  (syn→syn·ack {a:.1}  →ack {b:.1})")
                    }
                    _ => format!("{ms:.1}ms handshake"),
                };
                (detail, t.text_muted)
            })
        }),
    };
    if let Some((text, colour)) = timing {
        lines.push(Line::from(Span::styled(text, Style::default().fg(colour))));
    }

    lines.extend(ladder_lines(&convo, t, inner.width.saturating_sub(2)));

    // Resolver behaviour over the capture, when this flow is DNS.
    if matches!(pkt.protocol.as_str(), "DNS") {
        lines.push(Line::raw(""));
        let resolver = if pkt.src_port == Some(53) {
            pkt.src_ip.clone()
        } else {
            pkt.dst_ip.clone()
        };
        let mine: Vec<&CapturedPacket> = packets
            .iter()
            .filter(|p| p.protocol == "DNS" && (p.src_ip == resolver || p.dst_ip == resolver))
            .collect();
        let queries = mine.iter().filter(|p| p.dst_ip == resolver).count();
        let replies = mine.iter().filter(|p| p.src_ip == resolver).count();

        let mut latencies: Vec<f64> = mine
            .iter()
            .filter(|p| p.src_ip == resolver)
            .filter_map(|p| dns_reply_latency(p, packets).map(|l| l.ms))
            .collect();
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        lines.push(Line::from(vec![
            Span::styled("resolver ", Style::default().fg(t.text_muted)),
            Span::styled(resolver.clone(), Style::default().fg(t.text_primary)),
        ]));
        lines.push(Line::from(Span::styled(
            format!(
                "queries {queries} · replies {replies} · unanswered {}",
                queries.saturating_sub(replies)
            ),
            Style::default().fg(t.text_muted),
        )));

        if !latencies.is_empty() {
            let pct = |p: f64| latencies[(((latencies.len() - 1) as f64) * p).round() as usize];
            let mut spans = vec![
                Span::styled("p50 ", Style::default().fg(t.text_muted)),
                Span::styled(
                    format!("{:.0}ms", pct(0.5)),
                    Style::default().fg(t.text_primary),
                ),
                Span::styled("  p95 ", Style::default().fg(t.text_muted)),
                Span::styled(
                    format!("{:.0}ms", pct(0.95)),
                    Style::default().fg(t.text_primary),
                ),
            ];
            if let Some(base) = app
                .diagnose
                .baselines
                .get(&resolver, "dns.rtt_p50")
                .filter(|_| {
                    app.diagnose
                        .baselines
                        .readiness(&resolver, "dns.rtt_p50")
                        .is_ready()
                })
            {
                spans.push(Span::styled(
                    format!("   base p50 {:.1}ms", base.mean),
                    Style::default().fg(t.text_muted),
                ));
            }
            lines.push(Line::from(spans));
        }
    }

    render_stream_body(f, lines, inner);
}

/// A DNS reply paired with the query it answers.
pub struct DnsLatency {
    pub query_id: u64,
    pub query_time: String,
    pub ms: f64,
}

/// Pair a DNS reply with its query and measure the gap.
///
/// Matched on the question — name and type — plus reversed endpoints, walking
/// backwards from the reply. The transaction id would be stronger, but it is
/// not carried on `AppProtocol::Dns`; the question is unique enough in
/// practice because a resolver that has two identical questions in flight to
/// the same client is already the problem being investigated.
pub fn dns_reply_latency(reply: &CapturedPacket, packets: &[CapturedPacket]) -> Option<DnsLatency> {
    use crate::dpi::AppProtocol::Dns;
    let Some(Dns {
        qname,
        qtype,
        rcode: Some(_),
    }) = &reply.app_protocol
    else {
        return None;
    };

    let query = packets
        .iter()
        .rev()
        .skip_while(|p| p.id >= reply.id)
        .find(|p| {
            matches!(
                &p.app_protocol,
                Some(Dns { qname: qn, qtype: qt, rcode: None }) if qn == qname && qt == qtype
            ) && p.src_ip == reply.dst_ip
                && p.dst_ip == reply.src_ip
        })?;

    // Capture timestamps are monotonic within a run, but a reply that somehow
    // precedes its query is a broken pairing rather than a negative latency.
    let ns = reply.timestamp_ns.checked_sub(query.timestamp_ns)?;
    Some(DnsLatency {
        query_id: query.id,
        query_time: query.timestamp.clone(),
        ms: ns as f64 / 1_000_000.0,
    })
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
            capture: None,
            annotation: None,
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

    /// Render the ladder to plain text, the way the panel draws it.
    fn ladder_text(convo: &stream_context::Conversation, width: u16) -> Vec<String> {
        let theme = crate::theme::by_name("default");
        ladder_lines(convo, &theme, width)
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn an_open_stream_view_does_not_follow_a_different_session() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut app =
            crate::app::App::prepare_with_config(crate::config::NetwatchConfig::default());
        app.packet_collector.seed_demo_capture();
        assert!(app.packet_collector.get_stream(1).is_some());
        app.ui.stream_view_index = Some(1);
        app.ui.stream_view_session = Some("previous-capture".into());
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal
            .draw(|f| render_stream_view(f, &app, f.area()))
            .unwrap();
        let screen: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(screen.contains("Stream #1 not found"), "{screen}");
    }

    fn demo_conversation(selected: Option<u64>) -> stream_context::Conversation {
        let c = crate::collectors::packets::PacketCollector::default();
        c.seed_demo_capture();
        let packets = c.get_packets().clone();
        // Stream #1 is the tls connection seeded by the demo.
        let stream = c.get_stream(1).expect("the demo seeds a tcp stream");
        stream_context::conversation(&stream, &packets, 1, selected, 12)
    }

    /// Every rung lines up. The cursor marker replaces a space rather than
    /// being inserted before one, so the selected row cannot shift the
    /// columns of the row above it.
    #[test]
    fn the_ladder_columns_line_up_on_every_rung() {
        let convo = demo_conversation(Some(5));
        let rows = ladder_text(&convo, 80);
        let rungs: Vec<&String> = rows.iter().filter(|r| r.contains('#')).collect();
        assert!(rungs.len() >= 6, "{rows:#?}");

        let arrow_col = |s: &str| {
            s.chars()
                .position(|c| c == '→' || c == '←')
                .unwrap_or_else(|| panic!("no arrow in {s:?}"))
        };
        let first = arrow_col(rungs[0]);
        for r in &rungs {
            assert_eq!(arrow_col(r), first, "misaligned rung: {r:?}");
        }
        assert!(
            rungs.iter().any(|r| r.starts_with('▌')),
            "the selected rung is marked: {rungs:#?}"
        );
        // The marked row keeps its id and its offset.
        let marked = rungs.iter().find(|r| r.starts_with('▌')).unwrap();
        assert!(marked.contains("#5"), "{marked:?}");
        assert!(marked.contains("ms"), "{marked:?}");
    }

    /// The ladder is the conversation: the handshake, the tls exchange, the
    /// resend and the reset, in order, with direction relative to the caller.
    #[test]
    fn the_ladder_tells_the_story_of_the_connection() {
        let convo = demo_conversation(Some(5));
        let rows = ladder_text(&convo, 80).join("\n");
        for expected in [
            "syn",
            "syn·ack",
            "ack",
            "tls client hello",
            "tls server hello",
            "tls certificate",
            "data",
            "rst",
        ] {
            assert!(rows.contains(expected), "missing {expected:?} in:\n{rows}");
        }
        // Packet #5 is the third packet *of this stream* — the ladder counts
        // within the conversation, not within the capture.
        assert!(rows.contains("packet 3 of 9"), "position is shown:\n{rows}");
        assert_eq!(convo.phase, stream_context::Phase::Reset);

        // Exactly one resend — the client re-sending its unacknowledged data.
        // The pure ACK that reuses the next segment's sequence number is not
        // one, and used to be counted as one.
        assert_eq!(convo.retransmits, 1, "{:#?}", convo.rungs);
        assert_eq!(
            rows.matches("retransmit").count(),
            1,
            "the ladder and the counter must agree:\n{rows}"
        );
    }

    /// The arrows form a column *on screen*, not just in the line builder.
    ///
    /// They did not: the panel drew its body with `Wrap { trim: true }`,
    /// which strips leading whitespace per line — so every unselected rung
    /// lost its one-space gutter while the selected rung's `▌` survived, and
    /// the ladder was shifted a column against itself. Asserting on
    /// `ladder_lines` alone missed it, because the defect was in how those
    /// lines were painted.
    #[test]
    fn the_arrows_form_a_column_once_painted() {
        use ratatui::{backend::TestBackend, Terminal};
        // The selection matters: the shift only appears when one rung starts
        // with `▌` and the rest start with a space, so a conversation with
        // nothing selected cannot show the defect.
        let convo = demo_conversation(Some(5));
        assert!(
            convo.rungs.iter().any(|r| r.selected),
            "the fixture must have a selected rung or this test proves nothing"
        );
        let theme = crate::theme::by_name("default");
        let lines = ladder_lines(&convo, &theme, 78);

        let mut terminal = Terminal::new(TestBackend::new(80, 20)).unwrap();
        terminal
            .draw(|f| render_stream_body(f, lines, Rect::new(0, 0, 80, 20)))
            .unwrap();
        let buf = terminal.backend().buffer().clone();

        let mut cols = Vec::new();
        for y in 0..buf.area.height {
            let row: String = (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect();
            if let Some(c) = row.chars().position(|c| c == '→' || c == '←') {
                cols.push((y, c, row.trim_end().to_string()));
            }
        }
        assert!(cols.len() >= 2, "expected several rungs, got {cols:#?}");
        let first = cols[0].1;
        for (y, c, row) in &cols {
            assert_eq!(*c, first, "row {y} is shifted: {row:?}");
        }
    }

    /// A narrow panel keeps the columns and shortens the label; it does not
    /// wrap a rung onto two lines.
    #[test]
    fn a_narrow_ladder_shortens_the_label_rather_than_wrapping() {
        let convo = demo_conversation(Some(6));
        for width in [40u16, 44, 52, 60, 100] {
            for row in ladder_text(&convo, width) {
                assert!(
                    row.chars().count() <= width as usize,
                    "rung overflows {width}: {row:?}"
                );
            }
        }
    }

    /// The stream column is reserved from the area alone. Walking a capture
    /// is the main thing done on this screen, and it used to rearrange itself
    /// on every arrow key: the column appeared only when the selected packet
    /// had a stream, so stepping onto an arp frame doubled the decode's width
    /// and re-wrapped every line in it.
    #[test]
    fn the_stream_column_depends_on_width_and_nothing_else() {
        let wide = Rect::new(0, 0, 160, 16);
        let (detail, stream) = lower_panes(wide);
        let stream = stream.expect("a wide pane reserves the stream column");
        assert_eq!(detail.x, wide.x);
        assert_eq!(
            detail.width + stream.width,
            wide.width,
            "the two columns must tile the pane exactly"
        );
        assert_eq!(stream.x, detail.x + detail.width, "no gap between them");
        assert_eq!(detail.height, wide.height);
        assert_eq!(stream.height, wide.height);

        // Narrow: the decode takes the row on its own rather than being
        // squeezed to 55% of too little.
        let narrow = Rect::new(0, 0, STREAM_COLUMN_MIN_WIDTH - 1, 16);
        let (detail, stream) = lower_panes(narrow);
        assert!(stream.is_none());
        assert_eq!(detail, narrow);
    }

    /// The three boxes in the decode column keep their heights whatever is
    /// selected. Sizing the protocol box to its own line count made the
    /// payload and hex boxes slide several rows on every keypress, because a
    /// dns reply and a tcp ack do not decode to the same number of lines.
    #[test]
    fn the_decode_column_always_has_three_boxes_at_fixed_heights() {
        for height in [16u16, 24, 40] {
            let area = Rect::new(0, 0, 90, height);
            let rows = detail_rows(area);
            assert_eq!(rows.len(), 3, "protocol, payload, hex");
            assert_eq!(
                rows.iter().map(|r| r.height).sum::<u16>(),
                height,
                "the boxes must tile the column at height {height}"
            );
            // Stacked, in order, with no gaps.
            assert_eq!(rows[0].y, area.y);
            assert_eq!(rows[1].y, rows[0].y + rows[0].height);
            assert_eq!(rows[2].y, rows[1].y + rows[1].height);
            // The decode gets the majority; the other two are equal.
            assert!(rows[0].height > rows[1].height, "at height {height}");
            assert_eq!(rows[1].height, rows[2].height, "at height {height}");
        }
    }

    #[test]
    fn clipboard_includes_full_decrypted_payload() {
        // A payload longer than the on-screen cap must still appear in full
        // on the clipboard — `y` is the "see the whole thing" affordance.
        let mut body = b"GET /verify HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        body.extend(std::iter::repeat_n(b'Z', 4000));
        let out = format_packet_for_clipboard(&pkt_with_decrypted(Some(body.clone())), &[]);
        assert!(out.contains("── TLS decrypted (4043 bytes) ──"));
        assert!(out.contains("GET /verify HTTP/1.1"));
        assert!(out.contains("Host: example.com"));
        assert_eq!(out.matches('Z').count(), 4000, "full payload, untruncated");
    }

    /// A copied IPv6 packet and its list cells bracket the address before
    /// the port: `2001:db8::20:53` would paste as a different host.
    #[test]
    fn ipv6_endpoints_are_bracketed_where_a_port_follows() {
        let mut pkt = pkt_with_decrypted(None);
        pkt.src_ip = "2001:db8::10".into();
        pkt.src_port = Some(53002);
        pkt.dst_ip = "2001:db8::20".into();
        pkt.dst_port = Some(53);
        let out = format_packet_for_clipboard(&pkt, &[]);
        assert!(
            out.contains("[2001:db8::10]:53002 → [2001:db8::20]:53  (100 bytes)"),
            "{out}"
        );
        assert_eq!(
            endpoint_cell("2001:db8::20", Some(53)),
            "[2001:db8::20]:53 (DNS)"
        );
        assert_eq!(
            endpoint_cell("2001:db8::10", Some(53002)),
            "[2001:db8::10]:53002"
        );
        assert_eq!(endpoint_cell("2001:db8::10", None), "2001:db8::10");
        assert_eq!(
            endpoint_cell("192.0.2.1", Some(443)),
            "192.0.2.1:443 (HTTPS)"
        );
        assert_eq!(endpoint_cell("dns.google", Some(53)), "dns.google:53 (DNS)");
    }

    #[test]
    fn clipboard_omits_section_without_decryption() {
        let out = format_packet_for_clipboard(&pkt_with_decrypted(None), &[]);
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

    /// Decrypted plaintext and HTTP/3 bodies are the server's to write. The
    /// preview keeps its line breaks and loses everything else a terminal
    /// would act on, bidi overrides included.
    #[test]
    fn preview_decrypted_replaces_control_characters_but_keeps_newlines() {
        let body = "HTTP/1.1 200 OK\r\nX: \x1b]52;c;AAAA\x07\u{202E}\n\nbody";
        assert_eq!(
            preview_decrypted_bytes(body.as_bytes(), body.len()),
            "HTTP/1.1 200 OK·\nX: ·]52;c;AAAA··\n\nbody"
        );
    }

    fn dns_packet(
        id: u64,
        src: &str,
        dst: &str,
        qname: &str,
        rcode: Option<u8>,
        ns: u64,
    ) -> CapturedPacket {
        CapturedPacket {
            capture: None,
            annotation: None,
            id,
            timestamp: format!("06:49:20.{id:03}"),
            src_ip: src.into(),
            dst_ip: dst.into(),
            src_host: None,
            dst_host: None,
            protocol: "DNS".into(),
            length: 71,
            src_port: Some(if rcode.is_some() { 53 } else { 58248 }),
            dst_port: Some(if rcode.is_some() { 58248 } else { 53 }),
            info: qname.into(),
            details: Vec::new(),
            payload_text: String::new(),
            raw_hex: String::new(),
            raw_ascii: String::new(),
            raw_bytes: Vec::new(),
            stream_index: Some(1),
            tcp_flags: None,
            tcp_seq: None,
            expert: ExpertSeverity::Chat,
            timestamp_ns: ns,
            app_protocol: Some(crate::dpi::AppProtocol::Dns {
                qname: qname.into(),
                qtype: 1,
                rcode,
            }),
            decrypted_plaintext: None,
        }
    }

    /// The id and stream columns are muted, and muted grey on the selection
    /// background is invisible — so both vanished on whichever row the cursor
    /// was on. That is the row whose id a reader most likely wants to quote.
    #[test]
    fn muted_cells_stay_legible_on_the_selected_row() {
        let t = crate::theme::by_name("dark");
        let muted = Style::default().fg(t.text_muted);

        assert_eq!(
            readable_when_selected(muted, true, &t).fg,
            Some(t.text_secondary),
            "a muted cell must lift on the selected row"
        );
        assert_eq!(
            readable_when_selected(muted, false, &t).fg,
            Some(t.text_muted),
            "and stay muted everywhere else"
        );

        // A cell already carrying meaning keeps it — the expert and protocol
        // columns are legible on the band and must not be recoloured.
        for carried in [t.status_error, t.status_warn, t.brand, t.text_primary] {
            let styled = Style::default().fg(carried);
            assert_eq!(
                readable_when_selected(styled, true, &t).fg,
                Some(carried),
                "{carried:?} must survive selection unchanged"
            );
        }
    }

    /// The reply is paired with *its own* query — matched on the question and
    /// on reversed endpoints, so a second name in flight to the same resolver
    /// cannot borrow the wrong start time.
    #[test]
    fn dns_latency_pairs_a_reply_with_its_own_query() {
        let packets = vec![
            dns_packet(1, "10.0.0.4", "169.254.1.1", "example.com", None, 0),
            dns_packet(2, "10.0.0.4", "169.254.1.1", "other.test", None, 1_000_000),
            dns_packet(
                3,
                "169.254.1.1",
                "10.0.0.4",
                "example.com",
                Some(0),
                41_200_000,
            ),
        ];
        let l = dns_reply_latency(&packets[2], &packets).expect("a pairing");
        assert_eq!(l.query_id, 1, "matched the wrong query");
        assert!((l.ms - 41.2).abs() < 0.01, "{}ms", l.ms);
    }

    /// A reply with no query in the buffer is not a zero-millisecond reply.
    #[test]
    fn dns_latency_is_absent_when_the_query_was_not_captured() {
        let packets = vec![dns_packet(
            9,
            "169.254.1.1",
            "10.0.0.4",
            "example.com",
            Some(0),
            5,
        )];
        assert!(dns_reply_latency(&packets[0], &packets).is_none());
        // And a query is not a reply.
        let q = vec![dns_packet(1, "10.0.0.4", "169.254.1.1", "a.test", None, 0)];
        assert!(dns_reply_latency(&q[0], &q).is_none());
    }

    /// `x` narrows to findings. Chat and Note are the ordinary run of a
    /// capture; only Warn and Error are things to look at.
    #[test]
    fn only_warnings_and_errors_count_as_expert_findings() {
        let mut p = dns_packet(1, "a", "b", "x.test", None, 0);
        for (sev, expected) in [
            (ExpertSeverity::Chat, false),
            (ExpertSeverity::Note, false),
            (ExpertSeverity::Warn, true),
            (ExpertSeverity::Error, true),
        ] {
            p.expert = sev;
            assert_eq!(is_expert(&p), expected, "{sev:?}");
        }
    }
}
