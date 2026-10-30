use std::collections::HashMap;

use crate::app::App;
use crate::collectors::geo::is_private_ip;
use crate::collectors::traceroute::TracerouteStatus;
use crate::theme::Theme;
use crate::ui::text::truncate_end as truncate;
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{BorderType, Paragraph},
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(14),   // topology graph (gets the slack)
            Constraint::Length(9), // hop detail table — fixed compact
            Constraint::Length(3), // footer
        ])
        .split(area);

    widgets::render_header(f, app, chunks[0]);
    render_topology_graph(f, app, chunks[1]);
    render_hop_detail(f, app, chunks[2]);
    render_footer(f, app, chunks[3]);
}

// ── Topology graph ──────────────────────────────────────────

struct RemoteNode {
    ip: String,
    label: String,
    process: Option<String>,
    conn_count: usize,
    rtt_ms: Option<f64>,
    has_established: bool,
}

/// The peers the Topology cursor steps through, in its order: the LAN
/// column, then the internet column, each as the graph draws it. `Enter` and
/// `T` act on the peer at the cursor's index here. It comes from the same
/// build as the graph, so it cannot name a host other than the highlighted
/// one, as a separate copy of the partition and sort once did.
pub(crate) fn selectable_peers(app: &App) -> Vec<String> {
    let (local, public) = build_remote_nodes(app);
    local
        .into_iter()
        .chain(public)
        .map(|node| node.ip)
        .collect()
}

fn build_remote_nodes(app: &App) -> (Vec<RemoteNode>, Vec<RemoteNode>) {
    let mut remotes: HashMap<String, (RemoteNode, bool)> = HashMap::new();
    let conns = app.connection_collector.connections();
    for conn in conns.iter() {
        let Some(ip) = crate::app::parse_addr_parts(&conn.remote_addr).0 else {
            continue;
        };
        let is_local = is_private_ip(&ip);
        let entry = remotes.entry(ip.clone()).or_insert_with(|| {
            (
                RemoteNode {
                    ip: ip.clone(),
                    label: app
                        .packet_collector
                        .dns_cache
                        .lookup(&ip)
                        .unwrap_or(ip.clone()),
                    process: None,
                    conn_count: 0,
                    rtt_ms: None,
                    has_established: false,
                },
                is_local,
            )
        });
        entry.0.conn_count += 1;
        if conn.state == "ESTABLISHED" {
            entry.0.has_established = true;
        }
        if entry.0.process.is_none() {
            entry.0.process = conn.process_name.clone();
        }
        if let Some(rtt_us) = conn.handshake_rtt_us {
            let rtt_ms = rtt_us / 1000.0;
            entry.0.rtt_ms = Some(match entry.0.rtt_ms {
                Some(prev) => prev.min(rtt_ms),
                None => rtt_ms,
            });
        }
    }
    let mut local: Vec<RemoteNode> = Vec::new();
    let mut public: Vec<RemoteNode> = Vec::new();
    for (_, (node, is_local)) in remotes {
        if is_local {
            local.push(node);
        } else {
            public.push(node);
        }
    }
    let sort = |nodes: &mut Vec<RemoteNode>| {
        nodes.sort_by(|a, b| {
            b.has_established
                .cmp(&a.has_established)
                .then_with(|| b.conn_count.cmp(&a.conn_count))
                .then_with(|| a.label.cmp(&b.label))
        });
    };
    sort(&mut local);
    sort(&mut public);
    (local, public)
}

fn render_topology_graph(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let legend = Line::from(vec![
        Span::styled(" ● ", Style::default().fg(t.status_good)),
        Span::styled("ok  ", Style::default().fg(t.text_muted)),
        Span::styled("● ", Style::default().fg(t.status_warn)),
        Span::styled(">50ms  ", Style::default().fg(t.text_muted)),
        Span::styled("● ", Style::default().fg(t.status_error)),
        Span::styled(">200ms / loss ", Style::default().fg(t.text_muted)),
    ])
    .alignment(Alignment::Right);
    let block = widgets::panel_block(t)
        .title(Line::from(Span::styled(
            " topology ",
            Style::default().fg(t.brand).bold(),
        )))
        .title(legend);
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 8 || inner.width < 90 {
        let msg = Paragraph::new(" Terminal too small for graph view")
            .style(Style::default().fg(t.text_muted));
        f.render_widget(msg, inner);
        return;
    }

    let (local_nodes, public_nodes) = build_remote_nodes(app);
    let hs = app.health_prober.status();

    // Layout: [SELF + LAN peers] ─ ROUTER ─ ISP ─ [public peers]
    let router_w = 16u16;
    let isp_w = 16u16;
    let gap = 4u16; // gap between center boxes
    let edge_gap = 3u16; // gap between center boxes and side columns
    let center_w = router_w + gap + isp_w;
    let side_total = inner.width.saturating_sub(center_w + edge_gap * 2);
    let lan_w = side_total / 2;
    let pub_w = side_total - lan_w;

    let lan_x = inner.x;
    let router_x = lan_x + lan_w + edge_gap;
    let isp_x = router_x + router_w + gap;
    let pub_x = isp_x + isp_w + edge_gap;

    // Center vertical row for the spine
    let mid_y = inner.y + inner.height / 2;

    // SELF box — rendered at the top of the left column, since the user's
    // host is itself a "local address" and belongs visually with the LAN.
    let hostname = app.config_collector.config.hostname.clone();
    let primary_ip = app
        .interface_info
        .iter()
        .find(|i| i.is_up && i.ipv4.is_some() && i.name != "lo0" && i.name != "lo")
        .and_then(|i| i.ipv4.clone())
        .unwrap_or_else(|| "—".to_string());
    let primary_iface = app
        .interface_info
        .iter()
        .find(|i| i.is_up && i.ipv4.is_some() && i.name != "lo0" && i.name != "lo")
        .map(|i| i.name.clone())
        .unwrap_or_else(|| "—".to_string());
    let self_h = 4u16;
    let self_w = lan_w;
    let self_y = inner.y;
    let self_block = widgets::panel_block(t)
        .title(Line::from(Span::styled(
            " self ",
            Style::default().fg(t.brand).bold(),
        )))
        // Emphasis is the accent border, not a second border weight — one
        // box in double lines next to nine in rounded ones reads as a
        // different kind of object, which "this machine" is not.
        .border_style(Style::default().fg(t.brand));
    let self_rect = Rect::new(lan_x, self_y, self_w, self_h);
    let self_inner_inner = self_block.inner(self_rect);
    f.render_widget(self_block, self_rect);
    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                format!(" {} ", hostname),
                Style::default().fg(t.brand).bold(),
            )),
            Line::from(Span::styled(
                format!(" {}  {} ", primary_ip, primary_iface),
                Style::default().fg(t.text_muted),
            )),
        ]),
        self_inner_inner,
    );

    // ROUTER box
    let router_label = app
        .config_collector
        .config
        .gateway
        .clone()
        .unwrap_or_else(|| "—".to_string());
    let gw_health = health_dot(hs.gateway_rtt_ms, hs.gateway_loss.pct().unwrap_or(0.0), t);
    let gw_color = gw_health.1;
    let router_h = 4u16;
    let router_y = mid_y.saturating_sub(router_h / 2);
    let router_block = widgets::panel_block(t)
        .title(Line::from(Span::styled(
            " router ",
            Style::default().fg(t.brand).bold(),
        )))
        .border_type(BorderType::Rounded);
    let router_rect = Rect::new(router_x, router_y, router_w, router_h);
    let router_inner = router_block.inner(router_rect);
    f.render_widget(router_block, router_rect);
    let rtt_str = hs
        .gateway_rtt_ms
        .map(|r| format!("{:.1}ms", r))
        .unwrap_or_else(|| "—".to_string());
    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                format!(" {} ", router_label),
                Style::default().fg(t.text_primary),
            )),
            Line::from(Span::styled(
                // "up" was printed unconditionally, beside a connection box
                // that could say the gateway was not answering.
                format!(
                    " {}  {}",
                    if matches!(
                        app.uptime.connection(),
                        crate::uptime::Connection::Down {
                            hop: crate::uptime::Hop::Gateway,
                            ..
                        }
                    ) {
                        "down"
                    } else {
                        "up"
                    },
                    rtt_str
                ),
                Style::default().fg(t.text_muted),
            )),
        ]),
        router_inner,
    );

    // ISP box (derive from traceroute hop 2 if available)
    let traceroute =
        crate::app::safe_lock(&app.traceroute_runner.result, "topology::render_isp_box");
    let isp_hop = traceroute.hops.iter().find(|h| h.hop_number == 2);
    let isp_ip = isp_hop
        .and_then(|h| h.ip.clone())
        .unwrap_or_else(|| "—".to_string());
    let isp_rtt: Option<f64> = isp_hop.and_then(|h| h.rtt_ms.iter().filter_map(|r| *r).next());
    let isp_dot_color = match isp_rtt {
        Some(r) if r < 50.0 => t.status_good,
        Some(r) if r < 200.0 => t.status_warn,
        Some(_) => t.status_error,
        None => t.text_muted,
    };
    let isp_h = 4u16;
    let isp_y = mid_y.saturating_sub(isp_h / 2);
    let isp_block = widgets::panel_block(t)
        .title(Line::from(Span::styled(
            " isp gateway ",
            Style::default().fg(t.brand).bold(),
        )))
        .border_type(BorderType::Rounded);
    let isp_rect = Rect::new(isp_x, isp_y, isp_w, isp_h);
    let isp_inner = isp_block.inner(isp_rect);
    f.render_widget(isp_block, isp_rect);
    let isp_rtt_str = isp_rtt
        .map(|r| format!("{:.1}ms", r))
        .unwrap_or_else(|| "—".to_string());
    let isp_status = if isp_rtt.is_some() {
        format!("up  {}", isp_rtt_str)
    } else {
        "T:Traceroute".to_string()
    };
    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                format!(" {} ", truncate(&isp_ip, isp_w as usize - 2)),
                Style::default().fg(t.text_primary),
            )),
            Line::from(Span::styled(
                format!(" {}", isp_status),
                Style::default().fg(t.text_muted),
            )),
        ]),
        isp_inner,
    );
    drop(traceroute);

    render_connection_uptime(
        f,
        app,
        Rect::new(router_x, isp_y + isp_h + 1, center_w, 4),
        inner,
    );

    // Spine connector: ROUTER → ISP. The locals-trunk (left column → ROUTER)
    // and publics-trunk (ISP → right column) are drawn below.
    let spine_y = mid_y;
    if spine_y >= inner.y && spine_y < inner.y + inner.height {
        let connector2_x = router_x + router_w;
        let connector2_w = isp_x - connector2_x;
        let conn2_text: String = "─".repeat(connector2_w as usize);
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                conn2_text,
                Style::default().fg(isp_dot_color),
            ))),
            Rect::new(connector2_x, spine_y, connector2_w, 1),
        );
        if spine_y > inner.y {
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    format!(" {} ", isp_rtt_str),
                    Style::default().fg(t.text_muted),
                ))),
                Rect::new(
                    connector2_x + 1,
                    spine_y - 1,
                    connector2_w.saturating_sub(2),
                    1,
                ),
            );
        }
    }

    // Suppress unused-warning: rtt_str is rendered as part of ROUTER box,
    // and gateway_loss_pct is not shown on the trunk in this layout.
    let _ = (&rtt_str, hs.gateway_loss, gw_color);
    drop(hs);

    // Cursor index spans both columns: [local..., public...]
    let combined_len = local_nodes.len() + public_nodes.len();
    let selected = if combined_len == 0 {
        0
    } else {
        app.ui.scroll.topology_scroll.min(combined_len - 1)
    };
    let local_selected = if selected < local_nodes.len() {
        Some(selected)
    } else {
        None
    };
    let public_selected = if selected >= local_nodes.len() {
        Some(selected - local_nodes.len())
    } else {
        None
    };

    // Trunk connectors: a single horizontal line at mid_y between each spine
    // box and its side column, so peers feel attached to the box even when
    // their rows are above or below mid_y.
    // Trunk connectors. Each trunk ends with a colored ● status dot pinned to
    // the spine box's edge, so router/isp health is visible at a glance.
    // Locals trunk: left column → ROUTER; publics trunk: ISP → right column.
    if lan_w > 14 && mid_y < inner.y + inner.height {
        let trunk_x = lan_x + lan_w;
        let trunk_w = router_x.saturating_sub(trunk_x);
        if trunk_w >= 1 {
            let mut spans: Vec<Span> = Vec::new();
            if trunk_w > 1 {
                spans.push(Span::styled(
                    "─".repeat((trunk_w - 1) as usize),
                    Style::default().fg(t.border),
                ));
            }
            spans.push(Span::styled("●", Style::default().fg(gw_color)));
            f.render_widget(
                Paragraph::new(Line::from(spans)),
                Rect::new(trunk_x, mid_y, trunk_w, 1),
            );
        }
    }
    if pub_w > 14 && mid_y < inner.y + inner.height {
        let trunk_x = isp_x + isp_w;
        let trunk_w = pub_x.saturating_sub(trunk_x);
        if trunk_w >= 1 {
            let mut spans: Vec<Span> = vec![Span::styled("●", Style::default().fg(isp_dot_color))];
            if trunk_w > 1 {
                spans.push(Span::styled(
                    "─".repeat((trunk_w - 1) as usize),
                    Style::default().fg(t.border),
                ));
            }
            f.render_widget(
                Paragraph::new(Line::from(spans)),
                Rect::new(trunk_x, mid_y, trunk_w, 1),
            );
        }
    }

    // LAN peers column — sits below the SELF box at the top of the left side.
    let lan_body_y = inner.y + self_h;
    let lan_body_h = inner.height.saturating_sub(self_h);
    if lan_w > 14 && lan_body_h > 1 {
        render_side_column(
            f,
            app,
            Rect::new(lan_x, lan_body_y, lan_w, lan_body_h),
            &local_nodes,
            local_selected,
            Side::Left,
            "no LAN peers",
            mid_y,
        );
    }

    // Public peers column (right of ISP)
    if pub_w > 14 {
        render_side_column(
            f,
            app,
            Rect::new(pub_x, inner.y, pub_w, inner.height),
            &public_nodes,
            public_selected,
            Side::Right,
            "no public peers",
            mid_y,
        );
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Left,
    Right,
}

fn render_side_column(
    f: &mut Frame,
    app: &App,
    area: Rect,
    nodes: &[RemoteNode],
    selected_idx: Option<usize>,
    side: Side,
    empty_label: &str,
    spine_mid_y: u16,
) {
    let t = &app.theme;
    let header_text = match side {
        Side::Left => " lan peers ",
        Side::Right => " internet ",
    };
    let align = match side {
        Side::Left => Alignment::Left,
        Side::Right => Alignment::Right,
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            header_text,
            Style::default().fg(t.text_muted).bold(),
        )))
        .alignment(align),
        Rect::new(area.x, area.y, area.width, 1),
    );

    // Reserve the header row so node rows don't sit on top of it.
    let body_y = area.y + 1;
    let body_h = area.height.saturating_sub(1);

    let max_nodes = (body_h / 2).min(5) as usize;
    let visible: Vec<&RemoteNode> = nodes.iter().take(max_nodes).collect();
    if visible.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                empty_label,
                Style::default().fg(t.text_muted),
            )))
            .alignment(align),
            Rect::new(area.x, spine_mid_y, area.width, 1),
        );
        return;
    }

    let n = visible.len() as u16;
    let spacing = (body_h / n).max(2);
    let total = spacing * n;
    let start_y = body_y + body_h.saturating_sub(total) / 2;

    for (i, remote) in visible.iter().enumerate() {
        let row_y = start_y + i as u16 * spacing;
        if row_y + 1 >= area.y + area.height {
            break;
        }

        let is_selected = selected_idx == Some(i);
        let dot_color = match remote.rtt_ms {
            Some(r) if r < 50.0 => t.status_good,
            Some(r) if r < 200.0 => t.status_warn,
            Some(_) => t.status_error,
            None if remote.has_established => t.status_good,
            None => t.text_muted,
        };

        let rtt_str = remote
            .rtt_ms
            .map(|r| format!("{:.0}ms", r))
            .unwrap_or_else(|| "—".to_string());
        let proc_str = remote.process.as_deref().unwrap_or("—");
        let label_color = if is_selected { t.brand } else { t.text_primary };
        let muted = Style::default().fg(t.text_muted);
        let bold_label = Style::default().fg(label_color).bold();
        let cursor_style = Style::default().fg(t.brand).bold();

        // Layout per side: status ● sits at the spine-facing edge so it lines
        // up with the trunk; label/cursor on the outer edge.
        // Reserve: cursor (2) + " " (1) + rtt (5) + " " (1) + ● (1) = 10
        let label_w = (area.width as usize).saturating_sub(10);
        let label = truncate(&remote.label, label_w);

        let (line1, line2) = match side {
            Side::Left => {
                // [▸ label   12ms ●]   — ● pinned to right edge (trunk side)
                let label_pad = format!("{:<w$}", label, w = label_w);
                let cursor = if is_selected { "▸ " } else { "  " };
                let l1 = Line::from(vec![
                    Span::styled(cursor, cursor_style),
                    Span::styled(label_pad, bold_label),
                    Span::raw(" "),
                    Span::styled(format!("{:>5}", rtt_str), muted),
                    Span::raw(" "),
                    Span::styled("●", Style::default().fg(dot_color)),
                ]);
                let l2 = Line::from(vec![
                    Span::raw("  "),
                    Span::styled(format!("{}× {}", remote.conn_count, proc_str), muted),
                ]);
                (l1, l2)
            }
            Side::Right => {
                // [● 12ms   label ◂]   — ● pinned to left edge (trunk side)
                let label_pad = format!("{:>w$}", label, w = label_w);
                let cursor = if is_selected { " ◂" } else { "  " };
                let l1 = Line::from(vec![
                    Span::styled("●", Style::default().fg(dot_color)),
                    Span::raw(" "),
                    Span::styled(format!("{:<5}", rtt_str), muted),
                    Span::raw(" "),
                    Span::styled(label_pad, bold_label),
                    Span::styled(cursor, cursor_style),
                ]);
                let body = format!("{}× {}", remote.conn_count, proc_str);
                let l2 = Line::from(vec![
                    Span::styled(
                        format!("{:>w$}", body, w = (area.width as usize).saturating_sub(2)),
                        muted,
                    ),
                    Span::raw("  "),
                ]);
                (l1, l2)
            }
        };

        f.render_widget(
            Paragraph::new(vec![line1, line2]),
            Rect::new(area.x, row_y, area.width, 2),
        );
    }
}

// ── Hop detail table ────────────────────────────────────────

/// How long the connection has been up, under the router → ISP spine: the
/// live state of the uptime monitor (`netwatch uptime` has the history).
/// Falls back to one line when the graph has no room for the box.
fn render_connection_uptime(f: &mut Frame, app: &App, rect: Rect, inner: Rect) {
    let t = &app.theme;
    let (state, headline, detail) = connection_text(app.uptime.connection(), chrono::Local::now());
    let dot = match state {
        ConnState::Up => t.status_good,
        ConnState::Down => t.status_error,
        ConnState::Unknown => t.text_muted,
    };
    let headline = Line::from(vec![
        Span::styled(" ● ", Style::default().fg(dot)),
        Span::styled(headline, Style::default().fg(t.text_primary).bold()),
    ]);
    let detail = Span::styled(format!(" {detail}"), Style::default().fg(t.text_muted));
    let bottom = inner.y + inner.height;
    if rect.y + rect.height <= bottom {
        let block = widgets::panel_block(t)
            .title(Line::from(Span::styled(
                " connection ",
                Style::default().fg(t.brand).bold(),
            )))
            .border_type(BorderType::Rounded);
        let body = block.inner(rect);
        f.render_widget(block, rect);
        f.render_widget(Paragraph::new(vec![headline, Line::from(detail)]), body);
    } else if rect.y < bottom {
        let mut spans = headline.spans;
        spans.push(detail);
        f.render_widget(
            Paragraph::new(Line::from(spans)),
            Rect::new(rect.x, rect.y, rect.width, 1),
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum ConnState {
    Up,
    Down,
    Unknown,
}

/// The connection box's two lines, against an explicit `now` so the
/// durations can be tested exactly.
fn connection_text(
    conn: crate::uptime::Connection,
    now: chrono::DateTime<chrono::Local>,
) -> (ConnState, String, String) {
    use crate::uptime::{duration, Connection};
    let ago = |since: u64| duration((now.timestamp().max(0) as u64).saturating_sub(since));
    let clock = |at: u64| {
        let at = chrono::DateTime::from_timestamp(at as i64, 0)
            .unwrap_or_default()
            .with_timezone(&chrono::Local);
        // The box is 34 columns; a date with a time does not fit beside
        // the outage.
        if at.date_naive() == now.date_naive() {
            at.format("%H:%M").to_string()
        } else {
            at.format("%b %-d").to_string()
        }
    };
    match conn {
        Connection::Up { since, last_outage } => (
            ConnState::Up,
            format!("up {}", ago(since)),
            match last_outage {
                Some(o) => format!(
                    "since {} ({}, {})",
                    clock(o.end),
                    o.hop.name(),
                    duration(o.end.saturating_sub(o.start))
                ),
                None => "since netwatch started".to_string(),
            },
        ),
        Connection::Down { since, hop } => (
            ConnState::Down,
            format!("down {}", ago(since)),
            format!("{} not answering", hop.name()),
        ),
        Connection::Unknown => (
            ConnState::Unknown,
            "checking".to_string(),
            "waiting for the internet probe".to_string(),
        ),
    }
}

fn render_hop_detail(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let result =
        crate::app::safe_lock(&app.traceroute_runner.result, "topology::render_hop_detail");

    let title_left = format!(" hop detail  self → {} ", result.target);
    let title_right = match result.status {
        TracerouteStatus::Idle => " press T to traceroute ".to_string(),
        TracerouteStatus::Running => " ⏳ running… ".to_string(),
        TracerouteStatus::Done => format!(" {} hops ", result.hops.len()),
        TracerouteStatus::Error(_) => " error ".to_string(),
    };
    let title_right_color = match &result.status {
        TracerouteStatus::Running => t.status_warn,
        TracerouteStatus::Error(_) => t.status_error,
        _ => t.text_muted,
    };

    let block = widgets::panel_block(t)
        .title(Line::from(Span::styled(
            title_left,
            Style::default().fg(t.status_warn).bold(),
        )))
        .title(
            Line::from(Span::styled(
                title_right,
                Style::default().fg(title_right_color),
            ))
            .alignment(Alignment::Right),
        );
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 2 {
        return;
    }

    let header =
        "  hop   host                              ip                    rtt      loss    jitter";
    let header_area = Rect {
        x: inner.x + 1,
        y: inner.y,
        width: inner.width.saturating_sub(2),
        height: 1,
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            header,
            Style::default().fg(t.text_muted),
        ))),
        header_area,
    );

    if let TracerouteStatus::Error(ref msg) = result.status {
        let msg_area = Rect {
            x: inner.x + 2,
            y: inner.y + 1,
            width: inner.width.saturating_sub(2),
            height: 1,
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!("✗ {}", msg),
                Style::default().fg(t.status_error),
            ))),
            msg_area,
        );
        return;
    }

    if matches!(result.status, TracerouteStatus::Idle) && result.hops.is_empty() {
        let msg_area = Rect {
            x: inner.x + 2,
            y: inner.y + 1,
            width: inner.width.saturating_sub(2),
            height: 1,
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "Press T to run traceroute against the gateway/selected remote.",
                Style::default().fg(t.text_muted),
            ))),
            msg_area,
        );
        return;
    }

    let max_rows = inner.height.saturating_sub(1) as usize;
    for (i, hop) in result.hops.iter().take(max_rows).enumerate() {
        let row_y = inner.y + 1 + i as u16;
        render_hop_row(f, t, inner, row_y, hop);
    }
}

fn render_hop_row(
    f: &mut Frame,
    t: &Theme,
    inner: Rect,
    row_y: u16,
    hop: &crate::collectors::traceroute::TracerouteHop,
) {
    let host = hop
        .host
        .clone()
        .or_else(|| hop.ip.clone())
        .unwrap_or_else(|| "*".to_string());
    let ip = hop.ip.clone().unwrap_or_else(|| "—".to_string());

    let valid: Vec<f64> = hop.rtt_ms.iter().filter_map(|r| *r).collect();
    let lost = hop.rtt_ms.len() - valid.len();
    let loss_pct = if hop.rtt_ms.is_empty() {
        100.0
    } else {
        (lost as f64) / (hop.rtt_ms.len() as f64) * 100.0
    };
    let avg_rtt = if valid.is_empty() {
        None
    } else {
        Some(valid.iter().sum::<f64>() / valid.len() as f64)
    };
    let jitter = if valid.len() < 2 {
        None
    } else {
        let mean = valid.iter().sum::<f64>() / valid.len() as f64;
        let var = valid.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / valid.len() as f64;
        Some(var.sqrt())
    };

    let rtt_color = match avg_rtt {
        Some(r) if r < 10.0 => t.status_good,
        Some(r) if r < 50.0 => t.status_warn,
        Some(r) if r < 200.0 => t.accent_amber(),
        Some(_) => t.status_error,
        None => t.text_muted,
    };

    let rtt_str = avg_rtt
        .map(|r| format!("{:.1}ms", r))
        .unwrap_or_else(|| "—".to_string());
    let loss_str = if loss_pct == 0.0 {
        "0%".to_string()
    } else {
        format!("{:.0}%", loss_pct)
    };
    let jitter_str = jitter
        .map(|j| format!("{:.1}", j))
        .unwrap_or_else(|| "—".to_string());

    let line = Line::from(vec![
        Span::styled("● ", Style::default().fg(rtt_color)),
        Span::styled(
            format!("{:>3} ", hop.hop_number),
            Style::default().fg(t.text_muted),
        ),
        Span::raw(" "),
        Span::styled(
            format!("{:<32}", truncate(&host, 32)),
            Style::default().fg(if hop.ip.is_some() {
                t.text_primary
            } else {
                t.text_muted
            }),
        ),
        Span::raw(" "),
        Span::styled(
            format!("{:<19}", truncate(&ip, 19)),
            Style::default().fg(t.text_muted),
        ),
        Span::styled(format!("{:>8}", rtt_str), Style::default().fg(rtt_color)),
        Span::raw(" "),
        Span::styled(
            format!("{:>5}", loss_str),
            Style::default().fg(if loss_pct == 0.0 {
                t.status_good
            } else {
                t.status_warn
            }),
        ),
        Span::raw(" "),
        Span::styled(
            format!("{:>6}", jitter_str),
            Style::default().fg(t.text_muted),
        ),
    ]);

    let row_area = Rect {
        x: inner.x + 1,
        y: row_y,
        width: inner.width.saturating_sub(2),
        height: 1,
    };
    f.render_widget(Paragraph::new(line), row_area);
}

// ── helpers ─────────────────────────────────────────────────

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let hints = vec![
        widgets::hint("↑↓", "remote"),
        widgets::hint("T", "trace"),
        widgets::hint("↵", "connections"),
    ];
    widgets::render_footer(f, app, area, hints);
}

fn health_dot(rtt: Option<f64>, loss: f64, t: &Theme) -> (&'static str, Color) {
    match rtt {
        Some(r) if loss == 0.0 && r < 50.0 => ("●", t.status_good),
        Some(r) if loss < 50.0 && r < 200.0 => ("●", t.status_warn),
        Some(_) => ("●", t.status_error),
        None => ("○", t.text_muted),
    }
}

#[cfg(test)]
mod tests {
    use super::{connection_text, ConnState};
    use crate::app::App;
    use crate::config::NetwatchConfig;
    use crate::uptime::{Connection, Hop, LastOutage, Monitor};
    use chrono::TimeZone;
    use ratatui::{backend::TestBackend, Terminal};

    /// 2026-10-24 15:00:00 local, as the reference `now`.
    fn now() -> chrono::DateTime<chrono::Local> {
        chrono::Local
            .with_ymd_and_hms(2026, 10, 24, 15, 0, 0)
            .single()
            .unwrap()
    }

    fn ago(secs: u64) -> u64 {
        now().timestamp() as u64 - secs
    }

    #[test]
    fn up_says_for_how_long_and_since_when() {
        let up = Connection::Up {
            since: ago(3 * 3600 + 12 * 60),
            last_outage: None,
        };
        assert_eq!(
            connection_text(up, now()),
            (
                ConnState::Up,
                "up 3h 12m".into(),
                "since netwatch started".into()
            )
        );
        let after = Connection::Up {
            since: ago(600),
            last_outage: Some(LastOutage {
                start: ago(780),
                end: ago(600),
                hop: Hop::Internet,
            }),
        };
        assert_eq!(
            connection_text(after, now()),
            (
                ConnState::Up,
                "up 10m 00s".into(),
                "since 14:50 (internet, 3m 00s)".into()
            )
        );
        // An outage on an earlier day shows the date; a time beside it
        // would not fit the box.
        let yesterday = Connection::Up {
            since: ago(86_400 + 3_600),
            last_outage: Some(LastOutage {
                start: ago(86_400 + 3_700),
                end: ago(86_400 + 3_600),
                hop: Hop::Gateway,
            }),
        };
        assert_eq!(
            connection_text(yesterday, now()).2,
            "since Oct 23 (gateway, 1m 40s)"
        );
    }

    #[test]
    fn down_says_for_how_long_and_which_hop() {
        let down = Connection::Down {
            since: ago(45),
            hop: Hop::Gateway,
        };
        assert_eq!(
            connection_text(down, now()),
            (
                ConnState::Down,
                "down 45s".into(),
                "gateway not answering".into()
            )
        );
        assert_eq!(
            connection_text(Connection::Unknown, now()).0,
            ConnState::Unknown
        );
    }

    /// The rendered screen. Durations depend on the wall clock and on how
    /// long building the app took (seconds on Windows), so the render tests
    /// check layout and words, and the text tests above check durations.
    fn screen(conn: Connection, w: u16, h: u16) -> String {
        let mut app = App::prepare_with_config(NetwatchConfig::default());
        app.uptime = Monitor::showing(conn);
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| super::render(f, &app, f.area())).unwrap();
        let buf = terminal.backend().buffer();
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn secs_ago(s: u64) -> u64 {
        chrono::Local::now().timestamp() as u64 - s
    }

    #[test]
    fn the_connection_box_sits_under_the_router() {
        let up = Connection::Up {
            since: secs_ago(3 * 3600),
            last_outage: None,
        };
        let s = screen(up, 140, 46);
        let row = |needle: &str| s.lines().position(|l| l.contains(needle));
        let (router, conn) = (row("╭ router"), row("╭ connection"));
        assert!(router.is_some() && conn.is_some(), "{s}");
        assert!(
            conn > router,
            "connection box is not under the router:\n{s}"
        );
        assert!(s.contains("● up 3h"), "{s}");
        assert!(s.contains("since netwatch started"), "{s}");
    }

    #[test]
    fn a_down_gateway_shows_in_the_box_and_on_the_router() {
        let down = Connection::Down {
            since: secs_ago(45),
            hop: Hop::Gateway,
        };
        let s = screen(down, 140, 46);
        assert!(s.contains("● down "), "{s}");
        assert!(s.contains("gateway not answering"), "{s}");
        assert!(s.contains("│ down  —"), "router box: {s}");
    }

    #[test]
    fn a_short_terminal_gets_one_line() {
        let up = Connection::Up {
            since: secs_ago(60),
            last_outage: None,
        };
        // At the graph's minimum height there is no room for the box.
        let s = screen(up, 140, 26);
        assert!(!s.contains("╭ connection"), "{s}");
        assert!(
            s.lines()
                .any(|l| l.contains("● up ") && l.contains("since netwatch started")),
            "{s}"
        );
    }
}
