use std::collections::HashMap;

use crate::app::App;
use crate::collectors::traceroute::TracerouteStatus;
use crate::theme::Theme;
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, BorderType, Borders, Paragraph},
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
    label: String,
    process: Option<String>,
    conn_count: usize,
    rtt_ms: Option<f64>,
    has_established: bool,
}

fn build_remote_nodes(app: &App) -> Vec<RemoteNode> {
    let mut remotes: HashMap<String, RemoteNode> = HashMap::new();
    let conns = app.connection_collector.connections.lock().unwrap();
    for conn in conns.iter() {
        let ip = extract_ip(&conn.remote_addr);
        if ip.is_empty() || ip == "*" {
            continue;
        }
        let entry = remotes.entry(ip.clone()).or_insert_with(|| RemoteNode {
            label: app
                .packet_collector
                .dns_cache
                .lookup(&ip)
                .unwrap_or(ip.clone()),
            process: None,
            conn_count: 0,
            rtt_ms: None,
            has_established: false,
        });
        entry.conn_count += 1;
        if conn.state == "ESTABLISHED" {
            entry.has_established = true;
        }
        if entry.process.is_none() {
            entry.process = conn.process_name.clone();
        }
        if let Some(rtt_us) = conn.kernel_rtt_us {
            let rtt_ms = rtt_us / 1000.0;
            entry.rtt_ms = Some(match entry.rtt_ms {
                Some(prev) => prev.min(rtt_ms),
                None => rtt_ms,
            });
        }
    }
    let mut nodes: Vec<RemoteNode> = remotes.into_values().collect();
    nodes.sort_by(|a, b| {
        b.has_established
            .cmp(&a.has_established)
            .then_with(|| b.conn_count.cmp(&a.conn_count))
            .then_with(|| a.label.cmp(&b.label))
    });
    nodes
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
    let block = Block::default()
        .title(Line::from(Span::styled(
            " TOPOLOGY ",
            Style::default().fg(t.brand).bold(),
        )))
        .title(legend)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.border));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 8 || inner.width < 80 {
        let msg = Paragraph::new(" Terminal too small for graph view")
            .style(Style::default().fg(t.text_muted));
        f.render_widget(msg, inner);
        return;
    }

    let remotes = build_remote_nodes(app);
    let hs = app.health_prober.status.lock().unwrap();

    // Layout: SELF (left) → ROUTER → ISP → remotes (right)
    let self_x = inner.x;
    let self_w = 22u16;
    let router_x = self_x + self_w + 8; // 8 cells for connector
    let router_w = 18u16;
    let isp_x = router_x + router_w + 8;
    let isp_w = 18u16;
    let remotes_x = isp_x + isp_w + 6;
    let remotes_w = inner.x + inner.width - remotes_x;

    // Center vertical row for the chain
    let mid_y = inner.y + inner.height / 2;

    // SELF box
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
    let self_y = mid_y.saturating_sub(self_h / 2);
    let self_block = Block::default()
        .title(Line::from(Span::styled(
            " SELF ",
            Style::default().fg(t.brand).bold(),
        )))
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(t.brand));
    let self_inner = Rect::new(self_x, self_y, self_w, self_h);
    let self_inner_inner = self_block.inner(self_inner);
    f.render_widget(self_block, self_inner);
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
    let gw_health = health_dot(hs.gateway_rtt_ms, hs.gateway_loss_pct, t);
    let gw_color = gw_health.1;
    let router_h = 4u16;
    let router_y = mid_y.saturating_sub(router_h / 2);
    let router_block = Block::default()
        .title(Line::from(Span::styled(
            " ROUTER ",
            Style::default().fg(t.text_muted),
        )))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(t.border));
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
            Line::from(vec![
                Span::raw(" "),
                Span::styled("● ", Style::default().fg(gw_color)),
                Span::styled(
                    format!("up  {}", rtt_str),
                    Style::default().fg(t.text_muted),
                ),
            ]),
        ]),
        router_inner,
    );

    // ISP box (derive from traceroute hop 2 if available)
    let traceroute = app.traceroute_runner.result.lock().unwrap();
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
    let isp_block = Block::default()
        .title(Line::from(Span::styled(
            " ISP GATEWAY ",
            Style::default().fg(t.text_muted),
        )))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(t.border));
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
            Line::from(vec![
                Span::raw(" "),
                Span::styled("● ", Style::default().fg(isp_dot_color)),
                Span::styled(isp_status, Style::default().fg(t.text_muted)),
            ]),
        ]),
        isp_inner,
    );
    drop(traceroute);

    // Connectors with inline RTT labels
    let self_to_router_y = mid_y;
    if self_to_router_y >= inner.y && self_to_router_y < inner.y + inner.height {
        let connector_x = self_x + self_w;
        let connector_w = router_x - connector_x;
        let conn_text: String = "─".repeat(connector_w as usize);
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                conn_text,
                Style::default().fg(gw_color),
            ))),
            Rect::new(connector_x, self_to_router_y, connector_w, 1),
        );
        // Above the connector: RTT label
        if self_to_router_y > inner.y {
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    format!(" {} {:.0}% ", rtt_str, hs.gateway_loss_pct),
                    Style::default().fg(t.text_muted),
                ))),
                Rect::new(
                    connector_x + 1,
                    self_to_router_y - 1,
                    connector_w.saturating_sub(2),
                    1,
                ),
            );
        }

        let connector2_x = router_x + router_w;
        let connector2_w = isp_x - connector2_x;
        let conn2_text: String = "─".repeat(connector2_w as usize);
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                conn2_text,
                Style::default().fg(isp_dot_color),
            ))),
            Rect::new(connector2_x, self_to_router_y, connector2_w, 1),
        );
        if self_to_router_y > inner.y {
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    format!(" {} ", isp_rtt_str),
                    Style::default().fg(t.text_muted),
                ))),
                Rect::new(
                    connector2_x + 1,
                    self_to_router_y - 1,
                    connector2_w.saturating_sub(2),
                    1,
                ),
            );
        }
    }

    drop(hs);

    // Remote endpoints column
    if remotes_w > 16 {
        render_remote_column(
            f,
            app,
            Rect::new(remotes_x, inner.y, remotes_w, inner.height),
            isp_x + isp_w,
            mid_y,
            &remotes,
            app.scroll.topology_scroll,
        );
    }
}

fn render_remote_column(
    f: &mut Frame,
    app: &App,
    area: Rect,
    isp_right_edge_x: u16,
    isp_mid_y: u16,
    remotes: &[RemoteNode],
    selected_idx: usize,
) {
    let t = &app.theme;
    let max_remotes = (area.height / 2).min(5) as usize;
    let visible: Vec<&RemoteNode> = remotes.iter().take(max_remotes).collect();
    if visible.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                " no remotes",
                Style::default().fg(t.text_muted),
            ))),
            Rect::new(area.x, isp_mid_y, area.width, 1),
        );
        return;
    }

    let n = visible.len() as u16;
    let spacing = (area.height / n).max(2);
    let total = spacing * n;
    let start_y = area.y + area.height.saturating_sub(total) / 2;

    let max_idx = visible.len().saturating_sub(1);
    let selected = selected_idx.min(max_idx);

    for (i, remote) in visible.iter().enumerate() {
        let row_y = start_y + i as u16 * spacing;
        if row_y >= area.y + area.height {
            break;
        }

        let is_selected = i == selected;
        let dot_color = match remote.rtt_ms {
            Some(r) if r < 50.0 => t.status_good,
            Some(r) if r < 200.0 => t.status_warn,
            Some(_) => t.status_error,
            None if remote.has_established => t.status_good,
            None => t.text_muted,
        };

        let connector_w = area.x.saturating_sub(isp_right_edge_x);
        if connector_w > 0 {
            let connector = "─".repeat(connector_w as usize);
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    connector,
                    Style::default().fg(if is_selected { t.brand } else { dot_color }),
                ))),
                Rect::new(isp_right_edge_x, row_y, connector_w, 1),
            );
        }

        let rtt_str = remote
            .rtt_ms
            .map(|r| format!("{:.0}ms", r))
            .unwrap_or_else(|| "—".to_string());
        let proc_str = remote.process.as_deref().unwrap_or("—");
        let label_truncate = (area.width.saturating_sub(4) as usize).saturating_sub(8);
        let cursor = if is_selected {
            Span::styled("▸ ", Style::default().fg(t.brand).bold())
        } else {
            Span::raw("  ")
        };
        let label_color = if is_selected { t.brand } else { t.text_primary };
        let line1 = Line::from(vec![
            cursor,
            Span::styled(
                format!(
                    "{:<width$}",
                    truncate(&remote.label, label_truncate),
                    width = label_truncate
                ),
                Style::default().fg(label_color).bold().to_owned(),
            ),
            Span::styled("● ", Style::default().fg(dot_color)),
            Span::styled(rtt_str, Style::default().fg(t.text_muted)),
        ]);
        let line2 = Line::from(vec![
            Span::raw("  "),
            Span::styled(
                format!("{}× {}", remote.conn_count, proc_str),
                Style::default().fg(t.text_muted),
            ),
        ]);
        f.render_widget(
            Paragraph::new(vec![line1, line2]),
            Rect::new(area.x, row_y, area.width, 2),
        );
    }
}

// ── Hop detail table ────────────────────────────────────────

fn render_hop_detail(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let result = app.traceroute_runner.result.lock().unwrap();

    let title_left = format!(" HOP DETAIL  self → {} ", result.target);
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

    let block = Block::default()
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
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.border));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 2 {
        return;
    }

    let header =
        "  HOP   HOST                              IP                    RTT      LOSS    JITTER";
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
        Some(r) if r < 200.0 => Color::Rgb(255, 165, 0),
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
    let t = &app.theme;
    let hints = vec![
        Span::styled("↑↓", Style::default().fg(t.key_hint).bold()),
        Span::raw(":Select remote  "),
        Span::styled("T", Style::default().fg(t.key_hint).bold()),
        Span::raw(":Traceroute  "),
        Span::styled("Enter", Style::default().fg(t.key_hint).bold()),
        Span::raw(":→Connections"),
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

fn extract_ip(addr: &str) -> String {
    if addr == "*:*" || addr.is_empty() {
        return String::new();
    }
    if let Some(bracket_end) = addr.rfind("]:") {
        addr[1..bracket_end].to_string()
    } else if let Some(colon) = addr.rfind(':') {
        let ip = &addr[..colon];
        if ip == "*" {
            String::new()
        } else {
            ip.to_string()
        }
    } else {
        addr.to_string()
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}
