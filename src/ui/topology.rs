use std::collections::HashMap;

use crate::app::App;
use crate::collectors::traceroute::TracerouteStatus;
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, BorderType, Borders, Clear, Paragraph},
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header
            Constraint::Min(10),   // topology map
            Constraint::Length(3), // summary
            Constraint::Length(3), // footer
        ])
        .split(area);

    render_header(f, app, chunks[0]);
    render_topology(f, app, chunks[1]);
    render_summary(f, app, chunks[2]);
    render_footer(f, app, chunks[3]);

    if app.traceroute_view_open {
        render_traceroute_overlay(f, app, area);
    }
}

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    widgets::render_header(f, app, area);
}

struct RemoteNode {
    ip: String,
    conn_count: usize,
    processes: Vec<String>,
    protocols: Vec<String>,
    geo_label: Option<String>,
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
            ip: ip.clone(),
            conn_count: 0,
            processes: Vec::new(),
            protocols: Vec::new(),
            geo_label: None,
            has_established: false,
        });

        entry.conn_count += 1;

        if conn.state == "ESTABLISHED" {
            entry.has_established = true;
        }

        if let Some(ref name) = conn.process_name {
            if !entry.processes.contains(name) {
                entry.processes.push(name.clone());
            }
        }

        let proto = conn.protocol.to_uppercase();
        if !entry.protocols.contains(&proto) {
            entry.protocols.push(proto);
        }
    }

    // Add geo labels if enabled
    if app.show_geo {
        for node in remotes.values_mut() {
            if let Some(geo) = app.geo_cache.lookup(&node.ip) {
                node.geo_label = Some(if geo.city.is_empty() {
                    format!("{} {}", geo.country_code, geo.org)
                } else {
                    format!("{} {}, {}", geo.country_code, geo.city, geo.org)
                });
            }
        }
    }

    let mut nodes: Vec<RemoteNode> = remotes.into_values().collect();
    nodes.sort_by(|a, b| b.conn_count.cmp(&a.conn_count));
    nodes
}

fn render_topology(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" Network Topology ")
        .title_style(Style::default().fg(Color::Cyan))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 5 || inner.width < 40 {
        let msg = Paragraph::new(" Terminal too small for topology view")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(msg, inner);
        return;
    }

    let remotes = build_remote_nodes(app);

    // Column widths
    let left_width = 16u16;
    let center_width = 18u16;
    let right_width = inner.width.saturating_sub(left_width + center_width + 8); // 8 for edge chars
    let edge_left_width = 4u16;
    let edge_right_width = 4u16;

    let left_x = inner.x;
    let edge_left_x = left_x + left_width;
    let center_x = edge_left_x + edge_left_width;
    let edge_right_x = center_x + center_width;
    let right_x = edge_right_x + edge_right_width;

    // Build centre node content
    let hostname = &app.config_collector.config.hostname;
    let primary_ip = app.interface_info.iter()
        .find(|i| i.is_up && i.ipv4.is_some() && i.name != "lo0" && i.name != "lo")
        .and_then(|i| i.ipv4.clone())
        .unwrap_or_else(|| "—".to_string());
    let iface_names: Vec<&str> = app.interface_info.iter()
        .filter(|i| i.is_up && i.name != "lo0" && i.name != "lo")
        .map(|i| i.name.as_str())
        .collect();
    let iface_str = if iface_names.len() <= 2 {
        iface_names.join(" / ")
    } else {
        format!("{} +{}", iface_names[0], iface_names.len() - 1)
    };

    let total_rx: f64 = app.traffic.interfaces.iter()
        .filter(|i| app.interface_info.iter().any(|info| info.name == i.name && info.is_up && info.name != "lo0" && info.name != "lo"))
        .map(|i| i.rx_rate)
        .sum();
    let total_tx: f64 = app.traffic.interfaces.iter()
        .filter(|i| app.interface_info.iter().any(|info| info.name == i.name && info.is_up && info.name != "lo0" && info.name != "lo"))
        .map(|i| i.tx_rate)
        .sum();

    // Centre node position (rendered later after calculating required height)
    let center_height = 7u16;
    let center_y = inner.y + 1;

    // Build left-side nodes (gateway + DNS)
    let mut left_nodes: Vec<(String, String, Style)> = Vec::new();

    let hs = app.health_prober.status.lock().unwrap();

    if let Some(ref gw) = app.config_collector.config.gateway {
        let (dot, style) = health_indicator(hs.gateway_rtt_ms, hs.gateway_loss_pct);
        let rtt_str = hs.gateway_rtt_ms
            .map(|r| format!("{:.1}ms", r))
            .unwrap_or_else(|| "—".to_string());
        left_nodes.push((
            format!("Gateway"),
            format!("{}\n{} {}", gw, dot, rtt_str),
            style,
        ));
    }

    for dns in &app.config_collector.config.dns_servers {
        // Use DNS health for first DNS server, Unknown for others
        let (dot, style) = if Some(dns) == app.config_collector.config.dns_servers.first() {
            health_indicator(hs.dns_rtt_ms, hs.dns_loss_pct)
        } else {
            ("○".to_string(), Style::default().fg(Color::DarkGray))
        };
        let rtt_str = if Some(dns) == app.config_collector.config.dns_servers.first() {
            hs.dns_rtt_ms
                .map(|r| format!("{:.1}ms", r))
                .unwrap_or_else(|| "—".to_string())
        } else {
            "—".to_string()
        };
        left_nodes.push((
            "DNS".to_string(),
            format!("{}\n{} {}", dns, dot, rtt_str),
            style,
        ));
    }

    drop(hs);

    // Calculate how tall the left column needs and stretch center node to match
    let left_node_height = 4u16;
    let left_spacing = 1u16;
    let left_total_height = if left_nodes.is_empty() {
        0
    } else {
        (left_nodes.len() as u16) * left_node_height
            + (left_nodes.len() as u16 - 1) * left_spacing
    };
    let center_height = center_height.max(left_total_height);
    let center_rect = Rect::new(center_x, center_y, center_width, center_height);
    // Re-render center node with adjusted height
    let center_node = Paragraph::new(vec![
        Line::from(Span::styled(format!(" {} ", hostname), Style::default().fg(Color::Cyan).bold())),
        Line::from(Span::raw(format!(" {} ", primary_ip))),
        Line::from(Span::styled(format!(" {} ", iface_str), Style::default().fg(Color::DarkGray))),
        Line::from(Span::styled(format!(" ↓{} ", widgets::format_bytes_rate(total_rx)), Style::default().fg(Color::Green))),
        Line::from(Span::styled(format!(" ↑{} ", widgets::format_bytes_rate(total_tx)), Style::default().fg(Color::Blue))),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    f.render_widget(center_node, center_rect);

    // Render left nodes
    let mut left_y = center_y;

    for (title, content, style) in &left_nodes {
        if left_y + left_node_height > inner.y + inner.height {
            break;
        }

        let lines: Vec<Line> = content.split('\n')
            .map(|s| Line::from(Span::styled(format!(" {} ", s), *style)))
            .collect();

        let node = Paragraph::new(lines).block(
            Block::default()
                .title(format!(" {} ", title))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(*style),
        );
        let rect = Rect::new(left_x, left_y, left_width, left_node_height);
        f.render_widget(node, rect);

        // Draw edge line from left node to centre
        let edge_y = left_y + left_node_height / 2;
        if edge_y >= inner.y && edge_y < inner.y + inner.height {
            let edge = Paragraph::new(Line::from(
                Span::styled("────", *style),
            ));
            let edge_rect = Rect::new(edge_left_x, edge_y, edge_left_width, 1);
            f.render_widget(edge, edge_rect);
        }

        left_y += left_node_height + left_spacing;
    }

    // Render right-side nodes (remote hosts)
    let right_node_height = 4u16;
    let right_spacing = 1u16;
    let max_right_nodes = ((inner.height.saturating_sub(2)) / (right_node_height + right_spacing)).max(1) as usize;

    // Stretch center node further if the right column is taller
    let visible_count = remotes.len().min(max_right_nodes) as u16;
    let right_total_height = if visible_count == 0 {
        0
    } else {
        visible_count * right_node_height + (visible_count - 1) * right_spacing
    };
    if right_total_height > center_height {
        let center_rect = Rect::new(center_x, center_y, center_width, right_total_height);
        let center_node = Paragraph::new(vec![
            Line::from(Span::styled(format!(" {} ", hostname), Style::default().fg(Color::Cyan).bold())),
            Line::from(Span::raw(format!(" {} ", primary_ip))),
            Line::from(Span::styled(format!(" {} ", iface_str), Style::default().fg(Color::DarkGray))),
            Line::from(Span::styled(format!(" ↓{} ", widgets::format_bytes_rate(total_rx)), Style::default().fg(Color::Green))),
            Line::from(Span::styled(format!(" ↑{} ", widgets::format_bytes_rate(total_tx)), Style::default().fg(Color::Blue))),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Cyan)),
        );
        f.render_widget(center_node, center_rect);
    }
    let scroll = app.topology_scroll.min(remotes.len().saturating_sub(max_right_nodes.max(1)));
    let visible_remotes: Vec<&RemoteNode> = remotes.iter().skip(scroll).take(max_right_nodes).collect();
    let mut right_y = center_y;

    for (i, remote) in visible_remotes.iter().enumerate() {
        if right_y + right_node_height > inner.y + inner.height {
            break;
        }

        let is_selected = i + scroll == app.topology_scroll;
        let border_style = if is_selected {
            Style::default().fg(Color::Yellow)
        } else if remote.has_established {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let proc_str = if remote.processes.is_empty() {
            "—".to_string()
        } else {
            let proto = remote.protocols.first().map(|s| s.as_str()).unwrap_or("");
            format!("{} ({})", remote.processes[0], proto)
        };

        let ip_prefix = if is_selected { "▶" } else { " " };
        let mut lines = vec![
            Line::from(Span::styled(
                format!("{} {} ", ip_prefix, remote.ip),
                if is_selected { Style::default().fg(Color::Yellow).bold() } else { Style::default() },
            )),
            Line::from(Span::styled(
                format!(" {}× {} ", remote.conn_count, proc_str),
                Style::default().fg(Color::DarkGray),
            )),
        ];
        if let Some(ref geo) = remote.geo_label {
            let truncated: String = geo.chars().take((right_width.saturating_sub(3)) as usize).collect();
            lines.push(Line::from(Span::styled(
                format!(" {} ", truncated),
                Style::default().fg(Color::DarkGray),
            )));
        }

        let node_h = if remote.geo_label.is_some() { 5u16 } else { right_node_height };
        let node = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(border_style),
        );
        let actual_right_width = right_width.min(inner.x + inner.width - right_x);
        let rect = Rect::new(right_x, right_y, actual_right_width, node_h);
        f.render_widget(node, rect);

        // Draw edge line from centre to right node
        let edge_y = right_y + node_h / 2;
        if edge_y >= inner.y && edge_y < inner.y + inner.height {
            let edge_style = if remote.has_established {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            let edge_label = format!("─▶{}×", remote.conn_count);
            let edge = Paragraph::new(Line::from(
                Span::styled(edge_label, edge_style),
            ));
            let edge_rect = Rect::new(edge_right_x, edge_y, edge_right_width, 1);
            f.render_widget(edge, edge_rect);
        }

        right_y += node_h + right_spacing;
    }
}

fn render_summary(f: &mut Frame, app: &App, area: Rect) {
    let conns = app.connection_collector.connections.lock().unwrap();
    let total_conns = conns.len();
    let mut unique_remotes = std::collections::HashSet::new();
    for conn in conns.iter() {
        let ip = extract_ip(&conn.remote_addr);
        if !ip.is_empty() && ip != "*" {
            unique_remotes.insert(ip);
        }
    }

    let infra_count = app.config_collector.config.gateway.iter().count()
        + app.config_collector.config.dns_servers.len();
    let node_count = 1 + infra_count + unique_remotes.len(); // 1 for local

    let summary = Paragraph::new(Line::from(vec![
        Span::styled(" Nodes: ", Style::default().fg(Color::Cyan).bold()),
        Span::raw(format!("{}", node_count)),
        Span::raw("  │  "),
        Span::styled("Connections: ", Style::default().fg(Color::Cyan).bold()),
        Span::raw(format!("{}", total_conns)),
        Span::raw("  │  "),
        Span::styled("Remotes: ", Style::default().fg(Color::Cyan).bold()),
        Span::raw(format!("{}", unique_remotes.len())),
    ]))
    .block(
        Block::default()
            .borders(Borders::LEFT)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    f.render_widget(summary, area);
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let hints = if app.traceroute_view_open {
        vec![
            Span::styled("Esc", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Close  "),
        ]
    } else {
        vec![
            Span::styled("T", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Traceroute  "),
            Span::styled("Enter", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":→Connections"),
        ]
    };
    widgets::render_footer(f, area, hints);
}

fn health_indicator(rtt: Option<f64>, loss: f64) -> (String, Style) {
    match rtt {
        Some(r) if loss == 0.0 && r < 10.0 => {
            ("●".to_string(), Style::default().fg(Color::Green))
        }
        Some(r) if loss < 50.0 && r < 100.0 => {
            ("●".to_string(), Style::default().fg(Color::Yellow))
        }
        Some(_) => {
            ("●".to_string(), Style::default().fg(Color::Red))
        }
        None => {
            ("○".to_string(), Style::default().fg(Color::DarkGray))
        }
    }
}

fn render_traceroute_overlay(f: &mut Frame, app: &App, area: Rect) {
    let result = app.traceroute_runner.result.lock().unwrap();

    // Centre overlay occupying ~70% of the screen
    let overlay_width = (area.width * 70 / 100).max(50).min(area.width.saturating_sub(4));
    let overlay_height = (area.height * 70 / 100).max(10).min(area.height.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(overlay_width)) / 2;
    let y = area.y + (area.height.saturating_sub(overlay_height)) / 2;
    let overlay = Rect::new(x, y, overlay_width, overlay_height);

    f.render_widget(Clear, overlay);

    let title = format!(" Traceroute → {} ", result.target);
    let border_color = match result.status {
        TracerouteStatus::Running => Color::Yellow,
        TracerouteStatus::Done => Color::Cyan,
        TracerouteStatus::Error(_) => Color::Red,
        TracerouteStatus::Idle => Color::DarkGray,
    };
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));
    let inner = block.inner(overlay);
    f.render_widget(block, overlay);

    let mut lines: Vec<Line> = Vec::new();

    match &result.status {
        TracerouteStatus::Running => {
            lines.push(Line::from(Span::styled(
                " ⏳ Running traceroute...",
                Style::default().fg(Color::Yellow),
            )));
            // Show hops collected so far
            for hop in &result.hops {
                lines.push(format_hop_line(hop));
            }
        }
        TracerouteStatus::Error(msg) => {
            lines.push(Line::from(Span::styled(
                format!(" ✗ Error: {}", msg),
                Style::default().fg(Color::Red),
            )));
        }
        TracerouteStatus::Done => {
            // Header
            lines.push(Line::from(vec![
                Span::styled(" Hop", Style::default().fg(Color::Cyan).bold()),
                Span::raw("  "),
                Span::styled(
                    format!("{:<40}", "Host / IP"),
                    Style::default().fg(Color::Cyan).bold(),
                ),
                Span::styled("RTT 1     ", Style::default().fg(Color::Cyan).bold()),
                Span::styled("RTT 2     ", Style::default().fg(Color::Cyan).bold()),
                Span::styled("RTT 3", Style::default().fg(Color::Cyan).bold()),
            ]));
            lines.push(Line::from(Span::styled(
                " ───────────────────────────────────────────────────────────────────",
                Style::default().fg(Color::DarkGray),
            )));

            for hop in &result.hops {
                lines.push(format_hop_line(hop));
            }

            if result.hops.is_empty() {
                lines.push(Line::from(Span::styled(
                    " No hops received",
                    Style::default().fg(Color::DarkGray),
                )));
            }
        }
        TracerouteStatus::Idle => {
            lines.push(Line::from(Span::styled(
                " No traceroute data",
                Style::default().fg(Color::DarkGray),
            )));
        }
    }

    let visible_height = inner.height as usize;
    let max_scroll = lines.len().saturating_sub(visible_height);
    let scroll = app.traceroute_scroll.min(max_scroll);
    let visible_lines: Vec<Line> = lines.into_iter().skip(scroll).take(visible_height).collect();

    let content = Paragraph::new(visible_lines);
    f.render_widget(content, inner);
}

fn format_hop_line(hop: &crate::collectors::traceroute::TracerouteHop) -> Line<'static> {
    let hop_num = format!(" {:>2} ", hop.hop_number);
    let host_ip = match (&hop.host, &hop.ip) {
        (Some(h), Some(ip)) => format!("{} ({})", h, ip),
        (None, Some(ip)) => ip.clone(),
        (Some(h), None) => h.clone(),
        (None, None) => "*".to_string(),
    };

    let rtt_spans: Vec<String> = if hop.rtt_ms.is_empty() && hop.ip.is_none() {
        vec!["*".to_string(); 3]
    } else {
        (0..3)
            .map(|i| match hop.rtt_ms.get(i) {
                Some(Some(ms)) => format!("{:>7.2}ms", ms),
                _ => "      *  ".to_string(),
            })
            .collect()
    };

    let rtt_color = hop.rtt_ms.iter().filter_map(|r| r.as_ref()).next().map(|ms| {
        if *ms < 10.0 {
            Color::Green
        } else if *ms < 50.0 {
            Color::Yellow
        } else if *ms < 100.0 {
            Color::Rgb(255, 165, 0) // orange
        } else {
            Color::Red
        }
    }).unwrap_or(Color::DarkGray);

    Line::from(vec![
        Span::styled(hop_num, Style::default().fg(Color::Cyan)),
        Span::raw("  "),
        Span::styled(format!("{:<40}", host_ip), Style::default().fg(if hop.ip.is_some() { Color::White } else { Color::DarkGray })),
        Span::styled(rtt_spans[0].clone(), Style::default().fg(rtt_color)),
        Span::raw(" "),
        Span::styled(rtt_spans[1].clone(), Style::default().fg(rtt_color)),
        Span::raw(" "),
        Span::styled(rtt_spans[2].clone(), Style::default().fg(rtt_color)),
    ])
}

fn extract_ip(addr: &str) -> String {
    if addr == "*:*" || addr.is_empty() {
        return String::new();
    }
    if let Some(bracket_end) = addr.rfind("]:") {
        addr[1..bracket_end].to_string()
    } else if let Some(colon) = addr.rfind(':') {
        let ip = &addr[..colon];
        if ip == "*" { String::new() } else { ip.to_string() }
    } else {
        addr.to_string()
    }
}
