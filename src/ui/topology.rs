use std::collections::HashMap;

use crate::app::App;
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph},
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

    render_header(f, chunks[0]);
    render_topology(f, app, chunks[1]);
    render_summary(f, app, chunks[2]);
    render_footer(f, chunks[3]);
}

fn render_header(f: &mut Frame, area: Rect) {
    let now = chrono::Local::now().format("%H:%M:%S").to_string();
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" NetWatch ", Style::default().fg(Color::Cyan).bold()),
        Span::raw("│ "),
        Span::raw("[1] Dashboard  [2] Connections  [3] Interfaces  [4] Packets  [5] Stats  "),
        Span::styled("[6] Topology", Style::default().fg(Color::Yellow).bold()),
        Span::raw("  [7] Timeline  [8] Insights"),
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
        .borders(Borders::ALL)
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
                .border_style(*style),
        );
        let rect = Rect::new(left_x, left_y, left_width, left_node_height);
        f.render_widget(node, rect);

        // Draw edge line from left node to centre
        let edge_y = left_y + left_node_height / 2;
        if edge_y >= inner.y && edge_y < inner.y + inner.height {
            let edge = Paragraph::new(Line::from(
                Span::styled("────", Style::default().fg(Color::DarkGray)),
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

        let mut lines = vec![
            Line::from(Span::raw(format!(" {} ", remote.ip))),
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
                .border_style(border_style),
        );
        let actual_right_width = right_width.min(inner.x + inner.width - right_x);
        let rect = Rect::new(right_x, right_y, actual_right_width, node_h);
        f.render_widget(node, rect);

        // Draw edge line from centre to right node
        let edge_y = right_y + node_h / 2;
        if edge_y >= inner.y && edge_y < inner.y + inner.height {
            let count_label = format!("{:>2}×", remote.conn_count);
            let edge = Paragraph::new(Line::from(
                Span::styled(count_label, Style::default().fg(Color::DarkGray)),
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
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(summary, area);
}

fn render_footer(f: &mut Frame, area: Rect) {
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" q", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Quit  "),
        Span::styled("a", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Analyze  "),
        Span::styled("↑↓", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Scroll  "),
        Span::styled("Enter", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":→Connections  "),
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
    ]))
    .block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(footer, area);
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
