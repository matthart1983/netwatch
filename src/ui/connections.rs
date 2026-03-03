use crate::app::App;
use crate::collectors::traceroute::TracerouteStatus;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table},
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(6),   // connection table
            Constraint::Length(3), // footer
        ])
        .split(area);

    render_header(f, app, chunks[0]);
    render_connection_table(f, app, chunks[1]);
    render_footer(f, app, chunks[2]);

    if app.traceroute_view_open {
        render_traceroute_overlay(f, app, area);
    }
}

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let now = chrono::Local::now().format("%H:%M:%S").to_string();
    let count = app.connection_collector.connections.lock().unwrap().len();
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" NetWatch ", Style::default().fg(Color::Cyan).bold()),
        Span::raw("│ "),
        Span::raw("[1] Dashboard  "),
        Span::styled("[2] Connections", Style::default().fg(Color::Yellow).bold()),
        Span::raw("  [3] Interfaces  [4] Packets  [5] Stats  [6] Topology  [7] Timeline  [8] Insights"),
        Span::raw("  │ "),
        Span::styled(format!("{count} connections"), Style::default().fg(Color::Green)),
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

fn render_connection_table(f: &mut Frame, app: &App, area: Rect) {
    let sort_indicator = |col: usize| -> &str {
        if app.sort_column == col { " ▼" } else { "" }
    };

    let mut header_cells = vec![
        Cell::from(format!("Process{}", sort_indicator(0)))
            .style(Style::default().fg(Color::Cyan).bold()),
        Cell::from(format!("PID{}", sort_indicator(1)))
            .style(Style::default().fg(Color::Cyan).bold()),
        Cell::from(format!("Proto{}", sort_indicator(2)))
            .style(Style::default().fg(Color::Cyan).bold()),
        Cell::from(format!("State{}", sort_indicator(3)))
            .style(Style::default().fg(Color::Cyan).bold()),
        Cell::from(format!("Local Address{}", sort_indicator(4)))
            .style(Style::default().fg(Color::Cyan).bold()),
        Cell::from(format!("Remote Address{}", sort_indicator(5)))
            .style(Style::default().fg(Color::Cyan).bold()),
    ];
    if app.show_geo {
        header_cells.push(
            Cell::from("Location")
                .style(Style::default().fg(Color::Cyan).bold()),
        );
    }
    let header = Row::new(header_cells).height(1);

    let mut conns = app.connection_collector.connections.lock().unwrap().clone();
    match app.sort_column {
        0 => conns.sort_by(|a, b| {
            a.process_name
                .as_deref()
                .unwrap_or("")
                .cmp(b.process_name.as_deref().unwrap_or(""))
        }),
        1 => conns.sort_by(|a, b| a.pid.cmp(&b.pid)),
        2 => conns.sort_by(|a, b| a.protocol.cmp(&b.protocol)),
        3 => conns.sort_by(|a, b| a.state.cmp(&b.state)),
        4 => conns.sort_by(|a, b| a.local_addr.cmp(&b.local_addr)),
        5 => conns.sort_by(|a, b| a.remote_addr.cmp(&b.remote_addr)),
        _ => {}
    }

    let visible_rows = area.height.saturating_sub(3) as usize; // borders + header
    let scroll = app.connection_scroll.min(conns.len().saturating_sub(visible_rows));

    let rows: Vec<Row> = conns
        .iter()
        .skip(scroll)
        .enumerate()
        .map(|(i, conn)| {
            let state_style = match conn.state.as_str() {
                "ESTABLISHED" => Style::default().fg(Color::Green),
                "LISTEN" => Style::default().fg(Color::Yellow),
                "CLOSE_WAIT" | "TIME_WAIT" => Style::default().fg(Color::Red),
                _ => Style::default().fg(Color::DarkGray),
            };

            let row_style = if i + scroll == app.connection_scroll {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };

            let mut cells = vec![
                Cell::from(conn.process_name.as_deref().unwrap_or("—").to_string()),
                Cell::from(
                    conn.pid
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "—".to_string()),
                ),
                Cell::from(conn.protocol.clone()),
                Cell::from(conn.state.clone()).style(state_style),
                Cell::from(conn.local_addr.clone()),
                Cell::from(conn.remote_addr.clone()),
            ];
            if app.show_geo {
                let remote_ip = extract_ip(&conn.remote_addr);
                let geo_label = remote_ip
                    .and_then(|ip| app.geo_cache.lookup(ip))
                    .map(|g| {
                        if g.city.is_empty() {
                            format!("{} {}", g.country_code, g.org)
                        } else {
                            format!("{} {}, {}", g.country_code, g.city, g.org)
                        }
                    })
                    .unwrap_or_default();
                cells.push(Cell::from(geo_label).style(Style::default().fg(Color::DarkGray)));
            }
            Row::new(cells).style(row_style)
        })
        .collect();

    let mut widths: Vec<Constraint> = vec![
        Constraint::Length(16),
        Constraint::Length(8),
        Constraint::Length(6),
        Constraint::Length(14),
        Constraint::Length(22),
        Constraint::Length(22),
    ];
    if app.show_geo {
        widths.push(Constraint::Min(20));
    }
    let table = Table::new(rows, widths)
    .header(header)
    .block(
        Block::default()
            .title(format!(
                " Connections [{}-{}] ",
                scroll + 1,
                (scroll + visible_rows).min(conns.len())
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    f.render_widget(table, area);
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let spans = if app.traceroute_view_open {
        vec![
            Span::styled(" Esc", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Close  "),
            Span::styled("↑↓", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Scroll  "),
            Span::styled("q", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Quit"),
        ]
    } else {
        vec![
            Span::styled(" q", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Quit  "),
            Span::styled("a", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Analyze  "),
            Span::styled("↑↓", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Scroll  "),
            Span::styled("s", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Sort  "),
            Span::styled("T", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Traceroute  "),
            Span::styled("Enter", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":→Packets  "),
            Span::styled("p", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Pause  "),
            Span::styled("r", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Refresh  "),
            Span::styled("1-8", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Tab  "),
            Span::styled("g", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Geo  "),
            Span::styled("W", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Whois  "),
            Span::styled("?", Style::default().fg(Color::Yellow).bold()),
            Span::raw(":Help"),
        ]
    };
    let footer = Paragraph::new(Line::from(spans))
    .block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(footer, area);
}

fn render_traceroute_overlay(f: &mut Frame, app: &App, area: Rect) {
    let result = app.traceroute_runner.result.lock().unwrap();

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
        }
        TracerouteStatus::Error(msg) => {
            lines.push(Line::from(Span::styled(
                format!(" ✗ Error: {}", msg),
                Style::default().fg(Color::Red),
            )));
        }
        TracerouteStatus::Done => {
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
            Color::Rgb(255, 165, 0)
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

fn extract_ip(addr: &str) -> Option<&str> {
    if addr == "*:*" || addr.is_empty() {
        return None;
    }
    if let Some(bracket_end) = addr.rfind("]:") {
        Some(&addr[1..bracket_end])
    } else if let Some(colon) = addr.rfind(':') {
        let ip = &addr[..colon];
        if ip == "*" { None } else { Some(ip) }
    } else {
        Some(addr)
    }
}
