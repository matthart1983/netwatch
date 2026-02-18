use crate::app::App;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
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
    render_footer(f, chunks[2]);
}

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let now = chrono::Local::now().format("%H:%M:%S").to_string();
    let count = app.connection_collector.connections.len();
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" NetWatch ", Style::default().fg(Color::Cyan).bold()),
        Span::raw("│ "),
        Span::raw("[1] Dashboard  "),
        Span::styled("[2] Connections", Style::default().fg(Color::Yellow).bold()),
        Span::raw("  [3] Interfaces  [4] Packets  [5] Stats"),
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

    let mut conns = app.connection_collector.connections.clone();
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

fn render_footer(f: &mut Frame, area: Rect) {
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" q", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Quit  "),
        Span::styled("↑↓", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Scroll  "),
        Span::styled("s", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Sort  "),
        Span::styled("Enter", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":→Packets  "),
        Span::styled("1-5", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Tab  "),
        Span::styled("p", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Pause  "),
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
