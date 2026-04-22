use crate::app::App;
use crate::collectors::traceroute::TracerouteStatus;
use crate::sort::{
    apply_direction, cmp_case_insensitive, cmp_f64, cmp_ip_addr, SortColumn, TabSortState,
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table},
};

pub const COLUMNS: &[SortColumn] = &[
    SortColumn { name: "Process" },
    SortColumn { name: "PID" },
    SortColumn { name: "Proto" },
    SortColumn { name: "State" },
    SortColumn {
        name: "Local Address",
    },
    SortColumn {
        name: "Remote Address",
    },
    SortColumn { name: "Down/Up" }, // RATE_COL — conditionally shown, see render
];

pub const DEFAULT_SORT: TabSortState = TabSortState {
    column: 0,
    ascending: true,
};

// index of the Down/Up column in COLUMNS (conditionally visible)
const RATE_COL: usize = 6;

pub fn sort(
    conns: &mut [crate::collectors::connections::Connection],
    column: usize,
    ascending: bool,
) {
    let col_name = COLUMNS.get(column).map(|c| c.name).unwrap_or("");
    conns.sort_by(|a, b| {
        let ord = match col_name {
            "Process" => cmp_case_insensitive(
                a.process_name.as_deref().unwrap_or(""),
                b.process_name.as_deref().unwrap_or(""),
            ),
            "PID" => a.pid.cmp(&b.pid),
            "Proto" => cmp_case_insensitive(&a.protocol, &b.protocol),
            "State" => cmp_case_insensitive(&a.state, &b.state),
            "Local Address" => cmp_ip_addr(&a.local_addr, &b.local_addr),
            "Remote Address" => cmp_ip_addr(&a.remote_addr, &b.remote_addr),
            "Down/Up" => {
                let total = |c: &crate::collectors::connections::Connection| {
                    c.rx_rate.unwrap_or(0.0) + c.tx_rate.unwrap_or(0.0)
                };
                cmp_f64(total(a), total(b))
            }
            _ => std::cmp::Ordering::Equal,
        };
        apply_direction(ord, ascending)
    });
}

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let layout = crate::ui::widgets::frame_layout(area);
    render_header(f, app, layout.header);
    render_connection_table(f, app, layout.content);
    render_footer(f, app, layout.footer);

    if app.traceroute_view_open {
        render_traceroute_overlay(f, app, area);
    }
}

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let conns = app.connection_collector.connections.lock().unwrap();
    let total = conns.len();
    let filter = active_connection_filter(app);
    let shown = if let Some(f) = filter.as_deref() {
        conns.iter().filter(|c| matches_filter(c, f)).count()
    } else {
        total
    };
    drop(conns);

    let mut extra = vec![Span::raw("  ")];
    if filter.is_some() {
        extra.push(Span::styled(
            format!("{shown}/{total} connections"),
            Style::default().fg(app.theme.status_warn),
        ));
        extra.push(Span::raw("  "));
        extra.push(Span::styled(
            format!("filter: {}", filter.as_deref().unwrap_or("")),
            Style::default().fg(app.theme.key_hint),
        ));
    } else {
        extra.push(Span::styled(
            format!("{total} connections"),
            Style::default().fg(app.theme.status_good),
        ));
    }
    crate::ui::widgets::render_header_with_extra(f, app, area, extra);
}

fn active_connection_filter(app: &App) -> Option<String> {
    if let Some(ref f) = app.connection_filter_active {
        return Some(f.clone());
    }
    if app.connection_filter_input && !app.connection_filter_text.is_empty() {
        return Some(app.connection_filter_text.clone());
    }
    None
}

fn matches_filter(conn: &crate::collectors::connections::Connection, filter: &str) -> bool {
    let needle = filter.to_lowercase();
    let process = conn.process_name.as_deref().unwrap_or("").to_lowercase();
    let state = conn.state.to_lowercase();
    let remote = conn.remote_addr.to_lowercase();
    process.contains(&needle) || state.contains(&needle) || remote.contains(&needle)
}

fn render_connection_table(f: &mut Frame, app: &App, area: Rect) {
    let tab = crate::app::Tab::Connections;

    let mut conns = app.connection_collector.connections.lock().unwrap().clone();
    if let Some(ref f) = active_connection_filter(app) {
        conns.retain(|c| matches_filter(c, f));
    }
    let has_rtt_data = conns.iter().any(|c| c.kernel_rtt_us.is_some());
    let has_rate_data = conns
        .iter()
        .any(|c| c.rx_rate.is_some() || c.tx_rate.is_some());
    let has_sparkline_data = !app.rtt_history.is_empty();

    // header cells generated from COLUMNS — adding a name to COLUMNS
    // automatically adds the header with sort indicator (▲/▼)
    let header_style = Style::default().fg(app.theme.brand).bold();
    let mut header_cells: Vec<Cell> = COLUMNS
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != RATE_COL || has_rate_data)
        .map(|(i, col)| {
            Cell::from(format!("{}{}", col.name, app.sort_indicator(tab, i))).style(header_style)
        })
        .collect();
    // non-sortable display-only columns
    if has_rtt_data {
        header_cells.push(Cell::from("RTT").style(header_style));
    }
    if has_sparkline_data {
        header_cells.push(Cell::from("RTT Trend").style(header_style));
    }
    if app.show_geo {
        header_cells.push(Cell::from("Location").style(header_style));
    }
    let header = Row::new(header_cells).height(1);

    let conn_sort = app.sort_states.get(&crate::app::Tab::Connections);
    let sort_col = conn_sort.map(|s| s.column).unwrap_or(0);
    let sort_asc = conn_sort.map(|s| s.ascending).unwrap_or(true);
    sort(&mut conns, sort_col, sort_asc);

    let visible_rows = area.height.saturating_sub(3) as usize; // borders + header
    let scroll = app
        .scroll
        .connection_scroll
        .min(conns.len().saturating_sub(visible_rows));

    let rows: Vec<Row> = conns
        .iter()
        .skip(scroll)
        .enumerate()
        .map(|(i, conn)| {
            let state_style = match conn.state.as_str() {
                "ESTABLISHED" => Style::default().fg(app.theme.status_good),
                "LISTEN" => Style::default().fg(app.theme.status_warn),
                "CLOSE_WAIT" | "TIME_WAIT" => Style::default().fg(app.theme.status_error),
                _ => Style::default().fg(app.theme.text_muted),
            };

            let row_style = if i + scroll == app.scroll.connection_scroll {
                Style::default().bg(app.theme.selection_bg)
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
            if has_rate_data {
                let (text, style) = match (conn.rx_rate, conn.tx_rate) {
                    (Some(rx), Some(tx)) => {
                        let total = rx + tx;
                        let color = if total > 1_000_000.0 {
                            app.theme.status_good
                        } else if total > 10_000.0 {
                            app.theme.status_warn
                        } else {
                            app.theme.text_primary
                        };
                        (
                            format!(
                                "{}↓/{}↑",
                                crate::ui::widgets::format_bytes_rate(rx),
                                crate::ui::widgets::format_bytes_rate(tx),
                            ),
                            Style::default().fg(color),
                        )
                    }
                    _ => ("—".to_string(), Style::default().fg(app.theme.text_muted)),
                };
                cells.push(Cell::from(text).style(style));
            }
            if has_rtt_data {
                let (rtt_text, rtt_style) = match conn.kernel_rtt_us {
                    Some(rtt) if rtt > 100_000.0 => (
                        format!("{:.1}ms", rtt / 1000.0),
                        Style::default().fg(app.theme.status_error),
                    ),
                    Some(rtt) if rtt > 10_000.0 => (
                        format!("{:.1}ms", rtt / 1000.0),
                        Style::default().fg(app.theme.status_warn),
                    ),
                    Some(rtt) => (
                        format!("{:.1}ms", rtt / 1000.0),
                        Style::default().fg(app.theme.status_good),
                    ),
                    None => ("—".to_string(), Style::default().fg(app.theme.text_muted)),
                };
                cells.push(Cell::from(rtt_text).style(rtt_style));
            }
            if has_sparkline_data {
                let remote_ip = extract_ip(&conn.remote_addr);
                let (spark_text, spark_style) = remote_ip
                    .and_then(|ip| app.rtt_history.get(ip))
                    .filter(|h| !h.is_empty())
                    .map(|h| {
                        let latest = h.back().copied().unwrap_or(0.0);
                        let text = format!("{} {:.0}ms", rtt_sparkline(h), latest);
                        let color = rtt_sparkline_color(h, &app.theme);
                        (text, Style::default().fg(color))
                    })
                    .unwrap_or_else(|| {
                        ("—".to_string(), Style::default().fg(app.theme.text_muted))
                    });
                cells.push(Cell::from(spark_text).style(spark_style));
            }
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
                cells.push(Cell::from(geo_label).style(Style::default().fg(app.theme.text_muted)));
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
    if has_rate_data {
        widths.push(Constraint::Length(20));
    }
    if has_rtt_data {
        widths.push(Constraint::Length(10));
    }
    if has_sparkline_data {
        widths.push(Constraint::Length(28));
    }
    if app.show_geo {
        widths.push(Constraint::Min(20));
    }
    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .title(format!(
                " Connections [{}-{}] ",
                scroll + 1,
                (scroll + visible_rows).min(conns.len())
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border)),
    );

    f.render_widget(table, area);
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    if app.connection_filter_input {
        let filter_line = Line::from(vec![
            Span::styled(" / ", Style::default().fg(app.theme.brand).bold()),
            Span::raw(&app.connection_filter_text),
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

    let hints = if app.traceroute_view_open {
        vec![
            Span::styled("Esc", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Close  "),
            Span::styled("q", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Quit"),
        ]
    } else {
        vec![
            Span::styled("s", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Sort  "),
            Span::styled("/", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Filter  "),
            Span::styled("T", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Traceroute  "),
            Span::styled("Enter", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":→Packets"),
        ]
    };
    crate::ui::widgets::render_footer(f, app, area, hints);
}

fn render_traceroute_overlay(f: &mut Frame, app: &App, area: Rect) {
    let result = app.traceroute_runner.result.lock().unwrap();

    let overlay_width = (area.width * 70 / 100)
        .max(50)
        .min(area.width.saturating_sub(4));
    let overlay_height = (area.height * 70 / 100)
        .max(10)
        .min(area.height.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(overlay_width)) / 2;
    let y = area.y + (area.height.saturating_sub(overlay_height)) / 2;
    let overlay = Rect::new(x, y, overlay_width, overlay_height);

    f.render_widget(Clear, overlay);

    let title = format!(" Traceroute → {} ", result.target);
    let border_color = match result.status {
        TracerouteStatus::Running => app.theme.status_warn,
        TracerouteStatus::Done => app.theme.brand,
        TracerouteStatus::Error(_) => app.theme.status_error,
        TracerouteStatus::Idle => app.theme.text_muted,
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
                Style::default().fg(app.theme.status_warn),
            )));
        }
        TracerouteStatus::Error(msg) => {
            lines.push(Line::from(Span::styled(
                format!(" ✗ Error: {}", msg),
                Style::default().fg(app.theme.status_error),
            )));
        }
        TracerouteStatus::Done => {
            lines.push(Line::from(vec![
                Span::styled(" Hop", Style::default().fg(app.theme.brand).bold()),
                Span::raw("  "),
                Span::styled(
                    format!("{:<40}", "Host / IP"),
                    Style::default().fg(app.theme.brand).bold(),
                ),
                Span::styled("RTT 1     ", Style::default().fg(app.theme.brand).bold()),
                Span::styled("RTT 2     ", Style::default().fg(app.theme.brand).bold()),
                Span::styled("RTT 3", Style::default().fg(app.theme.brand).bold()),
            ]));
            lines.push(Line::from(Span::styled(
                " ───────────────────────────────────────────────────────────────────",
                Style::default().fg(app.theme.text_muted),
            )));
            for hop in &result.hops {
                lines.push(format_hop_line(hop, &app.theme));
            }
            if result.hops.is_empty() {
                lines.push(Line::from(Span::styled(
                    " No hops received",
                    Style::default().fg(app.theme.text_muted),
                )));
            }
        }
        TracerouteStatus::Idle => {
            lines.push(Line::from(Span::styled(
                " No traceroute data",
                Style::default().fg(app.theme.text_muted),
            )));
        }
    }

    let visible_height = inner.height as usize;
    let max_scroll = lines.len().saturating_sub(visible_height);
    let scroll = app.scroll.traceroute_scroll.min(max_scroll);
    let visible_lines: Vec<Line> = lines
        .into_iter()
        .skip(scroll)
        .take(visible_height)
        .collect();

    let content = Paragraph::new(visible_lines);
    f.render_widget(content, inner);
}

fn format_hop_line(
    hop: &crate::collectors::traceroute::TracerouteHop,
    theme: &crate::theme::Theme,
) -> Line<'static> {
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

    let rtt_color = hop
        .rtt_ms
        .iter()
        .filter_map(|r| r.as_ref())
        .next()
        .map(|ms| {
            if *ms < 10.0 {
                theme.status_good
            } else if *ms < 50.0 {
                theme.status_warn
            } else if *ms < 100.0 {
                Color::Rgb(255, 165, 0)
            } else {
                theme.status_error
            }
        })
        .unwrap_or(theme.text_muted);

    Line::from(vec![
        Span::styled(hop_num, Style::default().fg(theme.brand)),
        Span::raw("  "),
        Span::styled(
            format!("{:<40}", host_ip),
            Style::default().fg(if hop.ip.is_some() {
                theme.text_primary
            } else {
                theme.text_muted
            }),
        ),
        Span::styled(rtt_spans[0].clone(), Style::default().fg(rtt_color)),
        Span::raw(" "),
        Span::styled(rtt_spans[1].clone(), Style::default().fg(rtt_color)),
        Span::raw(" "),
        Span::styled(rtt_spans[2].clone(), Style::default().fg(rtt_color)),
    ])
}

const SPARKLINE_BLOCKS: &[char] = &['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

fn rtt_sparkline(history: &std::collections::VecDeque<f64>) -> String {
    if history.is_empty() {
        return String::new();
    }
    let min = history.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = history.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let range = max - min;

    history
        .iter()
        .map(|&v| {
            let idx = if range < 0.001 {
                3 // middle block for flat line
            } else {
                let normalized = (v - min) / range;
                (normalized * 7.0).round() as usize
            };
            SPARKLINE_BLOCKS[idx.min(7)]
        })
        .collect()
}

fn rtt_sparkline_color(
    history: &std::collections::VecDeque<f64>,
    theme: &crate::theme::Theme,
) -> Color {
    match history.back() {
        Some(&rtt) if rtt > 100.0 => theme.status_error,
        Some(&rtt) if rtt > 50.0 => theme.status_warn,
        _ => theme.status_good,
    }
}

fn extract_ip(addr: &str) -> Option<&str> {
    if addr == "*:*" || addr.is_empty() {
        return None;
    }
    if let Some(bracket_end) = addr.rfind("]:") {
        Some(&addr[1..bracket_end])
    } else if let Some(colon) = addr.rfind(':') {
        let ip = &addr[..colon];
        if ip == "*" {
            None
        } else {
            Some(ip)
        }
    } else {
        Some(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::connections::Connection;
    use std::collections::VecDeque;

    fn conn(proc: &str, state: &str, remote: &str) -> Connection {
        Connection {
            protocol: "TCP".into(),
            local_addr: "127.0.0.1:1234".into(),
            remote_addr: remote.into(),
            state: state.into(),
            pid: Some(1),
            process_name: Some(proc.into()),
            kernel_rtt_us: None,
            rx_rate: None,
            tx_rate: None,
        }
    }

    #[test]
    fn filter_matches_process_name() {
        let c = conn("apache2", "ESTABLISHED", "1.2.3.4:443");
        assert!(matches_filter(&c, "apache"));
        assert!(matches_filter(&c, "APACHE")); // case insensitive
    }

    #[test]
    fn filter_matches_state() {
        let c = conn("firefox", "CLOSE_WAIT", "1.2.3.4:443");
        assert!(matches_filter(&c, "close_wait"));
        assert!(matches_filter(&c, "CLOSE"));
    }

    #[test]
    fn filter_matches_remote_address() {
        let c = conn("firefox", "ESTABLISHED", "192.168.1.50:443");
        assert!(matches_filter(&c, "192.168"));
        assert!(matches_filter(&c, ":443"));
    }

    #[test]
    fn filter_rejects_non_matching() {
        let c = conn("firefox", "ESTABLISHED", "10.0.0.1:80");
        assert!(!matches_filter(&c, "apache"));
        assert!(!matches_filter(&c, "close_wait"));
        assert!(!matches_filter(&c, "192.168"));
    }

    #[test]
    fn filter_handles_missing_process_name() {
        let mut c = conn("", "LISTEN", "0.0.0.0:22");
        c.process_name = None;
        assert!(!matches_filter(&c, "sshd"));
        assert!(matches_filter(&c, "listen"));
    }

    #[test]
    fn sparkline_empty() {
        let h = VecDeque::new();
        assert_eq!(rtt_sparkline(&h), "");
    }

    #[test]
    fn sparkline_single_sample() {
        let h = VecDeque::from(vec![10.0]);
        let s = rtt_sparkline(&h);
        assert_eq!(s.chars().count(), 1);
        // Single sample → flat line → middle block
        assert_eq!(s, "▄");
    }

    #[test]
    fn sparkline_flat_line() {
        let h = VecDeque::from(vec![5.0, 5.0, 5.0, 5.0]);
        let s = rtt_sparkline(&h);
        assert_eq!(s.chars().count(), 4);
        // All same → all middle blocks
        assert!(s.chars().all(|c| c == '▄'));
    }

    #[test]
    fn sparkline_ascending() {
        let h = VecDeque::from(vec![0.0, 50.0, 100.0]);
        let s = rtt_sparkline(&h);
        let chars: Vec<char> = s.chars().collect();
        assert_eq!(chars.len(), 3);
        assert_eq!(chars[0], '▁'); // min
        assert_eq!(chars[2], '█'); // max
    }

    #[test]
    fn sparkline_descending() {
        let h = VecDeque::from(vec![100.0, 50.0, 0.0]);
        let s = rtt_sparkline(&h);
        let chars: Vec<char> = s.chars().collect();
        assert_eq!(chars[0], '█'); // max
        assert_eq!(chars[2], '▁'); // min
    }

    #[test]
    fn sparkline_color_green_low() {
        let h = VecDeque::from(vec![10.0, 15.0, 12.0]);
        let theme = crate::theme::dark();
        assert_eq!(rtt_sparkline_color(&h, &theme), theme.status_good);
    }

    #[test]
    fn sparkline_color_yellow_medium() {
        let h = VecDeque::from(vec![10.0, 60.0]);
        let theme = crate::theme::dark();
        assert_eq!(rtt_sparkline_color(&h, &theme), theme.status_warn);
    }

    #[test]
    fn sparkline_color_red_high() {
        let h = VecDeque::from(vec![10.0, 150.0]);
        let theme = crate::theme::dark();
        assert_eq!(rtt_sparkline_color(&h, &theme), theme.status_error);
    }

    #[test]
    fn sparkline_twenty_samples() {
        let h: VecDeque<f64> = (0..20).map(|i| i as f64 * 5.0).collect();
        let s = rtt_sparkline(&h);
        assert_eq!(s.chars().count(), 20);
    }
}
