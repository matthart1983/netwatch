use std::time::Instant;

use crate::app::App;
use crate::collectors::connections::TrackedConnection;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph},
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header
            Constraint::Min(6),    // timeline chart
            Constraint::Length(3), // legend
            Constraint::Length(3), // summary
            Constraint::Length(3), // footer
        ])
        .split(area);

    render_header(f, app, chunks[0]);
    render_chart(f, app, chunks[1]);
    render_legend(f, chunks[2]);
    render_summary(f, app, chunks[3]);
    render_footer(f, chunks[4]);
}

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let now = chrono::Local::now().format("%H:%M:%S").to_string();
    let window_label = app.timeline_window.label();
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" NetWatch ", Style::default().fg(Color::Cyan).bold()),
        Span::raw("│ "),
        Span::raw("[1] Dashboard  [2] Connections  [3] Interfaces  [4] Packets  [5] Stats  [6] Topology  "),
        Span::styled("[7] Timeline", Style::default().fg(Color::Yellow).bold()),
        Span::raw("  [8] Insights"),
        Span::raw("  │ "),
        Span::styled(format!("last {}", window_label), Style::default().fg(Color::Green)),
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

fn render_chart(f: &mut Frame, app: &App, area: Rect) {
    let window_secs = app.timeline_window.seconds();
    let now = Instant::now();
    let window_start = now - std::time::Duration::from_secs(window_secs);

    // Sort: active first, then by first_seen (oldest at top)
    let mut sorted: Vec<&TrackedConnection> = app.connection_timeline.tracked.iter()
        .filter(|t| t.last_seen >= window_start)
        .collect();
    sorted.sort_by(|a, b| {
        b.is_active.cmp(&a.is_active)
            .then_with(|| a.first_seen.cmp(&b.first_seen))
    });

    let block = Block::default()
        .title(format!(
            " Timeline ({}) — now ← {:>30} → {} ago ",
            sorted.len(),
            "",
            app.timeline_window.label(),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 2 || inner.width < 30 {
        return;
    }

    let label_width = 24u16; // "process    remote_ip   "
    let bar_width = inner.width.saturating_sub(label_width + 1) as usize;

    if bar_width < 5 {
        return;
    }

    let visible_rows = inner.height as usize;
    let scroll = app.timeline_scroll.min(sorted.len().saturating_sub(visible_rows.max(1)));
    let visible: Vec<&TrackedConnection> = sorted.iter().skip(scroll).take(visible_rows).copied().collect();

    let lines: Vec<Line> = visible.iter().enumerate().map(|(i, tracked)| {
        let is_selected = i + scroll == app.timeline_scroll;

        // Build label: "process    remote_ip"
        let proc_name = tracked.process_name.as_deref().unwrap_or("—");
        let remote = extract_ip(&tracked.key.remote_addr);
        let label = format!(" {:<10} {:<12}", truncate(proc_name, 10), truncate(&remote, 12));

        let label_style = if is_selected {
            Style::default().fg(Color::Yellow).bold()
        } else if tracked.is_active {
            Style::default().fg(Color::White)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        // Build the bar
        let bar = render_bar(tracked, now, window_start, bar_width);

        let mut spans = vec![Span::styled(label, label_style), Span::raw(" ")];
        spans.extend(bar);

        Line::from(spans)
    }).collect();

    let content = Paragraph::new(lines);
    f.render_widget(content, inner);
}

fn render_bar(
    tracked: &TrackedConnection,
    now: Instant,
    window_start: Instant,
    width: usize,
) -> Vec<Span<'static>> {
    let window_duration = now.duration_since(window_start).as_secs_f64();
    if window_duration <= 0.0 || width == 0 {
        return vec![Span::raw(" ".repeat(width))];
    }

    let first = tracked.first_seen.max(window_start);
    let last = tracked.last_seen.min(now);

    if first > last {
        return vec![Span::raw(" ".repeat(width))];
    }

    // Flipped axis: left = now (col 0), right = window_start (col width)
    // A point at time T maps to col: (now - T) / window_duration * width
    let start_frac = now.duration_since(last).as_secs_f64() / window_duration;
    let end_frac = now.duration_since(first).as_secs_f64() / window_duration;

    let start_col = (start_frac * width as f64).floor() as usize;
    let end_col = (end_frac * width as f64).ceil() as usize;
    let start_col = start_col.min(width);
    let end_col = end_col.max(start_col + 1).min(width);

    let (bar_char, color) = bar_style(tracked);

    let mut spans = Vec::new();

    // If active, mark the leftmost cell (now edge) with ▓
    if tracked.is_active && start_col == 0 {
        spans.push(Span::styled("▓".to_string(), Style::default().fg(color)));
        let bar_len = (end_col - start_col).saturating_sub(1);
        if bar_len > 0 {
            spans.push(Span::styled(
                bar_char.to_string().repeat(bar_len),
                Style::default().fg(color),
            ));
        }
    } else {
        if start_col > 0 {
            spans.push(Span::raw(" ".repeat(start_col)));
        }
        let bar_len = end_col - start_col;
        spans.push(Span::styled(
            bar_char.to_string().repeat(bar_len),
            Style::default().fg(color),
        ));
    }

    let used = end_col;
    if used < width {
        spans.push(Span::raw(" ".repeat(width - used)));
    }

    spans
}

fn bar_style(tracked: &TrackedConnection) -> (char, Color) {
    if !tracked.is_active {
        return ('░', Color::DarkGray);
    }
    match tracked.state.as_str() {
        "ESTABLISHED" => ('█', Color::Green),
        "LISTEN" => ('█', Color::Yellow),
        "SYN_SENT" | "SYN_RECV" | "SYN_RECEIVED" => ('░', Color::Cyan),
        "CLOSE_WAIT" | "TIME_WAIT" | "FIN_WAIT_1" | "FIN_WAIT_2" | "FIN_WAIT1" | "FIN_WAIT2" => {
            ('░', Color::Red)
        }
        _ => ('█', Color::Green),
    }
}

fn render_legend(f: &mut Frame, area: Rect) {
    let legend = Paragraph::new(Line::from(vec![
        Span::styled(" ██", Style::default().fg(Color::Green)),
        Span::raw(" Established  "),
        Span::styled("██", Style::default().fg(Color::Yellow)),
        Span::raw(" Listen  "),
        Span::styled("░░", Style::default().fg(Color::Cyan)),
        Span::raw(" Connecting  "),
        Span::styled("░░", Style::default().fg(Color::Red)),
        Span::raw(" Closing  "),
        Span::styled("░░", Style::default().fg(Color::DarkGray)),
        Span::raw(" Closed  "),
        Span::styled("▓", Style::default().fg(Color::Green)),
        Span::raw(" Active edge"),
    ]))
    .block(
        Block::default()
            .title(" Legend ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(legend, area);
}

fn render_summary(f: &mut Frame, app: &App, area: Rect) {
    let active = app.connection_timeline.tracked.iter().filter(|t| t.is_active).count();
    let closed = app.connection_timeline.tracked.iter().filter(|t| !t.is_active).count();
    let total = app.connection_timeline.tracked.len();

    let summary = Paragraph::new(Line::from(vec![
        Span::styled(" Active: ", Style::default().fg(Color::Cyan).bold()),
        Span::styled(format!("{}", active), Style::default().fg(Color::Green)),
        Span::raw("  │  "),
        Span::styled("Closed: ", Style::default().fg(Color::Cyan).bold()),
        Span::styled(format!("{}", closed), Style::default().fg(Color::DarkGray)),
        Span::raw("  │  "),
        Span::styled("Total seen: ", Style::default().fg(Color::Cyan).bold()),
        Span::raw(format!("{}", total)),
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
        Span::styled("t", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Timespan  "),
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

fn extract_ip(addr: &str) -> String {
    if addr == "*:*" || addr.is_empty() {
        return "—".to_string();
    }
    if let Some(bracket_end) = addr.rfind("]:") {
        addr[1..bracket_end].to_string()
    } else if let Some(colon) = addr.rfind(':') {
        let ip = &addr[..colon];
        if ip == "*" { "—".to_string() } else { ip.to_string() }
    } else {
        addr.to_string()
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}
