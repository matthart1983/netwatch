use crate::app::{App, Tab};
use crate::collectors::incident::RecorderState;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph},
};

/// Standard 3-chunk vertical layout used by most tabs: header / content / footer.
/// Each panel is 3 rows tall; content takes whatever remains.
pub struct FrameChunks {
    pub header: Rect,
    pub content: Rect,
    pub footer: Rect,
}

pub fn frame_layout(area: Rect) -> FrameChunks {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(area);
    FrameChunks {
        header: chunks[0],
        content: chunks[1],
        footer: chunks[2],
    }
}

/// Fixed column width for rate strings (e.g. "999 MB/s"). Right-aligned.
pub const RATE_WIDTH: usize = 8;

/// Fixed column width for total byte strings (e.g. "999 MB"). Right-aligned.
pub const TOTAL_WIDTH: usize = 6;

/// Unpadded rate for inline use. Zero → "-", integers only.
pub fn format_bytes_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec < 1.0 {
        return "-".to_string();
    }
    let (val, unit) = if bytes_per_sec >= 1_000_000_000.0 {
        (bytes_per_sec / 1_000_000_000.0, "GB/s")
    } else if bytes_per_sec >= 1_000_000.0 {
        (bytes_per_sec / 1_000_000.0, "MB/s")
    } else if bytes_per_sec >= 1_000.0 {
        (bytes_per_sec / 1_000.0, "KB/s")
    } else {
        (bytes_per_sec, "B/s")
    };
    let rounded = val.round().max(1.0) as u64;
    format!("{} {}", rounded, unit)
}

/// Right-aligned rate for table cells. Fixed width [`RATE_WIDTH`].
pub fn format_bytes_rate_padded(bytes_per_sec: f64) -> String {
    format!("{:>width$}", format_bytes_rate(bytes_per_sec), width = RATE_WIDTH)
}

/// Unpadded byte total for inline use. Zero → "-", integers only.
pub fn format_bytes_total(bytes: u64) -> String {
    if bytes == 0 {
        return "-".to_string();
    }
    let (val, unit) = if bytes >= 1_000_000_000 {
        (bytes as f64 / 1_000_000_000.0, "GB")
    } else if bytes >= 1_000_000 {
        (bytes as f64 / 1_000_000.0, "MB")
    } else if bytes >= 1_000 {
        (bytes as f64 / 1_000.0, "KB")
    } else {
        (bytes as f64, "B")
    };
    let rounded = val.round().max(1.0) as u64;
    format!("{} {}", rounded, unit)
}

/// Right-aligned byte total for table cells. Fixed width [`TOTAL_WIDTH`].
pub fn format_bytes_total_padded(bytes: u64) -> String {
    format!("{:>width$}", format_bytes_total(bytes), width = TOTAL_WIDTH)
}

const BASE_TABS: &[Tab] = &[
    Tab::Dashboard,
    Tab::Connections,
    Tab::Interfaces,
    Tab::Packets,
    Tab::Stats,
    Tab::Topology,
    Tab::Timeline,
    Tab::Processes,
];

fn visible_tabs(insights_enabled: bool) -> Vec<Tab> {
    let mut tabs = BASE_TABS.to_vec();
    if insights_enabled {
        tabs.push(Tab::Insights);
    }
    tabs
}

fn tab_label(tab: Tab) -> (&'static str, &'static str) {
    match tab {
        Tab::Dashboard => ("1", "Dashboard"),
        Tab::Connections => ("2", "Connections"),
        Tab::Interfaces => ("3", "Interfaces"),
        Tab::Packets => ("4", "Packets"),
        Tab::Stats => ("5", "Stats"),
        Tab::Topology => ("6", "Topology"),
        Tab::Timeline => ("7", "Timeline"),
        Tab::Processes => ("8", "Processes"),
        Tab::Insights => ("9", "Insights"),
    }
}

pub fn build_header_line(app: &App, extra: Option<Vec<Span<'static>>>) -> Line<'static> {
    let t = &app.theme;
    let now = chrono::Local::now().format("%H:%M:%S").to_string();

    let mut spans: Vec<Span<'static>> = vec![Span::styled(
        "◉ NetWatch ",
        Style::default().fg(t.brand).bold(),
    )];

    let tabs = visible_tabs(app.user_config.insights_enabled);
    for (i, &tab) in tabs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" │ ", Style::default().fg(t.separator)));
        }
        let (num, name) = tab_label(tab);
        let label = format!("[{}] {}", num, name);
        if tab == app.current_tab {
            spans.push(Span::styled(
                label,
                Style::default().fg(t.active_tab).bold(),
            ));
        } else {
            spans.push(Span::styled(label, Style::default().fg(t.inactive_tab)));
        }
    }

    if app.paused {
        spans.push(Span::styled(
            " ⏸ PAUSED ",
            Style::default().fg(t.text_inverse).bg(t.status_warn),
        ));
    }

    let alert_count = app.network_intel.active_alert_count();
    if alert_count > 0 {
        spans.push(Span::styled(
            format!(" ⚠ {} ", alert_count),
            Style::default().fg(t.text_inverse).bg(t.status_error),
        ));
    }

    match app.incident_recorder.state() {
        RecorderState::Armed => {
            spans.push(Span::styled(
                format!(" REC {} ", app.incident_recorder.window_label()),
                Style::default().fg(t.text_inverse).bg(t.brand),
            ));
        }
        RecorderState::Frozen => {
            spans.push(Span::styled(
                " FROZEN ",
                Style::default().fg(t.text_inverse).bg(t.status_warn),
            ));
        }
        RecorderState::Off => {}
    }

    if app.current_tab != Tab::Packets {
        if let Some(status) = &app.export_status {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(
                truncate_inline(status, 56),
                Style::default().fg(t.status_good),
            ));
        }
    }

    if let Some(extra_spans) = extra {
        for s in extra_spans {
            spans.push(s);
        }
    }

    spans.push(Span::raw("  "));
    spans.push(Span::styled(now, Style::default().fg(t.text_muted)));

    Line::from(spans)
}

fn truncate_inline(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }

    let mut truncated: String = text.chars().take(max_chars.saturating_sub(1)).collect();
    truncated.push('…');
    truncated
}

pub fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let line = build_header_line(app, None);
    let header = Paragraph::new(line).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(app.theme.border)),
    );
    f.render_widget(header, area);
}

pub fn render_header_with_extra(f: &mut Frame, app: &App, area: Rect, extra: Vec<Span<'static>>) {
    let line = build_header_line(app, Some(extra));
    let header = Paragraph::new(line).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(app.theme.border)),
    );
    f.render_widget(header, area);
}

/// Given a click column within the header row, return which tab was clicked (if any).
pub fn tab_at_column(col: u16, insights_enabled: bool) -> Option<Tab> {
    // Reconstruct the column offsets matching build_header_spans layout:
    // "◉ NetWatch " = 11 chars
    let mut x = 11u16;
    let tabs = visible_tabs(insights_enabled);
    for (i, &tab) in tabs.iter().enumerate() {
        if i > 0 {
            x += 3; // " │ " separator
        }
        let (num, name) = tab_label(tab);
        let label_len = format!("[{}] {}", num, name).len() as u16;
        if col >= x && col < x + label_len {
            return Some(tab);
        }
        x += label_len;
    }
    None
}

pub fn render_footer(f: &mut Frame, app: &App, area: Rect, context_hints: Vec<Span<'static>>) {
    let t = &app.theme;
    let mut spans: Vec<Span<'static>> = vec![Span::raw(" ")];

    for s in context_hints {
        spans.push(s);
    }

    if spans.len() > 1 {
        spans.push(Span::raw("  "));
    }

    let standard_hints: &[(&str, &str)] = &[
        ("R", "Rec"),
        ("F", "Freeze"),
        ("E", "Export"),
        ("q", "Quit"),
        ("↑↓", "Scroll"),
        ("1-8", "Tab"),
        ("?", "Help"),
    ];
    for (i, (key, desc)) in standard_hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled(
            key.to_string(),
            Style::default().fg(t.key_hint).bold(),
        ));
        spans.push(Span::raw(format!(":{}", desc)));
    }

    let footer = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(t.border)),
    );
    f.render_widget(footer, area);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find_first_col(target: Tab, insights_enabled: bool) -> Option<u16> {
        (0..220).find(|&col| tab_at_column(col, insights_enabled) == Some(target))
    }

    #[test]
    fn tab_at_column_before_tabs_returns_none() {
        assert!(tab_at_column(0, false).is_none());
        assert!(tab_at_column(5, false).is_none());
    }

    #[test]
    fn tab_at_column_hits_dashboard() {
        let col = find_first_col(Tab::Dashboard, false).expect("Dashboard must be reachable");
        assert_eq!(tab_at_column(col, false), Some(Tab::Dashboard));
        if col > 0 {
            assert_ne!(tab_at_column(col - 1, false), Some(Tab::Dashboard));
        }
    }

    #[test]
    fn tab_at_column_hits_each_tab() {
        for &tab in BASE_TABS {
            let col = find_first_col(tab, false);
            assert!(col.is_some(), "{:?} must be reachable by click", tab);
        }
    }

    #[test]
    fn tab_at_column_way_past_end_returns_none() {
        assert!(tab_at_column(220, false).is_none());
    }

    #[test]
    fn all_base_tabs_reachable() {
        let mut found_tabs = std::collections::HashSet::new();
        for col in 0..220 {
            if let Some(tab) = tab_at_column(col, false) {
                found_tabs.insert(format!("{:?}", tab));
            }
        }
        assert_eq!(found_tabs.len(), 8);
    }

    #[test]
    fn insights_tab_reachable_when_enabled() {
        let col = find_first_col(Tab::Insights, true);
        assert!(col.is_some(), "Insights must be reachable when enabled");
        assert!(tab_at_column(col.unwrap(), false).is_none());
    }

    #[test]
    fn tabs_are_in_order() {
        let tabs = visible_tabs(false);
        let positions: Vec<u16> = tabs
            .iter()
            .map(|&t| find_first_col(t, false).unwrap())
            .collect();
        for i in 1..positions.len() {
            assert!(
                positions[i] > positions[i - 1],
                "Tab {:?} should come after {:?}",
                tabs[i],
                tabs[i - 1]
            );
        }
    }
}
