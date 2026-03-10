use crate::app::{App, Tab};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph},
};

pub fn format_bytes_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec >= 1_000_000_000.0 {
        format!("{:.1} GB/s", bytes_per_sec / 1_000_000_000.0)
    } else if bytes_per_sec >= 1_000_000.0 {
        format!("{:.1} MB/s", bytes_per_sec / 1_000_000.0)
    } else if bytes_per_sec >= 1_000.0 {
        format!("{:.1} KB/s", bytes_per_sec / 1_000.0)
    } else {
        format!("{:.0}  B/s", bytes_per_sec)
    }
}

pub fn format_bytes_total(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.1} GB", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{} B", bytes)
    }
}

const ALL_TABS: &[Tab] = &[
    Tab::Dashboard, Tab::Connections, Tab::Interfaces, Tab::Packets,
    Tab::Stats, Tab::Topology, Tab::Timeline, Tab::Insights,
];

fn tab_label(tab: Tab) -> (&'static str, &'static str) {
    match tab {
        Tab::Dashboard => ("1", "Dashboard"),
        Tab::Connections => ("2", "Connections"),
        Tab::Interfaces => ("3", "Interfaces"),
        Tab::Packets => ("4", "Packets"),
        Tab::Stats => ("5", "Stats"),
        Tab::Topology => ("6", "Topology"),
        Tab::Timeline => ("7", "Timeline"),
        Tab::Insights => ("8", "Insights"),
    }
}

fn build_header_spans(app: &App, extra: Option<Vec<Span<'static>>>) -> Line<'static> {
    let t = &app.theme;
    let now = chrono::Local::now().format("%H:%M:%S").to_string();

    let mut spans: Vec<Span<'static>> = vec![
        Span::styled("◉ NetWatch ", Style::default().fg(t.brand).bold()),
    ];

    for (i, &tab) in ALL_TABS.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" │ ", Style::default().fg(t.separator)));
        }
        let (num, name) = tab_label(tab);
        let label = format!("[{}] {}", num, name);
        if tab == app.current_tab {
            spans.push(Span::styled(label, Style::default().fg(t.active_tab).bold()));
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

    if let Some(extra_spans) = extra {
        for s in extra_spans {
            spans.push(s);
        }
    }

    spans.push(Span::raw("  "));
    spans.push(Span::styled(now, Style::default().fg(t.text_muted)));

    Line::from(spans)
}

pub fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let line = build_header_spans(app, None);
    let header = Paragraph::new(line)
        .block(Block::default().borders(Borders::BOTTOM).border_style(Style::default().fg(app.theme.border)));
    f.render_widget(header, area);
}

pub fn render_header_with_extra(f: &mut Frame, app: &App, area: Rect, extra: Vec<Span<'static>>) {
    let line = build_header_spans(app, Some(extra));
    let header = Paragraph::new(line)
        .block(Block::default().borders(Borders::BOTTOM).border_style(Style::default().fg(app.theme.border)));
    f.render_widget(header, area);
}

/// Given a click column within the header row, return which tab was clicked (if any).
pub fn tab_at_column(col: u16) -> Option<Tab> {
    // Reconstruct the column offsets matching build_header_spans layout:
    // "◉ NetWatch " = 11 chars
    let mut x = 11u16;
    for (i, &tab) in ALL_TABS.iter().enumerate() {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn find_first_col(target: Tab) -> Option<u16> {
        (0..200).find(|&col| tab_at_column(col) == Some(target))
    }

    #[test]
    fn tab_at_column_before_tabs_returns_none() {
        assert!(tab_at_column(0).is_none());
        assert!(tab_at_column(5).is_none());
    }

    #[test]
    fn tab_at_column_hits_dashboard() {
        let col = find_first_col(Tab::Dashboard).expect("Dashboard must be reachable");
        assert_eq!(tab_at_column(col), Some(Tab::Dashboard));
        // One column before should not be Dashboard
        if col > 0 {
            assert_ne!(tab_at_column(col - 1), Some(Tab::Dashboard));
        }
    }

    #[test]
    fn tab_at_column_hits_each_tab() {
        for &tab in ALL_TABS {
            let col = find_first_col(tab);
            assert!(col.is_some(), "{:?} must be reachable by click", tab);
        }
    }

    #[test]
    fn tab_at_column_way_past_end_returns_none() {
        assert!(tab_at_column(200).is_none());
    }

    #[test]
    fn all_tabs_reachable() {
        let mut found_tabs = std::collections::HashSet::new();
        for col in 0..200 {
            if let Some(tab) = tab_at_column(col) {
                found_tabs.insert(format!("{:?}", tab));
            }
        }
        assert_eq!(found_tabs.len(), 8);
    }

    #[test]
    fn tabs_are_in_order() {
        let positions: Vec<u16> = ALL_TABS
            .iter()
            .map(|&t| find_first_col(t).unwrap())
            .collect();
        for i in 1..positions.len() {
            assert!(
                positions[i] > positions[i - 1],
                "Tab {:?} should come after {:?}",
                ALL_TABS[i],
                ALL_TABS[i - 1]
            );
        }
    }
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
        ("q", "Quit"),
        ("↑↓", "Scroll"),
        ("1-8", "Tab"),
        ("?", "Help"),
    ];
    for (i, (key, desc)) in standard_hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled(format!("{}", key), Style::default().fg(t.key_hint).bold()));
        spans.push(Span::raw(format!(":{}", desc)));
    }

    let footer = Paragraph::new(Line::from(spans))
        .block(Block::default().borders(Borders::TOP).border_style(Style::default().fg(t.border)));
    f.render_widget(footer, area);
}
