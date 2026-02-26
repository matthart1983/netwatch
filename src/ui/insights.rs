use crate::app::App;
use crate::collectors::insights::InsightsStatus;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Wrap},
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header
            Constraint::Length(3), // status bar
            Constraint::Min(8),    // insights content
            Constraint::Length(3), // footer
        ])
        .split(area);

    render_header(f, chunks[0]);
    render_status(f, app, chunks[1]);
    render_insights(f, app, chunks[2]);
    render_footer(f, chunks[3]);
}

fn render_header(f: &mut Frame, area: Rect) {
    let now = chrono::Local::now().format("%H:%M:%S").to_string();
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" NetWatch ", Style::default().fg(Color::Cyan).bold()),
        Span::raw("│ "),
        Span::raw("[1] Dashboard  [2] Connections  [3] Interfaces  [4] Packets  [5] Stats  [6] Topology  [7] Timeline  "),
        Span::styled("[8] Insights", Style::default().fg(Color::Yellow).bold()),
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

fn render_status(f: &mut Frame, app: &App, area: Rect) {
    let status = app.insights_collector.get_status();
    let model = &app.insights_collector.model;

    let (status_text, status_style) = match &status {
        InsightsStatus::Idle => (
            "Waiting for packet data...".to_string(),
            Style::default().fg(Color::DarkGray),
        ),
        InsightsStatus::Analyzing => (
            format!("🔄 Analyzing with {}...", model),
            Style::default().fg(Color::Yellow),
        ),
        InsightsStatus::Available => (
            format!("✓ AI analysis via {} (auto-refreshes every 15s)", model),
            Style::default().fg(Color::Green),
        ),
        InsightsStatus::Error(e) => (
            format!("✗ Error: {}", e),
            Style::default().fg(Color::Red),
        ),
        InsightsStatus::OllamaUnavailable => (
            "✗ Ollama not running — start with: ollama serve".to_string(),
            Style::default().fg(Color::Red),
        ),
    };

    let status_bar = Paragraph::new(Line::from(vec![
        Span::styled(format!(" {} ", status_text), status_style),
    ]))
    .block(
        Block::default()
            .title(" AI Analysis ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(status_bar, area);
}

fn render_insights(f: &mut Frame, app: &App, area: Rect) {
    let insights = app.insights_collector.get_insights();

    let block = Block::default()
        .title(format!(" Network Insights ({}) ", insights.len()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if insights.is_empty() {
        let status = app.insights_collector.get_status();
        let msg = match status {
            InsightsStatus::OllamaUnavailable => vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  Ollama is not running. To enable AI insights:",
                    Style::default().fg(Color::Yellow),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "    1. Install Ollama: https://ollama.com",
                    Style::default().fg(Color::White),
                )),
                Line::from(Span::styled(
                    "    2. Pull a model:   ollama pull llama3.2",
                    Style::default().fg(Color::White),
                )),
                Line::from(Span::styled(
                    "    3. Start serving:  ollama serve",
                    Style::default().fg(Color::White),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  NetWatch will auto-detect Ollama and begin analysis.",
                    Style::default().fg(Color::DarkGray),
                )),
            ],
            _ => vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  Start capturing packets on tab [4] to enable AI analysis.",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(Span::styled(
                    "  Insights will appear here automatically every 15 seconds.",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  Press 'a' to trigger analysis immediately.",
                    Style::default().fg(Color::DarkGray),
                )),
            ],
        };
        let content = Paragraph::new(msg);
        f.render_widget(content, inner);
        return;
    }

    // Build display lines from insights (most recent first)
    let mut lines: Vec<Line> = Vec::new();
    let visible_height = inner.height as usize;

    for insight in insights.iter().rev() {
        lines.push(Line::from(vec![
            Span::styled(
                format!("─── {} ", insight.timestamp),
                Style::default().fg(Color::Cyan).bold(),
            ),
            Span::styled(
                "─".repeat(inner.width.saturating_sub(16) as usize),
                Style::default().fg(Color::DarkGray),
            ),
        ]));

        for text_line in insight.text.lines() {
            lines.push(Line::from(Span::raw(format!("  {}", text_line))));
        }

        lines.push(Line::from(""));
    }

    // Apply scroll
    let total_lines = lines.len();
    let scroll = app.insights_scroll.min(total_lines.saturating_sub(visible_height));
    let visible_lines: Vec<Line> = lines.into_iter().skip(scroll).take(visible_height).collect();

    let content = Paragraph::new(visible_lines).wrap(Wrap { trim: false });
    f.render_widget(content, inner);
}

fn render_footer(f: &mut Frame, area: Rect) {
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" q", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Quit  "),
        Span::styled("a", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Analyze  "),
        Span::styled("↑↓", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Scroll  "),
        Span::styled("p", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Pause  "),
        Span::styled("r", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Refresh  "),
        Span::styled("1-8", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Tab  "),
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
