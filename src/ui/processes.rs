use crate::app::App;
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Row, Table},
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(6),   // process table
            Constraint::Length(3), // footer
        ])
        .split(area);

    render_header(f, app, chunks[0]);
    render_process_table(f, app, chunks[1]);
    render_footer(f, app, chunks[2]);
}

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let ranked = app.process_bandwidth.ranked();
    let extra = vec![
        Span::raw("  "),
        Span::styled(
            format!("{} processes", ranked.len()),
            Style::default().fg(app.theme.status_good),
        ),
    ];
    widgets::render_header_with_extra(f, app, area, extra);
}

fn render_process_table(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        Cell::from("Process").style(Style::default().fg(app.theme.brand).bold()),
        Cell::from("PID").style(Style::default().fg(app.theme.brand).bold()),
        Cell::from("Conns").style(Style::default().fg(app.theme.brand).bold()),
        Cell::from("RX Rate").style(Style::default().fg(app.theme.brand).bold()),
        Cell::from("TX Rate").style(Style::default().fg(app.theme.brand).bold()),
        Cell::from("Total Rate").style(Style::default().fg(app.theme.brand).bold()),
        Cell::from("RX Total").style(Style::default().fg(app.theme.brand).bold()),
        Cell::from("TX Total").style(Style::default().fg(app.theme.brand).bold()),
    ])
    .height(1);

    let ranked = app.process_bandwidth.ranked();
    let visible_rows = area.height.saturating_sub(3) as usize;
    let scroll = app.process_scroll.min(ranked.len().saturating_sub(visible_rows));

    let rows: Vec<Row> = ranked
        .iter()
        .skip(scroll)
        .enumerate()
        .map(|(i, proc)| {
            let row_style = if i + scroll == app.process_scroll {
                Style::default().bg(app.theme.selection_bg)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(proc.process_name.clone()),
                Cell::from(
                    proc.pid
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "—".into()),
                ),
                Cell::from(proc.connection_count.to_string()),
                Cell::from(widgets::format_bytes_rate(proc.rx_rate))
                    .style(Style::default().fg(app.theme.rx_rate)),
                Cell::from(widgets::format_bytes_rate(proc.tx_rate))
                    .style(Style::default().fg(app.theme.tx_rate)),
                Cell::from(widgets::format_bytes_rate(proc.rx_rate + proc.tx_rate)),
                Cell::from(widgets::format_bytes_total(proc.rx_bytes)),
                Cell::from(widgets::format_bytes_total(proc.tx_bytes)),
            ])
            .style(row_style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(20),
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Length(14),
            Constraint::Length(14),
            Constraint::Length(14),
            Constraint::Length(12),
            Constraint::Length(12),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(format!(
                " Processes [{}-{}] ",
                scroll + 1,
                (scroll + visible_rows).min(ranked.len())
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border)),
    );

    f.render_widget(table, area);
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let hints = vec![
        Span::styled("s", Style::default().fg(app.theme.key_hint).bold()),
        Span::raw(":Sort  "),
        Span::styled("e", Style::default().fg(app.theme.key_hint).bold()),
        Span::raw(":Export  "),
        Span::styled("Enter", Style::default().fg(app.theme.key_hint).bold()),
        Span::raw(":→Connections"),
    ];
    widgets::render_footer(f, app, area, hints);
}
