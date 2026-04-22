use crate::app::App;
use crate::sort::{apply_direction, cmp_case_insensitive, cmp_f64, SortColumn};
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Row, Table},
};

use crate::sort::TabSortState;

pub const COLUMNS: &[SortColumn] = &[
    SortColumn { name: "Process" },
    SortColumn { name: "PID" },
    SortColumn { name: "Conns" },
    SortColumn { name: "Rx Rate" },
    SortColumn { name: "Tx Rate" },
    SortColumn { name: "Total Rate" },
    SortColumn { name: "Rx Total" },
    SortColumn { name: "Tx Total" },
];

// top bandwidth first — matches prior behavior before sort picker
pub const DEFAULT_SORT: TabSortState = TabSortState {
    column: 5, // "Total Rate"
    ascending: false,
};

pub fn sort(
    procs: &mut [crate::collectors::process_bandwidth::ProcessBandwidth],
    column: usize,
    ascending: bool,
) {
    let col_name = COLUMNS.get(column).map(|c| c.name).unwrap_or("");
    procs.sort_by(|a, b| {
        let ord = match col_name {
            "Process" => cmp_case_insensitive(&a.process_name, &b.process_name),
            "PID" => a.pid.cmp(&b.pid),
            "Conns" => a.connection_count.cmp(&b.connection_count),
            "Rx Rate" => cmp_f64(a.rx_rate, b.rx_rate),
            "Tx Rate" => cmp_f64(a.tx_rate, b.tx_rate),
            "Total Rate" => cmp_f64(a.rx_rate + a.tx_rate, b.rx_rate + b.tx_rate),
            "Rx Total" => a.rx_bytes.cmp(&b.rx_bytes),
            "Tx Total" => a.tx_bytes.cmp(&b.tx_bytes),
            _ => std::cmp::Ordering::Equal,
        };
        apply_direction(ord, ascending)
    });
}

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let layout = widgets::frame_layout(area);
    render_header(f, app, layout.header);
    render_process_table(f, app, layout.content);
    render_footer(f, app, layout.footer);
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
    let tab = crate::app::Tab::Processes;

    let header = widgets::sort_header_row(app, tab, COLUMNS);

    let mut ranked = app.process_bandwidth.ranked().to_vec();
    let sort_state = app.sort_states.get(&crate::app::Tab::Processes);
    if let Some(state) = sort_state {
        sort(&mut ranked, state.column, state.ascending);
    }
    let visible_rows = area.height.saturating_sub(3) as usize;
    let scroll = app
        .scroll
        .process_scroll
        .min(ranked.len().saturating_sub(visible_rows));

    let rows: Vec<Row> = ranked
        .iter()
        .skip(scroll)
        .enumerate()
        .map(|(i, proc)| {
            let row_style = if i + scroll == app.scroll.process_scroll {
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
                Cell::from(widgets::format_bytes_rate_padded(proc.rx_rate))
                    .style(Style::default().fg(app.theme.rx_rate)),
                Cell::from(widgets::format_bytes_rate_padded(proc.tx_rate))
                    .style(Style::default().fg(app.theme.tx_rate)),
                Cell::from(widgets::format_bytes_rate_padded(
                    proc.rx_rate + proc.tx_rate,
                )),
                Cell::from(widgets::format_bytes_total_padded(proc.rx_bytes)),
                Cell::from(widgets::format_bytes_total_padded(proc.tx_bytes)),
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
