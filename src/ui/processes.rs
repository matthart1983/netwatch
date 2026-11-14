use std::collections::HashMap;

use crate::app::App;
use crate::collectors::process_bandwidth::ProcessBandwidth;
use crate::sort::{apply_direction, cmp_case_insensitive, cmp_f64, SortColumn, TabSortState};
use crate::ui::text::truncate_end as truncate;
use crate::ui::widgets;
use ratatui::{prelude::*, widgets::Paragraph};

pub const COLUMNS: &[SortColumn] = &[
    SortColumn { name: "Process" },
    SortColumn { name: "PID" },
    SortColumn { name: "Conns" },
    SortColumn { name: "Rx Rate" },
    SortColumn { name: "Tx Rate" },
    SortColumn { name: "Total Rate" },
    SortColumn { name: "Rx Total" },
    SortColumn { name: "Tx Total" },
    SortColumn { name: "RTT" },
    SortColumn { name: "CPU%" },
];

pub const DEFAULT_SORT: TabSortState = TabSortState {
    column: 5, // Total Rate desc
    ascending: false,
};

pub fn sort(procs: &mut [ProcessBandwidth], column: usize, ascending: bool) {
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
            "RTT" => cmp_f64(
                a.rtt_ms.unwrap_or(f64::INFINITY),
                b.rtt_ms.unwrap_or(f64::INFINITY),
            ),
            "CPU%" => cmp_f64(a.cpu_percent.unwrap_or(0.0), b.cpu_percent.unwrap_or(0.0)),
            _ => std::cmp::Ordering::Equal,
        };
        // Ties keep one order from tick to tick. An idle machine is all
        // ties — every rate is zero — and the collector's map order under
        // them reshuffled the table once a second with the cursor on a
        // different process each time.
        apply_direction(ord, ascending)
            .then_with(|| cmp_case_insensitive(&a.process_name, &b.process_name))
            .then_with(|| a.pid.cmp(&b.pid))
    });
}

/// Rows the drill-in panel needs: its borders, a header and five remotes.
const DRILL_IN_MIN_ROWS: u16 = 8;

/// The tab's bands for a table of `rows` processes.
///
/// The table is as tall as its contents and no taller: ten processes used to
/// sit in a twenty-row box above an eight-row drill-in whose graph had three
/// rows to draw in. What the list does not need goes to the drill-in.
fn layout_chunks(area: Rect, rows: usize) -> std::rc::Rc<[Rect]> {
    let header = widgets::ATTRIBUTION_HEADER_ROWS;
    let room = area
        .height
        .saturating_sub(header + 1 + DRILL_IN_MIN_ROWS + 3);
    let table = (rows.max(1) as u16).saturating_add(3).min(room).max(4);
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(header),         // header and attribution coverage
            Constraint::Length(1),              // sort chips
            Constraint::Length(table),          // table
            Constraint::Min(DRILL_IN_MIN_ROWS), // drill-in panel, down to the footer
            Constraint::Length(3),              // footer
        ])
        .split(area)
}

pub fn table_inner_area(area: Rect, rows: usize) -> Rect {
    let table = layout_chunks(area, rows)[2];
    Rect::new(
        table.x + 1,
        table.y + 1,
        table.width.saturating_sub(2),
        table.height.saturating_sub(2),
    )
}
pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = layout_chunks(area, app.process_bandwidth.ranked().len());
    widgets::render_attribution_header(f, app, chunks[0], vec![]);
    render_sort_chips(f, app, chunks[1]);

    let mut ranked = app.process_bandwidth.ranked().to_vec();
    if let Some(state) = app.ui.sort_states.get(&crate::app::Tab::Processes) {
        sort(&mut ranked, state.column, state.ascending);
    }

    render_process_table(f, app, &ranked, chunks[2]);
    render_drill_in(f, app, &ranked, chunks[3]);
    render_footer(f, app, chunks[4]);
}

// ── Sort chip row (reflects current sort state) ─────────────

fn render_sort_chips(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let sort_state = app
        .ui
        .sort_states
        .get(&crate::app::Tab::Processes)
        .copied()
        .unwrap_or(DEFAULT_SORT);

    let chips: [(&str, &str, bool); 6] = [
        ("rx/s", "Rx Rate", false),
        ("tx/s", "Tx Rate", false),
        ("conns", "Conns", false),
        ("rtt", "RTT", false),
        ("cpu", "CPU%", false),
        ("name", "Process", false),
    ];
    let active_col_name = COLUMNS.get(sort_state.column).map(|c| c.name).unwrap_or("");

    let mut spans: Vec<Span> = vec![Span::styled(" sort  ", Style::default().fg(t.text_muted))];
    for (label, col, disabled) in chips.iter() {
        let active = active_col_name == *col;
        let suffix = if active {
            if sort_state.ascending {
                " ▲"
            } else {
                " ▼"
            }
        } else {
            ""
        };
        let chip_label = format!("{}{}", label, suffix);
        if active {
            spans.push(Span::styled(
                format!(" {} ", chip_label),
                Style::default()
                    .fg(t.text_primary)
                    .bg(t.selection_bg)
                    .bold(),
            ));
        } else if *disabled {
            spans.push(Span::styled(
                format!(" {} ", chip_label),
                Style::default().fg(t.text_muted),
            ));
        } else {
            spans.push(Span::styled(
                format!(" {} ", chip_label),
                Style::default().fg(t.text_secondary),
            ));
        }
        spans.push(Span::raw(" "));
    }

    // Right-aligned summary
    let ranked = app.process_bandwidth.ranked();
    let total_socks: u32 = ranked.iter().map(|p| p.connection_count).sum();
    let summary = format!(
        "{} procs  {} sockets   s opens picker",
        ranked.len(),
        total_socks
    );
    let used: usize = spans.iter().map(|s| s.content.chars().count()).sum();
    let total = area.width as usize;
    let summary_w = summary.chars().count();
    if total > used + summary_w + 2 {
        spans.push(Span::raw(" ".repeat(total - used - summary_w - 1)));
        spans.push(Span::styled(summary, Style::default().fg(t.text_muted)));
    }

    f.render_widget(
        Paragraph::new(vec![Line::from(spans), Line::from("")]),
        area,
    );
}

// ── Table ───────────────────────────────────────────────────

/// One column of the process table: the header and every row are cut from
/// this, so they cannot disagree about where a column starts.
///
/// They used to be a literal header string and a row of hand-counted
/// `format!` widths. The pid was `{:>5}`, Linux pids run to seven digits, and
/// each long one pushed the rest of its row two columns right of its header.
struct Col {
    header: &'static str,
    width: usize,
    right: bool,
    /// Per-process rates, totals and round trips come from captured packets.
    needs_capture: bool,
}

impl Col {
    /// `text` in this column, with the column's one-space gutter.
    fn cell(&self, text: &str) -> String {
        let text = truncate(text, self.width);
        let pad = self.width.saturating_sub(crate::ui::text::width(&text));
        if self.right {
            format!("{}{text} ", " ".repeat(pad))
        } else {
            format!("{text}{} ", " ".repeat(pad))
        }
    }
}

const fn col(header: &'static str, width: usize, right: bool, needs_capture: bool) -> Col {
    Col {
        header,
        width,
        right,
        needs_capture,
    }
}

const COLS: [Col; 9] = [
    col("process", 18, false, false),
    // `pid_max` on a 64-bit kernel is 4194304: seven digits.
    col("pid", 8, true, false),
    col("conns", 6, true, false),
    col("rx/s", 10, true, true),
    col("tx/s", 10, true, true),
    col("rx total", 9, true, true),
    col("tx total", 9, true, true),
    col("rtt", 7, true, true),
    col("cpu", 7, true, false),
];

/// True when capture is off and no process has a rate, a total or a round
/// trip to show: the five columns that need packets would be `–` on every
/// row, so the table leaves them out and its title says why.
fn rates_unavailable(app: &App, ranked: &[ProcessBandwidth]) -> bool {
    widgets::capture_failure(app).is_some()
        && ranked.iter().all(|p| {
            p.rx_rate < 1.0
                && p.tx_rate < 1.0
                && p.rx_bytes == 0
                && p.tx_bytes == 0
                && p.rtt_ms.is_none()
        })
}

/// Which of [`COLS`] a table `width` columns wide draws.
///
/// The capture columns go when nothing can fill them. Then, while the row is
/// wider than the table, the session totals and the round trip go — in that
/// order, the least-read first — so `cpu` at the right-hand end is never the
/// column that falls off, as it was at 80 columns.
fn visible_cols(no_rates: bool, width: usize) -> [bool; COLS.len()] {
    let mut keep = [true; COLS.len()];
    for (k, c) in keep.iter_mut().zip(&COLS) {
        *k = !no_rates || !c.needs_capture;
    }
    let total = |keep: &[bool; COLS.len()]| -> usize {
        2 + COLS
            .iter()
            .zip(keep)
            .filter(|(_, k)| **k)
            .map(|(c, _)| c.width + 1)
            .sum::<usize>()
    };
    // rx total, tx total, rtt.
    for drop in [5usize, 6, 7] {
        if total(&keep) <= width {
            break;
        }
        keep[drop] = false;
    }
    keep
}

fn render_process_table(f: &mut Frame, app: &App, ranked: &[ProcessBandwidth], area: Rect) {
    let t = &app.theme;
    let no_rates = rates_unavailable(app, ranked);
    let keep = visible_cols(no_rates, usize::from(area.width.saturating_sub(4)));

    let block = widgets::panel_block(t)
        .title(Line::from(Span::styled(
            " processes ",
            Style::default().fg(t.brand).bold(),
        )))
        .title(
            Line::from(Span::styled(
                if no_rates {
                    format!(" {} · rates and rtt need capture ", ranked.len())
                } else {
                    format!(" {} ", ranked.len())
                },
                Style::default().fg(t.text_muted),
            ))
            .alignment(Alignment::Right),
        );
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 2 {
        return;
    }

    let header: String = std::iter::once("  ".to_string())
        .chain(
            COLS.iter()
                .zip(keep)
                .filter(|&(_, k)| k)
                .map(|(c, _)| c.cell(c.header)),
        )
        .collect();
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            header,
            Style::default().fg(t.text_muted),
        ))),
        Rect::new(inner.x + 1, inner.y, inner.width.saturating_sub(2), 1),
    );

    let visible = inner.height.saturating_sub(1) as usize;
    let max_idx = ranked.len().saturating_sub(1);
    let selected = app.ui.scroll.process_scroll.min(max_idx);
    let window_top = if selected < visible {
        0
    } else {
        selected
            .saturating_sub(visible / 2)
            .min(ranked.len().saturating_sub(visible))
    };

    let rendered = ranked.iter().skip(window_top).take(visible).count();
    for (i, proc) in ranked.iter().skip(window_top).take(visible).enumerate() {
        let row_y = inner.y + 1 + i as u16;
        let abs_idx = window_top + i;
        let is_selected = abs_idx == selected;
        let row_alpha = if app.user_config.graph_fade && !is_selected {
            crate::graph::row_fade_alpha(i, rendered)
        } else {
            1.0
        };
        render_process_row(f, app, inner, row_y, proc, is_selected, row_alpha, keep);
    }

    if ranked.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  No process traffic — waiting for data",
                Style::default().fg(t.text_muted),
            ))),
            Rect::new(inner.x + 1, inner.y + 1, inner.width.saturating_sub(2), 1),
        );
    }
}

fn render_process_row(
    f: &mut Frame,
    app: &App,
    inner: Rect,
    row_y: u16,
    proc: &ProcessBandwidth,
    is_selected: bool,
    row_alpha: f32,
    keep: [bool; COLS.len()],
) {
    let t = &app.theme;
    let active = proc.rx_rate > 0.0 || proc.tx_rate > 0.0;
    // Muted text on the selected row would be invisible in the `terminal`
    // theme, where muted text and the selection ground are both ANSI 8: the
    // cursor on an idle process was a blank grey band. The selected row is
    // the one being read, so it is never dimmed.
    let muted = if is_selected {
        t.text_primary
    } else {
        t.text_muted
    };
    let dot_color = if active { t.status_good } else { muted };
    // A process with no traffic this second is still a row to read, as a
    // connection is in the Connections table: its name is primary text and
    // its counts secondary. Only a value that is zero or unmeasured is muted.
    // The whole row used to be, so with capture off the table was a block of
    // grey under the one selected line.
    let secondary = if is_selected {
        t.text_primary
    } else {
        t.text_secondary
    };
    let total_color = |bytes: u64| if bytes > 0 { t.text_primary } else { muted };

    let (rtt_str, rtt_color) = match proc.rtt_ms {
        Some(rtt) if rtt < 1.0 => (format!("{:.1}ms", rtt), t.status_good),
        Some(rtt) if rtt < 50.0 => (format!("{:.0}ms", rtt), t.status_good),
        Some(rtt) if rtt < 200.0 => (format!("{:.0}ms", rtt), t.status_warn),
        Some(rtt) => (format!("{:.0}ms", rtt), t.status_error),
        None => (widgets::NO_VALUE.to_string(), muted),
    };
    let (cpu_str, cpu_color) = match proc.cpu_percent {
        Some(cpu) if cpu >= 10.0 => (format!("{:.1}%", cpu), t.status_warn),
        Some(cpu) => (format!("{:.1}%", cpu), t.text_primary),
        None => (widgets::NO_VALUE.to_string(), muted),
    };
    // In `COLS` order.
    let cells: [(String, Color); 9] = [
        (proc.process_name.clone(), t.text_primary),
        (
            proc.pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| widgets::NO_VALUE.into()),
            secondary,
        ),
        (proc.connection_count.to_string(), secondary),
        (
            widgets::format_bytes_rate(proc.rx_rate),
            if active { t.rx_rate } else { muted },
        ),
        (
            widgets::format_bytes_rate(proc.tx_rate),
            if active { t.tx_rate } else { muted },
        ),
        (
            widgets::format_bytes_total(proc.rx_bytes),
            total_color(proc.rx_bytes),
        ),
        (
            widgets::format_bytes_total(proc.tx_bytes),
            total_color(proc.tx_bytes),
        ),
        (rtt_str, rtt_color),
        (cpu_str, cpu_color),
    ];
    let mut spans = vec![Span::styled(
        if is_selected { "▸ " } else { "● " },
        Style::default().fg(if is_selected { t.brand } else { dot_color }),
    )];
    spans.extend(
        COLS.iter()
            .zip(cells)
            .zip(keep)
            .enumerate()
            .filter(|&(_, (_, k))| k)
            .map(|(i, ((c, (text, color)), _))| {
                let style = Style::default().fg(color);
                // The name is the row's handle, bold as a group's is in
                // Connections.
                Span::styled(c.cell(&text), if i == 0 { style.bold() } else { style })
            }),
    );
    let line = Line::from(spans);

    let row_area = Rect {
        x: inner.x + 1,
        y: row_y,
        width: inner.width.saturating_sub(2),
        height: 1,
    };
    let bg = if is_selected {
        Style::default().bg(t.selection_bg)
    } else {
        Style::default()
    };
    let line = if (row_alpha - 1.0).abs() < f32::EPSILON {
        line
    } else {
        Line::from(crate::graph::fade_spans_fg(
            line.spans,
            t.bg,
            row_alpha,
            t.defers_to_terminal(),
        ))
    };
    f.render_widget(Paragraph::new(line).style(bg), row_area);
}

// ── Drill-in panel ──────────────────────────────────────────

fn render_drill_in(f: &mut Frame, app: &App, ranked: &[ProcessBandwidth], area: Rect) {
    let t = &app.theme;
    let max_idx = ranked.len().saturating_sub(1);
    let selected_idx = app.ui.scroll.process_scroll.min(max_idx);
    let selected = ranked.get(selected_idx);

    let title_left = match selected {
        Some(p) => format!(
            " {}  pid {} ",
            p.process_name,
            p.pid
                .map(|x| x.to_string())
                .unwrap_or_else(|| widgets::NO_VALUE.into())
        ),
        None => " detail ".to_string(),
    };
    let no_rates = rates_unavailable(app, ranked);
    let title_right = match selected {
        Some(p) if no_rates => format!(" {} sockets  ↑↓ to switch ", p.connection_count),
        Some(p) => format!(
            " {} sockets  {} rx  ↑↓ to switch ",
            p.connection_count,
            widgets::format_bytes_total(p.rx_bytes)
        ),
        None => " ↑↓ to switch ".to_string(),
    };

    let block = widgets::panel_block(t)
        .title(Line::from(Span::styled(
            title_left,
            Style::default().fg(t.status_warn).bold(),
        )))
        .title(
            Line::from(Span::styled(
                title_right,
                Style::default().fg(t.brand).bold(),
            ))
            .alignment(Alignment::Right),
        );
    let inner = block.inner(area);
    f.render_widget(block, area);
    // Two columns in from the border, where the Connections detail starts.
    let inner = Rect {
        x: inner.x + 2.min(inner.width),
        width: inner.width.saturating_sub(4),
        ..inner
    };

    if inner.height < 4 {
        return;
    }

    let Some(proc) = selected else {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "no process selected",
                Style::default().fg(t.text_muted),
            ))),
            Rect::new(inner.x, inner.y, inner.width, 1),
        );
        return;
    };

    // 3 columns: TOP REMOTES (left) | SOCKET STATES (middle) | RX 60s (right)
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(34),
            Constraint::Length(24),
            Constraint::Min(0),
        ])
        .split(inner);

    render_top_remotes(f, app, cols[0], proc, no_rates);
    render_socket_states(f, app, cols[1], proc);
    // Without capture there is no per-process rate to plot: an empty chart
    // over `peak 0  avg 0  p99 0` claimed a measurement that was never made.
    if !no_rates {
        render_chart(f, app, cols[2], proc);
    }
}

fn render_top_remotes(
    f: &mut Frame,
    app: &App,
    area: Rect,
    proc: &ProcessBandwidth,
    no_rates: bool,
) {
    let t = &app.theme;
    // Label, a nine-column figure, and a gap before the socket states.
    let label_w = (area.width as usize).saturating_sub(13).max(8);
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!(
                "{:<label_w$} {:>9}",
                "top remotes",
                if no_rates { "conns" } else { "rate" }
            ),
            Style::default().fg(t.text_muted),
        ))),
        Rect::new(area.x, area.y, area.width, 1),
    );

    let conns = app.connection_collector.connections();
    // Aggregate REAL per-host traffic from per-connection rates (the packet
    // capture path), not a proportional split of the process byte total by
    // connection count — two remotes with equal connection counts must not
    // report identical traffic. host -> (rate B/s, connection count).
    let mut per_host: HashMap<String, (f64, u32)> = HashMap::new();
    for c in conns.iter() {
        let conn_name =
            crate::collectors::connections::process_label(c.process_name.as_deref(), c.pid);
        if conn_name != proc.process_name {
            continue;
        }
        if c.pid != proc.pid {
            continue;
        }
        let host = host_only(&c.remote_addr);
        // A wildcard is where a listener waits, not a remote it talks to.
        if host.is_empty()
            || host == "*"
            || host
                .trim_matches(|c| c == '[' || c == ']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_unspecified())
        {
            continue;
        }
        let entry = per_host.entry(host).or_insert((0.0, 0));
        entry.0 += c.rx_rate.unwrap_or(0.0) + c.tx_rate.unwrap_or(0.0);
        entry.1 += 1;
    }
    drop(conns);

    // Sort by measured rate; fall back to connection count when no capture
    // data is available so the list is still ordered sensibly.
    let mut sorted: Vec<(String, f64, u32)> =
        per_host.into_iter().map(|(h, (r, n))| (h, r, n)).collect();
    sorted.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.2.cmp(&a.2))
            .then_with(|| a.0.cmp(&b.0))
    });

    if sorted.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "no remotes for this process",
                Style::default().fg(t.text_muted),
            ))),
            Rect::new(area.x, area.y + 1, area.width, 1),
        );
        return;
    }

    let max_rows = area.height.saturating_sub(1) as usize;

    // Every remote when they fit; otherwise all but the last row, which
    // counts the rest. It stopped at five whatever the panel's height.
    let shown = if sorted.len() <= max_rows {
        sorted.len()
    } else {
        max_rows.saturating_sub(1)
    };
    for (i, (host, rate, n)) in sorted.iter().take(shown).enumerate() {
        let row_y = area.y + 1 + i as u16;
        // With no capture the figure is how many connections go there, which
        // is measured, not a rate of `0`, which is not.
        let figure = if no_rates {
            Span::styled(format!(" {n:>9}"), Style::default().fg(t.text_secondary))
        } else {
            Span::styled(
                format!(" {:>9}", widgets::format_bytes_rate(*rate)),
                Style::default().fg(if *rate > 0.0 { t.rx_rate } else { t.text_muted }),
            )
        };
        let line = Line::from(vec![
            Span::styled(
                format!("{:<width$}", truncate(host, label_w), width = label_w),
                Style::default().fg(t.text_primary),
            ),
            figure,
        ]);
        f.render_widget(
            Paragraph::new(line),
            Rect::new(area.x, row_y, area.width, 1),
        );
    }

    let remaining = sorted.len().saturating_sub(shown);
    if remaining > 0 && max_rows >= 2 {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!("+ {remaining} more"),
                Style::default().fg(t.text_muted),
            ))),
            Rect::new(area.x, area.y + 1 + shown as u16, area.width, 1),
        );
    }
}

/// The SOCKET STATES row a connection counts towards. Linux and Windows
/// spell states as `ss` does (`CLOSE-WAIT`), macOS as lsof does
/// (`CLOSE_WAIT`), so each row takes both spellings.
fn socket_state_row(state: &str) -> &'static str {
    match state {
        "ESTABLISHED" => "ESTABLISHED",
        "LISTEN" => "LISTEN",
        "TIME_WAIT" | "TIME-WAIT" => "TIME_WAIT",
        "CLOSE_WAIT" | "CLOSE-WAIT" => "CLOSE_WAIT",
        "FIN_WAIT_1" | "FIN_WAIT_2" | "FIN_WAIT1" | "FIN_WAIT2" | "FIN-WAIT-1" | "FIN-WAIT-2" => {
            "FIN_WAIT"
        }
        "SYN_SENT" | "SYN_RECV" | "SYN_RECEIVED" | "SYN_RCVD" | "SYN-SENT" | "SYN-RECV" => "SYN",
        _ => "OTHER",
    }
}

fn render_socket_states(f: &mut Frame, app: &App, area: Rect, proc: &ProcessBandwidth) {
    let t = &app.theme;
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "socket states",
            Style::default().fg(t.text_muted),
        ))),
        Rect::new(area.x, area.y, area.width, 1),
    );

    let conns = app.connection_collector.connections();
    let mut counts: HashMap<&'static str, u32> = HashMap::new();
    for c in conns.iter() {
        let conn_name =
            crate::collectors::connections::process_label(c.process_name.as_deref(), c.pid);
        if conn_name != proc.process_name {
            continue;
        }
        if c.pid != proc.pid {
            continue;
        }
        *counts.entry(socket_state_row(&c.state)).or_insert(0) += 1;
    }
    drop(conns);

    let order: &[(&str, Color)] = &[
        // The Connections table's rule: ordinary states are text, and the
        // half-closed ones an application has left open take the warning.
        ("ESTABLISHED", t.text_secondary),
        ("LISTEN", t.text_muted),
        ("TIME_WAIT", t.text_muted),
        ("CLOSE_WAIT", t.status_warn),
        ("FIN_WAIT", t.status_warn),
        ("SYN", t.text_muted),
    ];

    for (i, (label, color)) in order.iter().enumerate() {
        let count = counts.get(label).copied().unwrap_or(0);
        let row_y = area.y + 1 + i as u16;
        if row_y >= area.y + area.height {
            break;
        }
        let line = Line::from(vec![
            Span::styled(
                // The counting keys stay the kernel's; the reader gets the
                // tool's lowercase words, as in the Connections table.
                format!(
                    "{:<14}",
                    match *label {
                        "FIN_WAIT" => "fin-wait".to_string(),
                        "SYN" => "syn".to_string(),
                        other => widgets::state_label(other),
                    }
                ),
                Style::default().fg(if count > 0 { *color } else { t.text_muted }),
            ),
            // A state with no sockets keeps its row, so the list does not
            // jump, but it is not a number to read.
            Span::styled(
                format!(" {:>4}", count),
                Style::default().fg(if count > 0 {
                    t.text_primary
                } else {
                    t.text_muted
                }),
            ),
        ]);
        f.render_widget(
            Paragraph::new(line),
            Rect::new(area.x, row_y, area.width, 1),
        );
    }
}

/// The process's throughput, drawn as the Interfaces and Stats charts are: a
/// header with both rates and the peak, rx over tx, and a time axis.
///
/// It was one rx plot under a bare `rx 60s` with `peak avg p99` on the last
/// row — a different chart from every other one in the app.
fn render_chart(f: &mut Frame, app: &App, area: Rect, proc: &ProcessBandwidth) {
    let t = &app.theme;
    if area.width < 8 || area.height < 3 {
        return;
    }

    let key = (proc.process_name.clone(), proc.pid);
    let series = |map: &HashMap<(String, Option<u32>), std::collections::VecDeque<u64>>| {
        map.get(&key)
            .map(|b| b.iter().copied().collect::<Vec<u64>>())
            .unwrap_or_default()
    };
    let rx = series(&app.caches.top_proc_rx_history);
    let tx = series(&app.caches.top_proc_tx_history);
    let peak = rx.iter().chain(&tx).copied().max().unwrap_or(0);
    let avg = if rx.is_empty() {
        0
    } else {
        rx.iter().sum::<u64>() / rx.len() as u64
    };
    // The header reports the true peak; only the plot's ceiling moves.
    let (rx_max, rx_clipped) = crate::graph::spike_capped_max(&rx);
    let (tx_max, tx_clipped) = crate::graph::spike_capped_max(&tx);

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("● rx ", Style::default().fg(t.rx_rate)),
            Span::styled(
                widgets::format_bytes_rate(proc.rx_rate),
                Style::default().fg(t.rx_rate).bold(),
            ),
            Span::raw("    "),
            Span::styled("● tx ", Style::default().fg(t.tx_rate)),
            Span::styled(
                widgets::format_bytes_rate(proc.tx_rate),
                Style::default().fg(t.tx_rate).bold(),
            ),
            Span::raw("    "),
            Span::styled(
                format!(
                    "peak {}  avg {}{}",
                    widgets::format_bytes_rate(peak as f64),
                    widgets::format_bytes_rate(avg as f64),
                    if rx_clipped || tx_clipped {
                        "    spike clipped"
                    } else {
                        ""
                    }
                ),
                Style::default().fg(t.text_muted),
            ),
        ])),
        Rect::new(area.x, area.y, area.width, 1),
    );

    let chart_h = area.height.saturating_sub(2);
    if chart_h < 1 {
        return;
    }
    if rx.is_empty() && tx.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "collecting…",
                Style::default().fg(t.text_muted),
            ))),
            Rect::new(area.x, area.y + 1, area.width, 1),
        );
        return;
    }

    // rx over tx, as on Interfaces. With one row there is only room for rx.
    let rx_h = if chart_h >= 2 { chart_h / 2 } else { chart_h };
    let tx_h = chart_h - rx_h;
    // One sample per sub-column, newest at the right, exactly as the
    // Interfaces chart draws: stretching a short history across the width
    // turned each sample into a block two or three columns wide.
    crate::graph::render_with_max(
        f,
        Rect::new(area.x, area.y + 1, area.width, rx_h),
        &rx,
        rx_max.max(1),
        app.graph_style,
        t.rx_rate,
        t.status_warn,
        app.graph_opts(),
    );
    if tx_h > 0 {
        crate::graph::render_with_max(
            f,
            Rect::new(area.x, area.y + 1 + rx_h, area.width, tx_h),
            &tx,
            tx_max.max(1),
            app.graph_style,
            t.tx_rate,
            t.status_warn,
            app.graph_opts(),
        );
    }

    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            crate::graph::time_axis(
                area.width,
                crate::graph::axis_window_secs(
                    area.width,
                    app.graph_style,
                    app.user_config.refresh_rate_ms,
                ),
            ),
            Style::default().fg(t.text_muted),
        ))),
        Rect::new(area.x, area.y + area.height - 1, area.width, 1),
    );
}

// ── helpers ─────────────────────────────────────────────────

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let hints = vec![
        widgets::hint("s", "sort"),
        widgets::hint("e", "export csv"),
        widgets::hint("↵", "connections"),
    ];
    widgets::render_footer(f, app, area, hints);
}

fn host_only(addr: &str) -> String {
    if let Some(stripped) = addr.strip_prefix('[') {
        if let Some(end) = stripped.find("]:") {
            return format!("[{}]", &stripped[..end]);
        }
    }
    if let Some(colon) = addr.rfind(':') {
        addr[..colon].to_string()
    } else {
        addr.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::socket_state_row;

    /// `ss` and the Windows socket tables use hyphens, lsof underscores. The
    /// panel used to count a Linux CLOSE-WAIT, FIN-WAIT or SYN-SENT socket
    /// as OTHER.
    #[test]
    fn both_spellings_of_each_state_count_in_the_same_row() {
        for (ss, lsof, row) in [
            ("TIME-WAIT", "TIME_WAIT", "TIME_WAIT"),
            ("CLOSE-WAIT", "CLOSE_WAIT", "CLOSE_WAIT"),
            ("FIN-WAIT-1", "FIN_WAIT_1", "FIN_WAIT"),
            ("FIN-WAIT-2", "FIN_WAIT_2", "FIN_WAIT"),
            ("SYN-SENT", "SYN_SENT", "SYN"),
            ("SYN-RECV", "SYN_RCVD", "SYN"),
        ] {
            assert_eq!(socket_state_row(ss), row, "{ss}");
            assert_eq!(socket_state_row(lsof), row, "{lsof}");
        }
        assert_eq!(socket_state_row("ESTABLISHED"), "ESTABLISHED");
        assert_eq!(socket_state_row("LISTEN"), "LISTEN");
        assert_eq!(socket_state_row("CLOSED"), "OTHER");
        assert_eq!(socket_state_row(""), "OTHER");
    }

    /// An idle process is still a row to read: its name is primary text, as
    /// a connection's is in the Connections table. Only the unmeasured cell
    /// is muted. The whole row was, so with capture off the table was grey.
    #[test]
    fn an_idle_process_row_is_not_greyed_out() {
        use ratatui::{backend::TestBackend, layout::Rect, Terminal};
        let mut app =
            crate::app::App::prepare_with_config(crate::config::NetwatchConfig::default());
        app.user_config.graph_fade = false;
        let proc = crate::collectors::process_bandwidth::ProcessBandwidth {
            process_name: "idle".into(),
            pid: Some(42),
            rx_bytes: 0,
            tx_bytes: 0,
            rx_rate: 0.0,
            tx_rate: 0.0,
            connection_count: 3,
            rtt_ms: None,
            cpu_percent: None,
        };
        let area = Rect::new(0, 0, 100, 1);
        let mut terminal = Terminal::new(TestBackend::new(100, 1)).unwrap();
        terminal
            .draw(|f| {
                super::render_process_row(
                    f,
                    &app,
                    area,
                    0,
                    &proc,
                    false,
                    1.0,
                    [true; super::COLS.len()],
                )
            })
            .unwrap();
        let buf = terminal.backend().buffer().clone();
        let t = &app.theme;
        let fg_at = |needle: &str| {
            let row: String = (0..100).map(|x| buf[(x, 0)].symbol()).collect();
            let byte = row
                .find(needle)
                .unwrap_or_else(|| panic!("{needle} in {row}"));
            let x = row[..byte].chars().count() as u16;
            buf[(x, 0)].fg
        };
        assert_eq!(fg_at("idle"), t.text_primary);
        assert_eq!(fg_at("42"), t.text_secondary);
        assert_eq!(fg_at(crate::ui::widgets::NO_VALUE), t.text_muted);
    }

    /// The drill-in chart is the Interfaces chart: both rates in the header,
    /// rx over tx, a time axis, and one sample per sub-column. It stretched
    /// sixty samples across the width, so a one-second burst was a solid
    /// block several columns wide.
    #[test]
    fn the_chart_draws_one_sample_per_sub_column() {
        use crate::graph::GraphStyle;
        use ratatui::{backend::TestBackend, layout::Rect, Terminal};
        let mut app =
            crate::app::App::prepare_with_config(crate::config::NetwatchConfig::default());
        let proc = crate::collectors::process_bandwidth::ProcessBandwidth {
            process_name: "curl".into(),
            pid: Some(1),
            rx_bytes: 0,
            tx_bytes: 0,
            rx_rate: 1000.0,
            tx_rate: 0.0,
            connection_count: 1,
            rtt_ms: None,
            cpu_percent: None,
        };
        let key = ("curl".to_string(), Some(1));
        let width = 80u16;
        let draw = |app: &crate::app::App| {
            let area = Rect::new(0, 0, width, 6);
            let mut terminal = Terminal::new(TestBackend::new(width, 6)).unwrap();
            terminal
                .draw(|f| super::render_chart(f, app, area, &proc))
                .unwrap();
            let buf = terminal.backend().buffer().clone();
            (0..6u16)
                .map(|y| (0..width).map(|x| buf[(x, y)].symbol()).collect::<String>())
                .collect::<Vec<String>>()
        };
        for style in [GraphStyle::Bars, GraphStyle::Dots] {
            app.graph_style = style;

            // A full history at full scale fills both halves edge to edge.
            let full: std::collections::VecDeque<u64> =
                vec![1000; crate::app::TOP_PROC_HISTORY_LEN].into();
            app.caches
                .top_proc_rx_history
                .insert(key.clone(), full.clone());
            app.caches.top_proc_tx_history.insert(key.clone(), full);
            let rows = draw(&app);
            assert!(rows[0].starts_with("● rx 1 KB/s    ● tx 0"), "{}", rows[0]);
            assert!(rows[5].starts_with('-'), "{}", rows[5]);
            assert!(rows[5].trim_end().ends_with("now"), "{}", rows[5]);
            for y in [1, 3] {
                assert!(!rows[y].contains(' '), "{style:?} row {y}: {:?}", rows[y]);
            }

            // One busy second is one column wide, not a block.
            let mut lone = vec![0u64; crate::app::TOP_PROC_HISTORY_LEN];
            let at = lone.len() - 10;
            lone[at] = 1000;
            app.caches
                .top_proc_rx_history
                .insert(key.clone(), lone.into());
            let rows = draw(&app);
            let tall = rows[1].chars().filter(|c| *c != ' ').count();
            assert_eq!(tall, 1, "{style:?}: {:?}", rows[1]);
        }
    }
}
