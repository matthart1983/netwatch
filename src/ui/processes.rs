use std::collections::HashMap;

use crate::app::App;
use crate::collectors::process_bandwidth::ProcessBandwidth;
use crate::sort::{apply_direction, cmp_case_insensitive, cmp_f64, SortColumn, TabSortState};
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Sparkline},
};

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
            _ => std::cmp::Ordering::Equal,
        };
        apply_direction(ord, ascending)
    });
}

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header
            Constraint::Length(2),  // sort chips
            Constraint::Min(8),     // table
            Constraint::Length(11), // drill-in panel
            Constraint::Length(3),  // footer
        ])
        .split(area);

    widgets::render_header(f, app, chunks[0]);
    render_sort_chips(f, app, chunks[1]);

    let mut ranked = app.process_bandwidth.ranked().to_vec();
    if let Some(state) = app.sort_states.get(&crate::app::Tab::Processes) {
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
        .sort_states
        .get(&crate::app::Tab::Processes)
        .copied()
        .unwrap_or(DEFAULT_SORT);

    let chips: [(&str, &str, bool); 6] = [
        ("rx/s", "Rx Rate", false),
        ("tx/s", "Tx Rate", false),
        ("conns", "Conns", false),
        ("rtt", "—", true), // no per-proc RTT data yet
        ("cpu", "—", true), // no per-proc CPU data yet
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

fn render_process_table(f: &mut Frame, app: &App, ranked: &[ProcessBandwidth], area: Rect) {
    let t = &app.theme;

    let block = Block::default()
        .title(Line::from(Span::styled(
            " PROCESSES ",
            Style::default().fg(t.brand).bold(),
        )))
        .title(
            Line::from(Span::styled(
                format!(" {} ", ranked.len()),
                Style::default().fg(t.text_muted),
            ))
            .alignment(Alignment::Right),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.border));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 2 {
        return;
    }

    let header = "  PROCESS              PID    CONNS    RX/s        TX/s      RX TOTAL    TX TOTAL    RTT      CPU";
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            header,
            Style::default().fg(t.text_muted),
        ))),
        Rect::new(inner.x + 1, inner.y, inner.width.saturating_sub(2), 1),
    );

    let visible = inner.height.saturating_sub(1) as usize;
    let max_idx = ranked.len().saturating_sub(1);
    let selected = app.scroll.process_scroll.min(max_idx);
    let window_top = if selected < visible {
        0
    } else {
        selected
            .saturating_sub(visible / 2)
            .min(ranked.len().saturating_sub(visible))
    };

    for (i, proc) in ranked.iter().skip(window_top).take(visible).enumerate() {
        let row_y = inner.y + 1 + i as u16;
        let abs_idx = window_top + i;
        let is_selected = abs_idx == selected;
        render_process_row(f, app, inner, row_y, proc, is_selected);
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
) {
    let t = &app.theme;
    let active = proc.rx_rate > 0.0 || proc.tx_rate > 0.0;
    let dot_color = if active { t.status_good } else { t.text_muted };
    let main_color = if active { t.text_primary } else { t.text_muted };

    let pid_str = proc
        .pid
        .map(|p| p.to_string())
        .unwrap_or_else(|| "—".into());
    let line = Line::from(vec![
        Span::styled(
            if is_selected { "▸ " } else { "● " },
            Style::default().fg(if is_selected { t.brand } else { dot_color }),
        ),
        Span::styled(
            format!("{:<18}", truncate(&proc.process_name, 18)),
            Style::default().fg(main_color),
        ),
        Span::styled(
            format!(" {:>5}", pid_str),
            Style::default().fg(t.text_muted),
        ),
        Span::styled(
            format!("  {:>4}", proc.connection_count),
            Style::default().fg(t.text_muted),
        ),
        Span::styled(
            format!("  {:>10}", widgets::format_bytes_rate(proc.rx_rate)),
            Style::default().fg(if active { t.rx_rate } else { t.text_muted }),
        ),
        Span::raw(" "),
        Span::styled(
            format!(" {:>9}", widgets::format_bytes_rate(proc.tx_rate)),
            Style::default().fg(if active { t.tx_rate } else { t.text_muted }),
        ),
        Span::raw(" "),
        Span::styled(
            format!(" {:>7}", widgets::format_bytes_total(proc.rx_bytes)),
            Style::default().fg(main_color),
        ),
        Span::raw(" "),
        Span::styled(
            format!(" {:>7}", widgets::format_bytes_total(proc.tx_bytes)),
            Style::default().fg(main_color),
        ),
        Span::raw("   "),
        // RTT and CPU stubbed — not collected per-process today
        Span::styled(format!("{:>5}", "—"), Style::default().fg(t.text_muted)),
        Span::raw("   "),
        Span::styled(format!("{:>5}", "—"), Style::default().fg(t.text_muted)),
    ]);

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
    f.render_widget(Paragraph::new(line).style(bg), row_area);
}

// ── Drill-in panel ──────────────────────────────────────────

fn render_drill_in(f: &mut Frame, app: &App, ranked: &[ProcessBandwidth], area: Rect) {
    let t = &app.theme;
    let max_idx = ranked.len().saturating_sub(1);
    let selected_idx = app.scroll.process_scroll.min(max_idx);
    let selected = ranked.get(selected_idx);

    let title_left = match selected {
        Some(p) => format!(
            " {}  pid {} ",
            p.process_name,
            p.pid.map(|x| x.to_string()).unwrap_or_else(|| "—".into())
        ),
        None => " DETAIL ".to_string(),
    };
    let title_right = match selected {
        Some(p) => format!(
            " {} sockets  {} RX  ↑↓ to switch ",
            p.connection_count,
            widgets::format_bytes_total(p.rx_bytes)
        ),
        None => " ↑↓ to switch ".to_string(),
    };

    let block = Block::default()
        .title(Line::from(Span::styled(
            title_left,
            Style::default().fg(t.status_warn).bold(),
        )))
        .title(
            Line::from(Span::styled(title_right, Style::default().fg(t.text_muted)))
                .alignment(Alignment::Right),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.border));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 4 {
        return;
    }

    let Some(proc) = selected else {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "↑↓ to select a process",
                Style::default().fg(t.text_muted),
            ))),
            Rect::new(inner.x + 2, inner.y + 1, inner.width.saturating_sub(2), 1),
        );
        return;
    };

    // 3 columns: TOP REMOTES (left) | SOCKET STATES (middle) | RX 60s (right)
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(32),
            Constraint::Length(22),
            Constraint::Min(0),
        ])
        .split(inner);

    render_top_remotes(f, app, cols[0], proc);
    render_socket_states(f, app, cols[1], proc);
    render_rx_chart(f, app, cols[2], proc);
}

fn render_top_remotes(f: &mut Frame, app: &App, area: Rect, proc: &ProcessBandwidth) {
    let t = &app.theme;
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "TOP REMOTES",
            Style::default().fg(t.text_muted),
        ))),
        Rect::new(area.x, area.y, area.width, 1),
    );

    let conns = app.connection_collector.connections.lock().unwrap();
    let mut totals: HashMap<String, u32> = HashMap::new();
    for c in conns.iter() {
        if c.process_name.as_deref() != Some(proc.process_name.as_str()) {
            continue;
        }
        if c.pid != proc.pid {
            continue;
        }
        let host = host_only(&c.remote_addr);
        if host.is_empty() {
            continue;
        }
        *totals.entry(host).or_insert(0) += 1;
    }
    drop(conns);

    let mut sorted: Vec<(String, u32)> = totals.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

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
    let total_conns = sorted.iter().map(|(_, n)| *n).sum::<u32>().max(1);

    for (i, (host, n)) in sorted.iter().take(max_rows.min(5)).enumerate() {
        let row_y = area.y + 1 + i as u16;
        // Approximate per-host bytes by proc.rx_bytes * (n / total_conns)
        let approx_bytes = (proc.rx_bytes as f64 * (*n as f64 / total_conns as f64)).round() as u64;
        let label_w = (area.width as usize).saturating_sub(10).max(8);
        let line = Line::from(vec![
            Span::styled(
                format!("{:<width$}", truncate(host, label_w), width = label_w),
                Style::default().fg(t.text_primary),
            ),
            Span::styled(
                format!(" {:>7}", widgets::format_bytes_total(approx_bytes)),
                Style::default().fg(t.rx_rate),
            ),
        ]);
        f.render_widget(
            Paragraph::new(line),
            Rect::new(area.x, row_y, area.width, 1),
        );
    }

    let remaining = sorted.len().saturating_sub(5);
    if remaining > 0 && max_rows >= 6 {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!("others ({})", remaining),
                Style::default().fg(t.text_muted),
            ))),
            Rect::new(area.x, area.y + 1 + 5, area.width, 1),
        );
    }
}

fn render_socket_states(f: &mut Frame, app: &App, area: Rect, proc: &ProcessBandwidth) {
    let t = &app.theme;
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "SOCKET STATES",
            Style::default().fg(t.text_muted),
        ))),
        Rect::new(area.x, area.y, area.width, 1),
    );

    let conns = app.connection_collector.connections.lock().unwrap();
    let mut counts: HashMap<&'static str, u32> = HashMap::new();
    for c in conns.iter() {
        if c.process_name.as_deref() != Some(proc.process_name.as_str()) {
            continue;
        }
        if c.pid != proc.pid {
            continue;
        }
        let label = match c.state.as_str() {
            "ESTABLISHED" => "ESTABLISHED",
            "LISTEN" => "LISTEN",
            "TIME_WAIT" | "TIME-WAIT" => "TIME_WAIT",
            "CLOSE_WAIT" => "CLOSE_WAIT",
            "FIN_WAIT_1" | "FIN_WAIT_2" | "FIN_WAIT1" | "FIN_WAIT2" => "FIN_WAIT",
            "SYN_SENT" | "SYN_RECV" | "SYN_RECEIVED" => "SYN",
            _ => "OTHER",
        };
        *counts.entry(label).or_insert(0) += 1;
    }
    drop(conns);

    let order: &[(&str, Color)] = &[
        ("ESTABLISHED", t.status_good),
        ("LISTEN", t.status_info),
        ("TIME_WAIT", t.status_warn),
        ("CLOSE_WAIT", t.text_muted),
        ("FIN_WAIT", t.text_muted),
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
                format!("{:<14}", label),
                Style::default().fg(if count > 0 { *color } else { t.text_muted }),
            ),
            Span::styled(
                format!(" {:>4}", count),
                Style::default().fg(t.text_primary),
            ),
        ]);
        f.render_widget(
            Paragraph::new(line),
            Rect::new(area.x, row_y, area.width, 1),
        );
    }
}

fn render_rx_chart(f: &mut Frame, app: &App, area: Rect, _proc: &ProcessBandwidth) {
    let t = &app.theme;
    if area.width < 8 || area.height < 3 {
        return;
    }

    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "RX 60s  (interface aggregate)",
            Style::default().fg(t.text_muted),
        ))),
        Rect::new(area.x, area.y, area.width, 1),
    );

    // Per-process RX history isn't tracked yet; show the aggregate interface RX
    // as a proxy so the panel isn't empty. The footer line marks this caveat.
    let interfaces = app.traffic.interfaces();
    let mut acc: Vec<u64> = Vec::new();
    for iface in &interfaces {
        if iface.name == "lo0" || iface.name == "lo" {
            continue;
        }
        if iface.rx_history.len() > acc.len() {
            acc.resize(iface.rx_history.len(), 0);
        }
        for (i, &v) in iface.rx_history.iter().enumerate() {
            acc[i] += v;
        }
    }

    let chart_h = area.height.saturating_sub(2);
    if chart_h < 1 {
        return;
    }
    let chart_area = Rect::new(area.x, area.y + 1, area.width, chart_h);
    let padded = pad_history(&acc, area.width as usize);
    f.render_widget(
        Sparkline::default()
            .data(&padded)
            .style(Style::default().fg(t.rx_rate)),
        chart_area,
    );

    // Footer stats
    let peak = *acc.iter().max().unwrap_or(&0);
    let avg = if !acc.is_empty() {
        acc.iter().sum::<u64>() / acc.len() as u64
    } else {
        0
    };
    let p99_idx = if acc.is_empty() {
        0
    } else {
        ((acc.len() as f64 * 0.99) as usize).min(acc.len() - 1)
    };
    let mut sorted = acc.clone();
    sorted.sort();
    let p99 = sorted.get(p99_idx).copied().unwrap_or(0);
    let footer_y = area.y + area.height - 1;
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!(
                "peak {}  avg {}  p99 {}",
                widgets::format_bytes_rate(peak as f64),
                widgets::format_bytes_rate(avg as f64),
                widgets::format_bytes_rate(p99 as f64)
            ),
            Style::default().fg(t.text_muted),
        ))),
        Rect::new(area.x, footer_y, area.width, 1),
    );
}

// ── helpers ─────────────────────────────────────────────────

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let hints = vec![
        Span::styled("s", Style::default().fg(t.key_hint).bold()),
        Span::raw(":Sort  "),
        Span::styled("e", Style::default().fg(t.key_hint).bold()),
        Span::raw(":Export  "),
        Span::styled("Enter", Style::default().fg(t.key_hint).bold()),
        Span::raw(":→Connections"),
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

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn pad_history(data: &[u64], target_width: usize) -> Vec<u64> {
    if target_width == 0 {
        return Vec::new();
    }
    if data.len() >= target_width {
        return data[data.len() - target_width..].to_vec();
    }
    let mut padded = vec![0u64; target_width - data.len()];
    padded.extend_from_slice(data);
    padded
}
