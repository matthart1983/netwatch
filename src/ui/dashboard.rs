use crate::app::App;
use crate::collectors::traffic::InterfaceTraffic;
use crate::ebpf::EbpfStatus;
use crate::sort::{SortColumn, TabSortState};
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Sparkline},
};
use std::collections::HashMap;

pub const COLUMNS: &[SortColumn] = &[];

pub const DEFAULT_SORT: TabSortState = TabSortState {
    column: 0,
    ascending: true,
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header
            Constraint::Length(5),  // KPI strip
            Constraint::Length(12), // Active Iface + Throughput
            Constraint::Min(8),     // Top Conns + Health
            Constraint::Length(3),  // footer
        ])
        .split(area);

    widgets::render_header(f, app, chunks[0]);
    render_kpi_strip(f, app, chunks[1]);
    render_mid_section(f, app, chunks[2]);
    render_bottom_section(f, app, chunks[3]);
    render_footer(f, app, chunks[4]);
}

// ── KPI strip ───────────────────────────────────────────────

fn render_kpi_strip(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
        ])
        .split(area);

    let hs = app.health_prober.status.lock().unwrap();
    let gw_history = rtt_history_to_u64(hs.gateway_rtt_history.as_slices().0);
    let dns_history = rtt_history_to_u64(hs.dns_rtt_history.as_slices().0);
    let loss_history = rtt_history_to_loss(hs.gateway_rtt_history.as_slices().0);

    // GW RTT
    render_kpi_tile(
        f,
        app,
        cols[0],
        "GW RTT",
        hs.gateway_rtt_ms.map(|v| format!("{:.1}", v)),
        "ms",
        trend_for_rtt(hs.gateway_rtt_history.as_slices().0),
        rtt_status_color(app, hs.gateway_rtt_ms, hs.gateway_loss_pct),
        &gw_history,
    );

    // DNS RTT
    render_kpi_tile(
        f,
        app,
        cols[1],
        "DNS RTT",
        hs.dns_rtt_ms.map(|v| format!("{:.1}", v)),
        "ms",
        trend_for_rtt(hs.dns_rtt_history.as_slices().0),
        rtt_status_color(app, hs.dns_rtt_ms, hs.dns_loss_pct),
        &dns_history,
    );

    // LOSS
    let max_loss = hs.gateway_loss_pct.max(hs.dns_loss_pct);
    let loss_color = if max_loss < 1.0 {
        app.theme.status_good
    } else if max_loss < 50.0 {
        app.theme.status_warn
    } else {
        app.theme.status_error
    };
    render_kpi_tile(
        f,
        app,
        cols[2],
        "LOSS",
        Some(format!("{:.0}", max_loss)),
        "%",
        TrendDisplay::neutral(),
        loss_color,
        &loss_history,
    );

    // THROUGHPUT
    let interfaces = app.traffic.interfaces();
    let total_rate: f64 = active_ifaces(&interfaces, &app.interface_info)
        .iter()
        .map(|i| i.rx_rate + i.tx_rate)
        .sum();
    let throughput_history = aggregate_history(&interfaces, &app.interface_info);
    let (val_str, unit_str) = format_rate_split(total_rate);
    render_kpi_tile(
        f,
        app,
        cols[3],
        "THROUGHPUT",
        Some(val_str),
        &unit_str,
        trend_for_throughput(&throughput_history, app),
        app.theme.rx_rate,
        &throughput_history,
    );
}

struct TrendDisplay {
    arrow: &'static str,
    delta: String,
    color: Color,
}

impl TrendDisplay {
    fn neutral() -> Self {
        Self {
            arrow: "→",
            delta: String::new(),
            color: Color::Reset,
        }
    }
}

fn render_kpi_tile(
    f: &mut Frame,
    app: &App,
    area: Rect,
    label: &str,
    value: Option<String>,
    unit: &str,
    trend: TrendDisplay,
    dot_color: Color,
    history: &[u64],
) {
    let t = &app.theme;
    let trend_color = if trend.color == Color::Reset {
        t.text_muted
    } else {
        trend.color
    };
    let trend_text = if trend.delta.is_empty() {
        format!(" {} ", trend.arrow)
    } else {
        format!(" {} {} ", trend.arrow, trend.delta)
    };

    let title = Line::from(vec![Span::styled(
        format!(" {} ", label),
        Style::default().fg(t.text_muted),
    )]);
    let block = Block::default()
        .title(title)
        .title_alignment(Alignment::Left)
        .title(
            Line::from(Span::styled(trend_text, Style::default().fg(trend_color)))
                .alignment(Alignment::Right),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.border));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height == 0 {
        return;
    }

    // Row 0 of inner: ● value unit
    let value_line = Line::from(vec![
        Span::styled("● ", Style::default().fg(dot_color)),
        Span::styled(
            value.clone().unwrap_or_else(|| "—".into()),
            Style::default().fg(t.text_primary).bold(),
        ),
        Span::raw(" "),
        Span::styled(unit.to_string(), Style::default().fg(t.text_muted)),
    ]);
    let value_area = Rect {
        x: inner.x + 1,
        y: inner.y,
        width: inner.width.saturating_sub(2),
        height: 1,
    };
    f.render_widget(Paragraph::new(value_line), value_area);

    // Row 1+ of inner: sparkline
    if inner.height >= 2 && !history.is_empty() {
        let spark_area = Rect {
            x: inner.x + 1,
            y: inner.y + 1,
            width: inner.width.saturating_sub(2),
            height: inner.height - 1,
        };
        let padded = pad_history(history, spark_area.width as usize);
        let spark = Sparkline::default()
            .data(&padded)
            .style(Style::default().fg(t.rx_rate));
        f.render_widget(spark, spark_area);
    }
}

// ── Mid section: Active Interface + Throughput ──────────────

fn render_mid_section(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(42), Constraint::Min(0)])
        .split(area);

    render_active_interface(f, app, cols[0]);
    render_throughput_chart(f, app, cols[1]);
}

fn render_active_interface(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let interfaces = app.traffic.interfaces();
    let actives = active_ifaces(&interfaces, &app.interface_info);
    let primary = actives.first().copied();
    // Only call an iface "live" if it currently has traffic; everything else
    // (including UP-but-silent and DOWN) goes to IDLE.
    let live_count = actives
        .iter()
        .filter(|i| i.rx_rate > 0.0 || i.tx_rate > 0.0)
        .count();
    let idle: Vec<_> = interfaces
        .iter()
        .filter(|i| i.rx_rate == 0.0 && i.tx_rate == 0.0)
        .collect();

    let title_right = format!(" {} live  {} idle ", live_count, idle.len());
    let block = Block::default()
        .title(Line::from(Span::styled(
            " ACTIVE INTERFACE ",
            Style::default().fg(t.brand).bold(),
        )))
        .title(
            Line::from(Span::styled(title_right, Style::default().fg(t.text_muted)))
                .alignment(Alignment::Right),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.border));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height == 0 {
        return;
    }

    let mut lines: Vec<Line> = Vec::new();

    if let Some(p) = primary {
        let info = app.interface_info.iter().find(|i| i.name == p.name);
        let ip = info
            .and_then(|i| i.ipv4.clone())
            .unwrap_or_else(|| "—".into());
        let mtu = info.and_then(|i| i.mtu).unwrap_or(0);
        let role = role_for(&p.name);
        let is_up = info.map(|i| i.is_up).unwrap_or(false);
        let status_span = if is_up {
            Span::styled("● UP", Style::default().fg(t.status_good))
        } else {
            Span::styled("● DOWN", Style::default().fg(t.status_error))
        };

        // Line 0: en0  192.168.0.213  wifi MTU 1500  ● UP
        lines.push(Line::from(vec![
            Span::styled(p.name.clone(), Style::default().fg(t.brand).bold()),
            Span::raw("  "),
            Span::styled(ip, Style::default().fg(t.text_primary)),
            Span::raw("  "),
            Span::styled(
                if mtu > 0 {
                    format!("{}  MTU {}", role, mtu)
                } else {
                    role.to_string()
                },
                Style::default().fg(t.text_muted),
            ),
            Span::raw("  "),
            status_span,
        ]));

        // Line 1: blank (was SSID line in mockup)
        lines.push(Line::from(""));

        // Line 2: RX  rate    TX  rate
        lines.push(Line::from(vec![
            Span::styled("RX ", Style::default().fg(t.text_muted)),
            Span::styled(
                widgets::format_bytes_rate(p.rx_rate),
                Style::default().fg(t.rx_rate).bold(),
            ),
            Span::raw("    "),
            Span::styled("TX ", Style::default().fg(t.text_muted)),
            Span::styled(
                widgets::format_bytes_rate(p.tx_rate),
                Style::default().fg(t.tx_rate).bold(),
            ),
        ]));

        // Line 3: total 95 GB    total 22 GB
        lines.push(Line::from(vec![
            Span::styled(
                format!("   total {}", widgets::format_bytes_total(p.rx_bytes_total)),
                Style::default().fg(t.text_muted),
            ),
            Span::raw("  "),
            Span::styled(
                format!("   total {}", widgets::format_bytes_total(p.tx_bytes_total)),
                Style::default().fg(t.text_muted),
            ),
        ]));

        // divider
        lines.push(Line::from(Span::styled(
            "─".repeat(inner.width.saturating_sub(2) as usize),
            Style::default().fg(t.border),
        )));

        // OTHER ACTIVE
        lines.push(Line::from(Span::styled(
            "OTHER ACTIVE",
            Style::default().fg(t.text_muted),
        )));

        for other in actives
            .iter()
            .skip(1)
            .filter(|i| i.rx_rate > 0.0 || i.tx_rate > 0.0)
            .take(3)
        {
            let other_info = app.interface_info.iter().find(|i| i.name == other.name);
            let other_ip = other_info
                .and_then(|i| i.ipv4.clone())
                .unwrap_or_else(|| "—".into());
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{:<8}", other.name),
                    Style::default().fg(t.text_primary),
                ),
                Span::styled(
                    format!(" {:>9}  ", widgets::format_bytes_rate(other.rx_rate)),
                    Style::default().fg(t.rx_rate),
                ),
                Span::styled(other_ip, Style::default().fg(t.text_muted)),
            ]));
        }

        // Idle summary
        if !idle.is_empty() {
            let names: String = idle
                .iter()
                .take(8)
                .map(|i| i.name.as_str())
                .collect::<Vec<_>>()
                .join(",");
            lines.push(Line::from(Span::styled(
                format!("{} IDLE: {}", idle.len(), names),
                Style::default().fg(t.text_muted),
            )));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "No active interface",
            Style::default().fg(t.text_muted),
        )));
    }

    let para = Paragraph::new(lines);
    let content_area = Rect {
        x: inner.x + 1,
        y: inner.y,
        width: inner.width.saturating_sub(2),
        height: inner.height,
    };
    f.render_widget(para, content_area);
}

fn render_throughput_chart(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let interfaces = app.traffic.interfaces();
    let actives = active_ifaces(&interfaces, &app.interface_info);

    let total_rx: f64 = actives.iter().map(|i| i.rx_rate).sum();
    let total_tx: f64 = actives.iter().map(|i| i.tx_rate).sum();

    let primary_name = actives
        .first()
        .map(|i| i.name.clone())
        .unwrap_or_else(|| "—".into());

    // Aggregate histories first so the title can describe what actually
    // fits in the chart (sparkline width vs available samples).
    let agg_rx = aggregate_rx(&actives);
    let agg_tx = aggregate_tx(&actives);

    // Approximate sparkline width before block.inner is computed (area minus
    // borders + 2-cell padding inside render).
    let chart_width = (area.width as usize).saturating_sub(4);
    let displayed = chart_width.min(agg_rx.len().max(agg_tx.len())).max(1);
    let window_label = if displayed >= 120 {
        format!("last {}m", displayed / 60)
    } else {
        format!("last {}s", displayed)
    };
    let title_left = format!(" THROUGHPUT  {}  {} ", primary_name, window_label);
    let block = Block::default()
        .title(Line::from(Span::styled(
            title_left,
            Style::default().fg(t.brand).bold(),
        )))
        .title(
            Line::from(Span::styled(" RX/TX ", Style::default().fg(t.text_muted)))
                .alignment(Alignment::Right),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.border));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 4 {
        return;
    }
    let peak_rx = *agg_rx.iter().max().unwrap_or(&0);
    let peak_tx = *agg_tx.iter().max().unwrap_or(&0);
    let avg_rx = if !agg_rx.is_empty() {
        agg_rx.iter().sum::<u64>() / agg_rx.len() as u64
    } else {
        0
    };
    let avg_tx = if !agg_tx.is_empty() {
        agg_tx.iter().sum::<u64>() / agg_tx.len() as u64
    } else {
        0
    };

    // Header line: ● RX rate  peak X  avg Y    ● TX rate  peak X  avg Y
    let header_area = Rect {
        x: inner.x + 1,
        y: inner.y,
        width: inner.width.saturating_sub(2),
        height: 1,
    };
    let header_line = Line::from(vec![
        Span::styled("● RX ", Style::default().fg(t.rx_rate)),
        Span::styled(
            widgets::format_bytes_rate(total_rx),
            Style::default().fg(t.rx_rate).bold(),
        ),
        Span::styled(
            format!(
                "  peak {}  avg {}    ",
                widgets::format_bytes_rate(peak_rx as f64),
                widgets::format_bytes_rate(avg_rx as f64),
            ),
            Style::default().fg(t.text_muted),
        ),
        Span::styled("● TX ", Style::default().fg(t.tx_rate)),
        Span::styled(
            widgets::format_bytes_rate(total_tx),
            Style::default().fg(t.tx_rate).bold(),
        ),
        Span::styled(
            format!(
                "  peak {}  avg {}",
                widgets::format_bytes_rate(peak_tx as f64),
                widgets::format_bytes_rate(avg_tx as f64),
            ),
            Style::default().fg(t.text_muted),
        ),
    ]);
    f.render_widget(Paragraph::new(header_line), header_area);

    // Stacked sparklines: RX top, TX bottom, with x-axis row at the bottom
    let chart_height = inner.height.saturating_sub(2);
    if chart_height < 2 {
        return;
    }
    let rx_h = chart_height / 2;
    let tx_h = chart_height - rx_h;

    let rx_area = Rect {
        x: inner.x + 1,
        y: inner.y + 1,
        width: inner.width.saturating_sub(2),
        height: rx_h,
    };
    let tx_area = Rect {
        x: inner.x + 1,
        y: inner.y + 1 + rx_h,
        width: inner.width.saturating_sub(2),
        height: tx_h,
    };

    let agg_rx_padded = pad_history(&agg_rx, rx_area.width as usize);
    let rx_spark = Sparkline::default()
        .data(&agg_rx_padded)
        .style(Style::default().fg(t.rx_rate));
    f.render_widget(rx_spark, rx_area);

    let agg_tx_padded = pad_history(&agg_tx, tx_area.width as usize);
    let tx_spark = Sparkline::default()
        .data(&agg_tx_padded)
        .style(Style::default().fg(t.tx_rate));
    f.render_widget(tx_spark, tx_area);

    // x-axis labels
    let axis_y = inner.y + inner.height - 1;
    let axis_w = inner.width.saturating_sub(2) as usize;
    let mut axis = String::new();
    axis.push_str("-60s");
    let mid_pad = axis_w.saturating_sub(11) / 2;
    axis.push_str(&" ".repeat(mid_pad));
    axis.push_str("-30s");
    let end_pad = axis_w.saturating_sub(axis.chars().count() + 3);
    axis.push_str(&" ".repeat(end_pad));
    axis.push_str("now");
    let axis_area = Rect {
        x: inner.x + 1,
        y: axis_y,
        width: inner.width.saturating_sub(2),
        height: 1,
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            axis,
            Style::default().fg(t.text_muted),
        ))),
        axis_area,
    );
}

// ── Bottom section: Top Connections + Health ────────────────

fn render_bottom_section(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(50)])
        .split(area);

    render_top_connections(f, app, cols[0]);
    render_health(f, app, cols[1]);
}

fn render_top_connections(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let block = Block::default()
        .title(Line::from(Span::styled(
            " TOP CONNECTIONS ",
            Style::default().fg(t.brand).bold(),
        )))
        .title(
            Line::from(Span::styled(
                " by RX  grouped by host ",
                Style::default().fg(t.text_muted),
            ))
            .alignment(Alignment::Right),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.border));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 3 {
        return;
    }

    // Header
    let header_area = Rect {
        x: inner.x + 1,
        y: inner.y,
        width: inner.width.saturating_sub(2),
        height: 1,
    };
    let header = Line::from(Span::styled(
        "  PROCESS         REMOTE                    RX/s        TX/s      RTT     RX 30s",
        Style::default().fg(t.text_muted),
    ));
    f.render_widget(Paragraph::new(header), header_area);

    // Build grouped rows from connections
    let conns = app.connection_collector.connections.lock().unwrap();
    let mut grouped: HashMap<(String, String), GroupedConn> = HashMap::new();
    for c in conns.iter() {
        // Skip listeners (no remote peer) and closed states; everything else
        // (ESTABLISHED, UDP "", etc.) can have measurable traffic.
        if c.state == "LISTEN" || c.state == "CLOSED" || c.remote_addr.is_empty() {
            continue;
        }
        let proc = c.process_name.clone().unwrap_or_else(|| "—".into());
        let host = remote_host_only(&c.remote_addr);
        let key = (proc.clone(), host.clone());
        let entry = grouped.entry(key).or_insert_with(|| GroupedConn {
            process: proc.clone(),
            host,
            rx_rate: 0.0,
            tx_rate: 0.0,
            rtt_ms_min: None,
            count: 0,
        });
        entry.rx_rate += c.rx_rate.unwrap_or(0.0);
        entry.tx_rate += c.tx_rate.unwrap_or(0.0);
        if let Some(rtt_us) = c.kernel_rtt_us {
            let rtt_ms = rtt_us / 1000.0;
            entry.rtt_ms_min = Some(match entry.rtt_ms_min {
                Some(prev) => prev.min(rtt_ms),
                None => rtt_ms,
            });
        }
        entry.count += 1;
    }

    let mut rows: Vec<GroupedConn> = grouped.into_values().collect();
    rows.sort_by(|a, b| {
        // Primary: rx_rate desc. Tiebreakers (tx_rate, process, host) make the
        // order fully deterministic across redraws — without them, all the 0.0
        // rate rows reshuffle every frame because HashMap iteration is random.
        b.rx_rate
            .partial_cmp(&a.rx_rate)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                b.tx_rate
                    .partial_cmp(&a.tx_rate)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.process.cmp(&b.process))
            .then_with(|| a.host.cmp(&b.host))
    });

    let max_rows = inner.height.saturating_sub(2) as usize;
    for (i, r) in rows.iter().take(max_rows).enumerate() {
        let key = (r.process.clone(), r.host.clone());
        let history_active = app
            .top_conn_history
            .get(&key)
            .map(|h| h.iter().any(|&v| v > 0))
            .unwrap_or(false);
        let active = r.rx_rate > 0.0 || r.tx_rate > 0.0 || history_active;
        // Idle rows get a blue dot instead of gray so the table feels lively
        // even when nothing's currently transferring.
        let dot_color = if active { t.status_good } else { t.status_info };
        let process_color = t.text_primary;
        let row_y = inner.y + 1 + i as u16;
        let remote_label = if r.count > 1 {
            format!("{}  x{}", truncate(&r.host, 20), r.count)
        } else {
            truncate(&r.host, 23)
        };
        let rtt_str = match r.rtt_ms_min {
            Some(rtt) if rtt < 1.0 => format!("{:.1}ms", rtt),
            Some(rtt) => format!("{:.0}ms", rtt),
            None => "—".to_string(),
        };
        let row_line = Line::from(vec![
            Span::styled("● ", Style::default().fg(dot_color)),
            Span::styled(
                format!("{:<16}", truncate(&r.process, 16)),
                Style::default().fg(process_color),
            ),
            Span::styled(
                format!(" {:<24}", remote_label),
                Style::default().fg(t.text_muted),
            ),
            Span::styled(
                format!("{:>9}", widgets::format_bytes_rate(r.rx_rate)),
                Style::default().fg(t.rx_rate),
            ),
            Span::raw("  "),
            Span::styled(
                format!("{:>9}", widgets::format_bytes_rate(r.tx_rate)),
                Style::default().fg(t.tx_rate),
            ),
            Span::raw("  "),
            Span::styled(
                format!("{:>5}", rtt_str),
                Style::default().fg(t.text_primary),
            ),
        ]);
        let row_area = Rect {
            x: inner.x + 1,
            y: row_y,
            width: inner.width.saturating_sub(2),
            height: 1,
        };
        let para = if i == 0 {
            Paragraph::new(row_line).style(Style::default().bg(t.selection_bg))
        } else {
            Paragraph::new(row_line)
        };
        f.render_widget(para, row_area);

        // RX history sparkline at end of row (if there's room)
        let row_w = row_area.width as usize;
        let leading_w = 2 + 16 + 25 + 9 + 2 + 9 + 2 + 5 + 2; // matches the row_line spans
        if row_w > leading_w {
            let spark_w = (row_w - leading_w).min(14);
            if spark_w >= 4 {
                let key = (r.process.clone(), r.host.clone());
                if let Some(hist) = app.top_conn_history.get(&key) {
                    let data: Vec<u64> = hist.iter().copied().collect();
                    if !data.is_empty() {
                        let spark_area = Rect {
                            x: row_area.x + leading_w as u16,
                            y: row_y,
                            width: spark_w as u16,
                            height: 1,
                        };
                        let padded = pad_history(&data, spark_w);
                        let spark = Sparkline::default().data(&padded).style(
                            Style::default().fg(if active { t.rx_rate } else { t.text_muted }),
                        );
                        f.render_widget(spark, spark_area);
                    }
                }
            }
        }
    }

    if rows.is_empty() {
        let empty_area = Rect {
            x: inner.x + 1,
            y: inner.y + 1,
            width: inner.width.saturating_sub(2),
            height: 1,
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  No established connections",
                Style::default().fg(t.text_muted),
            ))),
            empty_area,
        );
    }
}

struct GroupedConn {
    process: String,
    host: String,
    rx_rate: f64,
    tx_rate: f64,
    rtt_ms_min: Option<f64>,
    count: u32,
}

fn render_health(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let hs = app.health_prober.status.lock().unwrap();

    let max_loss = hs.gateway_loss_pct.max(hs.dns_loss_pct);
    let title_right = if max_loss < 1.0 {
        " all nominal ".to_string()
    } else {
        format!(" {:.0}% loss ", max_loss)
    };
    let title_color = if max_loss < 1.0 {
        t.status_good
    } else {
        t.status_warn
    };

    let block = Block::default()
        .title(Line::from(Span::styled(
            " HEALTH ",
            Style::default().fg(t.brand).bold(),
        )))
        .title(
            Line::from(Span::styled(title_right, Style::default().fg(title_color)))
                .alignment(Alignment::Right),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.border));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 4 {
        return;
    }

    // Column header
    let hdr_area = Rect {
        x: inner.x + 1,
        y: inner.y,
        width: inner.width.saturating_sub(2),
        height: 1,
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "  TARGET            RTT(60s)         NOW",
            Style::default().fg(t.text_muted),
        ))),
        hdr_area,
    );

    let gw_label = app
        .config_collector
        .config
        .gateway
        .clone()
        .unwrap_or_else(|| "—".into());
    let dns_label = app
        .config_collector
        .config
        .dns_servers
        .first()
        .cloned()
        .unwrap_or_else(|| "—".into());

    render_health_target(
        f,
        app,
        Rect {
            x: inner.x + 1,
            y: inner.y + 1,
            width: inner.width.saturating_sub(2),
            height: 2,
        },
        "Gateway",
        &gw_label,
        hs.gateway_rtt_ms,
        hs.gateway_loss_pct,
        hs.gateway_rtt_history.as_slices().0,
    );
    render_health_target(
        f,
        app,
        Rect {
            x: inner.x + 1,
            y: inner.y + 3,
            width: inner.width.saturating_sub(2),
            height: 2,
        },
        "DNS",
        &dns_label,
        hs.dns_rtt_ms,
        hs.dns_loss_pct,
        hs.dns_rtt_history.as_slices().0,
    );

    // Bottom strip: eBPF / errors / drops / retransmits
    let bottom_y = inner.y + inner.height.saturating_sub(2);
    if bottom_y > inner.y + 5 {
        let interfaces = app.traffic.interfaces();
        let total_errors: u64 = interfaces.iter().map(|i| i.rx_errors + i.tx_errors).sum();
        let total_drops: u64 = interfaces.iter().map(|i| i.rx_drops + i.tx_drops).sum();
        let ebpf_text = match &app.ebpf_status {
            EbpfStatus::Active => "eBPF active",
            EbpfStatus::Unavailable(_) => "eBPF off",
            EbpfStatus::NotCompiled => "eBPF off",
        };

        // separator
        let sep_y = bottom_y.saturating_sub(1);
        let sep_area = Rect {
            x: inner.x + 1,
            y: sep_y,
            width: inner.width.saturating_sub(2),
            height: 1,
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "─".repeat(inner.width.saturating_sub(2) as usize),
                Style::default().fg(t.border),
            ))),
            sep_area,
        );

        let strip_area = Rect {
            x: inner.x + 1,
            y: bottom_y,
            width: inner.width.saturating_sub(2),
            height: 1,
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!(
                    "{}   errors {}   drops {}",
                    ebpf_text, total_errors, total_drops
                ),
                Style::default().fg(t.text_muted),
            ))),
            strip_area,
        );
    }
}

fn render_health_target(
    f: &mut Frame,
    app: &App,
    area: Rect,
    name: &str,
    host: &str,
    rtt: Option<f64>,
    loss: f64,
    history: &[Option<f64>],
) {
    let t = &app.theme;
    if area.height < 1 {
        return;
    }
    let dot_color = if loss < 1.0 && rtt.is_some() {
        t.status_good
    } else if loss < 50.0 {
        t.status_warn
    } else {
        t.status_error
    };

    let rtt_str = rtt
        .map(|r| format!("{:.1}ms", r))
        .unwrap_or_else(|| "—".into());

    // Row 0: ● Name [sparkline area]    rtt
    let name_span = Line::from(vec![
        Span::styled("● ", Style::default().fg(dot_color)),
        Span::styled(
            format!("{:<8}", name),
            Style::default().fg(t.text_primary).bold(),
        ),
    ]);
    let name_area = Rect {
        x: area.x,
        y: area.y,
        width: 11,
        height: 1,
    };
    f.render_widget(Paragraph::new(name_span), name_area);

    // sparkline between name and rtt value
    let rtt_w: u16 = 8;
    if area.width > 11 + rtt_w {
        let spark_area = Rect {
            x: area.x + 11,
            y: area.y,
            width: area.width - 11 - rtt_w,
            height: 1,
        };
        let data = rtt_history_to_u64(history);
        if !data.is_empty() {
            let padded = pad_history(&data, spark_area.width as usize);
            let spark = Sparkline::default()
                .data(&padded)
                .style(Style::default().fg(dot_color));
            f.render_widget(spark, spark_area);
        }
    }

    // rtt value right-aligned
    let rtt_area = Rect {
        x: area.x + area.width.saturating_sub(rtt_w),
        y: area.y,
        width: rtt_w,
        height: 1,
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!("{:>7}", rtt_str),
            Style::default().fg(t.text_primary),
        ))),
        rtt_area,
    );

    // Row 1: host and loss
    if area.height >= 2 {
        let row1_area = Rect {
            x: area.x,
            y: area.y + 1,
            width: area.width,
            height: 1,
        };
        let row1 = Line::from(vec![
            Span::raw("  "),
            Span::styled(host.to_string(), Style::default().fg(t.text_muted)),
            Span::raw("  "),
            Span::styled(
                format!("{:.0}% loss", loss),
                Style::default().fg(t.text_muted),
            ),
        ]);
        f.render_widget(Paragraph::new(row1), row1_area);
    }
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let hints = vec![
        Span::styled("p", Style::default().fg(app.theme.key_hint).bold()),
        Span::raw(":Pause  "),
        Span::styled("r", Style::default().fg(app.theme.key_hint).bold()),
        Span::raw(":Refresh  "),
        Span::styled(",", Style::default().fg(app.theme.key_hint).bold()),
        Span::raw(":Settings"),
    ];
    widgets::render_footer(f, app, area, hints);
}

// ── helpers ─────────────────────────────────────────────────

fn role_for(name: &str) -> &'static str {
    if name == "lo0" || name == "lo" {
        "loopback"
    } else if name.starts_with("utun") || name.starts_with("tun") || name.starts_with("wg") {
        "vpn"
    } else if name.starts_with("en") || name.starts_with("wlan") || name.starts_with("wlp") {
        "ethernet/wifi"
    } else if name.starts_with("anpi") || name.starts_with("ap") {
        "apple"
    } else if name.starts_with("bridge") {
        "bridge"
    } else if name.starts_with("awdl") {
        "awdl"
    } else {
        ""
    }
}

/// All UP, non-loopback interfaces — used for the throughput chart and to pick
/// the primary interface. Sorted by cumulative bytes desc so the busiest iface
/// surfaces first even during idle moments.
fn active_ifaces<'a>(
    interfaces: &'a [InterfaceTraffic],
    info: &[crate::platform::InterfaceInfo],
) -> Vec<&'a InterfaceTraffic> {
    let mut v: Vec<_> = interfaces
        .iter()
        .filter(|i| {
            let is_up = info
                .iter()
                .find(|inf| inf.name == i.name)
                .map(|inf| inf.is_up)
                .unwrap_or(false);
            is_up && i.name != "lo0" && i.name != "lo"
        })
        .collect();
    v.sort_by(|a, b| {
        let a_sum = a.rx_bytes_total + a.tx_bytes_total;
        let b_sum = b.rx_bytes_total + b.tx_bytes_total;
        b_sum.cmp(&a_sum)
    });
    v
}

fn aggregate_rx(actives: &[&InterfaceTraffic]) -> Vec<u64> {
    aggregate_iter(actives.iter().map(|i| &i.rx_history))
}

fn aggregate_tx(actives: &[&InterfaceTraffic]) -> Vec<u64> {
    aggregate_iter(actives.iter().map(|i| &i.tx_history))
}

fn aggregate_iter<'a, I>(iter: I) -> Vec<u64>
where
    I: Iterator<Item = &'a std::collections::VecDeque<u64>>,
{
    let mut acc: Vec<u64> = Vec::new();
    for hist in iter {
        if hist.len() > acc.len() {
            acc.resize(hist.len(), 0);
        }
        for (t, &v) in hist.iter().enumerate() {
            acc[t] += v;
        }
    }
    acc
}

fn aggregate_history(
    interfaces: &[InterfaceTraffic],
    info: &[crate::platform::InterfaceInfo],
) -> Vec<u64> {
    let actives = active_ifaces(interfaces, info);
    let rx = aggregate_rx(&actives);
    let tx = aggregate_tx(&actives);
    rx.iter()
        .zip(tx.iter().chain(std::iter::repeat(&0u64)))
        .map(|(r, t)| r + t)
        .collect()
}

fn rtt_history_to_u64(history: &[Option<f64>]) -> Vec<u64> {
    history
        .iter()
        .map(|r| r.map(|v| v.round() as u64).unwrap_or(0))
        .collect()
}

/// Left-pad with zeros (or trim) so `data` is exactly `target_width` long.
/// The newest sample ends up at the right edge of the rendered Sparkline area,
/// which is what time-series charts want ("now" at the right).
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

fn rtt_history_to_loss(history: &[Option<f64>]) -> Vec<u64> {
    history
        .iter()
        .map(|r| if r.is_none() { 100 } else { 0 })
        .collect()
}

fn rtt_status_color(app: &App, rtt: Option<f64>, loss: f64) -> Color {
    if loss >= 50.0 {
        app.theme.status_error
    } else if loss > 1.0 {
        app.theme.status_warn
    } else {
        match rtt {
            Some(r) if r > 200.0 => app.theme.status_error,
            Some(r) if r > 50.0 => app.theme.status_warn,
            Some(_) => app.theme.status_good,
            None => app.theme.text_muted,
        }
    }
}

fn trend_for_rtt(history: &[Option<f64>]) -> TrendDisplay {
    let halves = split_avg(history);
    match halves {
        Some((older, newer)) => {
            let delta = newer - older;
            if delta.abs() < 0.05 {
                TrendDisplay {
                    arrow: "→",
                    delta: format!("{:.1}", delta.abs()),
                    color: Color::Reset,
                }
            } else if delta < 0.0 {
                TrendDisplay {
                    arrow: "↓",
                    delta: format!("{:.1}", delta.abs()),
                    color: Color::Reset, // good but understated
                }
            } else {
                TrendDisplay {
                    arrow: "↑",
                    delta: format!("{:.1}", delta),
                    color: Color::Reset,
                }
            }
        }
        None => TrendDisplay::neutral(),
    }
}

fn trend_for_throughput(history: &[u64], _app: &App) -> TrendDisplay {
    if history.len() < 4 {
        return TrendDisplay::neutral();
    }
    let mid = history.len() / 2;
    let older: u64 = history[..mid].iter().sum::<u64>() / mid as u64;
    let newer: u64 = history[mid..].iter().sum::<u64>() / (history.len() - mid) as u64;
    if newer == older {
        TrendDisplay {
            arrow: "→",
            delta: "0".to_string(),
            color: Color::Reset,
        }
    } else if newer > older {
        let delta = newer - older;
        TrendDisplay {
            arrow: "↑",
            delta: widgets::format_bytes_rate(delta as f64),
            color: Color::Reset,
        }
    } else {
        let delta = older - newer;
        TrendDisplay {
            arrow: "↓",
            delta: widgets::format_bytes_rate(delta as f64),
            color: Color::Reset,
        }
    }
}

fn split_avg(history: &[Option<f64>]) -> Option<(f64, f64)> {
    let valid: Vec<f64> = history.iter().filter_map(|x| *x).collect();
    if valid.len() < 4 {
        return None;
    }
    let mid = valid.len() / 2;
    let older: f64 = valid[..mid].iter().sum::<f64>() / mid as f64;
    let newer: f64 = valid[mid..].iter().sum::<f64>() / (valid.len() - mid) as f64;
    Some((older, newer))
}

fn format_rate_split(bytes_per_sec: f64) -> (String, String) {
    if bytes_per_sec < 1.0 {
        return ("0".into(), "B/s".into());
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
    (format!("{:.1}", val), unit.to_string())
}

fn remote_host_only(addr: &str) -> String {
    // Strip trailing :port; preserve [ipv6]:port → [ipv6]
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
