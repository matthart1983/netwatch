use std::collections::HashMap;

use crate::app::{App, StatsRange};
use crate::collectors::packets::CapturedPacket;
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Sparkline},
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header
            Constraint::Length(2),  // range chips
            Constraint::Length(4),  // 5 KPI tiles
            Constraint::Length(11), // 3 breakdown panels
            Constraint::Min(8),     // throughput chart
            Constraint::Length(3),  // footer
        ])
        .split(area);

    let packets = app.packet_collector.get_packets();
    let stats = compute_stats(app, &packets);

    widgets::render_header(f, app, chunks[0]);
    render_range_chips(f, app, chunks[1]);
    render_kpi_tiles(f, app, &stats, chunks[2]);
    render_breakdowns(f, app, &packets, &stats, chunks[3]);
    render_throughput_chart(f, app, chunks[4]);
    render_footer(f, app, chunks[5]);
}

struct AggregateStats {
    total_packets: u64,
    total_bytes: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    connection_count: usize,
    dns_queries: u64,
    dns_errors: u64,
    retrans_count: u64,
}

fn compute_stats(app: &App, packets: &[CapturedPacket]) -> AggregateStats {
    let total_packets = packets.len() as u64;
    let total_bytes: u64 = packets.iter().map(|p| p.length as u64).sum();

    let dns_queries = packets.iter().filter(|p| p.protocol == "DNS").count() as u64;
    let dns_errors = packets
        .iter()
        .filter(|p| {
            p.protocol == "DNS"
                && (p.info.contains("NXDOMAIN")
                    || p.info.contains("Server Failure")
                    || p.info.contains("SERVFAIL")
                    || p.info.contains("Refused"))
        })
        .count() as u64;

    // Aggregate RX/TX from interfaces (cumulative since process start)
    let interfaces = app.traffic.interfaces();
    let rx_bytes: u64 = interfaces
        .iter()
        .filter(|i| i.name != "lo0" && i.name != "lo")
        .map(|i| i.rx_bytes_total)
        .sum();
    let tx_bytes: u64 = interfaces
        .iter()
        .filter(|i| i.name != "lo0" && i.name != "lo")
        .map(|i| i.tx_bytes_total)
        .sum();

    let connection_count = app.connection_collector.connections.lock().unwrap().len();

    // Retrans heuristic — packets where info contains retrans/retransmit/dup-ack
    let retrans_count = packets
        .iter()
        .filter(|p| {
            let info = p.info.to_lowercase();
            info.contains("retrans") || info.contains("dup ack")
        })
        .count() as u64;

    AggregateStats {
        total_packets,
        total_bytes,
        rx_bytes,
        tx_bytes,
        connection_count,
        dns_queries,
        dns_errors,
        retrans_count,
    }
}

// ── Range chips row ─────────────────────────────────────────

fn render_range_chips(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;

    let chips: [StatsRange; 6] = [
        StatsRange::Min1,
        StatsRange::Min5,
        StatsRange::Min15,
        StatsRange::Hour1,
        StatsRange::Hour24,
        StatsRange::Session,
    ];

    let mut spans: Vec<Span> = vec![Span::styled(" range  ", Style::default().fg(t.text_muted))];
    for r in chips.iter() {
        let active = *r == app.stats_range;
        if active {
            spans.push(Span::styled(
                format!(" {} ", r.label()),
                Style::default()
                    .fg(t.text_primary)
                    .bg(t.selection_bg)
                    .bold(),
            ));
        } else {
            spans.push(Span::styled(
                format!(" {} ", r.label()),
                Style::default().fg(t.text_secondary),
            ));
        }
        spans.push(Span::raw(" "));
    }

    // Right-aligned session info
    let elapsed = app.session_started_at.elapsed().as_secs();
    let dur = format_duration(elapsed);
    let stamp = chrono::Local::now().format("%H:%M:%S").to_string();
    let session_label = format!("session start  duration {}    {}", dur, stamp);

    let used: usize = spans.iter().map(|s| s.content.chars().count()).sum();
    let total = area.width as usize;
    let label_w = session_label.chars().count();
    if total > used + label_w + 2 {
        spans.push(Span::raw(" ".repeat(total - used - label_w - 1)));
        spans.push(Span::styled(
            session_label,
            Style::default().fg(t.text_muted),
        ));
    }

    f.render_widget(
        Paragraph::new(vec![Line::from(spans), Line::from("")]),
        area,
    );
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

// ── KPI tiles row ───────────────────────────────────────────

fn render_kpi_tiles(f: &mut Frame, app: &App, stats: &AggregateStats, area: Rect) {
    let t = &app.theme;
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Ratio(1, 5),
            Constraint::Ratio(1, 5),
            Constraint::Ratio(1, 5),
            Constraint::Ratio(1, 5),
            Constraint::Ratio(1, 5),
        ])
        .split(area);

    let elapsed = app.session_started_at.elapsed().as_secs().max(1);

    let pkts_per_sec = stats.total_packets / elapsed;
    let avg_label = format!("{}/s avg", format_count(pkts_per_sec));
    render_kpi_tile(
        f,
        app,
        cols[0],
        "PACKETS",
        format_count(stats.total_packets),
        &avg_label,
        t.text_primary,
    );

    let bytes_label = format!(
        "rx {}  tx {}",
        format_bytes_short(stats.rx_bytes),
        format_bytes_short(stats.tx_bytes),
    );
    render_kpi_tile(
        f,
        app,
        cols[1],
        "BYTES",
        format_bytes_short(stats.total_bytes),
        &bytes_label,
        t.rx_rate,
    );

    render_kpi_tile(
        f,
        app,
        cols[2],
        "CONNS",
        stats.connection_count.to_string(),
        "active",
        t.status_info,
    );

    let dns_label = if stats.dns_errors > 0 {
        format!("{} errors", stats.dns_errors)
    } else {
        "0 errors".to_string()
    };
    let dns_color = if stats.dns_errors > 0 {
        t.status_warn
    } else {
        t.text_primary
    };
    render_kpi_tile(
        f,
        app,
        cols[3],
        "DNS",
        format_count(stats.dns_queries),
        &dns_label,
        dns_color,
    );

    let retrans_pct = if stats.total_packets > 0 {
        stats.retrans_count as f64 / stats.total_packets as f64 * 100.0
    } else {
        0.0
    };
    let retrans_val = if retrans_pct > 0.0 {
        format!("{:.1}%", retrans_pct)
    } else {
        "0".to_string()
    };
    let retrans_label = format!(
        "{} of {}",
        stats.retrans_count,
        format_count(stats.total_packets)
    );
    render_kpi_tile(
        f,
        app,
        cols[4],
        "RETRANS",
        retrans_val,
        &retrans_label,
        t.text_primary,
    );
}

fn render_kpi_tile(
    f: &mut Frame,
    app: &App,
    area: Rect,
    label: &str,
    value: String,
    sub: &str,
    val_color: Color,
) {
    let t = &app.theme;
    let block = Block::default()
        .title(Line::from(Span::styled(
            format!(" {} ", label),
            Style::default().fg(t.text_muted),
        )))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.border));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 1 {
        return;
    }

    let val_area = Rect {
        x: inner.x + 1,
        y: inner.y,
        width: inner.width.saturating_sub(2),
        height: 1,
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            value,
            Style::default().fg(val_color).bold(),
        ))),
        val_area,
    );

    if inner.height >= 2 {
        let sub_area = Rect {
            x: inner.x + 1,
            y: inner.y + 1,
            width: inner.width.saturating_sub(2),
            height: 1,
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                sub.to_string(),
                Style::default().fg(t.text_muted),
            ))),
            sub_area,
        );
    }
}

// ── Breakdowns row ──────────────────────────────────────────

fn render_breakdowns(
    f: &mut Frame,
    app: &App,
    packets: &[CapturedPacket],
    _stats: &AggregateStats,
    area: Rect,
) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
        ])
        .split(area);

    render_protocol_breakdown(f, app, packets, cols[0]);
    render_processes_breakdown(f, app, cols[1]);
    render_remotes_breakdown(f, app, packets, cols[2]);
}

struct BreakdownItem {
    label: String,
    value: f64,
    unit: &'static str,
    color: Color,
}

fn render_breakdown_panel(
    f: &mut Frame,
    app: &App,
    area: Rect,
    title: &str,
    items: Vec<BreakdownItem>,
) {
    let t = &app.theme;
    let block = Block::default()
        .title(Line::from(Span::styled(
            format!(" {} ", title),
            Style::default().fg(t.brand).bold(),
        )))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.border));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 1 || items.is_empty() {
        if items.is_empty() {
            let empty_area = Rect {
                x: inner.x + 1,
                y: inner.y,
                width: inner.width.saturating_sub(2),
                height: 1,
            };
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "no data yet",
                    Style::default().fg(t.text_muted),
                ))),
                empty_area,
            );
        }
        return;
    }

    let label_w = 14usize;
    let val_w = 7usize;
    let bar_w = inner.width.saturating_sub((label_w + val_w + 4) as u16) as usize;

    let max_val = items
        .iter()
        .map(|i| i.value)
        .fold(0.0f64, f64::max)
        .max(1.0);

    let max_rows = inner.height as usize;
    for (i, item) in items.iter().take(max_rows).enumerate() {
        let filled = ((item.value / max_val) * bar_w as f64).round() as usize;
        let bar: String = (0..bar_w)
            .map(|j| if j < filled { '█' } else { '░' })
            .collect();

        let line = Line::from(vec![
            Span::raw(" "),
            Span::styled(
                format!(
                    "{:<label$}",
                    truncate(&item.label, label_w),
                    label = label_w
                ),
                Style::default().fg(t.text_primary),
            ),
            Span::raw(" "),
            Span::styled(bar, Style::default().fg(item.color)),
            Span::raw(" "),
            Span::styled(
                format!("{:>5.1}", item.value),
                Style::default().fg(t.text_primary),
            ),
            Span::styled(format!(" {}", item.unit), Style::default().fg(t.text_muted)),
        ]);
        let row_area = Rect {
            x: inner.x,
            y: inner.y + i as u16,
            width: inner.width,
            height: 1,
        };
        f.render_widget(Paragraph::new(line), row_area);
    }
}

fn render_protocol_breakdown(f: &mut Frame, app: &App, packets: &[CapturedPacket], area: Rect) {
    let t = &app.theme;
    let mut totals: HashMap<&'static str, u64> = HashMap::new();
    for p in packets {
        let label = classify_protocol(&p.protocol);
        *totals.entry(label).or_insert(0) += p.length as u64;
    }
    let total: u64 = totals.values().sum();
    if total == 0 {
        render_breakdown_panel(f, app, area, "PROTOCOL  by bytes", Vec::new());
        return;
    }
    let mut items: Vec<BreakdownItem> = totals
        .into_iter()
        .map(|(label, bytes)| BreakdownItem {
            label: label.to_string(),
            value: bytes as f64 / total as f64 * 100.0,
            unit: "%",
            color: protocol_palette(label, t),
        })
        .collect();
    items.sort_by(|a, b| {
        b.value
            .partial_cmp(&a.value)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    items.truncate(6);
    render_breakdown_panel(f, app, area, "PROTOCOL  by bytes", items);
}

fn classify_protocol(p: &str) -> &'static str {
    match p {
        "TCP" => "TCP",
        "UDP" => "UDP",
        "DNS" => "DNS",
        "ICMP" | "ICMPv6" => "ICMP",
        "ARP" => "ARP",
        _ => "other",
    }
}

fn protocol_palette(label: &str, t: &crate::theme::Theme) -> Color {
    match label {
        "TCP" => t.status_info,
        "UDP" => Color::Rgb(217, 122, 255),
        "DNS" => t.status_good,
        "ICMP" => t.status_warn,
        "ARP" => t.brand,
        _ => t.text_muted,
    }
}

fn render_processes_breakdown(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let ranked = app.process_bandwidth.ranked();
    let total: u64 = ranked.iter().map(|p| p.rx_bytes + p.tx_bytes).sum();
    if total == 0 {
        render_breakdown_panel(f, app, area, "TOP PROCESSES  by RX", Vec::new());
        return;
    }

    let palette = process_palette(t);
    let mut items: Vec<BreakdownItem> = ranked
        .iter()
        .take(5)
        .enumerate()
        .map(|(i, p)| BreakdownItem {
            label: p.process_name.clone(),
            value: bytes_to_unit_value(p.rx_bytes),
            unit: bytes_to_unit_str(p.rx_bytes),
            color: palette[i % palette.len()],
        })
        .collect();

    let other_bytes: u64 = ranked.iter().skip(5).map(|p| p.rx_bytes).sum();
    if other_bytes > 0 {
        items.push(BreakdownItem {
            label: format!("others ({})", ranked.len().saturating_sub(5)),
            value: bytes_to_unit_value(other_bytes),
            unit: bytes_to_unit_str(other_bytes),
            color: t.text_muted,
        });
    }

    render_breakdown_panel(f, app, area, "TOP PROCESSES  by RX", items);
}

fn render_remotes_breakdown(f: &mut Frame, app: &App, packets: &[CapturedPacket], area: Rect) {
    let t = &app.theme;

    // Aggregate bytes by counterparty IP (whichever isn't the local interface IP)
    let local_ips = local_ip_set(app);
    let mut totals: HashMap<String, u64> = HashMap::new();
    for p in packets {
        let remote = if local_ips.contains(&p.dst_ip) {
            &p.src_ip
        } else {
            &p.dst_ip
        };
        if remote.is_empty() {
            continue;
        }
        *totals.entry(remote.clone()).or_insert(0) += p.length as u64;
    }
    if totals.is_empty() {
        render_breakdown_panel(f, app, area, "TOP REMOTES  by RX", Vec::new());
        return;
    }

    let mut sorted: Vec<(String, u64)> = totals.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));

    let palette = remote_palette(t);
    let mut items: Vec<BreakdownItem> = sorted
        .iter()
        .take(5)
        .enumerate()
        .map(|(i, (label, bytes))| {
            let display = app
                .packet_collector
                .dns_cache
                .lookup(label)
                .unwrap_or_else(|| label.clone());
            BreakdownItem {
                label: display,
                value: bytes_to_unit_value(*bytes),
                unit: bytes_to_unit_str(*bytes),
                color: palette[i % palette.len()],
            }
        })
        .collect();

    let other_bytes: u64 = sorted.iter().skip(5).map(|x| x.1).sum();
    if other_bytes > 0 {
        items.push(BreakdownItem {
            label: format!("others ({})", sorted.len().saturating_sub(5)),
            value: bytes_to_unit_value(other_bytes),
            unit: bytes_to_unit_str(other_bytes),
            color: t.text_muted,
        });
    }

    render_breakdown_panel(f, app, area, "TOP REMOTES  by RX", items);
}

fn local_ip_set(app: &App) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    for info in &app.interface_info {
        if let Some(ref ipv4) = info.ipv4 {
            set.insert(ipv4.clone());
        }
        if let Some(ref ipv6) = info.ipv6 {
            set.insert(ipv6.clone());
        }
    }
    set.insert("127.0.0.1".to_string());
    set
}

fn process_palette(t: &crate::theme::Theme) -> Vec<Color> {
    vec![
        t.status_good,
        t.rx_rate,
        t.status_info,
        t.brand,
        t.text_muted,
    ]
}

fn remote_palette(t: &crate::theme::Theme) -> Vec<Color> {
    vec![
        t.status_good,
        t.rx_rate,
        t.status_info,
        t.brand,
        Color::Rgb(217, 122, 255),
    ]
}

fn bytes_to_unit_value(bytes: u64) -> f64 {
    if bytes >= 1_000_000_000 {
        bytes as f64 / 1_000_000_000.0
    } else if bytes >= 1_000_000 {
        bytes as f64 / 1_000_000.0
    } else if bytes >= 1_000 {
        bytes as f64 / 1_000.0
    } else {
        bytes as f64
    }
}

fn bytes_to_unit_str(bytes: u64) -> &'static str {
    if bytes >= 1_000_000_000 {
        "GB"
    } else if bytes >= 1_000_000 {
        "MB"
    } else if bytes >= 1_000 {
        "KB"
    } else {
        "B"
    }
}

fn format_bytes_short(bytes: u64) -> String {
    let (val, unit) = if bytes >= 1_000_000_000 {
        (bytes as f64 / 1_000_000_000.0, "GB")
    } else if bytes >= 1_000_000 {
        (bytes as f64 / 1_000_000.0, "MB")
    } else if bytes >= 1_000 {
        (bytes as f64 / 1_000.0, "KB")
    } else {
        (bytes as f64, "B")
    };
    if val >= 100.0 {
        format!("{:.0} {}", val, unit)
    } else {
        format!("{:.1} {}", val, unit)
    }
}

fn format_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

// ── Throughput chart ────────────────────────────────────────

fn render_throughput_chart(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;

    let interfaces = app.traffic.interfaces();
    let actives: Vec<_> = interfaces
        .iter()
        .filter(|i| i.name != "lo0" && i.name != "lo")
        .collect();

    let agg_rx = aggregate_history(actives.iter().map(|i| &i.rx_history));
    let agg_tx = aggregate_history(actives.iter().map(|i| &i.tx_history));

    let peak_rx = *agg_rx.iter().max().unwrap_or(&0);
    let peak_tx = *agg_tx.iter().max().unwrap_or(&0);
    let avg_rx = if !agg_rx.is_empty() {
        agg_rx.iter().sum::<u64>() / agg_rx.len() as u64
    } else {
        0
    };

    let block = Block::default()
        .title(Line::from(Span::styled(
            " THROUGHPUT  session ",
            Style::default().fg(t.brand).bold(),
        )))
        .title(
            Line::from(Span::styled(
                format!(
                    " {}  RX/TX ",
                    format_duration(app.session_started_at.elapsed().as_secs())
                ),
                Style::default().fg(t.text_muted),
            ))
            .alignment(Alignment::Right),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.border));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 4 {
        return;
    }

    // Header summary line
    let header_line = Line::from(vec![
        Span::styled(
            format!("● RX peak {}", widgets::format_bytes_rate(peak_rx as f64)),
            Style::default().fg(t.rx_rate),
        ),
        Span::styled("    ", Style::default()),
        Span::styled(
            format!("● TX peak {}", widgets::format_bytes_rate(peak_tx as f64)),
            Style::default().fg(t.tx_rate),
        ),
        Span::styled("    ", Style::default()),
        Span::styled(
            format!("avg {}", widgets::format_bytes_rate(avg_rx as f64)),
            Style::default().fg(t.text_muted),
        ),
    ]);
    let header_area = Rect {
        x: inner.x + 1,
        y: inner.y,
        width: inner.width.saturating_sub(2),
        height: 1,
    };
    f.render_widget(Paragraph::new(header_line), header_area);

    // Stacked sparklines
    let chart_h = inner.height.saturating_sub(2);
    if chart_h < 2 {
        return;
    }
    let rx_h = chart_h / 2;
    let tx_h = chart_h - rx_h;
    let chart_w = inner.width.saturating_sub(2);

    let rx_area = Rect {
        x: inner.x + 1,
        y: inner.y + 1,
        width: chart_w,
        height: rx_h,
    };
    let tx_area = Rect {
        x: inner.x + 1,
        y: inner.y + 1 + rx_h,
        width: chart_w,
        height: tx_h,
    };

    let rx_padded = pad_history(&agg_rx, chart_w as usize);
    let tx_padded = pad_history(&agg_tx, chart_w as usize);
    f.render_widget(
        Sparkline::default()
            .data(&rx_padded)
            .style(Style::default().fg(t.rx_rate)),
        rx_area,
    );
    f.render_widget(
        Sparkline::default()
            .data(&tx_padded)
            .style(Style::default().fg(t.tx_rate)),
        tx_area,
    );

    // X-axis labels (last row of inner)
    let axis_y = inner.y + inner.height.saturating_sub(1);
    let axis_area = Rect {
        x: inner.x + 1,
        y: axis_y,
        width: chart_w,
        height: 1,
    };
    let axis_w = chart_w as usize;
    let mut axis = String::from("-60s");
    let mid_pad = axis_w.saturating_sub(11) / 2;
    axis.push_str(&" ".repeat(mid_pad));
    axis.push_str("-30s");
    let used = axis.chars().count();
    let end_pad = axis_w.saturating_sub(used + 3);
    axis.push_str(&" ".repeat(end_pad));
    axis.push_str("now");
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            axis,
            Style::default().fg(t.text_muted),
        ))),
        axis_area,
    );
}

fn aggregate_history<'a, I>(iter: I) -> Vec<u64>
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

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let hints = vec![
        Span::styled("t", Style::default().fg(t.key_hint).bold()),
        Span::raw(":Range  "),
        Span::styled("a", Style::default().fg(t.key_hint).bold()),
        Span::raw(":Analyze"),
    ];
    widgets::render_footer(f, app, area, hints);
}
