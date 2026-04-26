use std::time::{Duration, Instant};

use crate::app::{App, IfaceChangeKind, TimelineFilter};
use crate::collectors::network_intel::{Alert, AlertSeverity};
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Sparkline},
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Length(2), // filter chips
            Constraint::Length(5), // activity strip
            Constraint::Min(8),    // events log
            Constraint::Length(3), // footer
        ])
        .split(area);

    let events = build_events(app);

    widgets::render_header(f, app, chunks[0]);
    render_chip_row(f, app, &events, chunks[1]);
    render_activity_strip(f, app, &events, chunks[2]);
    render_events(f, app, &events, chunks[3]);
    render_footer(f, app, chunks[4]);
}

// ── Event model ─────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Crit,
    Warn,
    Info,
    Ok,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Crit => "CRIT",
            Kind::Warn => "WARN",
            Kind::Info => "INFO",
            Kind::Ok => "OK",
        }
    }
    fn color(self, t: &crate::theme::Theme) -> Color {
        match self {
            Kind::Crit => t.status_error,
            Kind::Warn => t.status_warn,
            Kind::Info => t.status_info,
            Kind::Ok => t.status_good,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum Category {
    Conn,
    Dns,
    Rtt,
    Iface,
    Proc,
    Reset,
    Alert,
}

impl Category {
    fn label(self) -> &'static str {
        match self {
            Category::Conn => "CONN",
            Category::Dns => "DNS",
            Category::Rtt => "RTT",
            Category::Iface => "IFACE",
            Category::Proc => "PROC",
            Category::Reset => "RESET",
            Category::Alert => "ALERT",
        }
    }
}

struct Event {
    when: Instant,
    kind: Kind,
    category: Category,
    summary: String,
    detail: String,
}

fn build_events(app: &App) -> Vec<Event> {
    let mut events: Vec<Event> = Vec::new();

    // Network-intel alerts
    for alert in app.network_intel.active_alerts() {
        events.push(alert_to_event(&alert));
    }

    // Connection lifecycle from ConnectionTimeline.tracked
    for tracked in &app.connection_timeline.tracked {
        let host = remote_host(&tracked.key.remote_addr);
        let proc = tracked.process_name.clone().unwrap_or_else(|| "—".into());
        let summary = format!(
            "{} → {} {}",
            proc,
            host,
            if tracked.is_active {
                "established"
            } else {
                "closed"
            }
        );
        let detail = format!(
            "{}  age {}",
            tracked.key.protocol,
            duration_label(tracked.last_seen.duration_since(tracked.first_seen))
        );
        events.push(Event {
            when: tracked.last_seen,
            kind: if tracked.is_active {
                Kind::Ok
            } else {
                Kind::Info
            },
            category: Category::Conn,
            summary,
            detail,
        });
    }

    // RTT spike events — scan health probe history for samples that exceed
    // 2× the rolling baseline AND 50ms absolute. We can't precisely time them
    // (history is just a deque of values without timestamps), so we attribute
    // each spike to "now - i seconds" using the deque index.
    {
        let hs = app.health_prober.status.lock().unwrap();
        for (label, history) in [
            ("gateway", hs.gateway_rtt_history.as_slices().0),
            ("DNS", hs.dns_rtt_history.as_slices().0),
        ] {
            let valid: Vec<f64> = history.iter().filter_map(|x| *x).collect();
            if valid.len() < 5 {
                continue;
            }
            let baseline = valid.iter().sum::<f64>() / valid.len() as f64;
            let now = Instant::now();
            for (i, sample) in history.iter().enumerate().rev().take(20) {
                let Some(rtt) = sample else { continue };
                if *rtt > 50.0 && *rtt > baseline * 2.0 {
                    let secs_ago = (history.len() - 1 - i) as u64;
                    events.push(Event {
                        when: now - Duration::from_secs(secs_ago),
                        kind: Kind::Warn,
                        category: Category::Rtt,
                        summary: format!(
                            "{} RTT spike {:.0}ms (baseline {:.1}ms)",
                            label, rtt, baseline
                        ),
                        detail: format!("{:.1}× normal", rtt / baseline),
                    });
                    break; // one spike event per probe target per render
                }
            }
        }
    }

    // Interface up/down/IP-changed events captured by app.iface_events
    for iface_ev in app.iface_events.iter() {
        let (kind_label, kind) = match iface_ev.kind {
            IfaceChangeKind::Up => ("up", Kind::Ok),
            IfaceChangeKind::Down => ("down", Kind::Warn),
            IfaceChangeKind::IpChanged => ("ip-changed", Kind::Info),
            IfaceChangeKind::Added => ("added", Kind::Info),
            IfaceChangeKind::Removed => ("removed", Kind::Info),
        };
        events.push(Event {
            when: iface_ev.when,
            kind,
            category: Category::Iface,
            summary: format!("{} {}", iface_ev.name, kind_label),
            detail: iface_ev.detail.clone(),
        });
    }

    // DNS errors from packets (last ~200)
    let packets = app.packet_collector.get_packets();
    for pkt in packets.iter().rev().take(200) {
        if pkt.protocol != "DNS" {
            continue;
        }
        let info_lc = pkt.info.to_lowercase();
        let (kind, label) = if info_lc.contains("nxdomain") {
            (Kind::Warn, "NXDOMAIN")
        } else if info_lc.contains("server failure") || info_lc.contains("servfail") {
            (Kind::Warn, "SERVFAIL")
        } else if info_lc.contains("refused") {
            (Kind::Warn, "REFUSED")
        } else {
            continue;
        };
        // CapturedPacket only carries timestamp_ns relative to capture start;
        // we don't have a wall-clock Instant. Treat all DNS errors as "now".
        events.push(Event {
            when: Instant::now(),
            kind,
            category: Category::Dns,
            summary: format!("{}  {}", label, truncate(&pkt.info, 60)),
            detail: format!("from {}:{}", pkt.src_ip, pkt.src_port.unwrap_or(0)),
        });
    }

    events.sort_by(|a, b| b.when.cmp(&a.when));
    events
}

fn alert_to_event(alert: &Alert) -> Event {
    let kind = match alert.severity {
        AlertSeverity::Critical => Kind::Crit,
        AlertSeverity::Warning => Kind::Warn,
    };
    Event {
        when: alert.timestamp,
        kind,
        category: Category::Alert,
        summary: format!("{}  {}", alert.category.label(), alert.message),
        detail: alert.detail.clone(),
    }
}

fn filter_matches(filter: TimelineFilter, ev: &Event) -> bool {
    match filter {
        TimelineFilter::All => true,
        TimelineFilter::Crit => ev.kind == Kind::Crit,
        TimelineFilter::Warn => ev.kind == Kind::Warn,
        TimelineFilter::Conn => ev.category == Category::Conn,
        TimelineFilter::Dns => ev.category == Category::Dns,
        TimelineFilter::Rtt => ev.category == Category::Rtt,
        TimelineFilter::Iface => ev.category == Category::Iface,
    }
}

// ── Filter chip row ─────────────────────────────────────────

fn render_chip_row(f: &mut Frame, app: &App, events: &[Event], area: Rect) {
    let t = &app.theme;

    let count_for = |filter: TimelineFilter| -> usize {
        events.iter().filter(|e| filter_matches(filter, e)).count()
    };

    let chips: [TimelineFilter; 7] = [
        TimelineFilter::All,
        TimelineFilter::Crit,
        TimelineFilter::Warn,
        TimelineFilter::Conn,
        TimelineFilter::Dns,
        TimelineFilter::Rtt,
        TimelineFilter::Iface,
    ];

    let mut spans: Vec<Span> = vec![Span::styled(" filter  ", Style::default().fg(t.text_muted))];
    for f in chips.iter() {
        let label = format!("{} {}", f.label(), count_for(*f));
        let active = *f == app.timeline_filter;
        if active {
            spans.push(Span::styled(
                format!(" {} ", label),
                Style::default()
                    .fg(t.text_primary)
                    .bg(t.selection_bg)
                    .bold(),
            ));
        } else {
            spans.push(Span::styled(
                format!(" {} ", label),
                Style::default().fg(t.text_secondary),
            ));
        }
        spans.push(Span::raw(" "));
    }

    let session = format!(
        "session  duration {}    f cycles",
        format_session_duration(app.session_started_at.elapsed()),
    );
    let used: usize = spans.iter().map(|s| s.content.chars().count()).sum();
    let total = area.width as usize;
    let session_w = session.chars().count();
    if total > used + session_w + 2 {
        spans.push(Span::raw(" ".repeat(total - used - session_w - 1)));
        spans.push(Span::styled(session, Style::default().fg(t.text_muted)));
    }

    f.render_widget(
        Paragraph::new(vec![Line::from(spans), Line::from("")]),
        area,
    );
}

fn format_session_duration(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{}s", s)
    } else if s < 3600 {
        format!("{}m", s / 60)
    } else {
        format!("{}h{}m", s / 3600, (s % 3600) / 60)
    }
}

// ── Activity strip ──────────────────────────────────────────

fn render_activity_strip(f: &mut Frame, app: &App, events: &[Event], area: Rect) {
    let t = &app.theme;
    let block = Block::default()
        .title(Line::from(Span::styled(
            " ACTIVITY  session ",
            Style::default().fg(t.brand).bold(),
        )))
        .title(
            Line::from(Span::styled(
                " density per second  cyan = now ",
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

    // Aggregate interface RX history as activity proxy (last 60s)
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

    // Mark seconds where Crit/Warn events happened so we tint those bars
    let now = Instant::now();
    let mut event_severity: Vec<Option<Kind>> = vec![None; acc.len()];
    for ev in events {
        let secs_ago = now.duration_since(ev.when).as_secs() as usize;
        if secs_ago >= acc.len() {
            continue;
        }
        let idx = acc.len().saturating_sub(secs_ago + 1);
        if let Some(slot) = event_severity.get_mut(idx) {
            let cur = *slot;
            let new = ev.kind;
            *slot = match (cur, new) {
                (Some(Kind::Crit), _) | (_, Kind::Crit) => Some(Kind::Crit),
                (Some(Kind::Warn), _) | (_, Kind::Warn) => Some(Kind::Warn),
                (cur, _) => cur.or(Some(new)),
            };
        }
    }

    let chart_w = inner.width as usize;
    let padded = pad_history(&acc, chart_w);
    let pad = chart_w.saturating_sub(acc.len());

    // Three-color overlay: green / yellow / red layers, only the cells
    // matching that severity tier carry data on each layer.
    let mut green_data = vec![0u64; chart_w];
    let mut yellow_data = vec![0u64; chart_w];
    let mut red_data = vec![0u64; chart_w];

    for i in 0..chart_w {
        let v = padded[i];
        if v == 0 {
            continue;
        }
        let raw_idx = if i < pad { None } else { Some(i - pad) };
        let sev = raw_idx.and_then(|idx| event_severity.get(idx).copied().flatten());
        match sev {
            Some(Kind::Crit) => red_data[i] = v,
            Some(Kind::Warn) => yellow_data[i] = v,
            _ => green_data[i] = v,
        }
    }

    f.render_widget(
        Sparkline::default()
            .data(&green_data)
            .style(Style::default().fg(t.status_good)),
        inner,
    );
    f.render_widget(
        Sparkline::default()
            .data(&yellow_data)
            .style(Style::default().fg(t.status_warn)),
        inner,
    );
    f.render_widget(
        Sparkline::default()
            .data(&red_data)
            .style(Style::default().fg(t.status_error)),
        inner,
    );

    // Cyan cursor at the right edge ("now")
    let cursor_x = inner.x + inner.width.saturating_sub(1);
    for y in inner.y..inner.y + inner.height {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled("│", Style::default().fg(t.brand)))),
            Rect::new(cursor_x, y, 1, 1),
        );
    }
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

// ── Event log ───────────────────────────────────────────────

fn render_events(f: &mut Frame, app: &App, events: &[Event], area: Rect) {
    let t = &app.theme;

    let filtered: Vec<&Event> = events
        .iter()
        .filter(|e| filter_matches(app.timeline_filter, e))
        .collect();

    let title_right = format!(" {} events  newest first ", filtered.len());
    let block = Block::default()
        .title(Line::from(Span::styled(
            " EVENTS ",
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

    if inner.height < 2 {
        return;
    }

    let header = "  AGE        KIND   CAT    EVENT";
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            header,
            Style::default().fg(t.text_muted),
        ))),
        Rect::new(inner.x + 1, inner.y, inner.width.saturating_sub(2), 1),
    );

    if filtered.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "No events yet — alerts and connection openings appear here as they happen.",
                Style::default().fg(t.text_muted),
            ))),
            Rect::new(inner.x + 2, inner.y + 1, inner.width.saturating_sub(2), 1),
        );
        return;
    }

    let max_rows = inner.height.saturating_sub(1) as usize;
    let scroll = app
        .scroll
        .timeline_scroll
        .min(filtered.len().saturating_sub(1));
    let now = Instant::now();
    for (i, ev) in filtered.iter().skip(scroll).take(max_rows).enumerate() {
        let row_y = inner.y + 1 + i as u16;
        let is_selected = i + scroll == app.scroll.timeline_scroll;
        let age = format_age(now.duration_since(ev.when));
        let line = Line::from(vec![
            Span::styled(
                if is_selected { "▸ " } else { "  " },
                Style::default().fg(t.brand).bold(),
            ),
            Span::styled(format!("{:<10}", age), Style::default().fg(t.text_muted)),
            Span::raw(" "),
            Span::styled(
                format!("{:<5}", ev.kind.label()),
                Style::default().fg(ev.kind.color(t)).bold(),
            ),
            Span::raw(" "),
            Span::styled(
                format!("{:<6}", ev.category.label()),
                Style::default().fg(t.text_muted),
            ),
            Span::raw(" "),
            Span::styled(
                truncate(&ev.summary, 50),
                Style::default().fg(t.text_primary),
            ),
            Span::raw("  "),
            Span::styled(truncate(&ev.detail, 50), Style::default().fg(t.text_muted)),
        ]);
        let row_area = Rect {
            x: inner.x + 1,
            y: row_y,
            width: inner.width.saturating_sub(2),
            height: 1,
        };
        let para = if is_selected {
            Paragraph::new(line).style(Style::default().bg(t.selection_bg))
        } else {
            Paragraph::new(line)
        };
        f.render_widget(para, row_area);
    }
}

fn format_age(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{}s ago", s)
    } else if s < 3600 {
        format!("{}m ago", s / 60)
    } else if s < 86_400 {
        format!("{}h ago", s / 3600)
    } else {
        format!("{}d ago", s / 86_400)
    }
}

fn duration_label(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{}s", s)
    } else if s < 3600 {
        format!("{}m{}s", s / 60, s % 60)
    } else {
        format!("{}h{}m", s / 3600, (s % 3600) / 60)
    }
}

// ── helpers ─────────────────────────────────────────────────

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let hints = vec![
        Span::styled("f", Style::default().fg(t.key_hint).bold()),
        Span::raw(":Filter  "),
        Span::styled("Enter", Style::default().fg(t.key_hint).bold()),
        Span::raw(":→Connections"),
    ];
    widgets::render_footer(f, app, area, hints);
}

fn remote_host(addr: &str) -> String {
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
