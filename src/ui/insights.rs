use std::time::Duration;

use crate::app::App;
use crate::collectors::insights::InsightsStatus;
use crate::collectors::network_intel::AlertSeverity;
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph},
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Length(2), // summary line
            Constraint::Min(8),    // cards
            Constraint::Length(1), // read-only disclaimer
            Constraint::Length(3), // footer
        ])
        .split(area);

    let cards = build_cards(app);

    widgets::render_header(f, app, chunks[0]);
    render_summary(f, app, &cards, chunks[1]);
    render_cards(f, app, &cards, chunks[2]);
    render_disclaimer(f, app, chunks[3]);
    render_footer(f, app, chunks[4]);
}

// ── Card model ──────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Severity {
    Crit,
    Warn,
    Info,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Severity::Crit => "CRIT",
            Severity::Warn => "WARN",
            Severity::Info => "INFO",
        }
    }
    fn fg(self, t: &crate::theme::Theme) -> Color {
        match self {
            Severity::Crit => t.status_error,
            Severity::Warn => t.status_warn,
            Severity::Info => t.status_info,
        }
    }
}

struct Card {
    severity: Severity,
    title: String,
    body: Vec<String>,
    age: Duration,
    actions: Vec<&'static str>,
}

fn build_cards(app: &App) -> Vec<Card> {
    let mut cards: Vec<Card> = Vec::new();

    // Pass through network-intel alerts as cards
    for alert in app.network_intel.active_alerts() {
        let severity = match alert.severity {
            AlertSeverity::Critical => Severity::Crit,
            AlertSeverity::Warning => Severity::Warn,
        };
        cards.push(Card {
            severity,
            title: format!("{} — {}", alert.category.label(), alert.message),
            body: vec![alert.detail.clone()],
            age: alert.timestamp.elapsed(),
            actions: vec!["view 60s window", "silence for 1h", "ignore"],
        });
    }

    // Detector: gateway loss
    {
        let hs = app.health_prober.status.lock().unwrap();
        let loss = hs.gateway_loss_pct;
        let rtt = hs.gateway_rtt_ms;
        if loss >= 50.0 {
            cards.push(Card {
                severity: Severity::Crit,
                title: format!("gateway packet loss spiked to {:.0}%", loss),
                body: vec![
                    format!(
                        "GW {} most-recent RTT {}",
                        app.config_collector
                            .config
                            .gateway
                            .as_deref()
                            .unwrap_or("—"),
                        rtt.map(|r| format!("{:.1}ms", r)).unwrap_or("—".into())
                    ),
                    "Check Wi-Fi signal, AP roam events, or cabling.".to_string(),
                ],
                age: Duration::ZERO,
                actions: vec!["view 60s window", "silence for 1h", "ignore"],
            });
        } else if loss >= 5.0 {
            cards.push(Card {
                severity: Severity::Warn,
                title: format!("gateway loss elevated ({:.0}%)", loss),
                body: vec![format!(
                    "Sustained loss above 5% on the LAN; latency-sensitive flows may stutter."
                )],
                age: Duration::ZERO,
                actions: vec!["view 60s window", "silence for 1h", "ignore"],
            });
        }
    }

    // Detector: bandwidth dominator
    let ranked = app.process_bandwidth.ranked();
    let total_bw: u64 = ranked.iter().map(|p| p.rx_bytes + p.tx_bytes).sum();
    if total_bw > 10_000_000 {
        if let Some(top) = ranked.first() {
            let share = (top.rx_bytes + top.tx_bytes) as f64 / total_bw as f64 * 100.0;
            if share >= 75.0 {
                cards.push(Card {
                    severity: Severity::Warn,
                    title: format!(
                        "{} is dominating bandwidth ({:.0}% of session)",
                        top.process_name, share
                    ),
                    body: vec![
                        format!(
                            "{} RX  {} sockets",
                            crate::ui::widgets::format_bytes_total(top.rx_bytes),
                            top.connection_count
                        ),
                        "Pin to Connections (8→Enter) to inspect remotes.".to_string(),
                    ],
                    age: Duration::ZERO,
                    actions: vec!["show process", "silence for 1h", "ignore"],
                });
            }
        }
    }

    // Detector: TIME_WAIT pile-up per process
    {
        let conns = app.connection_collector.connections.lock().unwrap();
        let mut pile_per_proc: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
        for c in conns.iter() {
            if c.state == "TIME_WAIT" || c.state == "TIME-WAIT" {
                let name = c.process_name.clone().unwrap_or_else(|| "—".into());
                *pile_per_proc.entry(name).or_insert(0) += 1;
            }
        }
        let mut piles: Vec<(String, u32)> = pile_per_proc
            .into_iter()
            .filter(|(_, n)| *n >= 10)
            .collect();
        piles.sort_by(|a, b| b.1.cmp(&a.1));
        for (proc, n) in piles.into_iter().take(2) {
            cards.push(Card {
                severity: Severity::Warn,
                title: format!("{} has {} sockets in TIME_WAIT", proc, n),
                body: vec![
                    "Normal for short-lived HTTPS, but could indicate reconnect churn.".to_string(),
                ],
                age: Duration::ZERO,
                actions: vec!["inspect", "view runbook"],
            });
        }
    }

    // Detector: DNS error rate from packets
    {
        let packets = app.packet_collector.get_packets();
        let dns_total = packets.iter().filter(|p| p.protocol == "DNS").count();
        let dns_errors = packets
            .iter()
            .filter(|p| {
                p.protocol == "DNS" && {
                    let info_lc = p.info.to_lowercase();
                    info_lc.contains("nxdomain")
                        || info_lc.contains("servfail")
                        || info_lc.contains("server failure")
                        || info_lc.contains("refused")
                }
            })
            .count();
        if dns_total >= 20 && dns_errors * 100 / dns_total.max(1) >= 10 {
            let pct = dns_errors * 100 / dns_total.max(1);
            cards.push(Card {
                severity: Severity::Warn,
                title: format!("DNS error rate {}% over last {} queries", pct, dns_total),
                body: vec![format!(
                    "{} of {} responses returned NXDOMAIN/SERVFAIL/Refused.",
                    dns_errors, dns_total
                )],
                age: Duration::ZERO,
                actions: vec!["view DNS errors", "silence for 1h", "ignore"],
            });
        }
    }

    // Pass-through: any LLM-generated insights that exist
    if let Some(collector) = app.insights_collector.as_ref() {
        for insight in collector.get_insights().iter().rev().take(2) {
            let mut lines = insight.text.lines();
            let title = lines
                .next()
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "AI analysis".to_string());
            let body: Vec<String> = lines
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_string())
                .take(2)
                .collect();
            cards.push(Card {
                severity: Severity::Info,
                title: format!("AI: {}", truncate(&title, 80)),
                body,
                age: Duration::ZERO,
                actions: vec!["dismiss"],
            });
        }
    }

    // Sort: crit > warn > info
    cards.sort_by(|a, b| {
        let sev_order = |s: Severity| match s {
            Severity::Crit => 0,
            Severity::Warn => 1,
            Severity::Info => 2,
        };
        sev_order(a.severity).cmp(&sev_order(b.severity))
    });

    cards
}

// ── Render: summary line ────────────────────────────────────

fn render_summary(f: &mut Frame, app: &App, cards: &[Card], area: Rect) {
    let t = &app.theme;
    let crit = cards
        .iter()
        .filter(|c| c.severity == Severity::Crit)
        .count();
    let warn = cards
        .iter()
        .filter(|c| c.severity == Severity::Warn)
        .count();
    let info = cards
        .iter()
        .filter(|c| c.severity == Severity::Info)
        .count();
    let active = crit + warn;

    let dot_color = if crit > 0 {
        t.status_error
    } else if warn > 0 {
        t.status_warn
    } else if active > 0 {
        t.status_info
    } else {
        t.status_good
    };

    let mut spans: Vec<Span> = vec![
        Span::raw(" "),
        Span::styled("● ", Style::default().fg(dot_color)),
        Span::styled(
            format!("{} active   ", active),
            Style::default().fg(dot_color).bold(),
        ),
        Span::styled(
            format!("{} critical, {} warning", crit, warn),
            Style::default().fg(t.text_muted),
        ),
        Span::styled("   │   ", Style::default().fg(t.separator)),
        Span::styled(
            format!("{} informational", info),
            Style::default().fg(t.text_muted),
        ),
    ];

    // Right side: refresh status from LLM collector
    if let Some(collector) = app.insights_collector.as_ref() {
        let status = collector.get_status();
        let status_color = match &status {
            InsightsStatus::Available | InsightsStatus::Analyzing => t.status_good,
            InsightsStatus::Error(_) | InsightsStatus::OllamaUnavailable => t.text_muted,
            _ => t.text_muted,
        };
        let status_text = match status {
            InsightsStatus::Idle => "AI: idle".to_string(),
            InsightsStatus::Analyzing => format!("AI: analyzing ({})", collector.model),
            InsightsStatus::Available => format!("AI: {} ready", collector.model),
            InsightsStatus::Error(e) => format!("AI error: {}", truncate(&e, 30)),
            InsightsStatus::OllamaUnavailable => "AI: ollama unavailable".to_string(),
        };
        let used: usize = spans.iter().map(|s| s.content.chars().count()).sum();
        let status_w = status_text.chars().count();
        let total = area.width as usize;
        if total > used + status_w + 2 {
            spans.push(Span::raw(" ".repeat(total - used - status_w - 1)));
            spans.push(Span::styled(status_text, Style::default().fg(status_color)));
        }
    }

    f.render_widget(
        Paragraph::new(vec![Line::from(spans), Line::from("")]),
        area,
    );
}

// ── Render: card stack ──────────────────────────────────────

fn render_cards(f: &mut Frame, app: &App, cards: &[Card], area: Rect) {
    let t = &app.theme;

    if cards.is_empty() {
        render_empty_state(f, app, area);
        return;
    }

    // Each card is 6 rows tall. Scroll if overflow.
    let card_h = 6u16;
    let visible = (area.height / card_h) as usize;
    let scroll = app
        .scroll
        .insights_scroll
        .min(cards.len().saturating_sub(visible.max(1)));

    for (i, card) in cards.iter().skip(scroll).take(visible).enumerate() {
        let y = area.y + (i as u16) * card_h;
        if y + card_h > area.y + area.height {
            break;
        }
        render_card(f, t, Rect::new(area.x, y, area.width, card_h), card);
    }
}

fn render_card(f: &mut Frame, t: &crate::theme::Theme, area: Rect, card: &Card) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.border));
    let inner = block.inner(area);
    f.render_widget(block, area);

    // Colored left edge
    for y in area.y + 1..area.y + area.height - 1 {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "│",
                Style::default().fg(card.severity.fg(t)).bold(),
            ))),
            Rect::new(area.x, y, 1, 1),
        );
    }

    if inner.height < 2 {
        return;
    }

    // Row 0: severity badge + title + age right
    let badge = format!(" {} ", card.severity.label());
    let title_line = Line::from(vec![
        Span::styled(
            badge,
            Style::default()
                .fg(card.severity.fg(t))
                .bg(card_bg(card.severity, t))
                .bold(),
        ),
        Span::raw("  "),
        Span::styled(
            card.title.clone(),
            Style::default().fg(t.text_primary).bold(),
        ),
    ]);
    f.render_widget(
        Paragraph::new(title_line),
        Rect::new(inner.x + 1, inner.y, inner.width.saturating_sub(2), 1),
    );

    // Right-aligned age
    let age_str = format_age(card.age);
    let age_w = age_str.chars().count() as u16;
    if inner.width > age_w + 2 {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                age_str,
                Style::default().fg(t.text_muted),
            ))),
            Rect::new(inner.x + inner.width - age_w - 1, inner.y, age_w, 1),
        );
    }

    // Body lines (rows 1..=3)
    for (i, body) in card.body.iter().take(3).enumerate() {
        let row_y = inner.y + 1 + i as u16;
        if row_y >= inner.y + inner.height - 1 {
            break;
        }
        let color = if i == 0 { t.text_primary } else { t.text_muted };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                truncate(body, inner.width.saturating_sub(2) as usize),
                Style::default().fg(color),
            ))),
            Rect::new(inner.x + 1, row_y, inner.width.saturating_sub(2), 1),
        );
    }

    // Action chips on last inner row
    let chip_y = inner.y + inner.height - 1;
    let mut spans: Vec<Span> = Vec::new();
    for (i, action) in card.actions.iter().enumerate() {
        let label = format!("[ {} ]", action);
        let style = if i == 0 {
            Style::default().fg(t.brand).bold()
        } else {
            Style::default().fg(t.text_muted)
        };
        spans.push(Span::styled(label, style));
        spans.push(Span::raw("  "));
    }
    f.render_widget(
        Paragraph::new(Line::from(spans)),
        Rect::new(inner.x + 1, chip_y, inner.width.saturating_sub(2), 1),
    );
}

fn card_bg(sev: Severity, t: &crate::theme::Theme) -> Color {
    let _ = t;
    match sev {
        Severity::Crit => Color::Rgb(0x3a, 0x1c, 0x1c),
        Severity::Warn => Color::Rgb(0x3a, 0x2c, 0x14),
        Severity::Info => Color::Rgb(0x15, 0x32, 0x3a),
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

// ── Empty state ─────────────────────────────────────────────

fn render_empty_state(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  No active insights — your network looks healthy.",
            Style::default().fg(t.status_good),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Insights will appear here when detectors find something noteworthy:",
            Style::default().fg(t.text_muted),
        )),
        Line::from(Span::styled(
            "    · gateway packet loss",
            Style::default().fg(t.text_muted),
        )),
        Line::from(Span::styled(
            "    · bandwidth-dominator processes",
            Style::default().fg(t.text_muted),
        )),
        Line::from(Span::styled(
            "    · TIME_WAIT pile-ups",
            Style::default().fg(t.text_muted),
        )),
        Line::from(Span::styled(
            "    · DNS resolver failures",
            Style::default().fg(t.text_muted),
        )),
        Line::from(Span::styled(
            "    · network-intel alerts (port scan, beaconing, DNS tunnel)",
            Style::default().fg(t.text_muted),
        )),
    ];

    if app.insights_collector.is_none() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  AI-generated insights are disabled in your config.",
            Style::default().fg(t.text_muted),
        )));
    } else {
        let status = app.insights_collector.as_ref().unwrap().get_status();
        if matches!(status, InsightsStatus::OllamaUnavailable) {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  AI: Ollama not running — `ollama serve` to enable AI cards.",
                Style::default().fg(t.text_muted),
            )));
        }
    }

    f.render_widget(Paragraph::new(lines), area);
}

// ── Disclaimer + footer ─────────────────────────────────────

fn render_disclaimer(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            " Insights are read-only suggestions — they never modify connections or processes.",
            Style::default().fg(t.text_muted),
        ))),
        area,
    );
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let hints = vec![
        Span::styled("a", Style::default().fg(t.key_hint).bold()),
        Span::raw(":Run AI  "),
        Span::styled(",", Style::default().fg(t.key_hint).bold()),
        Span::raw(":AI Settings"),
    ];
    widgets::render_footer(f, app, area, hints);
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}
