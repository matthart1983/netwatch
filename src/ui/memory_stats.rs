//! Debug overlay (`M` key) showing every bounded in-memory collection
//! with its current fill ratio. Lets the user verify in a real
//! long-running session that the caps actually hold.
//!
//! Not advertised in the footer hotkey strip — this is a diagnostic
//! tool, not a normal-user feature. Documented in the help dialog.

use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph},
};

use crate::app::App;

/// One row of the overlay: a bounded data structure and its current size.
struct Gauge {
    name: &'static str,
    current: usize,
    cap: usize,
    /// One-line explanation of what fills this structure.
    note: &'static str,
}

impl Gauge {
    fn fill_pct(&self) -> f32 {
        if self.cap == 0 {
            0.0
        } else {
            (self.current as f32 / self.cap as f32) * 100.0
        }
    }
}

fn gather(app: &App) -> Vec<Gauge> {
    use crate::collectors::network_intel::{MAX_TRACKED_BEACONS, MAX_TRACKED_IPS};
    use crate::collectors::packets::{MAX_STREAMS, STREAM_EVICT_BATCH};

    let mut out: Vec<Gauge> = Vec::new();

    // ── StreamTracker ──
    if let Ok(tracker) = app.packet_collector.stream_tracker.try_lock() {
        out.push(Gauge {
            name: "stream tracker — flows",
            current: tracker.all_streams.len(),
            cap: MAX_STREAMS + STREAM_EVICT_BATCH,
            note: "LRU evicted on oldest last_seen_ns",
        });
    }

    // ── App-level RTT bookkeeping ──
    out.push(Gauge {
        name: "rtt history — IP keys",
        current: app.rtt_history.len(),
        cap: 256, // MAX_RTT_HISTORY_IPS — private const in app module
        note: "FIFO eviction on first-insert order",
    });

    // ── Connection timeline ──
    out.push(Gauge {
        name: "connection timeline",
        current: app.connection_timeline.tracked_len(),
        cap: app.connection_timeline.tracked_cap(),
        note: "hard cap with O(n) index rebuild",
    });

    // ── Network intel ──
    out.push(Gauge {
        name: "network-intel — scan states",
        current: app.network_intel.scan_states_len(),
        cap: MAX_TRACKED_IPS,
        note: "LRU evicted on oldest last_seen",
    });
    out.push(Gauge {
        name: "network-intel — beacon states",
        current: app.network_intel.beacon_states_len(),
        cap: MAX_TRACKED_BEACONS,
        note: "LRU evicted on oldest last_seen",
    });
    out.push(Gauge {
        name: "network-intel — alert history",
        current: app.network_intel.alert_history_len(),
        cap: 100,
        note: "ring buffer; oldest dropped",
    });

    // ── Packet ring ──
    out.push(Gauge {
        name: "packet ring",
        current: app.packet_collector.packet_count_hint(),
        cap: 5000, // MAX_PACKETS in packets.rs
        note: "ring buffer; oldest dropped",
    });

    out
}

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let gauges = gather(app);
    let popup_w = (area.width as i32 - 8).max(70).min(area.width as i32 - 4) as u16;
    let popup_h = (gauges.len() as u16 + 6).min(area.height.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(popup_w)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_h)) / 2;
    let popup = Rect::new(x, y, popup_w, popup_h);

    f.render_widget(Clear, popup);
    let block = Block::default()
        .title(" Memory ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(app.theme.brand));
    let inner = block.inner(popup);
    f.render_widget(block, popup);

    // Column layout: name (32) + current/cap (16) + fill bar (20) + note (rest)
    let name_w = 32usize;
    let count_w = 16usize;
    let bar_w = 20usize;
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled(
            format!("{:<name_w$}", "collection", name_w = name_w),
            Style::default()
                .fg(app.theme.text_muted)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{:<count_w$}", "current/cap", count_w = count_w),
            Style::default()
                .fg(app.theme.text_muted)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{:<bar_w$}", "fill", bar_w = bar_w),
            Style::default()
                .fg(app.theme.text_muted)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "note",
            Style::default()
                .fg(app.theme.text_muted)
                .add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::raw(""));

    for g in &gauges {
        let pct = g.fill_pct();
        let bar_color = if pct >= 90.0 {
            app.theme.status_error
        } else if pct >= 70.0 {
            app.theme.status_warn
        } else {
            app.theme.status_good
        };
        let filled = ((pct.clamp(0.0, 100.0) / 100.0) * bar_w as f32).round() as usize;
        let filled = filled.min(bar_w);
        let bar = format!(
            "{}{}",
            "█".repeat(filled),
            "·".repeat(bar_w.saturating_sub(filled))
        );
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:<name_w$}", g.name, name_w = name_w),
                Style::default().fg(app.theme.text_primary),
            ),
            Span::styled(
                format!(
                    "{:<count_w$}",
                    format!("{}/{}", g.current, g.cap),
                    count_w = count_w
                ),
                Style::default().fg(app.theme.text_primary),
            ),
            Span::styled(bar, Style::default().fg(bar_color)),
            Span::raw("  "),
            Span::styled(g.note, Style::default().fg(app.theme.text_muted)),
        ]));
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled(
            "M / Esc",
            Style::default()
                .fg(app.theme.key_hint)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(":Close — green <70% fill, yellow <90%, red ≥90%"),
    ]));

    f.render_widget(Paragraph::new(lines), inner);
}
