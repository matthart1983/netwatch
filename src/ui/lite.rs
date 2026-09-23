//! NetWatch Lite — the minimal single-screen view.
//!
//! One screen at 80×24, six advertised keys, a handful of theme tokens. It is a
//! deliberate counterpart to the full TUI (10 tabs, 130×36): the question it
//! answers is "what's using my network right now, and is my connection OK?"
//!
//! Entered with `--lite` or toggled with `L`. Opt-in only — the full TUI stays
//! the default at every terminal size.
//!
//! The constants below are **authoritative**. They are transcribed from the
//! design handoff (`design_handoff_netwatch_lite`) with the corrections
//! recorded in `~/Documents/netwatch-lite-implementation-plan-2026-07-28.md`.
//! The tests at the bottom of this file lock the grid so it cannot drift
//! silently — if you move a column, a test tells you what it collided with.
//!
//! Colours come from [`crate::theme::Theme`] tokens, never hardcoded hex, so
//! Lite honours the user's theme. The "four hues" discipline is about how many
//! tokens Lite uses, not which values it burns in.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

use crate::app::App;
use crate::theme::Theme;

// ── The grid ────────────────────────────────────────────────────────────────

/// The grid Lite is designed for. Below this, render the too-small notice
/// rather than a clipped layout.
pub const GRID_W: u16 = 80;
/// See [`GRID_W`].
pub const GRID_H: u16 = 24;

/// Content starts at col 1 — col 0 and col 79 are padding.
pub const CONTENT_X: u16 = 1;
/// Content width in columns.
pub const CONTENT_W: u16 = 78;
/// Last content column, inclusive.
pub const CONTENT_X_END: u16 = CONTENT_X + CONTENT_W - 1;

// ── Rows ────────────────────────────────────────────────────────────────────

pub const ROW_HEADER: u16 = 0;
pub const ROW_DOWN_LABEL: u16 = 2;
pub const ROW_DOWN_CHART: u16 = 3;
pub const DOWN_CHART_H: u16 = 3;
pub const ROW_UP_LABEL: u16 = 6;
pub const ROW_UP_CHART: u16 = 7;
pub const UP_CHART_H: u16 = 2;
pub const ROW_AXIS: u16 = 9;
pub const ROW_HEALTH: u16 = 10;
pub const ROW_TABLE_HEAD: u16 = 12;
pub const ROW_RULE: u16 = 13;
/// First talker row. The list runs to [`ROW_PROMPT`] - 1.
pub const ROW_TALKERS: u16 = 14;
/// Talkers visible in the default state (rows 14..=21).
pub const TALKER_ROWS: u16 = 8;
/// Filter prompt row; blank in every other mode.
pub const ROW_PROMPT: u16 = 22;
pub const ROW_FOOTER: u16 = 23;

/// The detail block renders directly beneath the selected row — not below the
/// whole list, which is what the handoff's reference renderer did.
pub const DETAIL_ROWS: u16 = 3;
/// Talkers visible while detail is open.
pub const TALKER_ROWS_DETAIL: u16 = TALKER_ROWS - DETAIL_ROWS;
/// Highest selection index that still leaves room for the detail block. If the
/// selection sits below this, scroll the window up until it doesn't.
pub const MAX_SEL_WITH_DETAIL: u16 = TALKER_ROWS_DETAIL - 1;

// ── History ─────────────────────────────────────────────────────────────────

/// Chart ring-buffer depth. Deliberately equal to [`CONTENT_W`] so each chart
/// column is exactly one sample — no interpolation, no doubled bars.
///
/// One sample per *refresh tick*, not per second: `refresh_rate_ms` is
/// configurable, so the axis label is computed by [`window_label`] rather than
/// printing the sample count.
pub const HISTORY_SAMPLES: usize = CONTENT_W as usize;

/// Per-row sparkline width. Each column is a *bucket max* over the history —
/// sampling instead would discard 69 of 78 values and hide every spike.
pub const SPARK_W: u16 = 9;

/// Format the wall-clock window that `samples` covers, given the tick interval.
///
/// History gains one sample per refresh tick, and `refresh_rate_ms` is
/// user-configurable (100–5000ms) — so sample count is *not* seconds. Labelling
/// a 78-sample chart "78s" is only right at the 1000ms default; at 500ms the
/// same chart covers 39 seconds. Both the axis and the sparkline header derive
/// their label through here so neither can drift from the data again.
pub fn window_label(samples: usize, refresh_rate_ms: u64) -> String {
    let secs = (samples as u64 * refresh_rate_ms) as f64 / 1000.0;
    if secs >= 120.0 {
        format!("{}m", (secs / 60.0).round() as u64)
    } else if secs >= 10.0 {
        format!("{}s", secs.round() as u64)
    } else {
        // Sub-10s windows round badly to whole seconds — a 100ms refresh over
        // 30 samples is 3 seconds, and "3s" beats "3.0s".
        format!("{}s", secs.max(1.0).round() as u64)
    }
}

/// Samples covered by sparkline column `i`, as a half-open range.
pub fn spark_bucket(i: u16, samples: usize) -> std::ops::Range<usize> {
    let lo = (i as usize * samples) / SPARK_W as usize;
    let hi = ((i as usize + 1) * samples) / SPARK_W as usize;
    lo..hi.max(lo + 1)
}

// ── Talker table ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    Left,
    Right,
}

#[derive(Debug, Clone, Copy)]
pub struct Field {
    pub header: &'static str,
    /// First column, inclusive.
    pub x: u16,
    pub w: u16,
    pub align: Align,
}

impl Field {
    /// Last column, inclusive.
    pub const fn x_end(&self) -> u16 {
        self.x + self.w - 1
    }
}

/// Talker table columns. Verified to tile without overlap and end exactly on
/// [`CONTENT_X_END`] — see `fields_tile_to_the_content_edge`.
pub const FIELDS: &[Field] = &[
    Field {
        header: "PROCESS",
        x: 1,
        w: 15,
        align: Align::Left,
    },
    Field {
        header: "HOST",
        x: 17,
        w: 22,
        align: Align::Left,
    },
    Field {
        header: "DOWN",
        x: 40,
        w: 10,
        align: Align::Right,
    },
    Field {
        header: "UP",
        x: 51,
        w: 10,
        align: Align::Right,
    },
    Field {
        header: "RTT",
        x: 62,
        w: 7,
        align: Align::Right,
    },
    Field {
        // Placeholder only. The rendered header is computed at draw time from
        // the sparkline's own depth (`TOP_CONN_HISTORY_LEN`) and the refresh
        // rate — it is a different window from the charts above, and neither
        // is a fixed number of seconds.
        header: "30s",
        x: 70,
        w: SPARK_W,
        align: Align::Left,
    },
];

// ── Footer ──────────────────────────────────────────────────────────────────

/// Keys advertised in the footer.
///
/// Navigation (`↑`/`↓`/`j`/`k`) and `Esc` are deliberately absent: they are
/// conventions from `less`/`vim`/`top` and live in the `?` overlay instead.
/// The handoff claimed "five keybindings" while omitting any way to move the
/// selection — this is the honest set.
pub const FOOTER_KEYS: &[(&str, &str)] = &[
    ("q", "quit"),
    ("p", "pause"),
    ("/", "filter"),
    ("↵", "detail"),
    ("L", "full"),
    ("?", "help"),
];

/// Blank columns between footer key pairs.
pub const FOOTER_GAP: u16 = 3;

/// Right-aligned footer version string.
pub fn footer_version() -> String {
    format!("netwatch {}", env!("CARGO_PKG_VERSION"))
}

/// Rendered width of the footer key list, in columns.
pub fn footer_keys_width() -> u16 {
    let pairs: u16 = FOOTER_KEYS
        .iter()
        .map(|(k, label)| (k.chars().count() + 1 + label.chars().count()) as u16)
        .sum();
    pairs + FOOTER_GAP * (FOOTER_KEYS.len() as u16 - 1)
}

// ── Adaptive layout ─────────────────────────────────────────────────────────

/// Resolved geometry for the terminal Lite is actually running in.
///
/// The `FIELDS` constants describe the 80×24 reference grid; this generalises
/// them so Lite is a usable mode at any size rather than an 80-column postage
/// stamp in the corner of a wide terminal. HOST absorbs surplus width (it is
/// the field most often truncated) and the talker list absorbs surplus height.
///
/// At exactly 80×24 this reproduces `FIELDS` and the row constants
/// character-for-character — locked by `layout_at_reference_size_matches_spec`.
#[derive(Debug, Clone, Copy)]
pub struct Layout {
    pub content_x: u16,
    pub content_w: u16,
    pub x_process: u16,
    pub w_process: u16,
    pub x_host: u16,
    pub w_host: u16,
    pub x_down: u16,
    pub x_up: u16,
    pub x_rtt: u16,
    pub x_spark: u16,
    pub row_talkers: u16,
    /// Talker rows available with no detail block open.
    pub talker_rows: u16,
    pub row_prompt: u16,
    pub row_footer: u16,
}

/// Widths of the fixed-width fields, and the single blank column between them.
const W_PROCESS: u16 = 15;
const W_RATE: u16 = 10;
const W_RTT: u16 = 7;
const FIELD_GAP: u16 = 1;

impl Layout {
    pub fn new(area: Rect) -> Self {
        let content_x = area.x + 1;
        let content_w = area.width.saturating_sub(2);
        let x_end = content_x + content_w - 1;

        // Right-anchored fields, walking leftward from the content edge.
        let x_spark = x_end + 1 - SPARK_W;
        let x_rtt = x_spark - FIELD_GAP - W_RTT;
        let x_up = x_rtt - FIELD_GAP - W_RATE;
        let x_down = x_up - FIELD_GAP - W_RATE;

        // Left-anchored, with HOST taking whatever is left in the middle.
        let x_process = content_x;
        let x_host = x_process + W_PROCESS + FIELD_GAP;
        let w_host = x_down.saturating_sub(FIELD_GAP).saturating_sub(x_host);

        let row_footer = area.y + area.height - 1;
        let row_prompt = row_footer - 1;
        let row_talkers = area.y + ROW_TALKERS;

        Self {
            content_x,
            content_w,
            x_process,
            w_process: W_PROCESS,
            x_host,
            w_host,
            x_down,
            x_up,
            x_rtt,
            x_spark,
            row_talkers,
            talker_rows: row_prompt.saturating_sub(row_talkers),
            row_prompt,
            row_footer,
        }
    }

    pub fn content_x_end(&self) -> u16 {
        self.content_x + self.content_w - 1
    }

    /// Talker rows available given whether the detail block is open.
    pub fn visible_talkers(&self, detail_open: bool) -> u16 {
        if detail_open {
            self.talker_rows.saturating_sub(DETAIL_ROWS)
        } else {
            self.talker_rows
        }
    }
}

// ── Talkers ─────────────────────────────────────────────────────────────────

/// One row of the talker table: a (process, remote host) group.
pub struct Talker {
    pub process: String,
    /// SNI when DPI has seen the handshake, else the bare remote IP.
    pub host: String,
    pub down: f64,
    pub up: f64,
    pub rtt_ms: Option<f64>,
    /// Rate history for the row sparkline. May be shorter than the sparkline
    /// width — `spark_bucket` handles any sample count.
    pub history: Vec<u64>,
    // ── detail-only fields ──
    pub remote_addr: String,
    pub protocol: String,
    pub state: String,
    pub conns: u32,
}

/// Group the live connection table into talker rows, sorted by total rate.
///
/// Grouping key matches `app::update_top_conn_history` exactly — that is what
/// makes the `top_conn_history` sparkline lookup hit.
pub fn collect_talkers(app: &App) -> Vec<Talker> {
    use std::collections::HashMap;

    let conns = app.connection_collector.connections();
    let mut groups: HashMap<(String, String), Talker> = HashMap::new();

    for c in conns.iter() {
        if c.state == "LISTEN" || c.state == "CLOSED" || c.remote_addr.is_empty() {
            continue;
        }
        // Unbound sockets report a wildcard peer. They aren't talking to
        // anything, so they'd occupy a talker slot to say nothing.
        if c.remote_addr.starts_with('*') || c.remote_addr.starts_with("0.0.0.0") {
            continue;
        }
        let process = c.process_name.clone().unwrap_or_else(|| "—".into());
        let host_key = host_of(&c.remote_addr);
        // Prefer the SNI when DPI has it — `github.com` beats `140.82.121.4`.
        // There is no rDNS in netwatch, so without capture this stays an IP.
        let display_host = sni_of(c).unwrap_or_else(|| host_key.clone());

        let e = groups
            .entry((process.clone(), host_key.clone()))
            .or_insert_with(|| Talker {
                process,
                host: display_host,
                down: 0.0,
                up: 0.0,
                rtt_ms: None,
                history: Vec::new(),
                remote_addr: c.remote_addr.clone(),
                protocol: c.protocol.clone(),
                state: c.state.clone(),
                conns: 0,
            });
        e.down += c.rx_rate.unwrap_or(0.0);
        e.up += c.tx_rate.unwrap_or(0.0);
        e.conns += 1;
        // Handshake RTT is per-flow and only exists for connections whose
        // SYN→SYN-ACK we captured. Take the lowest in the group.
        if let Some(us) = c.handshake_rtt_us {
            let ms = us / 1000.0;
            e.rtt_ms = Some(e.rtt_ms.map_or(ms, |cur: f64| cur.min(ms)));
        }
    }

    let mut out: Vec<Talker> = groups
        .into_iter()
        .map(|(key, mut t)| {
            if let Some(h) = app.caches.top_conn_history.get(&key) {
                t.history = h.iter().copied().collect();
            }
            t
        })
        .collect();

    // Ties must break on something stable. Rates are frequently all zero
    // (idle host, or no capture privileges), and process name alone doesn't
    // separate eight Chrome rows — without the host tiebreak the order comes
    // from HashMap iteration and the list reshuffles every tick, so the
    // selection silently lands on a different connection each frame.
    out.sort_by(|a, b| {
        (b.down + b.up)
            .partial_cmp(&(a.down + a.up))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.process.cmp(&b.process))
            .then_with(|| a.host.cmp(&b.host))
            .then_with(|| a.remote_addr.cmp(&b.remote_addr))
    });
    out
}

/// Strip the trailing `:port`, preserving IPv6 brackets. Must stay identical
/// to `app::top_conn_host` or the sparkline history lookup misses.
fn host_of(addr: &str) -> String {
    if let Some(stripped) = addr.strip_prefix('[') {
        if let Some(end) = stripped.find("]:") {
            return format!("[{}]", &stripped[..end]);
        }
    }
    match addr.rfind(':') {
        Some(colon) => addr[..colon].to_string(),
        None => addr.to_string(),
    }
}

/// The TLS/QUIC ClientHello's SNI, when the handshake was captured.
///
/// `pub(crate)` so Dense resolves hostnames the same way — a table of bare
/// IPs where the other views show names is the same data rendered worse.
pub(crate) fn sni_of(c: &crate::collectors::connections::Connection) -> Option<String> {
    use crate::dpi::AppProtocol::{Quic, Tls};
    match &c.app_protocol {
        Some(Tls { sni: Some(s), .. }) | Some(Quic { sni: Some(s), .. }) => Some(s.clone()),
        _ => None,
    }
}

/// Talkers matching the active filter. Matches process **or** host,
/// case-insensitively.
pub fn filter_talkers(talkers: Vec<Talker>, query: &str) -> Vec<Talker> {
    if query.is_empty() {
        return talkers;
    }
    let q = query.to_lowercase();
    talkers
        .into_iter()
        .filter(|t| t.process.to_lowercase().contains(&q) || t.host.to_lowercase().contains(&q))
        .collect()
}

// ── Formatting ──────────────────────────────────────────────────────────────

/// Split a rate into (value, unit) so callers can style them separately and
/// print the unit on `peak`/`avg` too. One decimal below 10, else integer —
/// `4.2 MB/s`, `880 KB/s`.
pub fn split_rate(bytes_per_sec: f64) -> (String, &'static str) {
    let (val, unit) = if bytes_per_sec >= 1e9 {
        (bytes_per_sec / 1e9, "GB/s")
    } else if bytes_per_sec >= 1e6 {
        (bytes_per_sec / 1e6, "MB/s")
    } else if bytes_per_sec >= 1e3 {
        (bytes_per_sec / 1e3, "KB/s")
    } else {
        (bytes_per_sec, "B/s")
    };
    let s = if val < 10.0 && val > 0.0 {
        format!("{val:.1}")
    } else {
        format!("{}", val.round() as u64)
    };
    (s, unit)
}

/// Single-string rate for table cells.
pub fn fmt_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec < 1.0 {
        return "—".into();
    }
    let (v, u) = split_rate(bytes_per_sec);
    format!("{v} {u}")
}

/// Truncate to `w` display columns, appending `…` when it doesn't fit.
///
/// Width-aware rather than byte- or char-aware so CJK process names don't
/// shear the columns to the right of them.
pub fn truncate_end(s: &str, w: u16) -> String {
    let w = w as usize;
    if s.width() <= w {
        return s.to_string();
    }
    if w <= 1 {
        return "…".into();
    }
    let mut out = String::new();
    let mut used = 0usize;
    for ch in s.chars() {
        let cw = ch.to_string().width();
        if used + cw > w - 1 {
            break;
        }
        out.push(ch);
        used += cw;
    }
    out.push('…');
    out
}

/// Middle-truncate a hostname, keeping the start and the TLD.
///
/// `ec2-52-1-2-3.compute-1.amazonaws.com` truncated hard from the right
/// becomes garbage that still reads as a real hostname; keeping the tail makes
/// the domain recognisable.
pub fn truncate_host(s: &str, w: u16) -> String {
    let wu = w as usize;
    if s.width() <= wu {
        return s.to_string();
    }
    if wu <= 3 {
        return truncate_end(s, w);
    }
    // Keep the last two labels (`amazonaws.com`) if they fit in half the space.
    let tail = match s.rfind('.') {
        Some(dot) => {
            let last = &s[..dot];
            match last.rfind('.') {
                Some(d2) => &s[d2 + 1..],
                None => &s[dot + 1..],
            }
        }
        None => "",
    };
    // Keep the tail only if it still leaves a head worth reading — otherwise
    // `…amazonaws.com` tells you less than `ec2-52-1-2-3.com…`.
    const MIN_HEAD: usize = 3;
    if tail.is_empty() || tail.width() + 1 + MIN_HEAD > wu {
        return truncate_end(s, w);
    }
    let head_w = wu - tail.width() - 1; // room for the ellipsis
    let mut head = String::new();
    let mut used = 0usize;
    for ch in s.chars() {
        let cw = ch.to_string().width();
        if used + cw > head_w {
            break;
        }
        head.push(ch);
        used += cw;
    }
    format!("{head}…{tail}")
}

// ── Drawing primitives ──────────────────────────────────────────────────────

fn put(f: &mut Frame, x: u16, y: u16, s: &str, style: Style, clip_x_end: u16) {
    if x > clip_x_end {
        return;
    }
    let max = (clip_x_end - x + 1) as usize;
    f.buffer_mut().set_stringn(x, y, s, max, style);
}

/// Draw right-aligned so the string *ends* on `x_end`.
fn put_right(f: &mut Frame, x_end: u16, y: u16, s: &str, style: Style) {
    let w = s.width() as u16;
    let x = x_end.saturating_sub(w.saturating_sub(1));
    put(f, x, y, s, style, x_end);
}

/// Left-pad a history with zeros to exactly `width` samples.
///
/// Required before handing data to the graph module: `render_bars` right-aligns
/// a short series but `render_dots` indexes cells directly and left-aligns it,
/// so an unpadded series renders in the wrong half of the chart under one style
/// and not the other. Padding to the exact width makes `now` land on the right
/// edge under both, and matches what every other chart call site does.
fn pad_to_width(data: &[u64], width: usize) -> Vec<u64> {
    if width == 0 {
        return Vec::new();
    }
    if data.len() >= width {
        return data[data.len() - width..].to_vec();
    }
    let mut out = vec![0u64; width - data.len()];
    out.extend_from_slice(data);
    out
}

/// Collapse a history of any length to exactly [`SPARK_W`] values, taking the
/// **max** of each bucket so a spike anywhere inside it survives.
///
/// This has to happen before the graph module sees the data: `render_bars`
/// keeps only the last `width` samples and discards the rest, which for a
/// 30-sample history in a 9-column cell would throw away 21 of them.
fn bucket_history(data: &[u64]) -> Vec<u64> {
    (0..SPARK_W)
        .map(|i| {
            let b = spark_bucket(i, data.len());
            data[b.start..b.end.min(data.len())]
                .iter()
                .copied()
                .max()
                .unwrap_or(0)
        })
        .collect()
}

/// Row sparkline, rendered through the shared graph module so it follows the
/// app-wide bars/dots setting like every other chart.
fn draw_sparkline(f: &mut Frame, app: &App, x: u16, y: u16, data: &[u64], color: Color) {
    if data.is_empty() {
        return;
    }
    let bucketed = bucket_history(data);
    crate::graph::render(
        f,
        Rect::new(x, y, SPARK_W, 1),
        &bucketed,
        app.graph_style,
        color,
        app.theme.status_warn,
        app.graph_opts(),
    );
}

// ── Render ──────────────────────────────────────────────────────────────────

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    if area.width < GRID_W || area.height < GRID_H {
        render_too_small(f, app, area);
        return;
    }

    let t = &app.theme;
    let l = Layout::new(area);
    let paused = app.ui.paused;

    let health = app.health_prober.status();
    // A probe that has not completed, or could not be sent, is not a fault:
    // only a measured probe can degrade the verdict.
    let unhealthy =
        health.gateway_loss.degrades(health.gateway_rtt_ms) || health.dns_loss.is_lossy();

    render_header(f, app, &l, &health, unhealthy, paused);
    render_throughput(f, app, &l, paused);
    render_axis(f, app, t, &l);
    let verdict = app.diagnose.engine.verdict(&app.diagnose.baselines);
    render_health_line(f, t, &l, &health, unhealthy, &verdict);
    render_table(f, app, &l, paused);
    render_footer(f, t, &l, app);
}

fn render_too_small(f: &mut Frame, app: &App, area: Rect) {
    // Lite has a hard floor: below it, a clipped grid is worse than a
    // sentence explaining the situation.
    let msg = format!(
        "netwatch lite needs {GRID_W}×{GRID_H} — this terminal is {}×{}",
        area.width, area.height
    );
    let p = Paragraph::new(vec![
        Line::from(Span::styled(
            msg,
            Style::default().fg(app.theme.text_secondary),
        )),
        Line::from(Span::styled(
            "resize, or press L for the full view",
            Style::default().fg(app.theme.text_muted),
        )),
    ]);
    f.render_widget(p, area);
}

fn render_header(
    f: &mut Frame,
    app: &App,
    l: &Layout,
    health: &crate::collectors::health::HealthStatus,
    unhealthy: bool,
    paused: bool,
) {
    let t = &app.theme;
    let y = ROW_HEADER;
    let end = l.content_x_end();

    let mut x = l.content_x;
    put(
        f,
        x,
        y,
        "netwatch",
        Style::default()
            .fg(t.text_primary)
            .add_modifier(Modifier::BOLD),
        end,
    );
    x += 10;
    let iface = &app.capture_interface;
    put(f, x, y, iface, Style::default().fg(t.tx_rate), end);
    x += iface.width() as u16;

    if let Some(ip) = app
        .interface_info
        .iter()
        .find(|i| &i.name == iface)
        .and_then(|i| i.ipv4.clone())
    {
        put(
            f,
            x,
            y,
            &format!(" · {ip}"),
            Style::default().fg(t.text_secondary),
            end,
        );
    }

    if paused {
        put_right(
            f,
            end,
            y,
            "◆ PAUSED",
            Style::default()
                .fg(t.status_warn)
                .add_modifier(Modifier::BOLD),
        );
        return;
    }

    // Right cluster: dot, RTT, loss. The glyph changes shape as well as
    // colour — red-vs-green is only 1.43:1 against each other, so hue alone
    // is not a signal.
    let rtt = health
        .gateway_rtt_ms
        .map(|v| format!("{v:.1}ms"))
        .unwrap_or_else(|| "—".into());
    let loss = format!("{} loss", health.gateway_loss.label(0));
    let dot = if unhealthy { "▲" } else { "●" };
    let dot_style = Style::default().fg(if unhealthy {
        t.status_error
    } else {
        t.status_good
    });

    let total = 2 + rtt.width() as u16 + 2 + loss.width() as u16;
    let sx = end + 1 - total;
    put(f, sx, y, dot, dot_style, end);
    put(f, sx + 2, y, &rtt, Style::default().fg(t.text_primary), end);
    put(
        f,
        sx + 2 + rtt.width() as u16 + 2,
        y,
        &loss,
        Style::default().fg(if unhealthy {
            t.status_error
        } else {
            t.text_secondary
        }),
        end,
    );
}

fn render_throughput(f: &mut Frame, app: &App, l: &Layout, paused: bool) {
    let t = &app.theme;
    let end = l.content_x_end();
    let ifaces = app.traffic.interfaces();
    let iface = ifaces.iter().find(|i| i.name == app.capture_interface);

    // Paused greys the charts, but the rate numbers stay legible — greying
    // the whole screen to the faintest token makes pause the least readable
    // state, which is backwards.
    let down_chart = Style::default().fg(if paused { t.text_muted } else { t.rx_rate });
    let up_chart = Style::default().fg(if paused { t.text_muted } else { t.tx_rate });

    for (label, y_label, y_chart, h, rate, hist, arrow, chart_style, series) in [
        (
            "down",
            ROW_DOWN_LABEL,
            ROW_DOWN_CHART,
            DOWN_CHART_H,
            iface.map(|i| i.rx_rate).unwrap_or(0.0),
            iface.map(|i| &i.rx_history),
            "↓",
            down_chart,
            t.rx_rate,
        ),
        (
            "up",
            ROW_UP_LABEL,
            ROW_UP_CHART,
            UP_CHART_H,
            iface.map(|i| i.tx_rate).unwrap_or(0.0),
            iface.map(|i| &i.tx_history),
            "↑",
            up_chart,
            t.tx_rate,
        ),
    ] {
        let _ = label;
        put(
            f,
            l.content_x,
            y_label,
            arrow,
            Style::default().fg(series).add_modifier(Modifier::BOLD),
            end,
        );
        let (val, unit) = split_rate(rate);
        put(
            f,
            l.content_x + 2,
            y_label,
            &val,
            Style::default()
                .fg(t.text_primary)
                .add_modifier(Modifier::BOLD),
            end,
        );
        put(
            f,
            l.content_x + 3 + val.width() as u16,
            y_label,
            unit,
            Style::default().fg(t.text_secondary),
            end,
        );

        // peak / avg carry their own units — the headline's unit can differ
        // (upload peaking in MB/s while current sits in KB/s).
        let samples: Vec<u64> = hist
            .map(|h| {
                let take = (l.content_w as usize).min(h.len());
                h.iter().skip(h.len() - take).copied().collect()
            })
            .unwrap_or_default();
        let ctx = if samples.is_empty() {
            "peak —  avg —".to_string()
        } else {
            let peak = samples.iter().copied().max().unwrap_or(0) as f64;
            let avg = samples.iter().copied().sum::<u64>() as f64 / samples.len() as f64;
            let (pv, pu) = split_rate(peak);
            let (av, au) = split_rate(avg);
            format!("peak {pv} {pu}  avg {av} {au}")
        };
        put_right(f, end, y_label, &ctx, Style::default().fg(t.text_secondary));

        // Route through the shared graph module so Lite honours the app-wide
        // `graph_style` (bars / btop-style braille dots) and `graph_fade`
        // settings, exactly like every other chart. `t` in the loop tuple is
        // only the fallback colour; the style itself comes from config.
        let series_color = if paused { t.text_muted } else { series };
        let _ = chart_style;
        crate::graph::render(
            f,
            Rect::new(l.content_x, y_chart, l.content_w, h),
            &pad_to_width(&samples, l.content_w as usize),
            app.graph_style,
            series_color,
            t.status_warn,
            app.graph_opts(),
        );
    }
}

fn render_axis(f: &mut Frame, app: &App, t: &Theme, l: &Layout) {
    let rule: String = "─".repeat(l.content_w as usize);
    let style = Style::default().fg(t.text_muted);
    put(f, l.content_x, ROW_AXIS, &rule, style, l.content_x_end());
    // One sample per column, so the window is the chart width in samples —
    // converted to wall-clock, since a sample is one refresh tick, not a second.
    let left = format!(
        " {} ago ",
        window_label(l.content_w as usize, app.user_config.refresh_rate_ms)
    );
    put(
        f,
        l.content_x,
        ROW_AXIS,
        &left,
        Style::default().fg(t.text_secondary),
        l.content_x_end(),
    );
    put_right(
        f,
        l.content_x_end(),
        ROW_AXIS,
        " now ",
        Style::default().fg(t.text_secondary),
    );
}

fn render_health_line(
    f: &mut Frame,
    t: &Theme,
    l: &Layout,
    health: &crate::collectors::health::HealthStatus,
    unhealthy: bool,
    verdict: &crate::diagnose::Verdict,
) {
    let end = l.content_x_end();
    let mut x = l.content_x;
    let fmt = |v: Option<f64>| v.map(|v| format!("{v:.1}ms")).unwrap_or_else(|| "—".into());

    for (label, val, bad) in [
        (
            "gateway",
            fmt(health.gateway_rtt_ms),
            health.gateway_loss.degrades(health.gateway_rtt_ms),
        ),
        (
            "dns",
            fmt(health.dns_rtt_ms),
            health.dns_loss.degrades(health.dns_rtt_ms),
        ),
        (
            "internet",
            fmt(health.internet_rtt_ms),
            health.internet_loss.degrades(health.internet_rtt_ms),
        ),
    ] {
        put(
            f,
            x,
            ROW_HEALTH,
            &format!("{label} "),
            Style::default().fg(t.text_secondary),
            end,
        );
        x += label.width() as u16 + 1;
        put(
            f,
            x,
            ROW_HEALTH,
            &val,
            Style::default().fg(if bad { t.status_error } else { t.text_primary }),
            end,
        );
        x += val.width() as u16 + 3;
    }

    let (verdict_text, style) = if health.gateway_loss.degrades(health.gateway_rtt_ms) {
        ("gateway degraded", Style::default().fg(t.status_error))
    } else if health.dns_loss.degrades(health.dns_rtt_ms) {
        ("dns degraded", Style::default().fg(t.status_error))
    } else if health.internet_loss.is_lossy() {
        ("internet degraded", Style::default().fg(t.status_error))
    } else if unhealthy {
        ("degraded", Style::default().fg(t.status_error))
    } else {
        // Reachability is fine, so the verdict is the diagnose engine's to
        // give. It distinguishes "nothing is wrong" from "not enough baseline
        // to say", which reachability alone cannot — and `text_muted` is only
        // 1.69:1 on nord and 2.79:1 on solarized, so nothing load-bearing
        // sits on it.
        (
            verdict.chip(),
            Style::default().fg(if verdict.is_clear() {
                t.text_secondary
            } else {
                verdict.color(t)
            }),
        )
    };
    put_right(f, end, ROW_HEALTH, verdict_text, style);
}

fn render_table(f: &mut Frame, app: &App, l: &Layout, paused: bool) {
    let t = &app.theme;
    let end = l.content_x_end();
    let head = Style::default().fg(t.text_secondary);

    put(f, l.x_process, ROW_TABLE_HEAD, "process", head, end);
    put(f, l.x_host, ROW_TABLE_HEAD, "host", head, end);
    put_right(f, l.x_down + W_RATE - 1, ROW_TABLE_HEAD, "DOWN", head);
    put_right(f, l.x_up + W_RATE - 1, ROW_TABLE_HEAD, "UP", head);
    put_right(f, l.x_rtt + W_RTT - 1, ROW_TABLE_HEAD, "RTT", head);
    // Derived, like the axis label — but from the sparkline's OWN depth, which
    // is the per-group history cap, not the chart width. The two series have
    // different depths, so reusing the chart's number here would trade a
    // hardcoded wrong label for a derived one.
    put(
        f,
        l.x_spark,
        ROW_TABLE_HEAD,
        &window_label(
            crate::app::TOP_CONN_HISTORY_LEN,
            app.user_config.refresh_rate_ms,
        ),
        head,
        end,
    );

    let rule: String = "─".repeat(l.content_w as usize);
    put(
        f,
        l.content_x,
        ROW_RULE,
        &rule,
        Style::default().fg(t.text_muted),
        end,
    );

    let talkers = filter_talkers(collect_talkers(app), &app.ui.lite.filter_text);
    let lite = &app.ui.lite;

    if talkers.is_empty() {
        let msg = if !lite.filter_text.is_empty() {
            "no talkers match".to_string()
        } else if !app.packet_collector.is_capturing() {
            // The homelab-without-sudo case is the target persona, not an
            // edge case: say what's missing rather than looking idle.
            "no traffic attributed — run with sudo for rates and RTT".to_string()
        } else {
            "no active connections".to_string()
        };
        // The only thing on screen — never render it on the weakest token.
        put(
            f,
            l.content_x,
            l.row_talkers,
            &msg,
            Style::default().fg(t.text_secondary),
            end,
        );
        render_prompt(f, app, l, talkers.len(), 0);
        return;
    }

    let visible = l.visible_talkers(lite.detail_open) as usize;
    let offset = lite.offset.min(talkers.len().saturating_sub(1));
    let sel = lite.selected.min(talkers.len() - 1);

    let down_style = Style::default().fg(if paused { t.text_muted } else { t.rx_rate });
    let up_style = Style::default().fg(if paused { t.text_muted } else { t.tx_rate });

    let mut y = l.row_talkers;
    for (i, talker) in talkers.iter().enumerate().skip(offset).take(visible) {
        let selected = i == sel;
        if selected {
            for x in l.content_x..=end {
                f.buffer_mut().get_mut(x, y).set_bg(t.selection_bg);
            }
        }
        // On the selected row, secondary text is promoted to primary: `dim`
        // on `selection_bg` measures 3.6:1, and the selected row is exactly
        // where the user is looking.
        let secondary = Style::default().fg(if selected {
            t.text_primary
        } else {
            t.text_secondary
        });

        put(
            f,
            l.x_process,
            y,
            &truncate_end(&talker.process, l.w_process),
            Style::default().fg(t.text_primary),
            end,
        );
        put(
            f,
            l.x_host,
            y,
            &truncate_host(&talker.host, l.w_host),
            secondary,
            end,
        );
        put_right(
            f,
            l.x_down + W_RATE - 1,
            y,
            &fmt_rate(talker.down),
            down_style,
        );
        put_right(f, l.x_up + W_RATE - 1, y, &fmt_rate(talker.up), up_style);
        let rtt = talker
            .rtt_ms
            .map(|v| format!("{v:.0}ms"))
            .unwrap_or_else(|| "—".into());
        put_right(f, l.x_rtt + W_RTT - 1, y, &rtt, secondary);
        draw_sparkline(
            f,
            app,
            l.x_spark,
            y,
            &talker.history,
            if selected { t.rx_rate } else { t.text_muted },
        );
        y += 1;

        // Detail renders directly beneath its own row — not below the whole
        // list, which is what the design's reference renderer did.
        if selected && lite.detail_open {
            render_detail(f, app, l, talker, &mut y);
        }
    }

    render_prompt(f, app, l, talkers.len(), sel);
}

fn render_detail(f: &mut Frame, app: &App, l: &Layout, talker: &Talker, y: &mut u16) {
    let t = &app.theme;
    let end = l.content_x_end();
    let dim = Style::default().fg(t.text_secondary);

    put(
        f,
        l.content_x + 2,
        *y,
        "└─",
        Style::default().fg(t.text_muted),
        end,
    );
    put(
        f,
        l.content_x + 5,
        *y,
        &format!(
            "{}   {}   {}   {} conns",
            talker.remote_addr,
            talker.protocol.to_lowercase(),
            talker.state.to_lowercase(),
            talker.conns
        ),
        dim,
        end,
    );
    *y += 1;

    let peak = talker.history.iter().copied().max().unwrap_or(0) as f64;
    let (pv, pu) = split_rate(peak);
    put(
        f,
        l.content_x + 5,
        *y,
        &format!(
            "rates   {} down   {} up   peak {pv} {pu}",
            fmt_rate(talker.down),
            fmt_rate(talker.up)
        ),
        dim,
        end,
    );
    *y += 1;

    let rtt = match talker.rtt_ms {
        Some(v) => format!("rtt {v:.0}ms   from tcp handshake"),
        None => "rtt —   no handshake captured for this flow".to_string(),
    };
    put(f, l.content_x + 5, *y, &rtt, dim, end);
    *y += 1;
}

/// The row above the footer: the filter prompt while editing, the active
/// filter once committed, otherwise a capture-privileges hint when there is
/// one to give. Blank in the ordinary healthy case.
fn render_prompt(f: &mut Frame, app: &App, l: &Layout, matched: usize, _sel: usize) {
    let t = &app.theme;
    let end = l.content_x_end();
    let lite = &app.ui.lite;

    if lite.filter_input || !lite.filter_text.is_empty() {
        put(
            f,
            l.content_x,
            l.row_prompt,
            "/",
            Style::default()
                .fg(t.status_warn)
                .add_modifier(Modifier::BOLD),
            end,
        );
        let q = &lite.filter_text;
        put(
            f,
            l.content_x + 2,
            l.row_prompt,
            q,
            Style::default().fg(t.text_primary),
            end,
        );
        if lite.filter_input {
            put(
                f,
                l.content_x + 2 + q.width() as u16,
                l.row_prompt,
                "█",
                Style::default().fg(t.text_primary),
                end,
            );
        }
        // A committed filter still narrows the list, so it has to stay
        // visible — otherwise the view looks like it's missing connections.
        let note = if lite.filter_input {
            format!("{matched} match")
        } else {
            format!("{matched} match · esc clears")
        };
        // Right-aligned so a long query can't overwrite it.
        put_right(
            f,
            end,
            l.row_prompt,
            &note,
            Style::default().fg(t.text_secondary),
        );
        return;
    }

    // Without capture, per-connection rates and RTT are simply unavailable —
    // every cell reads "—". Saying so beats looking broken. This is the
    // homelab-without-sudo case the view is aimed at, not an edge case.
    if !app.packet_collector.is_capturing() {
        put(
            f,
            l.content_x,
            l.row_prompt,
            "no capture — rates and RTT need sudo; hosts show as IPs",
            Style::default().fg(t.text_muted),
            end,
        );
    }
}

fn render_footer(f: &mut Frame, t: &Theme, l: &Layout, app: &App) {
    let end = l.content_x_end();
    let mut x = l.content_x;
    for (k, label) in FOOTER_KEYS {
        put(
            f,
            x,
            l.row_footer,
            k,
            Style::default().fg(t.key_hint).add_modifier(Modifier::BOLD),
            end,
        );
        x += k.width() as u16;
        put(
            f,
            x,
            l.row_footer,
            &format!(" {label}"),
            Style::default().fg(t.text_secondary),
            end,
        );
        x += 1 + label.width() as u16 + FOOTER_GAP;
    }
    let _ = app;
    put_right(
        f,
        end,
        l.row_footer,
        &footer_version(),
        Style::default().fg(t.text_muted),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_tile_to_the_content_edge() {
        let mut prev_end = CONTENT_X - 1;
        for f in FIELDS {
            assert!(
                f.x > prev_end,
                "field {} starts at col {} but the previous field ends at {}",
                f.header,
                f.x,
                prev_end
            );
            prev_end = f.x_end();
        }
        assert_eq!(
            prev_end, CONTENT_X_END,
            "the last field must end exactly on the content edge"
        );
    }

    #[test]
    fn field_headers_fit_their_columns() {
        for f in FIELDS {
            assert!(
                f.header.chars().count() as u16 <= f.w,
                "header {:?} is wider than its {}-col field",
                f.header,
                f.w
            );
        }
    }

    // These compare constants, so clippy can fold them — but that is the
    // point: the test fails to compile-and-pass the moment someone edits a
    // row constant into an overlapping position.
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn bands_do_not_collide() {
        assert!(ROW_DOWN_CHART + DOWN_CHART_H <= ROW_UP_LABEL);
        assert!(ROW_UP_CHART + UP_CHART_H <= ROW_AXIS);
        assert!(ROW_HEALTH < ROW_TABLE_HEAD);
        assert!(ROW_RULE < ROW_TALKERS);
        assert_eq!(
            ROW_TALKERS + TALKER_ROWS,
            ROW_PROMPT,
            "the talker list must end exactly where the prompt row begins"
        );
        assert!(ROW_PROMPT < ROW_FOOTER);
        assert!(ROW_FOOTER < GRID_H);
    }

    #[test]
    fn detail_block_fits_beneath_any_selection() {
        // Detail renders directly under the selected row; everything below
        // shifts down and the list clips at the prompt row.
        for sel in 0..=MAX_SEL_WITH_DETAIL {
            let last = ROW_TALKERS + sel + DETAIL_ROWS;
            assert!(
                last < ROW_PROMPT,
                "detail for selection {sel} would run to row {last}, past the list"
            );
        }
        assert_eq!(TALKER_ROWS_DETAIL, 5);
    }

    #[test]
    fn footer_keys_clear_the_version_string() {
        let keys_end = CONTENT_X + footer_keys_width() - 1;
        let version_start = CONTENT_X_END - footer_version().chars().count() as u16 + 1;
        assert!(
            keys_end < version_start,
            "footer keys end at col {keys_end} but the version starts at col {version_start}"
        );
    }

    #[test]
    fn spark_buckets_cover_the_history_exactly() {
        let mut prev_end = 0;
        for i in 0..SPARK_W {
            let b = spark_bucket(i, HISTORY_SAMPLES);
            assert_eq!(b.start, prev_end, "gap or overlap at sparkline column {i}");
            assert!(!b.is_empty(), "sparkline column {i} has no samples");
            prev_end = b.end;
        }
        assert_eq!(prev_end, HISTORY_SAMPLES);
    }

    #[test]
    fn history_is_one_sample_per_chart_column() {
        // The handoff labelled the axis "60s ago" while drawing 78 columns,
        // which duplicated ~30% of samples. Keep these locked together.
        assert_eq!(HISTORY_SAMPLES, CONTENT_W as usize);
    }

    #[test]
    fn layout_at_reference_size_matches_spec() {
        // The FIELDS constants describe the 80×24 reference grid; Layout
        // generalises them. At the reference size the two must agree exactly,
        // or the design handoff and the code have silently diverged.
        let l = Layout::new(Rect::new(0, 0, GRID_W, GRID_H));
        assert_eq!(l.content_x, CONTENT_X);
        assert_eq!(l.content_w, CONTENT_W);
        assert_eq!(l.content_x_end(), CONTENT_X_END);

        assert_eq!(l.x_process, FIELDS[0].x);
        assert_eq!(l.w_process, FIELDS[0].w);
        assert_eq!(l.x_host, FIELDS[1].x);
        assert_eq!(l.w_host, FIELDS[1].w);
        assert_eq!(l.x_down, FIELDS[2].x);
        assert_eq!(l.x_up, FIELDS[3].x);
        assert_eq!(l.x_rtt, FIELDS[4].x);
        assert_eq!(l.x_spark, FIELDS[5].x);

        assert_eq!(l.row_talkers, ROW_TALKERS);
        assert_eq!(l.talker_rows, TALKER_ROWS);
        assert_eq!(l.row_prompt, ROW_PROMPT);
        assert_eq!(l.row_footer, ROW_FOOTER);
        assert_eq!(l.visible_talkers(true), TALKER_ROWS_DETAIL);
    }

    #[test]
    fn layout_stays_coherent_on_larger_terminals() {
        // HOST absorbs surplus width, the talker list absorbs surplus height,
        // and the right-anchored fields stay glued to the content edge.
        for (w, h) in [(80, 24), (100, 30), (130, 36), (200, 60)] {
            let l = Layout::new(Rect::new(0, 0, w, h));
            assert_eq!(
                l.x_spark + SPARK_W - 1,
                l.content_x_end(),
                "sparkline must end on the content edge at {w}×{h}"
            );
            assert!(
                l.x_host + l.w_host < l.x_down,
                "HOST overruns DOWN at {w}×{h}"
            );
            assert!(l.w_host >= FIELDS[1].w, "HOST shrank below spec at {w}×{h}");
            assert!(l.talker_rows >= TALKER_ROWS, "lost talker rows at {w}×{h}");
            assert!(l.row_footer < h, "footer off-screen at {w}×{h}");
        }
    }

    #[test]
    fn truncation_is_display_width_aware_and_marks_elision() {
        assert_eq!(truncate_end("firefox", 15), "firefox");
        // Fills the field: 14 chars + the ellipsis == the full 15 columns.
        assert_eq!(truncate_end("mDNSResponder-extra", 15), "mDNSResponder-…");
        assert_eq!(truncate_end("mDNSResponder-extra", 15).width(), 15);

        // CJK: two columns per char, so 8 chars would overflow a 10-col field
        // if measured by char count.
        let cjk = "网络监视器网络监视器";
        assert!(truncate_end(cjk, 10).width() <= 10);

        // Hosts keep their TLD so the domain stays recognisable.
        let long = "ec2-52-1-2-3.compute-1.amazonaws.com";
        let out = truncate_host(long, 22);
        assert!(out.width() <= 22, "{out:?} exceeds 22 columns");
        assert!(out.ends_with("amazonaws.com"), "{out:?} lost its TLD");
        assert!(out.contains('…'), "{out:?} has no elision marker");
        assert_eq!(truncate_host("github.com", 22), "github.com");
    }

    #[test]
    fn rates_carry_units_and_scale() {
        assert_eq!(split_rate(4_200_000.0), ("4.2".into(), "MB/s"));
        assert_eq!(split_rate(880_000.0), ("880".into(), "KB/s"));
        assert_eq!(fmt_rate(0.0), "—");
        // peak/avg must be able to differ in unit from the headline — that's
        // why split_rate returns the unit rather than implying it.
        let (_, headline) = split_rate(61_000.0);
        let (_, peak) = split_rate(2_100_000.0);
        assert_ne!(headline, peak);
    }

    #[test]
    fn filter_matches_process_or_host() {
        let mk = |p: &str, h: &str| Talker {
            process: p.into(),
            host: h.into(),
            down: 0.0,
            up: 0.0,
            rtt_ms: None,
            history: vec![],
            remote_addr: String::new(),
            protocol: String::new(),
            state: String::new(),
            conns: 1,
        };
        let rows = vec![
            mk("firefox", "github.com"),
            mk("Spotify", "spotify-edge"),
            mk("ssh", "build-01.lan"),
        ];
        assert_eq!(filter_talkers(rows_clone(&rows), "fire").len(), 1);
        // Matches the host as well as the process, case-insensitively.
        assert_eq!(filter_talkers(rows_clone(&rows), "GITHUB").len(), 1);
        assert_eq!(filter_talkers(rows_clone(&rows), "").len(), 3);
        assert_eq!(filter_talkers(rows_clone(&rows), "zzz").len(), 0);
    }

    fn rows_clone(rows: &[Talker]) -> Vec<Talker> {
        rows.iter()
            .map(|t| Talker {
                process: t.process.clone(),
                host: t.host.clone(),
                down: t.down,
                up: t.up,
                rtt_ms: t.rtt_ms,
                history: t.history.clone(),
                remote_addr: t.remote_addr.clone(),
                protocol: t.protocol.clone(),
                state: t.state.clone(),
                conns: t.conns,
            })
            .collect()
    }

    #[test]
    fn talker_order_is_total_so_the_selection_cannot_drift() {
        // Every row here ties on rate *and* process — the exact shape that
        // occurs on an idle host or without capture privileges. If the
        // comparator leaves any pair equal, the underlying HashMap order
        // decides and the list reshuffles between frames.
        let mk = |p: &str, h: &str, a: &str| Talker {
            process: p.into(),
            host: h.into(),
            down: 0.0,
            up: 0.0,
            rtt_ms: None,
            history: vec![],
            remote_addr: a.into(),
            protocol: String::new(),
            state: String::new(),
            conns: 1,
        };
        let rows = [
            mk("Chrome", "10.0.0.3", "10.0.0.3:443"),
            mk("Chrome", "10.0.0.1", "10.0.0.1:443"),
            mk("Chrome", "10.0.0.2", "10.0.0.2:443"),
        ];
        let cmp = |a: &Talker, b: &Talker| {
            (b.down + b.up)
                .partial_cmp(&(a.down + a.up))
                .unwrap()
                .then_with(|| a.process.cmp(&b.process))
                .then_with(|| a.host.cmp(&b.host))
                .then_with(|| a.remote_addr.cmp(&b.remote_addr))
        };
        for i in 0..rows.len() {
            for j in 0..rows.len() {
                if i != j {
                    assert_ne!(
                        cmp(&rows[i], &rows[j]),
                        std::cmp::Ordering::Equal,
                        "rows {i} and {j} compare equal — order is not total"
                    );
                }
            }
        }
    }

    #[test]
    fn sparkline_bucket_keeps_spikes() {
        // A spike in any sample inside a bucket must survive to the glyph —
        // this is the whole reason buckets take the max instead of sampling.
        let mut data = vec![0u64; 78];
        data[40] = 1_000_000;
        let b = (0..SPARK_W)
            .map(|i| {
                let r = spark_bucket(i, data.len());
                data[r.start..r.end].iter().copied().max().unwrap_or(0)
            })
            .max()
            .unwrap();
        assert_eq!(b, 1_000_000, "the spike was sampled away");
    }

    #[test]
    fn window_label_converts_samples_to_wall_clock() {
        // A sample is one refresh tick, not one second. At the 1000ms default
        // the numbers coincide; at any other rate they must not.
        assert_eq!(window_label(78, 1000), "78s");
        assert_eq!(window_label(78, 500), "39s");
        assert_eq!(window_label(78, 2000), "3m");
        // The sparkline's window is its own depth, not the chart width.
        assert_eq!(window_label(30, 1000), "30s");
        assert_eq!(window_label(30, 500), "15s");
        // Never renders a zero-second window at the fastest refresh.
        assert_eq!(window_label(30, 100), "3s");
        assert_eq!(window_label(1, 100), "1s");
    }

    #[test]
    fn chart_and_sparkline_windows_are_labelled_independently() {
        // The bug this guards: reusing the chart width for the sparkline
        // header. They are different depths and must never print the same
        // number unless the depths genuinely coincide.
        let rate = 1000;
        let chart = window_label(CONTENT_W as usize, rate);
        let spark = window_label(crate::app::TOP_CONN_HISTORY_LEN, rate);
        assert_ne!(
            chart, spark,
            "chart and sparkline cover different windows and must be labelled separately"
        );
    }

    #[test]
    fn padding_anchors_the_newest_sample_to_the_right_edge() {
        // Short history left-pads with zeros so `now` lands on the right edge
        // under both bars (which right-aligns) and dots (which does not).
        let padded = pad_to_width(&[7, 8, 9], 6);
        assert_eq!(padded, vec![0, 0, 0, 7, 8, 9]);
        // Over-long history keeps the newest samples, not the oldest.
        assert_eq!(pad_to_width(&[1, 2, 3, 4, 5], 3), vec![3, 4, 5]);
        assert_eq!(pad_to_width(&[1, 2, 3], 3), vec![1, 2, 3]);
        assert!(pad_to_width(&[1, 2, 3], 0).is_empty());
    }

    #[test]
    fn bucketing_yields_exactly_one_value_per_sparkline_column() {
        // The graph module keeps only the last `width` samples, so the
        // bucketing has to hand it a pre-collapsed series of exactly SPARK_W.
        for len in [1usize, 5, 9, 30, 78, 600] {
            let data: Vec<u64> = (0..len as u64).collect();
            assert_eq!(
                bucket_history(&data).len(),
                SPARK_W as usize,
                "history of {len} produced the wrong column count"
            );
        }
    }
}
