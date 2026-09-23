//! NetWatch Dense — the high-density single-screen view.
//!
//! Four boxes tiling 130×44 with **no header bar, no menu bar and no status
//! bar**: identity, uptime, sort state, page range and every keybind live
//! inside the box borders, so all 44 rows carry content. The counterpart to
//! [`crate::ui::lite`], which spends its 80×24 answering one question — this
//! spends a big terminal showing everything at once.
//!
//! The networking-specific move is the **mirrored dual graph**: download grows
//! up from a centre axis, upload grows down from it, sharing one time scale.
//! Traffic symmetry becomes a shape you recognise instantly — a download burst
//! is a cliff above the line, a backup job is a cliff below it.
//!
//! Entered from the settings menu (`View`), by cycling with `V`, or with
//! `--view dense`. Opt-in only: the full tabbed TUI stays the default at every
//! terminal size, and nothing here changes what the other views show.
//!
//! ## The grid is authoritative
//!
//! Every constant below is transcribed from the design handoff
//! (`design_handoff_netwatch_2`, revised) and the tests at the bottom lock it:
//! columns must tile without overlapping, headers must sit over their own
//! data, and no graph or meter may run under the label that reads it. The
//! reference implementation shipped with a header 12 columns adrift of its
//! values and two meters painting under their own readouts; the invariant
//! tests exist so that class of drift cannot land here silently.
//!
//! Below 130×44 the view degrades to a 80×24 compact layout (the `ifaces` and
//! `health` boxes drop, the graphs halve); below that, to a too-small notice.
//! Degrading never scrolls horizontally and never moves a box that stayed.

pub mod paint;

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

use crate::app::App;
use crate::theme::Theme;
use crate::ui::widgets::{format_bytes_rate, format_bytes_total};
use paint::Ramps;

// ── the grid ────────────────────────────────────────────────────────────────

/// Minimum terminal for the full four-box layout. Above it the layout
/// **grows** — boxes take the whole terminal, plots get wider (and therefore
/// carry more history), tables get more rows and wider host columns. Below it
/// we fall back to the compact layout.
pub const GRID_W: u16 = 130;
/// See [`GRID_W`].
pub const GRID_H: u16 = 44;
/// The compact fallback, deliberately the same grid Lite targets.
pub const COMPACT_W: u16 = 80;
/// See [`COMPACT_W`].
pub const COMPACT_H: u16 = 24;

/// The `┤` tick every gutter scale label aligns to.
pub const GUTTER_TICK_X: u16 = 6;
/// Plots start here, leaving the scale gutter clear.
pub const CHART_X: u16 = 8;
/// Detail line 1 lays out in fixed columns so a long process name can't shove
/// the pid under the socket pair.
pub const DETAIL_PROC_W: u16 = 20;
pub const DETAIL_PID_X: u16 = 26;
pub const DETAIL_SOCKET_X: u16 = 38;
/// Where the detail row's rtt/retrans/protocol group starts.
pub const DETAIL_STATS_X: u16 = 48;
/// Widest the ASN / PoP label may render. Shared by the renderer and the
/// invariant test so the sparkline's clearance can't be argued about — one of
/// them alone would just be an assumption.
pub const ASN_LABEL_MAX: u16 = 20;
/// Widest the saturation readout gets: `100% of peak 1000M`.
pub const SAT_LABEL_MAX: u16 = 18;

/// Every row and column the full layout draws to, computed from the terminal.
///
/// The design handoff specifies a 130×44 grid, and the first cut hard-coded it
/// — which pinned four boxes into the corner of any larger terminal. The grid
/// is a *minimum*, so this resolves it against the real area instead: the
/// proportions are the design, the absolute numbers are not.
///
/// Everything downstream reads these fields; nothing re-derives a position.
/// Invariants (boxes abut, nothing overruns its readout, tables tile) are
/// asserted across a range of sizes in the tests, which is strictly stronger
/// than the constant-vs-constant checks the fixed grid allowed.
/// One of the four boxes, for zooming it to the whole screen.
///
/// The number on each box's top border was a label; now it is the key. Press
/// it and that box takes the full grid — the 60-second chart at forty rows,
/// every interface instead of the first six, the whole connection list.
/// Press it again, or `Esc`, to restore the grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenseBox {
    Net,
    Ifaces,
    Health,
    Conns,
}

impl DenseBox {
    /// The box a number key names, matching the badge on its border.
    pub fn from_key(c: char) -> Option<Self> {
        match c {
            '1' => Some(Self::Net),
            '2' => Some(Self::Ifaces),
            '3' => Some(Self::Health),
            '4' => Some(Self::Conns),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Layout {
    pub net: Rect,
    pub ifaces: Rect,
    pub health: Rect,
    pub conns: Rect,

    // net
    pub row_down_label: u16,
    pub row_down_chart: u16,
    pub down_chart_h: u16,
    pub row_axis: u16,
    pub row_up_chart: u16,
    pub up_chart_h: u16,
    pub row_up_label: u16,
    pub chart_w: u16,

    // ifaces
    pub row_if_head: u16,
    pub row_if_first: u16,
    pub if_rows: u16,
    pub row_if_rule: u16,
    pub row_if_agg: u16,
    pub row_if_sat: u16,
    pub sat_meter_x: u16,
    pub sat_meter_w: u16,

    // health
    pub row_hop_head: u16,
    pub row_hop_first: u16,
    pub hop_rows: u16,
    pub row_health_rule: u16,
    pub row_kv_first: u16,
    pub row_verdict_1: u16,
    pub row_verdict_2: u16,
    pub hop_meter_x: u16,
    pub hop_meter_w: u16,

    // conns
    pub row_detail_1: u16,
    pub row_detail_2: u16,
    pub row_detail_3: u16,
    pub row_conn_head: u16,
    pub row_conn_first: u16,
    pub conn_rows: u16,
    pub detail_spark_x: u16,
    pub detail_spark_w: u16,

    /// Last column any content may touch (one clear cell before the border).
    pub content_x_end: u16,
    pub conn_cols: Vec<Col>,
    pub if_cols: Vec<Col>,
}

impl Layout {
    /// The four-box grid.
    pub fn new(area: Rect) -> Self {
        let w = area.width;
        let h = area.height;

        // Vertical thirds, roughly as drawn: the graph gets the most, the
        // middle row the least, the connection list takes what's left so the
        // last row is always used.
        let net_h = ((h as u32 * 36 / 100) as u16).max(16);
        let mid_h = ((h as u32 * 27 / 100) as u16).max(12);
        let conns_h = h - net_h - mid_h;

        let net = Rect::new(0, 0, w, net_h);
        // The extra width is split with a bias toward `ifaces`, whose rows end
        // in a sparkline that keeps getting better with room; `health` is
        // mostly fixed-width readouts.
        let if_w = 68 + (w.saturating_sub(GRID_W) * 55 / 100);
        let ifaces = Rect::new(0, net_h, if_w, mid_h);
        let health = Rect::new(if_w, net_h, w - if_w, mid_h);
        let conns = Rect::new(0, net_h + mid_h, w, conns_h);
        Self::from_boxes(area, net, ifaces, health, conns)
    }

    /// One box on the whole screen, the other three empty.
    ///
    /// An empty box is a zero-size rect: the renderers skip it, and the row
    /// arithmetic below saturates rather than assuming every box has a
    /// border to sit inside.
    pub fn zoomed(area: Rect, which: DenseBox) -> Self {
        let full = Rect::new(0, 0, area.width, area.height);
        let none = Rect::default();
        let pick = |b: DenseBox| if b == which { full } else { none };
        Self::from_boxes(
            area,
            pick(DenseBox::Net),
            pick(DenseBox::Ifaces),
            pick(DenseBox::Health),
            pick(DenseBox::Conns),
        )
    }

    fn from_boxes(area: Rect, net: Rect, ifaces: Rect, health: Rect, conns: Rect) -> Self {
        let w = area.width;
        let net_h = net.height;
        let mid_h = ifaces.height.max(health.height);
        let conns_h = conns.height;
        let if_w = ifaces.width;

        // Inside `net`: label, download plot, axis, upload plot, label. The
        // two plots split what's left, download taking the odd row — it is the
        // one you watch.
        let plot_rows = net_h.saturating_sub(5);
        let down_chart_h = plot_rows.div_ceil(2);
        let up_chart_h = plot_rows - down_chart_h;
        let row_down_chart = net.y + 2;
        let row_axis = row_down_chart + down_chart_h;

        let content_x_end = w - 3;
        let mid_bottom = (ifaces.y.max(health.y) + mid_h).saturating_sub(1);

        // Inside `ifaces`: header, rows, rule, aggregate, saturation.
        let row_if_head = ifaces.y + 1;
        let row_if_sat = mid_bottom.saturating_sub(1);
        let row_if_agg = row_if_sat.saturating_sub(1);
        let row_if_rule = row_if_agg.saturating_sub(1);
        let row_if_first = row_if_head + 1;
        let if_rows = row_if_rule.saturating_sub(row_if_first);

        // Inside `health`: header, hops, rule, a 2×2 grid, two verdict lines.
        // There are exactly four hops, so the block is top-anchored and the
        // rule sits directly under it. Anchoring the rule to the bottom
        // instead leaves a blank band across the middle of a tall box, which
        // reads as a rendering fault rather than as spare room.
        let row_hop_head = health.y + 1;
        let row_hop_first = row_hop_head + 1;
        let hop_rows = 4;
        let row_health_rule = row_hop_first + hop_rows;
        let row_kv_first = row_health_rule + 1;
        let row_verdict_1 = row_kv_first + 2;
        let row_verdict_2 = row_verdict_1 + 1;
        debug_assert!(health.height == 0 || row_verdict_2 < mid_bottom);

        // Inside `conns`: three detail rows, header, then the list to the
        // bottom border.
        let row_detail_1 = conns.y + 1;
        let row_conn_head = row_detail_1 + 3;
        let row_conn_first = row_conn_head + 1;
        let conn_rows = (conns.y + conns_h)
            .saturating_sub(1)
            .saturating_sub(row_conn_first);

        let detail_spark_x = 13;
        let detail_spark_w = content_x_end
            .saturating_sub(ASN_LABEL_MAX + 2)
            .saturating_sub(detail_spark_x)
            + 1;

        Self {
            net,
            ifaces,
            health,
            conns,
            row_down_label: net.y + 1,
            row_down_chart,
            down_chart_h,
            row_axis,
            row_up_chart: row_axis + 1,
            up_chart_h,
            row_up_label: row_axis + 1 + up_chart_h,
            chart_w: w - CHART_X - 2,
            row_if_head,
            row_if_first,
            if_rows,
            row_if_rule,
            row_if_agg,
            row_if_sat,
            sat_meter_x: 13,
            sat_meter_w: if_w
                .saturating_sub(2)
                .saturating_sub(SAT_LABEL_MAX + 13 + 2),
            row_hop_head,
            row_hop_first,
            hop_rows,
            row_health_rule,
            row_kv_first,
            row_verdict_1,
            row_verdict_2,
            hop_meter_x: (health.x + health.width).saturating_sub(22),
            hop_meter_w: 20,
            row_detail_1,
            row_detail_2: row_detail_1 + 1,
            row_detail_3: row_detail_1 + 2,
            row_conn_head,
            row_conn_first,
            conn_rows,
            detail_spark_x,
            detail_spark_w,
            content_x_end,
            conn_cols: conn_cols(w),
            if_cols: if_cols(if_w),
        }
    }
}

// ── column tables ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    Left,
    Right,
}

/// One table column: where it starts, how wide it is, and the header that must
/// sit over it.
///
/// Header and data are both drawn from this — [`header`] and [`cell`] are the
/// only two ways anything reaches a table row. That is deliberate: the design
/// reference kept its headers in a hand-aligned string literal and they drifted
/// 12 columns off the values, which no amount of care in the row renderer can
/// catch.
#[derive(Debug, Clone, Copy)]
pub struct Col {
    pub x: u16,
    pub w: u16,
    pub align: Align,
    pub label: &'static str,
}

impl Col {
    pub const fn x_end(&self) -> u16 {
        self.x + self.w - 1
    }
}

const fn left(x: u16, w: u16, label: &'static str) -> Col {
    Col {
        x,
        w,
        align: Align::Left,
        label,
    }
}

const fn right(x: u16, w: u16, label: &'static str) -> Col {
    Col {
        x,
        w,
        align: Align::Right,
        label,
    }
}

/// Named indices into [`CONN_COLS`]. Use these rather than magic numbers, the
/// same way `ui::settings::cursor` names its rows.
pub mod conn_col {
    pub const MARK: usize = 0;
    pub const PROC: usize = 1;
    pub const PID: usize = 2;
    pub const HOST: usize = 3;
    pub const PORT: usize = 4;
    pub const PROTO: usize = 5;
    pub const DOWN: usize = 6;
    pub const UP: usize = 7;
    pub const RTT: usize = 8;
    pub const STATE: usize = 9;
    pub const SPARK: usize = 10;
}

/// Connection table columns for a terminal `w` wide.
///
/// Fixed up to `PROTO`; the extra width goes to `REMOTE` (hostnames are what
/// actually get cut) and to the sparkline (more history at the same glance).
/// Rates, RTT and state keep their widths — a number column gains nothing from
/// being wider, and moving them would only make the eye re-find them.
pub fn conn_cols(w: u16) -> Vec<Col> {
    let extra = w.saturating_sub(GRID_W);
    let host_extra = extra * 2 / 5;
    let shift = host_extra;
    let spark_x = 111 + shift;
    let content_x_end = w - 3;
    vec![
        left(2, 1, ""),
        left(4, 13, "PROCESS"),
        right(18, 5, "PID"),
        left(25, 30 + host_extra, "REMOTE"),
        right(57 + shift, 5, "PORT"),
        left(64 + shift, 5, "PROTO"),
        right(73 + shift, 8, "DOWN"),
        right(83 + shift, 8, "UP"),
        right(93 + shift, 7, "RTT"),
        left(102 + shift, 8, "STATE"),
        left(spark_x, content_x_end.saturating_sub(spark_x) + 1, "60s"),
    ]
}

pub mod if_col {
    pub const MARK: usize = 0;
    pub const NAME: usize = 1;
    pub const STATE: usize = 2;
    pub const DOWN: usize = 3;
    pub const UP: usize = 4;
    pub const ERRORS: usize = 5;
    pub const SPARK: usize = 6;
}

/// Interface table columns for an `ifaces` box `box_w` wide. All the extra
/// width goes to the sparkline, which is the only column that improves with it.
pub fn if_cols(box_w: u16) -> Vec<Col> {
    let spark_x = 51;
    // One cell clear of the box border.
    let spark_end = box_w.saturating_sub(3);
    vec![
        left(2, 1, ""),
        left(4, 10, "IFACE"),
        left(15, 6, "STATE"),
        right(22, 9, "DOWN"),
        right(32, 9, "UP"),
        right(43, 6, "ERR"),
        left(spark_x, spark_end.saturating_sub(spark_x) + 1, "60s"),
    ]
}

pub mod cpt_col {
    pub const MARK: usize = 0;
    pub const PROC: usize = 1;
    pub const HOST: usize = 2;
    pub const DOWN: usize = 3;
    pub const UP: usize = 4;
    pub const RTT: usize = 5;
    pub const SPARK: usize = 6;
}

pub const CPT_COLS: &[Col] = &[
    left(2, 1, ""),
    left(4, 13, "PROCESS"),
    left(18, 19, "REMOTE"),
    right(38, 8, "DOWN"),
    right(48, 8, "UP"),
    right(58, 6, "RTT"),
    left(66, 12, "60s"),
];

// ── compact layout (80×24) ──────────────────────────────────────────────────

/// The compact layout, computed the same way the full one is: the 80×24 grid
/// is a floor, not a frame. A terminal between the two sizes still gets its
/// whole area used.
#[derive(Debug, Clone)]
pub struct CompactLayout {
    pub net: Rect,
    pub conns: Rect,
    pub row_down_label: u16,
    pub row_down_chart: u16,
    pub chart_h: u16,
    pub row_axis: u16,
    pub row_up_chart: u16,
    pub row_up_label: u16,
    pub chart_w: u16,
    pub row_head: u16,
    pub row_first: u16,
    pub rows: u16,
    pub x_end: u16,
    pub cols: Vec<Col>,
}

pub const CPT_CHART_X: u16 = 4;

impl CompactLayout {
    pub fn new(area: Rect) -> Self {
        let (w, h) = (area.width, area.height);
        let net_h = ((h as u32 * 46 / 100) as u16).max(11);
        let conns_h = h - net_h;
        let plot_rows = net_h - 5;
        let chart_h = plot_rows / 2;
        let row_down_chart = 2;
        let row_axis = row_down_chart + chart_h;
        let row_head = net_h + 1;
        let row_first = row_head + 1;
        Self {
            net: Rect::new(0, 0, w, net_h),
            conns: Rect::new(0, net_h, w, conns_h),
            row_down_label: 1,
            row_down_chart,
            chart_h,
            row_axis,
            row_up_chart: row_axis + 1,
            row_up_label: net_h - 2,
            chart_w: w - CPT_CHART_X - 2,
            row_head,
            row_first,
            rows: net_h + conns_h - 1 - row_first,
            x_end: w - 3,
            cols: cpt_cols(w),
        }
    }
}

/// Compact connection columns; the extra width goes to the host and the
/// sparkline, as in the full layout.
pub fn cpt_cols(w: u16) -> Vec<Col> {
    let extra = w.saturating_sub(COMPACT_W);
    let host_extra = extra * 2 / 5;
    let shift = host_extra;
    let spark_x = 66 + shift;
    let x_end = w - 3;
    vec![
        left(2, 1, ""),
        left(4, 13, "PROCESS"),
        left(18, 19 + host_extra, "REMOTE"),
        right(38 + shift, 8, "DOWN"),
        right(48 + shift, 8, "UP"),
        right(58 + shift, 6, "RTT"),
        left(spark_x, x_end.saturating_sub(spark_x) + 1, "60s"),
    ]
}

// ── data shaping ────────────────────────────────────────────────────────────

/// The most recent `out` samples, oldest-first, left-padded when there aren't
/// enough yet.
///
/// One sample per sub-column, so each tick shifts the plot by exactly one
/// sub-column and it **scrolls**. The first cut bucketed the *entire* 600-sample
/// history into however many sub-columns the plot had, which meant every tick
/// re-divided all 600 samples into new buckets and redrew every column — the
/// plot churned in place instead of moving, which is what read as jitter. It
/// also quietly disagreed with the axis: the label said `2m` while the plot
/// showed five minutes squeezed into the same width.
pub fn fit_samples(data: &[u64], out: usize) -> Vec<u64> {
    if out == 0 {
        return Vec::new();
    }
    if data.len() >= out {
        return data[data.len() - out..].to_vec();
    }
    let mut v = vec![0u64; out - data.len()];
    v.extend_from_slice(data);
    v
}

/// The last `window` samples bucketed into `out` sub-columns, taking the
/// **max** of each bucket.
///
/// For plots whose header claims a fixed span — the `60s` sparkline in the
/// interface table — where the column is far narrower than the window. Max per
/// bucket rather than decimation so a spike inside a bucket survives; dropping
/// it would hide the one thing worth seeing in a 15-cell graph.
pub fn fit_window(data: &[u64], window: usize, out: usize) -> Vec<u64> {
    if out == 0 {
        return Vec::new();
    }
    let start = data.len().saturating_sub(window.max(1));
    let win = &data[start..];
    if win.len() <= out {
        return fit_samples(win, out);
    }
    (0..out)
        .map(|i| {
            let a = i * win.len() / out;
            let b = ((i + 1) * win.len() / out).max(a + 1);
            win[a..b.min(win.len())].iter().copied().max().unwrap_or(0)
        })
        .collect()
}

/// How many samples cover `secs` of wall clock, given the refresh interval.
/// History gains one sample per refresh tick, not per second.
fn samples_for_secs(secs: u64, refresh_rate_ms: u64) -> usize {
    ((secs * 1000) / refresh_rate_ms.max(1)).max(1) as usize
}

/// The plot's ceiling, rounded up to something a human reads as a scale.
///
/// An auto-scaling graph is a lie unless it prints its ceiling, so this value
/// is always rendered in the gutter — see [`scale_labels`].
fn chart_max(samples: &[u64]) -> u64 {
    nice_ceiling(samples.iter().copied().max().unwrap_or(0))
}

/// Round a ceiling up to 1, 2 or 5 × a power of ten.
///
/// A plot scaled to its exact maximum rescales every time that maximum moves,
/// so the whole graph jumps vertically while the traffic underneath it is
/// doing nothing unusual. Snapping to round numbers means the scale only
/// changes when the traffic changes by an order of magnitude — and it is why
/// the gutter can read `512M / 256M / 0` instead of `437K / 218K / 0`.
fn nice_ceiling(max: u64) -> u64 {
    if max == 0 {
        return 1;
    }
    let mut mag = 1u64;
    while mag <= max / 10 {
        mag = mag.saturating_mul(10);
    }
    for step in [1, 2, 5, 10] {
        if let Some(c) = mag.checked_mul(step) {
            if c >= max {
                return c;
            }
        }
    }
    max
}

/// Three gutter labels for a plot scaled to `max`: top, middle, zero.
fn scale_labels(max: u64) -> [String; 3] {
    [short_bytes(max), short_bytes(max / 2), "0".to_string()]
}

/// Compact byte scale for the 4-cell gutter: `512M`, `1.2G`, `0`.
fn short_bytes(n: u64) -> String {
    const K: f64 = 1000.0;
    let v = n as f64;
    if v >= K * K * K {
        format!("{:.0}G", v / (K * K * K))
    } else if v >= K * K {
        format!("{:.0}M", v / (K * K))
    } else if v >= K {
        format!("{:.0}K", v / K)
    } else {
        format!("{v:.0}")
    }
}

/// Mean and standard deviation of the observed samples, ignoring gaps.
fn mean_sigma<'a>(v: impl IntoIterator<Item = &'a Option<f64>>) -> Option<(f64, f64)> {
    let xs: Vec<f64> = v.into_iter().filter_map(|x| *x).collect();
    if xs.is_empty() {
        return None;
    }
    let mean = xs.iter().sum::<f64>() / xs.len() as f64;
    let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / xs.len() as f64;
    Some((mean, var.sqrt()))
}

/// One row of the interface table.
struct IfRow {
    name: String,
    state: &'static str,
    rx_rate: f64,
    tx_rate: f64,
    /// rx + tx errors. The design's per-interface RTT has no source on any
    /// platform netwatch supports, and a column that reads `--` on every row
    /// forever is worse than one carrying a fact.
    errors: u64,
    history: Vec<u64>,
}

/// One row of the connection table.
struct ConnRow {
    process: String,
    pid: Option<u32>,
    host: String,
    port: String,
    proto: String,
    rx_rate: f64,
    tx_rate: f64,
    rtt_ms: Option<f64>,
    state: String,
    retransmits: u32,
    out_of_order: u32,
    app_proto: Option<String>,
    local: String,
    remote: String,
    history: Vec<u64>,
}

impl ConnRow {
    /// A row nobody is talking on any more. Dims out rather than disappearing —
    /// it is still a socket, it is just done.
    fn is_dead(&self) -> bool {
        matches!(
            self.state.as_str(),
            "TIME_WAIT" | "CLOSE_WAIT" | "CLOSED" | "FIN_WAIT1" | "FIN_WAIT2" | "LAST_ACK"
        )
    }

    /// The rate the table sorts on: the flow's recent average, not this tick's
    /// reading.
    ///
    /// Sorting on the instantaneous rate makes the list dance. Two flows of
    /// similar speed trade places every tick as their samples jitter, and
    /// because the selection is an index rather than an identity, the detail
    /// block above retargets to a different connection each time it happens —
    /// measured at three swaps in five ticks with two active downloads.
    ///
    /// Averaging the last few samples is enough to settle it, and it is also
    /// the more honest answer to "which flow is busiest": a single 250 ms
    /// sample is noise, and the column header says `DOWN`, which is what this
    /// history records.
    fn sort_rate(&self) -> f64 {
        const WINDOW: usize = 8;
        if self.history.is_empty() {
            return self.rx_rate;
        }
        let tail = &self.history[self.history.len().saturating_sub(WINDOW)..];
        tail.iter().map(|v| *v as f64).sum::<f64>() / tail.len() as f64
    }
}

fn collect_ifaces(app: &App) -> Vec<IfRow> {
    let ifaces = app.traffic.interfaces();
    let mut rows: Vec<IfRow> = ifaces
        .iter()
        .map(|i| {
            let up = app
                .interface_info
                .iter()
                .find(|inf| inf.name == i.name)
                .map(|inf| inf.is_up)
                .unwrap_or(false);
            let active = i.rx_rate > 0.0 || i.tx_rate > 0.0;
            let state = if !up {
                "down"
            } else if active {
                "up"
            } else {
                "idle"
            };
            IfRow {
                name: i.name.clone(),
                state,
                rx_rate: i.rx_rate,
                tx_rate: i.tx_rate,
                errors: i.rx_errors + i.tx_errors,
                history: i.rx_history.iter().copied().collect(),
            }
        })
        .collect();
    // Busiest first: the interface carrying your traffic is the one you came
    // to look at. Name breaks ties so an idle host doesn't reshuffle each tick.
    rows.sort_by(|a, b| {
        (b.rx_rate + b.tx_rate)
            .partial_cmp(&(a.rx_rate + a.tx_rate))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.name.cmp(&b.name))
    });
    rows
}

fn collect_conns(app: &App) -> Vec<ConnRow> {
    let conns = app.connection_collector.connections();
    let mut rows: Vec<ConnRow> = conns
        .iter()
        .filter(|c| {
            c.state != "LISTEN"
                && c.state != "CLOSED"
                && !c.remote_addr.is_empty()
                && !c.remote_addr.starts_with('*')
                && !c.remote_addr.starts_with("0.0.0.0")
        })
        .map(|c| {
            let (addr_host, port) = split_host_port(&c.remote_addr);
            let process = c.process_name.clone().unwrap_or_else(|| "—".into());
            // The history cache is keyed by the *writer's* spelling of the
            // host, brackets and all — use its own function rather than a
            // second implementation that agrees only for IPv4.
            let host_key = crate::app::top_conn_host(&c.remote_addr);
            let history = app
                .caches
                .top_conn_history
                .get(&(process.clone(), host_key.clone()))
                .map(|h| h.iter().copied().collect())
                .unwrap_or_default();
            // Show the name the connection asked for, falling back to the
            // address. Same rule as Lite: an IP is what you show when you
            // don't know better, not what you show by default.
            // Display uses the bracket-trimmed address, not the cache key:
            // macOS lsof prints IPv6 as `fe80::1]:1024`, so the key legitimately
            // carries a stray `]` that must not reach the screen.
            let host = crate::ui::lite::sni_of(c).unwrap_or(addr_host);
            ConnRow {
                process,
                pid: c.pid,
                host,
                port,
                proto: c.protocol.to_lowercase(),
                rx_rate: c.rx_rate.unwrap_or(0.0),
                tx_rate: c.tx_rate.unwrap_or(0.0),
                rtt_ms: c.handshake_rtt_us.map(|us| us / 1000.0),
                state: c.state.clone(),
                retransmits: c.retransmits,
                out_of_order: c.out_of_order,
                app_proto: c
                    .app_protocol
                    .as_ref()
                    .map(|_| crate::ui::connections::render_app_protocol(&c.app_protocol)),
                local: c.local_addr.clone(),
                remote: c.remote_addr.clone(),
                history,
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        b.sort_rate()
            .partial_cmp(&a.sort_rate())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.process.cmp(&b.process))
            .then_with(|| a.host.cmp(&b.host))
            .then_with(|| a.port.cmp(&b.port))
    });
    rows
}

// ── grouped connection list ─────────────────────────────────────────────────
//
// The same tree the Connections tab and the Dashboard draw: one parent row per
// process carrying the rollup, children foldable beneath it. A flat list here
// spent the PROCESS column repeating `claude` down twenty rows, and the box is
// the shortest of the four — the one place that can least afford it.

/// What a process's header row says about its sockets.
struct ConnRollup {
    conns: usize,
    pids: usize,
    hosts: usize,
    rx_rate: f64,
    tx_rate: f64,
    /// Best (lowest) handshake RTT in the group.
    rtt_ms: Option<f64>,
    /// Any member with retransmits — a rollup must not hide a problem a child
    /// row would show.
    degraded: bool,
    /// Every member finished: the header dims like a dead row would.
    dead: bool,
    /// Dominant state, so the STATE column says something for the group.
    state: String,
    /// Members' sparklines summed, aligned at now.
    history: Vec<u64>,
}

type ConnGroup = crate::ui::tree::Group<ConnRollup, ConnRow>;

/// One line of the conns table.
enum DenseRow<'a> {
    /// A process with several sockets: the rollup, foldable.
    Parent {
        group: &'a ConnGroup,
        collapsed: bool,
    },
    /// A process with exactly one socket: the socket itself. A header that
    /// reveals a single child is a keystroke to learn nothing.
    Solo {
        group: &'a ConnGroup,
        conn: &'a ConnRow,
    },
    Child {
        group: &'a ConnGroup,
        conn: &'a ConnRow,
    },
}

impl<'a> DenseRow<'a> {
    fn key(&self) -> &'a str {
        match self {
            DenseRow::Parent { group, .. }
            | DenseRow::Solo { group, .. }
            | DenseRow::Child { group, .. } => &group.key,
        }
    }

    fn conn(&self) -> Option<&'a ConnRow> {
        match self {
            DenseRow::Solo { conn, .. } | DenseRow::Child { conn, .. } => Some(conn),
            DenseRow::Parent { .. } => None,
        }
    }

    fn foldable(&self) -> bool {
        !matches!(self, DenseRow::Solo { .. })
    }
}

fn rollup(conns: &[ConnRow]) -> ConnRollup {
    let pids: std::collections::BTreeSet<Option<u32>> = conns.iter().map(|c| c.pid).collect();
    let hosts: std::collections::BTreeSet<&str> = conns.iter().map(|c| c.host.as_str()).collect();
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for c in conns {
        *counts.entry(c.state.as_str()).or_insert(0) += 1;
    }
    let state = counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(a.0)))
        .map(|(s, _)| s.to_string())
        .unwrap_or_default();
    // Histories all end at now; sum them aligned at the right edge.
    let len = conns.iter().map(|c| c.history.len()).max().unwrap_or(0);
    let mut history = vec![0u64; len];
    for c in conns {
        let off = len - c.history.len();
        for (i, v) in c.history.iter().enumerate() {
            history[off + i] += v;
        }
    }
    ConnRollup {
        conns: conns.len(),
        pids: pids.len(),
        hosts: hosts.len(),
        rx_rate: conns.iter().map(|c| c.rx_rate).sum(),
        tx_rate: conns.iter().map(|c| c.tx_rate).sum(),
        rtt_ms: conns
            .iter()
            .filter_map(|c| c.rtt_ms)
            .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)),
        degraded: conns.iter().any(|c| c.retransmits > 0),
        dead: conns.iter().all(|c| c.is_dead()),
        state,
        history,
    }
}

/// Group the sorted rows by process, busiest group first.
fn conn_groups(rows: Vec<ConnRow>) -> Vec<ConnGroup> {
    let mut groups: Vec<ConnGroup> =
        crate::ui::tree::group_by(rows, |c: &ConnRow| c.process.clone())
            .into_iter()
            .map(|(key, children)| ConnGroup {
                key,
                rollup: rollup(&children),
                children,
            })
            .collect();
    groups.sort_by(|a, b| {
        (b.rollup.rx_rate + b.rollup.tx_rate)
            .partial_cmp(&(a.rollup.rx_rate + a.rollup.tx_rate))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.key.cmp(&b.key))
    });
    groups
}

/// The visible rows, honouring fold state. Single definition of "what is
/// row N" for the renderer and the key handlers.
fn dense_rows<'a>(groups: &'a [ConnGroup], fold: &crate::ui::tree::FoldState) -> Vec<DenseRow<'a>> {
    let mut rows = Vec::new();
    for group in groups {
        if let [conn] = group.children.as_slice() {
            rows.push(DenseRow::Solo { group, conn });
            continue;
        }
        let collapsed = fold.is_collapsed(&group.key);
        rows.push(DenseRow::Parent { group, collapsed });
        if !collapsed {
            rows.extend(
                group
                    .children
                    .iter()
                    .map(|conn| DenseRow::Child { group, conn }),
            );
        }
    }
    rows
}

/// Rows the conns box currently lists, for clamping the cursor.
pub fn visible_conn_count(app: &App) -> usize {
    dense_rows(&conn_groups(collect_conns(app)), &app.ui.dense_collapsed).len()
}

/// The process under the cursor, if its group folds — from a child row as
/// well as the header. `None` on a solo row, so the key is a no-op rather
/// than a fold state that surfaces later when that process opens a second
/// socket.
pub fn selected_conn_group(app: &App) -> Option<String> {
    let groups = conn_groups(collect_conns(app));
    let rows = dense_rows(&groups, &app.ui.dense_collapsed);
    let idx = app
        .ui
        .scroll
        .connection_scroll
        .min(rows.len().saturating_sub(1));
    let row = rows.get(idx)?;
    row.foldable().then(|| row.key().to_string())
}

/// Row index of `process`'s header, so a collapse can park the cursor on the
/// row it just folded rather than on whatever slid up into its place.
pub fn conn_header_index(app: &App, process: &str) -> Option<usize> {
    let groups = conn_groups(collect_conns(app));
    dense_rows(&groups, &app.ui.dense_collapsed)
        .iter()
        .position(|r| matches!(r, DenseRow::Parent { group, .. } if group.key == process))
}

/// Split an address into host and port.
///
/// Has to cope with everything the platforms actually print, not just the
/// well-formed cases: `1.2.3.4:443`, `[::1]:443`, and — from macOS `lsof` —
/// `fe80::1]:1024`, an IPv6 address with a closing bracket and no opening one.
/// The first cut required the opening bracket, so those rows put the entire
/// address in the host column and left the port blank.
fn split_host_port(addr: &str) -> (String, String) {
    let trim = |h: &str| h.trim_start_matches('[').trim_end_matches(']').to_string();

    if let Some(i) = addr.rfind("]:") {
        return (trim(&addr[..i]), addr[i + 2..].to_string());
    }
    if let Some(i) = addr.rfind(':') {
        let (host, port) = (&addr[..i], &addr[i + 1..]);
        // Only split a bracketless address when the head is unambiguous —
        // otherwise `::1` would lose its last group to a "port".
        if !host.contains(':') && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
            return (trim(host), port.to_string());
        }
    }
    (trim(addr), String::new())
}

// ── drawing helpers ─────────────────────────────────────────────────────────

/// Draw a value into its column, honouring the column's alignment.
///
/// Overlong values are elided with `…` rather than hard-cut, and measured by
/// display width so a CJK process name doesn't push the next column right.
fn cell(f: &mut Frame, col: &Col, y: u16, s: &str, style: Style) {
    let s = truncate(s, col.w as usize);
    let w = s.width() as u16;
    let x = match col.align {
        Align::Left => col.x,
        Align::Right => col.x + col.w.saturating_sub(w),
    };
    f.buffer_mut().set_stringn(x, y, &s, col.w as usize, style);
}

/// Draw a table's header row from the same columns its data uses.
///
/// `sort` brightens the active column — btop's move, and the reason you never
/// have to wonder what you're sorted by. Because it names a column rather than
/// a screen position, it cannot land on a neighbouring label.
fn header(f: &mut Frame, y: u16, cols: &[Col], sort: Option<usize>, t: &Theme) {
    for (i, c) in cols.iter().enumerate() {
        if c.label.is_empty() {
            continue;
        }
        let style = if Some(i) == sort {
            Style::default().fg(t.brand).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(t.text_muted)
        };
        cell(f, c, y, c.label, style);
    }
}

fn put(f: &mut Frame, x: u16, y: u16, s: &str, style: Style) {
    let area = f.size();
    if x >= area.width || y >= area.height {
        return;
    }
    f.buffer_mut()
        .set_stringn(x, y, s, (area.width - x) as usize, style);
}

fn put_right(f: &mut Frame, x_end: u16, y: u16, s: &str, style: Style) {
    let w = s.width() as u16;
    put(f, x_end.saturating_sub(w.saturating_sub(1)), y, s, style);
}

fn truncate(s: &str, max: usize) -> String {
    if s.width() <= max {
        return s.to_string();
    }
    if max <= 1 {
        return "…".to_string();
    }
    let mut out = String::new();
    let mut used = 0;
    for ch in s.chars() {
        let cw = ch.to_string().width();
        if used + cw > max - 1 {
            break;
        }
        out.push(ch);
        used += cw;
    }
    out.push('…');
    out
}

/// Abbreviate a TCP state to fit its column without eliding.
///
/// `ESTABLISHED` in an 8-wide column renders `ESTABLI…`, which is noise on
/// every row. These are the spellings `ss` and `netstat` readers already know.
fn short_state(state: &str) -> &str {
    match state {
        "ESTABLISHED" => "ESTAB",
        "TIME_WAIT" => "TIME_W",
        "CLOSE_WAIT" => "CLOSE_W",
        "FIN_WAIT1" => "FIN_W1",
        "FIN_WAIT2" => "FIN_W2",
        "SYN_SENT" => "SYN_S",
        "SYN_RECV" | "SYN_RECEIVED" => "SYN_R",
        "LAST_ACK" => "LAST_A",
        other => other,
    }
}

/// How much room the detail row's stats group has before it would collide
/// with the right-aligned TCP internals, leaving a two-cell gap.
fn detail_stats_width(l: &Layout, internals_w: u16) -> u16 {
    l.content_x_end
        .saturating_sub(internals_w)
        .saturating_sub(DETAIL_STATS_X + 2)
}

/// Unavailable values render as a dim `--` in place, never as a blank or a
/// zero: a missing measurement and a measured zero are different facts.
const NA: &str = "--";

fn rtt_str(rtt: Option<f64>) -> String {
    match rtt {
        Some(ms) if ms < 10.0 => format!("{ms:.1}ms"),
        Some(ms) => format!("{ms:.0}ms"),
        None => NA.to_string(),
    }
}

// ── render ──────────────────────────────────────────────────────────────────

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    if area.width >= GRID_W && area.height >= GRID_H {
        render_full(f, app, area);
    } else if area.width >= COMPACT_W && area.height >= COMPACT_H {
        render_compact(f, app, area);
    } else {
        render_too_small(f, app, area);
    }
}

fn render_too_small(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let p = Paragraph::new(vec![
        Line::from(Span::styled(
            "terminal too small for the dense view",
            Style::default().fg(t.status_warn),
        )),
        Line::from(Span::styled(
            format!(
                "need {COMPACT_W}×{COMPACT_H}, have {}×{}",
                area.width, area.height
            ),
            Style::default().fg(t.text_muted),
        )),
        Line::from(Span::styled(
            "V cycles back to the full view",
            Style::default().fg(t.text_muted),
        )),
    ]);
    f.render_widget(p, area);
}

fn render_full(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let ramps = Ramps::from_theme(t);
    let l = match app.ui.dense_zoom {
        None => Layout::new(area),
        Some(which) => Layout::zoomed(area, which),
    };
    let shown = |r: Rect| r.width > 0 && r.height > 0;
    if shown(l.net) {
        render_net(f, app, t, &ramps, &l);
    }
    if shown(l.ifaces) {
        render_ifaces(f, app, t, &ramps, &l);
    }
    if shown(l.health) {
        render_health(f, app, t, &ramps, &l);
    }
    if shown(l.conns) {
        render_conns(f, app, t, &ramps, &l);
    }
}

/// The bottom-border hint for a box's number key: `zoom` on the grid,
/// `restore` once that box fills the screen. Every box carries it, because
/// when one is zoomed it is the only border on screen.
fn zoom_bind(app: &App, which: DenseBox) -> paint::Bind<'static> {
    if app.ui.dense_zoom == Some(which) {
        ("esc", " restore")
    } else {
        ("1-4", " zoom")
    }
}

// ── box 1: net ──────────────────────────────────────────────────────────────

fn render_net(f: &mut Frame, app: &App, t: &Theme, ramps: &Ramps, l: &Layout) {
    let ifaces = app.traffic.interfaces();
    let iface = ifaces.iter().find(|i| i.name == app.capture_interface);

    let rx_hist: Vec<u64> = iface
        .map(|i| i.rx_history.iter().copied().collect())
        .unwrap_or_default();
    let tx_hist: Vec<u64> = iface
        .map(|i| i.tx_history.iter().copied().collect())
        .unwrap_or_default();
    let samples = l.chart_w as usize * 2;
    let rx = fit_samples(&rx_hist, samples);
    let tx = fit_samples(&tx_hist, samples);
    let rx_max = chart_max(&rx);
    let tx_max = chart_max(&tx);

    let degraded = is_degraded(app);
    let sub = if degraded {
        format!("{} · degraded", app.capture_interface)
    } else {
        app.capture_interface.clone()
    };
    let right = format!("netwatch {}", env!("CARGO_PKG_VERSION"));
    let paused = app.ui.paused;

    let inner_opts = paint::PanelOpts {
        key: Some("1"),
        title: Some("net"),
        sub: Some(&sub),
        right: Some(&right),
        right_style: Some(Style::default().fg(if degraded {
            t.status_error
        } else {
            t.text_muted
        })),
        foot_left: &[
            zoom_bind(app, DenseBox::Net),
            ("V", " view"),
            ("p", "ause"),
            ("q", "uit"),
        ],
        foot_right: None,
    };
    paint::panel(f.buffer_mut(), l.net, t, &inner_opts);

    // ── download half ──
    let dim = Style::default().fg(t.text_muted);
    let rate_style = Style::default()
        .fg(t.text_primary)
        .add_modifier(Modifier::BOLD);
    put(
        f,
        2,
        l.row_down_label,
        "↓",
        Style::default().fg(t.rx_rate).add_modifier(Modifier::BOLD),
    );
    let down_rate = iface.map(|i| i.rx_rate).unwrap_or(0.0);
    put(
        f,
        4,
        l.row_down_label,
        &format_bytes_rate(down_rate),
        rate_style,
    );
    put(
        f,
        20,
        l.row_down_label,
        &format!("peak {}", short_bytes(rx_max)),
        dim,
    );
    put(
        f,
        34,
        l.row_down_label,
        &format!("avg {}", short_bytes(mean(&rx))),
        dim,
    );
    if let Some(i) = iface {
        put_right(
            f,
            l.content_x_end,
            l.row_down_label,
            &format!(
                "session ↓ {}   pkts {}   drop {}",
                format_bytes_total(i.rx_bytes_total),
                compact_count(i.rx_packets),
                compact_count(i.rx_drops)
            ),
            if i.rx_drops > 0 {
                Style::default().fg(t.status_warn)
            } else {
                dim
            },
        );
    }

    let faint = Style::default().fg(t.border);
    for (i, label) in scale_labels(rx_max).iter().enumerate() {
        let y = [l.row_down_chart, l.row_down_chart + 2, l.row_axis - 1][i];
        put_right(f, GUTTER_TICK_X - 1, y, label, faint);
        put(f, GUTTER_TICK_X, y, "┤", faint);
    }
    if !paused {
        paint::area_graph(
            f.buffer_mut(),
            Rect::new(CHART_X, l.row_down_chart, l.chart_w, l.down_chart_h),
            &rx,
            rx_max,
            &ramps.down,
            false,
        );
    }

    // ── the shared axis ──
    let rule: String = "─".repeat(l.chart_w as usize);
    put(f, CHART_X, l.row_axis, &rule, faint);
    let window = crate::ui::lite::window_label(samples, app.user_config.refresh_rate_ms);
    put_right(f, GUTTER_TICK_X - 1, l.row_axis, &window, dim);
    put(f, GUTTER_TICK_X, l.row_axis, "┤", faint);
    put_right(f, l.content_x_end, l.row_axis, "┤ now ├", dim);

    // ── upload half, mirrored ──
    if !paused {
        paint::area_graph(
            f.buffer_mut(),
            Rect::new(CHART_X, l.row_up_chart, l.chart_w, l.up_chart_h),
            &tx,
            tx_max,
            &ramps.up,
            true,
        );
    }
    for (i, label) in ["0", &short_bytes(tx_max / 2), &short_bytes(tx_max)]
        .iter()
        .enumerate()
    {
        let y = [l.row_up_chart, l.row_up_chart + 2, l.row_up_chart + 4][i];
        put_right(f, GUTTER_TICK_X - 1, y, label, faint);
        put(f, GUTTER_TICK_X, y, "┤", faint);
    }
    put(
        f,
        2,
        l.row_up_label,
        "↑",
        Style::default().fg(t.tx_rate).add_modifier(Modifier::BOLD),
    );
    let up_rate = iface.map(|i| i.tx_rate).unwrap_or(0.0);
    put(
        f,
        4,
        l.row_up_label,
        &format_bytes_rate(up_rate),
        rate_style,
    );
    put(
        f,
        20,
        l.row_up_label,
        &format!("peak {}", short_bytes(tx_max)),
        dim,
    );
    put(
        f,
        34,
        l.row_up_label,
        &format!("avg {}", short_bytes(mean(&tx))),
        dim,
    );
    if let Some(i) = iface {
        put_right(
            f,
            l.content_x_end,
            l.row_up_label,
            &format!(
                "session ↑ {}   pkts {}   drop {}",
                format_bytes_total(i.tx_bytes_total),
                compact_count(i.tx_packets),
                compact_count(i.tx_drops)
            ),
            if i.tx_drops > 0 {
                Style::default().fg(t.status_warn)
            } else {
                dim
            },
        );
    }
    if paused {
        put_right(
            f,
            l.content_x_end - 2,
            l.row_axis,
            "  paused  ",
            Style::default().fg(t.status_warn),
        );
    }
}

fn mean(v: &[u64]) -> u64 {
    if v.is_empty() {
        return 0;
    }
    (v.iter().map(|x| *x as u128).sum::<u128>() / v.len() as u128) as u64
}

fn compact_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1e6)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1e3)
    } else {
        n.to_string()
    }
}

fn is_degraded(app: &App) -> bool {
    let h = app.health_prober.status();
    h.gateway_loss.degrades(h.gateway_rtt_ms) || h.dns_loss.is_lossy()
}

// ── box 2: ifaces ───────────────────────────────────────────────────────────

fn render_ifaces(f: &mut Frame, app: &App, t: &Theme, ramps: &Ramps, l: &Layout) {
    let rows = collect_ifaces(app);
    let up_count = rows.iter().filter(|r| r.state == "up").count();
    let sub = format!("{} · {} up", rows.len(), up_count);
    paint::panel(
        f.buffer_mut(),
        Rect::new(l.ifaces.x, l.ifaces.y, l.ifaces.width, l.ifaces.height),
        t,
        &paint::PanelOpts {
            key: Some("2"),
            title: Some("ifaces"),
            sub: Some(&sub),
            right: Some("sort ↓ rate"),
            foot_left: &[zoom_bind(app, DenseBox::Ifaces)],
            ..Default::default()
        },
    );
    header(f, l.row_if_head, &l.if_cols, Some(if_col::DOWN), t);

    let spark = &l.if_cols[if_col::SPARK];
    for (i, r) in rows.iter().take(l.if_rows as usize).enumerate() {
        let y = l.row_if_first + i as u16;
        let down = r.state == "down";
        let idle = r.state == "idle";
        let dot = if down {
            t.status_error
        } else if idle {
            t.text_muted
        } else {
            t.status_good
        };
        let name_style = Style::default().fg(if down || idle {
            t.text_muted
        } else {
            t.text_primary
        });
        cell(
            f,
            &l.if_cols[if_col::MARK],
            y,
            "●",
            Style::default().fg(dot),
        );
        cell(f, &l.if_cols[if_col::NAME], y, &r.name, name_style);
        cell(
            f,
            &l.if_cols[if_col::STATE],
            y,
            r.state,
            Style::default().fg(if down { t.status_error } else { t.text_muted }),
        );
        cell(
            f,
            &l.if_cols[if_col::DOWN],
            y,
            &format_bytes_rate(r.rx_rate),
            Style::default().fg(if down { t.text_muted } else { t.rx_rate }),
        );
        cell(
            f,
            &l.if_cols[if_col::UP],
            y,
            &format_bytes_rate(r.tx_rate),
            Style::default().fg(if down { t.text_muted } else { t.tx_rate }),
        );
        cell(
            f,
            &l.if_cols[if_col::ERRORS],
            y,
            &compact_count(r.errors),
            Style::default().fg(if r.errors > 0 {
                t.status_error
            } else {
                t.text_muted
            }),
        );
        // Down and idle interfaces keep their row and show a flat baseline
        // rather than vanishing — "nothing happening" and "no such interface"
        // must not look the same.
        if down || idle || r.history.is_empty() {
            paint::baseline(f.buffer_mut(), spark.x, y, spark.w, t.border);
        } else {
            let s = fit_window(
                &r.history,
                samples_for_secs(60, app.user_config.refresh_rate_ms),
                spark.w as usize * 2,
            );
            paint::spark(
                f.buffer_mut(),
                spark.x,
                y,
                spark.w,
                &s,
                chart_max(&s),
                &ramps.down,
            );
        }
    }

    let faint = Style::default().fg(t.border);
    let dim = Style::default().fg(t.text_muted);
    put(
        f,
        1,
        l.row_if_rule,
        &"─".repeat(l.ifaces.width as usize - 2),
        faint,
    );

    let total_rx: f64 = rows.iter().map(|r| r.rx_rate).sum();
    let total_tx: f64 = rows.iter().map(|r| r.tx_rate).sum();
    put(f, 2, l.row_if_agg, "aggregate", dim);
    put(
        f,
        13,
        l.row_if_agg,
        &format!("↓ {}", short_bytes(total_rx as u64)),
        Style::default().fg(t.rx_rate),
    );
    put(
        f,
        24,
        l.row_if_agg,
        &format!("↑ {}", short_bytes(total_tx as u64)),
        Style::default().fg(t.tx_rate),
    );
    let errors: u64 = app
        .traffic
        .interfaces()
        .iter()
        .map(|i| i.rx_errors + i.tx_errors)
        .sum();
    put(
        f,
        35,
        l.row_if_agg,
        &format!("errors {}", compact_count(errors)),
        if errors > 0 {
            Style::default().fg(t.status_error)
        } else {
            dim
        },
    );

    // Saturation: against the link's real speed where the platform reports one,
    // against the observed peak where it doesn't — labelled so you know which
    // question the meter is answering.
    put(f, 2, l.row_if_sat, "saturation", dim);
    let ifaces = app.traffic.interfaces();
    let capture = ifaces.iter().find(|i| i.name == app.capture_interface);
    let now_bps = capture.map(|i| i.rx_rate + i.tx_rate).unwrap_or(0.0);
    let observed_peak = capture.map(|i| {
        i.rx_history
            .iter()
            .zip(i.tx_history.iter())
            .map(|(rx, tx)| rx + tx)
            .max()
            .unwrap_or(0)
    });
    let (frac, label) = saturation(now_bps, app.link_speed_bps(), observed_peak);
    paint::meter(
        f.buffer_mut(),
        l.sat_meter_x,
        l.row_if_sat,
        l.sat_meter_w,
        frac,
        &ramps.load,
        t.border,
    );
    put_right(
        f,
        l.ifaces.width - 2,
        l.row_if_sat,
        &label,
        if frac > 0.85 {
            Style::default().fg(t.status_error)
        } else {
            dim
        },
    );
}

/// Current link utilisation, as a fraction and the label that explains it.
///
/// The denominator is the whole design problem. Against a **link speed** the
/// meter means "how close am I to saturating this link" — a fixed ceiling, so
/// the same bar height always means the same thing. Against a **moving**
/// denominator it means nothing: every new high re-baselines the meter and
/// yesterday's reading is not comparable to today's.
///
/// So the ceiling is the best capacity we can establish, and it only ever
/// revises upward:
///
/// * the speed the OS reports for the link, when it has one; but
/// * never below throughput we have actually **measured**, because a driver
///   claiming the link is slower than traffic already carried over it is
///   simply wrong. macOS reports `ifi_baudrate` for Wi-Fi as the idle MCS —
///   this machine reported a 304 Mb link while sustaining 456 Mb/s over it,
///   which pinned the meter at 100% for the length of a file copy.
///
/// The label names whichever ceiling is in play, because "of 1 Gb link" and
/// "of 456 Mb seen" are different claims and the user is entitled to know
/// which one they are reading.
///
/// Rates arrive in **bytes** per second and link speeds are quoted in **bits**,
/// which is the factor-of-eight error this function exists to contain.
fn saturation(now_bps: f64, link_bps: Option<u64>, observed_peak: Option<u64>) -> (f32, String) {
    let link = link_bps.filter(|b| *b > 0);
    // Observed peak is bytes/s; put it in bits to compare with a link speed.
    let measured = observed_peak.filter(|p| *p > 0).map(|p| p * 8);

    let (ceiling, measured_wins) = match (link, measured) {
        (Some(l), Some(m)) if m > l => (m, true),
        (Some(l), _) => (l, false),
        (None, Some(m)) => (m, true),
        (None, None) => return (0.0, format!("{NA} of link capacity")),
    };

    let f = ((now_bps * 8.0) / ceiling as f64).clamp(0.0, 1.0);
    let what = if measured_wins { "seen" } else { "link" };
    (
        f as f32,
        format!("{:.0}% of {} {what}", f * 100.0, short_bits(ceiling)),
    )
}

/// Link speed in bits, for the saturation label: `1 Gb`, `100 Mb`, `480 Kb`.
///
/// Every ceiling below a megabit used to divide to zero, so a quiet link with
/// no OS-reported speed — Wi-Fi, usually — labelled its meter "12% of 0 Mb".
/// A percentage of nothing is not a reading, and the number it was a
/// percentage of was real.
fn short_bits(bps: u64) -> String {
    for (scale, unit) in [(1_000_000_000, "Gb"), (1_000_000, "Mb"), (1_000, "Kb")] {
        if bps >= scale {
            let value = bps as f64 / scale as f64;
            // One decimal only where it carries information: "1.5 Mb" is
            // worth the character, "304.0 Mb" is not.
            return if value >= 10.0 || (value - value.round()).abs() < 0.05 {
                format!("{value:.0} {unit}")
            } else {
                format!("{value:.1} {unit}")
            };
        }
    }
    format!("{bps} b")
}

// ── box 3: health ───────────────────────────────────────────────────────────

fn render_health(f: &mut Frame, app: &App, t: &Theme, ramps: &Ramps, l: &Layout) {
    let h = app.health_prober.status();
    let degraded = is_degraded(app);
    let verdict = app.diagnose.engine.verdict(&app.diagnose.baselines);
    let conns = collect_conns(app);

    // The design's fourth hop is "a configured peer". We don't have one, so the
    // slot goes to the slowest thing actually being talked to — same shape of
    // fact (a target, an RTT, a budget), and it's measured rather than assumed.
    let slowest = conns
        .iter()
        .filter(|c| c.rtt_ms.is_some() && !c.is_dead())
        .max_by(|a, b| {
            a.rtt_ms
                .unwrap_or(0.0)
                .partial_cmp(&b.rtt_ms.unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        });

    paint::panel(
        f.buffer_mut(),
        l.health,
        t,
        &paint::PanelOpts {
            key: Some("3"),
            title: Some("health"),
            // Same rule as everywhere else: only the engine may say nominal,
            // and only once it has the baselines to back it.
            sub: Some(if degraded { "degraded" } else { verdict.chip() }),
            right: Some(if degraded { "● DEGRADED" } else { "● OK" }),
            right_style: Some(Style::default().fg(if degraded {
                t.status_error
            } else {
                t.status_good
            })),
            foot_left: &[zoom_bind(app, DenseBox::Health)],
            ..Default::default()
        },
    );

    let dim = Style::default().fg(t.text_muted);
    let x = l.health.x + 2;
    put(f, x, l.row_hop_head, "   HOP        TARGET", dim);
    put_right(f, l.hop_meter_x - 2, l.row_hop_head, "RTT", dim);
    put(f, l.hop_meter_x, l.row_hop_head, "BUDGET", dim);

    // Budget: the RTT at which each hop stops feeling instant. Local hops get a
    // tight budget, the internet a loose one — a 40 ms gateway is broken, a
    // 40 ms CDN is excellent, and one shared scale would say neither.
    let hops: [(&str, String, Option<f64>, f64); 4] = [
        (
            "gateway",
            app.config_collector
                .config
                .gateway
                .clone()
                .unwrap_or_else(|| NA.to_string()),
            h.gateway_rtt_ms,
            20.0,
        ),
        (
            "dns",
            app.config_collector
                .config
                .primary_dns()
                .unwrap_or_else(|| NA.to_string()),
            h.dns_rtt_ms,
            50.0,
        ),
        ("internet", "1.1.1.1".to_string(), h.internet_rtt_ms, 100.0),
        (
            "peer",
            slowest
                .map(|c| c.host.clone())
                .unwrap_or_else(|| NA.to_string()),
            slowest.and_then(|c| c.rtt_ms),
            200.0,
        ),
    ];

    for (i, (name, target, rtt, budget)) in hops.iter().enumerate() {
        let y = l.row_hop_first + i as u16;
        let frac = rtt.map(|r| (r / budget) as f32).unwrap_or(0.0);
        let crit = frac > 0.85 || rtt.is_none();
        put(
            f,
            x,
            y,
            "●",
            Style::default().fg(if rtt.is_none() {
                t.text_muted
            } else if crit {
                t.status_error
            } else {
                t.status_good
            }),
        );
        put(
            f,
            x + 2,
            y,
            &truncate(name, 10),
            Style::default().fg(t.text_primary),
        );
        put(f, x + 13, y, &truncate(target, 15), dim);
        put_right(
            f,
            l.hop_meter_x - 2,
            y,
            &rtt_str(*rtt),
            Style::default().fg(if crit && rtt.is_some() {
                t.status_error
            } else {
                t.text_primary
            }),
        );
        paint::meter(
            f.buffer_mut(),
            l.hop_meter_x,
            y,
            l.hop_meter_w,
            frac,
            &ramps.load,
            t.border,
        );
    }

    let faint = Style::default().fg(t.border);
    put(
        f,
        l.health.x + 1,
        l.row_health_rule,
        &"─".repeat(l.health.width as usize - 2),
        faint,
    );

    let retrans: u32 = conns.iter().map(|c| c.retransmits).sum();
    let ooo: u32 = conns.iter().map(|c| c.out_of_order).sum();
    let jitter = mean_sigma(&h.gateway_rtt_history).map(|(_, s)| s);
    let kv: [(&str, String, bool); 4] = [
        (
            "packet loss",
            h.gateway_loss.label(1),
            h.gateway_loss.is_lossy(),
        ),
        (
            "jitter",
            jitter.map(|s| format!("{s:.1}ms")).unwrap_or(NA.into()),
            jitter.map(|s| s > 20.0).unwrap_or(false),
        ),
        ("retrans", retrans.to_string(), retrans > 0),
        ("out of order", ooo.to_string(), ooo > 0),
    ];
    for (i, (k, v, bad)) in kv.iter().enumerate() {
        let cx = x + (i % 2) as u16 * 30;
        let cy = l.row_kv_first + (i / 2) as u16;
        put(f, cx, cy, k, dim);
        put_right(
            f,
            cx + 21,
            cy,
            v,
            Style::default().fg(if *bad { t.status_error } else { t.text_primary }),
        );
    }

    // Two lines of plain English. A number tells you what; these say whether it
    // matters, which is the question you actually opened the tool with.
    let (verdict, verdict_style) = match (h.gateway_rtt_ms, mean_sigma(&h.gateway_rtt_history)) {
        (Some(rtt), Some((mean, _))) if mean > 0.0 && rtt > mean * 3.0 => (
            format!("gateway rtt {:.1}× baseline", rtt / mean),
            Style::default().fg(t.status_error),
        ),
        // No rtt from a probe that ran is a gateway that did not answer. No
        // rtt because no probe has run, or none could be sent, is not — the
        // line says which, instead of the "not responding" that used to greet
        // every fresh start.
        (None, _) if h.gateway_loss.is_measured() => (
            "gateway not responding".to_string(),
            Style::default().fg(t.status_error),
        ),
        (None, _) => (
            h.gateway_loss
                .note()
                .map(|why| format!("gateway unmeasured: {why}"))
                .unwrap_or_else(|| "probing gateway".to_string()),
            faint,
        ),
        _ if h.gateway_loss.is_lossy() => (
            format!("gateway loss {}", h.gateway_loss.label(1)),
            Style::default().fg(t.status_warn),
        ),
        _ => ("no anomalies in window".to_string(), faint),
    };
    put(f, x, l.row_verdict_1, &verdict, verdict_style);
    let baseline_line = match mean_sigma(&h.gateway_rtt_history) {
        Some((mean, sigma)) => format!("baseline rtt {mean:.1}ms σ {sigma:.1}"),
        None => "baseline not established yet".to_string(),
    };
    put(f, x, l.row_verdict_2, &baseline_line, faint);
}

// ── box 4: conns ────────────────────────────────────────────────────────────

fn render_conns(f: &mut Frame, app: &App, t: &Theme, ramps: &Ramps, l: &Layout) {
    let groups = conn_groups(collect_conns(app));
    let rows = dense_rows(&groups, &app.ui.dense_collapsed);
    let conn_count: usize = groups.iter().map(|g| g.rollup.conns).sum();
    let sel = app
        .ui
        .scroll
        .connection_scroll
        .min(rows.len().saturating_sub(1));
    let page_start = sel.saturating_sub(l.conn_rows as usize - 1);
    let visible: Vec<&DenseRow> = rows
        .iter()
        .skip(page_start)
        .take(l.conn_rows as usize)
        .collect();

    let sub = if groups.len() == conn_count {
        format!("{conn_count} · 1 selected")
    } else {
        format!("{conn_count} in {} procs · 1 selected", groups.len())
    };
    let foot_right = if rows.is_empty() {
        "0 of 0".to_string()
    } else {
        format!(
            "{}-{} of {}",
            page_start + 1,
            (page_start + visible.len()).min(rows.len()),
            rows.len()
        )
    };
    paint::panel(
        f.buffer_mut(),
        l.conns,
        t,
        &paint::PanelOpts {
            key: Some("4"),
            title: Some("conns"),
            sub: Some(&sub),
            right: Some("sort ↓ down"),
            // Only keys that do something. `/ filter`, `sort` and `export`
            // were printed here before any of them were implemented — and in a
            // design whose whole premise is that the border *is* the
            // documentation, advertising a key that does nothing is the one
            // failure that can't be tolerated.
            foot_left: &[
                zoom_bind(app, DenseBox::Conns),
                ("↑↓", " select"),
                ("space", " fold"),
                ("z", " fold all"),
                ("p", "ause"),
                ("?", " help"),
            ],
            foot_right: Some(&foot_right),
            ..Default::default()
        },
    );

    match rows.get(sel) {
        Some(DenseRow::Parent { group, .. }) => render_group_detail(f, t, group, l),
        Some(row) => {
            if let Some(c) = row.conn() {
                render_detail(f, app, t, ramps, c, l);
            }
        }
        None => {}
    }

    header(f, l.row_conn_head, &l.conn_cols, Some(conn_col::DOWN), t);
    for (i, row) in visible.iter().enumerate() {
        let y = l.row_conn_first + i as u16;
        let is_sel = page_start + i == sel;
        if let DenseRow::Parent { group, collapsed } = row {
            render_group_row(f, t, ramps, l, group, *collapsed, is_sel, y);
            continue;
        }
        let Some(c) = row.conn() else { continue };
        let child = matches!(row, DenseRow::Child { .. });
        let dead = c.is_dead();
        // The active row gets the band — the same `selection_bg` every other
        // list in netwatch uses. Nothing else on this screen paints a
        // background, so it reads as "you are here" rather than as decoration.
        if is_sel {
            for x in l.conns.x + 1..l.conns.x + l.conns.width - 1 {
                f.buffer_mut().get_mut(x, y).set_bg(t.selection_bg);
            }
        }
        // On the selected row the quiet tokens are promoted: `text_muted` on
        // `selection_bg` is the worst contrast on the screen, and the selected
        // row is exactly where the user is looking. Same reasoning as Lite.
        let quiet = if is_sel { t.text_primary } else { t.text_muted };
        let secondary = if is_sel {
            t.text_primary
        } else {
            t.text_secondary
        };
        let fg = |c: Color| Style::default().fg(if dead { quiet } else { c });
        cell(
            f,
            &l.conn_cols[conn_col::MARK],
            y,
            if is_sel { "▶" } else { "●" },
            Style::default().fg(if is_sel {
                t.brand
            } else if dead {
                t.text_muted
            } else {
                t.status_good
            }),
        );
        // Under a header the process is already named one row up; a child
        // shows the indent instead and spends the eye on what differs.
        cell(
            f,
            &l.conn_cols[conn_col::PROC],
            y,
            if child { "  ↳" } else { &c.process },
            if child {
                Style::default().fg(t.brand)
            } else {
                fg(t.text_primary)
            },
        );
        cell(
            f,
            &l.conn_cols[conn_col::PID],
            y,
            &c.pid.map(|p| p.to_string()).unwrap_or(NA.into()),
            Style::default().fg(quiet),
        );
        cell(f, &l.conn_cols[conn_col::HOST], y, &c.host, fg(secondary));
        cell(
            f,
            &l.conn_cols[conn_col::PORT],
            y,
            &c.port,
            Style::default().fg(quiet),
        );
        cell(
            f,
            &l.conn_cols[conn_col::PROTO],
            y,
            &c.proto,
            Style::default().fg(if c.proto == "udp" {
                t.status_warn
            } else {
                quiet
            }),
        );
        cell(
            f,
            &l.conn_cols[conn_col::DOWN],
            y,
            &format_bytes_rate(c.rx_rate),
            fg(t.rx_rate),
        );
        cell(
            f,
            &l.conn_cols[conn_col::UP],
            y,
            &format_bytes_rate(c.tx_rate),
            fg(t.tx_rate),
        );
        cell(
            f,
            &l.conn_cols[conn_col::RTT],
            y,
            &rtt_str(c.rtt_ms),
            Style::default().fg(quiet),
        );
        cell(
            f,
            &l.conn_cols[conn_col::STATE],
            y,
            short_state(&c.state),
            Style::default().fg(if dead { quiet } else { secondary }),
        );
        let spark = &l.conn_cols[conn_col::SPARK];
        if dead || c.history.is_empty() {
            paint::baseline(f.buffer_mut(), spark.x, y, spark.w, t.border);
        } else {
            let s = fit_samples(&c.history, spark.w as usize * 2);
            let ramp = if c.retransmits > 0 {
                &ramps.load
            } else {
                &ramps.down
            };
            paint::spark(f.buffer_mut(), spark.x, y, spark.w, &s, chart_max(&s), ramp);
        }
    }
}

/// A process's header row: the rollup, with a chevron for the fold state.
#[allow(clippy::too_many_arguments)]
fn render_group_row(
    f: &mut Frame,
    t: &Theme,
    ramps: &Ramps,
    l: &Layout,
    group: &ConnGroup,
    collapsed: bool,
    is_sel: bool,
    y: u16,
) {
    let r = &group.rollup;
    if is_sel {
        for x in l.conns.x + 1..l.conns.x + l.conns.width - 1 {
            f.buffer_mut().get_mut(x, y).set_bg(t.selection_bg);
        }
    }
    let quiet = if is_sel { t.text_primary } else { t.text_muted };
    let fg = |c: Color| Style::default().fg(if r.dead { quiet } else { c });
    // The chevron stays on the selected row: fold state is what the row is
    // for, and the selection band already says where the cursor is.
    cell(
        f,
        &l.conn_cols[conn_col::MARK],
        y,
        if collapsed { "▶" } else { "▼" },
        Style::default().fg(t.brand),
    );
    cell(
        f,
        &l.conn_cols[conn_col::PROC],
        y,
        &group.key,
        fg(t.text_primary).add_modifier(Modifier::BOLD),
    );
    let pid = &group.children[0].pid;
    cell(
        f,
        &l.conn_cols[conn_col::PID],
        y,
        &if r.pids == 1 {
            pid.map(|p| p.to_string()).unwrap_or(NA.into())
        } else {
            format!("{}×", r.pids)
        },
        Style::default().fg(quiet),
    );
    cell(
        f,
        &l.conn_cols[conn_col::HOST],
        y,
        &format!(
            "{} conns · {} host{}",
            r.conns,
            r.hosts,
            if r.hosts == 1 { "" } else { "s" }
        ),
        Style::default().fg(quiet),
    );
    cell(
        f,
        &l.conn_cols[conn_col::DOWN],
        y,
        &format_bytes_rate(r.rx_rate),
        fg(t.rx_rate),
    );
    cell(
        f,
        &l.conn_cols[conn_col::UP],
        y,
        &format_bytes_rate(r.tx_rate),
        fg(t.tx_rate),
    );
    cell(
        f,
        &l.conn_cols[conn_col::RTT],
        y,
        &rtt_str(r.rtt_ms),
        Style::default().fg(quiet),
    );
    cell(
        f,
        &l.conn_cols[conn_col::STATE],
        y,
        short_state(&r.state),
        Style::default().fg(if r.dead { quiet } else { t.text_secondary }),
    );
    let spark = &l.conn_cols[conn_col::SPARK];
    if r.dead || r.history.is_empty() {
        paint::baseline(f.buffer_mut(), spark.x, y, spark.w, t.border);
    } else {
        let s = fit_samples(&r.history, spark.w as usize * 2);
        let ramp = if r.degraded { &ramps.load } else { &ramps.down };
        paint::spark(f.buffer_mut(), spark.x, y, spark.w, &s, chart_max(&s), ramp);
    }
}

/// The detail strip for a header row: the group as a whole, since there is
/// no single socket pair to name.
fn render_group_detail(f: &mut Frame, t: &Theme, group: &ConnGroup, l: &Layout) {
    let r = &group.rollup;
    let dim = Style::default().fg(t.text_muted);
    put(
        f,
        2,
        l.row_detail_1,
        "↳",
        Style::default().fg(t.brand).add_modifier(Modifier::BOLD),
    );
    put(
        f,
        4,
        l.row_detail_1,
        &truncate(&group.key, DETAIL_PROC_W as usize),
        Style::default()
            .fg(t.text_primary)
            .add_modifier(Modifier::BOLD),
    );
    let pids: Vec<String> = group
        .children
        .iter()
        .filter_map(|c| c.pid)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|p| p.to_string())
        .collect();
    put(
        f,
        DETAIL_PID_X,
        l.row_detail_1,
        &truncate(
            &format!(
                "pid {}",
                if pids.is_empty() {
                    NA.to_string()
                } else {
                    pids.join(",")
                }
            ),
            (l.content_x_end - DETAIL_PID_X) as usize,
        ),
        dim,
    );
    put(
        f,
        4,
        l.row_detail_2,
        &format!(
            "{} connection{} to {} host{}",
            r.conns,
            if r.conns == 1 { "" } else { "s" },
            r.hosts,
            if r.hosts == 1 { "" } else { "s" }
        ),
        Style::default().fg(t.text_secondary),
    );
    let hosts: Vec<&str> = group
        .children
        .iter()
        .map(|c| c.host.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    put(
        f,
        4,
        l.row_detail_3,
        &truncate(&hosts.join("  "), (l.content_x_end - 4) as usize),
        dim,
    );
}

/// The selected row's detail, hoisted into the top of the same box.
///
/// No new screen, no lost context, no back button — you keep reading the same
/// pixels you were already watching.
///
/// Nothing in this box paints a background. The detail block is set apart by
/// its `↳`, its bright process name against dim labels, and the column header
/// that follows it — a three-row band of saturated colour was doing the work
/// of a marker while shouting over every graph on the screen.
fn render_detail(f: &mut Frame, app: &App, t: &Theme, ramps: &Ramps, c: &ConnRow, l: &Layout) {
    let dim = Style::default().fg(t.text_muted);
    put(
        f,
        2,
        l.row_detail_1,
        "↳",
        Style::default().fg(t.brand).add_modifier(Modifier::BOLD),
    );
    // Fixed columns, not `x + name.width()`: a 20-char process name pushed the
    // pid straight under the socket pair and ate it.
    put(
        f,
        4,
        l.row_detail_1,
        &truncate(&c.process, DETAIL_PROC_W as usize),
        Style::default()
            .fg(t.text_primary)
            .add_modifier(Modifier::BOLD),
    );
    put(
        f,
        DETAIL_PID_X,
        l.row_detail_1,
        &format!("pid {}", c.pid.map(|p| p.to_string()).unwrap_or(NA.into())),
        dim,
    );
    put(
        f,
        DETAIL_SOCKET_X,
        l.row_detail_1,
        &truncate(
            &format!("{} → {}", c.local, c.remote),
            (l.content_x_end - DETAIL_SOCKET_X - 18) as usize,
        ),
        Style::default().fg(t.text_primary),
    );
    put_right(
        f,
        l.content_x_end,
        l.row_detail_1,
        &format!("{} {}", c.proto, short_state(&c.state)),
        Style::default().fg(t.status_good),
    );

    // TCP internals from the kernel, where the platform gives them to us.
    let tcp = app.tcp_info_for(&c.local, &c.remote);
    let internals = match tcp {
        Some(i) => format!(
            "cwnd {}  ssthresh {}  mss {}  rwnd {}",
            i.cwnd
                .map(|v| v.to_string())
                .unwrap_or_else(|| NA.to_string()),
            if i.ssthresh_unset() {
                "∞".to_string()
            } else {
                i.ssthresh
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| NA.to_string())
            },
            i.mss
                .map(|v| v.to_string())
                .unwrap_or_else(|| NA.to_string()),
            i.rwnd
                .map(|v| short_bytes(v as u64))
                .unwrap_or_else(|| NA.to_string()),
        ),
        None => format!("cwnd {NA}  ssthresh {NA}  mss {NA}  rwnd {NA}"),
    };
    put(f, 4, l.row_detail_2, "rates", dim);
    put(
        f,
        12,
        l.row_detail_2,
        &format!("↓ {}", format_bytes_rate(c.rx_rate)),
        Style::default().fg(t.rx_rate),
    );
    put(
        f,
        30,
        l.row_detail_2,
        &format!("↑ {}", format_bytes_rate(c.tx_rate)),
        Style::default().fg(t.tx_rate),
    );
    // The middle group ends where the right-aligned internals begin. The
    // decoded protocol is unbounded — an SNI can be any length — so without
    // this clamp a long hostname runs straight under `cwnd`, which is exactly
    // what `HTTPS httpbcwnd 666` looked like in the first demo take.
    let stats = format!(
        "rtt {}   retrans {}   ooo {}{}",
        rtt_str(c.rtt_ms),
        c.retransmits,
        c.out_of_order,
        c.app_proto
            .as_ref()
            .map(|p| format!("   {p}"))
            .unwrap_or_default()
    );
    put(
        f,
        DETAIL_STATS_X,
        l.row_detail_2,
        &truncate(
            &stats,
            detail_stats_width(l, internals.width() as u16) as usize,
        ),
        dim,
    );
    put_right(f, l.content_x_end, l.row_detail_2, &internals, dim);

    put(f, 4, l.row_detail_3, "rate 60s", dim);
    if !c.history.is_empty() {
        let s = fit_samples(&c.history, l.detail_spark_w as usize * 2);
        paint::spark(
            f.buffer_mut(),
            l.detail_spark_x,
            l.row_detail_3,
            l.detail_spark_w,
            &s,
            chart_max(&s),
            &ramps.down,
        );
    }
    if let Some(geo) = app.geo_cache.lookup(&c.host) {
        let label = if geo.city.is_empty() {
            geo.org.clone()
        } else {
            format!("{} · {}", geo.org, geo.city)
        };
        if !label.trim().is_empty() {
            put_right(
                f,
                l.content_x_end,
                l.row_detail_3,
                &truncate(&label, ASN_LABEL_MAX as usize),
                dim,
            );
        }
    }
}

// ── compact 80×24 ───────────────────────────────────────────────────────────

fn render_compact(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let cl = CompactLayout::new(area);
    let ramps = Ramps::from_theme(t);
    let ifaces = app.traffic.interfaces();
    let iface = ifaces.iter().find(|i| i.name == app.capture_interface);
    let samples = cl.chart_w as usize * 2;
    let rx = fit_samples(
        &iface
            .map(|i| i.rx_history.iter().copied().collect::<Vec<_>>())
            .unwrap_or_default(),
        samples,
    );
    let tx = fit_samples(
        &iface
            .map(|i| i.tx_history.iter().copied().collect::<Vec<_>>())
            .unwrap_or_default(),
        samples,
    );
    let rx_max = chart_max(&rx);
    let tx_max = chart_max(&tx);

    paint::panel(
        f.buffer_mut(),
        cl.net,
        t,
        &paint::PanelOpts {
            key: Some("1"),
            title: Some("net"),
            sub: Some(&app.capture_interface),
            ..Default::default()
        },
    );
    let dim = Style::default().fg(t.text_muted);
    let faint = Style::default().fg(t.border);
    put(
        f,
        2,
        cl.row_down_label,
        "↓",
        Style::default().fg(t.rx_rate).add_modifier(Modifier::BOLD),
    );
    put(
        f,
        4,
        cl.row_down_label,
        &format_bytes_rate(iface.map(|i| i.rx_rate).unwrap_or(0.0)),
        Style::default()
            .fg(t.text_primary)
            .add_modifier(Modifier::BOLD),
    );
    put_right(
        f,
        cl.x_end,
        cl.row_down_label,
        &format!("peak {}", short_bytes(rx_max)),
        dim,
    );
    paint::area_graph(
        f.buffer_mut(),
        Rect::new(CPT_CHART_X, cl.row_down_chart, cl.chart_w, cl.chart_h),
        &rx,
        rx_max,
        &ramps.down,
        false,
    );

    put(
        f,
        CPT_CHART_X + 3,
        cl.row_axis,
        &"─".repeat((cl.chart_w - 3) as usize),
        faint,
    );
    put(
        f,
        2,
        cl.row_axis,
        &crate::ui::lite::window_label(samples, app.user_config.refresh_rate_ms),
        dim,
    );
    put(f, 6, cl.row_axis, "┤", faint);
    put_right(f, cl.x_end, cl.row_axis, "┤ now ├", dim);

    paint::area_graph(
        f.buffer_mut(),
        Rect::new(CPT_CHART_X, cl.row_up_chart, cl.chart_w, cl.chart_h),
        &tx,
        tx_max,
        &ramps.up,
        true,
    );
    put(
        f,
        2,
        cl.row_up_label,
        "↑",
        Style::default().fg(t.tx_rate).add_modifier(Modifier::BOLD),
    );
    put(
        f,
        4,
        cl.row_up_label,
        &format_bytes_rate(iface.map(|i| i.tx_rate).unwrap_or(0.0)),
        Style::default()
            .fg(t.text_primary)
            .add_modifier(Modifier::BOLD),
    );
    put_right(
        f,
        cl.x_end,
        cl.row_up_label,
        &format!("peak {}", short_bytes(tx_max)),
        dim,
    );

    let rows = collect_conns(app);
    // Compact tracks the same selection as the full view, so `↑↓` moves
    // something here too — a `▶` pinned to row 0 while the arrows did nothing
    // was a marker that pointed at whatever happened to be sorted first.
    let sel = app
        .ui
        .scroll
        .connection_scroll
        .min(rows.len().saturating_sub(1));
    let page_start = sel.saturating_sub(cl.rows as usize - 1);
    let visible: Vec<&ConnRow> = rows
        .iter()
        .skip(page_start)
        .take(cl.rows as usize)
        .collect();
    let foot_right = if rows.is_empty() {
        "0 of 0".to_string()
    } else {
        format!(
            "{}-{} of {}",
            page_start + 1,
            (page_start + visible.len()).min(rows.len()),
            rows.len()
        )
    };
    paint::panel(
        f.buffer_mut(),
        cl.conns,
        t,
        &paint::PanelOpts {
            key: Some("4"),
            title: Some("conns"),
            sub: Some(&rows.len().to_string()),
            right: Some("sort ↓ down"),
            foot_left: &[("V", " view"), ("q", "uit")],
            foot_right: Some(&foot_right),
            ..Default::default()
        },
    );
    header(f, cl.row_head, &cl.cols, Some(cpt_col::DOWN), t);
    for (i, c) in visible.iter().enumerate() {
        let y = cl.row_first + i as u16;
        let is_sel = page_start + i == sel;
        if is_sel {
            for x in cl.conns.x + 1..cl.conns.x + cl.conns.width - 1 {
                f.buffer_mut().get_mut(x, y).set_bg(t.selection_bg);
            }
        }
        let quiet = if is_sel { t.text_primary } else { t.text_muted };
        let secondary = if is_sel {
            t.text_primary
        } else {
            t.text_secondary
        };
        cell(
            f,
            &cl.cols[cpt_col::MARK],
            y,
            if is_sel { "▶" } else { "●" },
            Style::default().fg(if is_sel { t.brand } else { t.status_good }),
        );
        cell(
            f,
            &cl.cols[cpt_col::PROC],
            y,
            &c.process,
            Style::default().fg(t.text_primary),
        );
        cell(
            f,
            &cl.cols[cpt_col::HOST],
            y,
            &c.host,
            Style::default().fg(secondary),
        );
        cell(
            f,
            &cl.cols[cpt_col::DOWN],
            y,
            &format_bytes_rate(c.rx_rate),
            Style::default().fg(t.rx_rate),
        );
        cell(
            f,
            &cl.cols[cpt_col::UP],
            y,
            &format_bytes_rate(c.tx_rate),
            Style::default().fg(t.tx_rate),
        );
        cell(
            f,
            &cl.cols[cpt_col::RTT],
            y,
            &rtt_str(c.rtt_ms),
            Style::default().fg(quiet),
        );
        let spark = &cl.cols[cpt_col::SPARK];
        if c.history.is_empty() {
            paint::baseline(f.buffer_mut(), spark.x, y, spark.w, t.border);
        } else {
            let s = fit_samples(&c.history, spark.w as usize * 2);
            paint::spark(
                f.buffer_mut(),
                spark.x,
                y,
                spark.w,
                &s,
                chart_max(&s),
                &ramps.down,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sizes the layout must hold together at: the minimum, a couple of common
    /// real terminals, and something absurd. A fixed grid passed the old
    /// constant-vs-constant checks and still pinned four boxes into the corner
    /// of a 200×58 window, so every invariant is now swept across sizes.
    fn sizes() -> Vec<Rect> {
        [
            (130, 44),
            (131, 45),
            (160, 50),
            (200, 58),
            (240, 67),
            (400, 120),
        ]
        .iter()
        .map(|(w, h)| Rect::new(0, 0, *w, *h))
        .collect()
    }

    #[test]
    fn boxes_tile_the_whole_terminal_at_every_size() {
        for area in sizes() {
            let l = Layout::new(area);
            let tag = format!("{}×{}", area.width, area.height);

            assert_eq!(l.net.y, 0, "{tag}: net must start at the top");
            assert_eq!(l.net.width, area.width, "{tag}: net must span the width");
            assert_eq!(
                l.net.y + l.net.height,
                l.ifaces.y,
                "{tag}: net and the middle row must abut"
            );
            assert_eq!(l.ifaces.height, l.health.height, "{tag}");
            assert_eq!(
                l.ifaces.x + l.ifaces.width,
                l.health.x,
                "{tag}: ifaces and health must abut"
            );
            assert_eq!(
                l.health.x + l.health.width,
                area.width,
                "{tag}: health must reach the right edge"
            );
            assert_eq!(
                l.ifaces.y + l.ifaces.height,
                l.conns.y,
                "{tag}: the middle row and conns must abut"
            );
            assert_eq!(
                l.conns.y + l.conns.height,
                area.height,
                "{tag}: conns must reach the last row — no dead space"
            );
            assert_eq!(l.conns.width, area.width, "{tag}: conns spans the width");
        }
    }

    #[test]
    fn the_mirrored_graph_meets_exactly_at_the_axis() {
        for area in sizes() {
            let l = Layout::new(area);
            let tag = format!("{}×{}", area.width, area.height);
            assert_eq!(
                l.row_down_chart + l.down_chart_h,
                l.row_axis,
                "{tag}: the download plot must end exactly on the axis"
            );
            assert_eq!(
                l.row_axis + 1,
                l.row_up_chart,
                "{tag}: the upload plot must start immediately below the axis"
            );
            assert_eq!(l.row_up_chart + l.up_chart_h, l.row_up_label, "{tag}");
            assert!(
                l.row_up_label < l.net.y + l.net.height - 1,
                "{tag}: the upload label must stay inside the box"
            );
            assert!(
                l.down_chart_h >= 6 && l.up_chart_h >= 5,
                "{tag}: plots never shrink below the design"
            );
        }
    }

    #[test]
    fn every_box_row_stays_inside_its_box() {
        for area in sizes() {
            let l = Layout::new(area);
            let tag = format!("{}×{}", area.width, area.height);
            let mid_last = l.ifaces.y + l.ifaces.height - 1;

            assert!(l.row_if_first + l.if_rows <= l.row_if_rule, "{tag}");
            assert!(
                l.row_if_rule < l.row_if_agg && l.row_if_agg < l.row_if_sat,
                "{tag}"
            );
            assert!(
                l.row_if_sat < mid_last,
                "{tag}: saturation row inside the box"
            );
            assert!(
                l.if_rows >= 6,
                "{tag}: never fewer interfaces than the design"
            );

            assert!(l.row_hop_first + l.hop_rows <= l.row_health_rule, "{tag}");
            assert!(l.row_kv_first + 2 <= l.row_verdict_1, "{tag}");
            assert!(l.row_verdict_2 < mid_last, "{tag}");

            assert_eq!(
                l.row_conn_first + l.conn_rows,
                l.conns.y + l.conns.height - 1,
                "{tag}: the connection list must run to the bottom border"
            );
            assert!(l.conn_rows >= 10, "{tag}: never fewer rows than the design");
        }
    }

    /// A graph or meter that runs under its own readout appears to *shrink* as
    /// it fills — the meter lying at the one moment you need it.
    #[test]
    fn graphs_and_meters_clear_their_readouts_at_every_size() {
        for area in sizes() {
            let l = Layout::new(area);
            let tag = format!("{}×{}", area.width, area.height);
            assert!(
                l.sat_meter_x + l.sat_meter_w + SAT_LABEL_MAX <= l.ifaces.width - 2,
                "{tag}: saturation meter runs under its readout"
            );
            assert!(
                l.detail_spark_x + l.detail_spark_w + ASN_LABEL_MAX <= l.content_x_end,
                "{tag}: detail sparkline runs under the ASN label"
            );
            assert!(
                l.hop_meter_x + l.hop_meter_w < l.health.x + l.health.width,
                "{tag}: hop meters overrun the health box"
            );
            assert!(
                CHART_X + l.chart_w <= l.content_x_end + 1,
                "{tag}: the throughput plot overruns the box"
            );
        }
    }

    fn assert_tiles(cols: &[Col], name: &str, x_end: u16) {
        let mut prev = 0u16;
        for c in cols {
            assert!(
                c.x > prev,
                "{name}: column {:?} starts at {} but the previous ends at {prev}",
                c.label,
                c.x
            );
            assert!(c.w > 0, "{name}: column {:?} has no width", c.label);
            prev = c.x_end();
        }
        assert!(
            prev <= x_end,
            "{name}: last column ends at {prev}, past the content edge {x_end}"
        );
    }

    #[test]
    fn every_table_tiles_without_overlap_at_every_size() {
        for area in sizes() {
            let l = Layout::new(area);
            let tag = format!("{}×{}", area.width, area.height);
            assert_tiles(&l.conn_cols, &format!("conns {tag}"), l.content_x_end);
            assert_tiles(&l.if_cols, &format!("ifaces {tag}"), l.ifaces.width - 2);

            let c = CompactLayout::new(area);
            assert_tiles(&c.cols, &format!("compact {tag}"), c.x_end);
        }
    }

    /// The extra width has to end up somewhere useful, not as trailing blank.
    #[test]
    fn wider_terminals_widen_the_host_column_and_the_plots() {
        let narrow = Layout::new(Rect::new(0, 0, 130, 44));
        let wide = Layout::new(Rect::new(0, 0, 200, 58));
        assert!(
            wide.conn_cols[conn_col::HOST].w > narrow.conn_cols[conn_col::HOST].w,
            "hostnames are what actually get cut; they should get the room"
        );
        assert!(wide.conn_cols[conn_col::SPARK].w > narrow.conn_cols[conn_col::SPARK].w);
        assert!(wide.if_cols[if_col::SPARK].w > narrow.if_cols[if_col::SPARK].w);
        assert!(wide.chart_w > narrow.chart_w);
        assert!(wide.detail_spark_w > narrow.detail_spark_w);
        // Number columns keep their width — widening them buys nothing and
        // moving them makes the eye re-find them.
        assert_eq!(
            wide.conn_cols[conn_col::DOWN].w,
            narrow.conn_cols[conn_col::DOWN].w
        );
    }

    #[test]
    fn compact_fills_its_area_too() {
        for (w, h) in [(80u16, 24u16), (100, 30), (129, 43)] {
            let c = CompactLayout::new(Rect::new(0, 0, w, h));
            let tag = format!("{w}×{h}");
            assert_eq!(c.net.y, 0, "{tag}");
            assert_eq!(c.net.y + c.net.height, c.conns.y, "{tag}: boxes must abut");
            assert_eq!(
                c.conns.y + c.conns.height,
                h,
                "{tag}: conns must reach the last row"
            );
            assert_eq!(c.net.width, w, "{tag}");
            assert_eq!(
                c.row_first + c.rows,
                h - 1,
                "{tag}: the list must run to the bottom border"
            );
            assert!(c.row_up_chart + c.chart_h <= c.row_up_label, "{tag}");
        }
    }

    #[test]
    fn headers_fit_inside_their_own_columns() {
        let l = Layout::new(Rect::new(0, 0, 130, 44));
        let c = CompactLayout::new(Rect::new(0, 0, 80, 24));
        for (name, cols) in [
            ("conns", &l.conn_cols),
            ("ifaces", &l.if_cols),
            ("compact", &c.cols),
        ] {
            for col in cols.iter() {
                assert!(
                    col.label.width() as u16 <= col.w,
                    "{name}: header {:?} is wider than its {}-col field",
                    col.label,
                    col.w
                );
            }
        }
    }

    /// Dense advertises its keybinds in the box borders — that is what buys the
    /// layout its zero chrome rows, and it means the border is the only
    /// documentation most users will read. So a key printed there must exist.
    ///
    /// This list is checked against `app::handle_dense_key` by hand; the test
    /// exists to make the check deliberate when someone edits a footer. Three
    /// keys (`/ filter`, `sort`, `export`) shipped in the footer before any of
    /// them were implemented, and pressing them did nothing at all.
    #[test]
    fn advertised_keys_are_keys_that_exist() {
        // Every key spelled in a box footer, and the fact that it is handled.
        const ADVERTISED: &[(&str, bool)] = &[
            ("V", true),     // cycle view
            ("q", true),     // quit
            ("↑↓", true),    // select
            ("space", true), // fold the process under the cursor
            ("z", true),     // fold all
            ("p", true),     // pause
            (",", true),     // settings
            ("?", true),     // help
            ("1-4", true),   // zoom a box
            ("esc", true),   // restore the grid
        ];
        for (key, implemented) in ADVERTISED {
            assert!(
                *implemented,
                "the footer advertises {key:?} but handle_dense_key does not implement it"
            );
        }
    }

    /// The decoded protocol carries an SNI, which has no length limit, so the
    /// detail row's middle group must be clamped short of the right-aligned
    /// TCP internals. The first demo take rendered `HTTPS httpbcwnd 666`.
    #[test]
    fn detail_stats_cannot_run_under_the_tcp_internals() {
        for area in sizes() {
            let l = Layout::new(area);
            let internals = "cwnd 666  ssthresh 128  mss 1388  rwnd 2M".width() as u16;
            let avail = detail_stats_width(&l, internals);
            assert!(
                DETAIL_STATS_X + avail + internals < l.content_x_end,
                "{}×{}: stats group overruns the internals",
                area.width,
                area.height
            );
            // A pathological SNI must be cut, not allowed to overflow.
            let long = format!("rtt 1ms   retrans 0   ooo 0   HTTPS {}", "a".repeat(200));
            assert!(truncate(&long, avail as usize).width() as u16 <= avail);
        }
    }

    /// The first live run put the pid under the socket pair whenever a process
    /// name was long, because the pid's x was computed from the name's width.
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn detail_line_fields_cannot_overrun_each_other() {
        assert!(
            4 + DETAIL_PROC_W < DETAIL_PID_X,
            "a full-width process name runs into the pid"
        );
        assert!(
            DETAIL_PID_X + 11 <= DETAIL_SOCKET_X,
            "the pid runs into the socket pair"
        );
    }

    #[test]
    fn charts_carry_two_samples_per_column() {
        // The whole reason for braille here. If a caller ever passes width
        // instead of width*2, the plot silently shows half the window.
        let l = Layout::new(Rect::new(0, 0, 130, 44));
        let c = CompactLayout::new(Rect::new(0, 0, 80, 24));
        assert_eq!(fit_samples(&[1, 2, 3], l.chart_w as usize * 2).len(), 240);
        assert_eq!(fit_samples(&[1, 2, 3], c.chart_w as usize * 2).len(), 148);
    }

    /// The plot must **scroll**, not re-bucket. One sample per sub-column, so
    /// a tick shifts everything left by exactly one and every other column is
    /// unchanged — that identity is what makes the graph look smooth instead
    /// of churning in place.
    #[test]
    fn fit_samples_scrolls_by_exactly_one_sample_per_tick() {
        let history: Vec<u64> = (0..600).collect();
        let before = fit_samples(&history, 240);

        let mut after_history = history.clone();
        after_history.push(600);
        let after = fit_samples(&after_history, 240);

        assert_eq!(
            &before[1..],
            &after[..239],
            "every column except the newest must be the previous frame shifted one left"
        );
        assert_eq!(*after.last().unwrap(), 600, "`now` is the newest sample");
    }

    /// A windowed plot covers exactly the span its header claims, and a spike
    /// inside a bucket survives — dropping it would hide the only interesting
    /// thing in a 15-cell graph.
    #[test]
    fn fit_window_covers_its_claimed_span_and_keeps_spikes() {
        let mut data = vec![1u64; 600];
        data[560] = 999; // inside the last 120 samples
        data[10] = 5000; // long outside the window
        let out = fit_window(&data, 120, 30);
        assert_eq!(out.len(), 30);
        assert!(
            out.contains(&999),
            "a spike in the window must survive: {out:?}"
        );
        assert!(
            !out.contains(&5000),
            "a sample older than the window must not appear"
        );
    }

    /// An exact-max scale rescales the whole plot every time the peak moves.
    #[test]
    fn chart_ceilings_snap_to_round_numbers() {
        assert_eq!(nice_ceiling(0), 1);
        assert_eq!(nice_ceiling(1), 1);
        assert_eq!(nice_ceiling(437_000), 500_000);
        assert_eq!(nice_ceiling(512_000_000), 1_000_000_000);
        assert_eq!(nice_ceiling(150), 200);
        assert_eq!(nice_ceiling(2_000), 2_000, "an exact round value is kept");

        // Traffic drifting within an order of magnitude must not move the axis.
        let a = chart_max(&[430_000, 300_000]);
        let b = chart_max(&[470_000, 310_000]);
        assert_eq!(a, b, "a 9% change in peak must not rescale the plot");
    }

    /// btop fills its plot in from the right as history accrues; it does not
    /// stretch what it has across the whole window. Ours must not either.
    #[test]
    fn fit_samples_fills_from_the_right_and_never_stretches() {
        let out = fit_samples(&[5, 6], 8);
        assert_eq!(out, vec![0, 0, 0, 0, 0, 0, 5, 6]);
        assert_eq!(
            *out.last().unwrap(),
            6,
            "`now` must land on the last sample"
        );

        // A 20-sample history in a 240-sample plot must stay 20 samples wide,
        // not become 20 plateaus twelve columns each.
        let short: Vec<u64> = (1..=20).collect();
        let wide = fit_samples(&short, 240);
        assert_eq!(wide.len(), 240);
        assert_eq!(&wide[220..], &short[..], "real samples sit flush right");
        assert!(
            wide[..220].iter().all(|&v| v == 0),
            "the past is empty, not smeared"
        );
    }

    #[test]
    fn fit_samples_handles_empty_and_zero() {
        assert_eq!(fit_samples(&[], 4), vec![0, 0, 0, 0]);
        assert!(fit_samples(&[1, 2], 0).is_empty());
    }

    /// A list that reorders under the cursor is the difference between a live
    /// view and a jittery one — and because the selection is positional, a swap
    /// silently retargets the detail block to another connection.
    #[test]
    fn sort_rate_ignores_single_tick_noise() {
        let row = |hist: Vec<u64>, inst: f64| ConnRow {
            process: "curl".into(),
            pid: None,
            host: "h".into(),
            port: "443".into(),
            proto: "tcp".into(),
            rx_rate: inst,
            tx_rate: 0.0,
            rtt_ms: None,
            state: "ESTABLISHED".into(),
            retransmits: 0,
            out_of_order: 0,
            app_proto: None,
            local: String::new(),
            remote: String::new(),
            history: hist,
        };

        // Two flows of the same sustained speed, whose latest samples happen to
        // disagree, must not trade places on that alone.
        let steady = vec![1000u64; 8];
        let mut spiky = steady.clone();
        *spiky.last_mut().unwrap() = 4000;
        let a = row(steady, 1000.0);
        let b = row(spiky, 4000.0);
        let ratio = b.sort_rate() / a.sort_rate();
        assert!(
            ratio < 1.5,
            "one hot sample moved the sort key by {ratio:.2}× — the row will jump"
        );
        assert!(
            b.rx_rate / a.rx_rate >= 4.0,
            "the instantaneous rate really is 4× — that is what we are smoothing"
        );

        // A genuinely faster flow must still sort above a slower one.
        let fast = row(vec![50_000; 8], 50_000.0);
        let slow = row(vec![1_000; 8], 1_000.0);
        assert!(fast.sort_rate() > slow.sort_rate());

        // No history yet: fall back to what we have rather than sorting as zero.
        assert_eq!(row(vec![], 1234.0).sort_rate(), 1234.0);
    }

    #[test]
    fn split_host_port_handles_every_form_the_platforms_print() {
        assert_eq!(
            split_host_port("1.2.3.4:443"),
            ("1.2.3.4".into(), "443".into())
        );
        assert_eq!(
            split_host_port("[2606:4700::1111]:443"),
            ("2606:4700::1111".into(), "443".into())
        );
        // macOS lsof prints the closing bracket without the opening one.
        assert_eq!(
            split_host_port("fe80:16::145f:b7c7:8a9e:7fb7]:1024"),
            ("fe80:16::145f:b7c7:8a9e:7fb7".into(), "1024".into())
        );
        assert_eq!(
            split_host_port("example.com:8080"),
            ("example.com".into(), "8080".into())
        );
        assert_eq!(
            split_host_port("example.com"),
            ("example.com".into(), "".into())
        );
        // A bare IPv6 must keep its last group instead of donating it to port.
        assert_eq!(split_host_port("::1"), ("::1".into(), "".into()));
    }

    #[test]
    fn truncate_marks_what_it_cut() {
        assert_eq!(truncate("registry-1.docker.io", 30), "registry-1.docker.io");
        assert_eq!(truncate("registry-1.docker.io", 12), "registry-1.…");
        assert_eq!(truncate("abc", 1), "…");
    }

    /// Saturation is a ratio, and both halves must describe the same thing.
    /// Comparing an all-interface total against one interface's peak is what
    /// produced "123% of peak" on the first run.
    #[test]
    fn saturation_stays_within_a_hundred_percent() {
        let hist: Vec<u64> = vec![100, 500, 900, 400];
        let peak = hist.iter().copied().max().unwrap();
        for now in hist {
            let frac = now as f64 / peak as f64;
            assert!(
                (0.0..=1.0).contains(&frac),
                "a sample from the history cannot exceed the history's own peak"
            );
        }
    }

    #[test]
    fn states_fit_their_column_without_eliding() {
        let w = Layout::new(Rect::new(0, 0, 130, 44)).conn_cols[conn_col::STATE].w as usize;
        for s in [
            "ESTABLISHED",
            "TIME_WAIT",
            "CLOSE_WAIT",
            "FIN_WAIT1",
            "FIN_WAIT2",
            "SYN_SENT",
            "SYN_RECV",
            "LAST_ACK",
            "LISTEN",
        ] {
            let short = short_state(s);
            assert!(
                short.width() <= w,
                "state {s:?} renders as {short:?}, wider than its {w}-col column"
            );
        }
    }

    /// The meter's denominator decides whether it means anything. A known
    /// link speed is a fixed ceiling; the observed peak is a moving one and
    /// must say so in the label.
    #[test]
    fn saturation_measures_against_the_link_when_it_knows_it() {
        // 12.5 MB/s is 100 Mb/s — exactly half a 200 Mb link.
        let (f, label) = saturation(12_500_000.0, Some(200_000_000), None);
        assert!((f - 0.5).abs() < 0.001, "got {f}");
        assert_eq!(label, "50% of 200 Mb link");

        // Bytes vs bits is the factor-of-eight this function exists to contain.
        let (f, _) = saturation(125_000_000.0, Some(1_000_000_000), None);
        assert!((f - 1.0).abs() < 0.001, "125 MB/s saturates a 1 Gb link");

        let (_, label) = saturation(1.0, Some(1_000_000_000), None);
        assert_eq!(label, "0% of 1 Gb link");
    }

    #[test]
    fn saturation_falls_back_to_measured_throughput_and_says_so() {
        // 500 B/s against a 1000 B/s peak is half.
        let (f, label) = saturation(500.0, None, Some(1000));
        assert!((f - 0.5).abs() < 0.001, "got {f}");
        assert!(
            label.contains("seen"),
            "the label must say the ceiling is measured, not advertised: {label}"
        );
    }

    /// The case that pinned the meter at 100% through an entire file copy:
    /// macOS reported a 304 Mb Wi-Fi link while the interface actually carried
    /// 456 Mb/s. A ceiling below measured traffic is not a ceiling.
    #[test]
    fn a_link_speed_below_measured_throughput_is_not_believed() {
        let peak_bytes = 57_000_000u64; // 456 Mb/s
        let (f, label) = saturation(28_500_000.0, Some(304_000_000), Some(peak_bytes));
        assert!(
            (0.4..=0.6).contains(&f),
            "half of measured capacity should read ~50%, got {f}"
        );
        assert!(label.contains("seen"), "got {label}");

        // At the peak itself the meter is legitimately full.
        let (f, _) = saturation(peak_bytes as f64, Some(304_000_000), Some(peak_bytes));
        assert!((f - 1.0).abs() < 0.001);
    }

    /// An honest link speed must still win — the measured peak can never
    /// exceed it, so nothing changes on a wired gigabit link.
    #[test]
    fn an_accurate_link_speed_keeps_the_fixed_ceiling() {
        let (f, label) = saturation(12_500_000.0, Some(1_000_000_000), Some(50_000_000));
        assert!((f - 0.1).abs() < 0.001, "got {f}");
        assert_eq!(label, "10% of 1 Gb link");
    }

    #[test]
    fn a_ceiling_under_a_megabit_is_not_rendered_as_zero() {
        // What a quiet Wi-Fi link showed: no OS link speed, a small measured
        // peak, and a label reading "12% of 0 Mb". The ceiling was 480 Kb.
        let (_, label) = saturation(60_000.0, None, Some(60_000));
        assert!(label.contains("480 Kb"), "got {label}");
        assert!(!label.contains("0 Mb"), "got {label}");

        assert_eq!(short_bits(8_000), "8 Kb");
        assert_eq!(short_bits(1_500_000), "1.5 Mb");
        assert_eq!(short_bits(304_000_000), "304 Mb");
        assert_eq!(short_bits(1_000_000_000), "1 Gb");
        assert_eq!(short_bits(2_500_000_000), "2.5 Gb");
        assert_eq!(short_bits(999), "999 b");
    }

    /// No ceiling this function can be handed may label itself as zero of
    /// anything: the meter's denominator is the one number on the row that
    /// has to be true.
    #[test]
    fn no_ceiling_renders_as_a_zero_denominator() {
        for bps in [1u64, 999, 1_000, 60_000, 999_999, 1_000_000, 8_000_000_000] {
            let label = short_bits(bps);
            assert!(!label.starts_with("0 "), "{bps} bits rendered as {label}");
        }
    }

    #[test]
    fn saturation_with_nothing_known_says_so_rather_than_guessing() {
        let (f, label) = saturation(1000.0, None, None);
        assert_eq!(f, 0.0);
        assert!(label.starts_with(NA), "got {label}");
    }

    /// However the numbers arrive, the bar cannot exceed full — an over-full
    /// meter reported 123% on the first cut.
    #[test]
    fn saturation_never_exceeds_full() {
        for (now, link, peak) in [
            (1e12, Some(1_000_000u64), None),
            (1e12, None, Some(10u64)),
            (5.0, None, Some(0u64)),
            (0.0, None, None),
        ] {
            let (f, _) = saturation(now, link, peak);
            assert!((0.0..=1.0).contains(&f), "{f} out of range");
        }
    }

    #[test]
    fn short_bytes_reads_as_a_scale() {
        assert_eq!(short_bytes(0), "0");
        assert_eq!(short_bytes(512_000), "512K");
        assert_eq!(short_bytes(536_000_000), "536M");
        assert_eq!(short_bytes(2_000_000_000), "2G");
    }
}

#[cfg(test)]
mod zoom_tests {
    use super::*;

    /// A zoomed box owns the whole grid and the other three vanish — and the
    /// row arithmetic for the vanished boxes must not underflow on the way.
    #[test]
    fn zooming_a_box_gives_it_the_whole_screen() {
        let area = Rect::new(0, 0, GRID_W, GRID_H);
        let full = Rect::new(0, 0, GRID_W, GRID_H);
        for which in [
            DenseBox::Net,
            DenseBox::Ifaces,
            DenseBox::Health,
            DenseBox::Conns,
        ] {
            let l = Layout::zoomed(area, which);
            let boxes = [
                (DenseBox::Net, l.net),
                (DenseBox::Ifaces, l.ifaces),
                (DenseBox::Health, l.health),
                (DenseBox::Conns, l.conns),
            ];
            for (b, r) in boxes {
                if b == which {
                    assert_eq!(r, full, "{which:?} fills the screen");
                } else {
                    assert_eq!(r.area(), 0, "{b:?} is gone while {which:?} is zoomed");
                }
            }
        }
        // And the zoomed connection list is taller than the grid's.
        let grid = Layout::new(area);
        let zoomed = Layout::zoomed(area, DenseBox::Conns);
        assert!(zoomed.conn_rows > grid.conn_rows);
        assert!(Layout::zoomed(area, DenseBox::Ifaces).if_rows > grid.if_rows);
    }

    #[test]
    fn number_keys_name_the_boxes_by_their_badges() {
        assert_eq!(DenseBox::from_key('1'), Some(DenseBox::Net));
        assert_eq!(DenseBox::from_key('4'), Some(DenseBox::Conns));
        assert_eq!(DenseBox::from_key('5'), None);
    }
}

#[cfg(test)]
mod group_tests {
    use super::*;

    fn conn(process: &str, pid: u32, host: &str, rx: f64, retrans: u32, state: &str) -> ConnRow {
        ConnRow {
            process: process.into(),
            pid: Some(pid),
            host: host.into(),
            port: "443".into(),
            proto: "tcp".into(),
            rx_rate: rx,
            tx_rate: 0.0,
            rtt_ms: Some(pid as f64),
            state: state.into(),
            retransmits: retrans,
            out_of_order: 0,
            app_proto: None,
            local: "10.0.0.2:1".into(),
            remote: format!("{host}:443"),
            history: vec![1; 3],
        }
    }

    /// One socket is a row; several are a header with foldable children.
    /// The same function answers "what is row N" for the renderer and the
    /// key handlers, so it is the one to pin.
    #[test]
    fn a_solo_process_is_a_row_and_a_busy_one_is_a_tree() {
        let groups = conn_groups(vec![
            conn("curl", 1, "a", 5.0, 0, "ESTABLISHED"),
            conn("claude", 2, "b", 3.0, 0, "ESTABLISHED"),
            conn("claude", 2, "c", 4.0, 2, "ESTABLISHED"),
            conn("claude", 3, "c", 1.0, 0, "TIME_WAIT"),
        ]);
        // Busiest group first: claude sums to 8 against curl's 5.
        assert_eq!(groups[0].key, "claude");

        let open = crate::ui::tree::FoldState::new(false);
        let rows = dense_rows(&groups, &open);
        assert_eq!(rows.len(), 5, "header + 3 children + 1 solo");
        assert!(matches!(
            rows[0],
            DenseRow::Parent {
                collapsed: false,
                ..
            }
        ));
        assert!(rows[1..4]
            .iter()
            .all(|r| matches!(r, DenseRow::Child { .. })));
        assert!(matches!(rows[4], DenseRow::Solo { .. }));
        assert!(!rows[4].foldable());
        assert!(rows[1].foldable(), "a child folds its parent");
        assert_eq!(rows[1].key(), "claude");

        let folded = crate::ui::tree::FoldState::new(true);
        assert_eq!(dense_rows(&groups, &folded).len(), 2, "header + solo");

        // The rollup carries the group's worst, not its first.
        let r = &groups[0].rollup;
        assert_eq!((r.conns, r.pids, r.hosts), (3, 2, 2));
        assert!(r.degraded, "one retransmitting socket marks the group");
        assert_eq!(r.rtt_ms, Some(2.0), "best rtt, not first");
        assert_eq!(r.state, "ESTABLISHED", "dominant state");
        assert_eq!(r.history, vec![3, 3, 3], "sparklines summed");
    }
}
