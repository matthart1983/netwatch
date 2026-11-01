//! Pluggable graph rendering for every chart in the app.
//!
//! Mirrors the theme module: a `GraphStyle` enum with a small `by_name` lookup,
//! plus a `render` entry point (and `render_with_max` for shared-axis overlays)
//! that dispatches to a per-style implementation. Every sparkline in the UI —
//! aggregated RX/TX, in-row top-connection lines, RTT history, timeline
//! severity layers, etc. — routes through here so a single setting toggles
//! them all.
//!
//! `GraphOpts.fade` enables the magnitude gradient: every cell is coloured by
//! how high it sits in the plot. Call
//! sites build the opts from `App::graph_opts()` so a single config toggle
//! governs the entire UI.
//!
//! [`area_graph`] is the one braille renderer. `GraphStyle::Dots` is it, the
//! Dense view's mirrored plot is it with `flip`, and the Dashboard's
//! throughput graph is two of them sharing a scale — so no two graphs in the
//! tool can drift apart in texture or in colour.

use ratatui::buffer::Buffer;
use ratatui::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphStyle {
    /// Solid-color stacked blocks. Kept for terminals whose font has no
    /// braille coverage, where [`GraphStyle::Dots`] renders as empty boxes.
    Bars,
    /// The braille area plot: two samples per cell column and 4× the vertical
    /// resolution of `Bars`. The default, and what every other graph in the
    /// tool draws.
    Dots,
}

pub const GRAPH_STYLE_NAMES: &[&str] = &["bars", "dots"];

pub fn by_name(name: &str) -> GraphStyle {
    match name.to_lowercase().as_str() {
        "bars" => GraphStyle::Bars,
        _ => GraphStyle::Dots,
    }
}

impl GraphStyle {
    pub fn name(self) -> &'static str {
        match self {
            GraphStyle::Bars => "bars",
            GraphStyle::Dots => "dots",
        }
    }
}

/// Cross-cutting render preferences passed to every chart call site.
#[derive(Debug, Clone, Copy)]
pub struct GraphOpts {
    /// Colour each cell by its height in the plot — dim at the baseline,
    /// the series colour through the body, bright at the peak. Off renders
    /// the flat solid-colour look.
    ///
    /// This used to also draw a faint dot grid behind the data. It went:
    /// three dotted horizontals across a plot read as extra copies of the
    /// line, which is the opposite of what a guide is for.
    pub fade: bool,
    /// Theme background color, used as the "fade-to" anchor when
    /// interpolating column colors and as the fallback when no Rgb
    /// information is available.
    pub bg: Color,
    /// True under the `terminal` theme, where every colour must resolve
    /// through the user's own palette. Fade then steps between palette
    /// tokens instead of blending in RGB — see [`palette_ramp`].
    pub terminal_palette: bool,
    /// Draw a floor under a zero sample, so a quiet series reads as "no
    /// traffic" rather than "no data".
    ///
    /// False for a layer that shares a rect with other layers: the Timeline
    /// paints ok/warn/critical event counts over one axis, and a floor there
    /// claims an event at every second of the window. A red line across an
    /// empty timeline is worse than a gap.
    pub baseline: bool,
}

impl GraphOpts {
    /// For an overlay layer: paint only the columns this series actually has.
    pub fn without_baseline(mut self) -> Self {
        self.baseline = false;
        self
    }
}

impl Default for GraphOpts {
    fn default() -> Self {
        Self {
            fade: false,
            bg: Color::Reset,
            terminal_palette: false,
            baseline: true,
        }
    }
}

/// Bottom of the magnitude gradient: the fraction of the base color a value
/// sitting on the baseline receives. 0.30 keeps a quiet series visible without
/// letting it compete with a busy one.
const MIN_FADE_ALPHA: f32 = 0.30;

/// The least a magnitude ramp's dimmest stop may contrast with the background.
/// An area graph puts most of its ink near the baseline, so that end has to be
/// readable, not only the peaks.
const MIN_RAMP_CONTRAST: f64 = 4.0;

/// The least the series colour may contrast with the background. It has to clear
/// [`MIN_RAMP_CONTRAST`] by enough for the stops below it to climb.
const MIN_SERIES_CONTRAST: f64 = 6.0;

/// What a ramp is measured against when the theme leaves the background to the
/// terminal, whose real colour netwatch can't know.
const ASSUMED_DARK_BG: (u8, u8, u8) = (0x1a, 0x1b, 0x26);

/// A five-stop color ramp, sampled 0.0..=1.0 along the axis it is applied to.
///
/// One definition of "how netwatch colors a graph", shared by every renderer.
/// The Dense view grew its own copy first; the two were the same five stops
/// written twice, which is how a gradient ends up looking different on two
/// screens of the same tool.
///
/// A ramp with one distinct stop is the 16-color degrade path and is not a
/// special case anywhere else — [`Ramp::at`] just always returns the token.
#[derive(Debug, Clone)]
pub struct Ramp {
    stops: Vec<Color>,
}

impl Ramp {
    pub fn new(stops: Vec<Color>) -> Self {
        Self { stops }
    }

    pub fn flat(c: Color) -> Self {
        Self { stops: vec![c] }
    }

    /// Sample at `f`, clamped to 0.0..=1.0.
    pub fn at(&self, f: f32) -> Color {
        match self.stops.len() {
            0 => Color::Reset,
            1 => self.stops[0],
            n => {
                let t = f.clamp(0.0, 1.0) * (n - 1) as f32;
                let i = t.floor() as usize;
                if i >= n - 1 {
                    return self.stops[n - 1];
                }
                lerp(self.stops[i], self.stops[i + 1], t - i as f32)
            }
        }
    }

    /// The ramp's midpoint — used where a single representative color is
    /// wanted (a legend, a label above the graph it describes).
    pub fn mid(&self) -> Color {
        self.at(0.55)
    }
}

/// Sub-cell height of `v` against `max`, rounded.
fn sub_height(v: u64, max: u64, sub_h: usize) -> usize {
    if max == 0 {
        return 0;
    }
    let v = v.min(max) as u128;
    // Round half up in integer maths: (v * sub_h + max/2) / max.
    ((v * sub_h as u128 * 2 + max as u128) / (max as u128 * 2)) as usize
}

/// Braille area plot at two samples per cell column.
///
/// `samples` is oldest-first and must already be exactly `2 × area.width`
/// long — see [`resample_to_window`], which is where the bucketing lives so
/// that a spike between samples survives instead of being dropped by
/// decimation.
///
/// `flip` grows the plot **downward from the top edge** instead of upward from
/// the bottom. That is the whole mirrored-graph trick: the upload half is the
/// same function with `flip = true`, sharing the axis row above it.
///
/// Every cell is coloured by its own height in the plot rather than by which
/// series it belongs to, so severity is pre-attentive — you see the spike
/// before you read the axis.
pub fn area_graph(
    buf: &mut Buffer,
    area: Rect,
    samples: &[u64],
    max: u64,
    ramp: &Ramp,
    flip: bool,
) {
    area_graph_with(buf, area, samples, max, ramp, flip, true);
}

/// [`area_graph`], with explicit control over the zero-sample floor. An
/// overlay layer passes `baseline = false` so it paints only its own columns.
#[allow(clippy::too_many_arguments)]
pub fn area_graph_with(
    buf: &mut Buffer,
    area: Rect,
    samples: &[u64],
    max: u64,
    ramp: &Ramp,
    flip: bool,
    baseline: bool,
) {
    if area.width == 0 || area.height == 0 || max == 0 {
        return;
    }
    let w = area.width as usize;
    let h = area.height as usize;
    let sub_h = h * 4;

    for cx in 0..w {
        let lh = sub_height(samples.get(cx * 2).copied().unwrap_or(0), max, sub_h);
        let rh = sub_height(samples.get(cx * 2 + 1).copied().unwrap_or(0), max, sub_h);
        // A zero sample still draws its baseline dot. Skipping it leaves holes
        // in the area wherever traffic went quiet, which reads as "no data"
        // rather than "no traffic" — and it is what stops this looking like
        // btop, whose plot is continuous across the whole window.
        let (lh, rh) = if baseline {
            (lh.max(1), rh.max(1))
        } else if lh == 0 && rh == 0 {
            continue;
        } else {
            (lh, rh)
        };
        for cy in 0..h {
            let mut bits: u8 = 0;
            for (s, (l_dot, r_dot)) in BRAILLE_BIT[0].iter().zip(BRAILLE_BIT[1]).enumerate() {
                let from_top = cy * 4 + s;
                // Depth of this sub-row measured from the growing edge.
                let depth = if flip { from_top + 1 } else { sub_h - from_top };
                if lh >= depth {
                    bits |= 1 << l_dot;
                }
                if rh >= depth {
                    bits |= 1 << r_dot;
                }
            }
            if bits == 0 {
                continue;
            }
            // Sample the ramp at the cell's vertical midpoint, measured along
            // the direction of growth, so both halves of a mirrored pair
            // brighten as traffic climbs.
            let mid = (cy * 4 + 2) as f32;
            let f = if flip {
                mid / sub_h as f32
            } else {
                (sub_h as f32 - mid) / sub_h as f32
            };
            let Some(ch) = char::from_u32(BRAILLE_BASE | bits as u32) else {
                continue;
            };
            let cell = &mut buf[(area.x + cx as u16, area.y + cy as u16)];
            cell.set_char(ch);
            cell.set_style(Style::default().fg(ramp.at(f)));
        }
    }
}

/// Draw values that are **already bucketed to one per column**.
///
/// The Timeline builds its three severity layers by column — a column maps to
/// an event's severity — so it has exactly `width` values and no more. Passing
/// those to [`render_with_max`] under the braille style right-aligns them into
/// a plot with room for twice as many, leaving the left half of the strip
/// blank. Here each bucket fills its own column in both styles.
/// One row of bottom-anchored eighths, for a sparkline that lives inside a
/// line of text rather than its own plot area.
///
/// The Diagnose detail is a `Vec<Line>`: it has no plot rectangle to hand a
/// renderer, and giving it one would mean splitting the pane and laying the
/// two halves out separately. A row of glyphs slots into the text it explains
/// and keeps the pane a single flow.
///
/// Values at or below zero draw the floor glyph rather than a blank, so a
/// quiet series reads as measured-and-quiet, not as missing data.
pub fn bar_row(data: &[u64], width: usize, max: u64) -> Vec<char> {
    const GLYPHS: &[char] = &['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    if width == 0 || data.is_empty() {
        return vec![];
    }
    let start = data.len().saturating_sub(width);
    data[start..]
        .iter()
        .map(|&v| {
            if max == 0 {
                return GLYPHS[0];
            }
            let scaled = (v.min(max) as u128 * (GLYPHS.len() as u128 - 1) / max as u128) as usize;
            GLYPHS[scaled]
        })
        .collect()
}

pub fn render_bucketed_with_max(
    f: &mut Frame,
    area: Rect,
    buckets: &[u64],
    max: u64,
    style: GraphStyle,
    base: Color,
    opts: GraphOpts,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    match style {
        GraphStyle::Bars => render_bars(f.buffer_mut(), area, buckets, max, base, opts),
        GraphStyle::Dots => {
            let ramp = fade_ramp(base, opts).unwrap_or_else(|| Ramp::flat(base));
            // Each bucket lights both sub-columns of its own cell.
            let doubled: Vec<u64> = buckets.iter().flat_map(|&v| [v, v]).collect();
            area_graph_with(
                f.buffer_mut(),
                area,
                &doubled,
                max,
                &ramp,
                false,
                opts.baseline,
            );
        }
    }
}

/// Put a series on a fixed wall-clock grid, so several of them can share one
/// time axis.
///
/// `data` is oldest-first and its samples are `secs_per_sample` apart, ending
/// now. The result is exactly `slots` values covering the last `window_secs`,
/// oldest first — whatever cadence the source ran at.
///
/// Without this, tracks drawn one above the other are only aligned at their
/// right edge. The Dashboard's timeline plots throughput, which advances once
/// per refresh tick, beside dns and gateway latency, which advance once per
/// health probe — five times slower. Every track was right-aligned to "now",
/// so a column *N* from the right meant a different moment on each row, and
/// reading down the stack gave a correlation that was not there. That reading
/// is the entire reason the panel exists.
///
/// A slot takes the **maximum** of the samples landing in it, not their mean:
/// these are spike-hunting plots, and averaging is how a one-second stall
/// disappears into the four quiet seconds around it. A slot with no sample
/// gets 0 — the series genuinely has no reading for that moment.
pub fn resample_to_window(
    data: &[u64],
    secs_per_sample: u64,
    window_secs: u64,
    slots: usize,
) -> Vec<u64> {
    let mut out = vec![0u64; slots];
    if slots == 0 || window_secs == 0 || data.is_empty() {
        return out;
    }
    let secs_per_sample = secs_per_sample.max(1);

    for (i, &v) in data.iter().enumerate() {
        // Age of this sample: the last one is "now", each earlier one a
        // further `secs_per_sample` back.
        let age = (data.len() - 1 - i) as u64 * secs_per_sample;
        if age >= window_secs {
            continue;
        }
        // A sample stands for the whole interval it was measured over, not
        // for one instant. Mapping only its timestamp left holes wherever the
        // source is coarser than a column: 120 five-second probes across 134
        // columns lit about seven in eight, and the rtt tracks read as a comb
        // of dropouts next to a solid throughput track — the same window,
        // drawn as if the probe kept stopping.
        //
        // Slot 0 is the oldest end of the window.
        let newest = window_secs - age - 1;
        let oldest = newest.saturating_sub(secs_per_sample - 1);
        let to_slot =
            |from_left: u64| (from_left as u128 * slots as u128 / window_secs as u128) as usize;
        let (first, last) = (to_slot(oldest), to_slot(newest).min(slots - 1));
        for slot in out.iter_mut().take(last + 1).skip(first) {
            *slot = (*slot).max(v);
        }
    }
    out
}

/// A plotting ceiling that a single outlier cannot dominate.
///
/// A raw `max()` is right for a series whose peak *is* the story. It is wrong
/// for latency: one 200ms spike against a 2ms baseline scales every normal
/// sample to the floor, and the track goes flat — which a reader takes as
/// "this stream stopped updating", not "this stream is steady". That was the
/// state of the dashboard's `dns rtt` and `gateway rtt` tracks: 146 columns of
/// live data rendering as a straight line with one tower in it.
///
/// Clamping to a high percentile keeps the body of the distribution legible.
/// Values above it clip to full height, so a spike is still unmistakably a
/// spike — it just stops erasing everything else.
pub fn robust_max(data: &[u64], percentile: f64) -> u64 {
    let mut vals: Vec<u64> = data.iter().copied().filter(|&v| v > 0).collect();
    if vals.is_empty() {
        return 1;
    }
    vals.sort_unstable();
    let idx = ((vals.len() - 1) as f64 * percentile).round() as usize;
    let p = vals[idx.min(vals.len() - 1)];
    let median = vals[vals.len() / 2];
    // Headroom above the middle of the distribution. Without it a *steady*
    // series is as unreadable as a spiky one for the opposite reason: when
    // p95 equals the median, every sample sits at the ceiling and the track
    // renders as a solid bar. Half again above the median leaves a flat
    // series sitting around two-thirds height, where its small movements are
    // still visible.
    let headroom = median.saturating_add(median / 2).max(median + 1);
    p.max(headroom).max(1)
}

/// The span of time a plot `width` columns wide covers, in seconds.
///
/// This is the plot's *capacity*, not how much of it happens to be filled.
/// Plots right-align — newest at the right edge — so on a fresh start the
/// left columns are genuinely empty, and the axis saying so is accurate.
/// Labelling by the data instead stretches a short history's window across
/// columns that hold nothing, which claims those columns are inside it.
///
/// Capacity depends on the style — braille carries two samples per column,
/// blocks one — and a sample is one refresh interval, not one second. Getting
/// either wrong makes the axis name a window the graph is not drawing.
pub fn axis_window_secs(width: u16, style: GraphStyle, refresh_ms: u64) -> u64 {
    width as u64 * samples_per_column(style) as u64 * refresh_ms / 1000
}

/// Samples a column of this style shows: braille packs two, blocks one.
///
/// A plot that scrolls one sample per tick needs exactly this many slots per
/// column, or the axis under it names a window the plot is not drawing.
pub fn samples_per_column(style: GraphStyle) -> usize {
    match style {
        GraphStyle::Dots => 2,
        GraphStyle::Bars => 1,
    }
}

/// The x-axis strip under a time-series plot: the window's start, its
/// midpoint, and `now`, spread across `width`.
///
/// Three call sites each built this by hand from the literal strings `-60s`
/// and `-30s`, regardless of how wide the plot was or how much history it
/// held. At any size past sixty columns all three named a window the graph
/// was not drawing.
pub fn time_axis(width: u16, secs: u64) -> String {
    let w = width as usize;
    let mut out = String::new();
    for (i, frac) in [0.0f32, 0.5, 1.0].iter().enumerate() {
        let text = match i {
            2 => "now".to_string(),
            _ => format!("-{}s", (secs as f32 * (1.0 - frac)).round() as u64),
        };
        let target = ((w.saturating_sub(text.chars().count())) as f32 * frac).round() as usize;
        if out.chars().count() < target {
            out.push_str(&" ".repeat(target - out.chars().count()));
        }
        out.push_str(&text);
    }
    out
}

/// The gradient a renderer should paint with, or `None` for a flat series.
///
/// `None` when fade is off, and when the theme defers to the terminal palette
/// — there is no 16-color equivalent of a gradient, so it degrades to off
/// rather than to wrong.
fn fade_ramp(base: Color, opts: GraphOpts) -> Option<Ramp> {
    if !opts.fade {
        return None;
    }
    if opts.terminal_palette {
        return Some(palette_ramp(base));
    }
    Some(magnitude_ramp(base, opts.bg))
}

/// The magnitude gradient in the terminal's own sixteen colours.
///
/// Fade used to switch off entirely under the `terminal` theme, on the
/// grounds that a gradient needs blended colours and the theme exists to
/// never synthesise one. But the palette already holds a second stop for
/// every hue: `Green` has `LightGreen`, `Blue` has `LightBlue`. Two tokens
/// are a two-step gradient, which is what btop itself draws on a 16-colour
/// terminal — the series colour along the body of the plot, the bright
/// variant at the peak. No colour is invented: [`lerp`] returns its lower
/// stop for non-RGB inputs, so the ramp quantises to the tokens it names.
///
/// The bright step covers the top quarter. A one-row sparkline samples the
/// ramp at its midpoint and stays the series colour; only a plot tall enough
/// to have a peak gets the highlight on it.
pub fn palette_ramp(base: Color) -> Ramp {
    let bright = bright_token(base);
    Ramp::new(vec![base, base, base, bright, bright])
}

/// The palette's bright variant of a named or indexed colour.
///
/// Already-bright tokens and `Reset` come back unchanged rather than mapped
/// to `White`: a series drawn in the terminal's foreground has no brighter
/// self, and inventing one is exactly what the palette-deferring theme
/// promises not to do. RGB values pass through — they never reach here under
/// that theme, and outside it a gradient is blended, not stepped.
pub fn bright_token(c: Color) -> Color {
    match c {
        Color::Black => Color::DarkGray,
        Color::Red => Color::LightRed,
        Color::Green => Color::LightGreen,
        Color::Yellow => Color::LightYellow,
        Color::Blue => Color::LightBlue,
        Color::Magenta => Color::LightMagenta,
        Color::Cyan => Color::LightCyan,
        Color::Gray => Color::White,
        Color::DarkGray => Color::Gray,
        Color::Indexed(n) if n < 8 => Color::Indexed(n + 8),
        other => other,
    }
}

/// The magnitude gradient: dim at the baseline, the series color in the
/// middle, lightened at the peak.
///
/// This is btop's move, and the reason its graphs read as depth rather than as
/// a solid block: a cell's color comes from *how high it sits*, so the shape of
/// the data is legible even where the fill is continuous. netwatch used to fade
/// along the time axis instead — old columns dim, new columns bright — which
/// dims the history rather than describing it, and leaves a steady series a
/// flat wall in exactly the way the design review objected to.
pub fn magnitude_ramp(base: Color, bg: Color) -> Ramp {
    // Resolve the series colour to RGB *first*. `lighten` interpolates toward
    // white and returns its input unchanged for a named colour, so on the
    // default `dark` theme — which uses `Color::Green`, `Color::Cyan` and the
    // rest — the top three stops all collapsed to the same token and the
    // gradient only worked below the midpoint. Palette-deferring themes are
    // excluded upstream in `fade_ramp`, so mapping to RGB here does not
    // override anyone's palette.
    let (r, g, b) = to_rgb_or_default(base, (255, 255, 255));
    // Named colours resolve to the VGA palette, where the default theme's upload
    // series is (0, 0, 170): 1.6:1 at the series colour and less below it.
    let behind = to_rgb_or_default(bg, ASSUMED_DARK_BG);
    let base = with_contrast(Color::Rgb(r, g, b), behind, MIN_SERIES_CONTRAST);
    // The floor moves up the fade rather than toward white, so it keeps the hue.
    let floor = (0..=70)
        .map(|step| MIN_FADE_ALPHA + step as f32 / 100.0)
        .find(|&alpha| contrast(fade_color(base, bg, alpha, false), behind) >= MIN_RAMP_CONTRAST)
        .unwrap_or(1.0);
    Ramp::new(vec![
        fade_color(base, bg, floor, false),
        fade_color(base, bg, floor + (1.0 - floor) * 0.46, false),
        base,
        lighten(base, 0.42),
        lighten(base, 0.76),
    ])
}

/// `c`, moved away from the background only as far as `min` needs.
fn with_contrast(c: Color, behind: (u8, u8, u8), min: f64) -> Color {
    let away = if luminance(behind) < 0.18 {
        Color::Rgb(255, 255, 255)
    } else {
        Color::Rgb(0, 0, 0)
    };
    (0..=100)
        .map(|step| lerp(c, away, step as f32 / 100.0))
        .find(|&moved| contrast(moved, behind) >= min)
        .unwrap_or(away)
}

/// WCAG contrast ratio.
fn contrast(c: Color, behind: (u8, u8, u8)) -> f64 {
    let a = luminance(to_rgb_or_default(c, behind));
    let b = luminance(behind);
    (a.max(b) + 0.05) / (a.min(b) + 0.05)
}

/// WCAG relative luminance.
fn luminance((r, g, b): (u8, u8, u8)) -> f64 {
    let linear = |v: u8| {
        let v = v as f64 / 255.0;
        if v <= 0.04045 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b)
}

/// Linear blend, RGB only. Non-RGB inputs return `a` unchanged rather than
/// guessing at a palette entry's actual value — the same discipline as
/// [`fade_color`], and what makes an indexed ramp quantise to its own stops
/// instead of synthesising a color the theme exists to avoid.
pub fn lerp(a: Color, b: Color, f: f32) -> Color {
    match (rgb(a), rgb(b)) {
        (Some((ar, ag, ab)), Some((br, bg_, bb))) => {
            let f = f.clamp(0.0, 1.0);
            let mix = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * f).round() as u8;
            Color::Rgb(mix(ar, br), mix(ag, bg_), mix(ab, bb))
        }
        _ => a,
    }
}

pub fn lighten(c: Color, f: f32) -> Color {
    lerp(c, Color::Rgb(255, 255, 255), f)
}

fn rgb(c: Color) -> Option<(u8, u8, u8)> {
    match c {
        Color::Rgb(r, g, b) => Some((r, g, b)),
        _ => None,
    }
}

/// Lowest fraction of the row's foreground color the bottommost
/// visible row receives. Higher than the chart fade (0.55 vs 0.30) so
/// table text stays legible at the dim end — fade reads as visual
/// hierarchy, not as illegibility.
const MIN_ROW_FADE_ALPHA: f32 = 0.55;

/// Render `data` into `area` using the chosen style.
///
/// `base` is the primary series color (e.g. `theme.rx_rate`). `accent` is
/// reserved for future gradient styles; current styles ignore it but call
/// sites pass it for forward compatibility. Auto-derives the y-axis max
/// from `data` — use [`render_with_max`] when overlaying multiple series
/// that need a shared scale.
pub fn render(
    f: &mut Frame,
    area: Rect,
    data: &[u64],
    style: GraphStyle,
    base: Color,
    accent: Color,
    opts: GraphOpts,
) {
    let max = data.iter().copied().max().unwrap_or(0);
    render_with_max(f, area, data, max, style, base, accent, opts);
}

/// Like [`render`], but with an explicit y-axis max — required when
/// multiple layers must share a scale (e.g. the timeline's three-color
/// severity overlay).
pub fn render_with_max(
    f: &mut Frame,
    area: Rect,
    data: &[u64],
    max: u64,
    style: GraphStyle,
    base: Color,
    _accent: Color,
    opts: GraphOpts,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    match style {
        GraphStyle::Bars => render_bars(f.buffer_mut(), area, data, max, base, opts),
        GraphStyle::Dots => render_dots(f.buffer_mut(), area, data, max, base, opts),
    }
}

/// A shared-axis pair: `rx` growing up from the zero line, `tx` hanging below.
///
/// The zero line is **one row**, and it belongs to the rx half. Drawing the
/// two halves as independent plots gave each its own baseline — a solid
/// full-width line on the last row of the top plot *and* another on the first
/// row of the bottom one. Two parallel lines a row apart, which on a quiet
/// link is the entire graph and reads as the series being drawn twice.
///
/// Returns the height of the rx half, so the caller can label that row `0`
/// rather than recomputing the split and drifting from it.
#[allow(clippy::too_many_arguments)]
pub fn render_mirrored_with_max(
    buf: &mut Buffer,
    plot: Rect,
    rx: &[u64],
    tx: &[u64],
    max: u64,
    style: GraphStyle,
    rx_color: Color,
    tx_color: Color,
    opts: GraphOpts,
) -> u16 {
    render_mirrored_scaled(buf, plot, rx, tx, max, max, style, rx_color, tx_color, opts)
}

/// The same mirror, with a separate maximum for each half.
///
/// Sharing one maximum is what makes rx and tx comparable, and that is the
/// default. But a 16 MB/s download beside a 61 KB/s upload puts the whole tx
/// half below one row: half the panel renders empty, and the reader cannot
/// tell "almost nothing" from "nothing at all". The caller decides when the
/// ratio has passed that point, and labels the axis with both numbers so the
/// halves are not silently read against each other.
#[allow(clippy::too_many_arguments)]
pub fn render_mirrored_scaled(
    buf: &mut Buffer,
    plot: Rect,
    rx: &[u64],
    tx: &[u64],
    rx_max: u64,
    tx_max: u64,
    style: GraphStyle,
    rx_color: Color,
    tx_color: Color,
    opts: GraphOpts,
) -> u16 {
    if plot.width == 0 || plot.height == 0 {
        return 0;
    }
    // An odd number of rows gives the extra one to rx, which is the busier
    // series on almost every host.
    let tx_h = plot.height / 2;
    let rx_h = plot.height - tx_h;

    render_half(
        buf,
        Rect {
            height: rx_h,
            ..plot
        },
        rx,
        rx_max,
        style,
        rx_color,
        opts,
        false,
    );
    render_half(
        buf,
        Rect {
            y: plot.y + rx_h,
            height: tx_h,
            ..plot
        },
        tx,
        tx_max,
        style,
        tx_color,
        // The zero line the rx half draws is this half's floor too.
        GraphOpts {
            baseline: false,
            ..opts
        },
        true,
    );
    rx_h
}

/// One half of a mirrored plot, growing away from the zero line.
#[allow(clippy::too_many_arguments)]
fn render_half(
    buf: &mut Buffer,
    area: Rect,
    data: &[u64],
    max: u64,
    style: GraphStyle,
    color: Color,
    opts: GraphOpts,
    flip: bool,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    match (style, flip) {
        (GraphStyle::Bars, false) => render_bars(buf, area, data, max, color, opts),
        (GraphStyle::Bars, true) => render_bars_flipped(buf, area, data, max, color, opts),
        (GraphStyle::Dots, _) => {
            let ramp = fade_ramp(color, opts).unwrap_or_else(|| Ramp::flat(color));
            area_graph_with(
                buf,
                area,
                &two_per_column(data, area.width),
                max,
                &ramp,
                flip,
                opts.baseline,
            );
        }
    }
}

/// Right-align `data` into exactly `2 × width` samples, zero-padding the left.
fn two_per_column(data: &[u64], width: u16) -> Vec<u64> {
    let want = width as usize * 2;
    let start = data.len().saturating_sub(want);
    let mut out = vec![0u64; want.saturating_sub(data.len() - start)];
    out.extend_from_slice(&data[start..]);
    out
}

fn render_bars(buf: &mut Buffer, area: Rect, data: &[u64], max: u64, base: Color, opts: GraphOpts) {
    if max == 0 || area.width == 0 || area.height == 0 {
        return;
    }

    let cell_w = area.width as usize;
    let cell_h = area.height as usize;
    let start = data.len().saturating_sub(cell_w);
    let samples = &data[start..];
    let n = samples.len();
    let ramp = fade_ramp(base, opts);

    const BAR_GLYPHS: &[char] = &[' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

    for (i, &v) in samples.iter().enumerate() {
        if max == 0 {
            continue;
        }
        let x_offset = cell_w.saturating_sub(n) + i;
        if x_offset >= cell_w {
            continue;
        }
        let x = area.x + x_offset as u16;

        // Number of one-eighth bar units this sample reaches. A zero sample
        // still draws its floor, for the same reason the braille plot draws a
        // baseline dot: a gap in the series reads as "no data" when what
        // happened was "no traffic", and a quiet track rendered as an empty
        // row looks like a track that failed to load.
        let v_clamped = v.min(max);
        let mut total_eighths = (v_clamped as u128 * cell_h as u128 * 8 / max as u128) as usize;
        if opts.baseline {
            total_eighths = total_eighths.max(1);
        } else if total_eighths == 0 {
            continue;
        }
        for cy in 0..cell_h {
            let cell_from_bottom = cell_h - 1 - cy;
            let eighths_in_this_cell = total_eighths.saturating_sub(cell_from_bottom * 8).min(8);
            let glyph = BAR_GLYPHS[eighths_in_this_cell];
            if glyph != ' ' {
                // Each cell takes its color from where it sits in the plot,
                // so a bar darkens toward its base and brightens at its tip.
                // The cell's midpoint, so a one-row sparkline samples the
                // middle of the ramp — the series colour — rather than its
                // dimmest end. Dividing by `cell_h - 1` put every in-row
                // sparkline at 0.0 and rendered them nearly invisible.
                let color = match &ramp {
                    Some(r) => r.at((cell_from_bottom as f32 + 0.5) / cell_h as f32),
                    None => base,
                };
                let cell = &mut buf[(x, area.y + cy as u16)];
                cell.set_char(glyph);
                cell.set_style(Style::default().fg(color));
            }
        }
    }
}

/// Top-anchored blocks, for the mirrored half of a `bars` graph.
///
/// Only three fill levels, against the eight [`render_bars`] has. The
/// bottom-anchored eighths (`▁`–`▇`) all live in the Block Elements range;
/// their top-anchored counterparts beyond `▔` (1/8) and `▀` (1/2) are in
/// Symbols for Legacy Computing, whose font coverage is exactly what `bars`
/// exists to avoid depending on. A coarser mirror in the fallback style beats
/// a mirror made of tofu.
fn render_bars_flipped(
    buf: &mut Buffer,
    area: Rect,
    data: &[u64],
    max: u64,
    base: Color,
    opts: GraphOpts,
) {
    if max == 0 || area.width == 0 || area.height == 0 {
        return;
    }
    let cell_w = area.width as usize;
    let cell_h = area.height as usize;
    let start = data.len().saturating_sub(cell_w);
    let samples = &data[start..];
    let n = samples.len();
    let ramp = fade_ramp(base, opts);

    for (i, &v) in samples.iter().enumerate() {
        let x_offset = cell_w.saturating_sub(n) + i;
        if x_offset >= cell_w {
            continue;
        }
        let x = area.x + x_offset as u16;
        let mut total_eighths = (v.min(max) as u128 * cell_h as u128 * 8 / max as u128) as usize;
        if opts.baseline {
            total_eighths = total_eighths.max(1);
        } else if total_eighths == 0 {
            continue;
        }
        for cy in 0..cell_h {
            let eighths = total_eighths.saturating_sub(cy * 8).min(8);
            // Nearest of the three levels the safe glyphs can express.
            let glyph = match eighths {
                0 => continue,
                1..=2 => '▔',
                3..=6 => '▀',
                _ => '█',
            };
            let color = match &ramp {
                Some(r) => r.at((cy as f32 + 0.5) / cell_h as f32),
                None => base,
            };
            let cell = &mut buf[(x, area.y + cy as u16)];
            cell.set_char(glyph);
            cell.set_style(Style::default().fg(color));
        }
    }
}

// ── braille pixel-dot line plot ─────────────────────────────────────────────

/// Bit position in a braille cell mask for each (sub_col, sub_row).
/// Braille pattern dots numbered 1–8 map to bits 0–7; the 4th row uses dots
/// 7 and 8 (bits 6 and 7) which is why it's not a straight `row + col*4`.
///
/// `pub(crate)` because the Dense view's mirrored graph addresses the two
/// sub-columns independently (two samples per cell) rather than filling both
/// like [`render_dots`] does. Same table, different packing — duplicating it
/// is how the two drift apart.
pub(crate) const BRAILLE_BIT: [[u8; 4]; 2] = [
    [0, 1, 2, 6], // sub_col 0: rows 0..=3 → dots 1, 2, 3, 7
    [3, 4, 5, 7], // sub_col 1: rows 0..=3 → dots 4, 5, 6, 8
];

pub(crate) const BRAILLE_BASE: u32 = 0x2800;

/// btop's area plot, at two samples per cell column.
///
/// This used to be a second braille renderer that filled *both* sub-columns
/// for every sample. That halves the horizontal resolution and, more visibly,
/// draws each sample as a solid full-width column — so a "dots" sparkline came
/// out as a row of bars, which is the look the style exists to replace. It now
/// delegates to [`area_graph`], the same renderer the Dense view and the
/// Dashboard's throughput graph use, so every graph in the tool has the same
/// texture and the same gradient.
fn render_dots(
    buf: &mut Buffer,
    area: Rect,
    data: &[u64],
    max: u64,
    color: Color,
    opts: GraphOpts,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let ramp = fade_ramp(color, opts).unwrap_or_else(|| Ramp::flat(color));
    area_graph_with(
        buf,
        area,
        &two_per_column(data, area.width),
        max,
        &ramp,
        false,
        opts.baseline,
    );
}

// ── fade helpers ────────────────────────────────────────────────────────────

/// Linear-interpolate from `bg` toward `base` at fraction `alpha`. Only
/// works in RGB; named/indexed colors are returned unchanged so we don't
/// silently lose them. Themes ship with `Color::Rgb` everywhere, so this
/// is the common path.
pub fn fade_color(base: Color, bg: Color, alpha: f32, defer_to_terminal: bool) -> Color {
    // No 16-color equivalent of a gradient exists, so fade degrades to off
    // rather than to wrong. Interpolating would also be doubly wrong here:
    // `bg` is Reset under that theme, so it would fade toward an assumed
    // black regardless of the terminal's real background.
    if defer_to_terminal {
        return base;
    }
    let alpha = alpha.clamp(0.0, 1.0);
    let (br, bgc, bb) = to_rgb_or_default(base, (255, 255, 255));
    let (gr, gg, gb) = to_rgb_or_default(bg, (0, 0, 0));
    Color::Rgb(
        lerp_u8(gr, br, alpha),
        lerp_u8(gg, bgc, alpha),
        lerp_u8(gb, bb, alpha),
    )
}

fn to_rgb_or_default(c: Color, fallback: (u8, u8, u8)) -> (u8, u8, u8) {
    // Standard xterm palette mapping. Necessary because the default
    // "dark" theme uses ANSI named colors (Color::Green, Color::Cyan,
    // …) — fade_color would otherwise fall through to a single fallback
    // and render every chart as a grayscale gradient regardless of base
    // color, which looks identical to "fade off" on first glance.
    match c {
        Color::Rgb(r, g, b) => (r, g, b),
        Color::Reset => fallback,
        Color::Black => (0, 0, 0),
        Color::Red => (170, 0, 0),
        Color::Green => (0, 170, 0),
        Color::Yellow => (170, 85, 0),
        Color::Blue => (0, 0, 170),
        Color::Magenta => (170, 0, 170),
        Color::Cyan => (0, 170, 170),
        Color::Gray => (170, 170, 170),
        Color::DarkGray => (85, 85, 85),
        Color::LightRed => (255, 85, 85),
        Color::LightGreen => (85, 255, 85),
        Color::LightYellow => (255, 255, 85),
        Color::LightBlue => (85, 85, 255),
        Color::LightMagenta => (255, 85, 255),
        Color::LightCyan => (85, 255, 255),
        Color::White => (255, 255, 255),
        // Color::Indexed(_) — could map via the 256-color palette but
        // not currently in use by any theme; fall back to neutral.
        _ => fallback,
    }
}

fn lerp_u8(a: u8, b: u8, t: f32) -> u8 {
    (a as f32 + (b as f32 - a as f32) * t)
        .round()
        .clamp(0.0, 255.0) as u8
}

/// Linear alpha for the `row_idx`-th visible row in a table of
/// `total_visible_rows` rows. Row 0 is full intensity (alpha 1.0);
/// the last row sits at `MIN_ROW_FADE_ALPHA`. Single-row tables get
/// 1.0 (avoid div-by-zero edge case).
pub fn row_fade_alpha(row_idx: usize, total_visible_rows: usize) -> f32 {
    if total_visible_rows <= 1 {
        return 1.0;
    }
    let denom = (total_visible_rows - 1) as f32;
    1.0 - (1.0 - MIN_ROW_FADE_ALPHA) * (row_idx as f32 / denom)
}

/// Map over every span in `spans`, blending each span's foreground
/// color toward `bg` at `alpha`. Used by table row renderers to apply
/// the btop-style top-bright / bottom-dim row fade in one shot, without
/// touching every per-cell color computation upstream. Spans without an
/// explicit fg are left untouched so unstyled text doesn't suddenly
/// pick up a fade color it wasn't supposed to have.
pub fn fade_spans_fg(
    spans: Vec<Span<'_>>,
    bg: Color,
    alpha: f32,
    defer_to_terminal: bool,
) -> Vec<Span<'_>> {
    spans
        .into_iter()
        .map(|mut s| {
            if let Some(fg) = s.style.fg {
                s.style = s.style.fg(fade_color(fg, bg, alpha, defer_to_terminal));
            }
            s
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dashboard timeline stacks throughput (one sample per tick) over the
    /// latency probes (one per five ticks). A column has to be the same moment
    /// on every row, whatever the source cadence.
    #[test]
    fn one_spike_does_not_flatten_the_rest_of_a_series() {
        // A steady 2ms latency with a single 200ms excursion — the exact
        // shape that rendered the dashboard's rtt tracks as a flat line.
        let mut data = vec![2u64; 145];
        data.push(200);

        assert_eq!(data.iter().copied().max().unwrap(), 200);
        let robust = robust_max(&data, 0.95);
        assert!(
            robust <= 3,
            "a lone outlier must not set the ceiling, got {robust}"
        );

        // A normal sample's share of full height: 1% under the raw max — the
        // floor, i.e. invisible — against most of the height under this one.
        let raw = data.iter().copied().max().unwrap() as f64;
        assert!(2.0 / raw < 0.05, "raw max renders normal samples flat");
        assert!(2.0 / robust as f64 > 0.5);
    }

    #[test]
    fn a_steady_series_does_not_render_as_a_solid_bar() {
        // 0.5ms dns latency in microseconds, barely moving. Every sample must
        // land below the ceiling, or the track saturates and says nothing.
        let data = vec![500u64; 100];
        let ceiling = robust_max(&data, 0.95);
        assert!(
            ceiling > 500,
            "a flat series needs headroom above it, got {ceiling}"
        );
        let share = 500.0 / ceiling as f64;
        assert!(
            (0.5..0.9).contains(&share),
            "a steady series should sit mid-height, not at the ceiling ({share:.2})"
        );
    }

    #[test]
    fn a_nearly_steady_series_shows_its_wiggle() {
        let mut data = vec![500u64; 100];
        for (i, v) in data.iter_mut().enumerate() {
            *v = 500 + (i as u64 % 7) * 10;
        }
        let ceiling = robust_max(&data, 0.95);
        let lo = *data.iter().min().unwrap() as f64 / ceiling as f64;
        let hi = *data.iter().max().unwrap() as f64 / ceiling as f64;
        assert!(hi < 1.0, "the top of a steady series must not clip");
        assert!(hi - lo > 0.0, "its variation must survive the scaling");
    }

    #[test]
    fn a_genuinely_varied_series_keeps_its_range() {
        let data: Vec<u64> = (1..=100).collect();
        let robust = robust_max(&data, 0.95);
        assert!(
            robust >= 90,
            "a real spread must not be clamped away, got {robust}"
        );
    }

    #[test]
    fn robust_max_is_total() {
        assert_eq!(robust_max(&[], 0.95), 1);
        assert_eq!(robust_max(&[0, 0, 0], 0.95), 1);
        // A lone sample gets headroom like any other steady series, so it
        // draws below the ceiling rather than as a full-height bar.
        assert!(robust_max(&[7], 0.95) > 7);
        // Percentiles outside 0..1 must not index out of bounds.
        assert!(robust_max(&[1, 2, 3], 5.0) >= 1);
        assert!(robust_max(&[1, 2, 3], -1.0) >= 1);
    }

    #[test]
    fn streams_of_different_cadences_land_on_the_same_columns() {
        const WINDOW: u64 = 600;
        const SLOTS: usize = 60;

        // 600 one-second samples and 120 five-second samples cover the same
        // ten minutes. A ramp in each should light the same slots.
        let fast: Vec<u64> = (0..600).map(|i| i as u64).collect();
        let slow: Vec<u64> = (0..120).map(|i| i as u64 * 5).collect();

        let a = resample_to_window(&fast, 1, WINDOW, SLOTS);
        let b = resample_to_window(&slow, 5, WINDOW, SLOTS);

        assert_eq!(a.len(), b.len());
        assert!(
            a.iter().all(|&v| v > 0),
            "a full fast series must fill every slot"
        );
        assert!(
            b.iter().all(|&v| v > 0),
            "a full slow series covering the same window must fill every slot too"
        );
    }

    /// The bug this was reported as: the slow series retained half the window
    /// of the fast one, so its track stopped extending part-way across and
    /// stayed there while its neighbour kept growing.
    #[test]
    fn a_short_retention_leaves_dead_columns_the_neighbour_fills() {
        const WINDOW: u64 = 600;
        const SLOTS: usize = 60;

        let fast: Vec<u64> = vec![7; 600];
        let starved: Vec<u64> = vec![7; 60]; // 60 × 5s = 300s — half the window

        let a = resample_to_window(&fast, 1, WINDOW, SLOTS);
        let b = resample_to_window(&starved, 5, WINDOW, SLOTS);

        let a_filled = a.iter().filter(|&&v| v > 0).count();
        let b_filled = b.iter().filter(|&&v| v > 0).count();
        assert_eq!(a_filled, SLOTS);
        assert!(
            b_filled < a_filled,
            "this is the reported symptom, reproduced: {b_filled} of {SLOTS} slots"
        );

        // And with the retention corrected, they agree.
        let fixed: Vec<u64> = vec![7; 120];
        let c = resample_to_window(&fixed, 5, WINDOW, SLOTS);
        assert_eq!(c.iter().filter(|&&v| v > 0).count(), SLOTS);
    }

    /// The dashboard draws this window across the panel's full width, which
    /// is more columns than the probes have samples. Every column inside the
    /// covered span must carry data: a five-second probe owns five seconds of
    /// the axis, not one instant of it.
    #[test]
    fn a_coarse_cadence_fills_every_column_it_covers() {
        const WINDOW: u64 = 600;
        // Wider than the 120 samples a 5s probe retains over ten minutes,
        // which is the dashboard's real geometry.
        const SLOTS: usize = 134;

        let probes: Vec<u64> = vec![7; 120];
        let out = resample_to_window(&probes, 5, WINDOW, SLOTS);
        assert_eq!(
            out.iter().filter(|&&v| v > 0).count(),
            SLOTS,
            "a fully-retained series must not leave gaps: {out:?}"
        );

        // And it still agrees column-for-column with a per-tick series over
        // the same window, which is the whole point of the stack.
        let ticks: Vec<u64> = vec![7; 600];
        assert_eq!(out, resample_to_window(&ticks, 1, WINDOW, SLOTS));
    }

    /// What "smooth" means for a scrolling strip: one tick later, every slot
    /// holds what its right-hand neighbour held, and the new sample is at the
    /// end. A window sized to the slots at the source cadence gives exactly
    /// that. The old fixed ten-minute window over ~134 columns did not — a
    /// sample crossed a column edge on its own schedule, so the shape
    /// crawled and shimmered between lurches instead of scrolling.
    #[test]
    fn one_tick_later_the_strip_has_shifted_by_exactly_one_slot() {
        const SLOTS: usize = 134;
        let mut history: Vec<u64> = (0..600).map(|i| i * 7 % 101).collect();
        let before = resample_to_window(&history, 1, SLOTS as u64, SLOTS);

        history.remove(0);
        history.push(999);
        let after = resample_to_window(&history, 1, SLOTS as u64, SLOTS);

        assert_eq!(&after[..SLOTS - 1], &before[1..]);
        assert_eq!(after[SLOTS - 1], 999);

        // And a slower source over the same window shifts in step with it:
        // a 5s probe covers five slots, and next tick covers the next five.
        let probes: Vec<u64> = (0..120).map(|i| i + 1).collect();
        let a = resample_to_window(&probes, 5, SLOTS as u64, SLOTS);
        let newest_run = a.iter().rev().take_while(|&&v| v == 120).count();
        assert_eq!(newest_run, 5, "the newest probe owns its five slots: {a:?}");
    }

    #[test]
    fn the_newest_sample_is_always_the_rightmost_slot() {
        // Whatever the cadence, "now" is the right edge — otherwise stacked
        // tracks would disagree about where the present is.
        for (cadence, len) in [(1u64, 600usize), (5, 120)] {
            let mut data = vec![1u64; len];
            *data.last_mut().unwrap() = 999;
            let out = resample_to_window(&data, cadence, 600, 60);
            assert_eq!(
                *out.last().unwrap(),
                999,
                "cadence {cadence}: newest sample must land in the last slot"
            );
        }
    }

    #[test]
    fn a_partly_filled_series_right_aligns() {
        // Ten minutes of capacity, one minute of data: the newest end is
        // populated and the old end is honestly empty.
        let data = vec![5u64; 60];
        let out = resample_to_window(&data, 1, 600, 60);
        assert_eq!(*out.last().unwrap(), 5);
        assert_eq!(out[0], 0, "the ten-minutes-ago slot holds no data yet");
    }

    #[test]
    fn resampling_is_total_for_degenerate_inputs() {
        assert!(resample_to_window(&[], 1, 600, 60).iter().all(|&v| v == 0));
        assert!(resample_to_window(&[1, 2], 1, 0, 60)
            .iter()
            .all(|&v| v == 0));
        assert_eq!(resample_to_window(&[1, 2], 1, 600, 0).len(), 0);
        // A zero cadence must not divide by zero.
        assert_eq!(resample_to_window(&[1, 2], 0, 600, 4).len(), 4);
    }

    /// A cell carries **two** samples, one per braille sub-column.
    ///
    /// The dots style used to light both sub-columns from a single sample,
    /// which draws every sample as a solid full-width column — a bar. That
    /// halved the horizontal resolution and made the "dots" setting look like
    /// the "bars" one it exists to replace. Two adjacent samples of different
    /// heights must now produce a cell that is taller on one side.
    #[test]
    fn a_dots_cell_carries_two_independent_samples() {
        let area = Rect::new(0, 0, 1, 1);
        let mut buf = Buffer::empty(area);
        // Left sub-column low, right sub-column full.
        render_dots(
            &mut buf,
            area,
            &[1, 10],
            10,
            Color::Green,
            GraphOpts::default(),
        );
        let sym = buf[(0, 0)].symbol().to_string();
        assert_ne!(sym, "⣿", "both halves cannot be full — the samples differ");
        assert_ne!(sym, "⣀", "the right half is a full-height sample");

        // Equal samples do fill the cell, which is what keeps a busy series
        // reading as a solid area rather than a dot matrix.
        let mut buf = Buffer::empty(area);
        render_dots(
            &mut buf,
            area,
            &[10, 10],
            10,
            Color::Green,
            GraphOpts::default(),
        );
        assert_eq!(buf[(0, 0)].symbol(), "⣿");
    }

    /// A quiet series still draws its baseline, so a gap reads as "no
    /// traffic" rather than "no data".
    #[test]
    fn dots_draw_a_baseline_for_zero_samples() {
        let area = Rect::new(0, 0, 1, 1);
        let mut buf = Buffer::empty(area);
        render_dots(
            &mut buf,
            area,
            &[0, 0],
            10,
            Color::Green,
            GraphOpts::default(),
        );
        assert_eq!(buf[(0, 0)].symbol(), "⣀");
    }

    /// Every entry point honours the style, the mirrored one included. The
    /// Dashboard's throughput plot called the braille renderer directly, so
    /// under `graph_style = "bars"` it was the one graph on the screen that
    /// ignored the setting — which reads as the setting being broken.
    #[test]
    fn the_flipped_renderer_honours_the_style() {
        let area = Rect::new(0, 0, 4, 2);
        let data: Vec<u64> = vec![10; 8];

        let braille = |c: char| ('\u{2800}'..='\u{28FF}').contains(&c);
        let blocks = |c: char| matches!(c, '▔' | '▀' | '█');

        let mut dots = Buffer::empty(area);
        render_bars_flipped_or_dots(&mut dots, area, &data, 10, GraphStyle::Dots);
        let mut bars = Buffer::empty(area);
        render_bars_flipped_or_dots(&mut bars, area, &data, 10, GraphStyle::Bars);

        for x in 0..4u16 {
            let d = dots[(x, 0)].symbol().chars().next().unwrap();
            let b = bars[(x, 0)].symbol().chars().next().unwrap();
            assert!(braille(d), "dots drew {d:?}");
            assert!(blocks(b), "bars drew {b:?}");
        }
    }

    /// The downward-growing half of a mirrored plot, on its own.
    fn render_bars_flipped_or_dots(
        buf: &mut Buffer,
        area: Rect,
        data: &[u64],
        max: u64,
        style: GraphStyle,
    ) {
        render_half(
            buf,
            area,
            data,
            max,
            style,
            Color::Green,
            GraphOpts::default(),
            true,
        );
    }

    /// A quiet link is the case that exposed this: with both halves drawing
    /// their own floor, the throughput panel showed two solid full-width
    /// lines one row apart, which reads as the series drawn twice. The mirror
    /// has one zero line and it belongs to the rx half.
    #[test]
    fn a_mirrored_plot_draws_one_zero_line() {
        for style in [GraphStyle::Dots, GraphStyle::Bars] {
            let area = Rect::new(0, 0, 20, 8);
            let mut buf = Buffer::empty(area);
            let quiet = vec![0u64; 40];
            let rx_h = render_mirrored_with_max(
                &mut buf,
                area,
                &quiet,
                &quiet,
                1,
                style,
                Color::Green,
                Color::Blue,
                GraphOpts::default(),
            );
            assert_eq!(rx_h, 4, "{style:?}: rx takes the extra row of an odd split");

            let painted = |y: u16| {
                (0..area.width)
                    .filter(|&x| buf[(x, y)].symbol() != " ")
                    .count()
            };
            assert_eq!(
                painted(rx_h - 1),
                area.width as usize,
                "{style:?}: the zero line spans the plot"
            );
            assert_eq!(
                painted(rx_h),
                0,
                "{style:?}: the tx half must not draw a second one below it"
            );
        }
    }

    /// Under the `terminal` theme fade is a two-step gradient in palette
    /// tokens, not off. The body of the plot is the series colour and the
    /// peak is its bright variant; nothing in between is synthesised.
    #[test]
    fn terminal_fade_steps_between_two_palette_tokens() {
        let opts = GraphOpts {
            fade: true,
            bg: Color::Reset,
            terminal_palette: true,
            baseline: true,
        };
        let ramp = fade_ramp(Color::Green, opts).expect("fade is on, so there is a ramp");

        assert_eq!(ramp.at(0.0), Color::Green, "the floor is the series colour");
        assert_eq!(
            ramp.at(0.5),
            Color::Green,
            "a one-row sparkline stays the series colour"
        );
        assert_eq!(
            ramp.at(1.0),
            Color::LightGreen,
            "the peak is the bright token"
        );
        for f in [0.0, 0.1, 0.3, 0.5, 0.7, 0.9, 1.0] {
            assert!(
                matches!(ramp.at(f), Color::Green | Color::LightGreen),
                "at {f} the ramp invented {:?}",
                ramp.at(f)
            );
        }

        // Fade off is still off, whatever the theme.
        assert!(fade_ramp(
            Color::Green,
            GraphOpts {
                fade: false,
                ..opts
            }
        )
        .is_none());
    }

    /// Every dull palette token has a bright one; the bright ones and the
    /// terminal's own foreground have nowhere brighter to go.
    #[test]
    fn bright_tokens_stay_inside_the_palette() {
        assert_eq!(bright_token(Color::Blue), Color::LightBlue);
        assert_eq!(bright_token(Color::Indexed(2)), Color::Indexed(10));
        assert_eq!(bright_token(Color::LightGreen), Color::LightGreen);
        assert_eq!(bright_token(Color::Indexed(10)), Color::Indexed(10));
        assert_eq!(bright_token(Color::Reset), Color::Reset);
        assert_eq!(bright_token(Color::Rgb(1, 2, 3)), Color::Rgb(1, 2, 3));
    }

    /// The floor rule, for every entry point: a quiet series paints exactly
    /// **one** row. Two is what "the graph is drawn twice" looks like — it is
    /// how the dashboard's mirror read before its halves stopped each drawing
    /// their own baseline, and it is the cheapest thing to regress.
    #[test]
    fn a_quiet_series_paints_exactly_one_row() {
        let area = Rect::new(0, 0, 20, 6);
        let quiet = vec![0u64; 40];

        for style in [GraphStyle::Dots, GraphStyle::Bars] {
            let mut plain = Buffer::empty(area);
            render_half(
                &mut plain,
                area,
                &quiet,
                1,
                style,
                Color::Green,
                GraphOpts::default(),
                false,
            );
            assert_eq!(
                painted_rows(&plain, area),
                vec![area.height - 1],
                "{style:?}: an upward plot floors on its bottom row and nowhere else"
            );

            let mut flipped = Buffer::empty(area);
            render_half(
                &mut flipped,
                area,
                &quiet,
                1,
                style,
                Color::Green,
                GraphOpts::default(),
                true,
            );
            assert_eq!(
                painted_rows(&flipped, area),
                vec![0],
                "{style:?}: a downward plot floors on its top row and nowhere else"
            );

            // And the pair of them together is still one line, not two.
            let mut mirrored = Buffer::empty(area);
            let rx_h = render_mirrored_with_max(
                &mut mirrored,
                area,
                &quiet,
                &quiet,
                1,
                style,
                Color::Green,
                Color::Blue,
                GraphOpts::default(),
            );
            assert_eq!(
                painted_rows(&mirrored, area),
                vec![rx_h - 1],
                "{style:?}: a mirror has one zero line"
            );
        }
    }

    /// Rows with any painted cell in them, top first.
    fn painted_rows(buf: &Buffer, area: Rect) -> Vec<u16> {
        (0..area.height)
            .filter(|&y| (0..area.width).any(|x| buf[(x, y)].symbol() != " "))
            .collect()
    }

    /// The dots style and the Dense view's plot are the same renderer, so a
    /// sparkline and the graph above it cannot drift apart in texture.
    #[test]
    fn the_dots_style_is_the_dense_area_plot() {
        let area = Rect::new(0, 0, 4, 2);
        let data: Vec<u64> = (0..8).map(|i| i * 3).collect();

        let mut via_style = Buffer::empty(area);
        render_dots(
            &mut via_style,
            area,
            &data,
            21,
            Color::Green,
            GraphOpts::default(),
        );

        let mut direct = Buffer::empty(area);
        area_graph(
            &mut direct,
            area,
            &data,
            21,
            &Ramp::flat(Color::Green),
            false,
        );

        for y in 0..2u16 {
            for x in 0..4u16 {
                assert_eq!(
                    via_style[(x, y)].symbol(),
                    direct[(x, y)].symbol(),
                    "cell ({x},{y}) differs between the style and the primitive"
                );
            }
        }
    }

    /// An unrecognised or empty setting gets the default look, not the
    /// legacy one — `bars` is now the opt-in for terminals without braille.
    #[test]
    fn by_name_falls_back_to_the_default_style() {
        assert_eq!(by_name("nonsense"), GraphStyle::Dots);
        assert_eq!(by_name(""), GraphStyle::Dots);
        assert_eq!(
            by_name(&crate::config::NetwatchConfig::default().graph_style),
            GraphStyle::Dots,
            "the config default and the name lookup must agree"
        );
    }

    #[test]
    fn by_name_recognises_known_styles() {
        assert_eq!(by_name("bars"), GraphStyle::Bars);
        assert_eq!(by_name("DOTS"), GraphStyle::Dots);
    }

    #[test]
    fn name_roundtrips_through_by_name() {
        for name in GRAPH_STYLE_NAMES {
            assert_eq!(by_name(name).name(), *name);
        }
    }

    #[test]
    fn fade_passes_base_through_untouched_for_terminal_theme() {
        // Fade interpolates in RGB. Under the `terminal` theme that would
        // emit 24-bit color for every faded cell and silently undo the one
        // guarantee the theme makes. Measured at 623 escapes per frame in
        // syswatch, which shares this fade design, before it was fixed.
        let base = Color::Cyan;
        for alpha in [0.0, 0.3, 0.55, 1.0] {
            assert_eq!(
                fade_color(base, Color::Reset, alpha, true),
                base,
                "alpha {alpha} must pass through under the terminal theme"
            );
        }
        // Every other theme keeps its gradient.
        assert!(matches!(
            fade_color(Color::Rgb(200, 100, 50), Color::Rgb(0, 0, 0), 0.5, false),
            Color::Rgb(..)
        ));
    }

    #[test]
    fn fade_color_endpoints_match_inputs() {
        let base = Color::Rgb(200, 100, 50);
        let bg = Color::Rgb(0, 0, 0);
        // alpha = 1.0 → fully base
        assert_eq!(fade_color(base, bg, 1.0, false), base);
        // alpha = 0.0 → fully bg
        assert_eq!(fade_color(base, bg, 0.0, false), bg);
    }

    #[test]
    fn fade_color_midpoint_is_halfway() {
        let base = Color::Rgb(200, 100, 50);
        let bg = Color::Rgb(0, 0, 0);
        // alpha = 0.5 → midpoint
        let mid = fade_color(base, bg, 0.5, false);
        assert_eq!(mid, Color::Rgb(100, 50, 25));
    }

    #[test]
    fn fade_color_clamps_out_of_range_alpha() {
        let base = Color::Rgb(200, 100, 50);
        let bg = Color::Rgb(0, 0, 0);
        assert_eq!(fade_color(base, bg, 2.0, false), base);
        assert_eq!(fade_color(base, bg, -1.0, false), bg);
    }

    #[test]
    fn fade_color_with_non_rgb_uses_fallback() {
        let base = Color::Green;
        let bg = Color::Reset;
        // Both unresolvable → result still RGB (fallback white → fallback black)
        let faded = fade_color(base, bg, 0.5, false);
        assert!(matches!(faded, Color::Rgb(_, _, _)));
    }

    #[test]
    fn fade_named_green_against_reset_bg_stays_green() {
        // Regression: the default "dark" theme uses Color::Green and
        // Color::Reset (terminal default). Before the named-color
        // palette mapping was added, fade_color treated both as
        // (255,255,255) → grayscale gradient that looked identical
        // to "fade off" on a green chart. Now Color::Green maps to
        // (0, 170, 0) so dim end retains green hue.
        let base = Color::Green;
        let bg = Color::Reset;
        // Full intensity → standard ANSI green.
        assert_eq!(fade_color(base, bg, 1.0, false), Color::Rgb(0, 170, 0));
        // Dim end → still green, just darker.
        let dim = fade_color(base, bg, 0.3, false);
        match dim {
            Color::Rgb(r, g, b) => {
                assert_eq!(r, 0, "red channel should stay zero");
                assert!(g > 0 && g < 170, "green should be reduced but non-zero");
                assert_eq!(b, 0, "blue channel should stay zero");
            }
            _ => panic!("expected Rgb variant, got {:?}", dim),
        }
    }

    /// btop's fade runs up the plot, not along it. A cell's colour comes from
    /// how high it sits, which is what makes a filled area read as depth
    /// instead of as a block. netwatch used to fade left-to-right by sample
    /// age, which dims the history rather than describing it.
    #[test]
    fn the_fade_runs_vertically_not_by_sample_age() {
        use ratatui::buffer::Buffer;
        let opts = GraphOpts {
            fade: true,
            bg: Color::Rgb(0, 0, 0),
            terminal_palette: false,
            baseline: true,
        };
        let area = Rect::new(0, 0, 4, 4);
        let mut buf = Buffer::empty(area);
        // Four identical full-height samples: nothing varies along x, so any
        // colour difference has to come from the vertical axis.
        render_bars(
            &mut buf,
            area,
            &[10, 10, 10, 10],
            10,
            Color::Rgb(0, 200, 0),
            opts,
        );

        let top = buf[(0, 0)].fg;
        let bottom = buf[(0, 3)].fg;
        assert_ne!(top, bottom, "a column must be brighter at its tip");

        // And every column is coloured identically, because they carry the
        // same value.
        for x in 1..4u16 {
            assert_eq!(buf[(x, 0)].fg, top, "column {x} differs at the top");
            assert_eq!(buf[(x, 3)].fg, bottom, "column {x} differs at the base");
        }
    }

    /// The default theme uses ANSI named colours, and `lighten` cannot
    /// interpolate those — it returns its input. That collapsed the ramp's
    /// top three stops into one token, so half the gradient was missing on
    /// the default install and present only on the RGB themes.
    #[test]
    fn the_ramp_gradates_for_named_colours_too() {
        for base in [Color::Green, Color::Cyan, Color::Red, Color::Blue] {
            let r = magnitude_ramp(base, Color::Rgb(0, 0, 0));
            let stops = [r.at(0.0), r.at(0.25), r.at(0.5), r.at(0.75), r.at(1.0)];
            for (i, c) in stops.iter().enumerate() {
                assert!(
                    matches!(c, Color::Rgb(..)),
                    "{base:?} stop {i} is {c:?}, not an interpolable colour"
                );
            }
            let lum = |c: &Color| match c {
                Color::Rgb(rr, gg, bb) => *rr as u32 + *gg as u32 + *bb as u32,
                _ => unreachable!(),
            };
            for w in stops.windows(2) {
                assert!(
                    lum(&w[1]) > lum(&w[0]),
                    "{base:?} ramp flattens: {:?} then {:?}",
                    w[0],
                    w[1]
                );
            }
        }
    }

    /// A one-row sparkline has no vertical axis to spend, so it takes the
    /// middle of the ramp — the series colour itself. Sampling the ramp's
    /// bottom instead rendered every in-row sparkline in the tool at 30%
    /// brightness, which reads as broken rather than as subtle.
    #[test]
    fn a_single_row_sparkline_lands_mid_ramp() {
        use ratatui::buffer::Buffer;
        let base = Color::Rgb(0, 200, 0);
        let opts = GraphOpts {
            fade: true,
            bg: Color::Rgb(0, 0, 0),
            terminal_palette: false,
            baseline: true,
        };
        for style in [GraphStyle::Bars, GraphStyle::Dots] {
            let area = Rect::new(0, 0, 4, 1);
            let mut buf = Buffer::empty(area);
            match style {
                GraphStyle::Bars => render_bars(&mut buf, area, &[10, 10, 10, 10], 10, base, opts),
                GraphStyle::Dots => render_dots(&mut buf, area, &[10, 10, 10, 10], 10, base, opts),
            }
            assert_eq!(buf[(0, 0)].fg, base, "{style:?} dimmed a one-row sparkline");
        }
    }

    /// A quiet series draws its floor in every style. The braille plot has
    /// always drawn a baseline dot; blocks drew nothing, so a timeline track
    /// with no traffic rendered as an empty row — indistinguishable from a
    /// track that failed to load.
    #[test]
    fn every_style_draws_a_floor_for_a_quiet_series() {
        use ratatui::buffer::Buffer;
        let area = Rect::new(0, 0, 2, 2);
        for style in [GraphStyle::Bars, GraphStyle::Dots] {
            let mut buf = Buffer::empty(area);
            match style {
                GraphStyle::Bars => render_bars(
                    &mut buf,
                    area,
                    &[0, 0],
                    100,
                    Color::Green,
                    GraphOpts::default(),
                ),
                GraphStyle::Dots => render_dots(
                    &mut buf,
                    area,
                    &[0, 0],
                    100,
                    Color::Green,
                    GraphOpts::default(),
                ),
            }
            // The floor sits on the bottom row, and the row above stays clear.
            assert_ne!(buf[(0, 1)].symbol(), " ", "{style:?} drew no baseline");
            assert_eq!(buf[(0, 0)].symbol(), " ", "{style:?} floor is not a fill");
        }
    }

    /// Two feeds at different cadences land on the same grid. This is the
    /// property the Dashboard's timeline rests on: throughput advances once
    /// per refresh tick, latency once per health probe — five times slower —
    /// and before this they were only aligned at their right edge, so reading
    /// down the stack gave a correlation that was not there.
    #[test]
    fn feeds_at_different_cadences_land_on_the_same_grid() {
        // 60s window, 6 slots → each slot is 10s.
        // Fast feed: one sample per second, a spike 25s ago.
        let mut fast = vec![0u64; 60];
        fast[60 - 1 - 25] = 99;
        // Slow feed: one sample per 5s, a spike at the same 25s ago.
        let mut slow = vec![0u64; 12];
        slow[12 - 1 - 5] = 99;

        let a = resample_to_window(&fast, 1, 60, 6);
        let b = resample_to_window(&slow, 5, 60, 6);

        let spike = |v: &[u64]| v.iter().position(|&x| x == 99);
        assert_eq!(
            spike(&a),
            spike(&b),
            "same moment, different slot: {a:?} {b:?}"
        );
        assert!(spike(&a).is_some(), "the spike must survive resampling");
    }

    /// A slot takes the maximum of what falls in it. Averaging is how a
    /// one-second stall disappears into the four quiet seconds around it.
    #[test]
    fn resampling_keeps_spikes_rather_than_averaging_them_away() {
        // 10s window, 2 slots of 5s each; one spike among four zeroes.
        let data = vec![0, 0, 80, 0, 0, 0, 0, 0, 0, 0];
        let out = resample_to_window(&data, 1, 10, 2);
        assert_eq!(out, vec![80, 0], "{out:?}");
    }

    /// Samples older than the window are dropped, and the newest lands in the
    /// last slot — the right edge is "now" in every style.
    #[test]
    fn resampling_windows_and_right_aligns() {
        let data: Vec<u64> = (1..=100).collect();
        let out = resample_to_window(&data, 1, 10, 10);
        assert_eq!(out.len(), 10);
        assert_eq!(
            *out.last().unwrap(),
            100,
            "the newest sample is at the right"
        );
        assert!(
            !out.contains(&50),
            "a sample 50s old is outside a 10s window"
        );

        // Degenerate inputs must not panic.
        assert!(resample_to_window(&[], 1, 60, 8).iter().all(|&v| v == 0));
        assert!(resample_to_window(&data, 1, 60, 0).is_empty());
        assert!(resample_to_window(&data, 0, 0, 4).iter().all(|&v| v == 0));
    }

    /// A feed with less history than the window fills only its recent slots,
    /// leaving the older ones empty rather than stretching to fit.
    #[test]
    fn a_short_history_leaves_the_old_slots_empty() {
        let out = resample_to_window(&[7, 7, 7], 1, 60, 6);
        assert_eq!(out[..5], [0, 0, 0, 0, 0], "{out:?}");
        assert_eq!(out[5], 7, "{out:?}");
    }

    /// The x-axis names the window the plot covers. It assumed braille
    /// packing and a one-second sample, so under `bars` it claimed twice the
    /// history it showed, and at a non-default refresh rate it was wrong for
    /// everyone. It is the plot's capacity, not the data's length: plots
    /// right-align, so labelling by a short history stretches its window
    /// across columns that hold nothing.
    #[test]
    fn the_axis_window_is_capacity_in_the_current_style() {
        // Braille packs two samples per column, blocks one.
        assert_eq!(axis_window_secs(100, GraphStyle::Dots, 1000), 200);
        assert_eq!(axis_window_secs(100, GraphStyle::Bars, 1000), 100);

        // A sample is one refresh interval, not one second.
        assert_eq!(axis_window_secs(100, GraphStyle::Bars, 500), 50);
        assert_eq!(axis_window_secs(100, GraphStyle::Bars, 2000), 200);

        // Degenerate sizes must not panic or divide by zero.
        assert_eq!(axis_window_secs(0, GraphStyle::Dots, 1000), 0);
    }

    /// The axis strip puts the window's start at the left, its midpoint in
    /// the middle, and `now` flush right.
    #[test]
    fn the_time_axis_spreads_its_marks_across_the_width() {
        let axis = time_axis(40, 120);
        assert!(axis.starts_with("-120s"), "{axis:?}");
        assert!(axis.ends_with("now"), "{axis:?}");
        assert!(axis.contains("-60s"), "{axis:?}");
        assert_eq!(axis.chars().count(), 40, "{axis:?}");

        // Too narrow to space them out, but still no panic and no overflow
        // past the width it was given.
        let tight = time_axis(9, 30);
        assert!(tight.ends_with("now"), "{tight:?}");
    }

    /// A renderer takes the newest data it has room for, so a caller must not
    /// pre-trim to the column count. Every chart outside the Dashboard did —
    /// which under the braille packing threw away half the history and left
    /// the left half of the plot blank.
    #[test]
    fn a_full_history_fills_the_plot_in_both_styles() {
        use ratatui::buffer::Buffer;
        let area = Rect::new(0, 0, 8, 2);
        // More history than either style can show.
        let data: Vec<u64> = (1..=64).collect();
        for style in [GraphStyle::Bars, GraphStyle::Dots] {
            let mut buf = Buffer::empty(area);
            match style {
                GraphStyle::Bars => render_bars(
                    &mut buf,
                    area,
                    &data,
                    64,
                    Color::Green,
                    GraphOpts::default(),
                ),
                GraphStyle::Dots => render_dots(
                    &mut buf,
                    area,
                    &data,
                    64,
                    Color::Green,
                    GraphOpts::default(),
                ),
            }
            // The leftmost column carries data, not an empty gap.
            let left: String = (0..2u16).map(|y| buf[(0, y)].symbol()).collect();
            assert_ne!(left.trim(), "", "{style:?} left the first column empty");
        }
    }

    /// A bucketed series is one value per column in both styles — the
    /// Timeline's severity layers are indexed by column and have no more.
    #[test]
    fn bucketed_values_fill_their_own_column() {
        use ratatui::buffer::Buffer;
        let area = Rect::new(0, 0, 4, 2);
        // One value per column, the oldest non-zero.
        let buckets = [40u64, 0, 0, 0];
        let ramp = Ramp::flat(Color::Green);
        let doubled: Vec<u64> = buckets.iter().flat_map(|&v| [v, v]).collect();
        let mut buf = Buffer::empty(area);
        area_graph_with(&mut buf, area, &doubled, 40, &ramp, false, false);

        let col0: String = (0..2u16).map(|y| buf[(0, y)].symbol()).collect();
        assert_ne!(col0.trim(), "", "the first bucket must draw in column 0");
        let col3: String = (0..2u16).map(|y| buf[(3, y)].symbol()).collect();
        assert_eq!(col3.trim(), "", "an empty bucket must stay empty");
    }

    /// An overlay layer paints only its own columns. The Timeline draws
    /// ok / warn / critical event counts over one axis, and a floor under the
    /// zero samples made an empty window show a solid red line the width of
    /// the strip — the loudest possible way to say nothing happened.
    #[test]
    fn an_overlay_layer_leaves_its_zero_columns_alone() {
        use ratatui::buffer::Buffer;
        let area = Rect::new(0, 0, 4, 2);
        let opts = GraphOpts::default().without_baseline();
        for style in [GraphStyle::Bars, GraphStyle::Dots] {
            let mut buf = Buffer::empty(area);
            match style {
                GraphStyle::Bars => render_bars(&mut buf, area, &[0; 8], 10, Color::Red, opts),
                GraphStyle::Dots => render_dots(&mut buf, area, &[0; 8], 10, Color::Red, opts),
            }
            for x in 0..4u16 {
                for y in 0..2u16 {
                    assert_eq!(
                        buf[(x, y)].symbol(),
                        " ",
                        "{style:?} painted an empty layer at ({x},{y})"
                    );
                }
            }
        }

        // The flipped renderer honours it too — the mirrored half of a graph
        // is no more entitled to invent data than the upward half.
        let mut buf = Buffer::empty(area);
        render_bars_flipped(&mut buf, area, &[0; 8], 10, Color::Red, opts);
        assert_eq!(buf[(0, 0)].symbol(), " ");
    }

    /// Fade off means one flat colour, not a subtler gradient.
    #[test]
    fn fade_off_paints_a_single_colour() {
        use ratatui::buffer::Buffer;
        let base = Color::Rgb(0, 200, 0);
        let area = Rect::new(0, 0, 4, 4);
        let mut buf = Buffer::empty(area);
        render_bars(
            &mut buf,
            area,
            &[10, 10, 10, 10],
            10,
            base,
            GraphOpts::default(),
        );
        assert_eq!(buf[(0, 0)].fg, base);
        assert_eq!(buf[(0, 3)].fg, base);
    }

    /// The gradient is dim at the baseline and bright at the peak, and its
    /// midpoint is the series colour itself.
    #[test]
    fn the_magnitude_ramp_climbs_from_dim_to_bright() {
        let base = Color::Rgb(0, 200, 0);
        let r = magnitude_ramp(base, Color::Rgb(0, 0, 0));
        let (lo, hi) = (r.at(0.0), r.at(1.0));
        let lum = |c: Color| match c {
            Color::Rgb(rr, gg, bb) => rr as u32 + gg as u32 + bb as u32,
            _ => panic!("expected rgb, got {c:?}"),
        };
        assert!(
            lum(lo) < lum(base),
            "the baseline must be dimmer than the series"
        );
        assert!(
            lum(hi) > lum(base),
            "the peak must be brighter than the series"
        );
        assert_eq!(
            r.at(0.5),
            base,
            "the middle of the ramp is the series colour"
        );
    }

    /// `dark` resolved its upload series to (0, 0, 170), so the graph's lower half
    /// all but vanished on a dark terminal. Nothing below the series colour may
    /// fall under the floor, and the floor must not flatten the gradient.
    #[test]
    fn every_theme_keeps_a_graph_readable_up_to_its_series_colour() {
        for name in crate::theme::THEME_NAMES {
            let theme = crate::theme::by_name(name);
            if theme.defers_to_terminal() {
                continue;
            }
            let behind = to_rgb_or_default(theme.bg, ASSUMED_DARK_BG);
            for base in [theme.rx_rate, theme.tx_rate] {
                let ramp = magnitude_ramp(base, theme.bg);
                let mut previous = 0.0;
                for step in 0..=10 {
                    let c = contrast(ramp.at(step as f32 / 20.0), behind);
                    assert!(
                        c >= MIN_RAMP_CONTRAST,
                        "{name} {base:?} at {step}: {c:.1}:1"
                    );
                    assert!(c > previous, "{name} {base:?} flattens at {step}");
                    previous = c;
                }
            }
        }
    }

    /// A series that is already readable keeps its own colour.
    #[test]
    fn a_readable_series_colour_is_left_alone() {
        let base = Color::Rgb(0x50, 0xfa, 0x7b);
        assert_eq!(magnitude_ramp(base, Color::Reset).at(0.5), base);
    }
}
