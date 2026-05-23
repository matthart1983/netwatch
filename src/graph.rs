//! Pluggable graph rendering for every chart in the app.
//!
//! Mirrors the theme module: a `GraphStyle` enum with a small `by_name` lookup,
//! plus a `render` entry point (and `render_with_max` for shared-axis overlays)
//! that dispatches to a per-style implementation. Every sparkline in the UI —
//! aggregated RX/TX, in-row top-connection lines, RTT history, timeline
//! severity layers, etc. — routes through here so a single setting toggles
//! them all.
//!
//! `GraphOpts.fade` enables a btop-style right-bright / left-dim gradient on
//! every column plus a faint dot grid behind the data. Call sites build
//! the opts from `App::graph_opts()` so a single config toggle governs the
//! entire UI.

use ratatui::buffer::Buffer;
use ratatui::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphStyle {
    /// Solid-color stacked blocks (ratatui `Sparkline`, the existing look).
    Bars,
    /// btop-style braille area plot: each column is filled with pixels
    /// from the bottom up to the sample's value height, giving 4× vertical
    /// resolution over `Bars` while keeping the filled-area look.
    Dots,
}

pub const GRAPH_STYLE_NAMES: &[&str] = &["bars", "dots"];

pub fn by_name(name: &str) -> GraphStyle {
    match name.to_lowercase().as_str() {
        "dots" => GraphStyle::Dots,
        _ => GraphStyle::Bars,
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
/// Fade + grid travel together because users want btop's whole look or
/// none of it — not partial.
#[derive(Debug, Clone, Copy)]
pub struct GraphOpts {
    /// Apply right-bright / left-dim color gradient per column AND draw
    /// a faint dot grid behind the data. Off → render the original
    /// solid-color look identical to pre-v0.21.
    pub fade: bool,
    /// Theme background color, used as the "fade-to" anchor when
    /// interpolating column colors and as the fallback when no Rgb
    /// information is available.
    pub bg: Color,
}

impl Default for GraphOpts {
    fn default() -> Self {
        Self {
            fade: false,
            bg: Color::Reset,
        }
    }
}

/// Lowest fraction of the base color the leftmost (oldest) column
/// receives when fade is on. 0.30 keeps the data visible without
/// dominating the chart's right side.
const MIN_FADE_ALPHA: f32 = 0.30;

/// Lowest fraction of the row's foreground color the bottommost
/// visible row receives. Higher than the chart fade (0.55 vs 0.30) so
/// table text stays legible at the dim end — fade reads as visual
/// hierarchy, not as illegibility.
const MIN_ROW_FADE_ALPHA: f32 = 0.55;

/// Smallest chart (cells) where the grid overlay renders. In-row
/// sparklines on Connections / Stats rows are too narrow to benefit
/// from the grid — the overlay just becomes visual noise.
const GRID_MIN_W: u16 = 16;
const GRID_MIN_H: u16 = 4;

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
    if opts.fade && area.width >= GRID_MIN_W && area.height >= GRID_MIN_H {
        render_grid(f.buffer_mut(), area, opts.bg);
    }
    match style {
        GraphStyle::Bars => render_bars(f.buffer_mut(), area, data, max, base, opts),
        GraphStyle::Dots => render_dots(f.buffer_mut(), area, data, max, base, opts),
    }
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
    let n_minus_1 = n.saturating_sub(1).max(1) as f32;

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

        let color = if opts.fade {
            let alpha = MIN_FADE_ALPHA + (1.0 - MIN_FADE_ALPHA) * (i as f32 / n_minus_1);
            fade_color(base, opts.bg, alpha)
        } else {
            base
        };

        // Number of one-eighth bar units this sample reaches.
        let v_clamped = v.min(max);
        let total_eighths = (v_clamped as u128 * cell_h as u128 * 8 / max as u128) as usize;
        for cy in 0..cell_h {
            let cell_from_bottom = cell_h - 1 - cy;
            let eighths_in_this_cell = total_eighths.saturating_sub(cell_from_bottom * 8).min(8);
            let glyph = BAR_GLYPHS[eighths_in_this_cell];
            if glyph != ' ' {
                let cell = buf.get_mut(x, area.y + cy as u16);
                cell.set_char(glyph);
                cell.set_style(Style::default().fg(color));
            }
        }
    }
}

// ── braille pixel-dot line plot ─────────────────────────────────────────────

/// Bit position in a braille cell mask for each (sub_col, sub_row).
/// Braille pattern dots numbered 1–8 map to bits 0–7; the 4th row uses dots
/// 7 and 8 (bits 6 and 7) which is why it's not a straight `row + col*4`.
const BRAILLE_BIT: [[u8; 4]; 2] = [
    [0, 1, 2, 6], // sub_col 0: rows 0..=3 → dots 1, 2, 3, 7
    [3, 4, 5, 7], // sub_col 1: rows 0..=3 → dots 4, 5, 6, 8
];

const BRAILLE_BASE: u32 = 0x2800;

fn render_dots(
    buf: &mut Buffer,
    area: Rect,
    data: &[u64],
    max: u64,
    color: Color,
    opts: GraphOpts,
) {
    if max == 0 || data.is_empty() {
        return;
    }

    let cell_w = area.width as usize;
    let cell_h = area.height as usize;
    if cell_w == 0 || cell_h == 0 {
        return;
    }
    let pix_h = cell_h * 4;

    let start = data.len().saturating_sub(cell_w);
    let samples = &data[start..];

    let mut masks = vec![vec![0u8; cell_w]; cell_h];

    for (i, &v) in samples.iter().enumerate() {
        if v == 0 {
            continue;
        }
        let v = v.min(max);
        let top_pixel_from_bottom = ((v as u128 * (pix_h as u128 - 1)) / max as u128) as usize;
        for fill in 0..=top_pixel_from_bottom {
            let pix_y_from_top = (pix_h - 1) - fill;
            let cell_y = pix_y_from_top / 4;
            let row_in_cell = pix_y_from_top % 4;
            masks[cell_y][i] |= 1 << BRAILLE_BIT[0][row_in_cell];
        }
    }

    let n = samples.len();
    let n_minus_1 = n.saturating_sub(1).max(1) as f32;

    for (y, row_masks) in masks.iter().enumerate() {
        for (x, &mask) in row_masks.iter().enumerate() {
            if mask == 0 {
                continue;
            }
            let cell_color = if opts.fade {
                let alpha = MIN_FADE_ALPHA + (1.0 - MIN_FADE_ALPHA) * (x as f32 / n_minus_1);
                fade_color(color, opts.bg, alpha)
            } else {
                color
            };
            let ch = char::from_u32(BRAILLE_BASE | mask as u32).unwrap_or(' ');
            let cell = buf.get_mut(area.x + x as u16, area.y + y as u16);
            cell.set_char(ch);
            cell.set_style(Style::default().fg(cell_color));
        }
    }
}

// ── fade + grid helpers ─────────────────────────────────────────────────────

/// Linear-interpolate from `bg` toward `base` at fraction `alpha`. Only
/// works in RGB; named/indexed colors are returned unchanged so we don't
/// silently lose them. Themes ship with `Color::Rgb` everywhere, so this
/// is the common path.
pub fn fade_color(base: Color, bg: Color, alpha: f32) -> Color {
    let alpha = alpha.clamp(0.0, 1.0);
    let (br, bgc, bb) = match to_rgb_or_default(base, (255, 255, 255)) {
        rgb => rgb,
    };
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
pub fn fade_spans_fg(spans: Vec<Span<'_>>, bg: Color, alpha: f32) -> Vec<Span<'_>> {
    spans
        .into_iter()
        .map(|mut s| {
            if let Some(fg) = s.style.fg {
                s.style = s.style.fg(fade_color(fg, bg, alpha));
            }
            s
        })
        .collect()
}

/// Faint dot grid behind the chart. Renders before the data so any data
/// cell overwrites a grid cell; the empty regions of the chart show the
/// grid through. Only runs on charts at least `GRID_MIN_W` × `GRID_MIN_H`
/// to avoid making narrow sparklines look noisy.
fn render_grid(buf: &mut Buffer, area: Rect, bg: Color) {
    // Grid color: half-way between bg and a neutral gray, so it sits well
    // below the data on every theme.
    let grid_color = fade_color(Color::Rgb(150, 150, 150), bg, 0.20);
    let cell_w = area.width as usize;
    let cell_h = area.height as usize;
    if cell_w < GRID_MIN_W as usize || cell_h < GRID_MIN_H as usize {
        return;
    }
    // 4 verticals + 4 horizontals → quartile guides.
    let v_step = (cell_w / 4).max(2);
    let h_step = (cell_h / 4).max(1);

    for x in (v_step..cell_w).step_by(v_step) {
        for cy in 0..cell_h {
            let cell = buf.get_mut(area.x + x as u16, area.y + cy as u16);
            cell.set_char('·');
            cell.set_style(Style::default().fg(grid_color));
        }
    }
    for y in (h_step..cell_h).step_by(h_step) {
        for cx in 0..cell_w {
            let cell = buf.get_mut(area.x + cx as u16, area.y + y as u16);
            // Don't overwrite an existing vertical grid dot — leave the
            // intersection visually balanced.
            if cell.symbol() != "·" {
                cell.set_char('·');
                cell.set_style(Style::default().fg(grid_color));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn by_name_falls_back_to_bars() {
        assert_eq!(by_name("nonsense"), GraphStyle::Bars);
        assert_eq!(by_name(""), GraphStyle::Bars);
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
    fn fade_color_endpoints_match_inputs() {
        let base = Color::Rgb(200, 100, 50);
        let bg = Color::Rgb(0, 0, 0);
        // alpha = 1.0 → fully base
        assert_eq!(fade_color(base, bg, 1.0), base);
        // alpha = 0.0 → fully bg
        assert_eq!(fade_color(base, bg, 0.0), bg);
    }

    #[test]
    fn fade_color_midpoint_is_halfway() {
        let base = Color::Rgb(200, 100, 50);
        let bg = Color::Rgb(0, 0, 0);
        // alpha = 0.5 → midpoint
        let mid = fade_color(base, bg, 0.5);
        assert_eq!(mid, Color::Rgb(100, 50, 25));
    }

    #[test]
    fn fade_color_clamps_out_of_range_alpha() {
        let base = Color::Rgb(200, 100, 50);
        let bg = Color::Rgb(0, 0, 0);
        assert_eq!(fade_color(base, bg, 2.0), base);
        assert_eq!(fade_color(base, bg, -1.0), bg);
    }

    #[test]
    fn fade_color_with_non_rgb_uses_fallback() {
        let base = Color::Green;
        let bg = Color::Reset;
        // Both unresolvable → result still RGB (fallback white → fallback black)
        let faded = fade_color(base, bg, 0.5);
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
        assert_eq!(fade_color(base, bg, 1.0), Color::Rgb(0, 170, 0));
        // Dim end → still green, just darker.
        let dim = fade_color(base, bg, 0.3);
        match dim {
            Color::Rgb(r, g, b) => {
                assert_eq!(r, 0, "red channel should stay zero");
                assert!(g > 0 && g < 170, "green should be reduced but non-zero");
                assert_eq!(b, 0, "blue channel should stay zero");
            }
            _ => panic!("expected Rgb variant, got {:?}", dim),
        }
    }
}
