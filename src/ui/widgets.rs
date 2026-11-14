use crate::app::{App, Tab};
use crate::collectors::incident::RecorderState;
use ratatui::{
    prelude::*,
    widgets::{Block, BorderType, Borders, Cell, Paragraph, Row},
};

/// The netwatch panel: one definition of the chrome every box in the tool
/// wears.
///
/// Before this existed there were 48 hand-built `Block`s across 15 files, each
/// picking its own title colour, its own corner style, and its own idea of
/// where metadata goes. They agreed by convention, which is another way of
/// saying they drifted — some titles were `text_muted`, some were bare
/// `&str`s inheriting the border colour, one box was `BorderType::Double` and
/// another `Rounded` on the same screen.
///
/// The shape, taken from the design mockups:
///
/// ```text
/// ╭ title ────────────────────────────────── right-aligned meta ╮
/// │ content                                                     │
/// ╰─────────────────────────────────────────────────────────────╯
/// ```
///
/// Rounded corners throughout; the title reads in the brand accent so it wins
/// against the border (the review's "lift dim-grey label contrast"); metadata
/// sits in the same border row, dimmed, because it is context rather than a
/// heading. A focused panel takes the accent on its border, so the box holding
/// the cursor is identifiable without a second colour vocabulary.
pub struct Panel {
    badge: Option<String>,
    title: Vec<Span<'static>>,
    meta: Vec<Span<'static>>,
    border: Option<Color>,
    focused: bool,
}

impl Panel {
    /// A panel titled with plain text.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            badge: None,
            title: vec![Span::raw(title.into())],
            meta: Vec::new(),
            border: None,
            focused: false,
        }
    }

    /// A panel whose title carries its own styling — a status dot, a severity
    /// colour, a count in a different weight.
    pub fn styled(title: Vec<Span<'static>>) -> Self {
        Self {
            badge: None,
            title,
            meta: Vec::new(),
            border: None,
            focused: false,
        }
    }

    /// An untitled box. Still gets the shared corners and border colour.
    pub fn plain() -> Self {
        Self {
            badge: None,
            title: Vec::new(),
            meta: Vec::new(),
            border: None,
            focused: false,
        }
    }

    /// The digit that opens the tab this panel summarises, drawn as an
    /// inverse chip before the title.
    ///
    /// A badge is a promise that pressing that key does something. It used to
    /// be a per-screen ordinal — `1`, `2`, `3` in reading order — which read
    /// as a shortcut and was not one: pressing `3` on a panel labelled `3`
    /// jumped to Topology. Now the number *is* the tab key, so the dashboard's
    /// `2 connections` box is telling the truth about what `2` does.
    ///
    /// Panels with nowhere to go carry no badge. See [`Panel::tab_badge`],
    /// which takes the tab rather than a loose integer so the two cannot
    /// drift.
    pub fn badge(mut self, n: u8) -> Self {
        self.badge = Some(n.to_string());
        self
    }

    /// Badge this panel with the key that opens `tab`.
    ///
    /// Derived from the tab bar's own labels, so a renumbered tab renumbers
    /// every badge that points at it.
    pub fn tab_badge(mut self, tab: Tab) -> Self {
        self.badge = Some(tab_label(tab).0.to_string());
        self
    }

    /// Right-aligned text in the top border: counts, windows, units, state.
    pub fn meta(mut self, meta: impl Into<String>) -> Self {
        self.meta = vec![Span::raw(meta.into())];
        self
    }

    pub fn meta_styled(mut self, meta: Vec<Span<'static>>) -> Self {
        self.meta = meta;
        self
    }

    /// Override the border colour — severity on the Diagnose detail pane, a
    /// status tint on a panel that is itself the subject of an alert.
    pub fn border(mut self, color: Color) -> Self {
        self.border = Some(color);
        self
    }

    /// Mark the panel that currently has the cursor.
    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }

    /// Columns the title occupies, badge and padding included.
    fn title_width(&self) -> usize {
        let text: usize = self
            .title
            .iter()
            .map(|s| crate::ui::text::width(&s.content))
            .sum::<usize>();
        let badge = self
            .badge
            .as_ref()
            .map(|n| crate::ui::text::width(n) + 3)
            .unwrap_or(0);
        // A leading space, the badge chip, then the title, then a space.
        if text == 0 && badge == 0 {
            0
        } else {
            1 + badge + text + 1
        }
    }

    /// Columns the metadata occupies, padding included.
    fn meta_width(&self) -> usize {
        let text: usize = self
            .meta
            .iter()
            .map(|s| crate::ui::text::width(&s.content))
            .sum::<usize>();
        if text == 0 {
            0
        } else {
            text + 2
        }
    }

    /// Drop the metadata when the panel is too narrow to hold both it and the
    /// title.
    ///
    /// ratatui draws left- and right-aligned titles independently, so a box
    /// that cannot fit both renders them *over each other* — the catalogue
    /// panel came out as `watching for les · 21 active`, which reads as a
    /// corrupted title rather than a dropped label. The title is the heading
    /// and wins; metadata is context and can go.
    pub fn fit(mut self, width: u16) -> Self {
        // Two corners, plus a column of border between the two titles.
        let budget = (width as usize).saturating_sub(3);
        if self.title_width() + self.meta_width() > budget {
            self.meta.clear();
        }
        self
    }

    pub fn block(self, t: &Theme) -> Block<'static> {
        let border = self
            .border
            .unwrap_or(if self.focused { t.brand } else { t.border });

        let mut block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(border));

        if !self.title.is_empty() || self.badge.is_some() {
            // Padded so the text never abuts the corner glyph.
            let mut spans = vec![Span::raw(" ")];
            if let Some(n) = &self.badge {
                spans.push(Span::styled(
                    format!(" {n} "),
                    Style::default().fg(t.text_inverse).bg(t.brand).bold(),
                ));
                spans.push(Span::raw(" "));
            }
            let default = Style::default().fg(t.brand).bold();
            for span in self.title {
                let style = if span.style == Style::default() {
                    default
                } else {
                    span.style
                };
                spans.push(Span::styled(span.content.into_owned(), style));
            }
            spans.push(Span::raw(" "));
            block = block
                .title(Line::from(spans))
                .title_alignment(Alignment::Left);
        }

        if !self.meta.is_empty() {
            let mut spans = vec![Span::raw(" ")];
            let default = Style::default().fg(t.text_muted);
            for span in self.meta {
                let style = if span.style == Style::default() {
                    default
                } else {
                    span.style
                };
                spans.push(Span::styled(span.content.into_owned(), style));
            }
            spans.push(Span::raw(" "));
            block = block.title(Line::from(spans).alignment(Alignment::Right));
        }

        block
    }

    /// Draw the panel and return the area inside it.
    pub fn render(self, f: &mut Frame, t: &Theme, area: Rect) -> Rect {
        let block = self.fit(area.width).block(t);
        let inner = block.inner(area);
        f.render_widget(block, area);
        inner
    }
}

use crate::theme::Theme;

/// The bare netwatch box, for call sites that build their own title spans.
///
/// Same corners and border colour as [`Panel`] — this exists so a panel with
/// an unusual title (a live status dot, a per-row severity tint) still gets
/// the shared chrome instead of hand-rolling `Block::default()` and drifting.
pub fn panel_block(t: &Theme) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(t.border))
}

/// Standard 3-chunk vertical layout used by most tabs: header / content / footer.
/// Each panel is 3 rows tall; content takes whatever remains.
pub struct FrameChunks {
    pub header: Rect,
    pub content: Rect,
    pub footer: Rect,
}

pub fn frame_layout(area: Rect) -> FrameChunks {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(area);
    FrameChunks {
        header: chunks[0],
        content: chunks[1],
        footer: chunks[2],
    }
}

/// Fixed column width for rate strings (e.g. "999 MB/s"). Right-aligned.
pub const RATE_WIDTH: usize = 8;

/// Fixed column width for total byte strings (e.g. "999 MB"). Right-aligned.
pub const TOTAL_WIDTH: usize = 6;

/// Re-paint the theme's panel background over `area` after a popup
/// uses the `Clear` widget. `Clear` resets each cell to terminal
/// default — which bypasses the root-level theme background fill in
/// `app.rs`, so popups on themes that paint a bg (`sky`, `paper`)
/// would otherwise show the *terminal* background, looking
/// transparent against the rest of the UI. Themes that leave bg
/// as `Color::Reset` skip this entirely (no-op).
///
/// Takes `&Theme` rather than `&App` so the sort-picker overlay
/// (which carries `&Theme` for layering reasons) can share the helper.
pub fn paint_overlay_bg(f: &mut Frame, theme: &crate::theme::Theme, area: Rect) {
    if theme.bg == ratatui::style::Color::Reset {
        return;
    }
    // Set both bg AND fg so unstyled spans inside the popup inherit
    // theme.text_primary — otherwise they fall back to the terminal's
    // own default fg, which washes out on a painted bg.
    f.render_widget(
        Block::default().style(Style::default().bg(theme.bg).fg(theme.text_primary)),
        area,
    );
}

/// Returns true if the interface saw any traffic in the last few history
/// samples (~5s at 1 Hz). Renderers use this instead of `rx_rate > 0.0`
/// for "is this interface active" decisions so badges and counts don't
/// flicker on/off between traffic bursts — the instantaneous rate is
/// genuinely 0 most ticks even on a heavily-used interface, which made
/// the "N live N idle" badge in the dashboard flap every refresh.
pub fn interface_recently_active(iface: &crate::collectors::traffic::InterfaceTraffic) -> bool {
    const RECENT_SAMPLES: usize = 5;
    let rx = iface.rx_history.iter().rev().take(RECENT_SAMPLES);
    let tx = iface.tx_history.iter().rev().take(RECENT_SAMPLES);
    rx.chain(tx).any(|&r| r > 0)
}

/// A count with thousands separators: `1,280`.
pub fn format_count(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, d) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(d);
    }
    out
}

/// Unpadded rate for inline use. Zero → "0", integers only.
///
/// Zero used to be `-`, beside `—` for "not measured" and `0` in the
/// Connections table: three marks for nothing, and no way to tell an idle flow
/// from an unmeasured one. A caller with no measurement draws [`NO_VALUE`].
pub fn format_bytes_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec < 1.0 {
        return "0".to_string();
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
    let rounded = val.round().max(1.0) as u64;
    format!("{} {}", rounded, unit)
}

/// Right-aligned rate for table cells. Fixed width [`RATE_WIDTH`].
pub fn format_bytes_rate_padded(bytes_per_sec: f64) -> String {
    format!(
        "{:>width$}",
        format_bytes_rate(bytes_per_sec),
        width = RATE_WIDTH
    )
}

/// Unpadded byte total for inline use. Zero → "0", integers only.
pub fn format_bytes_total(bytes: u64) -> String {
    if bytes == 0 {
        return "0".to_string();
    }
    let (val, unit) = if bytes >= 1_000_000_000 {
        (bytes as f64 / 1_000_000_000.0, "GB")
    } else if bytes >= 1_000_000 {
        (bytes as f64 / 1_000_000.0, "MB")
    } else if bytes >= 1_000 {
        (bytes as f64 / 1_000.0, "KB")
    } else {
        (bytes as f64, "B")
    };
    let rounded = val.round().max(1.0) as u64;
    format!("{} {}", rounded, unit)
}

/// Right-aligned byte total for table cells. Fixed width [`TOTAL_WIDTH`].
pub fn format_bytes_total_padded(bytes: u64) -> String {
    format!("{:>width$}", format_bytes_total(bytes), width = TOTAL_WIDTH)
}

/// What a cell shows when a value was not measured.
///
/// One glyph for it, everywhere. Dense wrote `--`, the dashboard `–` and the
/// tabs `—`, which reads as three kinds of nothing. A measured zero is a
/// different fact and keeps its own mark: [`format_bytes_rate`] writes `-`
/// for a rate under one byte a second.
pub const NO_VALUE: &str = "—";

/// The tab-range the footer advertises. A constant so the hint and the tab
/// bar can be asserted against each other rather than drifting apart.
pub const FOOTER_TAB_HINT: &str = "1-9,0";

const BASE_TABS: &[Tab] = &[
    Tab::Dashboard,
    Tab::Connections,
    Tab::Interfaces,
    Tab::Packets,
    Tab::Stats,
    Tab::Topology,
    Tab::Timeline,
    Tab::Processes,
];

/// The tab bar. Ten tabs, always — `1`–`9` then `0`.
///
/// Diagnose is unconditional where the old Insights tab was config-gated.
/// A conditional tab meant `9` did nothing on most installs while the help
/// screen listed it anyway, and it meant the number a user learned for a tab
/// changed depending on a setting. Diagnose needs no configuration: it runs
/// the deterministic engine, and the optional AI narrative appears inside it
/// when enabled.
fn visible_tabs() -> Vec<Tab> {
    let mut tabs = BASE_TABS.to_vec();
    tabs.push(Tab::Diagnose);
    tabs.push(Tab::Egress);
    tabs
}

fn tab_label(tab: Tab) -> (&'static str, &'static str) {
    match tab {
        Tab::Dashboard => ("1", "Dashboard"),
        Tab::Connections => ("2", "Connections"),
        Tab::Interfaces => ("3", "Interfaces"),
        Tab::Packets => ("4", "Packets"),
        Tab::Stats => ("5", "Stats"),
        Tab::Topology => ("6", "Topology"),
        Tab::Timeline => ("7", "Timeline"),
        Tab::Processes => ("8", "Processes"),
        Tab::Diagnose => ("9", "Diagnose"),
        Tab::Egress => ("0", "Egress"),
    }
}

/// Columns before the first tab: the width of the `◉ NetWatch ` brand.
const TAB_BAR_ORIGIN: u16 = 11;
/// Spacing between tabs.
const TAB_GAP: &str = " ";

/// How much of each tab's name the bar can afford at this terminal width.
///
/// The full bar is 141 columns. Drawn into anything narrower it used to run
/// off the right edge, so at 120 columns `9` had no name and `0 egress` was
/// not there at all, and at 80 the last four tabs did not exist. A tab that
/// is not drawn cannot be clicked and is not advertised, so the bar shortens
/// instead: every digit stays, names give way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TabDensity {
    /// `1 dashboard  2 connections …`
    Full,
    /// `1 dash  2 conns …`
    Short,
    /// `1  2  3 interfaces  4 …` — only the current tab keeps its name.
    Digits,
}

const TAB_DENSITIES: [TabDensity; 3] = [TabDensity::Full, TabDensity::Short, TabDensity::Digits];

fn tab_short_name(tab: Tab) -> &'static str {
    match tab {
        Tab::Dashboard => "dash",
        Tab::Connections => "conns",
        Tab::Interfaces => "ifaces",
        Tab::Packets => "pkts",
        Tab::Stats => "stats",
        Tab::Topology => "topo",
        Tab::Timeline => "time",
        Tab::Processes => "procs",
        Tab::Diagnose => "diag",
        Tab::Egress => "egress",
    }
}

/// Exactly what one tab occupies in the bar at a density.
///
/// Selected and unselected render the same width at `Full` and `Short` — the
/// selected one as a single inverted span, the unselected as a coloured digit
/// plus a name. At `Digits` the current tab alone carries its name, so the
/// geometry depends on which tab is current. Either way this is the single
/// source of truth: the renderer and [`tab_at_column`] both walk it, which is
/// what stopped the click hit-test from silently addressing the previous
/// layout when the bar was restyled.
fn tab_segment(tab: Tab, density: TabDensity, current: Tab) -> String {
    let (num, name) = tab_label(tab);
    match density {
        TabDensity::Full => format!(" {num} {} ", name.to_lowercase()),
        TabDensity::Short => format!(" {num} {} ", tab_short_name(tab)),
        TabDensity::Digits if tab == current => format!(" {num} {} ", name.to_lowercase()),
        TabDensity::Digits => format!(" {num} "),
    }
}

/// Columns the brand and the tabs occupy at a density.
fn tab_bar_width(density: TabDensity, current: Tab) -> u16 {
    let tabs = visible_tabs();
    let segments: usize = tabs
        .iter()
        .map(|&tab| tab_segment(tab, density, current).chars().count())
        .sum();
    let gaps = TAB_GAP.chars().count() * tabs.len().saturating_sub(1);
    TAB_BAR_ORIGIN + (segments + gaps) as u16
}

/// The roomiest density whose bar fits in `width` columns.
///
/// The last segment ends in a blank, which may hang off the edge. `Digits` is
/// the floor: below its ~60 columns nothing shorter is still a tab bar.
pub fn tab_density(width: u16, current: Tab) -> TabDensity {
    TAB_DENSITIES
        .into_iter()
        .find(|&d| tab_bar_width(d, current) <= width.saturating_add(1))
        .unwrap_or(TabDensity::Digits)
}

/// The tab bar itself: `1 dashboard  2 connections …`.
///
/// The number takes the key-hint colour so the bar doubles as its own keymap,
/// and the current tab is inverted rather than merely recoloured. Brackets are
/// gone — they cost twenty columns across ten tabs, which was most of what
/// pushed the status chips off the right edge at 150 columns.
///
/// Pure so it can be tested against [`tab_at_column`] without standing up an
/// `App` and its collectors.
pub fn tab_bar_spans(current: Tab, density: TabDensity, t: &Theme) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    for (i, &tab) in visible_tabs().iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(TAB_GAP));
        }
        let segment = tab_segment(tab, density, current);
        if tab == current {
            spans.push(Span::styled(
                segment,
                Style::default().fg(t.text_inverse).bg(t.active_tab).bold(),
            ));
        } else {
            // Split so the digit reads as the key it is. The two spans still
            // occupy exactly `tab_segment`'s width, which is what keeps the
            // click hit-test honest.
            let (num, _) = tab_label(tab);
            let digit = format!(" {num}");
            let rest = segment[digit.len()..].to_string();
            spans.push(Span::styled(digit, Style::default().fg(t.key_hint)));
            spans.push(Span::styled(rest, Style::default().fg(t.inactive_tab)));
        }
    }
    spans
}

/// The header row for a terminal `width` columns wide.
///
/// The tabs come first and are never clipped: they pick the roomiest
/// [`TabDensity`] that fits. Chips follow in priority order — paused, alerts,
/// recorder, the tab's own extras, then the clock — and one that does not fit
/// whole is left out rather than cut mid-word. `attribution: lsof — ebp` at
/// the right edge told nobody anything.
pub fn build_header_line(
    app: &App,
    extra: Option<Vec<Span<'static>>>,
    width: u16,
) -> Line<'static> {
    let t = &app.theme;
    let now = chrono::Local::now().format("%H:%M:%S").to_string();
    let current = app.ui.current_tab;
    let density = tab_density(width, current);

    // Lowercase, and exactly `TAB_BAR_ORIGIN` columns wide — the hit-test
    // measures the bar from the end of this span.
    let mut spans: Vec<Span<'static>> = vec![Span::styled(
        "◉ netwatch ",
        Style::default().fg(t.brand).bold(),
    )];

    spans.extend(tab_bar_spans(current, density, t));

    let mut chips: Vec<Vec<Span<'static>>> = Vec::new();

    if app.ui.paused {
        chips.push(vec![Span::styled(
            " ⏸ paused ",
            Style::default().fg(t.text_inverse).bg(t.status_warn),
        )]);
    }

    let alert_count = app.network_intel.active_alert_count();
    if alert_count > 0 {
        chips.push(vec![Span::styled(
            format!(" ⚠ {} ", alert_count),
            Style::default().fg(t.text_inverse).bg(t.status_error),
        )]);
    }

    match app.incident_recorder.state() {
        RecorderState::Armed => {
            chips.push(vec![Span::styled(
                format!(" ● rec {} ", app.incident_recorder.window_label()),
                Style::default().fg(t.text_inverse).bg(t.status_error),
            )]);
        }
        RecorderState::Frozen => {
            chips.push(vec![Span::styled(
                " frozen ",
                Style::default().fg(t.text_inverse).bg(t.status_warn),
            )]);
        }
        RecorderState::Off => {}
    }

    if let Some(extra_spans) = extra {
        // A tab's extras are independent facts separated by blank spans, and
        // the first should survive when the second does not fit. A label and
        // its value (`bpf ` `port 53`) stay together.
        let mut group: Vec<Span<'static>> = Vec::new();
        for s in extra_spans {
            if s.content.trim().is_empty() {
                if !group.is_empty() {
                    let mut chip = vec![Span::raw("  ")];
                    chip.append(&mut group);
                    chips.push(chip);
                }
            } else {
                group.push(s);
            }
        }
        if !group.is_empty() {
            let mut chip = vec![Span::raw("  ")];
            chip.append(&mut group);
            chips.push(chip);
        }
    }

    chips.push(vec![
        Span::raw("  "),
        Span::styled(now, Style::default().fg(t.text_muted)),
    ]);

    let mut used: usize = spans
        .iter()
        .map(|s| crate::ui::text::width(&s.content))
        .sum();
    for chip in chips {
        let w: usize = chip
            .iter()
            .map(|s| crate::ui::text::width(&s.content))
            .sum();
        if used + w <= usize::from(width) {
            used += w;
            spans.extend(chip);
        }
    }

    Line::from(spans)
}

/// Truncate to `max_cols` columns, marking the cut with `…`.
///
/// Shared so a label that does not fit shortens the same way everywhere
/// instead of each call site inventing its own cut.
pub fn ellipsise(text: &str, max_cols: usize) -> String {
    crate::ui::text::truncate_end(text, max_cols)
}

/// The verdict line that sits under the tab bar on every tab.
///
/// One line, read from the same `Vec<Issue>` the Diagnose tab renders: what is
/// wrong, since when, and what to press. When nothing is open it collapses to
/// a single dim sentence — and when netwatch hasn't learned enough to judge,
/// it says that instead of claiming health. "All nominal" from a tool that has
/// been running for ninety seconds is not a diagnosis.
pub fn build_verdict_line(app: &App) -> Line<'static> {
    let t = &app.theme;
    let verdict = app.diagnose.engine.verdict(&app.diagnose.baselines);

    // `--demo` replays a recorded incident through the engine while every
    // other collector stays live. That mix is useful for a walkthrough and
    // dishonest if unlabelled — the verdict line is the one piece of chrome
    // on every tab, so the marker goes here rather than only on Diagnose.
    let demo: Vec<Span<'static>> = if app.diagnose.is_demo() {
        vec![
            Span::styled(
                " DEMO ",
                Style::default().fg(t.text_inverse).bg(t.status_warn).bold(),
            ),
            Span::styled(
                " replayed incident · other tabs are live ",
                Style::default().fg(t.text_muted),
            ),
        ]
    } else {
        Vec::new()
    };
    let with_demo = |mut spans: Vec<Span<'static>>| -> Line<'static> {
        if demo.is_empty() {
            return Line::from(spans);
        }
        let mut out = demo.clone();
        out.push(Span::raw(" "));
        out.append(&mut spans);
        Line::from(out)
    };

    // Nothing open: a status, not a coverage breakdown. The counts live on
    // the Diagnose tab, one keypress away, and are noise on every other tab.
    match &verdict {
        crate::diagnose::Verdict::Clear { .. } => with_demo(vec![
            Span::styled(" ● ", Style::default().fg(t.status_good)),
            Span::styled("no issues", Style::default().fg(t.text_muted)),
        ]),
        // What the engine returns with ready baselines and nothing open while
        // a core rule still lacks its input. Not green, on every tab.
        crate::diagnose::Verdict::Incomplete { .. } => with_demo(vec![Span::styled(
            " ◌ no issues",
            Style::default().fg(t.text_muted),
        )]),
        // Not green: still learning is an absence of information, not health.
        crate::diagnose::Verdict::Learning { .. } => with_demo(vec![Span::styled(
            " ◌ no issues · learning",
            Style::default().fg(t.text_muted),
        )]),
        crate::diagnose::Verdict::Issues {
            severity,
            count,
            headline,
            ..
        } => {
            let color = match severity {
                crate::diagnose::Severity::Critical | crate::diagnose::Severity::High => {
                    t.status_error
                }
                crate::diagnose::Severity::Medium => t.status_warn,
                crate::diagnose::Severity::Info => t.status_info,
            };
            with_demo(vec![
                Span::styled(" ▌", Style::default().fg(color).bold()),
                Span::raw(" "),
                Span::styled(
                    if *count == 1 {
                        "1 issue".to_string()
                    } else {
                        format!("{count} issues")
                    },
                    Style::default().fg(color).bold(),
                ),
                Span::styled(" · ", Style::default().fg(t.separator)),
                Span::styled(headline.clone(), Style::default().fg(t.text_secondary)),
                Span::raw("   "),
                Span::styled("9", Style::default().fg(t.key_hint).bold()),
                Span::styled(" diagnose", Style::default().fg(t.text_muted)),
            ])
        }
    }
}

/// Why capture is not running, when opening it failed. `--demo` seeds
/// packets instead of capturing, so a failure there reports on something the
/// user did not ask for.
pub fn capture_failure(app: &App) -> Option<String> {
    app.packet_collector
        .get_error()
        .filter(|_| !app.diagnose.is_demo())
}

/// `rows` off the top of `area`, and what is left. Taken before a [`Layout`]
/// runs, so that rows the content depends on are rows the solver cannot shrink.
pub fn take_top(area: Rect, rows: u16) -> (Rect, Rect) {
    let rows = rows.min(area.height);
    (
        Rect {
            height: rows,
            ..area
        },
        Rect {
            y: area.y + rows,
            height: area.height - rows,
            ..area
        },
    )
}

/// Where the exact fix is, when the header cannot draw it whole.
pub const CAPTURE_FIX_POINTER: &str =
    "fix: netwatch doctor --check-capture --json, or REFERENCE.md";

const FAILURE_LEAD: &str = " ⚠ capture off: ";
const FAILURE_INDENT: &str = " ";

/// `text` broken between words, for a message that is not a command.
fn failure_word_rows(text: &str, width: usize) -> Vec<(&'static str, String)> {
    use crate::ui::text::width as cells;
    let mut rows = vec![(FAILURE_LEAD, String::new())];
    for word in text.split_inclusive(' ') {
        let (lead, row) = &rows[rows.len() - 1];
        if !row.is_empty() && cells(lead) + cells(row) + cells(word.trim_end()) > width {
            rows.push((FAILURE_INDENT, String::new()));
        }
        let last = rows.len() - 1;
        rows[last].1.push_str(word);
    }
    rows
}

/// The fix's commands as rows of whole commands under a row of their own for
/// the sentence, or `None` when a command is wider than a row.
fn failure_command_rows(
    sentence: &str,
    commands: &[&str],
    width: usize,
) -> Option<Vec<(&'static str, String)>> {
    use crate::ui::text::width as cells;
    let room = width.checked_sub(cells(FAILURE_INDENT))?;
    let mut chain: Vec<String> = Vec::new();
    for command in commands {
        if cells(command) > room {
            return None;
        }
        match chain.last_mut() {
            Some(row) if cells(row) + 1 + cells(command) <= room => {
                row.push(' ');
                row.push_str(command);
            }
            _ => chain.push((*command).to_string()),
        }
    }
    let mut rows = vec![(FAILURE_LEAD, format!("{sentence}. Run:"))];
    rows.extend(chain.into_iter().map(|row| (FAILURE_INDENT, row)));
    Some(rows)
}

/// The header's capture-failure rows at `width`: what failed and, for a
/// refused open, the fix (see [`crate::platform::capture_fix`]).
///
/// The Linux fix is a chain of commands longer than most terminals are wide,
/// and it is drawn whole or not at all. A chain cut off before its `setcap`
/// fixes nothing, and one broken inside a command pastes as something else:
/// 50-column rows ran `netwatch` inside `$(...)` and pointed `chown` at a file
/// named after what it printed. Rows break between commands, so they still
/// paste as one. If the chain does not fit `width`, or needs more than `spare`
/// rows, the rows name where the exact line is instead. Prose breaks between
/// words, whatever the rows.
pub fn capture_failure_lines(
    theme: &Theme,
    error: &str,
    width: u16,
    spare: u16,
) -> Vec<Line<'static>> {
    let width = usize::from(width);
    let rows = match crate::platform::fix_commands(error) {
        Some((sentence, commands)) => failure_command_rows(sentence, &commands, width)
            .filter(|rows| rows.len() <= usize::from(spare))
            .unwrap_or_else(|| failure_word_rows(CAPTURE_FIX_POINTER, width)),
        None => failure_word_rows(error, width),
    };
    let style = Style::default().fg(theme.status_error).bold();
    rows.into_iter()
        .map(|(lead, row)| {
            Line::from(vec![
                Span::raw(lead),
                Span::styled(row.trim_end().to_string(), style),
            ])
        })
        .collect()
}

/// The bottom row, for the first moments of a session whose config has keys it
/// ignored: `sandbox_mode = "strict"` is a sandbox that is not strict, and stderr
/// is behind the TUI until it quits. Over the view rather than in its layout, so
/// that it reaches Lite and Dense too and moves nothing when it goes.
pub fn render_config_notice(f: &mut Frame, app: &App, area: Rect) {
    let showing = app
        .ui
        .config_notice_until
        .is_some_and(|until| std::time::Instant::now() < until);
    if !showing || area.height == 0 {
        return;
    }
    let mut warnings = app.config_warnings().filter(|warning| !warning.is_quiet());
    let Some(first) = warnings.next() else {
        return;
    };
    let more = match warnings.count() {
        0 => String::new(),
        n => format!(" (+{n} more)"),
    };
    let row = Rect {
        y: area.y + area.height - 1,
        height: 1,
        ..area
    };
    // Lite has no Settings of its own: `,` does nothing there, and `L` leaves it.
    let way = if app.ui.view_mode == crate::app::ViewMode::Lite {
        "L then , settings"
    } else {
        ", settings"
    };
    let tail = format!("{more}  {way}");
    let room = usize::from(row.width).saturating_sub(3 + crate::ui::text::width(&tail));
    let text = format!(" ⚠ {}{tail}", ellipsise(&first.short(), room));
    let style = Style::default()
        .fg(app.theme.text_inverse)
        .bg(app.theme.status_warn);
    f.render_widget(ratatui::widgets::Clear, row);
    f.render_widget(Paragraph::new(text).style(style), row);
}

/// The footer while a filter is being typed: the text, a cursor, and the two
/// keys that end it.
///
/// Three tabs drew this themselves. Two showed `/ text█` and nothing else, so
/// the footer's keys vanished and nothing said how to get them back; the
/// third wrote `Enter apply   Esc cancel` in a style of its own.
pub fn render_filter_bar(f: &mut Frame, t: &Theme, area: Rect, text: &str) {
    let mut spans = vec![
        Span::styled(" / ", Style::default().fg(t.brand).bold()),
        Span::styled(text.to_string(), Style::default().fg(t.text_primary)),
        Span::styled("▏", Style::default().fg(t.brand).bold()),
    ];
    let hints = hint_spans(t, &[hint("↵", "apply"), hint("esc", "cancel")]);
    let used: usize = spans
        .iter()
        .map(|s| crate::ui::text::width(&s.content))
        .sum();
    let hints_w: usize = hints
        .iter()
        .map(|s| crate::ui::text::width(&s.content))
        .sum();
    let avail = usize::from(area.width);
    if avail > used + hints_w + 3 {
        spans.push(Span::raw(" ".repeat(avail - used - hints_w - 1)));
        spans.extend(hints);
    }
    f.render_widget(
        Paragraph::new(Line::from(spans)).block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(t.border)),
        ),
        area,
    );
}

/// `1 connection`, `2 connections`.
pub fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// Make text on a selected row readable when its colour is the selection's.
///
/// The `terminal` theme's selection ground is ANSI 8, on purpose: it is the
/// one slot that is a neutral mid-grey in light and dark palettes alike. Its
/// muted text is ANSI 8 too. So every muted cell on the selected row — an idle
/// process, a dim count, an age — was drawn grey on the same grey, and the
/// cursor on an idle row was a blank band. Each table would have to remember
/// not to dim its selected row; this runs once per frame, after all of them,
/// and lifts any such cell to the secondary text colour.
pub fn lift_text_on_selection(buf: &mut ratatui::buffer::Buffer, theme: &Theme) {
    // `DarkGray` and `Indexed(8)` are the same slot under two names.
    fn slot(c: Color) -> Color {
        match c {
            Color::DarkGray => Color::Indexed(8),
            c => c,
        }
    }
    let grounds = [slot(theme.selection_bg), slot(theme.highlight_bg)];
    for cell in buf.content.iter_mut() {
        let bg = slot(cell.bg);
        if bg != Color::Reset && grounds.contains(&bg) && slot(cell.fg) == bg {
            cell.fg = theme.text_secondary;
        }
    }
}

/// The drill path, right-aligned on the verdict row: where `↵` came from,
/// where it is now, and the key that goes back.
///
/// `processes › connections › packets   esc back`. Drawn only while there is
/// a path, and only if it fits beside what the row already says.
pub fn render_breadcrumb(f: &mut Frame, app: &App, header: Rect) {
    if app.ui.drill_path.is_empty() || header.height < 2 {
        return;
    }
    let t = &app.theme;
    let mut spans = Vec::new();
    for tab in &app.ui.drill_path {
        spans.push(Span::styled(
            tab_label(*tab).1.to_lowercase(),
            Style::default().fg(t.text_muted),
        ));
        spans.push(Span::styled(" › ", Style::default().fg(t.separator)));
    }
    spans.push(Span::styled(
        tab_label(app.ui.current_tab).1.to_lowercase(),
        Style::default().fg(t.text_primary).bold(),
    ));
    spans.push(Span::raw("   "));
    spans.extend(hint_spans(t, &[hint("esc", "back")]));
    spans.push(Span::raw(" "));
    let w: usize = spans
        .iter()
        .map(|s| crate::ui::text::width(&s.content))
        .sum();
    // Leave the verdict its half of the row.
    if w + 2 > usize::from(header.width) / 2 {
        return;
    }
    let row = Rect {
        x: header.x + header.width - w as u16,
        y: header.y + 1,
        width: w as u16,
        height: 1,
    };
    f.render_widget(ratatui::widgets::Clear, row);
    f.render_widget(Paragraph::new(Line::from(spans)), row);
}

pub fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let mut lines = vec![
        build_header_line(app, None, area.width),
        build_verdict_line(app),
    ];
    if let Some(error) = capture_failure(app).filter(|_| area.height > 3) {
        // Two rows above and the border below.
        let spare = area.height.saturating_sub(3);
        lines.extend(capture_failure_lines(&app.theme, &error, area.width, spare));
    }
    let header = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(app.theme.border)),
    );
    f.render_widget(header, area);
    render_breadcrumb(f, app, area);
}

/// Header without the verdict row, for the Diagnose tab — which renders the
/// verdict itself, in full, immediately below.
pub fn render_header_without_verdict(f: &mut Frame, app: &App, area: Rect) {
    let header = Paragraph::new(build_header_line(app, None, area.width)).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(app.theme.border)),
    );
    f.render_widget(header, area);
}

pub fn render_header_with_extra(f: &mut Frame, app: &App, area: Rect, extra: Vec<Span<'static>>) {
    let lines = vec![
        build_header_line(app, Some(extra), area.width),
        build_verdict_line(app),
    ];
    let header = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(app.theme.border)),
    );
    f.render_widget(header, area);
    render_breadcrumb(f, app, area);
}

/// Rows [`render_attribution_header`] needs: tabs, verdict, rule, coverage.
pub const ATTRIBUTION_HEADER_ROWS: u16 = 4;

/// Keep coverage on a row of its own so narrow terminals do not lose it after
/// the tabs.
///
/// One row, muted. It was two rows in primary text, which on a tab that also
/// has a control strip put five rows of chrome above the first panel and made
/// a standing caveat the loudest thing on the screen.
pub fn render_attribution_header(f: &mut Frame, app: &App, area: Rect, extra: Vec<Span<'static>>) {
    render_header_with_extra(
        f,
        app,
        Rect::new(area.x, area.y, area.width, area.height.min(3)),
        extra,
    );
    if area.height > 3 {
        let coverage = app.connection_collector.coverage();
        let drops = coverage
            .capture_drops
            .map(|n| n.to_string())
            .unwrap_or_else(|| "not measured".into());
        // Bytes in the units every other number on the screen uses. The
        // collector's own summary prints them raw (`307995/30371761`), which
        // is right for a log and unreadable at a glance.
        let summary = coverage.summary();
        let summary = if summary.starts_with("attributed flows") {
            format!(
                "attributed {} of {} flows · {} of {} (last capture interval)",
                coverage.attributed_flows,
                coverage.eligible_flows,
                format_bytes_total(coverage.attributed_payload_bytes),
                format_bytes_total(coverage.eligible_payload_bytes),
            )
        } else {
            summary
        };
        let text =
            format!(" {summary} · capture drops: {drops} · polling can miss short-lived flows");
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                ellipsise(&text, usize::from(area.width)),
                Style::default().fg(app.theme.text_muted),
            ))),
            Rect::new(area.x, area.y + 3, area.width, 1),
        );
    }
}

/// Given a click column within the header row of a `width`-column terminal,
/// return which tab was clicked (if any). `current` matters because the
/// narrowest bar names only the current tab.
pub fn tab_at_column(col: u16, width: u16, current: Tab) -> Option<Tab> {
    let density = tab_density(width, current);
    let mut x = TAB_BAR_ORIGIN;
    for (i, &tab) in visible_tabs().iter().enumerate() {
        if i > 0 {
            x += TAB_GAP.chars().count() as u16;
        }
        let w = tab_segment(tab, density, current).chars().count() as u16;
        if col >= x && col < x + w {
            return Some(tab);
        }
        x += w;
    }
    None
}

/// Short, lowercase socket state, in the tool's own vocabulary.
///
/// The table used to truncate the kernel's name to fit its column, which
/// turned `ESTABLISHED` into `ESTABLI…` — not a word, and not a state anyone
/// can look up. These are the names `ss` prints, lowercased, and every one
/// fits the column whole.
pub fn state_label(state: &str) -> String {
    match state {
        "ESTABLISHED" => "estab",
        "LISTEN" => "listen",
        "TIME_WAIT" | "TIME-WAIT" => "time-wait",
        "CLOSE_WAIT" | "CLOSE-WAIT" => "close-wait",
        "SYN_SENT" | "SYN-SENT" => "syn-sent",
        "SYN_RECV" | "SYN-RECV" => "syn-recv",
        "FIN_WAIT1" | "FIN_WAIT_1" | "FIN-WAIT-1" => "fin-wait-1",
        "FIN_WAIT2" | "FIN_WAIT_2" | "FIN-WAIT-2" => "fin-wait-2",
        "LAST_ACK" | "LAST-ACK" => "last-ack",
        "CLOSING" => "closing",
        "CLOSED" => "closed",
        "UNCONN" => "unconn",
        "" => "—",
        // UDP and anything the platform names differently: lowercased so it
        // still reads as one vocabulary, never truncated.
        other => return other.to_lowercase(),
    }
    .to_string()
}

/// Build a table header row from a tab's COLUMNS array with sort indicators.
///
/// Headers are lowercased here rather than in each `COLUMNS` array, so the
/// casing is one decision instead of sixty. Column *names* stay Title Case in
/// source, where they read as prose in sort menus and error messages; the
/// table renders them in the tool's lowercase voice.
pub fn sort_header_row(app: &App, tab: Tab, columns: &[crate::sort::SortColumn]) -> Row<'static> {
    Row::new(
        columns
            .iter()
            .enumerate()
            .map(|(i, col)| {
                Cell::from(format!(
                    "{}{}",
                    col.name.to_lowercase(),
                    app.sort_indicator(tab, i)
                ))
                .style(Style::default().fg(app.theme.brand).bold())
            })
            .collect::<Vec<_>>(),
    )
    .height(1)
}

/// One key hint: the glyph the user presses, and what it does.
///
/// Structured rather than pre-styled so the footer can *deduplicate*. Every
/// tab used to hand-assemble its own spans, which is how Processes ended up
/// advertising `e:Export` and `E:Export` side by side and Diagnose ended up
/// with `↑↓:Issue` next to `↑↓:Scroll` — the same key twice, wearing two
/// labels, in one strip.
pub type Hint = (String, String);

/// Build a [`Hint`]. `hint("↵", "apply")` reads better at the call site than
/// a tuple of two `to_string()`s.
pub fn hint(key: impl Into<String>, label: impl Into<String>) -> Hint {
    (key.into(), label.into())
}

/// Render hints as `key label`, two spaces between pairs.
///
/// The one rendering of a key hint in the tool — footer, status strip, control
/// strip, panel actions. Key in the hint colour and bold, label muted, no
/// colon. `↵ drill`, never `↵:Drill`.
pub fn hint_spans(t: &Theme, hints: &[Hint]) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    for (i, (key, label)) in hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled(
            key.clone(),
            Style::default().fg(t.key_hint).bold(),
        ));
        spans.push(Span::styled(
            format!(" {label}"),
            Style::default().fg(t.text_muted),
        ));
    }
    spans
}

/// The keys that mean the same thing on every tab, in footer order.
///
/// `E incident` is deliberately not `E export`: `e` on a tab that has its own
/// export writes that tab's data, `E` writes the incident bundle. Two keys,
/// two actions, two labels — the review found them sharing one word.
fn universal_hints() -> Vec<Hint> {
    vec![
        hint("R", "rec"),
        hint("F", "freeze"),
        hint("E", "incident"),
        hint("↑↓", "scroll"),
        hint(FOOTER_TAB_HINT, "tab"),
        hint(":", "command"),
        hint("?", "help"),
        hint("q", "quit"),
    ]
}

/// One segmented control: a dim group label, then its options, the active one
/// on a raised ground.
///
/// `show [concern 3] all 9  established 5` — the label says what is being
/// chosen, the chip says what is chosen now, and the rest are the other
/// choices. Counts ride inside an option rather than beside it, because
/// `all 9` is one fact and `all` + `9` reads as two.
pub struct Control {
    pub label: &'static str,
    /// `(text, is_active)` in display order.
    pub options: Vec<(String, bool)>,
}

impl Control {
    pub fn new(label: &'static str, options: Vec<(String, bool)>) -> Self {
        Self { label, options }
    }

    /// A control with exactly one state and no alternatives — a status
    /// readout that lives in the strip because that is where the reader looks
    /// for it, e.g. `capture [● eth0]`.
    pub fn state(label: &'static str, text: impl Into<String>) -> Self {
        Self {
            label,
            options: vec![(text.into(), true)],
        }
    }
}

pub fn control_spans(t: &Theme, controls: &[Control]) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    for (i, c) in controls.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("   "));
        }
        spans.push(Span::styled(
            format!("{} ", c.label),
            Style::default().fg(t.text_muted),
        ));
        for (j, (text, active)) in c.options.iter().enumerate() {
            if j > 0 {
                spans.push(Span::raw(" "));
            }
            spans.push(Span::styled(
                format!(" {text} "),
                if *active {
                    Style::default().fg(t.text_primary).bg(t.selection_bg)
                } else {
                    Style::default().fg(t.text_muted)
                },
            ));
        }
    }
    spans
}

/// The control strip: segmented controls on the left, provenance in the
/// middle, the keys that change them on the right.
///
/// It is a row the tab earns, not one it reserves — a tab with nothing to put
/// here passes an empty slice and gets the row back for its panels.
pub fn render_control_strip(
    f: &mut Frame,
    t: &Theme,
    area: Rect,
    controls: &[Control],
    meta: Vec<Span<'static>>,
    hints: &[Hint],
) {
    if area.height == 0 {
        return;
    }
    let mut spans = vec![Span::raw(" ")];
    spans.extend(control_spans(t, controls));
    if !meta.is_empty() {
        spans.push(Span::raw("   "));
        spans.extend(meta);
    }

    let left: usize = spans.iter().map(|s| s.content.chars().count()).sum();
    let right = hint_spans(t, hints);
    let right_w: usize = right.iter().map(|s| s.content.chars().count()).sum();
    let avail = area.width as usize;
    if right_w > 0 && avail > left + right_w + 2 {
        spans.push(Span::raw(" ".repeat(avail - left - right_w - 1)));
        spans.extend(right);
    }

    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// A socket verdict as a coloured word on the panel ground.
///
/// The colour is the *severity* of the verdict, not a per-category colour —
/// which is why `app-limited` is green and `bufferbloat` amber. An
/// app-limited socket is working exactly as intended; a bufferbloated one is
/// the reason someone opened this screen.
pub fn socket_verdict_chip(
    t: &Theme,
    v: crate::diagnose::detectors::SocketVerdict,
) -> Span<'static> {
    use crate::diagnose::detectors::SocketVerdict as V;
    let fg = match v {
        V::Ok | V::AppLimited => t.status_good,
        V::ReceiverLimited => t.status_info,
        V::Bufferbloat | V::Congestion => t.status_warn,
        V::RetransBurst | V::ZeroWindow => t.status_error,
    };
    Span::styled(v.label().to_string(), Style::default().fg(fg))
}

/// How loudly a verdict asks to be looked at. Higher sorts first.
pub fn socket_verdict_concern(v: crate::diagnose::detectors::SocketVerdict) -> u8 {
    use crate::diagnose::detectors::SocketVerdict as V;
    match v {
        V::ZeroWindow => 5,
        V::RetransBurst => 4,
        V::Bufferbloat => 3,
        V::Congestion => 2,
        V::ReceiverLimited => 1,
        V::AppLimited | V::Ok => 0,
    }
}

/// Columns [`hint_spans`] will occupy for `hints`.
fn hint_width(hints: &[Hint]) -> usize {
    hints
        .iter()
        .map(|(k, l)| crate::ui::text::width(k) + 1 + crate::ui::text::width(l))
        .sum::<usize>()
        + hints.len().saturating_sub(1) * 2
}

/// Which hint a footer that does not fit gives up next, or `None` when what
/// is left stays whatever the width.
///
/// The footer used to pop from the right, and the right end is `? help` and
/// `q quit`: at 120 columns a tab with eight keys of its own lost the one hint
/// that leads to all the others. So the order is by what a reader can best
/// recover without being told. The tab digits are in the bar above; arrows
/// scroll in every program; the recorder's three keys are on every tab and in
/// help; `q` quits most things. Then the tab's own keys from the right. The
/// tab's first key and `? help` are never dropped.
fn next_hint_to_drop(hints: &[Hint], context: usize) -> Option<usize> {
    for key in [FOOTER_TAB_HINT, "↑↓", "E", "F", "R", "q", ":"] {
        if let Some(i) = hints
            .iter()
            .enumerate()
            .skip(context)
            .find_map(|(i, (k, _))| (k == key).then_some(i))
        {
            return Some(i);
        }
    }
    (context > 1).then(|| context - 1)
}

/// The footer: context keys, then the universal ones, then the toast.
///
/// A universal hint is dropped when the tab has already bound that key — the
/// tab's own label is the specific one and wins. Deduplication is by key, so
/// `↑↓ issue` silences `↑↓ scroll` while `e export report` leaves `E incident`
/// standing, which is correct: those are different keys.
pub fn render_footer(f: &mut Frame, app: &App, area: Rect, context_hints: Vec<Hint>) {
    let t = &app.theme;

    let mut hints = context_hints;
    let bound: std::collections::HashSet<String> = hints.iter().map(|(k, _)| k.clone()).collect();
    let before = hints.len();
    hints.extend(
        universal_hints()
            .into_iter()
            .filter(|(k, _)| !bound.contains(k)),
    );
    let universal_count = hints.len() - before;

    let avail = area.width as usize;

    // The toast carries the path of anything written to disk — the review
    // found `E` writing eight files and 6.4 MB with nothing on screen to say
    // where. So it is the footer's *first* claim on the width, and the keys
    // give way to it: a hint the user can rediscover by pressing `?` outranks
    // nothing, but it does not outrank the one line naming the file they just
    // asked for. See `next_hint_to_drop` for the order they go in.
    let toast: Option<(String, &str, Color)> = app.ui.export_status.as_ref().map(|status| {
        // Failures say so mid-sentence ("Incident export failed: …",
        // "Egress promote failed: …"), so the check cannot be a prefix.
        let lower = status.to_lowercase();
        let (glyph, color) = if lower.contains("failed") || lower.contains("error") {
            ("✕ ", t.status_error)
        } else if lower.contains("cancel") {
            // Nothing happened, by request. Not a success and not a failure.
            ("· ", t.text_muted)
        } else {
            ("✓ ", t.status_good)
        };
        (
            ellipsise(status, avail.saturating_sub(8).min(72)),
            glyph,
            color,
        )
    });
    let toast_width = toast
        .as_ref()
        .map(|(s, _, _)| crate::ui::text::width(s) + 4)
        .unwrap_or(0);

    // `1 +` for the leading space.
    let mut context = hints.len() - universal_count;
    while 1 + hint_width(&hints) + toast_width > avail {
        let Some(drop) = next_hint_to_drop(&hints, context) else {
            break;
        };
        hints.remove(drop);
        if drop < context {
            context -= 1;
        }
    }

    let mut spans = vec![Span::raw(" ")];
    spans.extend(hint_spans(t, &hints));

    let left_width: usize = spans
        .iter()
        .map(|s| crate::ui::text::width(&s.content))
        .sum();
    if let Some((text, glyph, color)) = toast {
        if avail > left_width + toast_width {
            spans.push(Span::raw(" ".repeat(avail - left_width - toast_width)));
            spans.push(Span::styled(glyph, Style::default().fg(color).bold()));
            spans.push(Span::styled(text, Style::default().fg(color)));
        }
    }

    let footer = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(t.border)),
    );
    f.render_widget(footer, area);
}

#[cfg(test)]
mod tests {
    #[test]
    fn format_count_groups_thousands() {
        for (n, text) in [
            (0, "0"),
            (999, "999"),
            (1_000, "1,000"),
            (1_280, "1,280"),
            (10_000, "10,000"),
            (123_456, "123,456"),
            (1_234_567, "1,234,567"),
        ] {
            assert_eq!(format_count(n), text);
        }
    }

    use super::*;

    fn failure_rows(error: &str, width: u16, spare: u16) -> Vec<String> {
        capture_failure_lines(&crate::theme::by_name("default"), error, width, spare)
            .iter()
            .map(|line| line.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect()
    }

    #[test]
    fn a_fix_is_drawn_whole_between_its_commands_or_not_at_all() {
        let error = "not permitted — first command && second command && third command";
        let whole = [
            " ⚠ capture off: not permitted. Run:",
            " first command && second command &&",
            " third command",
        ];
        assert_eq!(failure_rows(error, 40, 3), whole);
        let pointer = [format!(" ⚠ capture off: {CAPTURE_FIX_POINTER}")];
        // Two rows at this width, and one row short of them.
        assert_eq!(
            failure_rows(error, 200, 2)[1],
            " first command && second command && third command"
        );
        assert_eq!(failure_rows(error, 200, 1), pointer);
        assert_eq!(failure_rows(error, 200, 0), pointer);
        // A command wider than a row, with rows to spare.
        let narrow = failure_rows("no — a very long first command && b", 18, 10).join(" ");
        assert!(!narrow.contains("very"), "{narrow}");
        assert!(narrow.contains("--check-capture"), "{narrow}");
    }

    /// Not a command, so nothing is lost by breaking it, whatever `spare` says.
    #[test]
    fn a_failure_in_prose_breaks_between_words() {
        let plain = "run with sudo, or give your user read access to the device";
        let wrapped = [
            " ⚠ capture off: run with sudo, or give",
            " your user read access to the device",
        ];
        assert_eq!(failure_rows(plain, 40, 0), wrapped);
        assert_eq!(failure_rows(plain, 40, 9), wrapped);
        assert_eq!(
            failure_rows(plain, 200, 0),
            [format!(" ⚠ capture off: {plain}")]
        );
    }

    /// The real one: every row fits, at the widths that take it at all.
    #[test]
    fn the_linux_fix_fits_an_ordinary_terminal_in_whole_commands() {
        let error = format!("not permitted — {}", crate::platform::LINUX_CAPTURE_FIX);
        for width in [80, 100, 120, 200] {
            let rows = failure_rows(&error, width, 40);
            assert!(rows[0].ends_with("not permitted. Run:"), "{rows:?}");
            assert_eq!(
                rows[1..]
                    .iter()
                    .map(|r| r.trim())
                    .collect::<Vec<_>>()
                    .join(" "),
                crate::platform::LINUX_CAPTURE_FIX
            );
            for row in &rows {
                assert!(crate::ui::text::width(row) <= usize::from(width), "{row}");
            }
        }
    }

    fn find_first_col(target: Tab) -> Option<u16> {
        (0..220).find(|&col| tab_at_column(col, 220, Tab::Dashboard) == Some(target))
    }

    #[test]
    fn tab_at_column_before_tabs_returns_none() {
        assert!(tab_at_column(0, 220, Tab::Dashboard).is_none());
        assert!(tab_at_column(5, 220, Tab::Dashboard).is_none());
    }

    #[test]
    fn tab_at_column_hits_dashboard() {
        let col = find_first_col(Tab::Dashboard).expect("Dashboard must be reachable");
        assert_eq!(
            tab_at_column(col, 220, Tab::Dashboard),
            Some(Tab::Dashboard)
        );
        if col > 0 {
            assert_ne!(
                tab_at_column(col - 1, 220, Tab::Dashboard),
                Some(Tab::Dashboard)
            );
        }
    }

    #[test]
    fn tab_at_column_hits_each_tab() {
        for &tab in BASE_TABS {
            let col = find_first_col(tab);
            assert!(col.is_some(), "{:?} must be reachable by click", tab);
        }
    }

    #[test]
    fn tab_at_column_way_past_end_returns_none() {
        assert!(tab_at_column(220, 220, Tab::Dashboard).is_none());
    }

    #[test]
    fn every_tab_in_the_bar_is_clickable() {
        let mut found_tabs = std::collections::HashSet::new();
        for col in 0..220 {
            if let Some(tab) = tab_at_column(col, 220, Tab::Dashboard) {
                found_tabs.insert(format!("{:?}", tab));
            }
        }
        assert_eq!(
            found_tabs.len(),
            visible_tabs().len(),
            "every drawn tab must be reachable by click"
        );
    }

    /// The hit-test is derived geometry, and derived geometry drifts. This
    /// walks the spans the bar actually emits and checks that the tab a
    /// column *says* it holds is the tab drawn there — which is what caught
    /// `tab_at_column` still addressing the bracketed layout after the bar
    /// was restyled.
    #[test]
    fn the_click_hit_test_agrees_with_what_is_drawn() {
        let theme = crate::theme::by_name("default");
        // One width per density, and one narrower than any bar.
        for width in [220u16, 141, 120, 100, 80, 40] {
            for &current in visible_tabs().iter() {
                let density = tab_density(width, current);
                let spans = tab_bar_spans(current, density, &theme);
                let mut text = String::new();
                for s in &spans {
                    text.push_str(&s.content);
                }

                let mut col = TAB_BAR_ORIGIN as usize;
                for (i, &tab) in visible_tabs().iter().enumerate() {
                    if i > 0 {
                        col += TAB_GAP.chars().count();
                    }
                    let seg = tab_segment(tab, density, current);
                    assert!(text.contains(&seg), "{seg:?} is not drawn at {width}");
                    // Every column the segment covers must hit-test to this tab.
                    for offset in 0..seg.chars().count() {
                        assert_eq!(
                            tab_at_column((col + offset) as u16, width, current),
                            Some(tab),
                            "at {width} columns with {current:?} selected, column {} \
                             draws {seg:?} but hit-tests elsewhere",
                            col + offset
                        );
                    }
                    col += seg.chars().count();
                }

                assert_eq!(
                    text.chars().count() + TAB_BAR_ORIGIN as usize,
                    col,
                    "the drawn bar and the hit-test disagree on total width"
                );
            }
        }
    }

    /// The bar ran off the right edge below 141 columns: at 120 `9` had no
    /// name and `0` was gone, at 80 so were `7` and `8`. Every digit has to be
    /// on screen at every width a terminal is likely to be.
    #[test]
    fn every_tab_digit_is_on_screen_at_common_widths() {
        for width in [80u16, 100, 120, 132, 140, 160, 200] {
            for &current in visible_tabs().iter() {
                let density = tab_density(width, current);
                assert!(
                    tab_bar_width(density, current) <= width + 1,
                    "{density:?} bar is {} columns in a {width}-column terminal",
                    tab_bar_width(density, current)
                );
            }
        }
        assert_eq!(tab_density(141, Tab::Dashboard), TabDensity::Full);
        assert_eq!(tab_density(120, Tab::Dashboard), TabDensity::Short);
        assert_eq!(tab_density(80, Tab::Dashboard), TabDensity::Digits);
    }

    /// A key may appear once in a footer. Processes shipped `e:Export` beside
    /// `E:Export`, and Diagnose shipped `↑↓:Issue` beside `↑↓:Scroll` — the
    /// same key twice, wearing two labels, in one strip.
    #[test]
    fn a_tab_binding_silences_the_universal_hint_for_the_same_key() {
        let context = [hint("↑↓", "issue"), hint("e", "export report")];
        let bound: std::collections::HashSet<String> =
            context.iter().map(|(k, _)| k.clone()).collect();
        let kept: Vec<Hint> = universal_hints()
            .into_iter()
            .filter(|(k, _)| !bound.contains(k))
            .collect();

        assert!(
            !kept.iter().any(|(k, _)| k == "↑↓"),
            "the tab already bound ↑↓; the universal scroll hint must go"
        );
        // `e` and `E` are different keys with different actions, so both stay
        // — but they must not both be called "export".
        let e_upper = kept.iter().find(|(k, _)| k == "E").expect("E survives");
        assert_ne!(e_upper.1, "export report", "E and e must not share a label");
    }

    /// Every key in a rendered footer is distinct, whatever the tab asked for.
    #[test]
    fn no_footer_can_advertise_a_key_twice() {
        for context in [
            vec![hint("↑↓", "issue"), hint("e", "export report")],
            vec![hint("R", "rec")],
            vec![hint("q", "quit"), hint("?", "help")],
            Vec::new(),
        ] {
            let bound: std::collections::HashSet<String> =
                context.iter().map(|(k, _)| k.clone()).collect();
            let mut all: Vec<String> = context.iter().map(|(k, _)| k.clone()).collect();
            all.extend(
                universal_hints()
                    .into_iter()
                    .filter(|(k, _)| !bound.contains(k))
                    .map(|(k, _)| k),
            );
            let unique: std::collections::HashSet<&String> = all.iter().collect();
            assert_eq!(all.len(), unique.len(), "duplicate key in {all:?}");
        }
    }

    /// `↵ drill`, never `↵:Drill`. One rendering of a key hint in the tool.
    #[test]
    fn hints_render_as_key_space_label_with_no_colon() {
        let t = crate::theme::by_name("dark");
        let text: String = hint_spans(&t, &[hint("↵", "drill"), hint("esc", "back")])
            .iter()
            .map(|s| s.content.to_string())
            .collect();
        assert_eq!(text, "↵ drill  esc back");
        assert!(!text.contains(':'));
    }

    /// ratatui draws left- and right-aligned titles independently, so a box
    /// too narrow for both renders them over each other. The catalogue panel
    /// came out reading `watching for les · 21 active`, which looks like a
    /// corrupted title rather than a dropped label.
    #[test]
    fn a_panel_too_narrow_for_its_metadata_drops_the_metadata() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let t = crate::theme::by_name("dark");
        let row = |w: u16| {
            let mut terminal = Terminal::new(TestBackend::new(w, 3)).unwrap();
            terminal
                .draw(|f| {
                    Panel::new("watching for")
                        .meta("25 rules · 21 active · 4 planned")
                        .render(f, &t, Rect::new(0, 0, w, 3));
                })
                .unwrap();
            let buf = terminal.backend().buffer().clone();
            (0..w)
                .map(|x| buf[(x, 0)].symbol().to_string())
                .collect::<String>()
        };

        let narrow = row(50);
        assert!(narrow.contains("watching for"), "{narrow:?}");
        assert!(
            !narrow.contains("21 active"),
            "metadata must be dropped, not overlapped: {narrow:?}"
        );

        // With room for both, both are drawn.
        let wide = row(80);
        assert!(wide.contains("watching for"), "{wide:?}");
        assert!(wide.contains("21 active"), "{wide:?}");
    }

    /// A CJK title takes two columns a char. Counted in chars, this one left
    /// room for metadata that then covered its last character.
    #[test]
    fn a_wide_title_is_measured_in_columns() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let t = crate::theme::by_name("dark");
        let mut terminal = Terminal::new(TestBackend::new(28, 3)).unwrap();
        terminal
            .draw(|f| {
                Panel::new("接続一覧接続一覧").meta("12 active").render(
                    f,
                    &t,
                    Rect::new(0, 0, 28, 3),
                );
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        let top: String = (0..28).map(|x| buf[(x, 0)].symbol()).collect();
        assert_eq!(buf[(16, 0)].symbol(), "覧", "{top:?}");
        assert!(!top.contains("active"), "{top:?}");
    }

    /// Verdict chips take the colour of the verdict's *severity*, not a
    /// per-category colour. `app-limited` is a socket working exactly as
    /// intended; `bufferbloat` is why someone opened the screen.
    #[test]
    fn verdict_chips_are_coloured_by_severity_not_category() {
        use crate::diagnose::detectors::SocketVerdict as V;
        let t = crate::theme::by_name("dark");

        assert_eq!(
            socket_verdict_chip(&t, V::AppLimited).style.fg,
            Some(t.status_good)
        );
        assert_eq!(socket_verdict_chip(&t, V::Ok).style.fg, Some(t.status_good));
        assert_eq!(
            socket_verdict_chip(&t, V::Bufferbloat).style.fg,
            Some(t.status_warn)
        );
        assert_eq!(
            socket_verdict_chip(&t, V::ZeroWindow).style.fg,
            Some(t.status_error)
        );
        // The word carries the colour; no filled pill, so the column reads as
        // text against the panel ground.
        assert_eq!(socket_verdict_chip(&t, V::Ok).style.bg, None);
    }

    /// Concern ordering is what the dashboard sorts by. A zero-window socket
    /// outranks a bufferbloated one, and both outrank anything healthy —
    /// otherwise the panel is sorted by "busiest", which the Stats tab already
    /// answers better.
    #[test]
    fn concern_ranks_broken_sockets_above_busy_ones() {
        use crate::diagnose::detectors::SocketVerdict as V;
        assert!(socket_verdict_concern(V::ZeroWindow) > socket_verdict_concern(V::Bufferbloat));
        assert!(
            socket_verdict_concern(V::Bufferbloat) > socket_verdict_concern(V::ReceiverLimited)
        );
        assert!(socket_verdict_concern(V::ReceiverLimited) > socket_verdict_concern(V::AppLimited));
        assert_eq!(
            socket_verdict_concern(V::AppLimited),
            socket_verdict_concern(V::Ok)
        );
    }

    /// The strip's active option is the one wearing the ground.
    #[test]
    fn a_control_marks_exactly_the_active_option() {
        let t = crate::theme::by_name("dark");
        let spans = control_spans(
            &t,
            &[Control::new(
                "show",
                vec![
                    ("concern 3".into(), true),
                    ("all 9".into(), false),
                    ("listen 2".into(), false),
                ],
            )],
        );
        let grounded: Vec<&str> = spans
            .iter()
            .filter(|s| s.style.bg == Some(t.selection_bg))
            .map(|s| s.content.as_ref())
            .collect();
        assert_eq!(grounded, vec![" concern 3 "]);
        // And the group label reads as a label, not as another option.
        assert_eq!(spans[0].style.fg, Some(t.text_muted));
    }

    /// The toast outranks the keys for the width it needs.
    ///
    /// The review found `E` writing eight files and 6.4 MB with nothing on
    /// screen naming the path. A footer that keeps `q quit` and drops the one
    /// line telling the user where their export went has its priorities
    /// backwards, so hints give way from the right until the toast fits.
    #[test]
    fn the_toast_pushes_hints_off_rather_than_being_dropped() {
        let mut hints = vec![hint("↑↓", "issue"), hint("↵", "apply fix")];
        hints.extend(universal_hints());
        let full = hint_width(&hints);

        let toast_width = 48;
        let avail = full; // exactly enough for the keys, and nothing else
        let mut trimmed = hints.clone();
        while trimmed.len() > 1 && 1 + hint_width(&trimmed) + toast_width > avail {
            trimmed.pop();
        }

        assert!(
            trimmed.len() < hints.len(),
            "the keys must yield width to the toast"
        );
        assert!(!trimmed.is_empty(), "never trim the footer to nothing");
        assert_eq!(
            trimmed[0],
            hint("↑↓", "issue"),
            "the tab's own first key is the last to go"
        );
    }

    /// The egress toast names a process, and a CJK name takes two columns a
    /// char. Counted in chars, the toast was placed one column too far right
    /// for each of them and ran off the edge, and a long one was cut at 72
    /// chars, not 72 columns, so it lost its end with no `…`.
    #[test]
    fn a_wide_toast_ends_inside_the_footer() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::prepare_with_config(crate::config::NetwatchConfig::default());
        for (name, end) in [
            ("firefox-esr", "remove  "),
            ("接続監視接", "remove  "),
            (&*"接続監視".repeat(10), "…  "),
        ] {
            app.ui.export_status = Some(format!("{name} has no rule to remove"));
            let mut terminal = Terminal::new(TestBackend::new(100, 3)).unwrap();
            terminal
                .draw(|f| render_footer(f, &app, f.area(), Vec::new()))
                .unwrap();
            let buf = terminal.backend().buffer();
            let row: String = (0..100).map(|x| buf[(x, 1)].symbol()).collect();
            assert!(row.ends_with(end), "{name}: {row:?}");
        }
    }

    /// The brand span is what the click hit-test measures the bar from, so its
    /// width and `TAB_BAR_ORIGIN` are one fact in two places.
    #[test]
    fn the_brand_is_lowercase_and_exactly_the_hit_test_origin() {
        const BRAND: &str = "◉ netwatch ";
        assert_eq!(BRAND.chars().count(), TAB_BAR_ORIGIN as usize);
        assert_eq!(BRAND, BRAND.to_lowercase());
    }

    /// A badge names the tab it opens, not its position on the screen. The
    /// dashboard's connections box wears `2` because `2` is what opens
    /// Connections; a per-screen ordinal read as a shortcut and was not one.
    #[test]
    fn a_tab_badge_is_the_key_that_opens_that_tab() {
        for tab in visible_tabs() {
            let p = Panel::new("x").tab_badge(tab);
            let badge = p.badge.clone().expect("a badge");
            assert_eq!(
                badge,
                tab_label(tab).0,
                "{tab:?} badge must match its tab-bar digit"
            );
            // And pressing it must land on that tab: the digit is the one the
            // bar draws, which is the one the key handler reads.
            assert!(
                badge.len() == 1 && badge.chars().all(|c| c.is_ascii_digit()),
                "{badge:?} is not a single digit key"
            );
        }
    }

    /// A badge is a promise that the digit key does something. It is drawn
    /// inverse so it reads as a key rather than as part of the title.
    #[test]
    fn a_badged_panel_draws_its_number_before_the_title() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let t = crate::theme::by_name("dark");
        let mut terminal = Terminal::new(TestBackend::new(40, 3)).unwrap();
        terminal
            .draw(|f| {
                let p = Panel::new("connections").badge(1).meta("9 shown");
                p.render(f, &t, Rect::new(0, 0, 40, 3));
            })
            .unwrap();
        let buf = terminal.backend().buffer().clone();
        // Column indices, not byte offsets — the border glyphs are multi-byte.
        let top: Vec<String> = (0..40).map(|x| buf[(x, 0)].symbol().to_string()).collect();
        let badge_at = top.iter().position(|c| c == "1").expect("the badge digit");
        let title_at = top.iter().position(|c| c == "c").expect("the title");
        assert!(
            badge_at < title_at,
            "badge before title in {:?}",
            top.concat()
        );

        // Inverse, so it is legible as a chip rather than reading as text.
        let cell = &buf[(badge_at as u16, 0)];
        assert_eq!(cell.bg, t.brand, "the badge sits on the accent");
        assert_ne!(cell.fg, t.brand, "and its digit is not the same colour");
    }

    /// The chrome is one decision, and this is where it is written down.
    /// Before `panel_block` existed there were 48 hand-built blocks across 15
    /// files; nothing stopped the next one from picking square corners or a
    /// dim title, and several already had.
    #[test]
    fn every_panel_wears_the_same_chrome() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let theme = crate::theme::by_name("default");
        let mut terminal = Terminal::new(TestBackend::new(40, 5)).unwrap();
        terminal
            .draw(|f| {
                let inner = Panel::new("title").meta("meta").render(f, &theme, f.area());
                assert_eq!(inner.width, 38, "a panel insets by one column a side");
                assert_eq!(inner.height, 3);
            })
            .unwrap();

        let buf = terminal.backend().buffer().clone();
        // Cell symbols, one per column — `String::find` would give byte
        // offsets, and the box-drawing glyphs are three bytes each.
        let cols = |y: u16| -> Vec<String> {
            (0..buf.area.width)
                .map(|x| buf[(x, y)].symbol().to_string())
                .collect()
        };
        let col_of = |row: &[String], needle: &str| -> u16 {
            let joined: String = row.concat();
            let byte = joined
                .find(needle)
                .unwrap_or_else(|| panic!("{needle:?} is not on the row: {joined:?}"));
            joined[..byte].chars().count() as u16
        };
        let top_cols = cols(0);
        let bottom_cols = cols(4);
        let top: String = top_cols.concat();
        let bottom: String = bottom_cols.concat();

        assert!(top.starts_with('╭'), "rounded top-left, got {top:?}");
        assert!(top.ends_with('╮'), "rounded top-right, got {top:?}");
        assert!(bottom.starts_with('╰'), "rounded bottom-left");
        assert!(bottom.ends_with('╯'), "rounded bottom-right");
        assert!(top.contains(" title "), "title sits in the top border");
        assert!(top.contains(" meta "), "meta sits in the same border row");
        let title_x = col_of(&top_cols, "title");
        let meta_x = col_of(&top_cols, "meta");
        assert!(title_x < meta_x, "title left, meta right");

        // The title reads in the accent, the metadata stays dim: a heading
        // and its context must not look like the same thing.
        assert_eq!(buf[(title_x, 0)].fg, theme.brand);
        assert_eq!(buf[(meta_x, 0)].fg, theme.text_muted);
    }

    #[test]
    fn an_untitled_panel_still_gets_the_corners() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let theme = crate::theme::by_name("default");
        let mut terminal = Terminal::new(TestBackend::new(20, 4)).unwrap();
        terminal
            .draw(|f| {
                Panel::plain().render(f, &theme, f.area());
            })
            .unwrap();
        let buf = terminal.backend().buffer().clone();
        assert_eq!(buf[(0, 0)].symbol(), "╭");
        assert_eq!(buf[(19, 3)].symbol(), "╯");
    }

    #[test]
    fn a_focused_panel_takes_the_accent_border() {
        let theme = crate::theme::by_name("default");
        let plain = Panel::new("x").block(&theme);
        let focused = Panel::new("x").focused(true).block(&theme);
        assert_ne!(
            format!("{plain:?}"),
            format!("{focused:?}"),
            "focus must be visible in the border"
        );
    }

    #[test]
    fn socket_states_are_words_not_truncations() {
        assert_eq!(state_label("ESTABLISHED"), "estab");
        assert_eq!(state_label("TIME_WAIT"), "time-wait");
        assert_eq!(state_label("CLOSE_WAIT"), "close-wait");
        assert_eq!(state_label("LISTEN"), "listen");
        // Unknown states pass through lowercased rather than being cut.
        assert_eq!(state_label("SOME_NEW_STATE"), "some_new_state");
        assert_eq!(state_label(""), "—");
        // Nothing renders an ellipsis.
        for s in [
            "ESTABLISHED",
            "TIME_WAIT",
            "CLOSE_WAIT",
            "FIN_WAIT1",
            "SYN_RECV",
        ] {
            assert!(!state_label(s).contains('…'), "{s} was truncated");
        }
    }

    #[test]
    fn table_headers_render_in_the_tool_s_lowercase_voice() {
        // Column names stay Title Case in source — they read as prose in the
        // sort picker — and are lowered for the table.
        for col in crate::ui::connections::COLUMNS {
            assert!(
                col.name.chars().next().unwrap().is_uppercase(),
                "{} should stay Title Case in COLUMNS",
                col.name
            );
        }
    }

    #[test]
    fn diagnose_is_tab_nine_and_always_present() {
        let tabs = visible_tabs();
        assert_eq!(tabs.len(), 10, "1-9 then 0");
        assert_eq!(tab_label(Tab::Diagnose), ("9", "Diagnose"));
        assert!(find_first_col(Tab::Diagnose).is_some());
    }

    /// The footer used to advertise `1-8` while the bar drew ten tabs.
    #[test]
    fn the_footer_tab_hint_covers_every_tab_that_exists() {
        let numbers: Vec<&str> = visible_tabs().iter().map(|&t| tab_label(t).0).collect();
        assert_eq!(numbers, ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"]);
        // Which is exactly what the footer claims.
        assert!(FOOTER_TAB_HINT.contains("1-9,0"));
    }

    #[test]
    fn tabs_are_in_order() {
        let tabs = visible_tabs();
        let positions: Vec<u16> = tabs.iter().map(|&t| find_first_col(t).unwrap()).collect();
        for i in 1..positions.len() {
            assert!(
                positions[i] > positions[i - 1],
                "Tab {:?} should come after {:?}",
                tabs[i],
                tabs[i - 1]
            );
        }
    }

    /// The engine never returns Clear, so a quiet host with learned
    /// baselines is Incomplete — and the header drew that as the same green
    /// ● it would give a healthy one, on every tab.
    #[test]
    fn the_header_never_draws_incomplete_green() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut app = App::prepare_with_config(crate::config::NetwatchConfig::default());
        app.diagnose.baselines = crate::diagnose::fixture::baselines();
        assert!(matches!(
            app.diagnose.engine.verdict(&app.diagnose.baselines),
            crate::diagnose::Verdict::Incomplete { .. }
        ));
        for name in crate::theme::THEME_NAMES {
            app.theme = crate::theme::by_name(name);
            let mut terminal = Terminal::new(TestBackend::new(160, 3)).unwrap();
            terminal.draw(|f| render_header(f, &app, f.area())).unwrap();
            let buf = terminal.backend().buffer().clone();
            let row: String = (0..buf.area.width).map(|x| buf[(x, 1)].symbol()).collect();
            assert!(row.contains("◌ no issues"), "{name}: {row}");
            for x in 0..buf.area.width {
                let cell = &buf[(x, 1)];
                assert!(
                    cell.symbol() == " " || cell.fg != app.theme.status_good,
                    "{name}: green {:?} at column {x} of {row}",
                    cell.symbol()
                );
            }
        }
    }
}
