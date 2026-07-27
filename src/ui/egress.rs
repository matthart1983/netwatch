//! Egress tab — per-process egress profiles and policy drift.
//!
//! Shows what each process talks to (SNI / ASN / port) as learned by the
//! `EgressProfiler`, and — when an `egress-policy.toml` is loaded — whether
//! each destination is within the declared allowlist. Read-only: the linter
//! warns, it never blocks.
//!
//! The data is a tree (process → destinations) and is rendered as one. The
//! flat table this replaced repeated the process name on every row, spent a
//! whole column restating the destination as an IP, and showed a raw
//! observation count that was really a dwell time in seconds.

use crate::app::App;
use crate::collectors::egress::{EgressDest, EgressProfile, Verdict};
use crate::state::EgressSort;
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

const SPARK: &[char] = &['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
/// Rows of chrome above the table body: tab bar (3) + table border + header.
const HEADER_ROWS: u16 = 3;

/// A destination paired with its display label and policy verdict.
type ScoredDest<'a> = (&'a str, &'a EgressDest, Verdict);
/// A process and its (filtered, sorted) destinations.
type Group<'a> = (&'a EgressProfile, Vec<ScoredDest<'a>>);

/// One line of the rendered tree.
pub enum EgressRow<'a> {
    /// A process, carrying the rollup of its destinations.
    Process {
        profile: &'a EgressProfile,
        dests: usize,
        bytes_out: u64,
        bytes_in: u64,
        activity: Vec<u64>,
        /// Worst verdict across the process's destinations — what the
        /// operator needs to see without expanding.
        worst: Verdict,
        collapsed: bool,
    },
    /// A destination beneath the process above it.
    Dest {
        process: &'a str,
        label: &'a str,
        dest: &'a EgressDest,
        verdict: Verdict,
    },
}

/// Flatten the profiles into the visible row list, honouring filter,
/// collapse state and sort. Public so the mouse handler maps clicks against
/// exactly the rows the renderer drew.
pub fn visible_rows(app: &App) -> Vec<EgressRow<'_>> {
    let profiles = app.egress_profiler.profiles_ref();
    let needle = app
        .ui
        .egress_filter_active
        .as_deref()
        .map(str::to_lowercase);

    let mut groups: Vec<Group<'_>> = Vec::new();
    for profile in profiles {
        let mut dests: Vec<ScoredDest<'_>> = profile
            .dests
            .iter()
            .map(|((label, _), d)| {
                (
                    label.as_str(),
                    d,
                    app.egress_profiler.verdict(&profile.process, d),
                )
            })
            .filter(|(label, d, _)| match needle.as_deref() {
                None => true,
                // Match the process or any of its destination identities, so
                // filtering by "google" finds both a process named that and
                // anything talking to it.
                Some(n) => {
                    profile.process.to_lowercase().contains(n)
                        || label.to_lowercase().contains(n)
                        || d.sni
                            .as_deref()
                            .is_some_and(|s| s.to_lowercase().contains(n))
                        || d.asn_org
                            .as_deref()
                            .is_some_and(|s| s.to_lowercase().contains(n))
                        || d.last_ip.contains(n)
                }
            })
            .collect();
        if dests.is_empty() {
            continue;
        }
        // Destinations always by volume then dwell — within one process the
        // question is always "what did it talk to most".
        dests.sort_by(|a, b| {
            b.1.bytes_out
                .cmp(&a.1.bytes_out)
                .then_with(|| b.1.count.cmp(&a.1.count))
        });
        groups.push((profile, dests));
    }

    let key = |g: &Group<'_>| -> (u64, u64, u64) {
        let out: u64 = g.1.iter().map(|(_, d, _)| d.bytes_out).sum();
        let active: u64 = g.1.iter().map(|(_, d, _)| d.count).max().unwrap_or(0);
        let last: u64 =
            g.1.iter()
                .map(|(_, d, _)| {
                    d.last_seen
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|x| x.as_secs())
                        .unwrap_or(0)
                })
                .max()
                .unwrap_or(0);
        (out, active, last)
    };
    match app.ui.egress_sort {
        EgressSort::Volume => groups.sort_by_key(|g| std::cmp::Reverse(key(g).0)),
        EgressSort::Active => groups.sort_by_key(|g| std::cmp::Reverse(key(g).1)),
        EgressSort::LastSeen => groups.sort_by_key(|g| std::cmp::Reverse(key(g).2)),
        EgressSort::Process => groups.sort_by(|a, b| a.0.process.cmp(&b.0.process)),
        // Risk: anything unchecked or broadly admitted floats up. This is the
        // ordering that answers "what should I look at" rather than "what is
        // biggest", and it surfaces exactly the two findings the policy
        // analysis called critical.
        EgressSort::Risk => groups.sort_by(|a, b| {
            let rank = |g: &Group<'_>| {
                g.1.iter()
                    .map(|(_, _, v)| match v {
                        Verdict::Drift => 0,
                        Verdict::NoRule => 1,
                        Verdict::Asn(_) => 2,
                        Verdict::Ech => 3,
                        _ => 4,
                    })
                    .min()
                    .unwrap_or(4)
            };
            rank(a).cmp(&rank(b)).then_with(|| key(b).0.cmp(&key(a).0))
        }),
    }

    let mut rows = Vec::new();
    for (profile, dests) in groups {
        let collapsed = app.ui.egress_collapsed.contains(&profile.process);
        let bytes_out = dests.iter().map(|(_, d, _)| d.bytes_out).sum();
        let bytes_in = dests.iter().map(|(_, d, _)| d.bytes_in).sum();
        let worst = dests
            .iter()
            .map(|(_, _, v)| v.clone())
            .min_by_key(|v| match v {
                Verdict::Drift => 0,
                Verdict::NoRule => 1,
                Verdict::Asn(_) => 2,
                Verdict::Ech => 3,
                _ => 4,
            })
            .unwrap_or(Verdict::NoPolicy);
        rows.push(EgressRow::Process {
            profile,
            dests: dests.len(),
            bytes_out,
            bytes_in,
            activity: merged_activity(&dests),
            worst,
            collapsed,
        });
        if !collapsed {
            for (label, dest, verdict) in dests {
                rows.push(EgressRow::Dest {
                    process: &profile.process,
                    label,
                    dest,
                    verdict,
                });
            }
        }
    }
    rows
}

/// Sum the per-tick activity of a process's destinations into one series.
fn merged_activity(dests: &[ScoredDest<'_>]) -> Vec<u64> {
    let n = dests
        .iter()
        .map(|(_, d, _)| d.activity.len())
        .max()
        .unwrap_or(0);
    (0..n)
        .map(|i| {
            dests
                .iter()
                .map(|(_, d, _)| {
                    // Align to the right: series are newest-last and may
                    // differ in length when a destination appeared later.
                    let off = n - d.activity.len();
                    if i >= off {
                        d.activity[i - off]
                    } else {
                        0
                    }
                })
                .sum()
        })
        .collect()
}

/// Block sparkline over a byte series, scaled to its own max.
fn spark(samples: &[u64], width: usize) -> String {
    if samples.is_empty() || width == 0 {
        return String::new();
    }
    let tail = &samples[samples.len().saturating_sub(width)..];
    let max = *tail.iter().max().unwrap_or(&0);
    if max == 0 {
        // All-zero is a real answer — a flat floor, not an empty cell.
        return SPARK[0].to_string().repeat(tail.len());
    }
    tail.iter()
        .map(|v| {
            let idx = ((*v as f64 / max as f64) * (SPARK.len() - 1) as f64).round() as usize;
            SPARK[idx.min(SPARK.len() - 1)]
        })
        .collect()
}

/// Dwell rendered as a duration. `count` increments once per ~1 s connection
/// tick, so it is seconds — showing it as a bare number reads as a request
/// count, which it is not.
fn dwell(count: u64) -> String {
    match count {
        0 => "—".into(),
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{:.1}h", s as f64 / 3600.0),
        s => format!("{:.1}d", s as f64 / 86_400.0),
    }
}

/// Compact byte formatting with a GB step — egress totals reach it.
fn human_bytes(b: u64) -> String {
    const K: f64 = 1024.0;
    let f = b as f64;
    if f < K {
        format!("{b} B")
    } else if f < K * K {
        format!("{:.0} KB", f / K)
    } else if f < K * K * K {
        format!("{:.1} MB", f / (K * K))
    } else {
        format!("{:.1} GB", f / (K * K * K))
    }
}

/// Process under the cursor — the promote target. Works whether the cursor
/// is on a process row or one of its destinations.
pub fn selected_process(app: &App) -> Option<String> {
    let rows = visible_rows(app);
    let sel = app
        .ui
        .scroll
        .egress_scroll
        .min(rows.len().saturating_sub(1));
    match rows.get(sel)? {
        EgressRow::Process { profile, .. } => Some(profile.process.clone()),
        EgressRow::Dest { process, .. } => Some(process.to_string()),
    }
}

/// Bytes, or an em dash when capture isn't running and the figure would be a
/// confident-looking zero.
fn vol(b: u64) -> String {
    if b == 0 {
        "—".into()
    } else {
        human_bytes(b)
    }
}

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let has_warnings = app.egress_profiler.recent_violation_count() > 0;
    let warn_h: u16 = if has_warnings { 6 } else { 0 };
    let detail_h: u16 = if app.ui.egress_detail { 7 } else { 0 };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),        // header
            Constraint::Min(5),           // tree
            Constraint::Length(detail_h), // detail pane (d)
            Constraint::Length(warn_h),   // warnings
            Constraint::Length(3),        // footer
        ])
        .split(area);

    render_header(f, app, chunks[0]);
    render_tree(f, app, chunks[1]);
    if app.ui.egress_detail {
        render_detail(f, app, chunks[2]);
    }
    if has_warnings {
        render_warnings(f, app, chunks[3]);
    }
    render_footer(f, app, chunks[4]);
}

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let rows = visible_rows(app);
    let procs = rows
        .iter()
        .filter(|r| matches!(r, EgressRow::Process { .. }))
        .count();
    let dests: usize = rows
        .iter()
        .filter_map(|r| match r {
            EgressRow::Process { dests, .. } => Some(*dests),
            _ => None,
        })
        .sum();
    let out: u64 = rows
        .iter()
        .filter_map(|r| match r {
            EgressRow::Process { bytes_out, .. } => Some(*bytes_out),
            _ => None,
        })
        .sum();
    // The two counts the policy analysis called critical, on the default
    // screen: how much is unchecked, and how much is admitted ASN-wide.
    let unchecked = rows
        .iter()
        .filter(|r| {
            matches!(
                r,
                EgressRow::Process {
                    worst: Verdict::NoRule,
                    ..
                }
            )
        })
        .count();
    let asn_wide = rows
        .iter()
        .filter(|r| {
            matches!(
                r,
                EgressRow::Dest {
                    verdict: Verdict::Asn(_),
                    ..
                }
            )
        })
        .count();

    let mut extra = vec![
        Span::raw("  "),
        Span::styled("EGRESS", Style::default().fg(t.brand).bold()),
        Span::raw(format!("  {procs} processes · {dests} destinations")),
    ];
    // Note: on a narrow terminal the tab bar consumes this row entirely, so
    // the same figures are repeated in the panel title, which always has
    // room. This line is the bonus on a wide terminal, not the only copy.
    if out > 0 {
        extra.push(Span::raw("  ·  "));
        extra.push(Span::styled(
            format!("{} out", human_bytes(out)),
            Style::default().fg(t.text_primary),
        ));
    }
    if app.egress_profiler.has_policy() {
        if unchecked > 0 {
            extra.push(Span::styled(
                format!("  ·  {unchecked} undeclared"),
                Style::default().fg(t.status_warn).bold(),
            ));
        }
        if asn_wide > 0 {
            extra.push(Span::styled(
                format!("  ·  {asn_wide} ASN-wide"),
                Style::default().fg(t.status_warn).bold(),
            ));
        }
        if unchecked == 0 && asn_wide == 0 {
            extra.push(Span::styled(
                "  ·  policy: all precise",
                Style::default().fg(t.status_good),
            ));
        }
    } else {
        extra.push(Span::styled(
            "  ·  observe only (no policy)",
            Style::default().fg(t.text_muted),
        ));
    }
    widgets::render_header_with_extra(f, app, area, extra);
}

/// The counts that decide whether the operator needs to care, rendered for
/// the panel title. Kept separate from the header so a narrow terminal —
/// where the tab bar eats the header row — still shows them.
fn summary_line(app: &App, rows: &[EgressRow<'_>]) -> Line<'static> {
    let t = &app.theme;
    let procs = rows
        .iter()
        .filter(|r| matches!(r, EgressRow::Process { .. }))
        .count();
    let dests: usize = rows
        .iter()
        .filter_map(|r| match r {
            EgressRow::Process { dests, .. } => Some(*dests),
            _ => None,
        })
        .sum();
    let out: u64 = rows
        .iter()
        .filter_map(|r| match r {
            EgressRow::Process { bytes_out, .. } => Some(*bytes_out),
            _ => None,
        })
        .sum();
    let unchecked = rows
        .iter()
        .filter(|r| {
            matches!(
                r,
                EgressRow::Process {
                    worst: Verdict::NoRule,
                    ..
                }
            )
        })
        .count();
    let asn_wide = rows
        .iter()
        .filter(|r| {
            matches!(
                r,
                EgressRow::Dest {
                    verdict: Verdict::Asn(_),
                    ..
                }
            )
        })
        .count();

    let mut spans = vec![
        Span::styled(" Egress ", Style::default().fg(t.brand).bold()),
        Span::styled(
            format!("· {procs} processes · {dests} destinations"),
            Style::default().fg(t.text_muted),
        ),
    ];
    if out > 0 {
        spans.push(Span::styled(
            format!(" · {} out", human_bytes(out)),
            Style::default().fg(t.text_primary),
        ));
    }
    if app.egress_profiler.has_policy() {
        if unchecked > 0 {
            spans.push(Span::styled(
                format!(" · {unchecked} undeclared"),
                Style::default().fg(t.status_warn).bold(),
            ));
        }
        if asn_wide > 0 {
            spans.push(Span::styled(
                format!(" · {asn_wide} ASN-wide"),
                Style::default().fg(t.status_warn).bold(),
            ));
        }
        if unchecked == 0 && asn_wide == 0 {
            spans.push(Span::styled(
                " · all precise",
                Style::default().fg(t.status_good),
            ));
        }
    } else {
        spans.push(Span::styled(
            " · observe only",
            Style::default().fg(t.text_muted),
        ));
    }
    spans.push(Span::raw(" "));
    Line::from(spans)
}

/// The table's inner rect — shared with the mouse handler so a click maps to
/// the row the user actually sees (the lesson from issue #28).
pub fn table_inner_area(area: Rect) -> Rect {
    Rect {
        x: area.x + 1,
        y: area.y + HEADER_ROWS + 1,
        width: area.width.saturating_sub(2),
        height: area.height.saturating_sub(HEADER_ROWS + 2 + 3),
    }
}

fn render_tree(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let rows = visible_rows(app);

    if rows.is_empty() {
        let msg = if app.ui.egress_filter_active.is_some() {
            "No destinations match the filter.\n\nPress / to edit it, Esc to clear."
        } else {
            "No egress observed yet.\n\nTraffic to external hosts will appear here, grouped by \
             process. SNI is read from the cleartext TLS/QUIC ClientHello — no decryption needed."
        };
        f.render_widget(
            Paragraph::new(msg)
                .style(Style::default().fg(t.text_muted))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(t.border)),
                ),
            area,
        );
        return;
    }

    let body = area.height.saturating_sub(3) as usize;
    let selected = app
        .ui
        .scroll
        .egress_scroll
        .min(rows.len().saturating_sub(1));
    let start = (selected + 1).saturating_sub(body.max(1));
    let spark_w = 7usize;

    let mut lines: Vec<Row> = Vec::new();
    for (i, row) in rows.iter().enumerate().skip(start).take(body) {
        let is_sel = i == selected;
        let bg = if is_sel { t.selection_bg } else { t.bg };
        lines.push(match row {
            EgressRow::Process {
                profile,
                dests,
                bytes_out,
                bytes_in,
                activity,
                worst,
                collapsed,
            } => {
                let chevron = if *collapsed { "▶" } else { "▼" };
                let (vcol, vtext) = verdict_style(t, worst, true);
                Row::new(vec![
                    Cell::from(format!("{chevron} {}", profile.process)).style(
                        Style::default()
                            .fg(t.brand)
                            .bg(bg)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Cell::from(format!("{dests} dests"))
                        .style(Style::default().fg(t.text_muted).bg(bg)),
                    Cell::from(vol(*bytes_out)).style(Style::default().fg(t.tx_rate).bg(bg)),
                    Cell::from(vol(*bytes_in)).style(Style::default().fg(t.rx_rate).bg(bg)),
                    Cell::from(spark(activity, spark_w))
                        .style(Style::default().fg(t.text_secondary).bg(bg)),
                    Cell::from("").style(Style::default().bg(bg)),
                    Cell::from(vtext).style(Style::default().fg(vcol).bg(bg)),
                ])
            }
            EgressRow::Dest {
                label,
                dest,
                verdict,
                ..
            } => {
                // host:port in one cell — the form everyone reads. The IP is
                // only shown when it adds something, i.e. when the label is
                // a name rather than the address itself.
                let endpoint = format!("    {}:{}", label, dest.port);
                let (vcol, vtext) = verdict_style(t, verdict, false);
                Row::new(vec![
                    Cell::from(endpoint).style(Style::default().fg(t.text_primary).bg(bg)),
                    Cell::from(if dest.last_ip == *label {
                        String::new()
                    } else {
                        dest.last_ip.clone()
                    })
                    .style(Style::default().fg(t.text_muted).bg(bg)),
                    Cell::from(vol(dest.bytes_out)).style(Style::default().fg(t.tx_rate).bg(bg)),
                    Cell::from(vol(dest.bytes_in)).style(Style::default().fg(t.rx_rate).bg(bg)),
                    Cell::from(spark(
                        &dest.activity.iter().copied().collect::<Vec<_>>(),
                        spark_w,
                    ))
                    .style(Style::default().fg(t.text_secondary).bg(bg)),
                    Cell::from(dwell(dest.count))
                        .style(Style::default().fg(t.text_secondary).bg(bg)),
                    Cell::from(vtext).style(Style::default().fg(vcol).bg(bg)),
                ])
            }
        });
    }

    let header = Row::new(vec![
        "Process / destination",
        "IP",
        "Out",
        "In",
        "Activity",
        "Active",
        "Policy",
    ])
    .style(Style::default().fg(t.key_hint).bold());

    let shown = lines.len();
    let right = format!(
        " {}–{} of {}  sort[{}]{} ",
        (start + 1).min(rows.len()),
        start + shown,
        rows.len(),
        app.ui.egress_sort.label(),
        app.ui
            .egress_filter_active
            .as_deref()
            .map(|x| format!("  filter:\"{x}\""))
            .unwrap_or_default()
    );

    f.render_widget(
        Table::new(
            lines,
            [
                Constraint::Min(34),    // process / destination
                Constraint::Length(16), // IP
                Constraint::Length(9),  // out
                Constraint::Length(9),  // in
                Constraint::Length(8),  // activity
                Constraint::Length(7),  // active
                Constraint::Length(11), // policy
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(t.border))
                .title_top(summary_line(app, &rows))
                .title_top(
                    Line::from(Span::styled(right, Style::default().fg(t.text_muted)))
                        .right_aligned(),
                ),
        ),
        area,
    );
}

/// Colour + text for a verdict. `~ asn` and `— no rule` are deliberately
/// styled as warnings rather than neutral: both mean "admitted without
/// really being checked", which a tick would hide.
fn verdict_style(t: &crate::theme::Theme, v: &Verdict, rollup: bool) -> (Color, String) {
    match v {
        Verdict::Sni | Verdict::Ip => (t.status_good, v.label().to_string()),
        Verdict::Asn(org) => (
            t.status_warn,
            if rollup {
                "⚠ asn-wide".to_string()
            } else {
                format!("~ {}", truncate(org, 9))
            },
        ),
        Verdict::Ech => (t.status_warn, v.label().to_string()),
        Verdict::Drift => (t.status_error, v.label().to_string()),
        Verdict::NoRule => (t.status_warn, v.label().to_string()),
        Verdict::NoPolicy => (t.text_muted, v.label().to_string()),
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n.saturating_sub(1)).collect::<String>() + "…"
    }
}

fn render_detail(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let rows = visible_rows(app);
    let sel = app
        .ui
        .scroll
        .egress_scroll
        .min(rows.len().saturating_sub(1));
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.border))
        .title(" Detail ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let Some(row) = rows.get(sel) else { return };
    let lines: Vec<Line> = match row {
        EgressRow::Process {
            profile,
            dests,
            bytes_out,
            bytes_in,
            worst,
            ..
        } => vec![
            kv(t, "Process", profile.process.clone()),
            kv(t, "Destinations", format!("{dests}")),
            kv(
                t,
                "Volume",
                format!("{} out · {} in", vol(*bytes_out), vol(*bytes_in)),
            ),
            kv(t, "Worst verdict", worst.label().to_string()),
        ],
        EgressRow::Dest {
            label,
            dest,
            verdict,
            ..
        } => {
            // The whole point of the pane: the untruncated name.
            let mut v = vec![
                kv(t, "Destination", format!("{}:{}", label, dest.port)),
                kv(
                    t,
                    "Address",
                    format!(
                        "{}{}",
                        if dest.last_ip.is_empty() {
                            "—"
                        } else {
                            &dest.last_ip
                        },
                        dest.asn_org
                            .as_deref()
                            .map(|a| format!("   ASN  {a}"))
                            .unwrap_or_default()
                    ),
                ),
                kv(
                    t,
                    "Volume",
                    format!("{} out · {} in", vol(dest.bytes_out), vol(dest.bytes_in)),
                ),
                kv(
                    t,
                    "Active",
                    format!(
                        "{}   ECH  {}",
                        dwell(dest.count),
                        if dest.ech { "yes" } else { "no" }
                    ),
                ),
            ];
            v.push(match verdict {
                Verdict::Asn(org) => Line::from(vec![
                    Span::styled(
                        format!("{:<14}", "Verdict"),
                        Style::default().fg(t.text_muted),
                    ),
                    Span::styled(
                        format!("~ asn — admitted by autonomous system \"{org}\", not by name."),
                        Style::default().fg(t.status_warn),
                    ),
                ]),
                other => kv(t, "Verdict", other.label().to_string()),
            });
            v
        }
    };
    f.render_widget(
        Paragraph::new(lines).style(Style::default().bg(t.bg)),
        inner,
    );
}

fn kv(t: &crate::theme::Theme, k: &str, v: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{k:<14}"), Style::default().fg(t.text_muted)),
        Span::styled(v, Style::default().fg(t.text_primary)),
    ])
}

fn render_warnings(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.status_error))
        .title(" Recent drift ");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let lines: Vec<Line> = app
        .egress_profiler
        .recent_violations()
        .take(inner.height as usize)
        .map(|v| {
            Line::from(vec![
                Span::styled(
                    format!("{:<20}", truncate(&v.process, 20)),
                    Style::default().fg(t.text_primary),
                ),
                Span::styled(
                    format!("{}:{}  ", truncate(&v.dest, 34), v.port),
                    Style::default().fg(t.status_error),
                ),
                Span::styled(v.reason.clone(), Style::default().fg(t.text_muted)),
            ])
        })
        .collect();
    f.render_widget(
        Paragraph::new(lines).style(Style::default().bg(t.bg)),
        inner,
    );
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    if app.ui.egress_filter_input {
        let line = Line::from(vec![
            Span::styled(" / ", Style::default().fg(t.brand).bold()),
            Span::styled(
                app.ui.egress_filter_text.clone(),
                Style::default().fg(t.text_primary),
            ),
            Span::styled("▏", Style::default().fg(t.brand).bold()),
            Span::styled(
                "    Enter apply   Esc cancel",
                Style::default().fg(t.text_muted),
            ),
        ]);
        f.render_widget(Paragraph::new(line).style(Style::default().bg(t.bg)), area);
        return;
    }
    let hint = |k: &'static str, label: &'static str| {
        vec![
            Span::styled(k, Style::default().fg(t.key_hint).bold()),
            Span::raw(format!(" {label}   ")),
        ]
    };
    let mut spans = vec![Span::raw(" ")];
    spans.extend(hint("s", "sort"));
    spans.extend(hint("/", "filter"));
    spans.extend(hint("space", "fold"));
    spans.extend(hint("d", "detail"));
    spans.extend(hint("↵", "promote"));
    spans.extend(hint("e", "export"));
    // Teach the two glyphs that aren't self-evident, rather than restating
    // that the linter never blocks — that belongs in the docs, not on every
    // frame.
    spans.push(Span::styled("~ asn", Style::default().fg(t.status_warn)));
    spans.push(Span::styled(
        " = whole-AS match   ",
        Style::default().fg(t.text_muted),
    ));
    spans.push(Span::styled(
        "— no rule",
        Style::default().fg(t.status_warn),
    ));
    spans.push(Span::styled(
        " = unchecked",
        Style::default().fg(t.text_muted),
    ));
    f.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(t.bg)),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `count` is ticks-since-first-seen, i.e. seconds. Rendering it raw was
    /// the bug: `31427` reads as a request count but means 8.7 hours.
    #[test]
    fn dwell_reads_as_a_duration_not_a_count() {
        assert_eq!(dwell(0), "—");
        assert_eq!(dwell(45), "45s");
        assert_eq!(dwell(600), "10m");
        assert_eq!(dwell(31_427), "8.7h");
        assert_eq!(dwell(200_000), "2.3d");
    }

    /// No capture means no rates, which means no bytes. Showing "0 B" would
    /// assert that nothing was sent; "—" says we don't know.
    #[test]
    fn zero_volume_renders_as_unknown_not_zero() {
        assert_eq!(vol(0), "—");
        assert_eq!(vol(1536), "2 KB");
    }

    #[test]
    fn human_bytes_reaches_gigabytes() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2 * 1024 * 1024), "2.0 MB");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.0 GB");
    }

    #[test]
    fn spark_scales_to_its_own_maximum() {
        let s = spark(&[0, 50, 100], 7);
        assert_eq!(s.chars().count(), 3);
        assert_eq!(s.chars().next().unwrap(), '▁');
        assert_eq!(s.chars().last().unwrap(), '█');
    }

    /// An all-zero series is a real answer — a flat floor — not an empty
    /// cell, which would look like missing data.
    #[test]
    fn spark_renders_a_flat_floor_for_all_zero() {
        assert_eq!(spark(&[0, 0, 0], 7), "▁▁▁");
        assert_eq!(spark(&[], 7), "");
    }

    #[test]
    fn spark_shows_only_the_most_recent_window() {
        let s = spark(&[1, 2, 3, 4, 5, 6, 7, 8, 9], 4);
        assert_eq!(s.chars().count(), 4, "oldest samples are dropped");
    }

    #[test]
    fn truncate_marks_elision() {
        assert_eq!(truncate("short", 9), "short");
        assert_eq!(truncate("Microsoft Corporation", 9), "Microsof…");
    }
}
