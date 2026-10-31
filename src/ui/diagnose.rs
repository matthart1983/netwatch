//! The Diagnose tab: issues → probable cause → remediation → report.
//!
//! Rendering takes a [`View`] rather than the `App`, so the whole screen can
//! be drawn from a fixture with no capture running. That is what makes the
//! demo and the snapshot tests possible, and it means the screenshots in the
//! docs are produced by the same code path a user sees.
//!
//! Colour vocabulary, applied strictly here and nowhere overloaded:
//! green/amber/red mean *status only*; blue is a key hint; selection is an
//! inverted row. Nothing is green unless it is healthy.

use ratatui::{
    prelude::*,
    widgets::{Paragraph, Wrap},
};

use crate::diagnose::baseline::BaselineStore;
use crate::diagnose::engine::{Engine, Verdict};
use crate::diagnose::issue::{
    Applied, Capability, CheckResult, Issue, IssueState, Severity, Step, StepKind,
};
use crate::diagnose::rules;
use crate::theme::Theme;
use crate::ui::widgets;

/// Everything the tab needs to draw itself.
pub struct View<'a> {
    pub engine: &'a Engine,
    pub baselines: &'a BaselineStore,
    pub theme: &'a Theme,
    /// Index into [`Engine::primary`].
    pub selected: usize,
    pub show_report: bool,
    /// Privileges netwatch holds, so unavailable apply steps are hidden
    /// rather than dangled.
    pub capability: Capability,
    /// Optional AI commentary. `None` when the feature is switched off;
    /// `Some` whenever it is on, *including* while it is failing — see [`Ai`].
    pub ai: Option<Ai>,
    /// Where the model is configured to live, for the failure message.
    pub endpoint: String,
    /// The `third_party_probes` config key: whether a test that asks a public
    /// server may be offered.
    pub third_party_probes: bool,
    /// Transient status line (export path, applied confirmation, reconciliation).
    pub status: Option<&'a str>,
    /// `status` is the recovery journal's notice, which is a warning whatever its
    /// words happen to be: some carry the text of a parse error.
    pub status_is_recovery: bool,
    /// Set when the engine is replaying a recorded scenario rather than
    /// watching the network. Rendered on every frame and not suppressible —
    /// a demo a viewer can mistake for live measurement is worse than none.
    pub demo_banner: Option<String>,
    /// Tests running against the selected issue.
    pub running_tests: Vec<String>,
    /// Recent samples of the selected issue's headline metric.
    ///
    /// The detail pane used to print the numbers and stop, which left the
    /// reader to imagine the shape: a spike that has already passed and one
    /// that is still climbing read identically as "40 ms". The caller owns
    /// the mapping from metric to series, so this module stays presentation.
    pub history: Option<MetricHistory>,
}

/// Recent samples behind an issue's headline metric.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricHistory {
    pub metric: String,
    /// Oldest first, in the metric's own unit.
    pub samples: Vec<f64>,
    /// The value the rule compares against, when it has one.
    pub threshold: Option<f64>,
    pub unit: String,
}

/// The AI commentary block's state.
///
/// Carries the collector's status, not just its output, because those are
/// different things and only one of them was being shown. When the Insights
/// tab folded into Diagnose, the narrative came with it and the status did
/// not — so a user with the feature enabled and no model running got total
/// silence: no paragraph, no error, no hint that anything had been attempted.
/// A feature that fails invisibly is worse than one that is off.
pub struct Ai {
    pub status: crate::collectors::insights::InsightsStatus,
    pub narrative: Option<String>,
}

impl Ai {
    /// The line shown when there is no narrative to show, or above one that
    /// is stale. Says what the model is doing and, when it has gone wrong,
    /// what to do about it.
    pub fn status_line(&self, endpoint: &str) -> String {
        use crate::collectors::insights::InsightsStatus as S;
        match &self.status {
            S::Idle => "waiting for the first analysis".to_string(),
            S::Analyzing => "analysing…".to_string(),
            S::Available => "commentary on the findings above, not a source of facts".to_string(),
            S::OllamaUnavailable => format!(
                "no model answering at {} — start ollama, or switch this off in settings (,)",
                crate::collectors::insights::resolve_endpoint(endpoint)
            ),
            S::Error(e) => format!("model error: {e}"),
        }
    }

    /// Whether the block is reporting a problem rather than a result.
    pub fn is_failing(&self) -> bool {
        use crate::collectors::insights::InsightsStatus as S;
        matches!(self.status, S::OllamaUnavailable | S::Error(_))
    }
}

/// The line every Diagnose page carries while Insights is on and sending in
/// the clear to another machine. Requests go out every 15 seconds whether or
/// not an issue is open, so it sits under the verdict rather than in a pane
/// that can run out of rows. It fits 80 columns, with its label first if not.
fn cleartext_insights_line(view: &View) -> Option<Line<'static>> {
    use crate::collectors::insights::{cleartext_off_host, CLEARTEXT_OFF_HOST};
    (view.ai.is_some() && cleartext_off_host(&view.endpoint)).then(|| {
        Line::from(Span::styled(
            format!(
                "{CLEARTEXT_OFF_HOST}: Insights sends DNS names and peer addresses unencrypted"
            ),
            Style::default().fg(view.theme.status_warn),
        ))
    })
}

impl<'a> View<'a> {
    /// The issue the cursor is on.
    pub fn current(&self) -> Option<&'a Issue> {
        let primary = self.engine.primary();
        primary
            .get(self.selected.min(primary.len().saturating_sub(1)))
            .copied()
    }

    /// Replaying the recorded scenario, where an apply step is simulated.
    /// Live, netwatch changes nothing from this screen, so nothing offers a
    /// key that would.
    fn is_demo(&self) -> bool {
        self.demo_banner.is_some()
    }
}

/// Recent samples behind the selected issue's headline metric.
///
/// Only the health probes keep a series netwatch can show: gateway, resolver
/// and internet RTT. Everything else returns `None` and the pane prints the
/// numbers alone, which is what it did for every issue until now.
fn selected_history(app: &crate::app::App) -> Option<MetricHistory> {
    let issues = app.diagnose.engine.primary();
    let issue = issues.get(app.diagnose.selected)?;
    let headline = issue.headline()?;
    let hs = app.health_prober.status();
    let samples: Vec<f64> = match headline.metric.as_str() {
        "gateway.rtt" => hs.gateway_rtt_history.iter().flatten().copied().collect(),
        "dns.rtt_p50" => hs.dns_rtt_history.iter().flatten().copied().collect(),
        "path.rtt" => hs.internet_rtt_history.iter().flatten().copied().collect(),
        _ => return None,
    };
    if samples.len() < 4 {
        return None;
    }
    Some(MetricHistory {
        metric: headline.metric.clone(),
        // The rule's own verify threshold, which is the line the issue
        // closes on — not a second number invented for the chart.
        threshold: (issue.verify.metric == headline.metric).then_some(issue.verify.threshold),
        unit: headline.unit.clone(),
        samples,
    })
}

pub fn render(f: &mut Frame, app: &crate::app::App, area: Rect) {
    // Present whenever the feature is enabled — a collector that exists but
    // cannot reach a model still has something to tell the user.
    let ai = app.insights_collector.as_ref().map(|c| Ai {
        status: (*c.get_status()).clone(),
        narrative: c.latest_narrative(),
    });
    let view = View {
        engine: &app.diagnose.engine,
        baselines: &app.diagnose.baselines,
        theme: &app.theme,
        selected: app.diagnose.selected,
        show_report: app.diagnose.show_report,
        capability: app.diagnose.capability,
        ai,
        endpoint: app.user_config.insights_endpoint.clone(),
        third_party_probes: app.user_config.third_party_probes,
        status: app
            .diagnose
            .journal
            .recovery_notice()
            .or(app.diagnose.status.as_deref()),
        status_is_recovery: app.diagnose.journal.recovery_notice().is_some(),
        demo_banner: app.diagnose.demo.as_ref().map(|d| d.banner()),
        running_tests: selected_issue(app)
            .map(|id| app.diagnose.tests.running_for(&id))
            .unwrap_or_default(),
        history: selected_history(app),
    };
    // The header's verdict row is suppressed here: this tab *is* the verdict,
    // and the body renders it in full a line below. Two copies of the same
    // sentence, stacked, reads as a rendering bug.
    crate::ui::widgets::render_header_without_verdict(f, app, chunk_header(area));
    if app.diagnose.show_coverage {
        let mut body = chunk_body(area);
        if let Some(line) = cleartext_insights_line(&view) {
            let (row, rest) = crate::ui::widgets::take_top(body, 1);
            f.render_widget(Paragraph::new(line), inset(row));
            body = rest;
        }
        render_coverage(f, app, body);
    } else {
        render_body(f, &view, chunk_body(area));
    }
    let hints = if app.diagnose.show_coverage {
        vec![
            crate::ui::widgets::hint("↑/↓", "select check"),
            crate::ui::widgets::hint("t", "run"),
            crate::ui::widgets::hint("x", "cancel"),
            crate::ui::widgets::hint("r", "reload config"),
            crate::ui::widgets::hint("[/]", "target"),
            crate::ui::widgets::hint("c", "back to issues"),
        ]
    } else {
        footer_hints(&view)
    };
    crate::ui::widgets::render_footer(f, app, chunk_footer(area), hints);
}

fn render_coverage(f: &mut Frame, app: &crate::app::App, area: Rect) {
    let coverage = app.diagnose.engine.coverage();
    let selected = app
        .diagnose
        .coverage_selected
        .min(coverage.rules.len().saturating_sub(1));
    let details = coverage
        .rules
        .get(selected)
        .map(|row| coverage_details(app, row))
        .unwrap_or_default();
    draw_coverage(f, &app.theme, &coverage.rules, selected, &details, area);
}

/// Label/value rows for the selected check's detail panel.
fn coverage_details(
    app: &crate::app::App,
    row: &crate::diagnose::coverage::RuleCoverage,
) -> Vec<(&'static str, String)> {
    let times = &app.diagnose.sampler.completed;
    let at = match row.rule.split('.').next().unwrap_or("") {
        "ipv6" => times.ipv6,
        "captive" => times.portal,
        "pmtu" => times.pmtu,
        "tcp"
            if matches!(
                row.rule.as_str(),
                "tcp.connect_failures" | "tcp.timewait_exhaustion"
            ) =>
        {
            times.kernel
        }
        "dns" => times.health.dns,
        "gateway" => times.health.gateway,
        "link" | "iface" | "wifi" => times.interface,
        "path" => times.path,
        "nat" => times.health.nat,
        "egress" => times.egress,
        "target" => times.targets.values().copied().max(),
        "tcp" if row.rule == "tcp.bufferbloat_local" => {
            app.diagnose.sampler.load_test.map(|(at, _, _)| at)
        }
        "tcp" => times.sockets,
        _ => None,
    };
    let age = at
        .map(|at| format!("{}s ago", at.elapsed().as_secs()))
        .unwrap_or_else(|| "no completed sample".into());
    let mut out = vec![
        ("Why", row.reason.clone()),
        ("Source", format!("{} · {age}", row.source())),
        ("Next", row.next_action().to_string()),
    ];
    if row.rule == "tcp.bufferbloat_local" {
        out.push((
            "Cost",
            "t starts up to 25 MB upload to speed.cloudflare.com; ~15–45s, may slow other traffic"
                .into(),
        ));
    }
    let (active, _, progress) = app.diagnose.active_prober.snapshot();
    if let Some(result) = active.get(&row.rule) {
        out.push(("Result", result.detail.clone()));
    }
    if !progress.is_empty()
        && matches!(
            row.rule.as_str(),
            "ipv6.broken" | "captive.portal" | "pmtu.blackhole"
        )
    {
        out.push(("Progress", progress));
    }
    if row.rule.starts_with("target.") {
        let (targets, _) = app
            .diagnose
            .target_prober
            .fresh(&app.user_config.diagnose_targets);
        if targets.is_empty() {
            out.push((
                "Setup",
                "add [[diagnose_targets]] name, host, port, http, tls, path to config.toml; t probes now"
                    .into(),
            ));
        }
        let selected = app
            .user_config
            .diagnose_targets
            .get(app.diagnose.target_selected);
        if let Some(cfg) = selected {
            out.push((
                "Target",
                format!(
                    "{}/{}: {}{} ({}:{}) · [/] select · d enable/disable",
                    app.diagnose.target_selected + 1,
                    app.user_config.diagnose_targets.len(),
                    cfg.name,
                    if cfg.enabled { "" } else { " [disabled]" },
                    cfg.host,
                    cfg.port
                ),
            ));
        }
        for (_, t) in targets
            .iter()
            .filter(|(_, t)| selected.is_some_and(|cfg| cfg.name == t.name))
        {
            let stage = |s: Option<&crate::diagnose::targets::Stage>| {
                s.map(|s| {
                    if let Some(e) = &s.error {
                        e.label()
                    } else {
                        format!("{:.0}ms", s.ms.unwrap_or_default())
                    }
                })
                .unwrap_or_else(|| "not run".into())
            };
            out.push((
                "Stages",
                format!(
                    "DNS {} · TCP {} · TLS {} · HTTP {}",
                    stage(Some(&t.resolve)),
                    stage(t.connect.as_ref()),
                    stage(t.tls_stage.as_ref()),
                    stage(t.http_stage.as_ref())
                ),
            ));
        }
    }
    if app.diagnose.tests.any_running("coverage") {
        out.push(("Running", "measurement in progress…".into()));
    }
    if let Some(status) = &app.diagnose.status {
        out.push(("Status", status.clone()));
    }
    out
}

/// Colour for an availability: green when the rule can fire, amber when it is
/// waiting on something that will come, muted when it is off by choice or has
/// nothing to watch, red when a collector is broken.
fn availability_color(t: &Theme, a: &crate::diagnose::coverage::Availability) -> Color {
    use crate::diagnose::coverage::Availability as A;
    match a {
        A::Available => t.status_good,
        A::Learning | A::AwaitingTest | A::Stale | A::NotMeasured => t.status_warn,
        A::PermissionDenied | A::CollectorFailed => t.status_error,
        A::NotConfigured
        | A::NoSubjects
        | A::NotApplicable
        | A::Unsupported
        | A::NotImplemented
        | A::Unknown => t.text_muted,
    }
}

/// The coverage view: every rule in a scrolling table grouped by area, and
/// the selected rule's detail in a panel below it.
fn draw_coverage(
    f: &mut Frame,
    t: &Theme,
    rules: &[crate::diagnose::coverage::RuleCoverage],
    selected: usize,
    details: &[(&'static str, String)],
    area: Rect,
) {
    use crate::diagnose::coverage::Availability;
    use ratatui::widgets::{Cell, Row, Table, TableState};

    // Detail panel sized to its content (label rows + borders),
    // never more than half the body so the table stays the main thing.
    let detail_h = (details.len() as u16 + 2).min(area.height / 2).max(4);
    let [table_area, detail_area] =
        Layout::vertical([Constraint::Min(6), Constraint::Length(detail_h)]).areas(area);

    let ready = rules
        .iter()
        .filter(|r| r.status == Availability::Available)
        .count();
    // Titles only when there is room for them; the detail panel always names
    // the selected rule's title, so narrow terminals lose nothing essential.
    let wide = area.width >= 130;
    let mut header = vec!["Area", "Check", "Title", "Status", "Why"];
    if !wide {
        header.remove(2);
    }
    let header = Row::new(header).style(Style::default().fg(t.key_hint).bold());
    let mut previous_area = "";
    let body: Vec<Row> = rules
        .iter()
        .map(|row| {
            let (group, _) = row.rule.split_once('.').unwrap_or((row.rule.as_str(), ""));
            // Name each area once, on its first row, so groups read as groups.
            let group_cell = if group == previous_area {
                String::new()
            } else {
                group.to_string()
            };
            previous_area = group;
            let title = rules::lookup(&row.rule).map(|r| r.title).unwrap_or("");
            let color = availability_color(t, &row.status);
            let dot = if row.status == Availability::Available {
                "●"
            } else {
                "○"
            };
            let mut cells = vec![
                Cell::from(group_cell).style(Style::default().fg(t.text_secondary).bold()),
                Cell::from(row.rule.clone()).style(Style::default().fg(t.text_primary)),
                Cell::from(format!("{dot} {}", row.status.label()))
                    .style(Style::default().fg(color)),
                Cell::from(row.reason.clone()).style(Style::default().fg(t.text_muted)),
            ];
            if wide {
                cells.insert(
                    2,
                    Cell::from(title).style(Style::default().fg(t.text_secondary)),
                );
            }
            Row::new(cells)
        })
        .collect();

    let position = if rules.is_empty() {
        " no rules ".to_string()
    } else {
        format!(" {}/{} ", selected + 1, rules.len())
    };
    let mut widths = vec![
        Constraint::Length(9),  // area
        Constraint::Length(25), // check: "tcp.timewait_exhaustion" + gap
        Constraint::Length(20), // status: "○ permission denied"
        Constraint::Min(20),    // why
    ];
    if wide {
        // "target refuses or drops connections"
        widths.insert(2, Constraint::Length(36));
    }
    let table = Table::new(body, widths)
        .header(header)
        .row_highlight_style(Style::default().bg(t.selection_bg))
        .highlight_symbol("› ")
        .highlight_spacing(ratatui::widgets::HighlightSpacing::Always)
        .block(
            widgets::panel_block(t)
                .title_top(Line::from(vec![
                    Span::styled(
                        " diagnose coverage ",
                        Style::default().fg(t.text_primary).bold(),
                    ),
                    Span::styled(
                        format!("{ready}/{} ready ", rules.len()),
                        Style::default().fg(t.status_good),
                    ),
                ]))
                .title_top(
                    Line::from(Span::styled(position, Style::default().fg(t.text_muted)))
                        .right_aligned(),
                ),
        );
    let mut state = TableState::default().with_selected((!rules.is_empty()).then_some(selected));
    f.render_stateful_widget(table, table_area, &mut state);

    let Some(row) = rules.get(selected) else {
        f.render_widget(widgets::panel_block(t), detail_area);
        return;
    };
    let label_w = details.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
    let lines: Vec<Line> = details
        .iter()
        .map(|(label, value)| {
            Line::from(vec![
                Span::styled(
                    format!(" {label:>label_w$}  "),
                    Style::default().fg(t.key_hint),
                ),
                Span::styled(value.clone(), Style::default().fg(t.text_primary)),
            ])
        })
        .collect();
    let title = rules::lookup(&row.rule).map(|r| r.title).unwrap_or("");
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(widgets::panel_block(t).title_top(Line::from(vec![
                Span::styled(
                    format!(" {} ", row.rule),
                    Style::default().fg(t.text_primary).bold(),
                ),
                Span::styled(format!("{title} "), Style::default().fg(t.text_secondary)),
                Span::styled(
                    format!("· {} ", row.status.label()),
                    Style::default().fg(availability_color(t, &row.status)),
                ),
            ]))),
        detail_area,
    );
}

fn chunk_header(area: Rect) -> Rect {
    Rect {
        height: 3.min(area.height),
        ..area
    }
}

fn chunk_body(area: Rect) -> Rect {
    let top = 3.min(area.height);
    let bottom = 3.min(area.height.saturating_sub(top));
    Rect {
        y: area.y + top,
        height: area.height.saturating_sub(top + bottom),
        ..area
    }
}

fn chunk_footer(area: Rect) -> Rect {
    let h = 3.min(area.height);
    Rect {
        y: area.y + area.height - h,
        height: h,
        ..area
    }
}

/// Index of the first step the user carries out by hand, which `d` marks done.
pub fn first_manual_step(issue: &crate::diagnose::Issue) -> Option<usize> {
    issue
        .remediation
        .iter()
        .position(|s| s.kind == StepKind::Instruct)
}

fn selected_issue(app: &crate::app::App) -> Option<String> {
    let primary = app.diagnose.engine.primary();
    primary
        .get(app.diagnose.selected.min(primary.len().saturating_sub(1)))
        .map(|i| i.id.clone())
}

pub fn footer_hints(view: &View) -> Vec<crate::ui::widgets::Hint> {
    use crate::ui::widgets::hint;
    // Issue keys only when there is an issue to point them at.
    let open = !view.engine.primary().is_empty();
    let mut hints = Vec::new();
    if open {
        hints.push(hint("↑↓", "issue"));
    }
    if view
        .current()
        .map(|i| has_applicable_step(i, view.capability, view.is_demo()))
        .unwrap_or(false)
    {
        hints.push(hint("↵", "apply fix"));
    }
    if let Some(issue) = view.current() {
        if view.running_tests.is_empty()
            && crate::diagnose::next_test::suggest(
                issue,
                view.capability,
                view.third_party_probes,
                &issue.last_seen,
            )
            .is_some()
        {
            hints.push(hint("t", "run test"));
        }
        if first_manual_step(issue).is_some() && issue.verification.is_none() {
            hints.push(hint("d", "done it"));
        }
    }
    hints.push(hint("c", "coverage"));
    if open {
        hints.push(hint("a", "ack"));
        hints.push(hint("m", "mute"));
    }
    // The same words the report panel puts on this key. Two labels for one
    // key is the defect the footer's deduplication exists to prevent; it
    // catches a key bound twice, not a key named twice.
    hints.push(hint(
        "o",
        if view.show_report {
            "back to issues"
        } else {
            "report"
        },
    ));
    hints.push(hint("e", "export report"));
    hints.push(hint("y", "copy summary"));
    hints
}

/// Whether `↵` would do anything on this issue.
///
/// Only in the demo, which simulates the step: live, `↵` writes nothing and
/// says so, so offering it was a key hint for a key that does nothing. The
/// full apply handoff is C19b.
///
/// A step netwatch has already run is not applicable — the screen shows
/// `applied 06:51:56 · 169.254.1.1 → 192.168.8.1` right next to a footer still
/// offering to apply it, which is the same defect. A step that was applied
/// and then reverted is applicable again.
fn has_applicable_step(issue: &Issue, cap: Capability, demo: bool) -> bool {
    demo && issue.remediation.iter().any(|s| {
        s.kind == StepKind::Apply
            && s.available(cap)
            && !matches!(
                s.applied,
                Some(Applied::Yes { .. })
                    | Some(Applied::No { .. })
                    | Some(Applied::RecoveryRequired { .. })
            )
    })
}

/// Draw everything between the header and the footer.
pub fn render_body(f: &mut Frame, view: &View, area: Rect) {
    let status_rows = if view.status.is_some() { 1 } else { 0 };
    // The engine strip only earns its rows in demo mode, where it carries the
    // banner. Otherwise baselines and coverage are one clause of the verdict
    // line, not a second copy of it in a box.
    let strip_rows = if view.demo_banner.is_some() { 3 } else { 0 };

    // The verdict comes off the top first: `Min(6)` below would otherwise take
    // its rows on a short terminal, and the second of them can hold a warning.
    let (verdict, area) = crate::ui::widgets::take_top(area, 2);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(strip_rows),  // demo banner
            Constraint::Min(6),              // issues + detail, or the report
            Constraint::Length(status_rows), // transient status
        ])
        .split(area);

    render_verdict(f, view, verdict);
    if strip_rows > 0 {
        render_engine_strip(f, view, chunks[0]);
    }
    // `o` swaps the working view for the whole report. With nothing open the
    // page says so once and gets out of the way — no catalogue, no preview,
    // no empty issue and detail boxes.
    if view.show_report {
        render_report_preview(f, view, chunks[1]);
    } else if view.engine.primary().is_empty() {
        render_nothing_open(f, view, chunks[1]);
    } else {
        render_main(f, view, chunks[1]);
    }
    if let Some(s) = view.status {
        render_status(f, view, s, chunks[2]);
    }
}

// ─────────────────────────────────────────────────── verdict

fn severity_color(sev: Severity, t: &Theme) -> Color {
    match sev {
        Severity::Critical | Severity::High => t.status_error,
        Severity::Medium => t.status_warn,
        Severity::Info => t.status_info,
    }
}

fn render_verdict(f: &mut Frame, view: &View, area: Rect) {
    let spans = verdict_spans(view.engine, view.baselines, view.theme);
    let mut lines = vec![Line::from(spans)];
    lines.extend(cleartext_insights_line(view));
    f.render_widget(Paragraph::new(lines), inset(area));
}

/// The verdict row: a glyph, then the words, then how many issues it leaves
/// out because they are muted.
fn verdict_spans(engine: &Engine, baselines: &BaselineStore, t: &Theme) -> Vec<Span<'static>> {
    let mut spans = verdict_state_spans(engine, baselines, t);
    // A muted issue leaves the count but not the screen: without this the row
    // reads "no issues found" over a fault that is still there.
    let muted = engine.muted_count();
    if muted > 0 {
        spans.push(Span::styled(
            format!(" · {muted} muted"),
            Style::default().fg(t.text_muted),
        ));
    }
    spans
}

fn verdict_state_spans(
    engine: &Engine,
    baselines: &BaselineStore,
    t: &Theme,
) -> Vec<Span<'static>> {
    let verdict = engine.verdict(baselines);

    let coverage = engine.coverage();
    // "rules", not "checks": a check is one line of evidence inside a cause,
    // and the coverage object counts catalogue rules. Two different numbers
    // under one word made the generated coverage document read as though it
    // described something else.
    let watching = format!(
        "watching {} of {} rules",
        coverage
            .rules
            .iter()
            .filter(|r| r.status == crate::diagnose::coverage::Availability::Available)
            .count(),
        coverage.rules.len()
    );
    match &verdict {
        // "Nothing found", never "healthy": the clause after it says how much
        // of the ruleset that is based on. The engine never returns Clear
        // until green is earned (C14); this arm is what it will draw then.
        Verdict::Clear => vec![
            Span::styled("● ", Style::default().fg(t.status_good)),
            Span::styled("no issues found", Style::default().fg(t.text_primary)),
            Span::styled(format!(" · {watching}"), Style::default().fg(t.text_muted)),
        ],
        // Ready baselines and an empty list are not health: the engine
        // returns this, never Clear, until C14 says which rules must have
        // had input. Muted, like Learning, because the module's rule is that
        // nothing is green unless it is healthy.
        Verdict::Incomplete { .. } => vec![
            Span::styled("◌ ", Style::default().fg(t.text_muted)),
            Span::styled(
                format!("no issues found · {watching}"),
                Style::default().fg(t.text_muted),
            ),
        ],
        // A host that hasn't learned its network yet says so, rather than
        // rendering the reassuring green it hasn't earned.
        Verdict::Learning { .. } => {
            let readiness = baselines.overall_readiness();
            let learning = if baselines.switched_network() {
                format!(
                    "new network {} · baselines {}",
                    baselines.fingerprint().label(),
                    readiness.label()
                )
            } else {
                format!("baselines {}", readiness.label())
            };
            vec![
                Span::styled("◌ ", Style::default().fg(t.text_muted)),
                Span::styled("no issues found yet", Style::default().fg(t.text_primary)),
                Span::styled(
                    format!(" · {learning} · {watching}"),
                    Style::default().fg(t.text_muted),
                ),
            ]
        }
        Verdict::Issues {
            severity,
            count,
            headline,
            ..
        } => {
            let c = severity_color(*severity, t);
            vec![
                Span::styled("▌ ", Style::default().fg(c).bold()),
                Span::styled(
                    format!(
                        "{} ",
                        if *count == 1 {
                            "1 issue".into()
                        } else {
                            format!("{count} issues")
                        }
                    ),
                    Style::default().fg(c).bold(),
                ),
                Span::styled("· ", Style::default().fg(t.separator)),
                Span::styled(headline.clone(), Style::default().fg(t.text_primary)),
            ]
        }
    }
}

/// The verdict row's words, without its glyph: what `y` copies, so a pasted
/// summary says what the screen says. It used to copy `Verdict::line()`,
/// which words the same state differently ("no visible issues").
pub fn verdict_words(engine: &Engine, baselines: &BaselineStore, t: &Theme) -> String {
    verdict_spans(engine, baselines, t)
        .iter()
        .skip(1)
        .map(|s| s.content.as_ref())
        .collect::<String>()
        .trim_end()
        .to_string()
}

fn inset(area: Rect) -> Rect {
    Rect {
        x: area.x + 1,
        width: area.width.saturating_sub(2),
        ..area
    }
}

// ────────────────────────────────────────────── engine strip

/// What the engine is running on. This replaces the mockup's pipeline strip
/// with something netwatch can actually stand behind: which detectors have
/// inputs, how far along the baselines are, and how much of the ruleset is
/// live. A user who sees no issues deserves to know whether that means
/// "healthy" or "not looking yet".
fn render_engine_strip(f: &mut Frame, view: &View, area: Rect) {
    let t = view.theme;
    let readiness = view.baselines.overall_readiness();

    // In demo mode the strip leads with what the data is, before anything
    // about what it says. Inverted, not merely coloured, so it survives a
    // palette-deferring theme and a screenshot at any size.
    if let Some(banner) = &view.demo_banner {
        let block = widgets::panel_block(t).border_style(Style::default().fg(t.status_warn));
        let line = Line::from(Span::styled(
            format!(" {banner} "),
            Style::default().fg(t.text_inverse).bg(t.status_warn).bold(),
        ));
        f.render_widget(Paragraph::new(line).block(block), area);
        return;
    }

    let mut spans = vec![
        Span::styled("baselines ", Style::default().fg(t.text_muted)),
        Span::styled(
            readiness.label(),
            Style::default().fg(if readiness.is_ready() {
                t.status_good
            } else {
                t.text_secondary
            }),
        ),
        Span::styled("  network ", Style::default().fg(t.text_muted)),
        Span::styled(
            view.baselines.fingerprint().label(),
            Style::default().fg(t.text_secondary),
        ),
    ];
    if view.baselines.switched_network() {
        spans.push(Span::styled(
            "  (changed — relearning)",
            Style::default().fg(t.status_warn),
        ));
    }
    spans.push(Span::styled(
        "  ruleset ",
        Style::default().fg(t.text_muted),
    ));
    spans.push(Span::styled(
        view.engine.coverage().label(),
        Style::default().fg(t.text_secondary),
    ));

    let block = widgets::panel_block(t).title(Span::styled(
        " engine ",
        Style::default().fg(t.text_secondary),
    ));
    f.render_widget(Paragraph::new(Line::from(spans)).block(block), area);
}

// ──────────────────────────────────────────── issues + detail

fn render_main(f: &mut Frame, view: &View, area: Rect) {
    // Panels size to content in both directions. The list takes the width its
    // widest row actually needs (capped at 40% so the detail pane always has
    // room) and the height its rows need; whatever is left goes to something
    // useful rather than to an empty box. A list panel that is 90% blank is
    // the most common way a TUI wastes a screen.
    let issues = view.engine.primary();
    // The 40% cap can fall below the 28-column floor on a narrow terminal, so
    // the cap wins and `clamp` is not used — `clamp(28, 24)` panics.
    let cap = ((area.width as usize * 2) / 5).max(1);
    let widest = issues
        .iter()
        .map(issue_row_width)
        .max()
        .unwrap_or(28)
        .max(28)
        .min(cap) as u16;

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(widest + 4), Constraint::Min(30)])
        .split(area);

    // Both panels are sized to their own content, and whatever is left over
    // stays empty rather than being padded into one of them. A list panel
    // stretched to fill a column is the layout bug the v0.29 review found on
    // four tabs at once.
    // The chronology only adds something when there is an order to show:
    // more than one tracked issue, or a consequence or closure the list omits.
    let chrono_rows = if view.engine.issues().len() > 1 {
        chronology_height(view)
    } else {
        0
    };
    let list_needed = (issues.len().max(1) * ROWS_PER_ISSUE) as u16 + 2;
    let list_height = list_needed.min(area.height.saturating_sub(chrono_rows.min(area.height)));

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(list_height),
            Constraint::Length(chrono_rows),
            Constraint::Min(0),
        ])
        .split(columns[0]);

    render_issue_list(f, view, &issues, left[0]);
    if left[1].height >= MIN_CHRONOLOGY_ROWS {
        render_chronology(f, view, left[1]);
    }
    // The detail takes the column's full height: it is what this tab is for.
    render_detail(f, view, columns[1]);
}

/// The page when nothing is open: one short panel saying so, plus the two
/// things worth a look even on a quiet network — a collector that has broken,
/// and issues that opened and closed while you were away. Neither appears
/// unless it has something in it.
fn render_nothing_open(f: &mut Frame, view: &View, area: Rect) {
    use crate::diagnose::coverage::Availability;
    let t = view.theme;
    let coverage = view.engine.coverage();

    let waiting = coverage
        .rules
        .iter()
        .filter(|r| r.status != Availability::Available)
        .count();
    let mut quiet = vec![Line::from(Span::styled(
        " Nothing to report. Diagnose re-checks continuously and raises an issue here when something breaks.",
        Style::default().fg(t.text_secondary),
    ))];
    if waiting > 0 {
        quiet.push(Line::from(vec![
            Span::styled(
                format!(
                    " {waiting} {} waiting on a test, configuration or more data — ",
                    if waiting == 1 {
                        "check is"
                    } else {
                        "checks are"
                    }
                ),
                Style::default().fg(t.text_muted),
            ),
            Span::styled("c", Style::default().fg(t.key_hint).bold()),
            Span::styled(" shows which.", Style::default().fg(t.text_muted)),
        ]));
    }

    let broken: Vec<_> = coverage
        .rules
        .iter()
        .filter(|r| {
            matches!(
                r.status,
                Availability::CollectorFailed | Availability::PermissionDenied
            )
        })
        .collect();
    let history = view.engine.issues().len();

    let mut constraints = vec![Constraint::Length(quiet.len() as u16 + 2)];
    if !broken.is_empty() {
        constraints.push(Constraint::Length(broken.len() as u16 + 2));
    }
    if history > 0 {
        constraints.push(Constraint::Length(chronology_height(view)));
    }
    constraints.push(Constraint::Min(0));
    let rows = Layout::vertical(constraints).split(area);

    f.render_widget(
        Paragraph::new(quiet)
            .wrap(Wrap { trim: false })
            .block(widgets::Panel::new("diagnose").block(t)),
        rows[0],
    );
    let mut next = 1;
    if !broken.is_empty() {
        let width = broken.iter().map(|r| r.rule.len()).max().unwrap_or(0);
        let lines: Vec<Line> = broken
            .iter()
            .map(|r| {
                Line::from(vec![
                    Span::styled(
                        format!(" {:<width$}  ", r.rule),
                        Style::default().fg(t.text_primary),
                    ),
                    Span::styled(
                        format!("{:<18}", r.status.label()),
                        Style::default().fg(t.status_error),
                    ),
                    Span::styled(r.reason.clone(), Style::default().fg(t.text_muted)),
                ])
            })
            .collect();
        f.render_widget(
            Paragraph::new(lines).block(
                widgets::Panel::new("needs attention")
                    .meta("these checks cannot run")
                    .block(t),
            ),
            rows[next],
        );
        next += 1;
    }
    if history > 0 && rows[next].height >= MIN_CHRONOLOGY_ROWS {
        render_chronology(f, view, rows[next]);
    }
}

const ROWS_PER_ISSUE: usize = 3;
/// Two borders and a row: below this the chronology has nowhere to draw.
const MIN_CHRONOLOGY_ROWS: u16 = 3;

/// Width the widest row of an issue actually needs, so the column is sized to
/// its content instead of to a guess.
/// After the title of an issue a beta rule opened.
const BETA_TAG: &str = " beta";

fn issue_row_width(i: &&Issue) -> usize {
    // +1 throughout for the selection rail in column zero.
    let title = i.title.len() + 7 + if i.beta { BETA_TAG.len() } else { 0 };
    let mut value = i.subject.label().len() + 6;
    if let Some(e) = i.headline() {
        value += e.value_label().len() + 3;
        if let Some(m) = e.multiple_label() {
            value += m.len() + 3;
        }
    }
    let short = crate::diagnose::issue::short_time;
    let mut when = short(&i.since).len() + 12;
    if let Some(stale) = &i.stale_since {
        when += short(stale).len() + 15;
    }
    title.max(value).max(when)
}

/// Every tracked issue in the window, oldest first.
///
/// The issue list answers "what is wrong"; this answers "in what order did it
/// happen", which is the question the whole screen exists to settle. The
/// reroute at 06:44 preceded the resolver slowdown at 06:48 — that ordering is
/// the correlation a reader has to see to believe the ranking, and reading it
/// off three separate `since` lines is work the screen should have done.
///
/// It also includes issues that are no longer open: suppressed consequences,
/// and anything the engine has closed. The close is the payoff of a
/// remediation, and an incident log that drops it stops one beat early.
fn render_chronology(f: &mut Frame, view: &View, area: Rect) {
    let t = view.theme;

    let mut tracked: Vec<&Issue> = view.engine.issues().iter().collect();
    tracked.sort_by(|a, b| a.since.cmp(&b.since));

    let selected_id = view.current().map(|i| i.id.clone());
    let inner = area.width.saturating_sub(2) as usize;

    let mut lines: Vec<Line> = Vec::new();
    for issue in tracked {
        let is_selected = selected_id.as_deref() == Some(issue.id.as_str());
        let open = issue.state.is_open();
        let muted_until = issue.state.muted_until();

        // A closed issue keeps its place in the order but stops shouting: the
        // severity colour is what "still wrong" looks like. A muted one is
        // neither: still wrong, only quiet, and never the ✓ of a fix.
        let (marker, marker_style) = if muted_until.is_some() {
            ("◌", Style::default().fg(t.text_muted))
        } else if !open {
            ("✓", Style::default().fg(t.status_good))
        } else if issue.suppressed_by.is_some() {
            ("└", Style::default().fg(t.text_muted))
        } else {
            ("▪", Style::default().fg(severity_color(issue.severity, t)))
        };

        let title_style = if !open {
            Style::default().fg(t.text_muted)
        } else if is_selected {
            Style::default().fg(t.text_primary).bold()
        } else {
            Style::default().fg(t.text_secondary)
        };

        // `since` is a full `%Y-%m-%d %H:%M:%S`; the date is the same for
        // every row in a window and the seconds are in the detail pane, so
        // the column carries `06:48` and spends the rest on the title.
        let stamp = crate::diagnose::issue::hh_mm(&issue.since);
        let used = 1 + stamp.chars().count() + 2 + 2;
        let mut spans = vec![
            Span::styled(
                if is_selected { "▌" } else { " " }.to_string(),
                Style::default().fg(if is_selected {
                    severity_color(issue.severity, t)
                } else {
                    t.bg
                }),
            ),
            Span::styled(format!("{stamp}  "), Style::default().fg(t.text_muted)),
            Span::styled(format!("{marker} "), marker_style),
            Span::styled(
                ellipsise(&issue.title, inner.saturating_sub(used)),
                title_style,
            ),
        ];
        if let Some(until) = muted_until {
            let muted = format!("  muted until {}", crate::diagnose::issue::hh_mm(until));
            if used + issue.title.chars().count() + muted.chars().count() <= inner {
                spans.push(Span::styled(muted, Style::default().fg(t.text_muted)));
            }
        } else if !open {
            let closed = format!("  {}", issue.state.label());
            if used + issue.title.chars().count() + closed.chars().count() <= inner {
                spans.push(Span::styled(closed, Style::default().fg(t.status_good)));
            }
        }
        lines.push(Line::from(spans));
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            " nothing tracked yet",
            Style::default().fg(t.text_muted),
        )));
    }

    let block = widgets::Panel::new("chronology")
        .meta(format!("{} tracked", view.engine.issues().len()))
        .fit(area.width)
        .block(t);
    f.render_widget(Paragraph::new(lines).block(block), area);
}

/// Rows the chronology needs: one per tracked issue, plus borders.
fn chronology_height(view: &View) -> u16 {
    view.engine.issues().len().max(1) as u16 + 2
}

fn render_issue_list(f: &mut Frame, view: &View, issues: &[&Issue], area: Rect) {
    let t = view.theme;
    let mut lines: Vec<Line> = Vec::new();

    if issues.is_empty() {
        lines.push(Line::from(Span::styled(
            "nothing open",
            Style::default().fg(t.text_muted),
        )));
    }

    for (n, issue) in issues.iter().enumerate() {
        let selected = n == view.selected.min(issues.len().saturating_sub(1));
        let sev_color = severity_color(issue.severity, t);
        // Selection is a rail down the left edge and bolder text, not a
        // background fill. `selection_bg` is ANSI 8 in the palette-deferring
        // theme, and what a terminal renders for ANSI 8 is anyone's guess —
        // several map it to a mid blue that swallows the severity colours
        // sitting on top of it, leaving the selected row the one row nobody
        // can read. A rail costs one column and works in every palette.
        let rail = |c: Color| {
            Span::styled(
                if selected { "▌" } else { " " }.to_string(),
                Style::default().fg(c),
            )
        };
        let title_style = if selected {
            Style::default().fg(t.text_primary).bold()
        } else {
            Style::default().fg(t.text_primary)
        };

        let mut head = vec![
            rail(sev_color),
            Span::styled(
                format!("{:<4} ", issue.severity.label()),
                Style::default().fg(sev_color).bold(),
            ),
            Span::styled(issue.title.clone(), title_style),
        ];
        if issue.beta {
            head.push(Span::styled(BETA_TAG, Style::default().fg(t.text_muted)));
        }
        if issue.recurrence > 0 {
            head.push(Span::styled(
                format!(" ×{}", issue.recurrence + 1),
                Style::default().fg(t.status_warn),
            ));
        }
        if !matches!(issue.state, IssueState::Open) {
            head.push(Span::styled(
                format!(" [{}]", issue.state.label()),
                Style::default().fg(t.text_muted),
            ));
        }
        lines.push(Line::from(head));

        // Second row: the subject and the headline number, both from evidence.
        let mut detail = vec![
            rail(sev_color),
            Span::styled(
                format!("     {}", issue.subject.label()),
                Style::default().fg(t.text_secondary),
            ),
        ];
        if let Some(e) = issue.headline() {
            detail.push(Span::styled(
                format!(" · {}", e.value_label()),
                Style::default().fg(t.text_primary),
            ));
            if let Some(m) = e.multiple_label() {
                detail.push(Span::styled(
                    format!(" · {m}"),
                    Style::default().fg(sev_color),
                ));
            }
        }
        lines.push(Line::from(detail));

        let mut when = vec![
            rail(sev_color),
            Span::styled(
                format!(
                    "     since {}",
                    crate::diagnose::issue::short_time(&issue.since)
                ),
                Style::default().fg(t.text_muted),
            ),
        ];
        // Why an issue whose evidence stopped arriving is still listed: it
        // can neither close nor expire until something measures it again.
        if let Some(stale) = &issue.stale_since {
            when.push(Span::styled(
                format!(
                    " · stale since {}",
                    crate::diagnose::issue::short_time(stale)
                ),
                Style::default().fg(t.status_warn),
            ));
        }
        lines.push(Line::from(when));
    }

    let block = widgets::Panel::new("issues")
        .meta_styled(vec![Span::raw(match issues.len() {
            0 => "nothing open".to_string(),
            1 => "1 open".to_string(),
            n => format!("{n} open"),
        })])
        .fit(area.width)
        .block(t);
    f.render_widget(Paragraph::new(lines).block(block), area);
}

/// Draw the detail pane and return the rows it used.
///
/// The caller needs the height back: the pane is content-sized, and the space
/// it does not need goes to the report preview rather than staying blank.
/// The sparkline row and its caption.
///
/// Scaled to the series' own peak, so the shape is visible whatever the
/// units; the caption carries the numbers, because a sparkline without one
/// is a decoration.
fn history_rows<'a>(
    h: &MetricHistory,
    issue: &crate::diagnose::issue::Issue,
    t: &Theme,
    width: u16,
) -> Vec<Line<'a>> {
    let cells = (width as usize).saturating_sub(4).clamp(8, 120);
    let scale = 1000.0_f64;
    let ints: Vec<u64> = h
        .samples
        .iter()
        .map(|v| (v.max(0.0) * scale) as u64)
        .collect();
    let peak = ints.iter().copied().max().unwrap_or(0);
    let glyphs = crate::graph::bar_row(&ints, cells, peak);
    if glyphs.is_empty() {
        return vec![];
    }
    // Colour per sample rather than per line: the point is which samples
    // crossed, not that any did.
    let shown = h.samples.len().saturating_sub(glyphs.len());
    let severity = severity_color(issue.severity, t);
    let mut spans = vec![Span::raw("  ")];
    for (i, g) in glyphs.iter().enumerate() {
        let above = h
            .threshold
            .is_some_and(|limit| h.samples[shown + i] > limit);
        spans.push(Span::styled(
            g.to_string(),
            Style::default().fg(if above { severity } else { t.text_muted }),
        ));
    }
    let mut caption = format!("  {}", h.metric);
    if let Some(limit) = h.threshold {
        caption.push_str(&format!(
            " · threshold {}{}",
            round_for_caption(limit),
            h.unit
        ));
    }
    caption.push_str(&format!(" · {} · now", plural(h.samples.len(), "sample")));
    vec![
        Line::from(spans),
        Line::from(Span::styled(caption, Style::default().fg(t.text_muted))),
    ]
}

/// Captions carry one decimal at most: the axis is a reminder of scale, not a
/// reading.
fn round_for_caption(v: f64) -> String {
    if v >= 10.0 {
        format!("{v:.0}")
    } else {
        format!("{v:.1}")
    }
}

fn render_detail(f: &mut Frame, view: &View, area: Rect) {
    let t = view.theme;
    let Some(issue) = view.current() else {
        // The empty state keeps the same frame as a populated one, so the
        // page does not change shape when the last issue closes.
        let block = widgets::Panel::new("detail").block(t);
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "No open issues.",
                Style::default().fg(t.text_muted),
            )))
            .wrap(Wrap { trim: true })
            .block(block),
            area,
        );
        return;
    };

    let mut lines: Vec<Line> = Vec::new();

    // ── issue ────────────────────────────────────────────────
    lines.push(section(t, "issue"));
    lines.push(Line::from(Span::styled(
        issue.subject.label(),
        Style::default().fg(t.text_primary).bold(),
    )));
    if issue.beta {
        lines.push(Line::from(Span::styled(
            "beta rule: contract not yet reviewed; not counted in `diagnose run`'s exit status",
            Style::default().fg(t.text_muted),
        )));
    }
    // One row per metric, aligned, instead of every figure on one line.
    let metric_w = issue
        .evidence
        .iter()
        .map(|e| e.metric.chars().count())
        .max()
        .unwrap_or(0);
    let value_w = issue
        .evidence
        .iter()
        .map(|e| e.value_label().chars().count())
        .max()
        .unwrap_or(0);
    for e in &issue.evidence {
        let mut row = vec![
            Span::styled(
                format!("  {:<metric_w$}  ", e.metric),
                Style::default().fg(t.text_secondary),
            ),
            Span::styled(
                format!("{:<value_w$}", e.value_label()),
                Style::default().fg(t.text_primary),
            ),
        ];
        if let Some(b) = e.baseline_label() {
            row.push(Span::styled(
                format!("  {b}"),
                Style::default().fg(t.text_muted),
            ));
            if let Some(m) = e.multiple_label() {
                row.push(Span::styled(
                    format!(" · {m}"),
                    Style::default().fg(severity_color(issue.severity, t)),
                ));
            }
        }
        lines.push(Line::from(row));
    }

    if let Some(e) = issue.headline() {
        if e.samples > 0 {
            lines.push(Line::from(Span::styled(
                format!(
                    "  {} over {} · since {} · {}",
                    plural(e.samples as usize, "sample"),
                    crate::diagnose::issue::format_duration(e.window_secs),
                    crate::diagnose::issue::short_time(&issue.since),
                    issue.state.label()
                ),
                Style::default().fg(t.text_muted),
            )));
        }
    }
    // The shape behind the number: one row of the recent samples, coloured
    // where they sit above the rule's threshold.
    if let Some(h) = view.history.as_ref().filter(|h| h.samples.len() >= 4) {
        lines.extend(history_rows(h, issue, t, area.width));
    }

    let scope = issue.scope.label();
    if !scope.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("  scope  {scope}"),
            Style::default().fg(t.text_secondary),
        )));
    }
    lines.push(Line::from(""));

    // ── probable cause ───────────────────────────────────────
    if !issue.causes.is_empty() {
        lines.push(section(t, "probable cause"));
        for (n, cause) in issue.causes.iter().enumerate() {
            let strong = n == 0;
            lines.push(Line::from(vec![
                Span::styled(format!("{}. ", n + 1), Style::default().fg(t.text_muted)),
                Span::styled(
                    cause.label.clone(),
                    if strong {
                        Style::default().fg(t.text_primary).bold()
                    } else {
                        Style::default().fg(t.text_secondary)
                    },
                ),
                // A word, never a percentage — the underlying score is a
                // check-pass fraction, not a calibrated probability.
                Span::styled(
                    format!(
                        "  {} · {}{}",
                        cause.confidence().label(),
                        cause.checks_label(),
                        match cause.missing_discriminator() {
                            // Name the measurement that would settle it, so
                            // "likely" reads as a gap rather than a mood.
                            Some(k) => format!(" · needs {}", k.name),
                            None => String::new(),
                        }
                    ),
                    Style::default().fg(t.text_muted),
                ),
            ]));
            if strong {
                lines.extend(cause.checks.iter().map(|c| check_line(t, c)));
            }
        }
        lines.push(Line::from(""));
    }

    // ── next test ────────────────────────────────────────────
    let runs = crate::diagnose::next_test::latest_runs(issue, &issue.last_seen);
    let suggestion = crate::diagnose::next_test::suggest(
        issue,
        view.capability,
        view.third_party_probes,
        &issue.last_seen,
    );
    if !view.running_tests.is_empty() || suggestion.is_some() || !runs.is_empty() {
        lines.push(section(t, "tests"));
        for run in &runs {
            let spec = crate::diagnose::next_test::lookup(&run.test);
            lines.push(Line::from(vec![
                Span::styled("  ✓ ", Style::default().fg(t.text_muted)),
                Span::styled(
                    spec.map_or(run.test.as_str(), |s| s.question).to_string(),
                    Style::default().fg(t.text_secondary),
                ),
                Span::styled(
                    format!(
                        " — {} · {}",
                        match run.outcome {
                            crate::diagnose::next_test::Outcome::Positive => "yes",
                            crate::diagnose::next_test::Outcome::Negative => "no",
                            crate::diagnose::next_test::Outcome::Inconclusive => "can't tell",
                        },
                        run.detail
                    ),
                    Style::default().fg(t.text_muted),
                ),
            ]));
        }
        for running in &view.running_tests {
            let spec = crate::diagnose::next_test::lookup(running);
            lines.push(Line::from(Span::styled(
                format!("  … {}", spec.map_or(running.as_str(), |s| s.question)),
                Style::default().fg(t.status_warn),
            )));
        }
        if let (true, Some(s)) = (view.running_tests.is_empty(), &suggestion) {
            lines.push(Line::from(vec![
                Span::styled("t ", Style::default().fg(t.key_hint).bold()),
                Span::styled(
                    format!("check whether {}", s.test.question),
                    Style::default().fg(t.text_primary),
                ),
            ]));
            lines.push(Line::from(Span::styled(
                format!("  {} · about {}s", s.test.does, s.test.cost.secs),
                Style::default().fg(t.text_muted),
            )));
        }
        lines.push(Line::from(""));
    }

    // ── remediation ──────────────────────────────────────────
    let steps: Vec<&Step> = issue.offered_steps(view.capability);
    if !steps.is_empty() {
        lines.push(section(t, "recommended remediation"));
        for step in &steps {
            let mut row = Vec::new();
            match (step.kind, step.key) {
                // A key hint only where the step can run: live, the step
                // carries the command to type instead.
                (StepKind::Apply, Some(k)) if view.is_demo() => row.push(Span::styled(
                    format!("{k} "),
                    Style::default().fg(t.key_hint).bold(),
                )),
                (StepKind::Escalate, _) => {
                    row.push(Span::styled("→ ", Style::default().fg(t.text_muted)))
                }
                _ => row.push(Span::styled("· ", Style::default().fg(t.text_muted))),
            }
            row.push(Span::styled(
                step.text.clone(),
                Style::default().fg(t.text_primary),
            ));
            lines.push(Line::from(row));
            lines.push(Line::from(Span::styled(
                format!("  {}", step.detail),
                Style::default().fg(t.text_muted),
            )));
            match &step.applied {
                Some(Applied::Yes { at, before, after }) => lines.push(Line::from(Span::styled(
                    format!(
                        "  applied {} · {before} → {after}",
                        crate::diagnose::issue::short_time(at)
                    ),
                    Style::default().fg(t.status_good),
                ))),
                Some(Applied::Reverted { at, reason }) => lines.push(Line::from(Span::styled(
                    format!(
                        "  reverted {} · {reason}",
                        crate::diagnose::issue::short_time(at)
                    ),
                    Style::default().fg(t.status_warn),
                ))),
                Some(outcome @ Applied::RecoveryRequired { .. }) => {
                    lines.push(Line::from(Span::styled(
                        format!("  {}", outcome.recovery_summary().unwrap()),
                        Style::default().fg(t.status_warn),
                    )))
                }
                Some(Applied::No { reason }) => lines.push(Line::from(Span::styled(
                    format!("  not applied · {reason}"),
                    Style::default().fg(t.text_muted),
                ))),
                None => {}
            }
        }
        // Steps netwatch is holding back, and why. Hidden, not greyed — but
        // never silently dropped.
        let withheld = issue.remediation.len() - steps.len();
        if withheld > 0 {
            lines.push(Line::from(Span::styled(
                format!(
                    "  {withheld} step{} hidden: netwatch is running with {}",
                    if withheld == 1 { "" } else { "s" },
                    view.capability.label()
                ),
                Style::default().fg(t.text_muted),
            )));
        }
        lines.push(Line::from(""));
    }

    // ── verify ───────────────────────────────────────────────
    lines.push(Line::from(vec![
        Span::styled("verify  ", Style::default().fg(t.text_secondary).bold()),
        Span::styled(issue.verify.label(), Style::default().fg(t.text_primary)),
        Span::styled(
            "  · the issue closes itself when this holds",
            Style::default().fg(t.text_muted),
        ),
    ]));
    if let Some(v) = &issue.verification {
        let step = issue
            .remediation
            .get(v.step)
            .map_or("a step", |s| s.text.as_str());
        let (text, color) = match v.outcome {
            None => (
                format!("after \"{step}\" · watching for recovery"),
                t.text_secondary,
            ),
            Some(o) => (
                format!("after \"{step}\" · {}", o.label()),
                match o {
                    crate::diagnose::issue::VerifyOutcome::Recovered => t.status_good,
                    crate::diagnose::issue::VerifyOutcome::NotRecovered => t.status_error,
                    _ => t.status_warn,
                },
            ),
        };
        lines.push(Line::from(Span::styled(
            format!("        {text}"),
            Style::default().fg(color),
        )));
    }

    // ── consequences ─────────────────────────────────────────
    if !issue.consequences.is_empty() {
        lines.push(Line::from(""));
        lines.push(section(t, "explained by this issue"));
        for cid in &issue.consequences {
            if let Some(c) = view.engine.get(cid) {
                lines.push(Line::from(Span::styled(
                    format!("  {} · {}", c.title, c.subject.label()),
                    Style::default().fg(t.text_secondary),
                )));
            }
        }
    }

    // ── optional AI commentary ───────────────────────────────
    //
    // Rendered whenever the feature is on, whatever state it is in. The
    // heading always says what this is; the second line says either what the
    // model is doing or what it said. Silence is not an option here — an
    // enabled feature that shows nothing is indistinguishable from a broken
    // one, and that is exactly what it was.
    if let Some(ai) = &view.ai {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("ai narrative", Style::default().fg(t.text_muted).italic()),
            Span::styled(
                format!("  {}", ai.status_line(&view.endpoint)),
                Style::default()
                    .fg(if ai.is_failing() {
                        t.status_warn
                    } else {
                        t.text_muted
                    })
                    .italic(),
            ),
        ]));
        if let Some(n) = &ai.narrative {
            lines.push(Line::from(Span::styled(
                n.clone(),
                Style::default().fg(t.text_secondary),
            )));
        }
    }

    let sev = severity_color(issue.severity, t);
    let block = widgets::Panel::styled(vec![
        Span::styled(issue.title.clone(), Style::default().fg(sev).bold()),
        Span::styled(
            format!(" · {}", issue.severity.long_label()),
            Style::default().fg(sev),
        ),
    ])
    .meta(issue.id.to_string())
    .border(sev)
    .fit(area.width)
    .block(t);
    // Full height, unlike the panels beside it. This one is the page: an
    // incident is what the tab is for, and a box that stops halfway down
    // leaves the rest of the screen to a background nobody is reading. The
    // earlier content-sized version was right for a panel among panels and
    // wrong for the subject of the view.
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        area,
    );
}

/// `1 sample` / `2 samples`. English pluralisation, in one place, because
/// "1 samples" on a diagnostic screen undermines every other number on it.
fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        format!("1 {word}")
    } else {
        format!("{n} {word}s")
    }
}

/// Truncate on a character boundary, marking the cut. Widths here are column
/// counts, and the triggers are ASCII, so chars are the right unit.
fn ellipsise(text: &str, max: usize) -> String {
    if max < 2 || text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max - 1).collect();
    out.push('…');
    out
}

/// One check under the top cause. A check that did not run says why before
/// its detail, so "not measured" and "not implemented" never read alike.
fn check_line(t: &Theme, c: &CheckResult) -> Line<'static> {
    let color = match c.passed {
        Some(true) => t.status_good,
        Some(false) => t.status_error,
        None => t.text_muted,
    };
    let detail = match &c.why_not {
        Some(why) => format!(" · {} · {}", why.label(), c.detail),
        None => format!(" — {}", c.detail),
    };
    Line::from(vec![
        Span::styled(format!("   {} ", c.glyph()), Style::default().fg(color)),
        Span::styled(c.name.clone(), Style::default().fg(t.text_secondary)),
        Span::styled(detail, Style::default().fg(t.text_muted)),
    ])
}

fn section(t: &Theme, label: &str) -> Line<'static> {
    Line::from(Span::styled(
        label.to_string(),
        Style::default().fg(t.text_secondary).bold(),
    ))
}

// ────────────────────────────────────────────── report preview

fn render_report_preview(f: &mut Frame, view: &View, area: Rect) {
    let t = view.theme;
    let report = crate::diagnose::report::Report {
        coverage: view.engine.coverage().clone(),
        generated_at: String::new(),
        window_start: String::new(),
        window_end: String::new(),
        environment: Default::default(),
        issues: view.engine.issues().to_vec(),
        timeline: vec![],
        artifacts: vec![],
    };
    let md = report.to_markdown();
    let lines: Vec<Line> = md
        .lines()
        .take(area.height.saturating_sub(2) as usize)
        .map(|l| {
            Line::from(Span::styled(
                l.to_string(),
                Style::default().fg(if l.starts_with('#') {
                    t.text_primary
                } else {
                    t.text_secondary
                }),
            ))
        })
        .collect();

    let block = widgets::Panel::new("report.md")
        .meta_styled(vec![
            Span::styled("o", Style::default().fg(t.key_hint).bold()),
            Span::styled(
                if view.show_report {
                    " back to issues  "
                } else {
                    " read in full  "
                },
                Style::default().fg(t.text_muted),
            ),
            Span::styled("e", Style::default().fg(t.key_hint).bold()),
            Span::styled(" export bundle", Style::default().fg(t.text_muted)),
        ])
        .fit(area.width)
        .block(t);
    f.render_widget(Paragraph::new(lines).block(block), area);
}

/// The transient line under the panels: what an apply, export or copy just
/// did. Same `✓` / `✕` vocabulary as the footer toast, because a user cannot
/// be expected to learn two confirmations for the same class of event.
fn render_status(f: &mut Frame, view: &View, status: &str, area: Rect) {
    let t = view.theme;
    let lower = status.to_lowercase();
    let (glyph, color) = if view.status_is_recovery {
        ("!", t.status_warn)
    } else if lower.contains("failed") || lower.contains("error") {
        ("✕", t.status_error)
    } else if lower.contains("recovery")
        || lower.contains("blocked")
        || lower.contains("not applied")
        || lower.contains("unavailable")
    {
        ("!", t.status_warn)
    } else {
        ("✓", t.status_good)
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!(" {glyph} "), Style::default().fg(color).bold()),
            Span::styled(status.to_string(), Style::default().fg(color)),
        ])),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::fixture;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    /// Render the fixture and return the screen as text.
    fn draw(width: u16, height: u16, mutate: impl Fn(&mut View)) -> String {
        let (engine, baselines) = fixture::run();
        draw_engine(&engine, &baselines, width, height, mutate)
    }

    fn draw_engine(
        engine: &crate::diagnose::engine::Engine,
        baselines: &crate::diagnose::baseline::BaselineStore,
        width: u16,
        height: u16,
        mutate: impl Fn(&mut View),
    ) -> String {
        let theme = crate::theme::by_name("default");
        let mut view = View {
            engine,
            baselines,
            theme: &theme,
            selected: 0,
            show_report: false,
            capability: Capability::Root,
            ai: None,
            endpoint: "local".to_string(),
            third_party_probes: true,
            status: None,
            status_is_recovery: false,
            demo_banner: None,
            running_tests: vec![],
            history: None,
        };
        mutate(&mut view);

        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| render_body(f, &view, f.area())).unwrap();
        let buf = terminal.backend().buffer().clone();
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The fixture's issues come from rules without a reviewed contract, so
    /// they are beta: tagged in the list and explained in the detail pane.
    #[test]
    fn beta_issue_is_tagged() {
        let (engine, _) = fixture::run();
        let first = engine.primary_issues()[0].clone();
        assert!(first.beta, "{} should be beta", first.rule);
        let screen = draw(150, 44, |_| {});
        assert!(
            screen.contains(&format!("{} beta", first.title)),
            "{screen}"
        );
        assert!(
            screen.contains("beta rule: contract not yet reviewed"),
            "{screen}"
        );
    }

    fn draw_coverage_text(width: u16, selected: usize) -> String {
        use crate::diagnose::coverage::{Availability, RuleCoverage};
        let theme = crate::theme::by_name("default");
        let rules: Vec<RuleCoverage> = rules::CATALOGUE
            .iter()
            .map(|r| RuleCoverage {
                rule: r.id.into(),
                status: Availability::Available,
                reason: "inputs present".into(),
            })
            .collect();
        let details = vec![("Why", "inputs present".to_string())];
        let mut terminal = Terminal::new(TestBackend::new(width, 20)).unwrap();
        terminal
            .draw(|f| draw_coverage(f, &theme, &rules, selected, &details, f.area()))
            .unwrap();
        let buf = terminal.backend().buffer().clone();
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn coverage_scrolls_to_the_selected_rule_and_names_it() {
        let last = rules::CATALOGUE.len() - 1;
        let s = draw_coverage_text(150, last);
        let id = rules::CATALOGUE[last].id;
        assert!(s.contains("› "), "{s}");
        assert!(s.contains(&format!("{}/{}", last + 1, last + 1)), "{s}");
        assert!(s.matches(id).count() >= 2, "row and detail title: {s}");
        assert!(s.contains("Title"), "{s}");
        // Narrow: titles drop out of the table but the check ids stay whole.
        let s = draw_coverage_text(100, last);
        assert!(!s.contains("Title"), "{s}");
        assert!(s.contains(id), "{s}");
    }

    #[test]
    fn the_verdict_line_leads_with_the_worst_issue() {
        let s = draw(150, 44, |_| {});
        assert!(s.contains("3 issues"), "{s}");
        assert!(s.contains("slow dns resolver"), "{s}");
    }

    #[test]
    fn the_screen_shows_the_computed_multiple_and_never_a_wrong_one() {
        let s = draw(150, 44, |_| {});
        assert!(s.contains("33× baseline"), "{s}");
        assert!(!s.contains("100×"), "{s}");
    }

    #[test]
    fn confidence_is_a_word_not_a_percentage() {
        let s = draw(150, 44, |_| {});
        assert!(s.contains("strong") || s.contains("likely"), "{s}");
        // No cause line may carry a percent sign.
        for line in s.lines().filter(|l| l.contains("checks")) {
            assert!(
                !line.contains('%'),
                "confidence rendered as a probability: {line}"
            );
        }
    }

    #[test]
    fn the_detail_pane_shows_cause_checks_for_the_top_cause() {
        let s = draw(150, 44, |_| {});
        assert!(s.contains("probable cause"), "{s}");
        assert!(s.contains("upstream forwarder"), "{s}");
        assert!(s.contains("✓") || s.contains("✗"), "{s}");
    }

    #[test]
    fn a_check_that_did_not_run_says_why_before_its_detail() {
        use crate::diagnose::coverage::Availability;
        let theme = crate::theme::by_name("default");
        let text = |c: &CheckResult| -> String {
            check_line(&theme, c)
                .spans
                .iter()
                .map(|s| s.content.as_ref())
                .collect()
        };
        let not_run = CheckResult::not_run(
            "alt_resolver_is_fast",
            "alt resolver is fast",
            Availability::NotMeasured,
            "no alternate resolver probe",
        );
        assert_eq!(
            text(&not_run),
            "   · alt resolver is fast · not measured · no alternate resolver probe"
        );
        let ran = CheckResult::fail("icmp_rtt_raised", "icmp rtt raised", "normal at 0.1ms");
        assert_eq!(text(&ran), "   ✗ icmp rtt raised — normal at 0.1ms");
    }

    #[test]
    fn every_issue_shows_its_verify_condition() {
        let (engine, _) = fixture::run();
        for n in 0..engine.primary().len() {
            let s = draw(150, 44, |v| v.selected = n);
            assert!(s.contains("verify"), "issue {n} has no verify line:\n{s}");
        }
    }

    #[test]
    fn selecting_a_different_issue_changes_the_detail_pane() {
        let a = draw(150, 44, |v| v.selected = 0);
        let b = draw(150, 44, |v| v.selected = 1);
        assert_ne!(a, b);
    }

    #[test]
    fn an_unprivileged_run_hides_apply_steps_and_says_why() {
        let s = draw(150, 44, |v| v.capability = Capability::None);
        assert!(
            s.contains("hidden: netwatch is running with no privileges"),
            "an unprivileged run must explain the missing step:\n{s}"
        );
    }

    #[test]
    fn a_privileged_run_offers_the_key_bound_fix() {
        // The demo, which simulates the switch; live mode offers no key.
        let s = draw(150, 44, |v| {
            v.capability = Capability::Root;
            v.demo_banner = Some("DEMO".into());
        });
        assert!(s.contains("1 switch this session's resolver"), "{s}");
        assert!(!s.contains("hidden:"), "{s}");
    }

    /// Live, `↵` writes nothing, so neither the footer nor the step offers a
    /// key: the step says what to run instead. Running as root with the
    /// resolver issue open is the case the hint used to lie about.
    #[test]
    fn live_mode_offers_no_enter() {
        let (engine, baselines) = fixture::run();
        let theme = crate::theme::by_name("default");
        let dns = engine
            .primary()
            .iter()
            .position(|i| i.rule == "dns.slow_resolver")
            .expect("the fixture opens the resolver issue");
        let mut view = View {
            engine: &engine,
            baselines: &baselines,
            theme: &theme,
            selected: dns,
            show_report: false,
            capability: Capability::Root,
            ai: None,
            endpoint: "local".to_string(),
            third_party_probes: true,
            status: None,
            status_is_recovery: false,
            demo_banner: None,
            running_tests: vec![],
            history: None,
        };
        let keys = |view: &View| -> Vec<String> {
            footer_hints(view).into_iter().map(|(key, _)| key).collect()
        };
        assert!(!keys(&view).contains(&"↵".to_string()), "{:?}", keys(&view));
        let s = draw(150, 44, |v| v.selected = dns);
        assert!(s.contains("· switch this session's resolver"), "{s}");
        assert!(!s.contains("1 switch this session's resolver"), "{s}");
        assert!(s.contains("netwatch does not change resolvers"), "{s}");

        view.demo_banner = Some("DEMO".into());
        assert!(keys(&view).contains(&"↵".to_string()), "{:?}", keys(&view));
    }

    #[test]
    fn the_issue_view_carries_no_catalogue_strip_or_preview() {
        let s = draw(150, 44, |_| {});
        assert!(s.contains("slow dns resolver"), "{s}");
        for noise in [
            "watching for",
            "report.md",
            "ruleset",
            "rule inputs available",
        ] {
            assert!(
                !s.contains(noise),
                "{noise} is back on the issue view:\n{s}"
            );
        }
    }

    #[test]
    fn the_detail_pane_shows_the_shape_behind_the_headline_number() {
        // Printing "40 ms" and stopping leaves the reader to imagine the
        // shape: a spike that has already passed and one still climbing read
        // identically. The row is only drawn when there are samples to draw.
        let quiet = draw(120, 40, |_| {});
        let charted = draw(120, 40, |v| {
            v.history = Some(MetricHistory {
                metric: "dns.rtt_p50".into(),
                samples: vec![1.0, 1.2, 1.1, 40.0, 41.0, 39.0],
                threshold: Some(5.0),
                unit: "ms".into(),
            });
        });
        assert!(
            !quiet.contains("threshold"),
            "no series, no caption: {quiet}"
        );
        assert!(
            charted.contains("dns.rtt_p50 · threshold 5.0ms · 6 samples · now"),
            "{charted}"
        );
        assert!(
            charted.chars().any(|c| "▁▂▃▄▅▆▇█".contains(c)),
            "the row itself is missing: {charted}"
        );
    }

    #[test]
    fn only_the_samples_above_the_threshold_are_coloured() {
        // The point is which samples crossed, not that any did — so the
        // colour goes on individual glyphs, not the whole row.
        let (engine, baselines) = fixture::run();
        let theme = crate::theme::by_name("nord");
        let view = View {
            engine: &engine,
            baselines: &baselines,
            theme: &theme,
            selected: 0,
            show_report: false,
            capability: Capability::Root,
            ai: None,
            endpoint: "local".to_string(),
            third_party_probes: true,
            status: None,
            status_is_recovery: false,
            demo_banner: None,
            running_tests: vec![],
            history: Some(MetricHistory {
                metric: "dns.rtt_p50".into(),
                samples: vec![1.0, 1.0, 1.0, 40.0],
                threshold: Some(5.0),
                unit: "ms".into(),
            }),
        };
        let issue = view.current().expect("fixture opens issues").clone();
        let rows = history_rows(view.history.as_ref().unwrap(), &issue, &theme, 60);
        let spans: Vec<_> = rows[0].spans.iter().skip(1).collect();
        assert_eq!(spans.len(), 4);
        let severity = severity_color(issue.severity, &theme);
        assert_eq!(spans[0].style.fg, Some(theme.text_muted), "below threshold");
        assert_eq!(spans[3].style.fg, Some(severity), "above threshold");
    }

    /// With learned baselines and nothing open the engine says Incomplete,
    /// never Clear, and the row drew that as the green ● of health.
    #[test]
    fn incomplete_never_draws_status_good_in_the_verdict_row() {
        use crate::diagnose::engine::{Engine, SystemClock};

        let engine = Engine::new(Box::new(SystemClock));
        let baselines = fixture::baselines();
        assert!(matches!(
            engine.verdict(&baselines),
            Verdict::Incomplete { .. }
        ));
        for name in crate::theme::THEME_NAMES {
            let theme = crate::theme::by_name(name);
            let view = View {
                engine: &engine,
                baselines: &baselines,
                theme: &theme,
                selected: 0,
                show_report: false,
                capability: Capability::Root,
                ai: None,
                endpoint: "local".to_string(),
                third_party_probes: true,
                status: None,
                status_is_recovery: false,
                demo_banner: None,
                running_tests: vec![],
                history: None,
            };
            let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
            terminal.draw(|f| render_body(f, &view, f.area())).unwrap();
            let buf = terminal.backend().buffer().clone();
            let row: String = (0..buf.area.width).map(|x| buf[(x, 0)].symbol()).collect();
            assert!(
                row.contains("◌ no issues found · watching"),
                "{name}: {row}"
            );
            for x in 0..buf.area.width {
                let cell = &buf[(x, 0)];
                assert!(
                    cell.symbol() == " " || cell.fg != theme.status_good,
                    "{name}: green {:?} at column {x} of {row}",
                    cell.symbol()
                );
            }
        }
    }

    /// A muted issue drew the green ✓ and green label of a fixed one. It is
    /// still wrong, only quiet: a muted `◌`, the time the mute ends, and a
    /// count on the verdict row, never a green cell. Checked with one issue
    /// muted beside open ones, and with every issue muted.
    #[test]
    fn muted_is_never_drawn_green() {
        let (mut one, baselines) = fixture::run();
        let id = one.primary()[0].id.clone();
        assert!(one.mute(&id, 60));
        // Consequences too: a muted root keeps its consequences suppressed,
        // so muting only what `primary` lists would leave them open.
        let (mut all, _) = fixture::run();
        let open: Vec<String> = all
            .issues()
            .iter()
            .filter(|i| i.state.is_open())
            .map(|i| i.id.clone())
            .collect();
        for id in &open {
            assert!(all.mute(id, 60));
        }
        assert!(all.issues().iter().all(|i| !i.state.is_open()));
        assert!(all.muted_count() > 1);

        for engine in [&one, &all] {
            let muted = engine
                .issues()
                .iter()
                .filter(|i| i.state.muted_until().is_some())
                .count();
            for name in crate::theme::THEME_NAMES {
                let theme = crate::theme::by_name(name);
                let view = View {
                    engine,
                    baselines: &baselines,
                    theme: &theme,
                    selected: 0,
                    show_report: false,
                    capability: Capability::Root,
                    ai: None,
                    endpoint: "local".to_string(),
                    third_party_probes: true,
                    status: None,
                    status_is_recovery: false,
                    demo_banner: None,
                    running_tests: vec![],
                    history: None,
                };
                let mut terminal = Terminal::new(TestBackend::new(150, 44)).unwrap();
                terminal.draw(|f| render_body(f, &view, f.area())).unwrap();
                let buf = terminal.backend().buffer().clone();
                let row = |y: u16| -> Vec<String> {
                    (0..buf.area.width)
                        .map(|x| buf[(x, y)].symbol().to_string())
                        .collect()
                };

                let verdict = row(0).concat();
                assert!(
                    verdict.contains(&format!(" · {} muted", engine.muted_count())),
                    "{name}: {verdict}"
                );

                // Each muted row, from its left edge to the end of its label.
                let label = "muted until 07:51";
                let mut rows = 0;
                for y in 0..buf.area.height {
                    let cells = row(y);
                    let Some(start) =
                        (0..cells.len()).find(|&x| cells[x..].concat().starts_with(label))
                    else {
                        continue;
                    };
                    rows += 1;
                    let end = start + label.len();
                    let text = cells[..end].concat();
                    assert!(text.contains('◌') && !text.contains('✓'), "{name}: {text}");
                    for x in 0..end {
                        let cell = &buf[(x as u16, y)];
                        assert!(
                            cell.symbol() == " " || cell.fg != theme.status_good,
                            "{name}: green {:?} at column {x} of {text}",
                            cell.symbol()
                        );
                    }
                }
                assert_eq!(rows, muted, "{name}: one row per muted issue");
            }
        }
    }

    #[test]
    fn a_clear_engine_does_not_claim_health_it_has_not_earned() {
        use crate::diagnose::baseline::NetworkFingerprint;
        use crate::diagnose::engine::{Engine, SystemClock};

        let engine = Engine::new(Box::new(SystemClock));
        let baselines = BaselineStore::new(NetworkFingerprint::new("eth0", None, vec![], None));
        let theme = crate::theme::by_name("default");
        let view = View {
            engine: &engine,
            baselines: &baselines,
            theme: &theme,
            selected: 0,
            show_report: false,
            capability: Capability::None,
            ai: None,
            endpoint: "local".to_string(),
            third_party_probes: true,
            status: None,
            status_is_recovery: false,
            demo_banner: None,
            running_tests: vec![],
            history: None,
        };
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|f| render_body(f, &view, f.area())).unwrap();
        let buf = terminal.backend().buffer().clone();
        let s: String = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(s.contains("no baseline"), "{s}");
        assert!(!s.contains("nominal"), "{s}");
        assert!(!s.contains("healthy"), "{s}");
        // Said once, then out of the way: no empty issue/detail boxes, no
        // catalogue, no report preview.
        assert!(s.contains("Nothing to report"), "{s}");
        assert!(s.contains("watching"), "{s}");
        for noise in ["watching for", "report.md", "nothing open", "detail"] {
            assert!(!s.contains(noise), "{noise} on a quiet page:\n{s}");
        }
    }

    #[test]
    fn the_report_preview_renders_the_same_numbers_as_the_screen() {
        let s = draw(150, 44, |v| v.show_report = true);
        assert!(s.contains("report.md"), "{s}");
        assert!(s.contains("netwatch report"), "{s}");
    }

    #[test]
    fn narrative_is_labelled_as_commentary() {
        use crate::collectors::insights::InsightsStatus;
        let s = draw(150, 44, |v| {
            v.ai = Some(Ai {
                status: InsightsStatus::Available,
                narrative: Some("The resolver change lines up with the reroute.".into()),
            })
        });
        assert!(s.contains("ai narrative"), "{s}");
        assert!(s.contains("not a source of facts"), "{s}");
        assert!(s.contains("lines up with the reroute"), "{s}");
    }

    /// The regression this whole investigation was about: with the feature
    /// enabled and no model reachable, the tab said nothing at all.
    #[test]
    fn a_failing_model_says_so_instead_of_going_silent() {
        use crate::collectors::insights::InsightsStatus;
        let s = draw(150, 44, |v| {
            v.ai = Some(Ai {
                status: InsightsStatus::OllamaUnavailable,
                narrative: None,
            })
        });
        assert!(
            s.contains("ai narrative"),
            "the block must still appear:\n{s}"
        );
        assert!(s.contains("no model answering"), "{s}");
        assert!(
            s.contains("localhost:11434"),
            "it must name the address it tried, not the config word:\n{s}"
        );
        // A fragment short enough to survive the wrap: the advice runs past
        // the detail pane's width, and the panel border sits between the
        // wrapped halves, so the full sentence never appears contiguously.
        assert!(s.contains("switch this off"), "{s}");
    }

    #[test]
    fn every_model_state_produces_a_line() {
        use crate::collectors::insights::InsightsStatus as S;
        for (status, expect) in [
            (S::Idle, "waiting for the first analysis"),
            (S::Analyzing, "analysing"),
            (S::Error("timed out".into()), "timed out"),
            (S::OllamaUnavailable, "no model answering"),
        ] {
            let s = draw(150, 44, |v| {
                v.ai = Some(Ai {
                    status: status.clone(),
                    narrative: None,
                })
            });
            assert!(
                s.contains(expect),
                "{status:?} should mention {expect:?}:\n{s}"
            );
        }
    }

    /// Not only on a detail pane: requests keep going out with nothing open,
    /// so the empty page has to say so too.
    #[test]
    fn a_cleartext_endpoint_shows_on_both_pages_whatever_the_model_is_doing() {
        use crate::collectors::insights::InsightsStatus;
        const WORDS: &str = "cleartext, off-host";
        let (engine, baselines) = fixture::run();
        let quiet = crate::diagnose::Engine::new(Box::new(crate::diagnose::engine::SystemClock));
        for status in [
            InsightsStatus::Idle,
            InsightsStatus::Available,
            InsightsStatus::OllamaUnavailable,
        ] {
            let on = |v: &mut View| {
                v.ai = Some(Ai {
                    status: status.clone(),
                    narrative: None,
                });
                v.endpoint = "http://10.0.0.5:11434".into();
            };
            let open = draw_engine(&engine, &baselines, 150, 44, on);
            assert!(
                open.contains(WORDS),
                "{status:?} with an issue open:\n{open}"
            );
            let empty = draw_engine(&quiet, &baselines, 150, 44, on);
            assert!(
                empty.contains(WORDS),
                "{status:?} with nothing open:\n{empty}"
            );
        }
        // Loopback, TLS, or the feature off: nothing to warn about, on either.
        for mutate in [
            (|v: &mut View| {
                v.ai = Some(Ai {
                    status: InsightsStatus::Idle,
                    narrative: None,
                });
                v.endpoint = "http://127.0.0.1:11434".into();
            }) as fn(&mut View),
            |v: &mut View| {
                v.ai = Some(Ai {
                    status: InsightsStatus::Idle,
                    narrative: None,
                });
                v.endpoint = "https://ollama.example.com".into();
            },
            |v: &mut View| v.endpoint = "http://10.0.0.5:11434".into(),
        ] {
            for s in [
                draw_engine(&engine, &baselines, 150, 44, mutate),
                draw_engine(&quiet, &baselines, 150, 44, mutate),
            ] {
                assert!(!s.contains(WORDS), "{s}");
            }
        }
    }

    /// Through the real page, which gives the body six fewer rows than the
    /// terminal has. The line used to be the last thing in a detail pane with
    /// no scroll, gone at every size up to 130x40 with an issue open, and in a
    /// panel on the empty page sized before its text wrapped, gone at 100
    /// columns and under.
    #[test]
    fn the_cleartext_line_reaches_the_screen_on_every_page_at_every_size() {
        use crate::app::{draw_frame, App, Tab};
        use crate::config::NetwatchConfig;
        use crate::diagnose::baseline::{BaselineStore, NetworkFingerprint};
        use crate::diagnose::detectors::{DnsObs, Observations, Thresholds};
        const WORDS: &str = "cleartext, off-host: Insights sends";

        let shown = |app: &mut App, width: u16, height: u16| {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal.draw(|f| draw_frame(f, app)).unwrap();
            let buffer = terminal.backend().buffer().clone();
            buffer
                .content
                .chunks(usize::from(width))
                .map(|row| row.iter().map(|c| c.symbol()).collect::<String>())
                .collect::<Vec<_>>()
                .join("\n")
        };
        let app = || {
            let mut app = App::prepare_with_config(NetwatchConfig {
                insights_enabled: true,
                insights_endpoint: "http://10.0.0.5:11434".into(),
                diagnose_record_episodes: false,
                diagnose_thresholds: Thresholds {
                    dns_ceiling_ms: 30.0,
                    ..Default::default()
                },
                ..Default::default()
            });
            app.ui.current_tab = Tab::Diagnose;
            app
        };
        let slow_resolver = Observations {
            dns: Some(DnsObs {
                resolver: "192.0.2.53".into(),
                rtt_p50_ms: Some(40.0),
                rtt_p95_ms: Some(48.0),
                failure_rate_pct: 0.0,
                truncation_rate_pct: 0.0,
                queries: 38,
                failed: 0,
                truncated: 0,
                alt_resolver: None,
                alt_rtt_ms: None,
                icmp_rtt_ms: None,
                cached_rtt_ms: None,
                window_secs: 180,
                cross: None,
            }),
            ..Default::default()
        };
        let base = BaselineStore::new(NetworkFingerprint::new("eth0", None, vec![], None));

        let mut empty = app();
        let mut open = app();
        for _ in 0..3 {
            open.diagnose.engine.observe(&slow_resolver, &base);
        }
        assert!(!open.diagnose.engine.primary().is_empty(), "no open issue");
        for (width, height) in [
            (78, 16),
            (80, 24),
            (100, 30),
            (120, 40),
            (130, 40),
            (150, 44),
            (200, 60),
        ] {
            let page = shown(&mut empty, width, height);
            assert!(page.contains(WORDS), "empty, {width}x{height}:\n{page}");
            let page = shown(&mut open, width, height);
            assert!(page.contains(WORDS), "issue, {width}x{height}:\n{page}");
            open.diagnose.show_report = true;
            let page = shown(&mut open, width, height);
            open.diagnose.show_report = false;
            assert!(page.contains(WORDS), "report, {width}x{height}:\n{page}");
            open.diagnose.show_coverage = true;
            let page = shown(&mut open, width, height);
            open.diagnose.show_coverage = false;
            assert!(page.contains(WORDS), "coverage, {width}x{height}:\n{page}");
        }
        // Too narrow for the sentence, the words that matter still show.
        let page = shown(&mut open, 40, 24);
        assert!(page.contains("cleartext, off-host"), "{page}");
    }

    #[test]
    fn the_block_is_absent_when_the_feature_is_off() {
        let s = draw(150, 44, |_| {});
        assert!(
            !s.contains("ai narrative"),
            "nothing about AI belongs on screen when it is disabled:\n{s}"
        );
    }

    #[test]
    fn selection_is_visible_without_a_background_fill() {
        let a = draw(150, 44, |v| v.selected = 0);
        let b = draw(150, 44, |v| v.selected = 1);
        assert!(a.contains('▌'), "the selected row needs a rail:\n{a}");
        assert_ne!(a, b, "moving the cursor must change the screen");

        // The verdict strip above the list draws its own severity rail, so
        // the cursor's rail is the first one *inside* the issues panel.
        let rail_line = |s: &str| {
            // The panel's top border, not the verdict line — which also
            // says "3 issues" and draws a rail of its own.
            let panel_top = s
                .lines()
                .position(|l| l.contains("issues") && l.contains('╮'))
                .expect("an issues panel");
            s.lines()
                .skip(panel_top)
                .position(|l| l.contains('▌'))
                .expect("a rail in the issue list")
                + panel_top
        };
        assert!(
            rail_line(&b) > rail_line(&a),
            "the rail must follow the cursor down the list"
        );
    }

    #[test]
    fn demo_mode_says_so_on_every_frame() {
        let s = draw(150, 44, |v| {
            v.demo_banner = Some("DEMO — recorded scenario, 6× · 250 of 439s".into())
        });
        assert!(s.contains("DEMO"), "{s}");
        assert!(s.contains("recorded scenario"), "{s}");
        // And it does not simultaneously claim to know the live network.
        assert!(!s.contains("network eth0"), "{s}");
    }

    #[test]
    fn sample_counts_are_pluralised() {
        assert_eq!(plural(1, "sample"), "1 sample");
        assert_eq!(plural(0, "sample"), "0 samples");
        assert_eq!(plural(38, "sample"), "38 samples");
    }

    #[test]
    fn ellipsise_never_splits_mid_character_or_overflows() {
        assert_eq!(ellipsise("short", 20), "short");
        assert_eq!(ellipsise("abcdefghij", 5), "abcd…");
        assert_eq!(ellipsise("abcdefghij", 5).chars().count(), 5);
        // Degenerate widths must not panic.
        assert_eq!(ellipsise("abc", 0), "abc");
        assert_eq!(ellipsise("σσσσσ", 3).chars().count(), 3);
    }

    /// The catalogue summarises; it does not compete with the issue list.
    ///
    /// It used to print every rule's full trigger sentence into a column
    /// sized to the issue titles, which produced twenty-five lines that all
    /// ended in `…`. A truncated sentence teaches nothing, so the panel now
    /// names categories and rule names and sends the reader to `?`.
    /// The chronology is the ordering argument the ranking rests on: the
    /// reroute came first, the resolver slowed four minutes later.
    #[test]
    fn the_chronology_runs_oldest_first() {
        let s = draw(150, 44, |_| {});
        let rows: Vec<&str> = s
            .lines()
            .skip_while(|l| !l.contains("chronology"))
            .skip(1)
            .take_while(|l| !l.starts_with('╰'))
            .collect();
        assert!(rows.len() >= 2, "expected a chronology:\n{s}");

        // The row starts with the panel border and, on the selected row, the
        // cursor rail — neither is part of the timestamp.
        let stamps: Vec<String> = rows
            .iter()
            .filter_map(|l| {
                l.split_whitespace()
                    .map(|w| w.trim_matches(|c| c == '│' || c == '▌'))
                    .find(|w| w.contains(':'))
                    .map(str::to_string)
            })
            .collect();
        let mut sorted = stamps.clone();
        sorted.sort_unstable();
        assert_eq!(stamps, sorted, "out of order: {stamps:?}\n{s}");
    }

    /// A consequence is filed under its root cause in the issue list, which
    /// means the list is the one place it cannot be seen in time order. The
    /// chronology carries it.
    #[test]
    fn the_chronology_includes_suppressed_consequences() {
        let s = draw(150, 44, |_| {});
        assert!(s.contains("path rtt above baseline"), "{s}");
        // And the issue list above it still does not list it as a finding.
        let list: String = s
            .lines()
            .skip_while(|l| !(l.contains("issues") && l.contains('╮')))
            .take_while(|l| !l.contains("chronology"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !list.contains("path rtt above baseline"),
            "a consequence must not also be a finding:\n{list}"
        );
    }

    /// `↵ apply fix` must not survive the apply. The detail pane says
    /// `applied 06:51:56 · 169.254.1.1 → 192.168.8.1` while the footer went on
    /// offering to apply it — a key hint for a key with nothing left to do.
    #[test]
    fn the_apply_hint_disappears_once_the_step_has_run() {
        use crate::diagnose::issue::Applied;

        let (engine, _) = fixture::run();
        let issue = engine
            .primary()
            .into_iter()
            .find(|i| i.remediation.iter().any(|s| s.kind == StepKind::Apply))
            .expect("the fixture has an appliable issue")
            .clone();

        assert!(
            has_applicable_step(&issue, Capability::Root, true),
            "before the apply, ↵ does something"
        );

        let mut applied = issue.clone();
        for step in applied.remediation.iter_mut() {
            if step.kind == StepKind::Apply {
                step.applied = Some(Applied::Yes {
                    at: "2026-09-03 06:51:56".into(),
                    before: "169.254.1.1".into(),
                    after: "192.168.8.1".into(),
                });
            }
        }
        assert!(
            !has_applicable_step(&applied, Capability::Root, true),
            "after the apply, ↵ has nothing left to do"
        );

        // Reverted is applicable again — the fix is off the box.
        let mut reverted = applied.clone();
        for step in reverted.remediation.iter_mut() {
            if step.kind == StepKind::Apply {
                step.applied = Some(Applied::Reverted {
                    at: "2026-09-03 06:55:00".into(),
                    reason: "user".into(),
                });
            }
        }
        assert!(has_applicable_step(&reverted, Capability::Root, true));
    }

    #[test]
    fn recovery_required_step_cannot_be_applied_again() {
        let (engine, _) = fixture::run();
        let mut issue = engine
            .primary()
            .into_iter()
            .find(|i| i.remediation.iter().any(|s| s.kind == StepKind::Apply))
            .unwrap()
            .clone();
        for step in &mut issue.remediation {
            if step.kind == StepKind::Apply {
                step.applied = Some(Applied::RecoveryRequired {
                    operation_id: "op-1".into(),
                    reason: "partial write".into(),
                    backup: "/backup".into(),
                });
            }
        }
        assert!(!has_applicable_step(&issue, Capability::Root, true));
    }

    #[test]
    fn recovery_status_does_not_display_a_success_checkmark() {
        let screen = draw(150, 44, |view| {
            view.status = Some("recovery required; restore by hand")
        });
        let line = screen
            .lines()
            .find(|l| l.contains("restore by hand"))
            .unwrap();
        assert!(!line.contains('✓'), "{line}");
        assert!(line.contains('!'), "{line}");
    }

    /// The tab uses the screen it is given. Panels stay content-sized, so
    /// the space the detail pane does not need goes to the report — which is
    /// generated from the same issues and is always longer than the room for
    /// it, rather than being padding.
    /// A short screen has nothing to spare, so the preview stays away rather
    /// than squeezing the pane it is meant to be filling around.
    #[test]
    fn a_short_screen_gets_no_preview() {
        let s = draw(150, 26, |_| {});
        assert!(!s.contains("report.md"), "{s}");
        assert!(
            s.contains("slow dns resolver"),
            "the working view survives:\n{s}"
        );
    }

    /// `o` swaps the working view for the whole report. Revealing a preview
    /// that is already on screen would be showing the same thing twice; what
    /// the key is for is reading the report at length.
    #[test]
    fn o_replaces_the_working_view_with_the_full_report() {
        let s = draw(150, 44, |v| v.show_report = true);
        assert!(s.contains("netwatch report"), "{s}");
        assert!(
            !s.contains("watching for"),
            "the working view must give way to the report:\n{s}"
        );
        assert!(s.contains("back to issues"), "the way out is named:\n{s}");
        // And the footer names it the same way — one key, one label.
        let view_hints = {
            let (engine, baselines) = fixture::run();
            let theme = crate::theme::by_name("default");
            let v = View {
                engine: &engine,
                baselines: &baselines,
                theme: &theme,
                selected: 0,
                show_report: true,
                capability: Capability::Root,
                ai: None,
                endpoint: "local".to_string(),
                third_party_probes: true,
                status: None,
                status_is_recovery: false,
                demo_banner: None,
                running_tests: vec![],
                history: None,
            };
            footer_hints(&v)
        };
        let o = view_hints
            .iter()
            .find(|(k, _)| k == "o")
            .expect("the report key");
        assert_eq!(o.1, "back to issues", "panel and footer disagree on `o`");
    }

    /// Panels are sized to their content. The detail pane used to be stretched
    /// to the full column height, leaving fourteen blank rows under its last
    /// sentence — which reads as a pane that failed to load.
    #[test]
    fn the_detail_pane_fills_the_page() {
        // The incident is the subject of this tab, not a panel among panels:
        // its frame runs to the bottom of the body rather than stopping at
        // the last sentence and leaving the rest of the screen empty.
        let s = draw(150, 44, |_| {});
        let lines: Vec<&str> = s.lines().collect();
        let close = lines
            .iter()
            .rposition(|l| l.contains('╯'))
            .expect("a closed panel");
        let last_drawn = lines
            .iter()
            .rposition(|l| !l.trim().is_empty())
            .expect("something is drawn");
        assert_eq!(
            close, last_drawn,
            "the detail frame should close on the last drawn row:\n{s}"
        );
    }

    #[test]
    fn an_empty_detail_pane_keeps_the_same_frame() {
        use crate::diagnose::baseline::NetworkFingerprint;
        use crate::diagnose::engine::{Engine, SystemClock};
        let engine = Engine::new(Box::new(SystemClock));
        let baselines = BaselineStore::new(NetworkFingerprint::new("eth0", None, vec![], None));
        let theme = crate::theme::by_name("default");
        let view = View {
            engine: &engine,
            baselines: &baselines,
            theme: &theme,
            selected: 0,
            show_report: false,
            capability: Capability::None,
            ai: None,
            endpoint: "local".to_string(),
            third_party_probes: true,
            status: None,
            status_is_recovery: false,
            demo_banner: None,
            running_tests: vec![],
            history: None,
        };
        let mut terminal = Terminal::new(TestBackend::new(80, 20)).unwrap();
        terminal
            .draw(|f| render_detail(f, &view, f.area()))
            .unwrap();
        let buf = terminal.backend().buffer().clone();
        let bottom: String = (0..buf.area.width)
            .map(|x| buf[(x, buf.area.height - 1)].symbol())
            .collect();
        assert!(
            bottom.contains('╯'),
            "the empty state closes at the bottom too: {bottom}"
        );
    }

    #[test]
    fn an_issue_nothing_measures_says_it_is_stale() {
        let (mut engine, baselines) = fixture::run();
        assert!(!draw_engine(&engine, &baselines, 150, 44, |_| {}).contains("stale"));
        // Every collector goes quiet: the open issues can neither close nor
        // expire, and each row says since when.
        engine.observe(
            &crate::diagnose::detectors::Observations::default(),
            &baselines,
        );
        let s = draw_engine(&engine, &baselines, 150, 44, |_| {});
        assert!(s.contains("since 06:48:10 · stale since 06:51:20"), "{s}");
    }

    #[test]
    fn a_lone_stale_issue_sizes_the_list_to_its_stale_since() {
        use crate::diagnose::detectors::{GatewayObs, Observations};
        use crate::diagnose::engine::{Engine, FixedClock};

        // The gateway outage behind blocked ICMP, alone: its title and
        // subject are short, so only the when row can size the column.
        let clock = std::sync::Arc::new(FixedClock::at("2026-09-03 06:48:10"));
        let engine = Engine::new(Box::new(clock.clone()));
        let mut settings = *engine.settings();
        settings.thresholds.consecutive_n = 1;
        let mut engine = engine.with_settings(settings);
        let baselines = fixture::baselines();
        engine.observe(
            &Observations {
                gateway: Some(GatewayObs {
                    addr: Some("192.168.8.1".into()),
                    rtt_ms: None,
                    loss_pct: 100.0,
                    arp_ok: None,
                    icmp_ok: false,
                    internet_reachable: Some(false),
                }),
                ..Default::default()
            },
            &baselines,
        );
        clock.advance_secs(5);
        engine.observe(&Observations::default(), &baselines);
        assert_eq!(engine.primary().len(), 1);
        for width in [120, 150, 200] {
            let s = draw_engine(&engine, &baselines, width, 30, |_| {});
            assert!(
                s.contains("since 06:48:10 · stale since 06:48:15"),
                "{width}: {s}"
            );
        }
    }

    #[test]
    fn it_renders_without_panicking_at_awkward_sizes() {
        // 20x5 is smaller than netwatch supports, but a resize passes through
        // every intermediate size on the way down, so none of them may panic.
        for (w, h) in [
            (80, 24),
            (100, 30),
            (200, 60),
            (60, 15),
            (40, 10),
            (20, 5),
            (1, 1),
        ] {
            for report in [false, true] {
                let s = draw(w, h, |v| v.show_report = report);
                let _ = s;
            }
        }
    }
}
