use crate::app::App;
use crate::collectors::traffic::InterfaceTraffic;
use crate::sort::{SortColumn, TabSortState};
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Cell, Paragraph, Row, Table},
};

pub const COLUMNS: &[SortColumn] = &[];

pub const DEFAULT_SORT: TabSortState = TabSortState {
    column: 0,
    ascending: true,
};

/// Rows the hero row needs: value, baseline, `since`, and two borders — the
/// title costs nothing now that it lives in the top border.
const KPI_ROWS: u16 = 5;
/// Throughput and health side by side.
const MID_ROWS: u16 = 14;
/// The incident timeline, when the screen is tall enough to earn it.
const TIMELINE_ROWS: u16 = 6;

/// Rows the interfaces panel needs to show its border, header and one
/// interface. Below this it has nothing to say that its title does not.
const IFACE_MIN_ROWS: u16 = 4;
/// How far back the KPI tiles' sparklines look.
///
/// Fixed, and the same for every tile, because the five sit in one row and are
/// read across. They used to plot "the last N samples" of whatever fed them —
/// and the latency probes sample once per five ticks while throughput samples
/// every tick, so the gateway tile was showing five minutes next to a
/// throughput tile showing one, at identical width. Same column, different
/// moment, no way to tell.
const KPI_WINDOW_SECS: u64 = 300;

/// How far apart rx and tx peaks have to be before the throughput mirror
/// gives each half its own scale. At 20× the quieter direction is under one
/// row of a ten-row half, which renders as an empty panel rather than a small
/// one.
const SPLIT_SCALE_RATIO: u64 = 20;
/// Below this the timeline is dropped rather than squeezing the connections
/// list, which is the panel a reader is actually working in.
const TIMELINE_MIN_HEIGHT: u16 = 38;

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    // The active-interface panel that used to hold half of the mid band is
    // gone: mac, mtu, queues, offload and qdisc are the Interfaces tab's
    // subject, and on the dashboard they cost a column that the throughput
    // graph and the health findings both had too little of.
    let show_timeline = area.height >= TIMELINE_MIN_HEIGHT;
    // Interfaces sits beside connections when the row can carry both. Below
    // that the connections table cannot hold its columns next to a 44-column
    // panel — its own guard blanks the table rather than squeezing it — so
    // interfaces falls back to sharing the throughput row, which is a graph
    // and shrinks without losing meaning.
    let iface_beside_conns = area.width >= IFACE_BESIDE_CONNS_MIN_W;
    // Where the timeline goes. Stacked under interfaces it shares the column
    // that already holds the other per-interface context, and the connections
    // table keeps the full height of the row instead of giving six of its
    // rows to a strip that spans the screen. A narrow layout has no such
    // column — interfaces is up in the throughput row — so it keeps the
    // full-width strip.
    let timeline_under_interfaces = show_timeline && iface_beside_conns;
    let timeline_full_width = show_timeline && !iface_beside_conns;
    let mut constraints = vec![
        Constraint::Length(3),        // header
        Constraint::Length(KPI_ROWS), // hero row
        Constraint::Length(MID_ROWS), // throughput, and interfaces when narrow
        Constraint::Min(6),           // connections, interfaces and timeline
    ];
    if timeline_full_width {
        constraints.push(Constraint::Length(TIMELINE_ROWS));
    }
    constraints.push(Constraint::Length(3)); // footer

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    widgets::render_header(f, app, chunks[0]);
    render_kpi_strip(f, app, chunks[1]);
    render_mid_section(f, app, chunks[2], iface_beside_conns);
    render_bottom_section(
        f,
        app,
        chunks[3],
        iface_beside_conns,
        timeline_under_interfaces,
    );
    if timeline_full_width {
        render_timeline(f, app, chunks[4]);
    }
    render_footer(f, app, chunks[chunks.len() - 1]);
}

// ── KPI strip ───────────────────────────────────────────────

/// A hero-row number together with what netwatch knows about it.
///
/// The v0.29 tiles showed a value and a trend arrow, which says whether the
/// last few samples went up — not whether the number is *wrong*. `41 ms` means
/// nothing until you know the resolver normally answers in 1.2. So every tile
/// that has a baseline carries `base · σ · nominal | N.Nσ`, and the one that
/// is deviating says since when.
struct Reading {
    /// `base 1.2 · σ 0.4 · 3.2σ`, or a plain qualifier for metrics with no
    /// learned distribution.
    detail: String,
    /// Set when the metric is currently the subject of an open issue.
    since: Option<String>,
    severity: Color,
}

impl Reading {
    /// A metric with no baseline: the qualifier is whatever the tile can say
    /// for itself.
    fn plain(detail: impl Into<String>, severity: Color) -> Self {
        Self {
            detail: detail.into(),
            since: None,
            severity,
        }
    }

    /// Look up `metric` on `subject` in the baseline store and describe
    /// `value` against it.
    ///
    /// Returns the learning state rather than a verdict when the store has not
    /// seen enough samples — "still learning" is an honest thing for a hero
    /// tile to say, and inventing `nominal` from four samples is not.
    fn baselined(app: &App, subject: &str, metric: &str, value: Option<f64>) -> Self {
        let t = &app.theme;
        let store = &app.diagnose.baselines;
        let readiness = store.readiness(subject, metric);
        let Some(base) = store.get(subject, metric) else {
            return Reading::plain(readiness.label(), t.text_muted);
        };
        if !readiness.is_ready() {
            return Reading::plain(readiness.label(), t.text_muted);
        }
        let Some(v) = value else {
            return Reading::plain(
                format!("base {} · no reading", fmt_ms(base.mean)),
                t.text_muted,
            );
        };

        let sigma = base.sigma();
        let above = base.sigma_above(v).unwrap_or(0.0);
        // Only deviation upward is interesting for a latency metric: a
        // resolver answering faster than baseline is not a finding.
        let (qualifier, severity) = if above >= 3.0 {
            (format!("{above:.1}σ"), t.status_error)
        } else if above >= 2.0 {
            (format!("{above:.1}σ"), t.status_warn)
        } else {
            ("nominal".to_string(), t.status_good)
        };

        // `since` comes from the open issue, not from a second clock — the
        // tile and the Diagnose tab must not disagree about when this started.
        let rule = crate::diagnose::live::BASELINED_METRICS
            .iter()
            .find(|(m, _)| *m == metric)
            .map(|(_, r)| *r);
        let since = rule.and_then(|r| {
            app.diagnose
                .engine
                .issues()
                .iter()
                .find(|i| i.rule == r && i.state.is_open() && i.subject.label() == subject)
                .map(|i| crate::diagnose::issue::short_time(&i.since).to_string())
        });

        Reading {
            detail: format!(
                "base {} · σ {} · {qualifier}",
                fmt_ms(base.mean),
                fmt_ms(sigma)
            ),
            since,
            severity,
        }
    }
}

/// A window length as people say it: `2m14s`, `4m`, `45s`.
fn fmt_window(secs: u64) -> String {
    match (secs / 60, secs % 60) {
        (0, s) => format!("{s}s"),
        (m, 0) => format!("{m}m"),
        (m, s) => format!("{m}m{s:02}s"),
    }
}

/// Milliseconds at the precision the number deserves: sub-10ms values carry a
/// decimal because 0.1 and 0.4 are different answers, above that they do not.
fn fmt_ms(v: f64) -> String {
    if v < 10.0 {
        format!("{v:.1}")
    } else {
        format!("{v:.0}")
    }
}

/// The hero row: five tiles, each a number netwatch is prepared to defend.
///
/// The set changed from v0.29. `internet rtt` was already being probed and
/// baselined and simply never drawn — the one measurement that separates "my
/// router is fine, the line is down" from "my router is down". `retrans` took
/// the slot `throughput` held, because throughput is the panel immediately
/// below this row and a tile of the same number twice is a wasted fifth of the
/// Wall-clock span covered by `samples` taken one per health probe.
fn probe_window_secs(app: &App, samples: usize) -> u64 {
    let tick_secs = (app.user_config.refresh_rate_ms / 1000).max(1);
    samples as u64 * tick_secs * crate::app::HEALTH_PROBE_TICKS as u64
}

/// row.
fn render_kpi_strip(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 5); 5])
        .split(area);

    let t = &app.theme;
    let hs = app.health_prober.status();
    let cfg = &app.config_collector.config;
    let gw_history = rtt_history_to_u64(hs.gateway_rtt_history.as_slices().0);
    let dns_history = rtt_history_to_u64(hs.dns_rtt_history.as_slices().0);
    let net_history = rtt_history_to_u64(hs.internet_rtt_history.as_slices().0);
    let loss_history = rtt_history_to_loss(hs.gateway_rtt_history.as_slices().0);
    // Health series advance once per probe; anything sampled per tick would
    // pass `tick_secs` instead. Both land on `KPI_WINDOW_SECS`.
    let tick_secs = (app.user_config.refresh_rate_ms / 1000).max(1);
    let probe_secs = tick_secs * crate::app::HEALTH_PROBE_TICKS as u64;

    let gw_subject = cfg.gateway.clone().unwrap_or_default();
    let dns_subject = cfg.primary_dns().unwrap_or_default();

    render_kpi_tile(
        f,
        app,
        cols[0],
        "gateway rtt",
        hs.gateway_rtt_ms.map(fmt_ms),
        "ms",
        Reading::baselined(app, &gw_subject, "gateway.rtt", hs.gateway_rtt_ms),
        &gw_history,
        probe_secs,
        &["gateway."],
    );

    render_kpi_tile(
        f,
        app,
        cols[1],
        "dns rtt",
        hs.dns_rtt_ms.map(fmt_ms),
        "ms",
        Reading::baselined(app, &dns_subject, "dns.rtt_p50", hs.dns_rtt_ms),
        &dns_history,
        probe_secs,
        &["dns."],
    );

    render_kpi_tile(
        f,
        app,
        cols[2],
        "internet rtt",
        hs.internet_rtt_ms.map(fmt_ms),
        "ms",
        Reading::baselined(app, "internet", "path.rtt", hs.internet_rtt_ms),
        &net_history,
        probe_secs,
        &["path."],
    );

    // Loss has no learned distribution: the only healthy value is zero, so
    // there is nothing to be σ away from. It says what window it measured
    // over instead, which is the thing a reader would otherwise assume wrong.
    //
    // And a probe that has not completed, or could not be sent, has no loss
    // figure at all. The tile says so — with the reason — instead of the 100%
    // that used to greet every fresh start and every host with ICMP blocked.
    let measured = [hs.gateway_loss.pct(), hs.dns_loss.pct()]
        .into_iter()
        .flatten()
        .reduce(f64::max);
    let (loss_value, loss_detail, loss_color) = match measured {
        Some(max_loss) => {
            let color = if max_loss < 1.0 {
                t.status_good
            } else if max_loss < 50.0 {
                t.status_warn
            } else {
                t.status_error
            };
            // Health samples are one per probe, not one per second: counting
            // them as seconds under-reported the window by the probe cadence,
            // so a five-minute loss figure was labelled "60s".
            // Clamped to the sparkline beside it: the label names the window
            // the reader is looking at, not everything retained behind it.
            let detail = format!(
                "{}s window",
                probe_window_secs(app, hs.gateway_rtt_history.len()).min(KPI_WINDOW_SECS)
            );
            (Some(format!("{max_loss:.0}")), detail, color)
        }
        None => {
            let detail = hs
                .gateway_loss
                .note()
                .or(hs.dns_loss.note())
                .map(|why| format!("unmeasured: {why}"))
                .unwrap_or_else(|| "probing".to_string());
            (None, detail, t.text_muted)
        }
    };
    render_kpi_tile(
        f,
        app,
        cols[3],
        "loss",
        loss_value,
        "%",
        Reading::plain(loss_detail, loss_color),
        &loss_history,
        probe_secs,
        &["path.high_loss", "gateway.unreachable"],
    );

    // Retransmits per minute across every socket with tcp_info, and where they
    // are concentrated. "12/min spread over forty sockets" and "12/min all on
    // one" are different problems, and the second is the common one.
    let (retrans_per_min, worst) = session_retrans(app);
    let retrans_color = if retrans_per_min == 0.0 {
        t.status_good
    } else if retrans_per_min < 10.0 {
        t.status_warn
    } else {
        t.status_error
    };
    let retrans_detail = match worst {
        Some((peer, share)) if share >= 0.8 => format!("all on {peer}"),
        Some((peer, _)) => format!("most on {peer}"),
        None => "none in session".to_string(),
    };
    render_kpi_tile(
        f,
        app,
        cols[4],
        "retrans",
        Some(format!("{retrans_per_min:.0}")),
        "/min",
        Reading::plain(retrans_detail, retrans_color),
        &[],
        probe_secs,
        &["tcp.retrans_burst"],
    );
}

/// Session retransmits per minute, and the peer carrying most of them.
///
/// `Connection::retransmits` is a per-socket total from `tcp_info`, so the rate
/// is that total over how long netwatch has been watching. Sockets that closed
/// before this sample are not counted — the number describes what is open now,
/// which is what the tile's second line says.
fn session_retrans(app: &App) -> (f64, Option<(String, f64)>) {
    let conns = app.connection_collector.connections();
    let total: u64 = conns.iter().map(|c| c.retransmits as u64).sum();
    if total == 0 {
        return (0.0, None);
    }
    let minutes = (app.session_started_at.elapsed().as_secs_f64() / 60.0).max(1.0 / 60.0);

    let worst = conns
        .iter()
        .filter(|c| c.retransmits > 0)
        .max_by_key(|c| c.retransmits)
        .map(|c| {
            (
                remote_host_only(&c.remote_addr),
                c.retransmits as f64 / total as f64,
            )
        });
    (total as f64 / minutes, worst)
}

/// One hero tile.
///
/// ```text
/// ╭ dns rtt ─────────────────────╮   <- title in the border, severity-coloured
/// │ 41 ms              ▁▂▃▂▁     │   <- value, unit, inline history
/// │ base 1.2 · σ 0.4 · 3.2σ      │
/// │ since 06:48                  │   <- only while it is deviating
/// ╰──────────────────────────────╯
/// ```
///
/// Status reaches the reader through the label and the border, not through a
/// dot in front of the number: a coloured bullet is a fifth thing on the row
/// competing with four that carry meaning, and the spec reserves status colour
/// for the value's relationship to its threshold.
/// Whether Diagnose has an open finding behind a tile's alarm colour.
///
/// A tile alarms on a threshold; Diagnose opens an issue only once a
/// condition has been confirmed across samples and its rule has the evidence
/// it needs. The two disagreeing is normal and often correct — but a red
/// border beside a status line reading "no issues" is a contradiction on
/// screen, so the tile says which of the two it is.
fn issue_behind(app: &App, rules: &[&str]) -> bool {
    app.diagnose
        .engine
        .primary()
        .iter()
        .any(|i| rules.iter().any(|r| i.rule.starts_with(r)))
}

fn render_kpi_tile(
    f: &mut Frame,
    app: &App,
    area: Rect,
    label: &str,
    value: Option<String>,
    unit: &str,
    reading: Reading,
    history: &[u64],
    secs_per_sample: u64,
    // Diagnose rules that would explain this tile's alarm, if one fired.
    rules: &[&str],
) {
    let t = &app.theme;
    // A tile only takes a coloured border when it is actually saying
    // something. Bordering every tile green makes the amber one no louder.
    let alarmed = reading.severity == t.status_warn || reading.severity == t.status_error;
    // The title rides in the border, like every other box in the tool. It used
    // to sit on the first content row, which spent a row on a heading and made
    // the hero tiles the one panel shape that did not match the rest.
    let inner = widgets::Panel::styled(vec![Span::styled(
        label.to_string(),
        Style::default().fg(reading.severity).bold(),
    )])
    .border(if alarmed { reading.severity } else { t.border })
    .fit(area.width)
    .render(f, t, area);
    if inner.height == 0 || inner.width < 4 {
        return;
    }

    let row = |n: u16| Rect {
        x: inner.x + 1,
        y: inner.y + n,
        width: inner.width.saturating_sub(2),
        height: 1,
    };

    // Row 0 — value and unit on the left, the history sparkline on the right.
    {
        let value_line = Line::from(vec![
            Span::styled(
                value.clone().unwrap_or_else(|| "—".into()),
                Style::default().fg(t.text_primary).bold(),
            ),
            Span::styled(format!(" {unit}"), Style::default().fg(t.text_muted)),
        ]);
        let used =
            value.as_ref().map(|v| v.chars().count()).unwrap_or(1) + 1 + unit.chars().count();
        f.render_widget(Paragraph::new(value_line), row(0));

        // The sparkline takes whatever the number left, down to a floor below
        // which it is noise rather than a trend.
        let spark_w = (inner.width as usize).saturating_sub(used + 3);
        if !history.is_empty() && spark_w >= 8 {
            let spark = Rect {
                x: inner.x + inner.width - 1 - spark_w as u16,
                y: inner.y,
                width: spark_w as u16,
                height: 1,
            };
            // Onto the shared window, so a column is the same moment in every
            // tile whatever cadence fed it.
            let data = crate::graph::resample_to_window(
                history,
                secs_per_sample,
                KPI_WINDOW_SECS,
                spark_w,
            );
            let max = crate::graph::robust_max(&data, 0.95);
            crate::graph::render_bucketed_with_max(
                f,
                spark,
                &data,
                max,
                app.graph_style,
                reading.severity,
                app.graph_opts(),
            );
        }
    }

    // Row 1 — the baseline. Row 2 — when it started, or why nothing has been
    // raised about it.
    if inner.height >= 2 {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                widgets::ellipsise(&reading.detail, inner.width.saturating_sub(2) as usize),
                Style::default().fg(t.text_muted),
            ))),
            row(1),
        );
    }
    if inner.height >= 3 {
        // On its own row rather than appended to the detail: "most on
        // 54.152.65.118" already fills a fifth of the screen's width, and the
        // note is the half that got truncated when the two shared a line.
        if let Some(since) = &reading.since {
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    format!("since {since}"),
                    Style::default().fg(reading.severity),
                ))),
                row(2),
            );
        } else if alarmed && !issue_behind(app, rules) {
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "no issue raised",
                    Style::default().fg(t.text_muted),
                ))),
                row(2),
            );
        }
    }
}

// ── Mid section: Active Interface + Throughput ──────────────

/// Narrowest useful interfaces panel: a 12-column name, a full 15-character
/// IPv4, two rate columns, the status dot and the borders.
const IFACE_MIN_W: u16 = 52;

/// Widest. Past this the address column is padding — an IPv4 has been fully
/// visible since [`IFACE_MIN_W`], and the rates are fixed-width.
const IFACE_MAX_W: u16 = 68;

/// Narrowest connections panel that still draws its table: 67 columns of
/// fixed fields, 20 elastic for the remote and app names, and its borders.
const CONN_MIN_W: u16 = 89;

/// Narrowest screen that fits both on one row.
const IFACE_BESIDE_CONNS_MIN_W: u16 = CONN_MIN_W + IFACE_MIN_W;

/// How much of a row the interfaces panel takes.
///
/// A third, bounded. Fixed at its minimum it left a wide terminal spending
/// every extra column on the connections table, which already has two elastic
/// columns and does not need a third share; capped, it stops the address
/// column growing into a void once the address is fully visible.
fn iface_width(total: u16) -> u16 {
    (total / 3).clamp(IFACE_MIN_W, IFACE_MAX_W)
}

fn render_mid_section(f: &mut Frame, app: &App, area: Rect, iface_beside_conns: bool) {
    if iface_beside_conns {
        // The graph takes the whole row: more columns is literally more
        // samples on screen.
        render_throughput_chart(f, app, area);
        return;
    }
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(40),
            Constraint::Length(iface_width(area.width)),
        ])
        .split(area);

    render_throughput_chart(f, app, cols[0]);
    render_interfaces(f, app, cols[1]);
}

fn render_bottom_section(
    f: &mut Frame,
    app: &App,
    area: Rect,
    iface_beside_conns: bool,
    timeline_under_interfaces: bool,
) {
    if !iface_beside_conns {
        render_connections(f, app, area);
        return;
    }
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(40),
            Constraint::Length(iface_width(area.width)),
        ])
        .split(area);

    render_connections(f, app, cols[0]);
    // The stacked pair needs a panel's worth of rows each. Below that the
    // timeline's own guard would blank its contents and leave an empty
    // bordered box under interfaces, which is worse than no timeline.
    if !timeline_under_interfaces || cols[1].height < IFACE_MIN_ROWS + TIMELINE_ROWS {
        render_interfaces(f, app, cols[1]);
        return;
    }

    // Interfaces takes what its rows need; the timeline takes the rest. Sized
    // the other way round, a host with one interface left a panel of empty
    // bordered space above a timeline squeezed into its minimum.
    let iface_rows = interfaces_height(app, cols[1].height);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(iface_rows),
            Constraint::Min(TIMELINE_ROWS),
        ])
        .split(cols[1]);
    render_interfaces(f, app, rows[0]);
    render_timeline(f, app, rows[1]);
}

/// Rows the interfaces panel needs: a border pair, the header, one row per
/// interface that is up, and the idle summary line.
///
/// Capped so that the timeline below it always gets its minimum, and floored
/// at a panel that can still show its header — below that the panel's own
/// guard blanks it.
fn interfaces_height(app: &App, available: u16) -> u16 {
    let interfaces = app.traffic.interfaces();
    let up = active_ifaces(&interfaces, &app.interface_info).len() as u16;
    interfaces_height_for(up, available)
}

/// Split out from [`interfaces_height`] so the arithmetic is testable without
/// an `App`.
fn interfaces_height_for(up: u16, available: u16) -> u16 {
    // Border pair, header, one row per interface that is up, idle summary.
    let wanted = 2 + 1 + up + 1;
    wanted.clamp(
        IFACE_MIN_ROWS,
        available.saturating_sub(TIMELINE_ROWS).max(IFACE_MIN_ROWS),
    )
}

/// Throughput, mirrored around a shared zero line.
///
/// Two things were wrong with the stacked version. It drew rx and tx as
/// separate graphs each autoscaled to its own peak, so a 7 MB/s download and a
/// 2 MB/s upload rendered the same height — the one comparison the panel
/// exists to support was the one it could not be used for. And it had no
/// y-axis at all, so no height meant a rate.
///
/// Now both series share one maximum, rx grows up from the middle and tx grows
/// down, and the axis is labelled at the top, the zero line and the bottom.
///
/// The one exception is a very lopsided link. At 16 MB/s down and 61 KB/s up
/// the entire tx half falls below a single row, so half the panel renders
/// empty and "almost idle" cannot be told from "nothing at all". Past
/// [`SPLIT_SCALE_RATIO`] the halves take their own maxima, and the axis
/// labels — which then differ — are what says so.
/// Whether the two halves of the throughput mirror need their own scales.
///
/// Both directions have to be carrying something: one idle direction renders
/// as an empty half either way, and splitting there would magnify noise into
/// a full-height bar.
fn split_scale(rx_peak: u64, tx_peak: u64) -> bool {
    if rx_peak == 0 || tx_peak == 0 {
        return false;
    }
    rx_peak / tx_peak >= SPLIT_SCALE_RATIO || tx_peak / rx_peak >= SPLIT_SCALE_RATIO
}

fn render_throughput_chart(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let interfaces = app.traffic.interfaces();
    let actives = active_ifaces(&interfaces, &app.interface_info);

    let total_rx: f64 = actives.iter().map(|i| i.rx_rate).sum();
    let total_tx: f64 = actives.iter().map(|i| i.tx_rate).sum();
    let primary_name = actives
        .first()
        .map(|i| i.name.clone())
        .unwrap_or_else(|| "—".into());

    let agg_rx = aggregate_rx(&actives);
    let agg_tx = aggregate_tx(&actives);
    let peak = agg_rx
        .iter()
        .chain(agg_tx.iter())
        .copied()
        .max()
        .unwrap_or(0);
    let rx_peak = agg_rx.iter().copied().max().unwrap_or(0);
    let tx_peak = agg_tx.iter().copied().max().unwrap_or(0);
    // Split only when the quieter direction would otherwise be invisible, and
    // only when it has something to show: two empty halves are still better
    // read against one scale.
    let split = split_scale(rx_peak, tx_peak);
    let mean = {
        let n = agg_rx.len() + agg_tx.len();
        if n == 0 {
            0
        } else {
            (agg_rx.iter().sum::<u64>() + agg_tx.iter().sum::<u64>()) / n as u64
        }
    };

    let log = app.ui.dashboard_log_scale;
    let meta = vec![
        Span::styled("▲ rx ", Style::default().fg(t.rx_rate)),
        Span::styled(
            widgets::format_bytes_rate(total_rx),
            Style::default().fg(t.rx_rate).bold(),
        ),
        Span::styled("  ▼ tx ", Style::default().fg(t.tx_rate)),
        Span::styled(
            widgets::format_bytes_rate(total_tx),
            Style::default().fg(t.tx_rate).bold(),
        ),
        Span::styled(
            format!(
                "   peak {} · avg {}   ",
                widgets::format_bytes_rate(peak as f64),
                widgets::format_bytes_rate(mean as f64)
            ),
            Style::default().fg(t.text_muted),
        ),
        Span::styled("t", Style::default().fg(t.key_hint).bold()),
        Span::styled(
            format!(" scale {}", if log { "linear" } else { "log" }),
            Style::default().fg(t.text_muted),
        ),
    ];

    // The interface's own tab is where this graph's detail lives — driver,
    // queues, qdisc, per-direction counters — so `3` is what the badge means.
    let inner = widgets::Panel::styled(vec![
        Span::styled("throughput", Style::default().fg(t.brand).bold()),
        Span::styled(
            format!(" {primary_name}"),
            Style::default().fg(t.text_muted),
        ),
    ])
    .tab_badge(crate::app::Tab::Interfaces)
    .meta_styled(meta)
    .fit(area.width)
    .render(f, t, area);

    // One row for the x-axis, and a y-axis gutter wide enough for the largest
    // label the scale will produce.
    if inner.height < 4 || inner.width < 12 {
        return;
    }
    let axis_label = widgets::format_bytes_total(peak.max(1));
    let gutter = (axis_label.chars().count() as u16 + 1).max(4);
    let plot = Rect {
        x: inner.x + gutter,
        y: inner.y,
        width: inner.width.saturating_sub(gutter),
        height: inner.height - 1,
    };

    // Both halves share one maximum — that is the point of the mirror — and
    // one zero line, which the graph module owns so the two halves cannot
    // each draw their own.
    let axis_scale = |v: u64| {
        if log {
            log_scale(v)
        } else {
            v.max(1)
        }
    };
    let (rx_scale, tx_scale) = if split {
        (axis_scale(rx_peak), axis_scale(tx_peak))
    } else {
        (axis_scale(peak), axis_scale(peak))
    };
    let rx_plot = maybe_log(&agg_rx, log);
    let tx_plot = maybe_log(&agg_tx, log);
    let rx_h = crate::graph::render_mirrored_scaled(
        f.buffer_mut(),
        plot,
        &rx_plot,
        &tx_plot,
        rx_scale,
        tx_scale,
        app.graph_style,
        t.rx_rate,
        t.tx_rate,
        app.graph_opts(),
    );
    let tx_h = plot.height - rx_h;

    // y-axis: peak at the top, zero on the shared line, peak again at the
    // bottom — the bottom half is tx growing downward, not a negative rate.
    let mut label = |y: u16, text: String| {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                text,
                Style::default().fg(t.text_muted),
            ))),
            Rect {
                x: inner.x,
                y,
                width: gutter,
                height: 1,
            },
        );
    };
    // On a split scale the two labels differ, which is the only signal that
    // the halves are no longer to the same scale. Keep both.
    let rx_label = if split {
        widgets::format_bytes_total(rx_peak.max(1))
    } else {
        axis_label.clone()
    };
    let tx_label = if split {
        widgets::format_bytes_total(tx_peak.max(1))
    } else {
        axis_label
    };
    label(inner.y, rx_label);
    if rx_h > 0 {
        label(inner.y + rx_h - 1, "0".to_string());
    }
    if tx_h > 1 {
        label(inner.y + rx_h + tx_h - 1, tx_label);
    }

    // x-axis, derived from how many samples the plot is actually showing.
    //
    // Capacity depends on the style: braille carries two samples per column,
    // blocks one. Getting that wrong halves or doubles the window the axis
    // claims — it read `-15s` over thirty seconds of data.
    let secs = crate::graph::axis_window_secs(
        plot.width,
        app.graph_style,
        app.user_config.refresh_rate_ms,
    );
    let axis_y = inner.y + inner.height - 1;
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            crate::graph::time_axis(plot.width, secs),
            Style::default().fg(t.text_muted),
        ))),
        Rect {
            x: plot.x,
            y: axis_y,
            width: plot.width,
            height: 1,
        },
    );
}

/// Connections, ordered by concern.
///
/// v0.29 sorted by rx rate, which answers "what is busiest" — a question the
/// Stats tab already answers better. On a screen whose job is to say whether
/// anything is wrong, the socket doing 4 MB/s cleanly matters less than the
/// one doing 2 MB/s with a collapsed window, so the verdict leads the sort and
/// the rate breaks ties within it.
///
/// The `app` column is the other half: `10.88.0.3:80` and
/// `http get /blob.bin` are the same row, and only one of them tells you what
/// the machine is doing.
fn render_connections(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let groups = connection_groups(app);
    let conns: usize = groups.iter().map(|g| g.conns.len()).sum();
    let meta = if groups.len() == conns {
        format!("{conns} · sorted by concern")
    } else {
        format!("{conns} in {} processes · sorted by concern", groups.len())
    };

    let inner = widgets::Panel::new("connections")
        .tab_badge(crate::app::Tab::Connections)
        .meta_styled(vec![Span::styled(meta, Style::default().fg(t.text_muted))])
        .fit(area.width)
        .render(f, t, area);

    if inner.height < 2 || inner.width < 40 {
        return;
    }

    // Fixed columns from the right, so the two elastic ones — remote and app —
    // share whatever is left rather than each guessing.
    const PROC: u16 = 16;
    const RATE: u16 = 10;
    const RTT: u16 = 8;
    const RETR: u16 = 6;
    // `receiver-limited` is the longest verdict at 16, plus a column of gap.
    const VERDICT: u16 = 17;
    let fixed = PROC + RATE * 2 + RTT + RETR + VERDICT;
    if inner.width <= fixed + 20 {
        return;
    }
    let elastic = inner.width - fixed;
    let remote_w = elastic * 2 / 5;
    let app_w = elastic - remote_w;

    let widths = [
        Constraint::Length(PROC),
        Constraint::Length(remote_w),
        Constraint::Length(app_w),
        Constraint::Length(RATE),
        Constraint::Length(RATE),
        Constraint::Length(RTT),
        Constraint::Length(RETR),
        Constraint::Length(VERDICT),
    ];

    // No `rtt 60s` column: it was ten columns wide, its header promised a
    // sparkline, and every cell in it was the empty string. Ten columns the
    // remote and app names can actually use.
    let header = Row::new(
        [
            "process", "remote", "app", "rx/s", "tx/s", "rtt", "retr", "verdict",
        ]
        .map(|h| Cell::from(h).style(Style::default().fg(t.text_muted))),
    );

    let all = dash_rows(&groups, &app.ui.dashboard_collapsed);
    let height = inner.height.saturating_sub(1) as usize;
    // Keep the cursor on screen, through the same windowing the tabs use.
    // With no cursor the panel stays anchored at the top, which is what a
    // reader who never pressed an arrow key expects to see.
    let selected = app
        .ui
        .scroll
        .dashboard_conn_scroll
        .map(|i| i.min(all.len().saturating_sub(1)));
    let first = selected
        .map(|i| crate::ui::tree::window_top(i, all.len(), height))
        .unwrap_or(0);

    let body: Vec<Row> = all
        .iter()
        .enumerate()
        .skip(first)
        .take(height)
        .map(|(i, dr)| {
            let cells = ConnCells::new(dr, PROC as usize - 1);
            let r = &cells;
            let is_selected = selected == Some(i);
            let rate = |v: Option<f64>, color: Color| match v {
                Some(x) if x >= 1.0 => Cell::from(
                    Line::from(Span::styled(
                        widgets::format_bytes_rate(x),
                        Style::default().fg(color),
                    ))
                    .alignment(Alignment::Right),
                ),
                _ => Cell::from(
                    Line::from(Span::styled("–", Style::default().fg(t.text_muted)))
                        .alignment(Alignment::Right),
                ),
            };
            Row::new(vec![
                Cell::from(r.process.clone()).style(if r.bold {
                    Style::default().fg(t.text_primary).bold()
                } else {
                    Style::default().fg(t.text_primary)
                }),
                Cell::from(truncate(&r.remote, remote_w as usize - 1)).style(Style::default().fg(
                    if r.muted_remote {
                        // A count is not an address. Dimming it keeps the
                        // column scannable as "where is this going".
                        t.text_muted
                    } else {
                        t.text_secondary
                    },
                )),
                Cell::from(truncate(&r.app, app_w as usize - 1))
                    .style(Style::default().fg(t.text_muted)),
                rate(r.rx_rate, t.rx_rate),
                rate(r.tx_rate, t.tx_rate),
                Cell::from(
                    Line::from(Span::styled(
                        match r.rtt_ms {
                            Some(v) => format!("{}ms", fmt_ms(v)),
                            None => "–".to_string(),
                        },
                        Style::default().fg(t.text_primary),
                    ))
                    .alignment(Alignment::Right),
                ),
                Cell::from(
                    Line::from(Span::styled(
                        if r.retrans == 0 {
                            "0".to_string()
                        } else {
                            r.retrans.to_string()
                        },
                        Style::default().fg(if r.retrans > 0 {
                            t.status_warn
                        } else {
                            t.text_muted
                        }),
                    ))
                    .alignment(Alignment::Right),
                ),
                match r.verdict {
                    Some(v) => Cell::from(Line::from(widgets::socket_verdict_chip(t, v))),
                    None => Cell::from(Line::from(Span::styled(
                        "–",
                        Style::default().fg(t.text_muted),
                    ))),
                },
            ])
            .style(if is_selected {
                Style::default().bg(t.selection_bg)
            } else {
                Style::default()
            })
        })
        .collect();

    f.render_widget(
        Table::new(body, widths).header(header),
        Rect {
            x: inner.x + 1,
            width: inner.width.saturating_sub(2),
            ..inner
        },
    );
}

/// One row of the dashboard's connections panel.
struct ConnRow {
    process: String,
    remote: String,
    app: String,
    rx_rate: Option<f64>,
    tx_rate: Option<f64>,
    rtt_ms: Option<f64>,
    retrans: u32,
    verdict: Option<crate::diagnose::detectors::SocketVerdict>,
    concern: u8,
}

/// Build the rows, worst first.
///
/// Listeners and closed sockets are excluded rather than folded here: this is
/// the dashboard's summary of live traffic, and the Connections tab is where
/// the full set with its folded listener row lives.
fn connection_rows(app: &App) -> Vec<ConnRow> {
    let conns = app.connection_collector.connections();
    let mut rows: Vec<ConnRow> = conns
        .iter()
        .filter(|c| c.state != "LISTEN" && c.state != "CLOSED" && !c.remote_addr.is_empty())
        .map(|c| {
            let verdict = app
                .diagnose
                .sampler
                .verdict_for(&c.local_addr, &c.remote_addr);
            ConnRow {
                process: crate::collectors::connections::process_label(
                    c.process_name.as_deref(),
                    c.pid,
                ),
                remote: c.remote_addr.clone(),
                app: dpi_hostname(&c.app_protocol).unwrap_or_default(),
                rx_rate: c.rx_rate,
                tx_rate: c.tx_rate,
                rtt_ms: c.handshake_rtt_us.map(|us| us / 1000.0),
                retrans: c.retransmits,
                verdict,
                concern: verdict.map(widgets::socket_verdict_concern).unwrap_or(0),
            }
        })
        .collect();

    rows.sort_by(by_concern);
    rows
}

/// The cells one panel line draws, whether it came from a group or a socket.
///
/// Rendering reads this rather than branching on group-or-not at every
/// column: the two shapes differ in three cells, not nine.
struct ConnCells {
    /// Already fitted to the column, chevron or indent included — truncating
    /// afterwards would eat the glyph that says the row is foldable.
    process: String,
    remote: String,
    app: String,
    /// True when `remote` is a rollup count rather than an address.
    muted_remote: bool,
    /// Headers carry the row's weight; children sit at normal intensity
    /// beneath, the same relationship the Connections tree draws.
    bold: bool,
    rx_rate: Option<f64>,
    tx_rate: Option<f64>,
    rtt_ms: Option<f64>,
    retrans: u32,
    verdict: Option<crate::diagnose::detectors::SocketVerdict>,
}

impl ConnCells {
    fn new(row: &DashRow<'_>, proc_w: usize) -> Self {
        match row {
            DashRow::Group { group, collapsed } => Self {
                process: format!(
                    "{} {}",
                    if *collapsed { "▶" } else { "▼" },
                    truncate(&group.process, proc_w.saturating_sub(2))
                ),
                remote: format!("{} conns", group.conns.len()),
                app: if group.hosts == 1 {
                    "1 host".to_string()
                } else {
                    format!("{} hosts", group.hosts)
                },
                muted_remote: true,
                bold: true,
                rx_rate: group.rx_rate,
                tx_rate: group.tx_rate,
                rtt_ms: group.rtt_ms,
                retrans: group.retrans,
                verdict: group.verdict,
            },
            DashRow::Solo { group, conn } => Self {
                // Two columns of lead-in so solo rows line up with the group
                // names beside them rather than with their chevrons.
                process: format!("  {}", truncate(&group.process, proc_w.saturating_sub(2))),
                ..Self::from_conn(conn)
            },
            // The header already named the process. Restating it on every
            // child is exactly what the grouping removed.
            DashRow::Child { conn, .. } => Self {
                process: "    ↳".to_string(),
                ..Self::from_conn(conn)
            },
        }
    }

    fn from_conn(conn: &ConnRow) -> Self {
        Self {
            process: String::new(),
            remote: conn.remote.clone(),
            app: conn.app.clone(),
            muted_remote: false,
            bold: false,
            rx_rate: conn.rx_rate,
            tx_rate: conn.tx_rate,
            rtt_ms: conn.rtt_ms,
            retrans: conn.retrans,
            verdict: conn.verdict,
        }
    }
}

/// One line of the connections panel: a process group, or a lone socket.
///
/// The Connections tab learned this first — a flat table spends the widest
/// column repeating the string above it, and `claude` down eleven consecutive
/// rows is how the process column ends up too narrow to spell
/// `Google Chrome Helper`. The dashboard has less room than that tab, not
/// more, so groups here stay rolled up: the panel's job is "is anything
/// wrong", and the tab is where you go to open one up.
struct ConnProcess {
    process: String,
    /// The group's sockets, worst first. Length 1 renders as a plain
    /// connection row — a `1 conn` rollup hides a remote address to say
    /// nothing in its place.
    conns: Vec<ConnRow>,
    rx_rate: Option<f64>,
    tx_rate: Option<f64>,
    /// Best (lowest) handshake RTT in the group.
    rtt_ms: Option<f64>,
    retrans: u32,
    /// The group's worst verdict, so a rollup never hides a problem that
    /// would be visible on a row of its own.
    verdict: Option<crate::diagnose::detectors::SocketVerdict>,
    concern: u8,
    /// Distinct remote hosts, which is what makes a rollup worth reading:
    /// forty sockets to one host and forty to forty hosts are not the same
    /// row.
    hosts: usize,
}

/// One line of the connections panel.
///
/// A process with a single socket is a `Solo`, not a header with one child:
/// a fold control that reveals exactly one row costs a keystroke to learn
/// nothing, and the rollup would replace a remote address with `1 conn`.
enum DashRow<'a> {
    Group {
        group: &'a ConnProcess,
        collapsed: bool,
    },
    Solo {
        group: &'a ConnProcess,
        conn: &'a ConnRow,
    },
    Child {
        group: &'a ConnProcess,
        conn: &'a ConnRow,
    },
}

impl DashRow<'_> {
    /// The process this row belongs to — the same answer for a header and
    /// for any row beneath it, which is what lets `space` fold the group you
    /// are standing inside.
    fn process(&self) -> &str {
        match self {
            DashRow::Group { group, .. }
            | DashRow::Solo { group, .. }
            | DashRow::Child { group, .. } => &group.process,
        }
    }

    /// Whether folding this row's group does anything.
    fn foldable(&self) -> bool {
        !matches!(self, DashRow::Solo { .. })
    }
}

/// Flatten groups into the visible row list, honouring fold state.
///
/// Single definition of "what is row N" for the renderer and the key
/// handlers, the same discipline `ui::tree::flatten` enforces on the tabs.
fn dash_rows<'a>(groups: &'a [ConnProcess], fold: &crate::ui::tree::FoldState) -> Vec<DashRow<'a>> {
    let mut rows = Vec::new();
    for group in groups {
        if let [conn] = group.conns.as_slice() {
            rows.push(DashRow::Solo { group, conn });
            continue;
        }
        let collapsed = fold.is_collapsed(&group.process);
        rows.push(DashRow::Group { group, collapsed });
        if !collapsed {
            rows.extend(
                group
                    .conns
                    .iter()
                    .map(|conn| DashRow::Child { group, conn }),
            );
        }
    }
    rows
}

/// Number of rows the panel currently draws, for clamping the cursor.
pub fn visible_row_count(app: &App) -> usize {
    dash_rows(&connection_groups(app), &app.ui.dashboard_collapsed).len()
}

/// The process under the cursor, if the cursor is on a foldable group.
///
/// Returns `None` for a solo row so `space` on a one-socket process is a
/// no-op rather than writing an invisible fold state that only shows up
/// later, when that process opens a second connection.
pub fn selected_group_key(app: &App) -> Option<String> {
    let groups = connection_groups(app);
    let rows = dash_rows(&groups, &app.ui.dashboard_collapsed);
    let idx = app.ui.scroll.dashboard_conn_scroll?;
    let row = rows.get(idx.min(rows.len().saturating_sub(1)))?;
    row.foldable().then(|| row.process().to_string())
}

/// Row index of `process`'s header, so a collapse can park the cursor on the
/// row it just folded rather than on whatever slid up into its place.
pub fn group_header_index(app: &App, process: &str) -> Option<usize> {
    let groups = connection_groups(app);
    dash_rows(&groups, &app.ui.dashboard_collapsed)
        .iter()
        .position(|r| matches!(r, DashRow::Group { group, .. } if group.process == process))
}

/// Group [`connection_rows`] by process, worst group first.
fn connection_groups(app: &App) -> Vec<ConnProcess> {
    let rows = connection_rows(app);
    let buckets = crate::ui::tree::group_by(rows, |r: &ConnRow| r.process.clone());
    let mut groups: Vec<ConnProcess> = buckets
        .into_iter()
        .map(|(process, conns)| {
            let sum = |f: fn(&ConnRow) -> Option<f64>| {
                let vals: Vec<f64> = conns.iter().filter_map(f).collect();
                (!vals.is_empty()).then(|| vals.iter().sum())
            };
            let worst = conns.iter().max_by_key(|c| c.concern);
            let hosts: std::collections::BTreeSet<String> =
                conns.iter().map(|c| remote_host_only(&c.remote)).collect();
            ConnProcess {
                process,
                rx_rate: sum(|c| c.rx_rate),
                tx_rate: sum(|c| c.tx_rate),
                rtt_ms: conns
                    .iter()
                    .filter_map(|c| c.rtt_ms)
                    .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)),
                retrans: conns.iter().map(|c| c.retrans).sum(),
                verdict: worst.and_then(|c| c.verdict),
                concern: worst.map(|c| c.concern).unwrap_or(0),
                hosts: hosts.len(),
                conns,
            }
        })
        .collect();
    groups.sort_by(group_by_concern);
    groups
}

/// Same ordering as [`by_concern`], applied to the rollup.
fn group_by_concern(a: &ConnProcess, b: &ConnProcess) -> std::cmp::Ordering {
    b.concern
        .cmp(&a.concern)
        .then_with(|| b.retrans.cmp(&a.retrans))
        .then_with(|| {
            let ab = a.rx_rate.unwrap_or(0.0) + a.tx_rate.unwrap_or(0.0);
            let bb = b.rx_rate.unwrap_or(0.0) + b.tx_rate.unwrap_or(0.0);
            bb.partial_cmp(&ab).unwrap_or(std::cmp::Ordering::Equal)
        })
        .then_with(|| a.process.cmp(&b.process))
}

/// Worst first, then busiest, then a total order so equal rows do not
/// reshuffle every frame.
fn by_concern(a: &ConnRow, b: &ConnRow) -> std::cmp::Ordering {
    b.concern
        .cmp(&a.concern)
        .then_with(|| b.retrans.cmp(&a.retrans))
        .then_with(|| {
            let ab = a.rx_rate.unwrap_or(0.0) + a.tx_rate.unwrap_or(0.0);
            let bb = b.rx_rate.unwrap_or(0.0) + b.tx_rate.unwrap_or(0.0);
            bb.partial_cmp(&ab).unwrap_or(std::cmp::Ordering::Equal)
        })
        .then_with(|| a.process.cmp(&b.process))
        .then_with(|| a.remote.cmp(&b.remote))
}

/// Compress a rate onto a log scale, keeping zero at zero.
///
/// `ln(1 + v)` rather than `ln(v)`: a quiet second is a real measurement and
/// belongs on the baseline, not at negative infinity. Scaled by 1000 so the
/// result still has useful resolution as an integer.
fn log_scale(v: u64) -> u64 {
    (((v as f64) + 1.0).ln() * 1000.0).round() as u64
}

fn maybe_log(samples: &[u64], log: bool) -> Vec<u64> {
    if log {
        samples.iter().copied().map(log_scale).collect()
    } else {
        samples.to_vec()
    }
}

/// The incident timeline: three metrics on one time axis, with the events
/// underneath them.
///
/// Its whole value is the shared axis. Three separate sparklines elsewhere on
/// the screen cannot show that the dns rise began four minutes after the path
/// change, and that ordering is the argument every cause ranking rests on.
fn render_timeline(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let hs = app.health_prober.status();
    let interfaces = app.traffic.interfaces();
    let actives = active_ifaces(&interfaces, &app.interface_info);

    // One row per track plus one for the events. Below that there is nothing
    // useful to draw, so the panel stays empty rather than drawing a track
    // with no label or a label with no track.
    const GUTTER: u16 = 12;
    // The window is whatever the plot can show at one sample per tick — the
    // same rule the throughput chart above follows. It used to be a fixed ten
    // minutes squeezed onto ~134 columns, which is 4.5 seconds a column: the
    // strip sat still for four ticks and then lurched, and because the bucket
    // edges were anchored to "now" every sample crossed a column boundary on
    // its own tick, so the shape crawled and shimmered rather than scrolling.
    // One sample per slot, one slot per tick, everything moves together.
    let plot_w = area.width.saturating_sub(2).saturating_sub(GUTTER);
    let window_secs =
        crate::graph::axis_window_secs(plot_w, app.graph_style, app.user_config.refresh_rate_ms);
    let slots = plot_w as usize * crate::graph::samples_per_column(app.graph_style);

    let inner = widgets::Panel::new("timeline")
        .tab_badge(crate::app::Tab::Timeline)
        .meta_styled(vec![Span::styled(
            format!("last {}", fmt_window(window_secs)),
            Style::default().fg(t.text_muted),
        )])
        .fit(area.width)
        .render(f, t, area);

    if inner.height < 4 || inner.width < GUTTER + 20 {
        return;
    }
    // The window above was sized from `area` before the panel existed; the
    // border is one column each side, so this is the same number.
    debug_assert_eq!(plot_w, inner.width - GUTTER);

    let throughput: Vec<u64> = aggregate_rx(&actives)
        .into_iter()
        .zip(aggregate_tx(&actives))
        .map(|(rx, tx)| rx + tx)
        .collect();

    let tick_ms = app.user_config.refresh_rate_ms.max(1);
    let probe_ms = tick_ms * crate::app::HEALTH_PROBE_TICKS as u64;
    let window_ms = slots as u64 * tick_ms;
    let now = std::time::Instant::now();
    let tracks = [
        (
            "throughput",
            crate::graph::resample_to_window(&throughput, tick_ms, window_ms, slots),
            t.rx_rate,
        ),
        (
            "dns rtt",
            timed_rtt_track(
                &hs.dns_rtt_history,
                &hs.completed.dns_history,
                now,
                probe_ms,
                window_ms,
                slots,
            ),
            t.status_warn,
        ),
        (
            "gateway rtt",
            timed_rtt_track(
                &hs.gateway_rtt_history,
                &hs.completed.gateway_history,
                now,
                probe_ms,
                window_ms,
                slots,
            ),
            t.status_warn,
        ),
    ];

    for (i, (label, data, color)) in tracks.into_iter().enumerate() {
        let y = inner.y + i as u16;
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                truncate(label, GUTTER as usize - 1),
                Style::default().fg(t.text_muted),
            ))),
            Rect {
                x: inner.x,
                y,
                width: GUTTER,
                height: 1,
            },
        );
        // One sample per slot on the panel's shared grid. The time base is
        // common; the *scale* deliberately is not — these are different units,
        // and a shared maximum would flatten every track but throughput.
        // A ceiling one outlier cannot own — see `graph::robust_max`. With a
        // raw max, a single rtt excursion scaled every other sample to the
        // floor and the track read as a dead flat line.
        let max = crate::graph::robust_max(&data, 0.95);
        // Through the same entry point as the throughput chart, so a braille
        // column carries two consecutive samples here as it does there,
        // rather than one value doubled.
        crate::graph::render_with_max(
            f,
            Rect {
                x: inner.x + GUTTER,
                y,
                width: plot_w,
                height: 1,
            },
            &data,
            max,
            app.graph_style,
            color,
            t.status_warn,
            app.graph_opts(),
        );
    }

    // Event row: where each open issue started, placed on the same axis.
    let now = chrono::Local::now();
    let mut marks: Vec<(u16, String, Color)> = Vec::new();
    for issue in app.diagnose.engine.issues() {
        let Some(at) = crate::diagnose::engine::parse_ts(&issue.since) else {
            continue;
        };
        let age = now.signed_duration_since(at).num_seconds();
        if age < 0 || age > window_secs as i64 {
            continue;
        }
        let frac = 1.0 - (age as f32 / window_secs.max(1) as f32);
        let x = (frac * plot_w.saturating_sub(1) as f32).round() as u16;
        marks.push((
            x,
            format!(
                "▲ {} {}",
                crate::diagnose::issue::short_time(&issue.since),
                issue.title
            ),
            match issue.severity {
                crate::diagnose::Severity::Critical | crate::diagnose::Severity::High => {
                    t.status_error
                }
                crate::diagnose::Severity::Medium => t.status_warn,
                crate::diagnose::Severity::Info => t.status_info,
            },
        ));
    }
    marks.sort_by_key(|(x, _, _)| *x);

    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut col = 0usize;
    for (x, text, color) in marks {
        let x = x as usize;
        // Markers that would overlap are dropped rather than stacked: two
        // labels sharing columns is unreadable, and the events are all still
        // listed on the Timeline tab.
        if x < col {
            continue;
        }
        spans.push(Span::raw(" ".repeat(x - col)));
        col = x + text.chars().count();
        if col > plot_w as usize {
            break;
        }
        spans.push(Span::styled(text, Style::default().fg(color)));
    }
    let events_y = inner.y + 3;
    if spans.is_empty() {
        spans.push(Span::styled(
            "no events in this window",
            Style::default().fg(t.text_muted),
        ));
    }
    f.render_widget(
        Paragraph::new(Line::from(spans)),
        Rect {
            x: inner.x + GUTTER,
            y: events_y,
            width: plot_w,
            height: 1,
        },
    );
}

/// Interfaces: which links are carrying traffic, and how much.
///
/// This half of the mid band used to hold the health findings, which are the
/// Diagnose tab's subject and are already summarised by the three latency
/// tiles in the hero row above. What the dashboard had no answer for was
/// "which link is this going over" — the throughput graph beside it aggregates
/// every active interface into one series and names only the busiest in its
/// title, so a host with a VPN up and Wi-Fi underneath showed one line and no
/// way to tell which link owned it.
///
/// Addresses, MTU, queues and offload stay on the Interfaces tab. This panel
/// answers the dashboard's question — where is the traffic — and `3` opens the
/// tab that answers the rest.
fn render_interfaces(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let interfaces = app.traffic.interfaces();
    let actives = active_ifaces(&interfaces, &app.interface_info);

    // "Live" is a few seconds of history, not this tick's rate: `rx_rate` is
    // genuinely zero on most ticks even on a busy link, and counting it
    // directly made the live/idle tally flicker between bursts.
    let live = actives
        .iter()
        .filter(|i| widgets::interface_recently_active(i))
        .count();

    let inner = widgets::Panel::new("interfaces")
        .tab_badge(crate::app::Tab::Interfaces)
        .meta_styled(vec![Span::styled(
            format!("{live} live · {} up", actives.len()),
            Style::default().fg(if live == 0 {
                t.text_muted
            } else {
                t.status_good
            }),
        )])
        .fit(area.width)
        .render(f, t, area);

    if inner.height < 2 || inner.width < 28 {
        return;
    }

    const NAME_W: u16 = 12;
    const RATE_W: u16 = 9;
    // Whatever the rates and the name do not need. The address is the column
    // that degrades gracefully — a truncated IP is still recognisable, a
    // truncated rate is a wrong number.
    let addr_w = inner
        .width
        .saturating_sub(2 + NAME_W + RATE_W * 2 + 2)
        .max(4);

    let row = |x: u16, y: u16, spans: Vec<Span<'static>>| {
        (
            Paragraph::new(Line::from(spans)),
            Rect {
                x,
                y,
                width: inner.width.saturating_sub(2),
                height: 1,
            },
        )
    };

    let (header, header_area) = row(
        inner.x + 1,
        inner.y,
        // Laid out against the same widths the rows use, including the two
        // columns the status dot occupies — a header that computes its own
        // spacing is a header that drifts off the columns it names.
        vec![Span::styled(
            format!(
                "  {:<nw$}{:<aw$} {:>rw$} {:>rw$}",
                "iface",
                "address",
                "rx/s",
                "tx/s",
                nw = NAME_W as usize - 2,
                aw = addr_w as usize,
                rw = RATE_W as usize,
            ),
            Style::default().fg(t.text_muted),
        )],
    );
    f.render_widget(header, header_area);

    let mut y = inner.y + 1;
    let last_row = inner.y + inner.height;
    for iface in actives.iter() {
        // Leave the final row for the idle summary, which is the one line
        // that says the list is not the whole story.
        if y + 1 >= last_row {
            break;
        }
        let info = app.interface_info.iter().find(|i| i.name == iface.name);
        let addr = info
            .and_then(|i| i.ipv4.clone())
            .or_else(|| info.and_then(|i| i.ipv6.clone()))
            .unwrap_or_else(|| {
                crate::ui::interfaces::role_for(&iface.name, info.and_then(|i| i.is_wireless))
                    .to_string()
            });
        let hot = widgets::interface_recently_active(iface);

        let (line, line_area) = row(
            inner.x + 1,
            y,
            vec![
                Span::styled(
                    "● ",
                    Style::default().fg(if hot { t.status_good } else { t.text_muted }),
                ),
                Span::styled(
                    format!(
                        "{:<w$}",
                        truncate(&iface.name, NAME_W as usize - 2),
                        w = NAME_W as usize - 2
                    ),
                    Style::default().fg(t.text_primary),
                ),
                Span::styled(
                    format!(
                        "{:<w$}",
                        truncate(&addr, addr_w as usize),
                        w = addr_w as usize
                    ),
                    Style::default().fg(t.text_muted),
                ),
                Span::styled(
                    format!(
                        " {:>w$}",
                        widgets::format_bytes_rate(iface.rx_rate),
                        w = RATE_W as usize
                    ),
                    Style::default().fg(if hot { t.rx_rate } else { t.text_muted }),
                ),
                Span::styled(
                    format!(
                        " {:>w$}",
                        widgets::format_bytes_rate(iface.tx_rate),
                        w = RATE_W as usize
                    ),
                    Style::default().fg(if hot { t.tx_rate } else { t.text_muted }),
                ),
            ],
        );
        f.render_widget(line, line_area);
        y += 1;
    }

    if actives.is_empty() {
        let (line, line_area) = row(
            inner.x + 1,
            y,
            vec![Span::styled(
                "no interfaces up",
                Style::default().fg(t.text_muted),
            )],
        );
        f.render_widget(line, line_area);
        return;
    }

    // Everything the rows above left out: interfaces the kernel knows about
    // that are down, or up and silent. Named rather than counted — "6 idle"
    // sends you to the tab to find out which, and the names are short.
    let idle: Vec<&str> = interfaces
        .iter()
        .filter(|i| !actives.iter().any(|a| a.name == i.name))
        .map(|i| i.name.as_str())
        .collect();
    if !idle.is_empty() && y < last_row {
        let (line, line_area) = row(
            inner.x + 1,
            y,
            vec![Span::styled(
                truncate(
                    &format!("{} idle: {}", idle.len(), idle.join(" ")),
                    inner.width.saturating_sub(2) as usize,
                ),
                Style::default().fg(t.text_muted),
            )],
        );
        f.render_widget(line, line_area);
    }
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let hints = vec![
        // `↵ drill` lived here for a release with nothing bound behind it.
        widgets::hint("space", "fold"),
        widgets::hint("z", "fold all"),
        widgets::hint("9", "diagnose"),
        widgets::hint(
            "t",
            if app.ui.dashboard_log_scale {
                "scale linear"
            } else {
                "scale log"
            },
        ),
        widgets::hint("p", "pause"),
        widgets::hint(",", "settings"),
    ];
    widgets::render_footer(f, app, area, hints);
}

// ── helpers ─────────────────────────────────────────────────

/// All UP, non-loopback interfaces — used for the throughput chart and to pick
/// the primary interface. Sorted by cumulative bytes desc so the busiest iface
/// surfaces first even during idle moments.
fn active_ifaces<'a>(
    interfaces: &'a [InterfaceTraffic],
    info: &[crate::platform::InterfaceInfo],
) -> Vec<&'a InterfaceTraffic> {
    let mut v: Vec<_> = interfaces
        .iter()
        .filter(|i| {
            let is_up = info
                .iter()
                .find(|inf| inf.name == i.name)
                .map(|inf| inf.is_up)
                .unwrap_or(false);
            is_up && i.name != "lo0" && i.name != "lo"
        })
        .collect();
    v.sort_by(|a, b| {
        let a_sum = a.rx_bytes_total + a.tx_bytes_total;
        let b_sum = b.rx_bytes_total + b.tx_bytes_total;
        b_sum.cmp(&a_sum)
    });
    v
}

fn aggregate_rx(actives: &[&InterfaceTraffic]) -> Vec<u64> {
    aggregate_iter(actives.iter().map(|i| &i.rx_history))
}

fn aggregate_tx(actives: &[&InterfaceTraffic]) -> Vec<u64> {
    aggregate_iter(actives.iter().map(|i| &i.tx_history))
}

/// Sum per-interface histories onto one series, aligned at *now*.
///
/// Every history ends at the current tick and grows backwards, so the right
/// edges are the same moment and the left edges are not: an interface that
/// came up two minutes ago holds 120 samples where the one that has been up
/// all session holds 600. Summing from index 0 lined up the two oldest
/// samples instead, which slid the newcomer's entire series eight minutes
/// into the past — the graph showed traffic on a link before it existed and
/// nothing on it now.
fn aggregate_iter<'a, I>(iter: I) -> Vec<u64>
where
    I: Iterator<Item = &'a std::collections::VecDeque<u64>>,
{
    let hists: Vec<&std::collections::VecDeque<u64>> = iter.collect();
    let len = hists.iter().map(|h| h.len()).max().unwrap_or(0);
    let mut acc = vec![0u64; len];
    for hist in hists {
        let offset = len - hist.len();
        for (t, &v) in hist.iter().enumerate() {
            acc[offset + t] += v;
        }
    }
    acc
}

/// RTT history as microseconds, for plotting.
///
/// Whole milliseconds threw away everything these graphs exist to show: a LAN
/// resolver answering in 0.5ms and a gateway at 2.4ms both round to small
/// integers, so the series became 0s and 1s and any non-zero sample rendered
/// at full height. The plots only care about relative magnitude, so the unit
/// is free — microseconds keep three more digits of the variation.
fn rtt_history_to_u64(history: &[Option<f64>]) -> Vec<u64> {
    history
        .iter()
        .map(|r| r.map(|v| (v * 1000.0).round().max(0.0) as u64).unwrap_or(0))
        .collect()
}

/// Hold an observed RTT until the next result, for at most one probe period.
/// Completion times keep old spikes fixed on the axis between probe updates.
/// Missing/invalid replies and expired readings leave gaps, not zero RTTs.
fn timed_rtt_track(
    values: &std::collections::VecDeque<Option<f64>>,
    times: &std::collections::VecDeque<std::time::Instant>,
    now: std::time::Instant,
    hold_ms: u64,
    window_ms: u64,
    slots: usize,
) -> Vec<u64> {
    let mut out = vec![0; slots];
    if slots == 0 || window_ms == 0 || values.len() != times.len() {
        return out;
    }
    let window = std::time::Duration::from_millis(window_ms);
    let hold = std::time::Duration::from_millis(hold_ms);
    for (i, (&at, value)) in times.iter().zip(values).enumerate() {
        let Some(value) = value.filter(|v| v.is_finite() && *v >= 0.0) else {
            continue;
        };
        let Some(age) = now.checked_duration_since(at) else {
            continue;
        };
        let end = times
            .get(i + 1)
            .copied()
            .unwrap_or(now)
            .min(at + hold)
            .min(now);
        let end_age = now.saturating_duration_since(end);
        if end_age >= window {
            continue;
        }
        let to_slot = |age: std::time::Duration| {
            ((window.as_nanos() - age.min(window).as_nanos()) * slots as u128 / window.as_nanos())
                .min((slots - 1) as u128) as usize
        };
        let first = to_slot(age);
        // Half-open intervals: a timeout must not inherit the previous RTT.
        let last = if end == now {
            slots - 1
        } else {
            to_slot(end_age + std::time::Duration::from_nanos(1))
        };
        let value = (value * 1000.0).round().max(1.0) as u64;
        for cell in out.iter_mut().take(last + 1).skip(first) {
            *cell = (*cell).max(value);
        }
    }
    out
}

fn rtt_history_to_loss(history: &[Option<f64>]) -> Vec<u64> {
    history
        .iter()
        .map(|r| if r.is_none() { 100 } else { 0 })
        .collect()
}

/// DPI-derived display hostname for a connection, when available.
/// Used by the dashboard's TOP CONNECTIONS panel to surface real
/// hostnames (`youtube.com`) instead of raw IPs (`172.217.x.x`).
fn dpi_hostname(app_proto: &Option<crate::dpi::AppProtocol>) -> Option<String> {
    use crate::dpi::AppProtocol::*;
    match app_proto {
        Some(Tls { sni: Some(h), .. }) => Some(h.clone()),
        Some(Quic { sni: Some(h), .. }) => Some(h.clone()),
        Some(Http { host: Some(h), .. }) => Some(h.clone()),
        _ => None,
    }
}

fn remote_host_only(addr: &str) -> String {
    // Strip trailing :port; preserve [ipv6]:port → [ipv6]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::detectors::SocketVerdict;

    fn row(process: &str, verdict: Option<SocketVerdict>, rate: f64, retrans: u32) -> ConnRow {
        ConnRow {
            process: process.into(),
            remote: format!("10.0.0.1:443 [{process}]"),
            app: String::new(),
            rx_rate: Some(rate),
            tx_rate: None,
            rtt_ms: None,
            retrans,
            verdict,
            concern: verdict.map(widgets::socket_verdict_concern).unwrap_or(0),
        }
    }

    fn group(process: &str, conns: Vec<ConnRow>) -> ConnProcess {
        let worst = conns.iter().max_by_key(|c| c.concern);
        let hosts: std::collections::BTreeSet<String> =
            conns.iter().map(|c| remote_host_only(&c.remote)).collect();
        ConnProcess {
            process: process.into(),
            rx_rate: Some(conns.iter().filter_map(|c| c.rx_rate).sum()),
            tx_rate: None,
            rtt_ms: None,
            retrans: conns.iter().map(|c| c.retrans).sum(),
            verdict: worst.and_then(|c| c.verdict),
            concern: worst.map(|c| c.concern).unwrap_or(0),
            hosts: hosts.len(),
            conns,
        }
    }

    #[test]
    fn rtt_timeline_uses_real_times_and_expires_old_readings() {
        use std::{
            collections::VecDeque,
            time::{Duration, Instant},
        };
        let now = Instant::now();
        let times = VecDeque::from([now - Duration::from_secs(8), now - Duration::from_secs(2)]);
        let values = VecDeque::from([Some(0.5), Some(2.0)]);
        let data = timed_rtt_track(&values, &times, now, 3000, 10000, 10);
        assert_eq!(data, vec![0, 0, 500, 500, 500, 0, 0, 0, 2000, 2000]);
        let later = timed_rtt_track(
            &values,
            &times,
            now + Duration::from_secs(2),
            3000,
            10000,
            10,
        );
        assert_eq!(later, vec![500, 500, 500, 0, 0, 0, 2000, 2000, 2000, 0]);
    }

    #[test]
    fn rtt_timeline_keeps_timeout_gaps_and_subsecond_positions() {
        use std::{
            collections::VecDeque,
            time::{Duration, Instant},
        };
        let now = Instant::now();
        let times = VecDeque::from([
            now - Duration::from_millis(750),
            now - Duration::from_millis(250),
        ]);
        let values = VecDeque::from([Some(0.125), None]);
        assert_eq!(
            timed_rtt_track(&values, &times, now, 1000, 1000, 4),
            vec![0, 125, 125, 0]
        );
        assert_eq!(
            timed_rtt_track(&values, &VecDeque::new(), now, 1000, 1000, 4),
            vec![0; 4]
        );
    }

    #[test]
    fn window_labels_read_like_speech() {
        assert_eq!(fmt_window(45), "45s");
        assert_eq!(fmt_window(240), "4m");
        assert_eq!(fmt_window(134), "2m14s");
        assert_eq!(fmt_window(605), "10m05s");
    }

    /// The interfaces panel is a third of the row, bounded at both ends —
    /// wide enough for a full IPv4 on a small screen, and not so wide on a
    /// large one that the address column is mostly padding.
    #[test]
    fn the_interfaces_panel_takes_a_bounded_third() {
        assert_eq!(iface_width(IFACE_BESIDE_CONNS_MIN_W), IFACE_MIN_W);
        assert_eq!(
            iface_width(120),
            IFACE_MIN_W,
            "a third of 120 is under the floor"
        );
        assert_eq!(iface_width(180), 60);
        assert_eq!(iface_width(400), IFACE_MAX_W, "and it stops growing");

        // Whatever it takes, the connections table keeps enough to draw.
        for total in [IFACE_BESIDE_CONNS_MIN_W, 160, 200, 400] {
            assert!(
                total - iface_width(total) >= CONN_MIN_W,
                "{total} columns left connections {} of {CONN_MIN_W}",
                total - iface_width(total)
            );
        }
    }

    /// The verdict column was sized for a padded pill and kept that width
    /// after the pill became a plain word. It is now the longest label plus a
    /// gap, so a shrink has to be checked against the labels themselves.
    #[test]
    fn the_verdict_column_fits_the_longest_label() {
        use crate::diagnose::detectors::SocketVerdict as V;
        let widest = [
            V::Ok,
            V::Bufferbloat,
            V::ReceiverLimited,
            V::AppLimited,
            V::Congestion,
            V::RetransBurst,
            V::ZeroWindow,
        ]
        .iter()
        .map(|v| v.label().chars().count())
        .max()
        .unwrap();
        assert_eq!(widest, 16, "labels changed; the column width must follow");
    }

    /// Interface histories all end at *now* and grow backwards, so they are
    /// aligned at the right edge, never the left. A link that came up
    /// mid-session used to have its whole series pushed into the past.
    #[test]
    fn interface_histories_are_summed_at_the_present_moment() {
        use std::collections::VecDeque;
        let old: VecDeque<u64> = vec![1u64; 10].into();
        let recent: VecDeque<u64> = vec![100u64; 3].into();
        let out = aggregate_iter([&old, &recent].into_iter());

        assert_eq!(out.len(), 10);
        // The newcomer's traffic lands on the last three samples...
        assert_eq!(&out[7..], &[101, 101, 101]);
        // ...and nothing appears on it before it existed.
        assert!(out[..7].iter().all(|&v| v == 1));
    }

    /// A one-socket process is a row, not a header with one child: a fold
    /// control that reveals a single line costs a keystroke to learn nothing.
    #[test]
    fn a_solo_process_renders_as_one_unfoldable_row() {
        let groups = [group(
            "curl",
            vec![row("curl", Some(SocketVerdict::Ok), 1.0, 0)],
        )];
        let fold = crate::ui::tree::FoldState::new(true);
        let rows = dash_rows(&groups, &fold);
        assert_eq!(rows.len(), 1);
        assert!(matches!(rows[0], DashRow::Solo { .. }));
        assert!(!rows[0].foldable());
    }

    /// Folded is one row; expanded is the header plus every socket. Both
    /// answer "what is row N" through the same function the key handlers use.
    #[test]
    fn folding_a_group_hides_exactly_its_children() {
        let groups = [group(
            "claude",
            vec![
                row("claude", Some(SocketVerdict::Ok), 1.0, 0),
                row("claude", Some(SocketVerdict::Ok), 2.0, 0),
                row("claude", Some(SocketVerdict::Ok), 3.0, 0),
            ],
        )];
        let mut fold = crate::ui::tree::FoldState::new(true);
        assert_eq!(dash_rows(&groups, &fold).len(), 1);

        fold.toggle("claude");
        let rows = dash_rows(&groups, &fold);
        assert_eq!(rows.len(), 4);
        assert!(matches!(
            rows[0],
            DashRow::Group {
                collapsed: false,
                ..
            }
        ));
        assert!(rows[1..].iter().all(|r| matches!(r, DashRow::Child { .. })));
        // A child answers with its parent's name, which is what lets `space`
        // fold the group you are standing inside.
        assert!(rows.iter().all(|r| r.process() == "claude"));
    }

    /// A rollup must not launder a problem. `claude` holding one zero-window
    /// socket among nine healthy ones is exactly the case the panel exists
    /// to surface, and averaging or first-wins would bury it.
    #[test]
    fn a_group_carries_its_worst_socket_verdict() {
        let g = group(
            "claude",
            vec![
                row("claude", Some(SocketVerdict::Ok), 10.0, 0),
                row("claude", Some(SocketVerdict::ZeroWindow), 5.0, 3),
                row("claude", Some(SocketVerdict::Ok), 10.0, 0),
            ],
        );
        assert_eq!(g.verdict, Some(SocketVerdict::ZeroWindow));
        assert_eq!(
            g.concern,
            widgets::socket_verdict_concern(SocketVerdict::ZeroWindow)
        );
        // Rates and retransmits are the group's, not one member's.
        assert_eq!(g.rx_rate, Some(25.0));
        assert_eq!(g.retrans, 3);
    }

    /// Groups are ranked by the same rule as sockets were, so the panel's
    /// promise ("worst first") survives the change of row granularity.
    #[test]
    fn interfaces_keeps_the_timeline_its_rows() {
        // One interface: the panel asks for five rows and gets them.
        assert_eq!(interfaces_height_for(1, 24), 5);
        // Eight interfaces still fit: 2 borders, a header, eight rows and the
        // idle line.
        assert_eq!(interfaces_height_for(8, 24), 12);
        // Twenty would take the whole column, so the panel is capped at
        // whatever leaves the timeline its minimum.
        assert_eq!(interfaces_height_for(20, 24), 24 - TIMELINE_ROWS);
        // A column too short for both: interfaces keeps its floor, and the
        // caller's guard is what stops the timeline being drawn at all.
        assert_eq!(interfaces_height_for(4, 8), IFACE_MIN_ROWS);
        assert_eq!(interfaces_height_for(1, 0), IFACE_MIN_ROWS);
    }

    #[test]
    fn a_lopsided_link_gets_a_scale_per_direction() {
        // 16 MB/s down, 61 KB/s up: on one scale the whole tx half is under a
        // single row, so it renders empty and "almost idle" cannot be told
        // from "nothing at all".
        assert!(split_scale(16_000_000, 61_000));
        assert!(split_scale(61_000, 16_000_000), "either direction");
        // A comparable pair keeps the shared scale — that comparison is what
        // the mirror is for.
        assert!(!split_scale(4_000_000, 1_000_000));
        assert!(!split_scale(1_000, 999));
        // An idle direction stays flat rather than having its noise magnified
        // to full height.
        assert!(!split_scale(16_000_000, 0));
        assert!(!split_scale(0, 0));
    }

    #[test]
    fn groups_rank_by_concern_not_throughput() {
        let mut groups = [
            group(
                "curl",
                vec![row("curl", Some(SocketVerdict::AppLimited), 4_000_000.0, 0)],
            ),
            group(
                "sshd",
                vec![row("sshd", Some(SocketVerdict::ZeroWindow), 1_000.0, 0)],
            ),
        ];
        groups.sort_by(group_by_concern);
        let order: Vec<&str> = groups.iter().map(|g| g.process.as_str()).collect();
        assert_eq!(order, vec!["sshd", "curl"]);
    }

    /// Distinct hosts, not socket count: forty sockets to one CDN and forty
    /// to forty hosts read very differently, and the panel says which.
    #[test]
    fn host_count_dedupes_ports() {
        let mut conns = Vec::new();
        for port in [443, 8443, 9000] {
            let mut c = row("claude", Some(SocketVerdict::Ok), 1.0, 0);
            c.remote = format!("10.0.0.1:{port}");
            conns.push(c);
        }
        let mut other = row("claude", Some(SocketVerdict::Ok), 1.0, 0);
        other.remote = "10.0.0.2:443".into();
        conns.push(other);
        assert_eq!(group("claude", conns).hosts, 2);
    }

    /// The panel's job is "is anything wrong", so a broken socket outranks a
    /// fast one. v0.29 sorted by rx rate, which put the 4 MB/s healthy
    /// download above the 2 MB/s socket with a collapsed window.
    #[test]
    fn a_broken_socket_outranks_a_faster_healthy_one() {
        let mut rows = [
            row("curl", Some(SocketVerdict::AppLimited), 4_000_000.0, 0),
            row("ncat", Some(SocketVerdict::Bufferbloat), 2_000_000.0, 12),
            row("sshd", Some(SocketVerdict::ZeroWindow), 1_000.0, 0),
        ];
        rows.sort_by(by_concern);
        let order: Vec<&str> = rows.iter().map(|r| r.process.as_str()).collect();
        assert_eq!(order, vec!["sshd", "ncat", "curl"]);
    }

    /// Within one verdict the busiest wins, and identical rows keep a stable
    /// order — a list that reshuffles every frame cannot be read.
    #[test]
    fn ties_break_deterministically() {
        let mk = || {
            vec![
                row("b", Some(SocketVerdict::Ok), 10.0, 0),
                row("a", Some(SocketVerdict::Ok), 10.0, 0),
                row("c", Some(SocketVerdict::Ok), 50.0, 0),
            ]
        };
        let mut first = mk();
        first.sort_by(by_concern);
        let mut second = mk();
        second.sort_by(by_concern);
        let names =
            |v: &[ConnRow]| -> Vec<String> { v.iter().map(|r| r.process.clone()).collect() };
        assert_eq!(names(&first), vec!["c", "a", "b"]);
        assert_eq!(names(&first), names(&second));
    }

    /// Sub-10ms latency keeps a decimal because 0.1 and 0.4 are different
    /// answers; above that the decimal is noise.
    #[test]
    fn milliseconds_are_formatted_at_a_useful_precision() {
        assert_eq!(fmt_ms(0.14), "0.1");
        assert_eq!(fmt_ms(9.96), "10.0");
        assert_eq!(fmt_ms(41.4), "41");
        assert_eq!(fmt_ms(184.6), "185");
    }
}
