//! Connection-table scale: 2,000, 10,000 and 50,000 rows.
//!
//! Two tests run with the rest of the suite: a 10,000-row table renders its
//! true count and every row can be scrolled to, and the timeline keeps every
//! active entry, and the last 2,000 that closed, when 10,000 are active and
//! some close. Two more check the timings below: each timed frame follows a
//! tick, and a missed `Pending` budget fails unless `NW_PERF_STRICT=0`.
//!
//! The rest are timings, `#[ignore]`d and named `scale_*`, for a release
//! build:
//!
//! ```text
//! cargo nextest run --release --run-ignored only --no-fail-fast -E 'test(/scale_/)' --no-capture
//! ```
//!
//! They time frames on a 200x50 terminal, the scroll key, the UI tick's
//! connection consumers, and Diagnose's socket join and the socket pass
//! around it, on synthetic tables ([`crate::testutil::connections`]), and on
//! Linux a real poll of 1,000, 5,000 and 25,000 loopback TCP pairs. Each
//! case prints one `SCALE` line, which `scripts/scale-bench.sh` turns into a
//! table. `NW_SCALE_ROWS=10000` runs one size.
//!
//! Budgets apply at 10,000 rows only and are multiplied by `NW_PERF_SLACK`
//! (1 on the reference machine, 3 in CI). The 2,000 and 50,000 rows are
//! printed but not judged; 50,000 has to work, not to be fast. Diagnose's
//! whole socket pass is printed at every size and has no budget. A budget
//! today's code misses is `Pending` on the branch expected to meet it, and
//! that branch makes it `Enforced`. A missed `Pending` budget fails like any
//! other, so the command above, like a release candidate's run, passes only
//! when every budget is met. `NW_PERF_STRICT=0`, which the perf workflow
//! sets, prints it as pending and does not fail the test.

use crate::app::{draw_frame, handle_key, App, ConnectionGroup, Tab, ViewMode};
use crate::collectors::attribution::MAX_MATCH_AGE;
use crate::collectors::connections::{Connection, ConnectionTimeline, MAX_CLOSED_HISTORY};
use crate::collectors::tcp_info::{normalize_endpoint, FlowMap, TcpInfo};
use crate::config::NetwatchConfig;
use crate::diagnose::live::rows_by_endpoints;
use crate::sort::TabSortState;
use crate::testutil::connections::synthetic_connections;
use crate::ui::connections::{build_view, selected_connection, ConnRow, COLUMNS};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{backend::TestBackend, Terminal};
use std::borrow::Cow;
use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

/// The size the budgets are for.
const BUDGET_ROWS: usize = 10_000;

/// The branch expected to meet the budgets today's code misses.
const VIEW_CACHE: &str = "perf/conn-view-cache";

#[derive(Clone, Copy)]
enum Stat {
    P50,
    P99,
}

#[derive(Clone, Copy)]
enum Gate {
    Enforced,
    /// Today's code misses it, and the named branch should meet it. Fails
    /// the test unless `NW_PERF_STRICT=0`.
    Pending(&'static str),
}

#[derive(Clone, Copy)]
struct Budget {
    stat: Stat,
    ms: f64,
    gate: Gate,
}

const fn budget(stat: Stat, ms: f64, gate: Gate) -> Budget {
    Budget { stat, ms, gate }
}

const FRAME_MS: f64 = 33.0;
const CONNECTIONS_FRAME: Budget = budget(Stat::P99, FRAME_MS, Gate::Pending(VIEW_CACHE));
const FILTERED_CONNECTIONS_FRAME: Budget = budget(Stat::P99, FRAME_MS, Gate::Enforced);
const DASHBOARD_FRAME: Budget = budget(Stat::P99, FRAME_MS, Gate::Enforced);
const DENSE_FRAME: Budget = budget(Stat::P99, FRAME_MS, Gate::Pending(VIEW_CACHE));
const TOPOLOGY_FRAME: Budget = budget(Stat::P99, FRAME_MS, Gate::Enforced);
const TIMELINE_FRAME: Budget = budget(Stat::P99, FRAME_MS, Gate::Enforced);
const SCROLL_KEY: Budget = budget(Stat::P99, 5.0, Gate::Pending(VIEW_CACHE));
const TICK_CONSUMERS: Budget = budget(Stat::P50, 15.0, Gate::Pending(VIEW_CACHE));
const DIAGNOSE_JOIN: Budget = budget(Stat::P50, 2.0, Gate::Enforced);
#[cfg(target_os = "linux")]
const POLL: Budget = budget(Stat::P50, 150.0, Gate::Enforced);

fn sizes() -> Vec<usize> {
    match std::env::var("NW_SCALE_ROWS") {
        Ok(v) => v
            .split(',')
            .map(|n| {
                n.trim()
                    .parse()
                    .unwrap_or_else(|_| panic!("NW_SCALE_ROWS={v}: not a list of row counts"))
            })
            .collect(),
        Err(_) => vec![2_000, BUDGET_ROWS, 50_000],
    }
}

fn slack() -> f64 {
    match std::env::var("NW_PERF_SLACK") {
        Ok(v) => match v.trim().parse::<f64>() {
            Ok(s) if s > 0.0 => s,
            _ => panic!("NW_PERF_SLACK={v}: not a positive number"),
        },
        Err(_) => 1.0,
    }
}

/// Whether a missed `Pending` budget fails: yes, unless `NW_PERF_STRICT=0`.
fn strict() -> bool {
    strict_from(std::env::var("NW_PERF_STRICT").ok().as_deref())
}

fn strict_from(v: Option<&str>) -> bool {
    match v.map(str::trim) {
        None | Some("1") => true,
        Some("0") => false,
        Some(v) => panic!("NW_PERF_STRICT={v}: not 0 or 1"),
    }
}

/// Samples per case: enough for a p99 that is not the single worst sample,
/// except at 50,000 rows, where frames take most of a second.
fn iterations(n: usize) -> usize {
    if n > BUDGET_ROWS {
        20
    } else {
        100
    }
}

/// Collects the cases, and fails at the end if an enforced budget was
/// missed, so one slow case does not hide the numbers after it.
struct Report {
    over: Vec<String>,
    slack: f64,
    /// Whether a missed `Pending` budget fails too.
    strict: bool,
}

impl Report {
    fn from_env() -> Self {
        Self {
            over: Vec::new(),
            slack: slack(),
            strict: strict(),
        }
    }

    fn record(&mut self, case: &str, n: usize, samples: Vec<Duration>, budget: Budget) {
        let times = Times::of(samples);
        let (stat, measured) = match budget.stat {
            Stat::P50 => ("p50", times.p50),
            Stat::P99 => ("p99", times.p99),
        };
        let limit = budget.ms * self.slack;
        let within = measured <= limit;
        let status = match (n == BUDGET_ROWS, budget.gate, within) {
            (false, ..) => "unjudged".to_string(),
            (true, Gate::Enforced, true) => "ok".to_string(),
            (true, Gate::Pending(owner), true) => format!("pending-met owner={owner}"),
            (true, Gate::Pending(owner), false) if !self.strict => {
                format!("pending owner={owner}")
            }
            (true, gate, false) => {
                let owner = match gate {
                    Gate::Enforced => String::new(),
                    Gate::Pending(owner) => format!(" owner={owner}"),
                };
                self.over.push(format!(
                    "{case}: {stat} {measured:.2} ms, budget {limit:.1} ms{owner}"
                ));
                format!("over{owner}")
            }
        };
        times.print(case, n, &format!("{stat}<={limit:.1}ms"), &status);
    }

    /// Print a case that has no budget, unjudged at every size.
    fn show(&self, case: &str, n: usize, samples: Vec<Duration>) {
        Times::of(samples).print(case, n, "none", "unjudged");
    }

    fn finish(self) {
        assert!(
            self.over.is_empty(),
            "over budget at {BUDGET_ROWS} rows (NW_PERF_SLACK={}, NW_PERF_STRICT={}):\n{}",
            self.slack,
            u8::from(self.strict),
            self.over.join("\n")
        );
    }
}

/// One case's samples, in milliseconds.
struct Times {
    p50: f64,
    p99: f64,
    max: f64,
    iters: usize,
}

impl Times {
    fn of(mut samples: Vec<Duration>) -> Self {
        samples.sort();
        let ms = |d: Duration| d.as_secs_f64() * 1e3;
        // Nearest rank: the smallest sample at or above the fraction q.
        let rank = |q: f64| {
            let i = (samples.len() as f64 * q).ceil() as usize;
            ms(samples[i.clamp(1, samples.len()) - 1])
        };
        Self {
            p50: rank(0.50),
            p99: rank(0.99),
            max: ms(*samples.last().unwrap()),
            iters: samples.len(),
        }
    }

    /// The case's `SCALE` line, which `scripts/scale-bench.sh` reads.
    fn print(&self, case: &str, n: usize, budget: &str, status: &str) {
        println!(
            "SCALE case={case} rows={n} p50_ms={:.2} p99_ms={:.2} max_ms={:.2} iters={} budget={budget} status={status}",
            self.p50, self.p99, self.max, self.iters,
        );
    }
}

/// An app showing a synthetic table, as one poll and one tick leave it.
struct Host {
    app: App,
    rows: Vec<Connection>,
    /// Whether each publish carries a kernel TCP dump, as in the Dense view.
    kernel: bool,
    published: Instant,
}

impl Host {
    fn new(n: usize) -> Self {
        Self::from_rows(synthetic_connections(n, 1))
    }

    fn from_rows(rows: Vec<Connection>) -> Self {
        let mut app = App::prepare_with_config(NetwatchConfig::default());
        // Not the user's learned baseline, which would make the numbers
        // depend on whose machine this is.
        app.egress_profiler = crate::collectors::egress::EgressProfiler::new();
        app.ui.view_mode = ViewMode::Full;
        app.ui.show_geo = false;
        let mut host = Self {
            app,
            rows,
            kernel: false,
            published: Instant::now(),
        };
        host.tick();
        host
    }

    /// Add what the Dense view's kernel dump and the diagnose pass after it
    /// leave: TCP state for every established flow, and socket verdicts.
    fn with_kernel_flows(mut self) -> Self {
        self.kernel = true;
        self.publish();
        diagnose_sockets(&mut self.app);
        self
    }

    /// Publish the table again with fresh evidence, as the next poll would.
    /// Rows older than `MAX_MATCH_AGE` show as unattributed, and
    /// `connections()` copies the whole table when they go stale to say so,
    /// which is not the cost being measured. A kernel dump older than 30 s is
    /// ignored by Diagnose.
    fn publish(&mut self) {
        for row in &mut self.rows {
            row.evidence.observe();
        }
        self.app
            .connection_collector
            .publish_for_test(self.rows.clone());
        if self.kernel {
            self.app.tcp_info.publish_for_test(kernel_flows(&self.rows));
        }
        self.published = Instant::now();
    }

    /// One tick's connection work: the poll the last tick started has
    /// published the table, and the tick's consumers take it in.
    fn tick(&mut self) {
        self.publish();
        self.app.observe_connections();
    }

    /// Publish the table as a poll more than `MAX_MATCH_AGE` ago left it.
    fn publish_stale(&mut self) {
        let mut rows = self.rows.clone();
        for row in &mut rows {
            // `None` on a host up for less than that, which is stale too.
            row.evidence.observed_at =
                Instant::now().checked_sub(MAX_MATCH_AGE + Duration::from_secs(1));
        }
        self.app.connection_collector.publish_for_test(rows);
    }

    /// Time `iters` runs of `f`, after one untimed run. Republishes between
    /// runs, untimed, before the rows go stale.
    fn time(&mut self, iters: usize, mut f: impl FnMut(&mut App)) -> Vec<Duration> {
        f(&mut self.app);
        (0..iters)
            .map(|_| {
                if self.published.elapsed() > Duration::from_secs(2) {
                    self.publish();
                }
                let started = Instant::now();
                f(&mut self.app);
                started.elapsed()
            })
            .collect()
    }

    /// Time `iters` frames as an idle TUI draws them, after one untimed
    /// frame. Its loop draws once per event, and an idle TUI's only event is
    /// the tick, so every frame follows a new table: each timed frame here
    /// comes after an untimed tick, and pays for whatever is rebuilt per
    /// table.
    fn frames(&mut self, iters: usize) -> Vec<Duration> {
        let mut terminal = Terminal::new(TestBackend::new(200, 50)).unwrap();
        let mut draw = |app: &mut App| {
            terminal.draw(|f| draw_frame(f, app)).unwrap();
        };
        draw(&mut self.app);
        (0..iters)
            .map(|_| {
                self.tick();
                let started = Instant::now();
                draw(&mut self.app);
                started.elapsed()
            })
            .collect()
    }
}

/// What the kernel dump reports for `rows`: established TCP flows only, keyed
/// as `tcp_info` keys them.
fn kernel_flows(rows: &[Connection]) -> FlowMap {
    rows.iter()
        .filter(|c| c.protocol == "TCP" && c.state == "ESTABLISHED")
        .enumerate()
        .map(|(i, c)| {
            let key = (
                normalize_endpoint(&c.local_addr),
                normalize_endpoint(&c.remote_addr),
            );
            let info = TcpInfo {
                cwnd: Some(10 + (i % 90) as u32),
                ssthresh: Some(i32::MAX as u32),
                mss: Some(1_448),
                rwnd: Some(65_535),
                rtt_us: Some(12_000 + (i % 97) as u32 * 100),
                total_retrans: Some((i % 50 == 0) as u32 * 3),
            };
            (key, info)
        })
        .collect()
}

/// Diagnose's join of kernel flows to connection-table rows, as
/// `LiveSampler::sockets` makes it: the table, its index of rows by
/// endpoints, and a lookup for each flow. Returns how many flows found a row.
fn diagnose_join(app: &App) -> usize {
    let flows = app.tcp_info.snapshot();
    let conns = app.connection_collector.connections();
    let by_endpoints = rows_by_endpoints(&conns);
    flows
        .keys()
        .filter_map(|(local, remote)| {
            by_endpoints
                .get(&(
                    Cow::Borrowed(local.as_str()),
                    Cow::Borrowed(remote.as_str()),
                ))
                .copied()
        })
        .count()
}

/// One diagnose socket pass, as `tick_diagnose` runs it.
fn diagnose_sockets(app: &mut App) -> usize {
    let thresholds = app.diagnose.engine.settings().thresholds;
    let mut sampler = std::mem::take(&mut app.diagnose.sampler);
    let sockets = sampler.sockets(app, &thresholds).len();
    app.diagnose.sampler = sampler;
    sockets
}

fn press(app: &mut App, code: KeyCode) {
    assert!(!handle_key(app, KeyEvent::new(code, KeyModifiers::NONE)));
}

fn screen(app: &mut App) -> Vec<String> {
    let mut terminal = Terminal::new(TestBackend::new(200, 50)).unwrap();
    terminal.draw(|f| draw_frame(f, app)).unwrap();
    let buffer = terminal.backend().buffer();
    buffer
        .content
        .chunks(buffer.area.width as usize)
        .map(|row| row.iter().map(|c| c.symbol()).collect())
        .collect()
}

type RowKey<'a> = (&'a str, &'a str, &'a str);

fn row_key(c: &Connection) -> RowKey<'_> {
    (&c.protocol, &c.local_addr, &c.remote_addr)
}

#[test]
fn ten_thousand_rows_render_true_count() {
    let mut host = Host::new(BUDGET_ROWS);
    let app = &mut host.app;
    app.ui.current_tab = Tab::Connections;
    app.ui.connection_group = ConnectionGroup::None;
    // By local address, which no two rows share and an owner going stale
    // does not change. The default, by process, reorders the table then.
    let column = COLUMNS
        .iter()
        .position(|c| c.name == "Local Address")
        .unwrap();
    app.ui.sort_states.insert(
        Tab::Connections,
        TabSortState {
            column,
            ascending: true,
        },
    );

    let lines = screen(app);
    assert!(
        lines.iter().any(|l| l.contains("10000 connections")),
        "header does not read 10000 connections:\n{}",
        lines[..4].join("\n")
    );

    // Every row can be scrolled to: the table holds each connection once,
    // the cursor stops on the last row and not before, and the table there
    // draws the last page with the cursor on its bottom row. Stepping there
    // a key at a time rebuilds the view per key, which a debug build cannot
    // afford at this size; the clamp is what decides whether the end is
    // reachable.
    let view = build_view(app);
    let rows = view.rows(&app.ui.connection_collapsed);
    let listed: Vec<RowKey> = rows
        .iter()
        .map(|r| match r {
            ConnRow::Conn { conn } => row_key(conn),
            ConnRow::Parent { .. } => panic!("a group header under group: none"),
        })
        .collect();
    assert_eq!(listed.len(), BUDGET_ROWS);
    let published: HashSet<RowKey> = host.rows.iter().map(row_key).collect();
    assert_eq!(listed.iter().copied().collect::<HashSet<_>>(), published);
    let last = listed[BUDGET_ROWS - 1];

    // A slow machine gets here after the rows' evidence has aged past
    // `MAX_MATCH_AGE`, and from then on they show without owners. Age them
    // now, so what follows holds on any machine.
    host.publish_stale();

    let app = &mut host.app;
    press(app, KeyCode::PageDown);
    assert_eq!(app.ui.scroll.connection_scroll, 10);
    app.ui.scroll.connection_scroll = BUDGET_ROWS - 5;
    press(app, KeyCode::PageDown);
    assert_eq!(app.ui.scroll.connection_scroll, BUDGET_ROWS - 1);
    press(app, KeyCode::Down);
    assert_eq!(app.ui.scroll.connection_scroll, BUDGET_ROWS - 1);
    let selected = selected_connection(app).expect("no connection under the cursor");
    assert_eq!(row_key(&selected), last);
    let lines = screen(app);
    let header = lines
        .iter()
        .position(|l| l.contains("proto  remote"))
        .expect("no connection table on screen");
    let drawn: Vec<&String> = lines[header + 1..]
        .iter()
        .take_while(|l| l.starts_with('│'))
        .collect();
    assert!(drawn.len() > 1, "the table draws {} rows", drawn.len());
    for (line, (proto, _, remote)) in drawn.iter().zip(&listed[BUDGET_ROWS - drawn.len()..]) {
        assert!(
            line.contains(&format!("{proto:<5} {remote:<32}")),
            "the table does not end on the last {} rows: {proto} {remote} is not on\n{line}",
            drawn.len()
        );
    }
    assert!(
        drawn.last().is_some_and(|l| l.contains('▸')),
        "the cursor is not on the table's bottom row"
    );
}

#[test]
fn every_timed_frame_follows_a_tick() {
    // The tick's consumers add one sample to each row's history per tick.
    fn ticks(host: &Host) -> usize {
        host.app
            .caches
            .top_conn_history
            .values()
            .map(VecDeque::len)
            .max()
            .unwrap_or(0)
    }
    let mut host = Host::new(200);
    let before = ticks(&host);
    host.frames(5);
    assert_eq!(ticks(&host), before + 5);
}

#[test]
fn strict_fails_a_missed_pending_budget() {
    // Strict unless NW_PERF_STRICT=0, so a bare run judges every budget.
    assert!(strict_from(None));
    assert!(strict_from(Some("1")));
    assert!(!strict_from(Some("0")));

    let pending = budget(Stat::P50, 10.0, Gate::Pending(VIEW_CACHE));
    let samples = || vec![Duration::from_millis(20); 10];
    let mut report = Report {
        over: Vec::new(),
        slack: 1.0,
        strict: false,
    };
    report.record("missed", BUDGET_ROWS, samples(), pending);
    assert!(report.over.is_empty(), "{:?}", report.over);

    report.strict = true;
    report.record("unjudged", 2_000, samples(), pending);
    report.record(
        "met",
        BUDGET_ROWS,
        vec![Duration::from_millis(5); 10],
        pending,
    );
    assert!(report.over.is_empty(), "{:?}", report.over);
    report.record("missed", BUDGET_ROWS, samples(), pending);
    assert_eq!(
        report.over,
        ["missed: p50 20.00 ms, budget 10.0 ms owner=perf/conn-view-cache"]
    );
}

#[test]
fn timeline_churn_with_10k_active() {
    // 10,000 open, then 3,000 of them close as 3,000 others open.
    let table = synthetic_connections(13_000, 1);
    let mut timeline = ConnectionTimeline::new();
    timeline.update(&table[..BUDGET_ROWS]);
    timeline.update(&table[3_000..]);

    let active: HashSet<_> = timeline
        .tracked
        .iter()
        .filter(|t| t.is_active)
        .map(|t| (t.key.protocol.as_str(), t.key.local_addr.as_str()))
        .collect();
    let open: HashSet<_> = table[3_000..]
        .iter()
        .map(|c| (c.protocol.as_str(), c.local_addr.as_str()))
        .collect();
    assert_eq!(active, open, "an active connection was evicted");

    // The bound is on closed history alone: however many are active, the
    // last 2,000 that closed stay.
    let closed = timeline.tracked.iter().filter(|t| !t.is_active).count();
    assert_eq!(closed, 3_000.min(MAX_CLOSED_HISTORY));
    assert_eq!(timeline.closed_len(), closed);
    assert!(timeline.closed_trimmed());
}

#[test]
#[ignore = "release-build timing; see the module docs"]
fn scale_connections_frames() {
    let mut report = Report::from_env();
    for n in sizes() {
        let mut host = Host::new(n);
        host.app.ui.current_tab = Tab::Connections;
        for (mode, group, filter, geo, budget) in [
            (
                "process",
                ConnectionGroup::Process,
                None,
                false,
                CONNECTIONS_FRAME,
            ),
            (
                "remote",
                ConnectionGroup::Remote,
                None,
                false,
                CONNECTIONS_FRAME,
            ),
            (
                "none",
                ConnectionGroup::None,
                None,
                false,
                CONNECTIONS_FRAME,
            ),
            // About 9% of the rows match.
            (
                "filter",
                ConnectionGroup::Process,
                Some("proc-01"),
                false,
                FILTERED_CONNECTIONS_FRAME,
            ),
            // No GeoIP database is loaded, so each drawn row's lookup finds
            // nothing: this is the GEO column without one.
            (
                "geo",
                ConnectionGroup::Process,
                None,
                true,
                CONNECTIONS_FRAME,
            ),
        ] {
            host.app.ui.connection_group = group;
            host.app.ui.connection_filter_active = filter.map(String::from);
            host.app.ui.show_geo = geo;
            let samples = host.frames(iterations(n));
            report.record(&format!("frame/connections/{mode}"), n, samples, budget);
        }
    }
    report.finish();
}

#[test]
#[ignore = "release-build timing; see the module docs"]
fn scale_view_frames() {
    let mut report = Report::from_env();
    for n in sizes() {
        let mut host = Host::new(n);
        for (case, tab, budget) in [
            ("frame/dashboard", Tab::Dashboard, DASHBOARD_FRAME),
            ("frame/topology", Tab::Topology, TOPOLOGY_FRAME),
            ("frame/timeline", Tab::Timeline, TIMELINE_FRAME),
        ] {
            host.app.ui.current_tab = tab;
            let samples = host.frames(iterations(n));
            report.record(case, n, samples, budget);
        }
        // Only the Dense view asks the kernel for TCP state.
        let mut host = host.with_kernel_flows();
        host.app.ui.view_mode = ViewMode::Dense;
        let samples = host.frames(iterations(n));
        report.record("frame/dense", n, samples, DENSE_FRAME);
    }
    report.finish();
}

#[test]
#[ignore = "release-build timing; see the module docs"]
fn scale_scroll_key() {
    let mut report = Report::from_env();
    for n in sizes() {
        let mut host = Host::new(n);
        host.app.ui.current_tab = Tab::Connections;
        for (mode, group) in [
            ("process", ConnectionGroup::Process),
            ("none", ConnectionGroup::None),
        ] {
            host.app.ui.connection_group = group;
            host.app.ui.scroll.connection_scroll = 0;
            let samples = host.time(iterations(n), |app| press(app, KeyCode::Down));
            report.record(&format!("key/scroll/{mode}"), n, samples, SCROLL_KEY);
        }
    }
    report.finish();
}

#[test]
#[ignore = "release-build timing; see the module docs"]
fn scale_tick_consumers() {
    let mut report = Report::from_env();
    for n in sizes() {
        // The same table every tick.
        let mut host = Host::new(n);
        let samples = host.time(iterations(n), App::observe_connections);
        report.record("tick/steady", n, samples, TICK_CONSUMERS);

        // A tenth of the table closes and as many open on every tick.
        let churn = n / 10;
        let table = synthetic_connections(n + churn, 1);
        let tables = [table[..n].to_vec(), table[churn..].to_vec()];
        let mut host = Host::from_rows(tables[0].clone());
        let mut samples = Vec::new();
        for i in 0..iterations(n) {
            host.rows = tables[(i + 1) % 2].clone();
            host.publish();
            let started = Instant::now();
            host.app.observe_connections();
            samples.push(started.elapsed());
        }
        report.record("tick/churn", n, samples, TICK_CONSUMERS);
    }
    report.finish();
}

/// The 2 ms budget is the join's. The whole pass also builds an observation
/// and keys its verdict history for each flow, which costs several times the
/// join at 10,000 rows, and is printed with no budget.
#[test]
#[ignore = "release-build timing; see the module docs"]
fn scale_diagnose_join() {
    let mut report = Report::from_env();
    for n in sizes() {
        let mut host = Host::new(n).with_kernel_flows();
        let flows = host.app.tcp_info.snapshot().len();
        // Every flow is one of the table's established rows, bracketed IPv6
        // ones included, so every flow finds its row.
        assert_eq!(diagnose_join(&host.app), flows);
        let samples = host.time(iterations(n), |app| {
            diagnose_join(app);
        });
        report.record("diagnose/join", n, samples, DIAGNOSE_JOIN);

        assert_eq!(diagnose_sockets(&mut host.app), flows);
        let iters = if n > BUDGET_ROWS { 5 } else { 30 };
        let samples = host.time(iters, |app| {
            diagnose_sockets(app);
        });
        report.show("diagnose/sockets", n, samples);
    }
    report.finish();
}

/// `ConnectionCollector::update` end to end, from the call until its worker
/// has published, against this process's own loopback sockets. `ss` lists
/// the whole host's sockets, so run it on a quiet host.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "release-build timing; see the module docs"]
fn scale_poll_real_sockets() {
    use crate::collectors::connections::{ConnectionCollector, ProcBroker};
    use crate::collectors::packets::StreamTracker;
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};

    let mut report = Report::from_env();
    for n in sizes() {
        let pairs = n / 2;
        let need = n as u64 + 1_024;
        let limit = open_file_limit();
        assert!(
            limit >= need,
            "{n} sockets need `ulimit -n` of at least {need}; it is {limit}"
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut sockets = Vec::with_capacity(2 * pairs);
        for _ in 0..pairs {
            let client = TcpStream::connect(addr).unwrap();
            let (server, _) = listener.accept().unwrap();
            sockets.extend([client, server]);
        }

        // Sockets first, so the broker's first scan already sees them.
        let broker = ProcBroker::start(Duration::from_secs(1));
        let collector = ConnectionCollector::new(Arc::new(Mutex::new(StreamTracker::new())))
            .with_proc_broker(Arc::clone(&broker));
        let deadline = Instant::now() + Duration::from_secs(60);
        while broker.latest().is_none() {
            assert!(Instant::now() < deadline, "the broker never scanned");
            std::thread::sleep(Duration::from_millis(10));
        }

        let iters = if n > BUDGET_ROWS { 5 } else { 10 };
        let poll = || {
            collector.update();
            let deadline = Instant::now() + Duration::from_secs(60);
            while collector.poll_in_flight() {
                assert!(Instant::now() < deadline, "the poll never finished");
                std::thread::sleep(Duration::from_millis(1));
            }
        };
        poll();
        let samples: Vec<Duration> = (0..iters)
            .map(|_| {
                let started = Instant::now();
                poll();
                started.elapsed()
            })
            .collect();

        let ours = collector
            .connections()
            .iter()
            .filter(|c| c.pid == Some(std::process::id()) && c.state == "ESTABLISHED")
            .count();
        assert_eq!(
            ours,
            2 * pairs,
            "the poll missed some of this test's sockets"
        );
        report.record("poll/update", n, samples, POLL);

        // Reset rather than close, so the next size does not start with this
        // one's sockets in TIME_WAIT.
        for socket in &sockets {
            socket2::SockRef::from(socket)
                .set_linger(Some(Duration::ZERO))
                .unwrap();
        }
    }
    report.finish();
}

/// The soft `RLIMIT_NOFILE`, from `/proc/self/limits`.
#[cfg(target_os = "linux")]
fn open_file_limit() -> u64 {
    let limits = std::fs::read_to_string("/proc/self/limits").unwrap();
    let line = limits
        .lines()
        .find(|l| l.starts_with("Max open files"))
        .expect("no open-file limit in /proc/self/limits");
    match line.split_whitespace().nth(3) {
        Some("unlimited") => u64::MAX,
        Some(soft) => soft.parse().unwrap(),
        None => panic!("unreadable limit: {line}"),
    }
}
