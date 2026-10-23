//! Uptime log and report: `netwatch uptime` (#76).
//!
//! The TUI and `netwatch daemon` both append to a small log under
//! `<state>/netwatch/uptime/`, one JSON line per record and one file per UTC
//! day. A record is a process start or stop, a heartbeat, or a hop (gateway,
//! internet, DNS) changing state. The report rebuilds outages from it.
//!
//! The rules:
//!
//! - A hop is down after [`DOWN_AFTER`] probe cycles in a row with 100%
//!   measured loss, dated from the first of them, and up again at the first
//!   reply. No default gateway counts as the gateway failing, and no
//!   resolver as DNS failing. A probe that could not be sent at all
//!   (ICMP blocked and no TCP answer) measures nothing, so the hop is
//!   unknown, never down.
//! - The connection is down while any hop is down, and the outage is blamed
//!   on the nearest hop that was down: the gateway means the LAN or router,
//!   the internet hop means the ISP or beyond, DNS means name resolution
//!   alone. It is up while the internet hop answers, and unknown otherwise.
//! - Time is monitored only while records keep arriving. A gap of more than
//!   [`GAP_SECS`], or a stop, is "not monitored", never up.
//!
//! The JSON and CSV outputs are versioned (`schema`) and part of the 1.0
//! compatibility promise.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Local, NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use crate::collectors::health::{HealthStatus, Loss};

/// Consecutive fully lost probe cycles before a hop counts as down.
pub const DOWN_AFTER: u32 = 3;
/// How often a running netwatch writes a heartbeat.
pub const HEARTBEAT_SECS: u64 = 60;
/// A longer silence than this, two missed heartbeats, ends monitored time.
pub const GAP_SECS: u64 = 3 * HEARTBEAT_SECS;
/// Log files older than this are deleted when a monitor starts.
pub const RETAIN_DAYS: i64 = 90;
/// Version of the `--json` and `--csv` output.
pub const SCHEMA: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hop {
    Gateway,
    Internet,
    Dns,
}

impl Hop {
    pub const ALL: [Hop; 3] = [Hop::Gateway, Hop::Internet, Hop::Dns];

    pub fn name(self) -> &'static str {
        match self {
            Hop::Gateway => "gateway",
            Hop::Internet => "internet",
            Hop::Dns => "dns",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HopState {
    Up,
    Down,
    Unknown,
}

/// One line of the log. `t` is Unix seconds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Record {
    Start { t: u64, version: String },
    Beat { t: u64 },
    Hop { t: u64, hop: Hop, state: HopState },
    Stop { t: u64 },
}

impl Record {
    pub fn t(&self) -> u64 {
        match self {
            Record::Start { t, .. }
            | Record::Beat { t }
            | Record::Hop { t, .. }
            | Record::Stop { t } => *t,
        }
    }
}

// ── Recording ───────────────────────────────────────────────────────────────

/// What one probe cycle said about a hop.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Sample {
    Answered,
    Lost,
    Unmeasured,
}

impl Sample {
    fn from_loss(loss: Loss) -> Option<Self> {
        match loss {
            Loss::Pending => None,
            Loss::Unmeasured(_) => Some(Sample::Unmeasured),
            Loss::Measured(pct) if pct >= 100.0 => Some(Sample::Lost),
            Loss::Measured(_) => Some(Sample::Answered),
        }
    }
}

#[derive(Default)]
struct HopTrack {
    state: Option<HopState>,
    lost_run: u32,
    first_lost: Option<u64>,
}

/// The per-hop state machine, apart from probing and files so it can be
/// tested on its own.
#[derive(Default)]
pub struct Tracker {
    hops: [HopTrack; 3],
}

impl Tracker {
    /// Feed one sample; returns the record to write if the hop changed state.
    pub fn sample(&mut self, hop: Hop, sample: Sample, t: u64) -> Option<Record> {
        let h = &mut self.hops[hop as usize];
        let (state, at) = match sample {
            Sample::Answered => {
                h.lost_run = 0;
                h.first_lost = None;
                (HopState::Up, t)
            }
            Sample::Lost => {
                h.lost_run += 1;
                let first = *h.first_lost.get_or_insert(t);
                if h.lost_run < DOWN_AFTER {
                    return None;
                }
                (HopState::Down, first)
            }
            Sample::Unmeasured => {
                h.lost_run = 0;
                h.first_lost = None;
                (HopState::Unknown, t)
            }
        };
        if h.state == Some(state) {
            return None;
        }
        h.state = Some(state);
        Some(Record::Hop { t: at, hop, state })
    }
}

/// Appends records to the day's file under `dir`.
pub struct Log {
    dir: PathBuf,
}

impl Log {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn append(&self, record: &Record) -> std::io::Result<()> {
        crate::owner_only::create_dir_all(&self.dir)?;
        let path = self.dir.join(file_name(now_unix()));
        let mut file = crate::owner_only::file_options()
            .create(true)
            .append(true)
            .open(path)?;
        let mut line = serde_json::to_string(record)?;
        line.push('\n');
        file.write_all(line.as_bytes())
    }

    /// Delete day files older than [`RETAIN_DAYS`]. Returns how many went.
    pub fn prune(&self, today: NaiveDate) -> usize {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return 0;
        };
        let mut removed = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(day) = day_of(&path) else { continue };
            if (today - day).num_days() > RETAIN_DAYS && std::fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
        removed
    }
}

/// `<state>/netwatch/uptime`, beside the episodes and the egress baseline so
/// the sandbox rule that permits those permits this.
pub fn default_dir() -> Option<PathBuf> {
    crate::collectors::egress::default_profiles_path()
        .and_then(|p| p.parent().map(|d| d.join("uptime")))
}

fn file_name(t: u64) -> String {
    let day = Utc
        .timestamp_opt(t as i64, 0)
        .single()
        .map(|d| d.date_naive())
        .unwrap_or_default();
    format!("{day}.jsonl")
}

fn day_of(path: &Path) -> Option<NaiveDate> {
    let stem = path.file_name()?.to_str()?.strip_suffix(".jsonl")?;
    NaiveDate::parse_from_str(stem, "%Y-%m-%d").ok()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The connection as of now, for the Topology view.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Connection {
    /// No verdict yet, or the internet probe cannot be sent.
    Unknown,
    /// Up since `since`; `last_outage` is the one before, if this session
    /// saw one.
    Up {
        since: u64,
        last_outage: Option<LastOutage>,
    },
    Down {
        since: u64,
        hop: Hop,
    },
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LastOutage {
    pub start: u64,
    pub end: u64,
    pub hop: Hop,
}

/// Folds hop records into [`Connection`], with the same rules as
/// [`report`]: down while any hop is down, blamed on the nearest, up while
/// the internet hop answers.
struct Live {
    states: BTreeMap<Hop, HopState>,
    conn: Connection,
    last_outage: Option<LastOutage>,
}

impl Live {
    fn new() -> Self {
        Self {
            states: BTreeMap::new(),
            conn: Connection::Unknown,
            last_outage: None,
        }
    }

    fn apply(&mut self, record: &Record) {
        let Record::Hop { t, hop, state } = *record else {
            return;
        };
        self.states.insert(hop, state);
        let (now, down_hop) = overall(&self.states);
        if let Connection::Down { since, hop } = self.conn {
            match now {
                Overall::Down => {
                    let hop = hop.min(down_hop.unwrap_or(hop));
                    self.conn = Connection::Down { since, hop };
                    return;
                }
                _ => {
                    self.last_outage = Some(LastOutage {
                        start: since,
                        end: t,
                        hop,
                    })
                }
            }
        }
        self.conn = match (now, self.conn) {
            (Overall::Down, _) => Connection::Down {
                since: t,
                hop: down_hop.unwrap_or(Hop::Internet),
            },
            (Overall::Up, up @ Connection::Up { .. }) => up,
            (Overall::Up, _) => Connection::Up {
                since: t,
                last_outage: self.last_outage,
            },
            (Overall::Unknown, _) => Connection::Unknown,
        };
    }
}

/// Watches the health prober from the app tick, keeps the live
/// [`Connection`], and writes the log when it has one. Owned by the app;
/// the TUI and the daemon both tick it.
pub struct Monitor {
    log: Option<Log>,
    tracker: Tracker,
    live: Live,
    seen: [Option<std::time::Instant>; 3],
    last_beat: Option<u64>,
}

impl Monitor {
    /// `dir` is `None` in tests and demo mode, where nothing is written.
    pub fn new(dir: Option<PathBuf>) -> Self {
        Self {
            log: dir.map(Log::new),
            tracker: Tracker::default(),
            live: Live::new(),
            seen: [None; 3],
            last_beat: None,
        }
    }

    pub fn is_recording(&self) -> bool {
        self.log.is_some()
    }

    pub fn connection(&self) -> Connection {
        self.live.conn
    }

    /// A monitor showing `conn`, for rendering tests.
    #[cfg(test)]
    pub(crate) fn showing(conn: Connection) -> Self {
        let mut m = Self::new(None);
        m.live.conn = conn;
        m
    }

    /// Call every tick. `gateway` and `dns` are whether the probe cycle had a
    /// default gateway and a resolver to probe. Tracks the connection even
    /// with no log, so the Topology view works with `record_uptime` off.
    pub fn observe(&mut self, status: &HealthStatus, gateway: bool, dns: bool) {
        self.observe_at(status, gateway, dns, now_unix());
    }

    fn observe_at(&mut self, status: &HealthStatus, gateway: bool, dns: bool, t: u64) {
        let mut out = Vec::new();
        if self.last_beat.is_none() {
            if let Some(log) = &self.log {
                log.prune(Utc::now().date_naive());
            }
            out.push(Record::Start {
                t,
                version: env!("CARGO_PKG_VERSION").to_string(),
            });
            self.last_beat = Some(t);
        }
        // The internet probe runs every cycle, so its completion marks one.
        let cycle = status.completed.internet != self.seen[Hop::Internet as usize];
        for hop in Hop::ALL {
            let (completed, loss, configured) = match hop {
                Hop::Gateway => (status.completed.gateway, status.gateway_loss, gateway),
                Hop::Internet => (status.completed.internet, status.internet_loss, true),
                Hop::Dns => (status.completed.dns, status.dns_loss, dns),
            };
            let sample = if !configured {
                cycle.then_some(Sample::Lost)
            } else if completed.is_some() && completed != self.seen[hop as usize] {
                Sample::from_loss(loss)
            } else {
                None
            };
            self.seen[hop as usize] = completed;
            if let Some(record) = sample.and_then(|s| self.tracker.sample(hop, s, t)) {
                self.live.apply(&record);
                out.push(record);
            }
        }
        if self.last_beat.is_some_and(|b| t >= b + HEARTBEAT_SECS) {
            out.push(Record::Beat { t });
            self.last_beat = Some(t);
        }
        self.write(&out);
    }

    /// Call on a clean exit, so the time after it reads as not monitored at
    /// once rather than after [`GAP_SECS`].
    pub fn stop(&mut self) {
        if self.last_beat.is_some() {
            self.write(&[Record::Stop { t: now_unix() }]);
        }
    }

    fn write(&self, records: &[Record]) {
        let Some(log) = &self.log else { return };
        for record in records {
            if let Err(e) = log.append(record) {
                tracing::warn!(target: "netwatch::uptime", error = %e, "uptime record not written");
                return;
            }
        }
    }
}

// ── Report ──────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Ended {
    /// A reply came back.
    Recovered,
    /// netwatch stopped, or went quiet, while it was still down.
    MonitoringStopped,
    /// Still down as of the report.
    Ongoing,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Outage {
    pub start: u64,
    pub end: u64,
    pub hop: Hop,
    pub ended: Ended,
}

impl Outage {
    pub fn secs(&self) -> u64 {
        self.end - self.start
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Summary {
    pub outages: usize,
    pub down_secs: u64,
    pub up_secs: u64,
    pub unknown_secs: u64,
    pub unmonitored_secs: u64,
    /// Up as a share of the time known to be up or down; `None` when there
    /// is none.
    pub uptime_pct: Option<f64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Report {
    pub since: u64,
    pub until: u64,
    pub outages: Vec<Outage>,
    pub summary: Summary,
}

#[derive(Clone, Copy, PartialEq)]
enum Overall {
    Up,
    Down,
    Unknown,
}

/// Rebuild outages and totals over `[since, until]` from `records`, in any
/// order.
pub fn report(mut records: Vec<Record>, since: u64, until: u64) -> Report {
    records.sort_by_key(Record::t);
    let mut acc = Accumulator::new(since, until);
    let mut states: BTreeMap<Hop, HopState> = BTreeMap::new();
    let mut last: Option<u64> = None;
    for record in &records {
        let t = record.t().min(until);
        if let Some(l) = last {
            if t.saturating_sub(l) > GAP_SECS {
                acc.close_segment(l, &states);
                states.clear();
                last = None;
            }
        }
        match record {
            Record::Start { .. } => {
                if let Some(l) = last {
                    acc.close_segment(l, &states);
                }
                states.clear();
                last = Some(t);
                continue;
            }
            Record::Stop { .. } => {
                if let Some(l) = last {
                    acc.span(l, t, &states);
                    acc.close_segment(t, &states);
                }
                states.clear();
                last = None;
                continue;
            }
            _ => {}
        }
        // A record with no open segment, e.g. the first after a gap, opens
        // one at its own time.
        let from = last.unwrap_or(t);
        acc.span(from, t, &states);
        if let Record::Hop { hop, state, .. } = record {
            states.insert(*hop, *state);
        }
        last = Some(t);
    }
    if let Some(l) = last {
        if until.saturating_sub(l) <= GAP_SECS {
            // Still running: monitored up to now, and an outage still open
            // is ongoing.
            acc.span(l, until, &states);
            acc.finish_outage(until, Ended::Ongoing);
        } else {
            acc.close_segment(l, &states);
        }
    }
    acc.into_report()
}

fn overall(states: &BTreeMap<Hop, HopState>) -> (Overall, Option<Hop>) {
    if let Some(hop) = Hop::ALL
        .into_iter()
        .find(|h| states.get(h) == Some(&HopState::Down))
    {
        return (Overall::Down, Some(hop));
    }
    if states.get(&Hop::Internet) == Some(&HopState::Up) {
        (Overall::Up, None)
    } else {
        (Overall::Unknown, None)
    }
}

struct Accumulator {
    since: u64,
    until: u64,
    summary: Summary,
    monitored: u64,
    outages: Vec<Outage>,
    open: Option<Outage>,
}

impl Accumulator {
    fn new(since: u64, until: u64) -> Self {
        Self {
            since,
            until,
            summary: Summary::default(),
            monitored: 0,
            outages: Vec::new(),
            open: None,
        }
    }

    /// `[from, to)` was monitored with the hops in `states`.
    fn span(&mut self, from: u64, to: u64, states: &BTreeMap<Hop, HopState>) {
        let (state, hop) = overall(states);
        if state == Overall::Down {
            let hop = hop.unwrap_or(Hop::Internet);
            match &mut self.open {
                // The nearest hop seen down during the outage takes the blame.
                Some(o) => o.hop = o.hop.min(hop),
                None => {
                    self.open = Some(Outage {
                        start: from,
                        end: from,
                        hop,
                        ended: Ended::Recovered,
                    })
                }
            }
        } else {
            self.finish_outage(from, Ended::Recovered);
        }
        let (a, b) = (from.max(self.since), to.min(self.until));
        if b <= a {
            return;
        }
        let secs = b - a;
        self.monitored += secs;
        match state {
            Overall::Up => self.summary.up_secs += secs,
            Overall::Down => self.summary.down_secs += secs,
            Overall::Unknown => self.summary.unknown_secs += secs,
        }
    }

    /// Monitoring ended at `at`. Settle the state the last record left
    /// first, so a recovery recorded just before the end still counts as one.
    fn close_segment(&mut self, at: u64, states: &BTreeMap<Hop, HopState>) {
        self.span(at, at, states);
        self.finish_outage(at, Ended::MonitoringStopped);
    }

    fn finish_outage(&mut self, at: u64, ended: Ended) {
        let Some(mut o) = self.open.take() else {
            return;
        };
        o.end = at;
        o.ended = ended;
        // Clip to the report window; an outage wholly outside it is dropped.
        if o.end <= self.since || o.start >= self.until {
            return;
        }
        o.start = o.start.max(self.since);
        o.end = o.end.min(self.until);
        self.outages.push(o);
    }

    fn into_report(mut self) -> Report {
        let period = self.until.saturating_sub(self.since);
        self.summary.unmonitored_secs = period.saturating_sub(self.monitored);
        self.summary.outages = self.outages.len();
        let known = self.summary.up_secs + self.summary.down_secs;
        self.summary.uptime_pct =
            (known > 0).then(|| self.summary.up_secs as f64 * 100.0 / known as f64);
        Report {
            since: self.since,
            until: self.until,
            outages: self.outages,
            summary: self.summary,
        }
    }
}

/// Every record under `dir` from files that can hold times at or after
/// `since`. A line that does not parse is skipped, so a torn last line from
/// a crash costs that line only.
pub fn load(dir: &Path, since: u64) -> Vec<Record> {
    let first_day = Utc
        .timestamp_opt(since as i64, 0)
        .single()
        .map(|d| d.date_naive())
        .unwrap_or_default();
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        // A day file holds what was written that day, and a back-dated
        // outage start can be from the day before.
        .filter(|p| day_of(p).is_some_and(|d| d >= first_day.pred_opt().unwrap_or(d)))
        .collect();
    files.sort();
    let mut out = Vec::new();
    for path in files {
        let Ok(file) = std::fs::File::open(&path) else {
            continue;
        };
        for line in std::io::BufReader::new(file).lines().map_while(Result::ok) {
            if let Ok(record) = serde_json::from_str::<Record>(&line) {
                out.push(record);
            }
        }
    }
    out
}

// ── Command ─────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq)]
enum Format {
    Text,
    Json,
    Csv,
}

/// `netwatch uptime [--since 7d] [--json | --csv] [DIR]`
pub fn command(args: &[String]) -> anyhow::Result<()> {
    let mut since_secs = 7 * 86_400;
    let mut format = Format::Text;
    let mut dir = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--since" => {
                let v = rest
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--since needs a period, e.g. 7d"))?;
                since_secs = parse_period(v)?;
            }
            "--json" if format == Format::Text => format = Format::Json,
            "--csv" if format == Format::Text => format = Format::Csv,
            "--json" | "--csv" => anyhow::bail!("pick one of --json and --csv"),
            flag if flag.starts_with("--") => anyhow::bail!("unknown uptime option: {flag}"),
            _ if dir.is_none() => dir = Some(PathBuf::from(arg)),
            _ => anyhow::bail!("usage: netwatch uptime [--since 7d] [--json | --csv] [DIR]"),
        }
    }
    let dir = match dir {
        Some(d) => d,
        None => default_dir().ok_or_else(|| anyhow::anyhow!("no state directory"))?,
    };
    let until = now_unix();
    let since = until.saturating_sub(since_secs);
    let report = report(load(&dir, since), since, until);
    let out = match format {
        Format::Text => text(&report, &dir),
        Format::Json => serde_json::to_string_pretty(&json(&report))? + "\n",
        Format::Csv => csv(&report),
    };
    print!("{out}");
    Ok(())
}

/// `7d`, `24h`, `90m`, `3600s`, or a bare number of days.
pub fn parse_period(v: &str) -> anyhow::Result<u64> {
    let (num, unit) = match v.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => (&v[..i], c),
        _ => (v, 'd'),
    };
    let n: u64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("--since takes a period such as 7d, 24h or 90m, not {v}"))?;
    let unit = match unit {
        'd' => 86_400,
        'h' => 3_600,
        'm' => 60,
        's' => 1,
        _ => anyhow::bail!("--since units are d, h, m or s, not {unit}"),
    };
    if n == 0 {
        anyhow::bail!("--since must be longer than zero");
    }
    Ok(n.saturating_mul(unit))
}

fn local(t: u64) -> DateTime<Local> {
    Local
        .timestamp_opt(t as i64, 0)
        .single()
        .unwrap_or_else(|| Local.timestamp_opt(0, 0).unwrap())
}

/// `3h 20m`, `4m 05s`, `12s`: the two largest units.
pub fn duration(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86_400, secs / 3_600 % 24, secs / 60 % 60, secs % 60);
    match (d, h, m) {
        (0, 0, 0) => format!("{s}s"),
        (0, 0, _) => format!("{m}m {s:02}s"),
        (0, _, _) => format!("{h}h {m:02}m"),
        _ => format!("{d}d {h:02}h"),
    }
}

fn ended_label(e: Ended) -> &'static str {
    match e {
        Ended::Recovered => "",
        Ended::MonitoringStopped => "  (monitoring stopped)",
        Ended::Ongoing => "  (ongoing)",
    }
}

fn text(r: &Report, dir: &Path) -> String {
    let fmt = |t: u64| local(t).format("%Y-%m-%d %H:%M:%S").to_string();
    let mut out = format!(
        "Uptime {} → {}\n\n",
        local(r.since).format("%Y-%m-%d %H:%M"),
        local(r.until).format("%Y-%m-%d %H:%M"),
    );
    let s = &r.summary;
    if s.up_secs + s.down_secs + s.unknown_secs == 0 {
        out.push_str(&format!(
            "Nothing was monitored in this period. netwatch records uptime while\n\
             the TUI or `netwatch daemon` runs, under {}.\n",
            dir.display()
        ));
        return out;
    }
    if r.outages.is_empty() {
        out.push_str("No outages.\n");
    } else {
        out.push_str(&format!(
            "{:<19}  {:<19}  {:>8}  FAILED\n",
            "START", "END", "DURATION"
        ));
        for o in &r.outages {
            out.push_str(&format!(
                "{:<19}  {:<19}  {:>8}  {}{}\n",
                fmt(o.start),
                fmt(o.end),
                duration(o.secs()),
                o.hop.name(),
                ended_label(o.ended),
            ));
        }
        out.push_str(
            "\ngateway: your router or LAN · internet: your ISP or beyond · dns: name resolution only\n",
        );
    }
    out.push_str(&format!(
        "\n{} {}, {} down",
        s.outages,
        if s.outages == 1 { "outage" } else { "outages" },
        duration(s.down_secs),
    ));
    if let Some(pct) = s.uptime_pct {
        out.push_str(&format!(", {pct:.2}% up"));
    }
    out.push_str(&format!(
        " over {} monitored",
        duration(s.up_secs + s.down_secs + s.unknown_secs)
    ));
    // The seconds before the first probe answers are unmeasured too; only
    // mention it when it is more than that.
    if s.unknown_secs >= 60 {
        out.push_str(&format!(" ({} unmeasured)", duration(s.unknown_secs)));
    }
    out.push_str(&format!(
        "; {} not monitored\n",
        duration(s.unmonitored_secs)
    ));
    out
}

fn json(r: &Report) -> serde_json::Value {
    let ts = |t: u64| local(t).to_rfc3339();
    serde_json::json!({
        "schema": SCHEMA,
        "since": ts(r.since),
        "until": ts(r.until),
        "outages": r.outages.iter().map(|o| serde_json::json!({
            "start": ts(o.start),
            "end": ts(o.end),
            "duration_secs": o.secs(),
            "hop": o.hop,
            "ended": o.ended,
        })).collect::<Vec<_>>(),
        "summary": r.summary,
    })
}

fn csv(r: &Report) -> String {
    let ts = |t: u64| local(t).to_rfc3339();
    let mut out = String::from("start,end,duration_secs,hop,ended\n");
    for o in &r.outages {
        let ended = serde_json::to_value(o.ended)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        out.push_str(&format!(
            "{},{},{},{},{}\n",
            ts(o.start),
            ts(o.end),
            o.secs(),
            o.hop.name(),
            ended
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(t: u64, hop: Hop, state: HopState) -> Record {
        Record::Hop { t, hop, state }
    }
    fn start(t: u64) -> Record {
        Record::Start {
            t,
            version: "test".into(),
        }
    }
    fn beats(from: u64, to: u64) -> Vec<Record> {
        (from..=to)
            .step_by(HEARTBEAT_SECS as usize)
            .map(|t| Record::Beat { t })
            .collect()
    }

    #[test]
    fn a_hop_is_down_after_three_lost_cycles_dated_from_the_first() {
        let mut tr = Tracker::default();
        assert_eq!(
            tr.sample(Hop::Internet, Sample::Answered, 0),
            Some(hop(0, Hop::Internet, HopState::Up))
        );
        assert_eq!(tr.sample(Hop::Internet, Sample::Lost, 5), None);
        assert_eq!(tr.sample(Hop::Internet, Sample::Lost, 10), None);
        assert_eq!(
            tr.sample(Hop::Internet, Sample::Lost, 15),
            Some(hop(5, Hop::Internet, HopState::Down))
        );
        assert_eq!(tr.sample(Hop::Internet, Sample::Lost, 20), None);
        assert_eq!(
            tr.sample(Hop::Internet, Sample::Answered, 25),
            Some(hop(25, Hop::Internet, HopState::Up))
        );
    }

    #[test]
    fn two_lost_cycles_are_not_an_outage() {
        let mut tr = Tracker::default();
        tr.sample(Hop::Gateway, Sample::Answered, 0);
        tr.sample(Hop::Gateway, Sample::Lost, 5);
        tr.sample(Hop::Gateway, Sample::Lost, 10);
        assert_eq!(tr.sample(Hop::Gateway, Sample::Answered, 15), None);
        assert_eq!(tr.sample(Hop::Gateway, Sample::Lost, 20), None);
    }

    #[test]
    fn an_unsendable_probe_is_unknown_not_down() {
        let mut tr = Tracker::default();
        for t in 0..5 {
            let r = tr.sample(Hop::Internet, Sample::Unmeasured, t * 5);
            assert!(r.is_none() || r == Some(hop(0, Hop::Internet, HopState::Unknown)));
        }
        // And it breaks a run of losses.
        tr.sample(Hop::Internet, Sample::Lost, 30);
        tr.sample(Hop::Internet, Sample::Lost, 35);
        tr.sample(Hop::Internet, Sample::Unmeasured, 40);
        assert_eq!(tr.sample(Hop::Internet, Sample::Lost, 45), None);
    }

    #[test]
    fn an_outage_is_timed_and_blamed_on_the_nearest_hop() {
        let mut recs = vec![start(0), hop(1, Hop::Internet, HopState::Up)];
        recs.extend(beats(60, 600));
        recs.push(hop(100, Hop::Gateway, HopState::Down));
        recs.push(hop(110, Hop::Internet, HopState::Down));
        recs.push(hop(300, Hop::Gateway, HopState::Up));
        recs.push(hop(305, Hop::Internet, HopState::Up));
        recs.push(Record::Stop { t: 600 });
        let r = report(recs, 0, 600);
        assert_eq!(
            r.outages,
            vec![Outage {
                start: 100,
                end: 305,
                hop: Hop::Gateway,
                ended: Ended::Recovered
            }]
        );
        assert_eq!(r.summary.down_secs, 205);
        assert_eq!(r.summary.unknown_secs, 1);
        assert_eq!(r.summary.up_secs, 600 - 205 - 1);
        assert_eq!(r.summary.unmonitored_secs, 0);
    }

    #[test]
    fn dns_alone_is_its_own_outage() {
        let mut recs = vec![start(0), hop(0, Hop::Internet, HopState::Up)];
        recs.extend(beats(60, 300));
        recs.push(hop(50, Hop::Dns, HopState::Down));
        recs.push(hop(80, Hop::Dns, HopState::Up));
        let r = report(recs, 0, 300);
        assert_eq!(r.outages.len(), 1);
        assert_eq!(r.outages[0].hop, Hop::Dns);
        assert_eq!(r.outages[0].secs(), 30);
    }

    #[test]
    fn time_with_no_records_is_not_monitored_not_up() {
        let mut recs = vec![start(0), hop(0, Hop::Internet, HopState::Up)];
        recs.extend(beats(60, 600));
        // netwatch killed at 600 without a stop; restarted at 4000.
        recs.push(start(4000));
        recs.push(hop(4000, Hop::Internet, HopState::Up));
        recs.extend(beats(4060, 4600));
        recs.push(Record::Stop { t: 4600 });
        let r = report(recs, 0, 5000);
        assert!(r.outages.is_empty());
        assert_eq!(r.summary.up_secs, 600 + 600);
        assert_eq!(r.summary.unmonitored_secs, 5000 - 1200);
        assert_eq!(r.summary.uptime_pct, Some(100.0));
    }

    #[test]
    fn an_outage_cut_off_by_a_stop_says_so() {
        let mut recs = vec![start(0), hop(0, Hop::Internet, HopState::Up)];
        recs.extend(beats(60, 300));
        recs.push(hop(200, Hop::Internet, HopState::Down));
        recs.push(Record::Stop { t: 300 });
        let r = report(recs, 0, 1000);
        assert_eq!(r.outages[0].ended, Ended::MonitoringStopped);
        assert_eq!(r.outages[0].end, 300);
    }

    #[test]
    fn a_recovery_just_before_a_stop_or_gap_is_a_recovery() {
        let mut recs = vec![start(0), hop(0, Hop::Internet, HopState::Up)];
        recs.extend(beats(60, 120));
        recs.push(hop(130, Hop::Internet, HopState::Down));
        recs.push(hop(170, Hop::Internet, HopState::Up));
        recs.push(Record::Stop { t: 175 });
        let r = report(recs.clone(), 0, 1000);
        assert_eq!(r.outages[0].ended, Ended::Recovered);
        assert_eq!((r.outages[0].start, r.outages[0].end), (130, 170));
        // The same, killed without a stop: the log just goes quiet.
        recs.pop();
        let r = report(recs, 0, 1000);
        assert_eq!(r.outages[0].ended, Ended::Recovered);
        assert_eq!(r.outages[0].end, 170);
    }

    #[test]
    fn an_outage_still_open_now_is_ongoing() {
        let mut recs = vec![start(0), hop(0, Hop::Internet, HopState::Up)];
        recs.extend(beats(60, 300));
        recs.push(hop(250, Hop::Internet, HopState::Down));
        let r = report(recs, 0, 320);
        assert_eq!(r.outages[0].ended, Ended::Ongoing);
        assert_eq!(r.outages[0].end, 320);
        assert_eq!(r.summary.down_secs, 70);
    }

    #[test]
    fn the_window_clips_outages_and_totals() {
        let mut recs = vec![start(0), hop(0, Hop::Internet, HopState::Up)];
        recs.extend(beats(60, 1200));
        recs.push(hop(100, Hop::Internet, HopState::Down));
        recs.push(hop(700, Hop::Internet, HopState::Up));
        recs.push(Record::Stop { t: 1200 });
        let r = report(recs, 500, 1200);
        assert_eq!(r.outages[0].start, 500);
        assert_eq!(r.outages[0].end, 700);
        assert_eq!(r.summary.down_secs, 200);
        assert_eq!(r.summary.up_secs, 500);
    }

    #[test]
    fn unknown_internet_is_neither_up_nor_down() {
        let mut recs = vec![start(0), hop(0, Hop::Internet, HopState::Unknown)];
        recs.extend(beats(60, 300));
        recs.push(Record::Stop { t: 300 });
        let r = report(recs, 0, 300);
        assert_eq!(r.summary.unknown_secs, 300);
        assert_eq!(r.summary.uptime_pct, None);
    }

    #[test]
    fn records_round_trip_through_the_log_and_bad_lines_are_skipped() {
        let dir = std::env::temp_dir().join(format!("nw-uptime-{}", uuid::Uuid::new_v4()));
        let log = Log::new(dir.clone());
        let recs = vec![start(now_unix()), hop(now_unix(), Hop::Dns, HopState::Down)];
        for r in &recs {
            log.append(r).unwrap();
        }
        let path = dir.join(file_name(now_unix()));
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(b"{\"kind\":\"beat\",\"t\":").unwrap();
        assert_eq!(load(&dir, now_unix() - 60), recs);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn prune_keeps_ninety_days() {
        let dir = std::env::temp_dir().join(format!("nw-uptime-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let today = NaiveDate::from_ymd_opt(2026, 10, 24).unwrap();
        for d in ["2026-07-25", "2026-07-26", "2026-10-24", "notes.txt"] {
            std::fs::write(dir.join(format!("{d}.jsonl")), "").unwrap();
        }
        assert_eq!(Log::new(dir.clone()).prune(today), 1);
        assert!(!dir.join("2026-07-25.jsonl").exists());
        assert!(dir.join("2026-07-26.jsonl").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn live(records: &[Record]) -> Connection {
        let mut l = Live::new();
        for r in records {
            l.apply(r);
        }
        l.conn
    }

    #[test]
    fn the_live_connection_follows_the_report_rules() {
        assert_eq!(live(&[]), Connection::Unknown);
        let up = hop(10, Hop::Internet, HopState::Up);
        assert_eq!(
            live(std::slice::from_ref(&up)),
            Connection::Up {
                since: 10,
                last_outage: None
            }
        );
        // Gateway and internet both fail; the gateway takes the blame, and
        // the outage keeps its start.
        let down = [
            up.clone(),
            hop(50, Hop::Internet, HopState::Down),
            hop(52, Hop::Gateway, HopState::Down),
        ];
        assert_eq!(
            live(&down),
            Connection::Down {
                since: 50,
                hop: Hop::Gateway
            }
        );
        let mut back = down.to_vec();
        back.push(hop(90, Hop::Gateway, HopState::Up));
        assert!(matches!(live(&back), Connection::Down { since: 50, .. }));
        back.push(hop(95, Hop::Internet, HopState::Up));
        assert_eq!(
            live(&back),
            Connection::Up {
                since: 95,
                last_outage: Some(LastOutage {
                    start: 50,
                    end: 95,
                    hop: Hop::Gateway
                })
            }
        );
        // A DNS state change while up does not restart the clock.
        back.push(hop(200, Hop::Dns, HopState::Up));
        assert!(matches!(live(&back), Connection::Up { since: 95, .. }));
    }

    #[test]
    fn the_monitor_tracks_the_connection_without_a_log() {
        let mut m = Monitor::new(None);
        let mut status = (*crate::collectors::health::HealthProber::new().status()).clone();
        let t0 = std::time::Instant::now();
        for (i, loss) in [0.0, 100.0, 100.0, 100.0, 0.0].into_iter().enumerate() {
            let at = t0 + std::time::Duration::from_secs(i as u64 * 5);
            status.completed.internet = Some(at);
            status.completed.gateway = Some(at);
            status.internet_loss = Loss::Measured(loss);
            status.gateway_loss = Loss::Measured(0.0);
            m.observe_at(&status, true, false, 1000 + i as u64 * 5);
            if i == 3 {
                // No resolver configured counts as DNS failing, so DNS has
                // been down since the first cycle and takes the blame.
                assert!(matches!(m.connection(), Connection::Down { .. }));
            }
        }
        assert!(!m.is_recording());
    }

    #[test]
    fn periods_parse() {
        assert_eq!(parse_period("7d").unwrap(), 7 * 86_400);
        assert_eq!(parse_period("24h").unwrap(), 86_400);
        assert_eq!(parse_period("90m").unwrap(), 5_400);
        assert_eq!(parse_period("3").unwrap(), 3 * 86_400);
        assert!(parse_period("0d").is_err());
        assert!(parse_period("7w").is_err());
        assert!(parse_period("soon").is_err());
    }

    #[test]
    fn durations_read_naturally() {
        assert_eq!(duration(12), "12s");
        assert_eq!(duration(245), "4m 05s");
        assert_eq!(duration(12_000), "3h 20m");
        assert_eq!(duration(2 * 86_400 + 4 * 3_600), "2d 04h");
    }

    #[test]
    fn json_and_csv_carry_the_schema_and_every_outage() {
        let mut recs = vec![start(0), hop(0, Hop::Internet, HopState::Up)];
        recs.extend(beats(60, 300));
        recs.push(hop(100, Hop::Gateway, HopState::Down));
        recs.push(hop(160, Hop::Gateway, HopState::Up));
        recs.push(Record::Stop { t: 300 });
        let r = report(recs, 0, 300);
        let j = json(&r);
        assert_eq!(j["schema"], 1);
        assert_eq!(j["outages"][0]["hop"], "gateway");
        assert_eq!(j["outages"][0]["duration_secs"], 60);
        assert_eq!(j["outages"][0]["ended"], "recovered");
        assert_eq!(j["summary"]["outages"], 1);
        let c = csv(&r);
        let lines: Vec<_> = c.lines().collect();
        assert_eq!(lines[0], "start,end,duration_secs,hop,ended");
        assert!(lines[1].ends_with(",60,gateway,recovered"), "{}", lines[1]);
    }
}
