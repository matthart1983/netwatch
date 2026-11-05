//! The daemon's flow log: one NDJSON line when a connection appears in the
//! table, and one when it closes or disappears, naming the process and the
//! destination. Experimental (`[experimental] flow_log`, `daemon --flow-log`).
//!
//! It is built from the polled connection table, so it sees what a poll sees:
//! a connection that opens and closes between two polls is never logged, and
//! `open` is the poll that first listed it, not the `connect()`. Names arrive
//! after the handshake, so `close` carries the most: the SNI or HTTP `Host`,
//! the reverse-DNS name and the ASN that were known by then.
//!
//! [`FlowTracker`] turns tables into events on the caller's thread.
//! [`FlowWriter`] owns a sandboxed worker that writes them, to daily files under
//! `<cache>/netwatch/flows/` (0600, in a 0700 directory) and/or stdout. Each file
//! starts with a header line naming [`crate::schemas::FLOW`]. The queue between
//! them is bounded; what does not fit is counted and reported as a `dropped`
//! line rather than held.

use super::connections::{AttributionSource, Connection};
use super::geo::{GeoCache, GeoInfo};
use super::packets::DnsCache;
use chrono::{DateTime, NaiveDate, SecondsFormat, Utc};
use serde::Serialize;
use std::collections::HashMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

pub const FLOW_SCHEMA: &str = "netwatch.flow.v0";

/// Lines the writer may fall behind by before events are dropped. A burst of
/// this many new connections in one tick is far past normal.
const QUEUE_CAP: usize = 8192;

/// Bytes are credited as rate × elapsed per tick. Clamped, as the egress
/// profiler does, so a stalled tick does not credit minutes of traffic.
const MAX_TICK_SECS: f64 = 5.0;

/// Where the log goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowLogMode {
    Off,
    File,
    Stdout,
    Both,
}

impl FlowLogMode {
    pub fn by_name(name: &str) -> Option<Self> {
        match name {
            "off" => Some(Self::Off),
            "file" => Some(Self::File),
            "stdout" => Some(Self::Stdout),
            "both" => Some(Self::Both),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::File => "file",
            Self::Stdout => "stdout",
            Self::Both => "both",
        }
    }

    pub fn enabled(self) -> bool {
        self != Self::Off
    }

    fn file(self) -> bool {
        matches!(self, Self::File | Self::Both)
    }

    fn stdout(self) -> bool {
        matches!(self, Self::Stdout | Self::Both)
    }
}

/// What the daemon runs the log with.
#[derive(Debug, Clone)]
pub struct FlowLogConfig {
    pub mode: FlowLogMode,
    /// Directory for the daily files; `None` when there is no cache directory.
    pub dir: Option<PathBuf>,
    pub keep_days: usize,
    pub loopback: bool,
}

impl FlowLogConfig {
    /// What `cfg` asks for, after [`apply_cli`]. `None` when the log is off.
    pub fn resolve(cfg: &crate::config::NetwatchConfig) -> Option<Self> {
        let exp = &cfg.experimental;
        let mode = FlowLogMode::by_name(&exp.flow_log).filter(|m| m.enabled())?;
        Some(Self {
            mode,
            dir: configured_dir(cfg).or_else(default_dir),
            keep_days: exp.flow_log_keep_days.max(1),
            loopback: exp.flow_log_loopback,
        })
    }
}

/// `daemon --flow-log` and `--flow-log-dir` win over `[experimental]`.
pub fn apply_cli(
    cfg: &mut crate::config::NetwatchConfig,
    mode: Option<FlowLogMode>,
    dir: Option<String>,
) {
    if let Some(mode) = mode {
        cfg.experimental.flow_log = mode.name().into();
    }
    if let Some(dir) = dir {
        cfg.experimental.flow_log_dir = dir;
    }
}

/// A `flow_log_dir` the files go to, when the log writes files. It is outside
/// netwatch's own directories, so the sandbox grants it on its own.
pub fn configured_dir(cfg: &crate::config::NetwatchConfig) -> Option<PathBuf> {
    let exp = &cfg.experimental;
    let writes_files = FlowLogMode::by_name(&exp.flow_log).is_some_and(FlowLogMode::file);
    let dir = exp.flow_log_dir.trim();
    (writes_files && !dir.is_empty()).then(|| PathBuf::from(dir))
}

/// `<cache>/netwatch/flows`, beside the log files.
pub fn default_dir() -> Option<PathBuf> {
    crate::logging::log_dir().map(|d| d.join("flows"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowEventKind {
    Open,
    Close,
}

/// Why a flow closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CloseReason {
    /// The socket reached a closing TCP state.
    Closed,
    /// The socket left the table without a closing state being seen.
    Gone,
    /// The daemon stopped while the flow was open.
    Shutdown,
}

/// One line of the log.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FlowEvent {
    pub ts: String,
    pub event: FlowEventKind,
    pub proto: String,
    pub process: Option<String>,
    pub pid: Option<u32>,
    pub attribution: AttributionSource,
    pub local: String,
    pub remote: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<CloseReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_source: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rdns: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn_org: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_protocol: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retransmits: Option<u32>,
    pub observed_by: &'static str,
}

/// One `connect()` the eBPF kprobes saw: TCP, or a connected UDP socket.
/// The kernel has not picked the source address yet when they fire, so there
/// is no local side.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectSeen {
    pub proto: &'static str,
    pub pid: u32,
    /// The task's 15-character `comm`.
    pub comm: String,
    pub remote: std::net::SocketAddr,
    pub wall: SystemTime,
}

/// The line a [`ConnectSeen`] becomes.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConnectLine {
    pub ts: String,
    pub event: &'static str,
    pub proto: &'static str,
    pub process: String,
    pub pid: u32,
    pub attribution: AttributionSource,
    pub remote: String,
    pub observed_by: &'static str,
}

/// Who owns a flow socket polling found no owner for, from a source other
/// than the table: `(proto, remote ip, remote port)` to `(pid, name)`. The
/// daemon passes the eBPF connect cache, unambiguous matches only.
pub type OwnerHint<'a> = &'a dyn Fn(&str, &str, u16) -> Option<(u32, String)>;

/// A flow is its 5-tuple. Not the pid: attribution can arrive a tick late, and
/// a pid joining the key would close and reopen the same connection.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct FlowKey {
    proto: String,
    local: String,
    remote: String,
}

#[derive(Debug)]
struct FlowState {
    opened: Instant,
    /// The [`FlowTracker::tick`] that last listed it.
    seen: u64,
    /// The flow has had its `close`; the entry stays until the socket leaves
    /// the table, so a TIME-WAIT socket is not opened again.
    closed: bool,
    process: Option<String>,
    pid: Option<u32>,
    attribution: AttributionSource,
    state: String,
    host: Option<String>,
    host_source: Option<&'static str>,
    rdns: Option<String>,
    geo: Option<GeoInfo>,
    geo_looked_up: bool,
    app_protocol: Option<&'static str>,
    bytes_out: f64,
    bytes_in: f64,
    retransmits: u32,
}

impl FlowState {
    fn new(opened: Instant, attribution: AttributionSource) -> Self {
        Self {
            opened,
            seen: 0,
            closed: false,
            process: None,
            pid: None,
            attribution,
            state: String::new(),
            host: None,
            host_source: None,
            rdns: None,
            geo: None,
            geo_looked_up: false,
            app_protocol: None,
            bytes_out: 0.0,
            bytes_in: 0.0,
            retransmits: 0,
        }
    }
}

/// Turns successive connection tables into open and close events.
#[derive(Debug)]
pub struct FlowTracker {
    flows: HashMap<FlowKey, FlowState>,
    loopback: bool,
    last_observe: Option<Instant>,
    tick: u64,
}

impl FlowTracker {
    pub fn new(loopback: bool) -> Self {
        Self {
            flows: HashMap::new(),
            loopback,
            last_observe: None,
            tick: 0,
        }
    }

    /// Flows open now.
    pub fn open_len(&self) -> usize {
        self.flows.values().filter(|f| !f.closed).count()
    }

    pub fn observe(
        &mut self,
        connections: &[Connection],
        geo: &GeoCache,
        dns: &DnsCache,
        hint: OwnerHint,
    ) -> Vec<FlowEvent> {
        self.observe_at(
            connections,
            Instant::now(),
            SystemTime::now(),
            &|ip| dns.lookup(ip),
            &|ip| geo.lookup(ip),
            hint,
        )
    }

    /// The lines for connects the kprobes saw, loopback left out as for flows.
    pub fn connects(&self, seen: impl IntoIterator<Item = ConnectSeen>) -> Vec<ConnectLine> {
        seen.into_iter()
            .filter(|c| self.loopback || !is_loopback(&c.remote.ip().to_canonical().to_string()))
            .map(|c| ConnectLine {
                ts: timestamp(c.wall),
                event: "connect",
                proto: c.proto,
                process: c.comm,
                pid: c.pid,
                attribution: AttributionSource::Ebpf,
                remote: std::net::SocketAddr::new(c.remote.ip().to_canonical(), c.remote.port())
                    .to_string(),
                observed_by: "ebpf",
            })
            .collect()
    }

    fn observe_at(
        &mut self,
        connections: &[Connection],
        now: Instant,
        wall: SystemTime,
        rdns: &dyn Fn(&str) -> Option<String>,
        geo: &dyn Fn(&str) -> Option<GeoInfo>,
        hint: OwnerHint,
    ) -> Vec<FlowEvent> {
        let elapsed = self
            .last_observe
            .map(|t| {
                now.duration_since(t)
                    .as_secs_f64()
                    .clamp(0.0, MAX_TICK_SECS)
            })
            .unwrap_or(0.0);
        self.last_observe = Some(now);
        let ts = timestamp(wall);
        self.tick = self.tick.wrapping_add(1);
        let tick = self.tick;
        let mut events = Vec::new();
        // One key, rewritten for each row: nearly every row is already known,
        // and needs no key of its own.
        let mut key = FlowKey {
            proto: String::new(),
            local: String::new(),
            remote: String::new(),
        };

        for conn in connections {
            let Some(remote_ip) = loggable_remote(conn, self.loopback) else {
                continue;
            };
            key.proto.clone_from(&conn.protocol);
            key.local.clone_from(&conn.local_addr);
            key.remote.clone_from(&conn.remote_addr);
            let is_new = !self.flows.contains_key(&key);
            if is_new {
                self.flows
                    .insert(key.clone(), FlowState::new(now, conn.attribution));
            }
            let Some(flow) = self.flows.get_mut(&key) else {
                continue;
            };
            flow.seen = tick;
            update(flow, conn, remote_ip, elapsed, rdns, geo, hint);
            if is_new {
                events.push(event(&key, flow, FlowEventKind::Open, &ts, now, None));
            }
            // A flow first seen already closing (one shorter than a poll, or
            // one closing when the daemon started) gets its close at once, so
            // every flow has exactly one.
            if !flow.closed && is_closing_state(&conn.state) {
                flow.closed = true;
                events.push(event(
                    &key,
                    flow,
                    FlowEventKind::Close,
                    &ts,
                    now,
                    Some(CloseReason::Closed),
                ));
            }
        }

        let mut gone = Vec::new();
        self.flows.retain(|key, flow| {
            let keep = flow.seen == tick;
            if !keep && !flow.closed {
                gone.push(event(
                    key,
                    flow,
                    FlowEventKind::Close,
                    &ts,
                    now,
                    Some(CloseReason::Gone),
                ));
            }
            keep
        });
        gone.sort_by(|a, b| (&a.remote, &a.local).cmp(&(&b.remote, &b.local)));
        events.extend(gone);
        events
    }

    /// Close every open flow, for the daemon's shutdown.
    pub fn finish(&mut self) -> Vec<FlowEvent> {
        self.finish_at(Instant::now(), SystemTime::now())
    }

    fn finish_at(&mut self, now: Instant, wall: SystemTime) -> Vec<FlowEvent> {
        let ts = timestamp(wall);
        let mut events: Vec<FlowEvent> = self
            .flows
            .drain()
            .filter(|(_, f)| !f.closed)
            .map(|(key, flow)| {
                event(
                    &key,
                    &flow,
                    FlowEventKind::Close,
                    &ts,
                    now,
                    Some(CloseReason::Shutdown),
                )
            })
            .collect();
        events.sort_by(|a, b| (&a.remote, &a.local).cmp(&(&b.remote, &b.local)));
        events
    }
}

/// The remote IP of a connection worth logging: one with a peer, not a
/// listening socket, and off loopback unless asked for.
fn loggable_remote(conn: &Connection, loopback: bool) -> Option<&str> {
    if conn.state.eq_ignore_ascii_case("LISTEN") {
        return None;
    }
    let (Some(remote_ip), Some(_)) = crate::app::addr_parts(&conn.remote_addr) else {
        return None;
    };
    if remote_ip == "0.0.0.0" || remote_ip == "::" {
        return None;
    }
    if !loopback {
        let local_ip = crate::app::addr_parts(&conn.local_addr).0;
        if [Some(remote_ip), local_ip]
            .into_iter()
            .flatten()
            .any(is_loopback)
        {
            return None;
        }
    }
    Some(remote_ip)
}

fn is_loopback(ip: &str) -> bool {
    let ip = ip.split('%').next().unwrap_or(ip);
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(v6)) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
        Ok(addr) => addr.is_loopback(),
        Err(_) => false,
    }
}

/// TCP states after the local or remote side has started to close. The table
/// keeps such a socket for up to a minute, which is not the connection's life.
fn is_closing_state(state: &str) -> bool {
    let canonical = state.to_ascii_uppercase().replace('_', "-");
    matches!(
        canonical.as_str(),
        "FIN-WAIT-1" | "FIN-WAIT-2" | "CLOSING" | "TIME-WAIT" | "LAST-ACK" | "CLOSED" | "CLOSE"
    )
}

fn update(
    flow: &mut FlowState,
    conn: &Connection,
    remote_ip: &str,
    elapsed: f64,
    rdns: &dyn Fn(&str) -> Option<String>,
    geo: &dyn Fn(&str) -> Option<GeoInfo>,
    hint: OwnerHint,
) {
    flow.state.clone_from(&conn.state);
    // Attribution can arrive late or improve; an unattributed tick never
    // erases what an earlier one learned.
    if conn.process_name.is_some() {
        flow.process.clone_from(&conn.process_name);
        flow.attribution = conn.attribution;
    }
    if conn.pid.is_some() {
        flow.pid = conn.pid;
    }
    // Polling found no owner (another user's socket without the broker's
    // capabilities, or one caught closing): take the process the connect
    // kprobe saw, if it agrees with any pid the table does have. A verified
    // owner on a later tick replaces it.
    if flow.process.is_none() && conn.process_name.is_none() {
        let port = crate::app::addr_parts(&conn.remote_addr)
            .1
            .and_then(|p| p.parse::<u16>().ok());
        if let Some((pid, comm)) = port.and_then(|port| hint(&conn.protocol, remote_ip, port)) {
            if conn.pid.is_none_or(|p| p == pid) {
                flow.process = Some(comm);
                flow.pid = Some(pid);
                flow.attribution = AttributionSource::Ebpf;
            }
        }
    }
    if flow.host.is_none() {
        if let Some(host) = super::egress::dest_hostname(&conn.app_protocol) {
            flow.host_source = Some(if super::egress::flow_http_host(&conn.app_protocol) {
                "http"
            } else {
                "sni"
            });
            flow.host = Some(host);
        }
    }
    if let Some(p) = &conn.app_protocol {
        flow.app_protocol = Some(p.tag());
    }
    if flow.rdns.is_none() {
        flow.rdns = rdns(remote_ip);
    }
    if !flow.geo_looked_up {
        flow.geo_looked_up = true;
        flow.geo = geo(remote_ip);
    }
    if !flow.closed {
        flow.bytes_out += (conn.tx_rate.unwrap_or(0.0) * elapsed).max(0.0);
        flow.bytes_in += (conn.rx_rate.unwrap_or(0.0) * elapsed).max(0.0);
    }
    flow.retransmits = flow.retransmits.max(conn.retransmits);
}

fn event(
    key: &FlowKey,
    flow: &FlowState,
    kind: FlowEventKind,
    ts: &str,
    now: Instant,
    reason: Option<CloseReason>,
) -> FlowEvent {
    let close = kind == FlowEventKind::Close;
    let nonempty = |s: &str| (!s.is_empty()).then(|| s.to_string());
    FlowEvent {
        ts: ts.to_string(),
        event: kind,
        proto: key.proto.clone(),
        process: flow.process.clone(),
        pid: flow.pid,
        attribution: flow.attribution,
        local: key.local.clone(),
        remote: key.remote.clone(),
        state: flow.state.clone(),
        reason,
        duration_ms: close.then(|| now.duration_since(flow.opened).as_millis() as u64),
        host: flow.host.clone(),
        host_source: flow.host_source,
        rdns: flow.rdns.clone(),
        asn_org: flow.geo.as_ref().and_then(|g| nonempty(&g.org)),
        country: flow.geo.as_ref().and_then(|g| nonempty(&g.country_code)),
        app_protocol: flow.app_protocol,
        bytes_out: close.then_some(flow.bytes_out as u64),
        bytes_in: close.then_some(flow.bytes_in as u64),
        retransmits: close.then_some(flow.retransmits),
        observed_by: "poll",
    }
}

fn timestamp(wall: SystemTime) -> String {
    DateTime::<Utc>::from(wall).to_rfc3339_opts(SecondsFormat::Millis, true)
}

// ── Daemon ─────────────────────────────────────────────────────────────────

/// Connects the kprobes may queue between two ticks before they are dropped
/// and counted.
const CONNECT_QUEUE_CAP: usize = 8192;

/// The flow log as `netwatch daemon` runs it: the poll tracker, the eBPF
/// connect stream when the probes loaded, and the writer.
pub struct DaemonFlowLog {
    tracker: FlowTracker,
    writer: FlowWriter,
    connects: Option<Receiver<ConnectSeen>>,
}

impl DaemonFlowLog {
    pub fn start(config: &FlowLogConfig, app: &crate::app::App) -> Self {
        let status = app.attribution_status();
        let ebpf = match &status {
            crate::app::AttributionStatus::Active(_) => Ok(()),
            crate::app::AttributionStatus::Failed(_, error) => Err(error.as_str()),
            crate::app::AttributionStatus::Lsof => Err("not built with eBPF"),
        };
        tracing::info!(target: "netwatch::flow_log", ebpf = ?ebpf, "flow log started");
        #[cfg(feature = "ebpf")]
        let connects = app
            .conn_tracker
            .as_ref()
            .map(|t| t.subscribe(CONNECT_QUEUE_CAP));
        #[cfg(not(feature = "ebpf"))]
        let connects = None;
        Self {
            tracker: FlowTracker::new(config.loopback),
            writer: FlowWriter::start(config, sources(ebpf)),
            connects,
        }
    }

    /// Write what changed since the last tick: connects first, as they
    /// happened before the poll that follows them.
    pub fn tick(&mut self, app: &crate::app::App) {
        if let Some(rx) = &self.connects {
            let seen: Vec<ConnectSeen> = rx.try_iter().take(CONNECT_QUEUE_CAP).collect();
            self.writer.send(&self.tracker.connects(seen));
        }
        #[cfg(feature = "ebpf")]
        if let Some(t) = &app.conn_tracker {
            self.writer.count_dropped(t.take_dropped());
        }
        #[cfg(feature = "ebpf")]
        let attributor = app.conn_tracker.as_ref().map(|t| &t.attributor);
        let hint = |proto: &str, ip: &str, port: u16| -> Option<(u32, String)> {
            #[cfg(feature = "ebpf")]
            {
                use netwatch_sdk::ebpf::Protocol;
                let proto = if proto.eq_ignore_ascii_case("tcp") {
                    Protocol::Tcp
                } else if proto.eq_ignore_ascii_case("udp") {
                    Protocol::Udp
                } else {
                    return None;
                };
                let ip: std::net::IpAddr = ip.split('%').next()?.parse().ok()?;
                attributor?
                    .lookup_unambiguous(proto, ip.to_canonical(), port)
                    .map(|a| (a.pid, a.comm))
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (proto, ip, port);
                None
            }
        };
        let events = self.tracker.observe(
            &app.connection_collector.connections(),
            &app.geo_cache,
            &app.packet_collector.dns_cache,
            &hint,
        );
        self.writer.send(&events);
    }

    /// Close what is open and let the writer drain.
    pub fn finish(mut self) {
        if let Some(rx) = &self.connects {
            let seen: Vec<ConnectSeen> = rx.try_iter().collect();
            self.writer.send(&self.tracker.connects(seen));
        }
        self.writer.send(&self.tracker.finish());
        self.writer.shutdown(Duration::from_secs(3));
    }
}

// ── Writer ─────────────────────────────────────────────────────────────────

/// The header line each file starts with. `sources` says what the events
/// come from, such as whether the eBPF probes loaded.
fn header(sources: Option<&serde_json::Value>) -> serde_json::Value {
    let mut meta = serde_json::json!({ "schema": FLOW_SCHEMA });
    if let Some(sources) = sources {
        meta["sources"] = sources.clone();
    }
    serde_json::json!({
        "_meta": meta,
        "metadata": crate::schemas::FLOW.metadata(),
    })
}

/// `_meta.sources` for a session: polling always, eBPF when it loaded.
pub fn sources(ebpf: Result<(), &str>) -> serde_json::Value {
    match ebpf {
        Ok(()) => serde_json::json!({ "poll": true, "ebpf": "active" }),
        Err(error) => {
            serde_json::json!({ "poll": true, "ebpf": "unavailable", "ebpf_error": error })
        }
    }
}

/// Queues lines for the writer thread. Never blocks the caller.
pub struct FlowWriter {
    tx: Option<SyncSender<String>>,
    dropped: Arc<AtomicU64>,
    worker: Option<crate::sandbox::worker::WorkerHandle>,
}

impl FlowWriter {
    pub fn start(config: &FlowLogConfig, sources: serde_json::Value) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel(QUEUE_CAP);
        let dropped = Arc::new(AtomicU64::new(0));
        let sink = Sink {
            files: config
                .mode
                .file()
                .then(|| config.dir.clone())
                .flatten()
                .map(|dir| DailyFiles::new(dir, config.keep_days).with_sources(&sources)),
            stdout: config.mode.stdout(),
            header: header(Some(&sources)).to_string(),
        };
        if config.mode.file() && sink.files.is_none() {
            tracing::warn!(target: "netwatch::flow_log", "no cache directory; flow log file disabled");
        }
        let counter = Arc::clone(&dropped);
        let worker = crate::sandbox::worker::spawn("flow-log", move || {
            run_writer(rx, sink, &counter, Utc::now);
        });
        Self {
            tx: Some(tx),
            dropped,
            worker: Some(worker),
        }
    }

    pub fn send<T: Serialize>(&self, events: &[T]) {
        let Some(tx) = &self.tx else { return };
        for event in events {
            let Ok(line) = serde_json::to_string(event) else {
                continue;
            };
            match tx.try_send(line) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Add events lost before they reached this queue, such as connects the
    /// kprobe tap had no room for, to the next `dropped` line.
    pub fn count_dropped(&self, count: u64) {
        if count > 0 {
            self.dropped.fetch_add(count, Ordering::Relaxed);
        }
    }

    /// Let the writer drain what is queued, then wait for it up to `timeout`.
    pub fn shutdown(mut self, timeout: Duration) {
        self.tx = None;
        let Some(worker) = self.worker.take() else {
            return;
        };
        let deadline = Instant::now() + timeout;
        while !worker.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if worker.is_finished() {
            let _ = worker.join();
        } else {
            tracing::warn!(target: "netwatch::flow_log", "flow log writer did not finish in time");
            worker.not_waited_for();
        }
    }
}

struct Sink {
    files: Option<DailyFiles>,
    stdout: bool,
    /// Written to stdout once, at start.
    header: String,
}

impl Sink {
    fn write(&mut self, line: &str, now: DateTime<Utc>) {
        if let Some(files) = &mut self.files {
            files.write(line, now);
        }
        if self.stdout {
            crate::logging::stdout_text(&format!("{line}\n"));
        }
    }

    fn flush(&mut self) {
        if let Some(files) = &mut self.files {
            files.flush();
        }
        if self.stdout {
            let _ = std::io::stdout().flush();
        }
    }
}

/// Write queued lines until every sender is gone. Ignores the sandbox's
/// stopping flag on purpose: what was queued before shutdown is written.
fn run_writer(
    rx: Receiver<String>,
    mut sink: Sink,
    dropped: &AtomicU64,
    clock: impl Fn() -> DateTime<Utc>,
) {
    if sink.stdout {
        crate::logging::stdout_text(&format!("{}\n", sink.header));
    }
    let report_dropped = |sink: &mut Sink| {
        let count = dropped.swap(0, Ordering::Relaxed);
        if count > 0 {
            let now = clock();
            let line = serde_json::json!({
                "ts": now.to_rfc3339_opts(SecondsFormat::Millis, true),
                "event": "dropped",
                "count": count,
            });
            sink.write(&line.to_string(), now);
        }
    };
    loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(line) => {
                report_dropped(&mut sink);
                sink.write(&line, clock());
                // Write out the rest of a burst before flushing once.
                while let Ok(line) = rx.try_recv() {
                    sink.write(&line, clock());
                }
                sink.flush();
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                report_dropped(&mut sink);
                sink.flush();
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    report_dropped(&mut sink);
    sink.flush();
}

/// `flows.YYYY-MM-DD.ndjson`, one per UTC day, each opened 0600 for append and
/// starting with the header. Files past `keep` days are deleted at each change
/// of day.
struct DailyFiles {
    dir: PathBuf,
    keep: usize,
    header: String,
    current: Option<(NaiveDate, std::io::BufWriter<std::fs::File>)>,
    /// One warning per failure streak, not one per line.
    failing: bool,
}

impl DailyFiles {
    fn new(dir: PathBuf, keep: usize) -> Self {
        Self {
            dir,
            keep: keep.max(1),
            header: header(None).to_string(),
            current: None,
            failing: false,
        }
    }

    fn with_sources(mut self, sources: &serde_json::Value) -> Self {
        self.header = header(Some(sources)).to_string();
        self
    }

    fn path_for(&self, day: NaiveDate) -> PathBuf {
        self.dir
            .join(format!("flows.{}.ndjson", day.format("%Y-%m-%d")))
    }

    fn write(&mut self, line: &str, now: DateTime<Utc>) {
        let day = now.date_naive();
        if self.current.as_ref().is_none_or(|(d, _)| *d != day) {
            self.flush();
            self.current = None;
            match self.open(day) {
                Ok(file) => self.current = Some((day, file)),
                Err(e) => return self.failed(&e),
            }
            self.prune(day);
        }
        if let Some((_, file)) = &mut self.current {
            if let Err(e) = writeln!(file, "{line}") {
                self.current = None;
                self.failed(&e);
            } else {
                self.failing = false;
            }
        }
    }

    fn open(&self, day: NaiveDate) -> std::io::Result<std::io::BufWriter<std::fs::File>> {
        crate::owner_only::create_dir_all(&self.dir)?;
        let path = self.path_for(day);
        let file = crate::owner_only::file_options()
            .create(true)
            .append(true)
            .open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        let empty = file.metadata()?.len() == 0;
        let mut file = std::io::BufWriter::new(file);
        // A file reopened the same day already has its header.
        if empty {
            writeln!(file, "{}", self.header)?;
        }
        Ok(file)
    }

    fn prune(&self, today: NaiveDate) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        let oldest_kept = today - chrono::Days::new(self.keep as u64 - 1);
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(day) = name.to_str().and_then(file_day) else {
                continue;
            };
            if day < oldest_kept {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    fn flush(&mut self) {
        if let Some((_, file)) = &mut self.current {
            if let Err(e) = file.flush() {
                self.current = None;
                self.failed(&e);
            }
        }
    }

    fn failed(&mut self, error: &std::io::Error) {
        if !self.failing {
            self.failing = true;
            tracing::warn!(target: "netwatch::flow_log", dir = %self.dir.display(), %error, "flow log write failed");
        }
    }
}

/// The day in a name [`DailyFiles`] writes, and `None` for any other file.
fn file_day(name: &str) -> Option<NaiveDate> {
    let day = name.strip_prefix("flows.")?.strip_suffix(".ndjson")?;
    NaiveDate::parse_from_str(day, "%Y-%m-%d").ok()
}

/// For tests elsewhere that need the path a day's file goes to.
#[cfg(test)]
fn file_for(dir: &std::path::Path, day: NaiveDate) -> PathBuf {
    DailyFiles::new(dir.to_path_buf(), 1).path_for(day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpi::AppProtocol;

    fn conn(local: &str, remote: &str, state: &str) -> Connection {
        Connection {
            protocol: "TCP".into(),
            local_addr: local.into(),
            remote_addr: remote.into(),
            state: state.into(),
            pid: Some(4242),
            process_name: Some("curl".into()),
            handshake_rtt_us: None,
            rx_rate: None,
            tx_rate: None,
            attribution: AttributionSource::Procfs,
            evidence: Default::default(),
            app_protocol: None,
            retransmits: 0,
            out_of_order: 0,
        }
    }

    fn no_rdns(_: &str) -> Option<String> {
        None
    }

    fn no_geo(_: &str) -> Option<GeoInfo> {
        None
    }

    fn no_hint(_: &str, _: &str, _: u16) -> Option<(u32, String)> {
        None
    }

    struct Clock {
        start: Instant,
        wall: SystemTime,
    }

    impl Clock {
        fn new() -> Self {
            Self {
                start: Instant::now(),
                wall: SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000),
            }
        }

        fn at(&self, secs: u64) -> (Instant, SystemTime) {
            let d = Duration::from_secs(secs);
            (self.start + d, self.wall + d)
        }
    }

    fn observe(
        t: &mut FlowTracker,
        clock: &Clock,
        secs: u64,
        conns: &[Connection],
    ) -> Vec<FlowEvent> {
        let (now, wall) = clock.at(secs);
        t.observe_at(conns, now, wall, &no_rdns, &no_geo, &no_hint)
    }

    const LOCAL: &str = "10.0.0.5:51234";
    const REMOTE: &str = "142.250.66.101:443";

    #[test]
    fn a_new_connection_opens_once() {
        let clock = Clock::new();
        let mut t = FlowTracker::new(false);
        let table = [conn(LOCAL, REMOTE, "ESTABLISHED")];
        let first = observe(&mut t, &clock, 0, &table);
        assert_eq!(first.len(), 1);
        let open = &first[0];
        assert_eq!(open.event, FlowEventKind::Open);
        assert_eq!(open.process.as_deref(), Some("curl"));
        assert_eq!(open.pid, Some(4242));
        assert_eq!(open.remote, REMOTE);
        assert_eq!(open.duration_ms, None);
        assert_eq!(open.ts, "2026-09-21T14:13:20.000Z");
        assert!(observe(&mut t, &clock, 1, &table).is_empty());
        assert_eq!(t.open_len(), 1);
    }

    /// UDP rows can have no state at all; that is not a new flow each tick.
    #[test]
    fn a_stateless_row_opens_once() {
        let clock = Clock::new();
        let mut t = FlowTracker::new(false);
        let mut udp = conn(LOCAL, "8.8.8.8:53", "");
        udp.protocol = "UDP".into();
        assert_eq!(observe(&mut t, &clock, 0, &[udp.clone()]).len(), 1);
        assert!(observe(&mut t, &clock, 1, &[udp.clone()]).is_empty());
        // The same row twice in one table is one flow.
        assert!(observe(&mut t, &clock, 2, &[udp.clone(), udp]).is_empty());
    }

    #[test]
    fn a_vanished_connection_closes_with_its_duration() {
        let clock = Clock::new();
        let mut t = FlowTracker::new(false);
        observe(&mut t, &clock, 0, &[conn(LOCAL, REMOTE, "ESTABLISHED")]);
        let events = observe(&mut t, &clock, 7, &[]);
        assert_eq!(events.len(), 1);
        let close = &events[0];
        assert_eq!(close.event, FlowEventKind::Close);
        assert_eq!(close.reason, Some(CloseReason::Gone));
        assert_eq!(close.duration_ms, Some(7_000));
        assert_eq!(close.bytes_in, Some(0));
        assert_eq!(t.open_len(), 0);
    }

    #[test]
    fn a_closing_state_closes_once_and_the_socket_is_not_reopened() {
        let clock = Clock::new();
        let mut t = FlowTracker::new(false);
        observe(&mut t, &clock, 0, &[conn(LOCAL, REMOTE, "ESTABLISHED")]);
        let events = observe(&mut t, &clock, 3, &[conn(LOCAL, REMOTE, "TIME_WAIT")]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].reason, Some(CloseReason::Closed));
        assert_eq!(events[0].duration_ms, Some(3_000));
        assert!(observe(&mut t, &clock, 30, &[conn(LOCAL, REMOTE, "TIME-WAIT")]).is_empty());
        assert!(observe(&mut t, &clock, 60, &[]).is_empty());
        // The same 4-tuple later is a new connection.
        let again = observe(&mut t, &clock, 61, &[conn(LOCAL, REMOTE, "ESTABLISHED")]);
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].event, FlowEventKind::Open);
    }

    #[test]
    fn a_connection_first_seen_closing_opens_and_closes_at_once() {
        let clock = Clock::new();
        let mut t = FlowTracker::new(false);
        let events = observe(&mut t, &clock, 0, &[conn(LOCAL, REMOTE, "TIME-WAIT")]);
        let kinds: Vec<_> = events.iter().map(|e| e.event).collect();
        assert_eq!(kinds, [FlowEventKind::Open, FlowEventKind::Close]);
        assert_eq!(events[1].reason, Some(CloseReason::Closed));
        assert_eq!(events[1].duration_ms, Some(0));
        assert!(observe(&mut t, &clock, 1, &[conn(LOCAL, REMOTE, "TIME-WAIT")]).is_empty());
        assert!(observe(&mut t, &clock, 2, &[]).is_empty());
    }

    #[test]
    fn names_learned_after_open_go_into_close() {
        let clock = Clock::new();
        let mut t = FlowTracker::new(false);
        let mut c = conn(LOCAL, REMOTE, "ESTABLISHED");
        c.process_name = None;
        c.pid = None;
        let open = observe(&mut t, &clock, 0, &[c.clone()]);
        assert_eq!(open[0].process, None);
        assert_eq!(open[0].host, None);

        c.process_name = Some("curl".into());
        c.pid = Some(7);
        c.app_protocol = Some(AppProtocol::Tls {
            sni: Some("www.google.com".into()),
            alpn: None,
            ech: false,
            ja4: None,
        });
        c.rx_rate = Some(1000.0);
        c.tx_rate = Some(100.0);
        assert!(observe(&mut t, &clock, 1, &[c.clone()]).is_empty());
        // A later unattributed tick does not forget the process.
        c.process_name = None;
        assert!(observe(&mut t, &clock, 2, &[c.clone()]).is_empty());
        let (now, wall) = clock.at(3);
        let close = t.observe_at(
            &[],
            now,
            wall,
            &|_| Some("fra16s.1e100.net".into()),
            &|_| {
                Some(GeoInfo {
                    country_code: "US".into(),
                    country: "United States".into(),
                    city: String::new(),
                    org: "Google LLC".into(),
                })
            },
            &no_hint,
        );
        let close = &close[0];
        assert_eq!(close.process.as_deref(), Some("curl"));
        assert_eq!(close.pid, Some(7));
        assert_eq!(close.host.as_deref(), Some("www.google.com"));
        assert_eq!(close.host_source, Some("sni"));
        assert_eq!(close.app_protocol, Some("tls"));
        // Lookups ran while the flow was in the table, which they found empty.
        assert_eq!(close.rdns, None);
        assert_eq!(close.asn_org, None);
        assert_eq!(close.bytes_in, Some(2000));
        assert_eq!(close.bytes_out, Some(200));
    }

    #[test]
    fn reverse_dns_and_asn_fill_in_while_the_flow_lives() {
        let clock = Clock::new();
        let mut t = FlowTracker::new(false);
        let (now, wall) = clock.at(0);
        let table = [conn(LOCAL, REMOTE, "ESTABLISHED")];
        t.observe_at(
            &table,
            now,
            wall,
            &|_| Some("fra16s.1e100.net".into()),
            &|_| {
                Some(GeoInfo {
                    country_code: "US".into(),
                    country: "United States".into(),
                    city: String::new(),
                    org: "Google LLC".into(),
                })
            },
            &no_hint,
        );
        let close = observe(&mut t, &clock, 1, &[]);
        assert_eq!(close[0].rdns.as_deref(), Some("fra16s.1e100.net"));
        assert_eq!(close[0].asn_org.as_deref(), Some("Google LLC"));
        assert_eq!(close[0].country.as_deref(), Some("US"));
    }

    #[test]
    fn listeners_unbound_and_loopback_are_not_logged() {
        let clock = Clock::new();
        let mut t = FlowTracker::new(false);
        let table = [
            conn("0.0.0.0:22", "0.0.0.0:*", "LISTEN"),
            conn("[::]:22", "[::]:*", "LISTEN"),
            conn("0.0.0.0:68", "*:*", "UNCONN"),
            conn("127.0.0.1:5000", "127.0.0.1:41000", "ESTABLISHED"),
            conn("[::1]:5000", "[::1]:41000", "ESTABLISHED"),
            conn(
                "[::ffff:127.0.0.1]:5000",
                "[::ffff:127.0.0.1]:41000",
                "ESTABLISHED",
            ),
        ];
        assert!(observe(&mut t, &clock, 0, &table).is_empty());

        let mut with_loopback = FlowTracker::new(true);
        let events = observe(&mut with_loopback, &clock, 0, &table);
        assert_eq!(events.len(), 3, "{events:?}");
    }

    #[test]
    fn shutdown_closes_what_is_open() {
        let clock = Clock::new();
        let mut t = FlowTracker::new(false);
        observe(
            &mut t,
            &clock,
            0,
            &[
                conn(LOCAL, REMOTE, "ESTABLISHED"),
                conn("10.0.0.5:51235", "1.1.1.1:443", "TIME-WAIT"),
            ],
        );
        let (now, wall) = clock.at(5);
        let events = t.finish_at(now, wall);
        assert_eq!(
            events.len(),
            1,
            "the TIME-WAIT socket had its close already"
        );
        assert_eq!(events[0].reason, Some(CloseReason::Shutdown));
        assert_eq!(events[0].duration_ms, Some(5_000));
        assert_eq!(t.open_len(), 0);
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netwatch_flow_log_{name}_{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn day(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn lines(path: &std::path::Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn daily_files_start_with_the_header_are_private_and_rotate() {
        let root = scratch("daily");
        let dir = root.join("flows");
        let mut files = DailyFiles::new(dir.clone(), 2);
        files.write("{\"n\":1}", day("2026-11-01T23:59:59Z"));
        files.write("{\"n\":2}", day("2026-11-02T00:00:01Z"));
        files.write("{\"n\":3}", day("2026-11-03T00:00:01Z"));
        files.flush();

        let first = file_for(&dir, NaiveDate::from_ymd_opt(2026, 11, 1).unwrap());
        assert!(!first.exists(), "past keep_days");
        let third = file_for(&dir, NaiveDate::from_ymd_opt(2026, 11, 3).unwrap());
        let body = lines(&third);
        assert_eq!(body[0]["_meta"]["schema"], FLOW_SCHEMA);
        assert_eq!(body[0]["metadata"]["schema"], FLOW_SCHEMA);
        assert_eq!(body[1]["n"], 3);
        assert_eq!(body.len(), 2);

        // Reopened the same day: appended, no second header.
        drop(files);
        let mut files = DailyFiles::new(dir.clone(), 2);
        files.write("{\"n\":4}", day("2026-11-03T08:00:00Z"));
        files.flush();
        let body = lines(&third);
        assert_eq!(body.len(), 3);
        assert_eq!(body[2]["n"], 4);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode =
                |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&third), 0o600);
            assert_eq!(mode(&dir), 0o700);
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_writer_drains_its_queue_and_reports_what_it_dropped() {
        let root = scratch("writer");
        let dir = root.join("flows");
        let (tx, rx) = std::sync::mpsc::sync_channel(4);
        let dropped = AtomicU64::new(3);
        for n in 0..2 {
            tx.send(format!("{{\"n\":{n}}}")).unwrap();
        }
        drop(tx);
        let sink = Sink {
            files: Some(DailyFiles::new(dir.clone(), 14)),
            stdout: false,
            header: String::new(),
        };
        let now = day("2026-11-05T10:00:00Z");
        run_writer(rx, sink, &dropped, || now);
        let body = lines(&file_for(&dir, now.date_naive()));
        assert_eq!(body.len(), 4, "{body:?}");
        assert_eq!(body[1]["event"], "dropped");
        assert_eq!(body[1]["count"], 3);
        assert_eq!(body[2]["n"], 0);
        assert_eq!(body[3]["n"], 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_full_queue_counts_instead_of_blocking() {
        let (tx, _rx) = std::sync::mpsc::sync_channel(1);
        let writer = FlowWriter {
            tx: Some(tx),
            dropped: Arc::new(AtomicU64::new(0)),
            worker: None,
        };
        let clock = Clock::new();
        let mut t = FlowTracker::new(false);
        let events = observe(
            &mut t,
            &clock,
            0,
            &[
                conn(LOCAL, REMOTE, "ESTABLISHED"),
                conn("10.0.0.5:2", REMOTE, "ESTABLISHED"),
                conn("10.0.0.5:3", REMOTE, "ESTABLISHED"),
            ],
        );
        writer.send(&events);
        assert_eq!(writer.dropped.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn modes_parse_by_name() {
        assert_eq!(FlowLogMode::by_name("both"), Some(FlowLogMode::Both));
        assert_eq!(FlowLogMode::by_name("off"), Some(FlowLogMode::Off));
        assert_eq!(FlowLogMode::by_name("Both"), None);
        assert!(FlowLogMode::File.file() && !FlowLogMode::File.stdout());
        assert!(FlowLogMode::Both.file() && FlowLogMode::Both.stdout());
    }

    #[test]
    fn cli_wins_over_config_and_off_means_none() {
        let mut cfg = crate::config::NetwatchConfig::default();
        assert!(FlowLogConfig::resolve(&cfg).is_none());
        cfg.experimental.flow_log = "file".into();
        let resolved = FlowLogConfig::resolve(&cfg).unwrap();
        assert_eq!(resolved.mode, FlowLogMode::File);
        assert_eq!(resolved.keep_days, 14);
        assert_eq!(resolved.dir, default_dir());
        assert_eq!(configured_dir(&cfg), None);

        apply_cli(
            &mut cfg,
            Some(FlowLogMode::Both),
            Some("/var/log/netwatch".into()),
        );
        let resolved = FlowLogConfig::resolve(&cfg).unwrap();
        assert_eq!(resolved.mode, FlowLogMode::Both);
        assert_eq!(
            resolved.dir.as_deref(),
            Some(std::path::Path::new("/var/log/netwatch"))
        );
        assert_eq!(configured_dir(&cfg), resolved.dir);

        // Stdout alone writes no file, so it needs no directory.
        apply_cli(&mut cfg, Some(FlowLogMode::Stdout), None);
        assert_eq!(configured_dir(&cfg), None);
        apply_cli(&mut cfg, None, None);
        assert_eq!(cfg.experimental.flow_log, "stdout");
    }

    /// A flow polling left ownerless takes the connect kprobe's process, and
    /// a verified owner on a later tick replaces it. A hint that names a
    /// different pid than the table does is not taken.
    #[test]
    fn an_ownerless_flow_takes_the_ebpf_owner_until_polling_verifies_one() {
        let clock = Clock::new();
        let mut t = FlowTracker::new(false);
        let mut c = conn(LOCAL, REMOTE, "ESTABLISHED");
        c.process_name = None;
        c.pid = None;
        c.attribution = AttributionSource::Lsof;
        let (now, wall) = clock.at(0);
        let hint = |proto: &str, ip: &str, port: u16| {
            assert_eq!((proto, ip, port), ("TCP", "142.250.66.101", 443));
            Some((4242, "curl".to_string()))
        };
        let open = t.observe_at(&[c.clone()], now, wall, &no_rdns, &no_geo, &hint);
        assert_eq!(open[0].process.as_deref(), Some("curl"));
        assert_eq!(open[0].pid, Some(4242));
        assert_eq!(open[0].attribution, AttributionSource::Ebpf);

        c.process_name = Some("curl-verified".into());
        c.pid = Some(4242);
        c.attribution = AttributionSource::Procfs;
        observe(&mut t, &clock, 1, &[c]);
        let close = observe(&mut t, &clock, 2, &[]);
        assert_eq!(close[0].process.as_deref(), Some("curl-verified"));
        assert_eq!(close[0].attribution, AttributionSource::Procfs);

        let mut t = FlowTracker::new(false);
        let mut other = conn(LOCAL, REMOTE, "ESTABLISHED");
        other.process_name = None;
        other.pid = Some(1);
        let open = t.observe_at(&[other], now, wall, &no_rdns, &no_geo, &hint);
        assert_eq!(
            open[0].process, None,
            "pid 1 in the table, 4242 in the hint"
        );
    }

    #[test]
    fn connects_become_lines_without_loopback() {
        let t = FlowTracker::new(false);
        let wall = SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000);
        let seen = |remote: &str| ConnectSeen {
            proto: "TCP",
            pid: 4242,
            comm: "curl".into(),
            remote: remote.parse().unwrap(),
            wall,
        };
        let lines = t.connects([
            seen("93.184.215.14:443"),
            seen("127.0.0.1:8080"),
            seen("[::1]:8080"),
            seen("[::ffff:1.1.1.1]:53"),
        ]);
        let remotes: Vec<_> = lines.iter().map(|l| l.remote.as_str()).collect();
        assert_eq!(remotes, ["93.184.215.14:443", "1.1.1.1:53"]);
        let json = serde_json::to_value(&lines[0]).unwrap();
        assert_eq!(json["event"], "connect");
        assert_eq!(json["process"], "curl");
        assert_eq!(json["attribution"], "ebpf");
        assert_eq!(json["observed_by"], "ebpf");
        assert_eq!(json["ts"], "2026-09-21T14:13:20.000Z");
        assert_eq!(
            FlowTracker::new(true)
                .connects([seen("127.0.0.1:8080")])
                .len(),
            1
        );
    }

    /// The real writer's lines, an open, every kind of close and a dropped
    /// line, against schemas/flow.v0.schema.json with its open parts closed.
    #[test]
    fn the_log_matches_its_schema() {
        use crate::schemas::test_support::{compile, errors, load, strict};
        let validator = compile(&strict(&load(crate::schemas::FLOW.file)));

        let clock = Clock::new();
        let mut t = FlowTracker::new(false);
        let mut tls = conn(LOCAL, REMOTE, "ESTABLISHED");
        tls.app_protocol = Some(AppProtocol::Http {
            method: "GET".into(),
            host: Some("example.com".into()),
            path: None,
            status: None,
        });
        let mut unattributed = conn("10.0.0.5:2", "[2606:4700::1111]:443", "ESTABLISHED");
        unattributed.process_name = None;
        unattributed.pid = None;
        unattributed.protocol = "UDP".into();
        let closing = conn("10.0.0.5:3", REMOTE, "ESTABLISHED");
        let (now, wall) = clock.at(0);
        let mut events = t.observe_at(
            &[tls.clone(), unattributed, closing],
            now,
            wall,
            &|_| Some("host.example".into()),
            &|_| {
                Some(GeoInfo {
                    country_code: "US".into(),
                    country: "United States".into(),
                    city: String::new(),
                    org: "Example".into(),
                })
            },
            &|proto, _, _| (proto == "UDP").then(|| (99, "quic-client".into())),
        );
        assert!(events
            .iter()
            .any(|e| e.attribution == AttributionSource::Ebpf && e.pid == Some(99)));
        events.extend(observe(
            &mut t,
            &clock,
            1,
            &[tls, conn("10.0.0.5:3", REMOTE, "FIN-WAIT-1")],
        ));
        events.extend(observe(
            &mut t,
            &clock,
            2,
            &[conn(LOCAL, REMOTE, "ESTABLISHED")],
        ));
        let (now, wall) = clock.at(3);
        events.extend(t.finish_at(now, wall));
        let reasons: Vec<_> = events.iter().filter_map(|e| e.reason).collect();
        for reason in [
            CloseReason::Closed,
            CloseReason::Gone,
            CloseReason::Shutdown,
        ] {
            assert!(reasons.contains(&reason), "{reasons:?}");
        }

        let mut docs: Vec<serde_json::Value> = vec![
            header(None),
            header(Some(&sources(Ok(())))),
            header(Some(&sources(Err("permission denied")))),
        ];
        docs.extend(events.iter().map(|e| serde_json::to_value(e).unwrap()));
        docs.push(
            serde_json::json!({"ts": "2026-11-05T10:00:00.000Z", "event": "dropped", "count": 2}),
        );
        for doc in &docs {
            assert_eq!(errors(&validator, doc), Vec::<String>::new(), "{doc}");
        }
    }
}
