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
    /// Only ever `true`: see [`ConnectLine::ech`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ech: Option<bool>,
    /// See [`ConnectLine::dns_name`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,
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
    /// The client side of the captured stream this connect started, when
    /// one was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<String>,
    pub remote: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_source: Option<&'static str>,
    /// Only ever `true`: the ClientHello carried Encrypted ClientHello, so
    /// `host` is the outer, public name, not the one the client asked for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ech: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_protocol: Option<&'static str>,
    /// The name a DNS answer seen in capture gave `remote`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,
    pub observed_by: &'static str,
}

/// A captured stream a connect may have started: its client and server
/// sides and what the decoder made of it.
#[derive(Debug, Clone)]
pub struct WireStream {
    pub index: u32,
    pub proto: &'static str,
    pub client: std::net::SocketAddr,
    pub server: std::net::SocketAddr,
    pub app_protocol: Option<crate::dpi::AppProtocol>,
}

/// Ticks a connect waits for its stream's ClientHello before it is written
/// with what is known by then.
const CONNECT_HOLD_TICKS: u32 = 2;

/// Joins connects, which name the process but have no source port and come
/// before any handshake, to the captured stream each one started, which has
/// the source port and the SNI. A stream counts as a connect's when it goes
/// to the same destination over the same transport, began after the connect
/// was read, was started from this side, and no earlier connect took it.
#[derive(Debug, Default)]
pub struct ConnectJoin {
    /// Each waiting connect, the lowest stream index it can have started,
    /// and the ticks it has waited.
    pending: Vec<(ConnectSeen, u32, u32)>,
    claimed: std::collections::HashSet<u32>,
    /// The tracker's `next_index` at the last two ticks.
    marks: std::collections::VecDeque<u32>,
    loopback: bool,
}

impl ConnectJoin {
    pub fn new(loopback: bool) -> Self {
        Self {
            loopback,
            ..Self::default()
        }
    }

    /// The lowest index a stream started by a connect read now can have: the
    /// tracker's next index two ticks ago. One tick ago is not enough: a
    /// connect read this tick may have happened just before the last read,
    /// and its SYN been counted before it.
    fn floor(&self) -> u32 {
        if self.marks.len() < 2 {
            0
        } else {
            self.marks[0]
        }
    }

    pub fn push(&mut self, seen: impl IntoIterator<Item = ConnectSeen>) {
        let floor = self.floor();
        for mut c in seen {
            let ip = c.remote.ip().to_canonical();
            if !self.loopback && is_loopback(&ip.to_string()) {
                continue;
            }
            c.remote = std::net::SocketAddr::new(ip, c.remote.port());
            self.pending.push((c, floor, 0));
        }
    }

    pub fn is_waiting(&self) -> bool {
        !self.pending.is_empty()
    }

    /// The lowest stream index any waiting connect can have started.
    pub fn since(&self) -> u32 {
        self.pending
            .iter()
            .map(|(_, floor, _)| *floor)
            .min()
            .unwrap_or_else(|| self.floor())
    }

    /// Destinations the waiting connects went to, to pick streams by.
    pub fn wanted(&self) -> std::collections::HashSet<(&'static str, std::net::SocketAddr)> {
        self.pending
            .iter()
            .map(|(c, _, _)| (c.proto, c.remote))
            .collect()
    }

    /// One tick: match what can be matched, write what has waited long
    /// enough. `next_index` is the stream tracker's, read with `streams`.
    pub fn tick(&mut self, next_index: u32, streams: &[WireStream]) -> Vec<ConnectLine> {
        let lines = self.resolve(streams, false);
        if self.marks.back().is_some_and(|m| next_index < *m) {
            // The tracker wrapped and started again at 0.
            self.marks.clear();
            self.claimed.clear();
            for (_, floor, _) in &mut self.pending {
                *floor = 0;
            }
        }
        self.marks.push_back(next_index);
        while self.marks.len() > 2 {
            self.marks.pop_front();
        }
        // A claim matters only while a connect could still match its stream.
        let keep = self.since().min(self.floor());
        self.claimed.retain(|i| *i >= keep);
        lines
    }

    /// Write every waiting connect now, for shutdown.
    pub fn flush(&mut self, streams: &[WireStream]) -> Vec<ConnectLine> {
        self.resolve(streams, true)
    }

    fn resolve(&mut self, streams: &[WireStream], all: bool) -> Vec<ConnectLine> {
        let mut lines = Vec::new();
        let mut waiting = Vec::new();
        for (seen, floor, ticks) in std::mem::take(&mut self.pending) {
            let stream = streams
                .iter()
                .filter(|w| {
                    w.index >= floor
                        && w.proto == seen.proto
                        && w.server == seen.remote
                        && !self.claimed.contains(&w.index)
                })
                .min_by_key(|w| w.index);
            // A name, or a DNS stream's first message: nothing more is coming
            // that the line would carry.
            let named = stream.is_some_and(|w| {
                super::egress::dest_hostname(&w.app_protocol).is_some()
                    || matches!(w.app_protocol, Some(crate::dpi::AppProtocol::Dns { .. }))
            });
            if named || all || ticks + 1 >= CONNECT_HOLD_TICKS {
                if let Some(w) = stream {
                    self.claimed.insert(w.index);
                }
                lines.push(connect_line(seen, stream));
            } else {
                waiting.push((seen, floor, ticks + 1));
            }
        }
        self.pending = waiting;
        lines
    }
}

fn connect_line(c: ConnectSeen, stream: Option<&WireStream>) -> ConnectLine {
    let app = stream.and_then(|w| w.app_protocol.clone());
    let host = super::egress::dest_hostname(&app);
    ConnectLine {
        ts: timestamp(c.wall),
        event: "connect",
        proto: c.proto,
        process: c.comm,
        pid: c.pid,
        attribution: AttributionSource::Ebpf,
        local: stream.map(|w| w.client.to_string()),
        remote: c.remote.to_string(),
        host_source: host.as_ref().map(|_| {
            if super::egress::flow_http_host(&app) {
                "http"
            } else {
                "sni"
            }
        }),
        host,
        ech: super::egress::flow_ech(&app).then_some(true),
        app_protocol: app.as_ref().map(crate::dpi::AppProtocol::tag),
        dns_name: None,
        observed_by: "ebpf",
    }
}

/// The streams in `tracker` at index `since` or later that go to one of
/// `wanted` and were started from this side.
pub fn wire_streams(
    tracker: &super::packets::StreamTracker,
    since: u32,
    wanted: &std::collections::HashSet<(&'static str, std::net::SocketAddr)>,
) -> Vec<WireStream> {
    use super::packets::StreamProtocol;
    let addr = |(ip, port): &(String, u16)| -> Option<std::net::SocketAddr> {
        let ip: std::net::IpAddr = ip.parse().ok()?;
        Some(std::net::SocketAddr::new(ip.to_canonical(), *port))
    };
    tracker
        .all_streams
        .values()
        .filter(|s| s.index >= since)
        .filter_map(|s| {
            let proto = match s.key.protocol {
                StreamProtocol::Tcp => "TCP",
                StreamProtocol::Udp => "UDP",
            };
            let (a, b) = (addr(&s.key.addr_a)?, addr(&s.key.addr_b)?);
            let (client, server) = if wanted.contains(&(proto, b)) {
                (a, b)
            } else if wanted.contains(&(proto, a)) {
                (b, a)
            } else {
                return None;
            };
            // A stream the far side started is an inbound one.
            if s.initiator.as_ref().and_then(addr) == Some(server) {
                return None;
            }
            Some(WireStream {
                index: s.index,
                proto,
                client,
                server,
                app_protocol: s.app_protocol.clone(),
            })
        })
        .collect()
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
    ech: bool,
    dns_name: Option<String>,
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
            ech: false,
            dns_name: None,
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
        dns_name: &dyn Fn(&str) -> Option<String>,
    ) -> Vec<FlowEvent> {
        self.observe_at(
            connections,
            Instant::now(),
            SystemTime::now(),
            &|ip| dns.lookup(ip),
            &|ip| geo.lookup(ip),
            hint,
            dns_name,
        )
    }

    fn observe_at(
        &mut self,
        connections: &[Connection],
        now: Instant,
        wall: SystemTime,
        rdns: &dyn Fn(&str) -> Option<String>,
        geo: &dyn Fn(&str) -> Option<GeoInfo>,
        hint: OwnerHint,
        dns_name: &dyn Fn(&str) -> Option<String>,
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
            update(flow, conn, remote_ip, elapsed, rdns, geo, hint, dns_name);
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
    dns_name: &dyn Fn(&str) -> Option<String>,
) {
    flow.state.clone_from(&conn.state);
    if flow.dns_name.is_none() {
        flow.dns_name = dns_name(remote_ip);
    }
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
            flow.ech = super::egress::flow_ech(&conn.app_protocol);
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
        ech: flow.ech.then_some(true),
        dns_name: flow.dns_name.clone(),
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

// ── DNS ────────────────────────────────────────────────────────────────────

/// One DNS message seen in capture, with its addresses and the packet's time.
#[derive(Debug, Clone)]
pub struct DnsWire {
    pub at: SystemTime,
    pub src: std::net::SocketAddr,
    pub dst: std::net::SocketAddr,
    pub msg: crate::dpi::dns::DnsMessage,
}

/// Messages the tap holds between two ticks; past this they are left out.
const MAX_DNS_TAP: usize = 65_536;

/// Parse `payload`, a captured packet's UDP payload on port 53, into the tap.
pub(crate) fn tap_dns(
    tap: &mut Vec<DnsWire>,
    pkt: &super::packets::CapturedPacket,
    payload: &[u8],
) {
    if tap.len() >= MAX_DNS_TAP {
        return;
    }
    let (Some(sport), Some(dport)) = (pkt.src_port, pkt.dst_port) else {
        return;
    };
    let ip = |s: &str| {
        s.parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| ip.to_canonical())
    };
    let (Some(src), Some(dst)) = (ip(&pkt.src_ip), ip(&pkt.dst_ip)) else {
        return;
    };
    let Some(msg) = crate::dpi::dns::parse_message(payload) else {
        return;
    };
    tap.push(DnsWire {
        at: SystemTime::UNIX_EPOCH + Duration::from_nanos(pkt.timestamp_ns),
        src: std::net::SocketAddr::new(src, sport),
        dst: std::net::SocketAddr::new(dst, dport),
        msg,
    });
}

/// Addresses held in the name cache, and how long a name is kept whatever
/// TTL the answer gave.
const MAX_NAMES: usize = 65_536;
const MIN_NAME_TTL: Duration = Duration::from_secs(60);
const MAX_NAME_TTL: Duration = Duration::from_secs(86_400);

/// Which name each address was the answer for, from DNS responses seen in
/// capture. The name is the one asked, so a CNAME chain gives the address
/// the name the client used, not the CDN's.
#[derive(Debug, Default)]
pub struct NameCache {
    names: HashMap<std::net::IpAddr, (String, SystemTime)>,
}

impl NameCache {
    pub fn learn(&mut self, msg: &crate::dpi::dns::DnsMessage, at: SystemTime) {
        use crate::dpi::dns::DnsRecordData;
        if !msg.is_response || msg.rcode != Some(0) {
            return;
        }
        // The names the question reaches through CNAMEs.
        let mut chain = vec![msg.qname.as_str()];
        for _ in 0..msg.answers.len() {
            let before = chain.len();
            for a in &msg.answers {
                if let DnsRecordData::Cname(target) = &a.data {
                    if chain.contains(&a.name.as_str()) && !chain.contains(&target.as_str()) {
                        chain.push(target);
                    }
                }
            }
            if chain.len() == before {
                break;
            }
        }
        for a in &msg.answers {
            if let DnsRecordData::Addr(ip) = a.data {
                if chain.contains(&a.name.as_str()) {
                    let ttl =
                        Duration::from_secs(u64::from(a.ttl)).clamp(MIN_NAME_TTL, MAX_NAME_TTL);
                    self.names
                        .insert(ip.to_canonical(), (msg.qname.clone(), at + ttl));
                }
            }
        }
        if self.names.len() > MAX_NAMES {
            self.names.retain(|_, (_, until)| *until > at);
            if self.names.len() > MAX_NAMES {
                self.names.clear();
            }
        }
    }

    pub fn lookup(&self, ip: &str, now: SystemTime) -> Option<String> {
        let ip: std::net::IpAddr = ip.split('%').next()?.parse().ok()?;
        self.names
            .get(&ip.to_canonical())
            .filter(|(_, until)| *until > now)
            .map(|(name, _)| name.clone())
    }
}

/// Ticks a query waits for its response before it is written as a timeout.
const DNS_TIMEOUT_TICKS: u32 = 3;

/// One DNS exchange: the query, and the response when one came.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DnsLine {
    pub ts: String,
    pub event: &'static str,
    pub proto: &'static str,
    pub process: Option<String>,
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribution: Option<AttributionSource>,
    pub local: String,
    pub server: String,
    pub qname: String,
    pub qtype: String,
    /// The response's RCODE by name, or `timeout` when none came.
    pub rcode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub answers: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cnames: Vec<String>,
    /// Only ever `false`: the response came for a query capture did not see.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_seen: Option<bool>,
    pub observed_by: &'static str,
}

#[derive(Debug)]
struct PendingDns {
    client: std::net::SocketAddr,
    server: std::net::SocketAddr,
    txid: u16,
    query: Option<(SystemTime, String, u16)>,
    response: Option<(SystemTime, crate::dpi::dns::DnsMessage)>,
    ticks: u32,
}

/// Owner of a local socket: `(pid, process, how it was matched)`.
pub type SocketOwner<'a> =
    &'a dyn Fn(std::net::SocketAddr) -> Option<(u32, String, AttributionSource)>;

/// Pairs DNS queries with their responses by client, server and txid.
#[derive(Debug, Default)]
pub struct DnsJoin {
    pending: Vec<PendingDns>,
    loopback: bool,
}

impl DnsJoin {
    pub fn new(loopback: bool) -> Self {
        Self {
            loopback,
            ..Self::default()
        }
    }

    pub fn push(&mut self, wires: impl IntoIterator<Item = DnsWire>) {
        for w in wires {
            let (client, server) = if w.msg.is_response {
                (w.dst, w.src)
            } else {
                (w.src, w.dst)
            };
            if !self.loopback
                && [client, server]
                    .iter()
                    .any(|a| is_loopback(&a.ip().to_string()))
            {
                continue;
            }
            let txid = w.msg.txid;
            if w.msg.is_response {
                let open = self.pending.iter_mut().find(|p| {
                    p.client == client
                        && p.server == server
                        && p.txid == txid
                        && p.response.is_none()
                });
                match open {
                    Some(p) => p.response = Some((w.at, w.msg)),
                    None => self.pending.push(PendingDns {
                        client,
                        server,
                        txid,
                        query: None,
                        response: Some((w.at, w.msg)),
                        ticks: 0,
                    }),
                }
            } else {
                // A retransmitted query with the same id is the same exchange.
                if self.pending.iter().any(|p| {
                    p.client == client
                        && p.server == server
                        && p.txid == txid
                        && p.response.is_none()
                }) {
                    continue;
                }
                self.pending.push(PendingDns {
                    client,
                    server,
                    txid,
                    query: Some((w.at, w.msg.qname, w.msg.qtype)),
                    response: None,
                    ticks: 0,
                });
            }
        }
    }

    /// Write the exchanges that are done: answered and a tick old, so the
    /// socket's connect has had its turn to name the owner, or past the
    /// timeout. `all` writes everything, for shutdown.
    pub fn tick(&mut self, owner: SocketOwner, all: bool) -> Vec<DnsLine> {
        let mut lines = Vec::new();
        let mut waiting = Vec::new();
        for mut p in std::mem::take(&mut self.pending) {
            let done =
                all || (p.response.is_some() && p.ticks >= 1) || p.ticks >= DNS_TIMEOUT_TICKS;
            if done {
                lines.push(dns_line(p, owner));
            } else {
                p.ticks += 1;
                waiting.push(p);
            }
        }
        self.pending = waiting;
        lines.sort_by(|a, b| a.ts.cmp(&b.ts));
        lines
    }
}

fn dns_line(p: PendingDns, owner: SocketOwner) -> DnsLine {
    use crate::dpi::dns::{qtype_label, rcode_label, DnsRecordData};
    let (pid, process, attribution) = match owner(p.client) {
        Some((pid, name, how)) => (Some(pid), Some(name), Some(how)),
        None => (None, None, None),
    };
    let (ts, qname, qtype, query_seen) = match (&p.query, &p.response) {
        (Some((at, qname, qtype)), _) => (*at, qname.clone(), *qtype, None),
        (None, Some((at, msg))) => (*at, msg.qname.clone(), msg.qtype, Some(false)),
        (None, None) => (SystemTime::now(), String::new(), 0, None),
    };
    let mut answers = Vec::new();
    let mut cnames = Vec::new();
    let (rcode, latency_ms) = match &p.response {
        Some((at, msg)) => {
            for a in &msg.answers {
                match &a.data {
                    DnsRecordData::Addr(ip) => answers.push(ip.to_string()),
                    DnsRecordData::Cname(target) => cnames.push(target.clone()),
                }
            }
            let latency = p
                .query
                .as_ref()
                .and_then(|(q, _, _)| at.duration_since(*q).ok())
                .map(|d| (d.as_secs_f64() * 10_000.0).round() / 10.0);
            (rcode_label(msg.rcode.unwrap_or(0)), latency)
        }
        None => ("timeout".to_string(), None),
    };
    DnsLine {
        ts: timestamp(ts),
        event: "dns",
        proto: "UDP",
        process,
        pid,
        attribution,
        local: p.client.to_string(),
        server: p.server.to_string(),
        qname,
        qtype: qtype_label(qtype),
        rcode,
        latency_ms,
        answers,
        cnames,
        query_seen,
        observed_by: "capture",
    }
}

/// How long a connect's socket is remembered as its process's, for the DNS
/// exchanges on it.
const SOCKET_OWNER_TTL: Duration = Duration::from_secs(60);

// ── Daemon ─────────────────────────────────────────────────────────────────

/// Connects the kprobes may queue between two ticks before they are dropped
/// and counted.
const CONNECT_QUEUE_CAP: usize = 8192;

/// Sockets remembered from connect lines before the expired ones are cleared.
const MAX_ATTR_OWNERS: usize = 65_536;

/// `"1.2.3.4:53"` or `"[::1]:53"`, as the connection table prints them.
fn parse_socket(addr: &str) -> Option<std::net::SocketAddr> {
    let (Some(ip), Some(port)) = crate::app::addr_parts(addr) else {
        return None;
    };
    let ip: std::net::IpAddr = ip.split('%').next()?.parse().ok()?;
    Some(std::net::SocketAddr::new(
        ip.to_canonical(),
        port.parse().ok()?,
    ))
}

/// The flow log as `netwatch daemon` runs it: the poll tracker, the eBPF
/// connect stream when the probes loaded, and the writer.
pub struct DaemonFlowLog {
    tracker: FlowTracker,
    writer: FlowWriter,
    connects: Option<Receiver<ConnectSeen>>,
    join: ConnectJoin,
    dns: DnsJoin,
    names: NameCache,
    /// Local sockets the connect lines named, with when that stops counting.
    owners: HashMap<std::net::SocketAddr, (u32, String, Instant)>,
}

impl DaemonFlowLog {
    pub fn start(config: &FlowLogConfig, app: &mut crate::app::App) -> Self {
        app.dns_tap = Some(Vec::new());
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
            join: ConnectJoin::new(config.loopback),
            dns: DnsJoin::new(config.loopback),
            names: NameCache::default(),
            owners: HashMap::new(),
        }
    }

    /// Write what changed since the last tick: connects first, as they
    /// happened before the poll that follows them.
    pub fn tick(&mut self, app: &mut crate::app::App) {
        let now = SystemTime::now();
        // Answers first, so this tick's lines can carry the names they gave.
        let wires = app.dns_tap.as_mut().map(std::mem::take).unwrap_or_default();
        for w in &wires {
            self.names.learn(&w.msg, w.at);
        }
        self.dns.push(wires);

        if let Some(rx) = &self.connects {
            self.join.push(rx.try_iter().take(CONNECT_QUEUE_CAP));
            let (next_index, streams) = self.streams(app);
            let mut lines = self.join.tick(next_index, &streams);
            self.annotate(&mut lines, now);
            self.writer.send(&lines);
        }
        self.write_dns(app, false);
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
        let names = &self.names;
        let events = self.tracker.observe(
            &app.connection_collector.connections(),
            &app.geo_cache,
            &app.packet_collector.dns_cache,
            &hint,
            &|ip| names.lookup(ip, now),
        );
        self.writer.send(&events);
    }

    /// Give connect lines the name their destination was the answer for, and
    /// remember the sockets they name for the DNS exchanges on them.
    fn annotate(&mut self, lines: &mut [ConnectLine], now: SystemTime) {
        let until = Instant::now() + SOCKET_OWNER_TTL;
        for line in lines {
            if let Some(ip) = line
                .remote
                .rsplit_once(':')
                .map(|(ip, _)| ip.trim_matches(['[', ']']))
            {
                line.dns_name = self.names.lookup(ip, now);
            }
            if let Some(local) = line.local.as_deref().and_then(|l| l.parse().ok()) {
                self.owners
                    .insert(local, (line.pid, line.process.clone(), until));
            }
        }
        if self.owners.len() > MAX_ATTR_OWNERS {
            let now = Instant::now();
            self.owners.retain(|_, (_, _, until)| *until > now);
        }
    }

    /// Write the DNS exchanges that are done, each named by the socket's owner:
    /// a verified one from the table first, then the one its connect named.
    fn write_dns(&mut self, app: &crate::app::App, all: bool) {
        let table: HashMap<std::net::SocketAddr, (u32, String, AttributionSource)> = app
            .connection_collector
            .connections()
            .iter()
            .filter(|c| c.protocol.eq_ignore_ascii_case("udp"))
            .filter_map(|c| {
                let local = parse_socket(&c.local_addr)?;
                Some((local, (c.pid?, c.process_name.clone()?, c.attribution)))
            })
            .collect();
        let now = Instant::now();
        let owners = &self.owners;
        let owner = |local: std::net::SocketAddr| {
            table.get(&local).cloned().or_else(|| {
                owners
                    .get(&local)
                    .filter(|(_, _, until)| *until > now)
                    .map(|(pid, name, _)| (*pid, name.clone(), AttributionSource::Ebpf))
            })
        };
        let lines = self.dns.tick(&owner, all);
        self.writer.send(&lines);
    }

    /// The tracker's next stream index, and the streams waiting connects may
    /// have started. Empty without capture, or with nothing waiting.
    fn streams(&self, app: &crate::app::App) -> (u32, Vec<WireStream>) {
        let tracker =
            crate::app::safe_lock(&app.packet_collector.stream_tracker, "flow_log::streams");
        let next_index = tracker.next_index();
        let streams = if self.join.is_waiting() {
            wire_streams(&tracker, self.join.since(), &self.join.wanted())
        } else {
            Vec::new()
        };
        (next_index, streams)
    }

    /// Close what is open and let the writer drain.
    pub fn finish(mut self, app: &crate::app::App) {
        let now = SystemTime::now();
        if let Some(rx) = &self.connects {
            self.join.push(rx.try_iter());
            let (_, streams) = self.streams(app);
            let mut lines = self.join.flush(&streams);
            self.annotate(&mut lines, now);
            self.writer.send(&lines);
        }
        self.write_dns(app, true);
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
        // A `flow_log_keep_days` reaching before chrono's first date keeps
        // everything; plain subtraction would panic the writer.
        let Some(oldest_kept) = today.checked_sub_days(chrono::Days::new(self.keep as u64 - 1))
        else {
            return;
        };
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

    fn no_name(_: &str) -> Option<String> {
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
        t.observe_at(conns, now, wall, &no_rdns, &no_geo, &no_hint, &no_name)
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
            &no_name,
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
            &no_name,
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
    fn a_huge_keep_days_keeps_everything_instead_of_panicking() {
        let root = scratch("keep-huge");
        let dir = root.join("flows");
        let mut files = DailyFiles::new(dir.clone(), usize::MAX);
        files.write("{\"n\":1}", day("2026-11-01T12:00:00Z"));
        files.write("{\"n\":2}", day("2026-11-02T12:00:00Z"));
        files.flush();
        assert!(file_for(&dir, NaiveDate::from_ymd_opt(2026, 11, 1).unwrap()).exists());
        assert!(file_for(&dir, NaiveDate::from_ymd_opt(2026, 11, 2).unwrap()).exists());
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
        let open = t.observe_at(&[c.clone()], now, wall, &no_rdns, &no_geo, &hint, &no_name);
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
        let open = t.observe_at(&[other], now, wall, &no_rdns, &no_geo, &hint, &no_name);
        assert_eq!(
            open[0].process, None,
            "pid 1 in the table, 4242 in the hint"
        );
    }

    fn seen(proto: &'static str, remote: &str) -> ConnectSeen {
        ConnectSeen {
            proto,
            pid: 4242,
            comm: "curl".into(),
            remote: remote.parse().unwrap(),
            wall: SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000),
        }
    }

    fn wire(index: u32, client: &str, server: &str, sni: Option<&str>) -> WireStream {
        WireStream {
            index,
            proto: "TCP",
            client: client.parse().unwrap(),
            server: server.parse().unwrap(),
            app_protocol: sni.map(|s| AppProtocol::Tls {
                sni: Some(s.into()),
                alpn: None,
                ech: false,
                ja4: None,
            }),
        }
    }

    /// A connect shorter than a poll still gets its SNI and source port from
    /// the stream it started.
    #[test]
    fn a_connect_takes_the_sni_and_local_port_of_its_stream() {
        let mut join = ConnectJoin::new(false);
        join.push([seen("TCP", "5.255.255.242:443")]);
        assert!(join.is_waiting());
        // The ClientHello has not been decoded yet: it waits.
        let first = join.tick(11, &[wire(10, "10.0.0.5:59694", "5.255.255.242:443", None)]);
        assert!(first.is_empty());
        let lines = join.tick(
            12,
            &[wire(
                10,
                "10.0.0.5:59694",
                "5.255.255.242:443",
                Some("ya.ru"),
            )],
        );
        assert_eq!(lines.len(), 1);
        let json = serde_json::to_value(&lines[0]).unwrap();
        assert_eq!(json["event"], "connect");
        assert_eq!(json["process"], "curl");
        assert_eq!(json["pid"], 4242);
        assert_eq!(json["local"], "10.0.0.5:59694");
        assert_eq!(json["remote"], "5.255.255.242:443");
        assert_eq!(json["host"], "ya.ru");
        assert_eq!(json["host_source"], "sni");
        assert_eq!(json["app_protocol"], "tls");
        assert_eq!(json["attribution"], "ebpf");
        assert_eq!(json["ts"], "2026-09-21T14:13:20.000Z");
        assert!(json.get("ech").is_none());
        assert!(!join.is_waiting());
    }

    /// Two connects to one destination take its streams in order, and a
    /// stream one took is not given to another.
    #[test]
    fn connects_to_one_destination_take_one_stream_each() {
        let mut join = ConnectJoin::new(false);
        join.push([seen("TCP", "1.1.1.1:443"), seen("TCP", "1.1.1.1:443")]);
        let streams = [
            wire(21, "10.0.0.5:2", "1.1.1.1:443", Some("b.example")),
            wire(20, "10.0.0.5:1", "1.1.1.1:443", Some("a.example")),
        ];
        let lines = join.tick(22, &streams);
        let hosts: Vec<_> = lines.iter().map(|l| l.host.as_deref().unwrap()).collect();
        assert_eq!(hosts, ["a.example", "b.example"]);
        // A third connect later finds both taken, waits, then goes bare.
        join.push([seen("TCP", "1.1.1.1:443")]);
        assert!(join.tick(22, &streams).is_empty());
        let late = join.tick(22, &streams);
        assert_eq!(late.len(), 1);
        assert_eq!(late[0].local, None);
        assert_eq!(late[0].host, None);
    }

    #[test]
    fn a_connect_with_no_stream_is_written_after_the_hold_and_at_shutdown() {
        let mut join = ConnectJoin::new(false);
        join.push([seen("UDP", "[2606:4700::1111]:443")]);
        assert!(join.tick(0, &[]).is_empty());
        let lines = join.tick(0, &[]);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].remote, "[2606:4700::1111]:443");
        assert_eq!(lines[0].local, None);

        join.push([seen("TCP", "9.9.9.9:443")]);
        assert_eq!(join.flush(&[]).len(), 1);
        assert!(!join.is_waiting());
    }

    #[test]
    fn connects_leave_out_loopback_and_unmap_v4() {
        let mut join = ConnectJoin::new(false);
        join.push([
            seen("TCP", "127.0.0.1:8080"),
            seen("TCP", "[::1]:8080"),
            seen("TCP", "[::ffff:1.1.1.1]:53"),
        ]);
        let lines = join.flush(&[]);
        let remotes: Vec<_> = lines.iter().map(|l| l.remote.as_str()).collect();
        assert_eq!(remotes, ["1.1.1.1:53"]);
        let mut with = ConnectJoin::new(true);
        with.push([seen("TCP", "127.0.0.1:8080")]);
        assert_eq!(with.flush(&[]).len(), 1);
    }

    /// The streams a waiting connect can match: newer than the mark, to a
    /// wanted destination, started from this side.
    #[test]
    fn wire_streams_pick_outbound_streams_to_wanted_destinations() {
        use super::super::packets::{Stream, StreamKey, StreamProtocol, StreamTracker};
        let mut tracker = StreamTracker::new();
        let mut add =
            |index: u32, local: (&str, u16), remote: (&str, u16), initiator: (&str, u16)| {
                let key = StreamKey::new(StreamProtocol::Tcp, local.0, local.1, remote.0, remote.1);
                let mut s = Stream::new(index, key, 0);
                s.initiator = Some((initiator.0.to_string(), initiator.1));
                tracker.all_streams.insert(index, s);
            };
        add(
            1,
            ("10.0.0.5", 1000),
            ("5.255.255.242", 443),
            ("10.0.0.5", 1000),
        );
        add(
            5,
            ("10.0.0.5", 1001),
            ("5.255.255.242", 443),
            ("10.0.0.5", 1001),
        );
        add(6, ("10.0.0.5", 1002), ("8.8.8.8", 443), ("10.0.0.5", 1002));
        // Started by the far side: not a connect from here.
        add(
            7,
            ("10.0.0.5", 2000),
            ("5.255.255.242", 443),
            ("5.255.255.242", 443),
        );
        let wanted = [("TCP", "5.255.255.242:443".parse().unwrap())]
            .into_iter()
            .collect();
        let found = wire_streams(&tracker, 2, &wanted);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].index, 5);
        assert_eq!(found[0].client.to_string(), "10.0.0.5:1001");
    }

    fn dns_msg(
        txid: u16,
        response: bool,
        qname: &str,
        answers: Vec<(&str, &str)>,
    ) -> crate::dpi::dns::DnsMessage {
        use crate::dpi::dns::{DnsAnswer, DnsMessage, DnsRecordData};
        DnsMessage {
            txid,
            is_response: response,
            qname: qname.into(),
            qtype: 1,
            rcode: response.then_some(0),
            answers: answers
                .into_iter()
                .map(|(name, data)| DnsAnswer {
                    name: name.into(),
                    ttl: 300,
                    data: match data.parse() {
                        Ok(ip) => DnsRecordData::Addr(ip),
                        Err(_) => DnsRecordData::Cname(data.into()),
                    },
                })
                .collect(),
        }
    }

    fn dns_wire(ms: u64, src: &str, dst: &str, msg: crate::dpi::dns::DnsMessage) -> DnsWire {
        DnsWire {
            at: SystemTime::UNIX_EPOCH + Duration::from_millis(1_790_000_000_000 + ms),
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            msg,
        }
    }

    const CLIENT: &str = "10.210.6.92:60281";
    const RESOLVER: &str = "10.200.6.2:53";

    /// An address gets the name that was asked, through the CNAME chain, for
    /// as long as the answer's TTL; a failed answer teaches nothing.
    #[test]
    fn the_name_cache_learns_the_asked_name_through_cnames() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000);
        let mut names = NameCache::default();
        names.learn(
            &dns_msg(
                1,
                true,
                "pypi.org",
                vec![
                    ("pypi.org", "dualstack.python.map.fastly.net"),
                    ("dualstack.python.map.fastly.net", "151.101.0.223"),
                    ("dualstack.python.map.fastly.net", "2a04:4e42::223"),
                    ("unrelated.example", "9.9.9.9"),
                ],
            ),
            at,
        );
        assert_eq!(
            names.lookup("151.101.0.223", at).as_deref(),
            Some("pypi.org")
        );
        assert_eq!(
            names.lookup("2a04:4e42::223", at).as_deref(),
            Some("pypi.org")
        );
        assert_eq!(
            names.lookup("::ffff:151.101.0.223", at).as_deref(),
            Some("pypi.org")
        );
        assert_eq!(
            names.lookup("9.9.9.9", at),
            None,
            "not on the question's chain"
        );
        assert_eq!(
            names.lookup("151.101.0.223", at + Duration::from_secs(301)),
            None
        );

        let mut failed = dns_msg(2, true, "evil.example", vec![("evil.example", "6.6.6.6")]);
        failed.rcode = Some(3);
        names.learn(&failed, at);
        assert_eq!(names.lookup("6.6.6.6", at), None);
        // A query teaches nothing either.
        names.learn(
            &dns_msg(3, false, "q.example", vec![("q.example", "7.7.7.7")]),
            at,
        );
        assert_eq!(names.lookup("7.7.7.7", at), None);
    }

    fn owner_of(local: std::net::SocketAddr) -> Option<(u32, String, AttributionSource)> {
        (local.to_string() == CLIENT)
            .then(|| (1002265, "python3".to_string(), AttributionSource::Ebpf))
    }

    fn no_owner(_: std::net::SocketAddr) -> Option<(u32, String, AttributionSource)> {
        None
    }

    #[test]
    fn a_query_and_its_answer_are_one_line_with_the_socket_owner() {
        let mut join = DnsJoin::new(false);
        join.push([
            dns_wire(0, CLIENT, RESOLVER, dns_msg(7, false, "pypi.org", vec![])),
            dns_wire(0, CLIENT, RESOLVER, dns_msg(7, false, "pypi.org", vec![])), // retransmit
            dns_wire(
                4,
                RESOLVER,
                CLIENT,
                dns_msg(
                    7,
                    true,
                    "pypi.org",
                    vec![
                        ("pypi.org", "dualstack.python.map.fastly.net"),
                        ("dualstack.python.map.fastly.net", "151.101.0.223"),
                    ],
                ),
            ),
        ]);
        // Answered, but a tick young: the socket's connect gets its turn first.
        assert!(join.tick(&owner_of, false).is_empty());
        let lines = join.tick(&owner_of, false);
        assert_eq!(lines.len(), 1);
        let json = serde_json::to_value(&lines[0]).unwrap();
        assert_eq!(json["event"], "dns");
        assert_eq!(json["process"], "python3");
        assert_eq!(json["pid"], 1002265);
        assert_eq!(json["attribution"], "ebpf");
        assert_eq!(json["local"], CLIENT);
        assert_eq!(json["server"], RESOLVER);
        assert_eq!(json["qname"], "pypi.org");
        assert_eq!(json["qtype"], "A");
        assert_eq!(json["rcode"], "NOERROR");
        assert_eq!(json["latency_ms"], 4.0);
        assert_eq!(json["answers"], serde_json::json!(["151.101.0.223"]));
        assert_eq!(
            json["cnames"],
            serde_json::json!(["dualstack.python.map.fastly.net"])
        );
        assert_eq!(json["ts"], "2026-09-21T14:13:20.000Z");
        assert!(json.get("query_seen").is_none());
    }

    #[test]
    fn an_unanswered_query_times_out_and_a_lone_answer_is_still_written() {
        let mut join = DnsJoin::new(false);
        join.push([dns_wire(
            0,
            CLIENT,
            RESOLVER,
            dns_msg(8, false, "slow.example", vec![]),
        )]);
        for _ in 0..DNS_TIMEOUT_TICKS {
            assert!(join.tick(&no_owner, false).is_empty());
        }
        let lines = join.tick(&no_owner, false);
        assert_eq!(lines[0].rcode, "timeout");
        assert_eq!(lines[0].process, None);
        assert_eq!(lines[0].latency_ms, None);

        join.push([dns_wire(
            9,
            RESOLVER,
            CLIENT,
            dns_msg(9, true, "late.example", vec![]),
        )]);
        let lines = join.tick(&no_owner, true);
        assert_eq!(lines[0].qname, "late.example");
        assert_eq!(lines[0].query_seen, Some(false));
        assert_eq!(
            lines[0].local, CLIENT,
            "the client is the response's destination"
        );
    }

    #[test]
    fn dns_on_loopback_is_left_out_unless_asked_for() {
        let q = || {
            dns_wire(
                0,
                "127.0.0.1:40000",
                "127.0.0.53:53",
                dns_msg(1, false, "a.example", vec![]),
            )
        };
        let mut join = DnsJoin::new(false);
        join.push([q()]);
        assert!(join.tick(&no_owner, true).is_empty());
        let mut with = DnsJoin::new(true);
        with.push([q()]);
        assert_eq!(with.tick(&no_owner, true).len(), 1);
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
            &|ip| (ip == "142.250.66.101").then(|| "www.google.com".to_string()),
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
        let mut join = ConnectJoin::new(false);
        join.push([
            seen("TCP", "93.184.215.14:443"),
            seen("UDP", "[2606:4700::1111]:443"),
        ]);
        let mut named = wire(
            3,
            "10.0.0.5:51234",
            "93.184.215.14:443",
            Some("example.com"),
        );
        if let Some(AppProtocol::Tls { ech, .. }) = &mut named.app_protocol {
            *ech = true;
        }
        let mut lines = join.flush(&[named]);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].ech, Some(true));
        lines[0].dns_name = Some("example.com".into());
        docs.extend(lines.iter().map(|c| serde_json::to_value(c).unwrap()));
        let mut dns = DnsJoin::new(false);
        dns.push([
            dns_wire(0, CLIENT, RESOLVER, dns_msg(7, false, "pypi.org", vec![])),
            dns_wire(
                4,
                RESOLVER,
                CLIENT,
                dns_msg(
                    7,
                    true,
                    "pypi.org",
                    vec![
                        ("pypi.org", "dualstack.python.map.fastly.net"),
                        ("dualstack.python.map.fastly.net", "151.101.0.223"),
                    ],
                ),
            ),
            dns_wire(
                5,
                "10.210.6.92:1",
                RESOLVER,
                dns_msg(8, false, "slow.example", vec![]),
            ),
            dns_wire(
                6,
                RESOLVER,
                "10.210.6.92:2",
                dns_msg(9, true, "late.example", vec![]),
            ),
        ]);
        let dns_lines = dns.tick(&owner_of, true);
        assert_eq!(dns_lines.len(), 3);
        docs.extend(dns_lines.iter().map(|d| serde_json::to_value(d).unwrap()));
        assert!(events
            .iter()
            .any(|e| e.dns_name.as_deref() == Some("www.google.com")));
        for doc in &docs {
            assert_eq!(errors(&validator, doc), Vec::<String>::new(), "{doc}");
        }
    }
}
