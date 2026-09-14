use crate::app::{safe_read, safe_write};
use crate::collectors::packets::{StreamKey, StreamProtocol, StreamTracker};
#[cfg(target_os = "macos")]
use crate::platform::pktap::PktapAttributor;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

/// Source of the socket-owner match. Kernel-event hints are recorded separately
/// in MatchEvidence; backend readiness never changes an individual match's source.
/// Pktap/Ebpf variants remain for serialized compatibility with historical rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AttributionSource {
    #[default]
    Lsof,
    Procfs,
    Pktap,
    Ebpf,
}

#[derive(Debug, Clone, Serialize)]
pub struct Connection {
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    /// TCP handshake RTT (SYN→SYN-ACK) in microseconds, measured in userspace
    /// from captured packets and joined onto this connection by its 5-tuple.
    /// `None` until a handshake is observed for the flow (e.g. UDP, or a
    /// connection that predates capture).
    pub handshake_rtt_us: Option<f64>,
    /// Inbound (remote→local) payload bytes per second, derived from the
    /// ambient packet capture. `None` when capture isn't running or the
    /// connection hasn't been seen on the wire yet.
    pub rx_rate: Option<f64>,
    /// Outbound (local→remote) payload bytes per second.
    pub tx_rate: Option<f64>,
    #[serde(default)]
    pub attribution: AttributionSource,
    pub evidence: super::attribution::MatchEvidence,
    /// Application-layer protocol detected by `crate::dpi` from the
    /// first non-trivial payload seen on this flow. `None` when capture
    /// isn't running, the flow hasn't been seen, or no classifier
    /// matched.
    #[serde(default)]
    pub app_protocol: Option<crate::dpi::AppProtocol>,
    /// TCP retransmits seen on this flow (sum of both directions). Sourced
    /// from `StreamTracker::snapshot_anomalies` at update time. Zero on
    /// non-TCP flows and on TCP flows where no anomaly has been observed.
    #[serde(default)]
    pub retransmits: u32,
    /// TCP segments that arrived behind the per-direction high-water mark
    /// by less than `OOO_WINDOW_BYTES` — network reorder rather than
    /// retransmission. Sum of both directions. Zero unless observed.
    #[serde(default)]
    pub out_of_order: u32,
}

/// Label shown when a connection has no owning process. Deliberately not
/// `pid:0`: PID 0 is the kernel swapper, so printing it for a *missing* pid
/// invented a process that owns nothing. Every screen that once showed
/// `pid:0 — 644 MB` was reporting unattributed bytes, which sent a review
/// hunting the Landlock sandbox for a bug that was in this format string.
pub const UNATTRIBUTED: &str = "unattributed";

/// Display name for a connection's owning process.
///
/// Three distinct states, three distinct labels:
/// * `Some(name)` — attributed, use the name.
/// * `None` name, `Some(pid)` — the pid is known but `/proc/<pid>/comm` was
///   unreadable (process exited, or another user's). `pid:<n>` is honest here.
/// * both `None` — attribution failed. [`UNATTRIBUTED`], never a fake pid.
pub fn process_label(process_name: Option<&str>, pid: Option<u32>) -> String {
    match (process_name, pid) {
        (Some(name), _) => name.to_string(),
        (None, Some(pid)) => format!("pid:{pid}"),
        (None, None) => UNATTRIBUTED.to_string(),
    }
}

/// Which side of a canonical `StreamKey` the connection's local endpoint sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalSide {
    A,
    B,
}

fn stream_protocol(p: &str) -> Option<StreamProtocol> {
    let up = p.to_ascii_uppercase();
    if up.starts_with("TCP") {
        Some(StreamProtocol::Tcp)
    } else if up.starts_with("UDP") {
        Some(StreamProtocol::Udp)
    } else {
        None
    }
}

fn parse_host_port(addr: &str) -> Option<(String, u16)> {
    if addr.is_empty() || addr == "*:*" {
        return None;
    }
    // Bracketed IPv6: [::1]:8080
    if let Some(stripped) = addr.strip_prefix('[') {
        let bracket_end = stripped.find("]:")?;
        let ip = normalize_ip(&stripped[..bracket_end]);
        let port: u16 = stripped[bracket_end + 2..].parse().ok()?;
        return Some((ip, port));
    }
    // Plain IPv4 or unbracketed IPv6 (ss sometimes prints the latter).
    // The last colon separates port from host.
    let colon = addr.rfind(':')?;
    let host = &addr[..colon];
    if host == "*" || host.is_empty() {
        return None;
    }
    let port: u16 = addr[colon + 1..].parse().ok()?;
    Some((normalize_ip(host), port))
}

/// Strip `::ffff:` prefix from IPv4-mapped IPv6 so we match the plain IPv4
/// addresses packet capture reports.
fn normalize_ip(ip: &str) -> String {
    if let Some(rest) = ip.strip_prefix("::ffff:") {
        if rest.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return rest.to_string();
        }
    }
    ip.to_string()
}

/// Last-resort match for UDP Connections whose remote is wildcard
/// (typical of `lsof`'s view of QUIC sockets on macOS). Returns the
/// AppProtocol of any tracked Stream that shares the Connection's
/// local endpoint, or `None` if no such Stream exists.
fn match_udp_app_protocol_by_local(
    conn: &Connection,
    app_protos: &HashMap<StreamKey, crate::dpi::AppProtocol>,
) -> Option<crate::dpi::AppProtocol> {
    let proto = stream_protocol(&conn.protocol)?;
    if proto != StreamProtocol::Udp {
        return None;
    }
    let (l_ip, l_port) = parse_host_port(&conn.local_addr)?;
    let local_endpoint = (l_ip, l_port);
    for (key, ap) in app_protos {
        if key.protocol != proto {
            continue;
        }
        if key.addr_a == local_endpoint || key.addr_b == local_endpoint {
            return Some(ap.clone());
        }
    }
    None
}

pub fn connection_stream_key(conn: &Connection) -> Option<(StreamKey, LocalSide)> {
    let proto = stream_protocol(&conn.protocol)?;
    let (l_ip, l_port) = parse_host_port(&conn.local_addr)?;
    let (r_ip, r_port) = parse_host_port(&conn.remote_addr)?;
    let key = StreamKey::new(proto, &l_ip, l_port, &r_ip, r_port);
    let side = if key.addr_a == (l_ip, l_port) {
        LocalSide::A
    } else {
        LocalSide::B
    };
    Some((key, side))
}

/// Holds the previous per-stream byte snapshot so we can compute rates.
/// Rates are stored in canonical (a_to_b, b_to_a) direction; callers orient
/// to local using `LocalSide`.
struct RateState {
    prev: HashMap<StreamKey, (u64, u64)>,
    prev_time: Instant,
    rates: HashMap<StreamKey, (f64, f64)>,
    generations: HashMap<StreamKey, u32>,
    initialized: bool,
}

impl RateState {
    fn new() -> Self {
        Self {
            prev: HashMap::new(),
            prev_time: Instant::now(),
            rates: HashMap::new(),
            generations: HashMap::new(),
            initialized: false,
        }
    }

    /// Diff the current snapshot against the previous one and store per-stream
    /// rates. Streams present only in the previous snapshot are dropped.
    fn tick(&mut self, snapshot: HashMap<StreamKey, (u64, u64)>, now: Instant) {
        let elapsed = now.duration_since(self.prev_time).as_secs_f64();
        let mut rates = HashMap::with_capacity(snapshot.len());
        if elapsed >= 0.01 {
            for (key, &(a, b)) in &snapshot {
                if let Some(&(pa, pb)) = self.prev.get(key) {
                    let da = a.saturating_sub(pa) as f64 / elapsed;
                    let db = b.saturating_sub(pb) as f64 / elapsed;
                    rates.insert(key.clone(), (da, db));
                }
            }
        }
        self.rates = rates;
        self.prev = snapshot;
        self.prev_time = now;
    }

    fn rate_for(&self, key: &StreamKey, side: LocalSide) -> Option<(f64, f64)> {
        self.rates.get(key).map(|&(a_to_b, b_to_a)| match side {
            // local is A → rx (to A) = b_to_a, tx (from A) = a_to_b
            LocalSide::A => (b_to_a, a_to_b),
            LocalSide::B => (a_to_b, b_to_a),
        })
    }
}

pub struct ConnectionCollector {
    /// Latest connection list, published via the `Arc<RwLock<Arc<…>>>`
    /// snapshot pattern. Readers clone the inner `Arc` in O(1) instead of
    /// contending with the background `update()` thread on an exclusive lock
    /// across an arbitrarily large `Vec<Connection>`.
    snapshot: Arc<RwLock<Arc<Vec<Connection>>>>,
    busy: Arc<AtomicBool>,
    stream_tracker: Arc<Mutex<StreamTracker>>,
    rate_state: Arc<Mutex<RateState>>,
    flow_registry: Arc<Mutex<super::attribution::FlowRegistry>>,
    coverage: Arc<RwLock<super::attribution::Coverage>>,
    capture_stats: Option<Arc<super::packets::CaptureStats>>,
    #[cfg(target_os = "macos")]
    pktap: Option<Arc<PktapAttributor>>,
    #[cfg(feature = "ebpf")]
    ebpf: Option<Arc<crate::ebpf::conn_tracker::EbpfAttributor>>,
    /// Pre-sandbox `/proc` attribution snapshot for connections that predate
    /// startup (see [`ProcSnapshot`]). `None` until attached.
    #[cfg(target_os = "linux")]
    proc_snapshot: Option<Arc<ProcSnapshot>>,
    /// Unconfined `/proc` scanner (see [`ProcBroker`]). `None` until attached.
    #[cfg(target_os = "linux")]
    proc_broker: Option<Arc<ProcBroker>>,
}

impl ConnectionCollector {
    pub fn new(stream_tracker: Arc<Mutex<StreamTracker>>) -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(Arc::new(Vec::new()))),
            busy: Arc::new(AtomicBool::new(false)),
            stream_tracker,
            rate_state: Arc::new(Mutex::new(RateState::new())),
            flow_registry: Arc::new(Mutex::new(Default::default())),
            coverage: Arc::new(RwLock::new(Default::default())),
            capture_stats: None,
            #[cfg(target_os = "macos")]
            pktap: None,
            #[cfg(feature = "ebpf")]
            ebpf: None,
            #[cfg(target_os = "linux")]
            proc_snapshot: None,
            #[cfg(target_os = "linux")]
            proc_broker: None,
        }
    }

    /// Cheap snapshot of the most recent connection list. Single atomic
    /// refcount bump regardless of connection count — the returned `Arc`
    /// derefs to `&Vec<Connection>` so call sites work with it like a slice.
    pub fn connections(&self) -> Arc<Vec<Connection>> {
        let snapshot = Arc::clone(&safe_read(&self.snapshot, "connections::snapshot"));
        if snapshot.iter().any(|c| !c.evidence.fresh()) {
            let mut rows = (*snapshot).clone();
            for row in &mut rows {
                if !row.evidence.fresh() {
                    row.pid = None;
                    row.process_name = None;
                    row.evidence.process = None;
                    row.evidence.unknown_reason =
                        Some(super::attribution::UnknownReason::StaleSnapshot);
                    row.rx_rate = None;
                    row.tx_rate = None;
                }
            }
            Arc::new(rows)
        } else {
            snapshot
        }
    }

    /// Attach a PKTAP attribution cache. When set, `update()` will overlay
    /// kernel-derived (pid, comm) onto each lsof-discovered connection whose
    /// 5-tuple appears in the cache.
    #[cfg(target_os = "macos")]
    pub fn with_pktap(mut self, pktap: Arc<PktapAttributor>) -> Self {
        self.pktap = Some(pktap);
        self
    }

    /// Attach the eBPF attribution cache (Linux). When set, `update()` will
    /// retain corroborating hints from the SDK without replacing verified owners.
    #[cfg(feature = "ebpf")]
    pub fn with_ebpf(mut self, ebpf: Arc<crate::ebpf::conn_tracker::EbpfAttributor>) -> Self {
        self.ebpf = Some(ebpf);
        self
    }

    #[cfg(target_os = "macos")]
    pub fn attach_pktap(&mut self, pktap: Arc<PktapAttributor>) {
        self.pktap = Some(pktap);
    }

    #[cfg(feature = "ebpf")]
    pub fn attach_ebpf(&mut self, ebpf: Arc<crate::ebpf::conn_tracker::EbpfAttributor>) {
        self.ebpf = Some(ebpf);
    }

    /// Attach the pre-sandbox `/proc` attribution snapshot. Set in `App::prepare`
    /// before `sandbox::apply`. Reuse still requires current socket and identity
    /// validation; blocked or expired entries remain unknown.
    #[cfg(target_os = "linux")]
    pub fn with_proc_broker(mut self, broker: Arc<ProcBroker>) -> Self {
        self.proc_broker = Some(broker);
        self
    }

    pub fn with_proc_snapshot(mut self, snapshot: Arc<ProcSnapshot>) -> Self {
        self.proc_snapshot = Some(snapshot);
        self
    }

    pub fn with_capture_stats(mut self, stats: Arc<super::packets::CaptureStats>) -> Self {
        self.capture_stats = Some(stats);
        self
    }
    pub fn coverage(&self) -> super::attribution::Coverage {
        let mut coverage = safe_read(&self.coverage, "connections::coverage").clone();
        coverage.capture_drops = self.capture_stats.as_ref().and_then(|s| s.observed_drops());
        coverage
    }

    pub fn update(&self) {
        if self.busy.load(Ordering::SeqCst) {
            tracing::trace!(target: "netwatch::connections", "update() skipped — previous spawn still running");
            return;
        }
        tracing::trace!(target: "netwatch::connections", "update() spawning lsof");
        self.busy.store(true, Ordering::SeqCst);
        let snapshot = Arc::clone(&self.snapshot);
        let busy = Arc::clone(&self.busy);
        let stream_tracker = Arc::clone(&self.stream_tracker);
        let rate_state = Arc::clone(&self.rate_state);
        let flow_registry = Arc::clone(&self.flow_registry);
        let coverage = Arc::clone(&self.coverage);
        #[cfg(target_os = "macos")]
        let pktap = self.pktap.clone();
        #[cfg(feature = "ebpf")]
        let ebpf = self.ebpf.clone();
        #[cfg(target_os = "linux")]
        let proc_snapshot = self.proc_snapshot.clone();
        #[cfg(target_os = "linux")]
        let brokered = self.proc_broker.as_ref().and_then(|b| b.latest());
        crate::sandbox::worker::spawn("connections", move || {
            #[cfg(target_os = "macos")]
            let mut result = parse_lsof();
            #[cfg(target_os = "linux")]
            let mut result = parse_linux_connections_with(brokered.as_deref());
            #[cfg(target_os = "windows")]
            let mut result = parse_windows_connections();
            #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
            let mut result: Vec<Connection> = Vec::new();

            let (stream_bytes, app_protos, anomalies, handshake_rtts, generations) = {
                let tracker = stream_tracker.lock().unwrap();
                (
                    tracker.snapshot_bytes(),
                    tracker.snapshot_app_protocols(),
                    tracker.snapshot_anomalies(),
                    tracker.snapshot_handshake_rtts(),
                    tracker.snapshot_generations(),
                )
            };
            let mut state = rate_state.lock().unwrap();
            // Never diff bytes across a reused tuple's capture generation.
            let previous_generations = state.generations.clone();
            state
                .prev
                .retain(|key, _| previous_generations.get(key) == generations.get(key));
            let increments = stream_bytes
                .iter()
                .filter_map(|(key, &(a, b))| {
                    let (pa, pb) = state
                        .prev
                        .get(key)
                        .copied()
                        .unwrap_or(if state.initialized { (0, 0) } else { (a, b) });
                    let bytes = a.saturating_sub(pa).saturating_add(b.saturating_sub(pb));
                    (bytes > 0).then(|| (key.clone(), bytes))
                })
                .collect::<HashMap<_, _>>();
            state.initialized = true;
            state.generations = generations.clone();
            state.tick(stream_bytes, Instant::now());
            for conn in &mut result {
                if let Some((key, side)) = connection_stream_key(conn) {
                    if let Some((rx, tx)) = state.rate_for(&key, side) {
                        conn.rx_rate = Some(rx);
                        conn.tx_rate = Some(tx);
                    }
                    if let Some(proto) = app_protos.get(&key) {
                        conn.app_protocol = Some(proto.clone());
                    }
                    if let Some(&(retx, ooo)) = anomalies.get(&key) {
                        conn.retransmits = retx;
                        conn.out_of_order = ooo;
                    }
                    if let Some(&rtt_us) = handshake_rtts.get(&key) {
                        conn.handshake_rtt_us = Some(rtt_us);
                    }
                } else if conn.app_protocol.is_none() {
                    // `lsof` typically reports Chrome's QUIC UDP sockets
                    // with remote `*:*` even though the kernel has a
                    // specific peer. `connection_stream_key` rejects
                    // wildcard remotes, so the strict 5-tuple join
                    // fails and DPI tags never attach. Fall back to a
                    // local-only match against the StreamTracker
                    // snapshot — first stream sharing this Connection's
                    // local endpoint wins. For QUIC each flow has a
                    // unique local port so the match is unambiguous in
                    // practice.
                    if let Some(proto) = match_udp_app_protocol_by_local(conn, &app_protos) {
                        conn.app_protocol = Some(proto);
                    }
                }
            }
            drop(state);

            #[cfg(target_os = "macos")]
            if let Some(pktap) = pktap.as_ref() {
                overlay_pktap_attribution(&mut result, pktap);
            }

            #[cfg(feature = "ebpf")]
            if let Some(ebpf) = ebpf.as_ref() {
                overlay_ebpf_attribution(&mut result, ebpf);
            }

            // Pre-sandbox snapshot fills connections that predate startup,
            // which neither eBPF (only new connects) nor a live /proc scan
            // (Landlock-blocked once sandboxed) can attribute.
            #[cfg(target_os = "linux")]
            if let Some(snap) = proc_snapshot.as_ref() {
                overlay_proc_snapshot(&mut result, snap);
            }

            // Last, after every attribution source has had its say: replace
            // the scraped name with the kernel's, which is neither truncated
            // nor version-stamped. Runs on the final (pid, name) pairs so it
            // corrects PKTAP and eBPF names too, not just lsof's.
            canonicalize_process_names(&mut result);

            #[cfg(not(target_os = "linux"))]
            for conn in &mut result {
                conn.evidence.observe();
                if conn.pid.is_some() {
                    conn.evidence.unknown_reason =
                        Some(super::attribution::UnknownReason::IdentityUnavailable);
                }
            }
            flow_registry.lock().unwrap().reconcile(&mut result);
            for conn in &mut result {
                let capture_generation =
                    connection_stream_key(conn).and_then(|(key, _)| generations.get(&key).copied());
                if let Some(flow) = conn.evidence.flow.as_mut() {
                    flow.capture_generation = capture_generation;
                }
            }
            *safe_write(&coverage, "connections::coverage") =
                measure_coverage(&result, &increments);
            let count = result.len();
            *safe_write(&snapshot, "connections::publish") = Arc::new(result);
            tracing::trace!(target: "netwatch::connections", count, "published connection snapshot");
            busy.store(false, Ordering::SeqCst);
        });
    }
}

fn measure_coverage(
    connections: &[Connection],
    increments: &HashMap<StreamKey, u64>,
) -> super::attribution::Coverage {
    let mut owners: HashMap<StreamKey, Option<super::attribution::ProcessIdentity>> =
        HashMap::new();
    for conn in connections {
        if let Some((key, _)) = connection_stream_key(conn) {
            let owner = conn
                .evidence
                .verified()
                .then(|| conn.evidence.process.clone())
                .flatten();
            owners
                .entry(key)
                .and_modify(|old| {
                    if *old != owner {
                        *old = None;
                    }
                })
                .or_insert(owner);
        }
    }
    let mut coverage = super::attribution::Coverage {
        completed_at: Some(Instant::now()),
        completed_at_utc_ms: Some(super::attribution::utc_ms()),
        ..Default::default()
    };
    for (key, bytes) in increments {
        coverage.eligible_flows += 1;
        coverage.eligible_payload_bytes = coverage.eligible_payload_bytes.saturating_add(*bytes);
        if owners.get(key).is_some_and(Option::is_some) {
            coverage.attributed_flows += 1;
            coverage.attributed_payload_bytes =
                coverage.attributed_payload_bytes.saturating_add(*bytes);
        }
    }
    coverage
}

/// Replace each connection's process name with the identity derived from the
/// kernel's executable path for its pid.
///
/// This is what makes a process's name stable enough to key an egress policy
/// on. The scraped names are not: `comm` is truncated at 16 bytes (macOS) or
/// 15 (Linux), so `Google Chrome Helper` and `Google Chrome Helper (GPU)`
/// collapse together, while lsof reports the executable's filename, which for
/// version-installed tools is the version itself — Claude Code appeared under
/// eight different "process names", one per release it had run.
///
/// Resolution is cached within a poll by PID and process identity. Identity
/// changes invalidate names rather than promoting old event names to a new PID.
fn canonicalize_process_names(connections: &mut [Connection]) {
    let mut cache: HashMap<(u32, Option<super::attribution::ProcessIdentity>), Option<String>> =
        HashMap::new();
    for conn in connections {
        let Some(pid) = conn.pid else {
            continue;
        };
        let before = super::attribution::process_identity(pid);
        // A later executable lookup without a start token could name a recycled
        // PID. Retain the original polling observation without upgrading it.
        if before.is_none() && conn.evidence.process.is_none() {
            continue;
        }
        if conn
            .evidence
            .process
            .as_ref()
            .is_some_and(|expected| !super::attribution::same_process(before.as_ref(), expected))
        {
            conn.pid = None;
            conn.process_name = None;
            conn.evidence.process = None;
            conn.evidence.unknown_reason = Some(super::attribution::UnknownReason::IdentityChanged);
            continue;
        }
        let resolved = cache
            .entry((pid, before.clone()))
            .or_insert_with(|| crate::platform::procname::stable_name(pid))
            .clone();
        let after = super::attribution::process_identity(pid);
        if before == after {
            if let Some(name) = resolved {
                conn.process_name = Some(name);
            }
        } else {
            conn.pid = None;
            conn.process_name = None;
            conn.evidence.process = None;
            conn.evidence.unknown_reason = Some(super::attribution::UnknownReason::IdentityChanged);
        }
    }
}

/// A recent PKTAP event may corroborate a polling PID but cannot replace it.
/// Without platform start identity this remains an unverified polling observation.
#[cfg(target_os = "macos")]
fn overlay_pktap_attribution(connections: &mut [Connection], pktap: &PktapAttributor) {
    for conn in connections {
        if let Some((key, _)) = connection_stream_key(conn) {
            if let Some(attr) = pktap.lookup(&key) {
                if conn.pid != Some(attr.pid)
                    || attr.seen_at.elapsed() > super::attribution::MAX_MATCH_AGE
                {
                    continue;
                }
                conn.evidence.corroborated_by = Some("pktap".into());
                conn.evidence.event_age_at_match_ms =
                    Some(attr.seen_at.elapsed().as_millis() as u64);
            }
        }
    }
}

/// Destination-only eBPF events are hints, never independent socket ownership.
/// Retain polling evidence and annotate corroboration only for the same verified PID.
#[cfg(feature = "ebpf")]
fn overlay_ebpf_attribution(
    connections: &mut [Connection],
    ebpf: &crate::ebpf::conn_tracker::EbpfAttributor,
) {
    use netwatch_sdk::ebpf::Protocol;
    for conn in connections {
        // TCP (`tcp_v{4,6}_connect`) and connected UDP — QUIC etc.
        // (`ip{4,6}_datagram_connect`) — are both attributed; the cache is
        // protocol-keyed so the two don't alias on a shared `daddr:dport`.
        let proto = if conn.protocol.eq_ignore_ascii_case("tcp") {
            Protocol::Tcp
        } else if conn.protocol.eq_ignore_ascii_case("udp") {
            Protocol::Udp
        } else {
            continue;
        };
        // Keyed on protocol + destination — the kprobes can't see the source
        // at connect-entry (see conn_tracker::AttrKey).
        let (Some(daddr), Some(dport)) = parse_endpoint(&conn.remote_addr) else {
            continue;
        };
        if let Some(attr) = ebpf.lookup(proto, daddr, dport) {
            if conn.pid != Some(attr.pid) || !conn.evidence.verified() {
                if conn.pid.is_none() {
                    conn.evidence.unknown_reason =
                        Some(super::attribution::UnknownReason::IncompleteEventKey);
                }
                continue;
            }
            conn.evidence.corroborated_by = Some("ebpf_destination_hint".into());
            conn.evidence.event_age_at_match_ms = Some(attr.seen_at.elapsed().as_millis() as u64);
        }
    }
}

/// Parse `"1.2.3.4:5678"` or a bracketed IPv6 endpoint (`"[2606:4700::1]:443"`,
/// the form ss/lsof print) into `(IpAddr, port)`. Bare IPv6 with a trailing
/// `:port` is handled as a fallback by splitting on the last colon. Either
/// component may be `None` if the underlying string was missing it (LISTEN
/// sockets often have remote = "*:*").
///
/// v4-mapped IPv6 addresses (`::ffff:a.b.c.d`, common in ss output for
/// dual-stack sockets) are canonicalised to `IpAddr::V4` — the SDK does
/// the same on the kprobe side, so cache keys agree on a single family.
#[cfg(feature = "ebpf")]
fn parse_endpoint(addr: &str) -> (Option<std::net::IpAddr>, Option<u16>) {
    use std::net::IpAddr;

    let (host, port) = if let Some(rest) = addr.strip_prefix('[') {
        // "[v6]:port"
        match rest.split_once(']') {
            Some((h, p)) => (h, p.strip_prefix(':').unwrap_or("")),
            None => (rest, ""),
        }
    } else {
        match addr.rsplit_once(':') {
            Some((h, p)) => (h, p),
            None => (addr, ""),
        }
    };

    let ip = host.parse::<IpAddr>().ok().map(|ip| match ip {
        IpAddr::V6(v6) => v6.to_canonical(),
        v4 => v4,
    });
    let port = port.parse::<u16>().ok();
    (ip, port)
}

const MAX_TRACKED_CONNECTIONS: usize = 2000;

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct ConnectionKey {
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub pid: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct TrackedConnection {
    pub key: ConnectionKey,
    pub process_name: Option<String>,
    pub state: String,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub is_active: bool,
}

pub struct ConnectionTimeline {
    pub tracked: Vec<TrackedConnection>,
    known_keys: HashMap<ConnectionKey, usize>,
}

impl Default for ConnectionTimeline {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionTimeline {
    pub fn new() -> Self {
        Self {
            tracked: Vec::new(),
            known_keys: HashMap::new(),
        }
    }

    /// Current tracked-connection count, for the `M` debug overlay.
    pub fn tracked_len(&self) -> usize {
        self.tracked.len()
    }
    /// Hard cap from `MAX_TRACKED_CONNECTIONS`, for the `M` debug overlay.
    pub fn tracked_cap(&self) -> usize {
        MAX_TRACKED_CONNECTIONS
    }

    pub fn update(&mut self, connections: &[Connection]) {
        let now = Instant::now();

        let mut current_keys: HashSet<ConnectionKey> = HashSet::new();

        for conn in connections {
            let key = ConnectionKey {
                protocol: conn.protocol.clone(),
                local_addr: conn.local_addr.clone(),
                remote_addr: conn.remote_addr.clone(),
                pid: conn.pid,
            };

            current_keys.insert(key.clone());

            if let Some(&idx) = self.known_keys.get(&key) {
                let tracked = &mut self.tracked[idx];
                tracked.last_seen = now;
                tracked.state = conn.state.clone();
                tracked.is_active = true;
            } else {
                let idx = self.tracked.len();
                self.tracked.push(TrackedConnection {
                    key: key.clone(),
                    process_name: conn.process_name.clone(),
                    state: conn.state.clone(),
                    first_seen: now,
                    last_seen: now,
                    is_active: true,
                });
                self.known_keys.insert(key, idx);
            }
        }

        for tracked in &mut self.tracked {
            if !current_keys.contains(&tracked.key) {
                tracked.is_active = false;
            }
        }

        // Evict oldest inactive connections if over limit
        if self.tracked.len() > MAX_TRACKED_CONNECTIONS {
            let mut inactive_indices: Vec<usize> = self
                .tracked
                .iter()
                .enumerate()
                .filter(|(_, t)| !t.is_active)
                .map(|(i, _)| i)
                .collect();
            inactive_indices.sort_by_key(|&i| self.tracked[i].first_seen);

            let to_remove = self.tracked.len() - MAX_TRACKED_CONNECTIONS;
            let remove_set: HashSet<usize> = inactive_indices.into_iter().take(to_remove).collect();

            if !remove_set.is_empty() {
                let removed_keys: Vec<ConnectionKey> = remove_set
                    .iter()
                    .map(|&i| self.tracked[i].key.clone())
                    .collect();
                for key in &removed_keys {
                    self.known_keys.remove(key);
                }

                let mut new_tracked = Vec::new();
                let mut new_keys = HashMap::new();
                for (i, t) in self.tracked.drain(..).enumerate() {
                    if !remove_set.contains(&i) {
                        let new_idx = new_tracked.len();
                        new_keys.insert(t.key.clone(), new_idx);
                        new_tracked.push(t);
                    }
                }
                self.tracked = new_tracked;
                self.known_keys = new_keys;
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn parse_lsof() -> Vec<Connection> {
    let output = match Command::new("lsof")
        .args(["-i", "-n", "-P", "-F", "pcPtTn"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut connections = Vec::new();

    let mut pid: Option<u32> = None;
    let mut process_name: Option<String> = None;
    let mut protocol = String::new();
    let mut state = String::new();
    let mut local_addr = String::new();
    let mut remote_addr = String::new();
    let mut has_network = false;

    // lsof -F field order per file descriptor is: f, t, P, n, TST=, TQR=, TQS=
    // The state (TST=) comes AFTER the network address (n), so we must defer
    // pushing the connection until the next file descriptor (f) or process (p)
    // boundary, or end-of-input.
    let flush = |connections: &mut Vec<Connection>,
                 has_network: &mut bool,
                 protocol: &str,
                 local_addr: &str,
                 remote_addr: &str,
                 state: &str,
                 pid: Option<u32>,
                 process_name: &Option<String>| {
        if *has_network {
            connections.push(Connection {
                protocol: protocol.to_string(),
                local_addr: local_addr.to_string(),
                remote_addr: remote_addr.to_string(),
                state: state.to_string(),
                pid,
                process_name: process_name.clone(),
                handshake_rtt_us: None,
                rx_rate: None,
                tx_rate: None,
                attribution: AttributionSource::Lsof,
                evidence: Default::default(),
                app_protocol: None,
                retransmits: 0,
                out_of_order: 0,
            });
            *has_network = false;
        }
    };

    for line in text.lines() {
        if line.is_empty() {
            continue;
        }

        let tag = line.as_bytes()[0];
        let value = &line[1..];

        match tag {
            b'p' => {
                flush(
                    &mut connections,
                    &mut has_network,
                    &protocol,
                    &local_addr,
                    &remote_addr,
                    &state,
                    pid,
                    &process_name,
                );
                pid = value.parse().ok();
                process_name = None;
            }
            b'c' => {
                process_name = Some(value.to_string());
            }
            b'f' => {
                flush(
                    &mut connections,
                    &mut has_network,
                    &protocol,
                    &local_addr,
                    &remote_addr,
                    &state,
                    pid,
                    &process_name,
                );
                protocol = String::new();
                state = String::new();
            }
            b'P' => {
                protocol = value.to_string();
            }
            b't' => {}
            b'T' => {
                if let Some(st) = value.strip_prefix("ST=") {
                    state = st.to_string();
                }
            }
            b'n' => {
                if let Some(arrow_pos) = value.find("->") {
                    local_addr = value[..arrow_pos]
                        .trim_matches(|c| c == '[' || c == ']')
                        .to_string();
                    remote_addr = value[arrow_pos + 2..]
                        .trim_matches(|c| c == '[' || c == ']')
                        .to_string();
                } else {
                    local_addr = value.to_string();
                    remote_addr = "*:*".to_string();
                };
                has_network = true;
            }
            _ => {}
        }
    }

    // Flush the last pending connection
    flush(
        &mut connections,
        &mut has_network,
        &protocol,
        &local_addr,
        &remote_addr,
        &state,
        pid,
        &process_name,
    );

    connections
}

#[cfg(all(target_os = "linux", test))]
fn parse_linux_connections() -> Vec<Connection> {
    parse_linux_connections_with(None)
}

#[cfg(target_os = "linux")]
fn parse_linux_connections_with(brokered: Option<&ProcSnapshot>) -> Vec<Connection> {
    let mut connections = Vec::new();

    if let Ok(output) = Command::new("ss").args(["-tunap"]).output() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 6 {
                continue;
            }

            let protocol = cols[0].to_uppercase();
            let state = match cols[1] {
                "ESTAB" => "ESTABLISHED".to_string(),
                other => other.to_string(),
            };
            let local_addr = cols[4].to_string();
            let remote_addr = cols[5].to_string();

            // The process column (`users:(("name",pid=N,fd=M))`) can contain
            // spaces — Firefox's "Web Content", "Isolated Web Co", etc. —
            // which `split_whitespace` above would shred across cols[6..].
            // Slice from the literal `users:((` token in the raw line so the
            // whole field reaches the parser intact.
            let (pid, process_name) = match line.find("users:((") {
                Some(idx) => parse_ss_process(&line[idx..]),
                None => (None, None),
            };

            connections.push(Connection {
                protocol,
                local_addr,
                remote_addr,
                state,
                pid,
                process_name,
                handshake_rtt_us: None,
                rx_rate: None,
                tx_rate: None,
                attribution: AttributionSource::Lsof,
                evidence: Default::default(),
                app_protocol: None,
                retransmits: 0,
                out_of_order: 0,
            });
        }
    }

    // `ss -p` only attributes sockets the caller is privileged to see. As a
    // normal user it returns NO process info — not even for the box's own
    // daemons — and on some hosts it stays empty even under sudo (see issue
    // #40). Fill anything ss left nameless straight from the kernel's tables:
    // /proc/net/{tcp,udp}{,6} maps a 5-tuple → socket inode, and
    // /proc/<pid>/fd/* maps that inode → owning process. Same source ss uses,
    // no subprocess, and it degrades to "attribute what this uid can see"
    // instead of the current all-or-nothing.
    overlay_proc_attribution(&mut connections, brokered);

    connections
}

#[cfg(target_os = "linux")]
fn parse_ss_process(field: &str) -> (Option<u32>, Option<String>) {
    // Format: users:(("process",pid=1234,fd=3)). The name is between the
    // first pair of double-quotes, so it survives embedded spaces.
    let name = field.split('"').nth(1).map(|s| s.to_string());

    let pid = field
        .split("pid=")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.parse().ok());

    (pid, name)
}

/// Parse a `/proc/net/{tcp,udp}*` hex endpoint (`"0100007F:1F90"`) into
/// `(IpAddr, port)`. The kernel prints the IPv4 address as the little-endian
/// host value of a network-order `be32`, and IPv6 as four little-endian
/// 32-bit words, so both need byte reversal. Port is plain big-endian hex.
///
/// Not `cfg`-gated so it stays unit-testable on every platform.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_proc_net_hex(s: &str) -> Option<(std::net::IpAddr, u16)> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let (ip_hex, port_hex) = s.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = match ip_hex.len() {
        8 => {
            let v = u32::from_str_radix(ip_hex, 16).ok()?;
            let b = v.to_le_bytes();
            IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
        }
        32 => {
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                let word = u32::from_str_radix(&ip_hex[i * 8..i * 8 + 8], 16).ok()?;
                bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some((ip, port))
}

/// Normalize an `ss`-rendered address (`"1.2.3.4:443"`, `"[::1]:443"`,
/// `"*:*"`) into `(IpAddr, port)`. Wildcards / unparseable forms → `None`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn normalize_addr(s: &str) -> Option<(std::net::IpAddr, u16)> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        rest.split_once("]:")?
    } else {
        s.rsplit_once(':')?
    };
    Some((host.parse().ok()?, port.parse().ok()?))
}

/// Read a process's `comm`, falling back to `pid:<n>` if it's gone.
#[cfg(target_os = "linux")]
fn read_proc_comm(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("pid:{pid}"))
}

/// Socket ownership is retained only when start/executable identity is stable
/// across descriptor enumeration. Shared sockets are explicitly ambiguous.
#[cfg(target_os = "linux")]
#[derive(Clone)]
struct SocketOwner {
    identity: super::attribution::ProcessIdentity,
    comm: String,
    fd: std::path::PathBuf,
}
#[cfg(target_os = "linux")]
fn socket_inode_owners() -> HashMap<u64, Option<SocketOwner>> {
    let mut map: HashMap<u64, Option<SocketOwner>> = HashMap::new();
    let Ok(proc) = std::fs::read_dir("/proc") else {
        return map;
    };
    let our_namespace =
        super::attribution::process_identity(std::process::id()).and_then(|p| p.network_namespace);
    if our_namespace.is_none() {
        return map;
    }
    for entry in proc.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Some(identity) = super::attribution::process_identity(pid) else {
            continue;
        };
        if identity.network_namespace != our_namespace {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        let comm = read_proc_comm(pid);
        let mut sockets = Vec::new();
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let Some(inode) = target
                .to_str()
                .and_then(|s| s.strip_prefix("socket:["))
                .and_then(|s| s.strip_suffix(']'))
                .and_then(|s| s.parse::<u64>().ok())
            else {
                continue;
            };
            sockets.push((inode, fd.path()));
        }
        if super::attribution::process_identity(pid).as_ref() != Some(&identity) {
            continue;
        }
        for (inode, fd) in sockets {
            map.entry(inode)
                .and_modify(|owner| {
                    if owner.as_ref().is_some_and(|o| o.identity != identity) {
                        *owner = None;
                    }
                })
                .or_insert_with(|| {
                    Some(SocketOwner {
                        identity: identity.clone(),
                        comm: comm.clone(),
                        fd,
                    })
                });
        }
    }
    map
}
#[cfg(target_os = "linux")]
type Endpoint = (std::net::IpAddr, u16);
#[cfg(target_os = "linux")]
type SocketKey = (StreamProtocol, Endpoint, Endpoint);
#[cfg(target_os = "linux")]
#[derive(Default)]
struct ProcNetIndex {
    by_pair: HashMap<SocketKey, u64>,
}
#[cfg(target_os = "linux")]
fn proc_net_inode_index() -> ProcNetIndex {
    let mut idx = ProcNetIndex::default();
    for (path, protocol) in [
        ("/proc/net/tcp", StreamProtocol::Tcp),
        ("/proc/net/tcp6", StreamProtocol::Tcp),
        ("/proc/net/udp", StreamProtocol::Udp),
        ("/proc/net/udp6", StreamProtocol::Udp),
    ] {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 {
                continue;
            }
            let (Some(local), Some(remote), Ok(inode)) = (
                parse_proc_net_hex(cols[1]),
                parse_proc_net_hex(cols[2]),
                cols[9].parse::<u64>(),
            ) else {
                continue;
            };
            if inode == 0 {
                continue;
            }
            // SO_REUSEPORT and shared endpoints must not select an arbitrary owner.
            idx.by_pair
                .entry((protocol, local, remote))
                .and_modify(|old| {
                    if *old != inode {
                        *old = 0;
                    }
                })
                .or_insert(inode);
        }
    }
    idx
}
#[cfg(target_os = "linux")]
fn socket_key(conn: &Connection) -> Option<SocketKey> {
    let protocol = stream_protocol(&conn.protocol)?;
    let local = normalize_addr(&conn.local_addr)?;
    let remote = normalize_addr(&conn.remote_addr).or_else(|| {
        // Wildcard peer is legitimate for an unconnected UDP or listening socket.
        (conn.remote_addr == "*:*" || conn.remote_addr.ends_with(":*")).then(|| {
            (
                if local.0.is_ipv4() {
                    std::net::IpAddr::from([0, 0, 0, 0])
                } else {
                    std::net::IpAddr::from([0u16; 8])
                },
                0,
            )
        })
    })?;
    Some((protocol, local, remote))
}
#[cfg(target_os = "linux")]
fn owner_still_valid(owner: &SocketOwner, inode: u64) -> bool {
    let target = format!("socket:[{inode}]");
    std::fs::read_link(&owner.fd)
        .ok()
        .is_some_and(|p| p == std::path::Path::new(&target))
        && super::attribution::process_identity(owner.identity.pid).as_ref()
            == Some(&owner.identity)
}
#[cfg(target_os = "linux")]
fn apply_owner(conn: &mut Connection, owner: &SocketOwner) {
    conn.attribution = AttributionSource::Procfs;
    conn.pid = Some(owner.identity.pid);
    conn.process_name = Some(owner.comm.clone());
    conn.evidence.process = Some(owner.identity.clone());
    conn.evidence.unknown_reason = None;
    conn.evidence.observe();
}
/// Revalidate every Linux polling match, including ss-provided PIDs. A PID name
/// alone cannot establish that the socket still belongs to that process.
///
/// A sandboxed worker cannot read other processes' `/proc/<pid>/fd` (Landlock
/// denies ptrace-mode access outside its domain), so when a [`ProcBroker`]
/// snapshot no older than `MAX_MATCH_AGE` is supplied, owners come from it.
/// The broker validated identity around each fd scan; here the socket inode
/// must still be the one the broker saw for this exact 5-tuple.
#[cfg(target_os = "linux")]
fn overlay_proc_attribution(connections: &mut [Connection], brokered: Option<&ProcSnapshot>) {
    let index = proc_net_inode_index();
    let brokered =
        brokered.filter(|s| s.captured_at.elapsed() <= super::attribution::MAX_MATCH_AGE);
    let owners = if brokered.is_some() {
        HashMap::new()
    } else {
        socket_inode_owners()
    };
    for conn in connections {
        conn.pid = None;
        conn.process_name = None;
        conn.evidence.observe();
        let key = socket_key(conn);
        let inode = key.and_then(|key| index.by_pair.get(&key).copied());
        if inode == Some(0) {
            conn.evidence.unknown_reason =
                Some(super::attribution::UnknownReason::AmbiguousEndpoint);
        }
        if let Some(snap) = brokered {
            let Some((seen, owner)) = key.and_then(|key| snap.entries.get(&key)) else {
                continue;
            };
            if inode == Some(*seen) {
                apply_owner(conn, owner);
            } else if inode.is_some_and(|i| i != 0) {
                conn.evidence.unknown_reason =
                    Some(super::attribution::UnknownReason::IdentityChanged);
            }
            continue;
        }
        if let Some((inode, owner)) =
            inode.and_then(|i| owners.get(&i).and_then(|o| o.as_ref()).map(|o| (i, o)))
        {
            if owner_still_valid(owner, inode) {
                apply_owner(conn, owner);
            } else {
                conn.evidence.unknown_reason =
                    Some(super::attribution::UnknownReason::IdentityChanged);
            }
        }
    }
}

/// Socket ownership scanned on a thread outside the worker sandbox.
///
/// Landlock confines per thread. The collector worker parses packet-derived
/// data and runs confined, which blocks reading other processes' socket fds;
/// this broker is started before any confinement (from `App::prepare`) and
/// only reads kernel procfs tables, never packet data. It holds no strong
/// reference to itself, so its thread exits when the collector is dropped.
#[cfg(target_os = "linux")]
pub struct ProcBroker {
    latest: RwLock<Option<Arc<ProcSnapshot>>>,
}

#[cfg(target_os = "linux")]
impl ProcBroker {
    /// Must be called from a thread that has not applied the sandbox.
    pub fn start(interval: std::time::Duration) -> Arc<Self> {
        let broker = Arc::new(Self {
            latest: RwLock::new(Some(Arc::new(capture_proc_snapshot()))),
        });
        let weak = Arc::downgrade(&broker);
        let spawned = std::thread::Builder::new()
            .name("netwatch-proc-broker".into())
            .spawn(move || loop {
                std::thread::sleep(interval);
                let Some(broker) = weak.upgrade() else {
                    break;
                };
                let snapshot = Arc::new(capture_proc_snapshot());
                *safe_write(&broker.latest, "proc_broker::publish") = Some(snapshot);
            });
        if let Err(error) = spawned {
            tracing::warn!(%error, "proc attribution broker did not start");
        }
        broker
    }

    pub fn latest(&self) -> Option<Arc<ProcSnapshot>> {
        safe_read(&self.latest, "proc_broker::latest").clone()
    }
}

/// Pre-sandbox evidence is a hint, never authority based on endpoint reuse.
#[cfg(target_os = "linux")]
pub struct ProcSnapshot {
    entries: HashMap<SocketKey, (u64, SocketOwner)>,
    captured_at: Instant,
}
#[cfg(target_os = "linux")]
pub fn capture_proc_snapshot() -> ProcSnapshot {
    let index = proc_net_inode_index();
    let owners = socket_inode_owners();
    let entries = index
        .by_pair
        .into_iter()
        .filter_map(|(key, inode)| {
            owners
                .get(&inode)
                .and_then(|o| o.clone())
                .map(|o| (key, (inode, o)))
        })
        .collect();
    ProcSnapshot {
        entries,
        captured_at: Instant::now(),
    }
}
#[cfg(target_os = "linux")]
fn overlay_proc_snapshot(connections: &mut [Connection], snap: &ProcSnapshot) {
    let index = proc_net_inode_index();
    for conn in connections {
        if conn.pid.is_some() {
            continue;
        }
        let Some(key) = socket_key(conn) else {
            continue;
        };
        let Some((inode, owner)) = snap.entries.get(&key) else {
            continue;
        };
        if snap.captured_at.elapsed() > super::attribution::MAX_MATCH_AGE {
            conn.evidence.unknown_reason = Some(super::attribution::UnknownReason::StaleSnapshot);
        } else if index.by_pair.get(&key) == Some(inode) && owner_still_valid(owner, *inode) {
            apply_owner(conn, owner);
        } else {
            conn.evidence.unknown_reason =
                Some(super::attribution::UnknownReason::IdentityUnavailable);
        }
    }
}

#[cfg(target_os = "windows")]
fn resolve_pids(pids: &[u32]) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    if pids.is_empty() {
        return map;
    }

    let output = match Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return map,
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let pid_set: HashSet<u32> = pids.iter().copied().collect();

    for line in text.lines() {
        // Format: "process.exe","1234","Console","1","12,345 K"
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 2 {
            continue;
        }
        let name = fields[0].trim_matches('"');
        let pid_str = fields[1].trim_matches('"');
        if let Ok(pid) = pid_str.parse::<u32>() {
            if pid_set.contains(&pid) {
                map.insert(pid, name.to_string());
            }
        }
    }

    map
}

#[cfg(target_os = "windows")]
fn parse_windows_connections() -> Vec<Connection> {
    let output = match Command::new("netstat").args(["-ano"]).output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);

    struct RawConn {
        protocol: String,
        local_addr: String,
        remote_addr: String,
        state: String,
        pid: Option<u32>,
    }

    let mut raw_connections = Vec::new();
    let mut all_pids = HashSet::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("TCP") && !trimmed.starts_with("UDP") {
            continue;
        }

        let cols: Vec<&str> = trimmed.split_whitespace().collect();

        let (protocol, local_addr, remote_addr, state, pid) = if cols[0] == "UDP" {
            // UDP lines: Proto LocalAddr ForeignAddr PID (no state)
            if cols.len() < 4 {
                continue;
            }
            let pid: Option<u32> = cols[3].parse().ok();
            (
                cols[0].to_string(),
                cols[1].to_string(),
                cols[2].to_string(),
                String::new(),
                pid,
            )
        } else {
            // TCP lines: Proto LocalAddr ForeignAddr State PID
            if cols.len() < 5 {
                continue;
            }
            let pid: Option<u32> = cols[4].parse().ok();
            (
                cols[0].to_string(),
                cols[1].to_string(),
                cols[2].to_string(),
                cols[3].to_string(),
                pid,
            )
        };

        if let Some(p) = pid {
            all_pids.insert(p);
        }

        raw_connections.push(RawConn {
            protocol,
            local_addr,
            remote_addr,
            state,
            pid,
        });
    }

    let pid_names = resolve_pids(&all_pids.into_iter().collect::<Vec<_>>());

    raw_connections
        .into_iter()
        .map(|rc| Connection {
            protocol: rc.protocol,
            local_addr: rc.local_addr,
            remote_addr: rc.remote_addr,
            state: rc.state,
            process_name: rc.pid.and_then(|p| pid_names.get(&p).cloned()),
            pid: rc.pid,
            handshake_rtt_us: None,
            rx_rate: None,
            tx_rate: None,
            attribution: AttributionSource::Lsof,
            evidence: Default::default(),
            app_protocol: None,
            retransmits: 0,
            out_of_order: 0,
        })
        .collect()
}

/// Export connections to JSON file
pub fn export_json(connections: &[Connection], path: &str) -> Result<usize, String> {
    use std::io::Write;
    let mut file = std::fs::File::create(path).map_err(|e| format!("Create error: {e}"))?;

    let entries: Vec<serde_json::Value> = connections
        .iter()
        .map(|c| {
            serde_json::json!({
                "process": c.process_name.as_deref().unwrap_or("—"),
                "pid": c.pid,
                "protocol": c.protocol,
                "state": c.state,
                "local_address": c.local_addr,
                "remote_address": c.remote_addr,
            })
        })
        .collect();

    let json = serde_json::to_string_pretty(&entries).map_err(|e| format!("JSON error: {e}"))?;
    file.write_all(json.as_bytes())
        .map_err(|e| format!("Write error: {e}"))?;
    Ok(connections.len())
}

/// Export connections to CSV file
pub fn export_csv(connections: &[Connection], path: &str) -> Result<usize, String> {
    use std::io::Write;
    let mut file = std::fs::File::create(path).map_err(|e| format!("Create error: {e}"))?;

    writeln!(
        file,
        "process,pid,protocol,state,local_address,remote_address"
    )
    .map_err(|e| format!("Write error: {e}"))?;

    for c in connections {
        writeln!(
            file,
            "{},{},{},{},{},{}",
            c.process_name.as_deref().unwrap_or("—"),
            c.pid.map(|p| p.to_string()).unwrap_or_else(|| "—".into()),
            c.protocol,
            c.state,
            c.local_addr,
            c.remote_addr,
        )
        .map_err(|e| format!("Write error: {e}"))?;
    }

    Ok(connections.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── process identity (issue: version-named + truncated comm) ────────

    /// The kernel's name wins over whatever lsof/PKTAP scraped — that is
    /// what collapses `Google Chrome He` and the eight `2.1.x` spellings of
    /// Claude Code onto one stable identity.
    ///
    /// Unix only: Windows has no executable-path resolver, so `stable_name`
    /// returns None there by design and names are left as scraped — asserted
    /// separately in `canonicalize_is_inert_without_a_resolver`.
    #[cfg(target_os = "linux")]
    #[test]
    fn canonicalize_replaces_the_scraped_name_for_a_live_pid() {
        let mut conns = vec![make_conn(
            "TCP",
            "1.2.3.4:1",
            "5.6.7.8:443",
            "ESTABLISHED",
            1,
        )];
        // Our own pid always resolves, so this asserts the overwrite happens.
        conns[0].pid = Some(std::process::id());
        conns[0].process_name = Some("2.1.219".into());
        canonicalize_process_names(&mut conns);
        let got = conns[0].process_name.as_deref().unwrap();
        assert_ne!(got, "2.1.219", "scraped name survived");
        assert!(
            got.contains("netwatch"),
            "expected the test binary, got {got:?}"
        );
    }

    /// A pid the kernel won't answer for must keep its existing name. This
    /// only ever upgrades attribution — it must never blank it.
    #[test]
    fn canonicalize_keeps_the_existing_name_when_the_pid_is_gone() {
        let mut conns = vec![make_conn(
            "TCP",
            "1.2.3.4:1",
            "5.6.7.8:443",
            "ESTABLISHED",
            1,
        )];
        conns[0].pid = Some(u32::MAX);
        conns[0].process_name = Some("was-here".into());
        canonicalize_process_names(&mut conns);
        assert_eq!(conns[0].process_name.as_deref(), Some("was-here"));
    }

    /// On a platform with no executable-path resolver, canonicalisation is
    /// a no-op rather than a name-eraser — the scraped name is all there is.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn canonicalize_is_inert_without_a_resolver() {
        let mut conns = vec![make_conn(
            "TCP",
            "1.2.3.4:1",
            "5.6.7.8:443",
            "ESTABLISHED",
            1,
        )];
        conns[0].pid = Some(std::process::id());
        conns[0].process_name = Some("scraped-name".into());
        canonicalize_process_names(&mut conns);
        assert_eq!(conns[0].process_name.as_deref(), Some("scraped-name"));
    }

    /// Connections with no pid are left entirely alone.
    #[test]
    fn canonicalize_ignores_connections_without_a_pid() {
        let mut conns = vec![make_conn(
            "TCP",
            "1.2.3.4:1",
            "5.6.7.8:443",
            "ESTABLISHED",
            1,
        )];
        conns[0].pid = None;
        conns[0].process_name = Some("keep-me".into());
        canonicalize_process_names(&mut conns);
        assert_eq!(conns[0].process_name.as_deref(), Some("keep-me"));
    }

    /// Two connections from one process resolve to the same name — the
    /// per-tick cache must not diverge between rows. Unix only, for the same
    /// reason as above.
    #[cfg(target_os = "linux")]
    #[test]
    fn canonicalize_is_consistent_across_rows_of_one_process() {
        let me = std::process::id();
        let mut conns = vec![
            make_conn("TCP", "1.2.3.4:1", "5.6.7.8:443", "ESTABLISHED", 1),
            make_conn("TCP", "1.2.3.4:2", "5.6.7.9:443", "ESTABLISHED", 1),
        ];
        conns[0].pid = Some(me);
        conns[1].pid = Some(me);
        conns[0].process_name = Some("Google Chrome He".into());
        conns[1].process_name = Some("Google Chrome Helper".into());
        canonicalize_process_names(&mut conns);
        assert_eq!(conns[0].process_name, conns[1].process_name);
    }

    #[test]
    fn coverage_counts_unknown_capture_flows_and_bytes_separately() {
        let mut c = make_conn("TCP", "127.0.0.1:100", "127.0.0.1:200", "ESTABLISHED", 1);
        c.evidence.process = Some(super::super::attribution::ProcessIdentity {
            session: "test".into(),
            pid: 1,
            start_token: "one".into(),
            executable: None,
            network_namespace: None,
        });
        c.evidence.unknown_reason = None;
        c.evidence.observe();
        let key = connection_stream_key(&c).unwrap().0;
        let unknown = StreamKey::new(StreamProtocol::Udp, "127.0.0.1", 300, "127.0.0.1", 400);
        let increments = HashMap::from([(key, 100), (unknown, 900)]);
        let coverage = measure_coverage(&[c.clone()], &increments);
        assert_eq!((coverage.attributed_flows, coverage.eligible_flows), (1, 2));
        assert_eq!(
            (
                coverage.attributed_payload_bytes,
                coverage.eligible_payload_bytes
            ),
            (100, 1000)
        );
        let mut conflict = c.clone();
        conflict.evidence.process.as_mut().unwrap().start_token = "reused".into();
        assert_eq!(
            measure_coverage(&[c.clone(), conflict], &increments).attributed_flows,
            0
        );
        c.evidence.observed_at = Some(Instant::now() - std::time::Duration::from_secs(10));
        assert_eq!(measure_coverage(&[c], &increments).attributed_flows, 0);
    }
    #[test]
    fn reused_pid_or_missing_poll_starts_new_flow_generation() {
        let mut registry = super::super::attribution::FlowRegistry::default();
        let mut rows = vec![make_conn(
            "TCP",
            "127.0.0.1:100",
            "127.0.0.1:200",
            "ESTABLISHED",
            1,
        )];
        rows[0].evidence.process = Some(super::super::attribution::ProcessIdentity {
            session: "test".into(),
            pid: 1,
            start_token: "one".into(),
            executable: Some("binary1".into()),
            network_namespace: None,
        });
        registry.reconcile(&mut rows);
        let first = rows[0].evidence.flow.as_ref().unwrap().generation;
        registry.reconcile(&mut rows);
        assert_eq!(first, rows[0].evidence.flow.as_ref().unwrap().generation);
        rows[0].evidence.process.as_mut().unwrap().start_token = "two".into();
        registry.reconcile(&mut rows);
        let reused = rows[0].evidence.flow.as_ref().unwrap().generation;
        assert_ne!(first, reused);
        registry.reconcile(&mut []);
        registry.reconcile(&mut rows);
        assert_ne!(reused, rows[0].evidence.flow.as_ref().unwrap().generation);
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn cached_identity_cannot_name_a_reused_pid() {
        let mut c = make_conn(
            "TCP",
            "127.0.0.1:100",
            "127.0.0.1:200",
            "ESTABLISHED",
            std::process::id(),
        );
        let mut identity = super::super::attribution::process_identity(std::process::id()).unwrap();
        identity.start_token = "wrong-start".into();
        c.evidence.process = Some(identity);
        canonicalize_process_names(std::slice::from_mut(&mut c));
        assert!(c.pid.is_none());
        assert!(c.process_name.is_none());
        assert_eq!(
            c.evidence.unknown_reason,
            Some(super::super::attribution::UnknownReason::IdentityChanged)
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn brokered_snapshot_attributes_without_local_fd_scan_and_rejects_stale_or_reused() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect("127.0.0.1:45679").unwrap();
        let local = socket.local_addr().unwrap().to_string();
        let mut snap = capture_proc_snapshot();
        let conn = || make_conn("UDP", &local, "127.0.0.1:45679", "", 1);

        let mut c = conn();
        overlay_proc_attribution(std::slice::from_mut(&mut c), Some(&snap));
        assert_eq!(c.pid, Some(std::process::id()));
        assert_eq!(c.attribution, AttributionSource::Procfs);

        // A stale broker snapshot is ignored in favour of the local scan.
        snap.captured_at = Instant::now() - std::time::Duration::from_secs(10);
        let mut c = conn();
        overlay_proc_attribution(std::slice::from_mut(&mut c), Some(&snap));
        assert_eq!(c.pid, Some(std::process::id()));

        // An owner recorded for a different inode on the same 5-tuple is not applied.
        snap.captured_at = Instant::now();
        let key = socket_key(&conn()).unwrap();
        snap.entries.get_mut(&key).unwrap().0 += 1;
        let mut c = conn();
        overlay_proc_attribution(std::slice::from_mut(&mut c), Some(&snap));
        assert!(c.pid.is_none());
        assert_eq!(
            c.evidence.unknown_reason,
            Some(super::super::attribution::UnknownReason::IdentityChanged)
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn proc_broker_publishes_fresh_snapshots_and_stops_with_its_owner() {
        let broker = ProcBroker::start(std::time::Duration::from_millis(20));
        // A /proc scan can take a while on a loaded test runner: poll, don't race.
        let eventually = |done: &dyn Fn() -> bool| {
            let deadline = Instant::now() + std::time::Duration::from_secs(10);
            while !done() && Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            done()
        };
        let first = broker.latest().unwrap().captured_at;
        assert!(eventually(&|| broker.latest().unwrap().captured_at > first));
        let weak = Arc::downgrade(&broker);
        drop(broker);
        assert!(eventually(&|| weak.upgrade().is_none()));
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn startup_snapshot_expires_and_revalidates_socket_identity() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect("127.0.0.1:45678").unwrap();
        let mut snap = capture_proc_snapshot();
        let mut c = make_conn(
            "UDP",
            &socket.local_addr().unwrap().to_string(),
            "127.0.0.1:45678",
            "",
            1,
        );
        c.pid = None;
        c.process_name = None;
        overlay_proc_snapshot(std::slice::from_mut(&mut c), &snap);
        assert_eq!(c.pid, Some(std::process::id()));
        c.pid = None;
        c.process_name = None;
        c.evidence = Default::default();
        snap.captured_at = Instant::now() - std::time::Duration::from_secs(10);
        overlay_proc_snapshot(std::slice::from_mut(&mut c), &snap);
        assert!(c.pid.is_none());
        assert_eq!(
            c.evidence.unknown_reason,
            Some(super::super::attribution::UnknownReason::StaleSnapshot)
        );
        snap.captured_at = Instant::now();
        drop(socket);
        overlay_proc_snapshot(std::slice::from_mut(&mut c), &snap);
        assert!(c.pid.is_none());
    }
    #[cfg(feature = "ebpf")]
    #[test]
    fn destination_event_never_overwrites_an_independent_owner() {
        let ebpf = crate::ebpf::conn_tracker::EbpfAttributor::new();
        ebpf.record_for_test(
            netwatch_sdk::ebpf::Protocol::Tcp,
            "127.0.0.1".parse().unwrap(),
            443,
            98765,
        );
        let mut c = make_conn(
            "TCP",
            "127.0.0.1:100",
            "127.0.0.1:443",
            "ESTABLISHED",
            12345,
        );
        overlay_ebpf_attribution(std::slice::from_mut(&mut c), &ebpf);
        assert_eq!(c.pid, Some(12345));
        c.pid = None;
        c.process_name = None;
        overlay_ebpf_attribution(std::slice::from_mut(&mut c), &ebpf);
        assert!(c.pid.is_none());
        assert_eq!(
            c.evidence.unknown_reason,
            Some(super::super::attribution::UnknownReason::IncompleteEventKey)
        );
    }

    /// Independent child emits its own endpoints/start token. No collector code
    /// participates in generating expected ownership. Used by the controlled matrix.
    #[cfg(target_os = "linux")]
    #[test]
    fn controlled_workload_child() {
        use std::io::Write;
        let Ok(remote) = std::env::var("NETWATCH_ATTR_REMOTE") else {
            return;
        };
        let protocol = std::env::var("NETWATCH_ATTR_PROTOCOL").unwrap();
        let short = std::env::var("NETWATCH_ATTR_SHORT").is_ok();
        let pid = std::process::id();
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let start = stat
            .rsplit_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .nth(19)
            .unwrap();
        let (local, socket): (String, Box<dyn std::any::Any>) = if protocol == "TCP" {
            let mut socket = std::net::TcpStream::connect(&remote).unwrap();
            socket
                .write_all(b"independent attribution workload")
                .unwrap();
            (socket.local_addr().unwrap().to_string(), Box::new(socket))
        } else {
            let socket = std::net::UdpSocket::bind(if remote.starts_with('[') {
                "[::1]:0"
            } else {
                "127.0.0.1:0"
            })
            .unwrap();
            socket.connect(&remote).unwrap();
            socket.send(b"independent attribution workload").unwrap();
            (socket.local_addr().unwrap().to_string(), Box::new(socket))
        };
        let socket = if short {
            drop(socket);
            None
        } else {
            Some(socket)
        };
        println!(
            "ATTR_EXPECTED {}",
            serde_json::json!({"pid":pid,"start":start,"protocol":protocol,"local":local,"remote":remote,"short":short,"logged_at_unix_ms":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()})
        );
        std::io::stdout().flush().unwrap();
        // Parent owns lifetime and always kills/reaps this test subprocess.
        let _keep_open = socket;
        loop {
            std::thread::park();
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn controlled_polling_matrix_matches_independent_processes() {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        for ipv6 in [false, true] {
            for protocol in ["TCP", "UDP"] {
                let bind = if ipv6 { "[::1]:0" } else { "127.0.0.1:0" };
                let (remote, _server): (String, Box<dyn std::any::Any>) = if protocol == "TCP" {
                    let listener = std::net::TcpListener::bind(bind).unwrap();
                    (
                        listener.local_addr().unwrap().to_string(),
                        Box::new(listener),
                    )
                } else {
                    let socket = std::net::UdpSocket::bind(bind).unwrap();
                    (socket.local_addr().unwrap().to_string(), Box::new(socket))
                };
                let mut children = Vec::new();
                let mut expected = Vec::new();
                // Two independent owners sharing a destination plus a flow closed
                // before the poll: incorrect and unknown must remain separate.
                for short in [false, false, true] {
                    let mut cmd = Command::new(std::env::current_exe().unwrap());
                    cmd.args([
                        "--exact",
                        "collectors::connections::tests::controlled_workload_child",
                        "--nocapture",
                    ])
                    .env("NETWATCH_ATTR_REMOTE", &remote)
                    .env("NETWATCH_ATTR_PROTOCOL", protocol)
                    .env_remove("NETWATCH_ATTR_SHORT")
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit());
                    if short {
                        cmd.env("NETWATCH_ATTR_SHORT", "1");
                    }
                    let mut child = Child(cmd.spawn().unwrap());
                    let stdout = child.0.stdout.take().unwrap();
                    let record = BufReader::new(stdout)
                        .lines()
                        .map(Result::unwrap)
                        .find_map(|line| line.strip_prefix("ATTR_EXPECTED ").map(str::to_owned))
                        .expect("child record");
                    println!("ATTR_EXPECTED {record}");
                    expected.push(serde_json::from_str::<serde_json::Value>(&record).unwrap());
                    children.push(child);
                }
                // These sockets predate collection and remain open over repeat polls.
                for poll in 0..2 {
                    let actual = parse_linux_connections();
                    let (mut correct, mut wrong, mut unknown) = (0, 0, 0);
                    for expected in &expected {
                        let row = actual.iter().find(|c| {
                            c.protocol == protocol
                                && c.local_addr == expected["local"].as_str().unwrap()
                                && c.remote_addr == remote
                        });
                        if expected["short"].as_bool().unwrap() {
                            assert!(
                                row.is_none_or(|r| r.pid.is_none()),
                                "closed flow must not retain an owner: {row:?}"
                            );
                            continue;
                        }
                        match row.and_then(|c| c.evidence.process.as_ref()) {
                            Some(identity)
                                if identity.pid == expected["pid"].as_u64().unwrap() as u32
                                    && identity.start_token
                                        == expected["start"].as_str().unwrap() =>
                            {
                                correct += 1
                            }
                            Some(_) => wrong += 1,
                            None => unknown += 1,
                        }
                    }
                    println!(
                        "ATTR_RESULT {}",
                        serde_json::json!({"platform":"linux","backend":"procfs_polling","protocol":protocol,"family":if ipv6 {"ipv6"} else {"ipv4"},"poll":poll,"eligible":2,"correct":correct,"wrong":wrong,"unknown":unknown,"closed_before_poll":1})
                    );
                    assert_eq!((correct, wrong, unknown), (2, 0, 0));
                }
                drop(children);
            }
        }
    }

    fn make_conn(proto: &str, local: &str, remote: &str, state: &str, pid: u32) -> Connection {
        Connection {
            protocol: proto.into(),
            local_addr: local.into(),
            remote_addr: remote.into(),
            state: state.into(),
            pid: Some(pid),
            process_name: Some("test".into()),
            handshake_rtt_us: None,
            rx_rate: None,
            tx_rate: None,
            attribution: AttributionSource::Lsof,
            evidence: Default::default(),
            app_protocol: None,
            retransmits: 0,
            out_of_order: 0,
        }
    }

    #[cfg(feature = "ebpf")]
    mod parse_endpoint {
        use super::super::parse_endpoint;
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        #[test]
        fn parses_ipv4_host_port() {
            assert_eq!(
                parse_endpoint("1.2.3.4:5678"),
                (Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))), Some(5678))
            );
        }

        #[test]
        fn parses_bracketed_ipv6() {
            assert_eq!(
                parse_endpoint("[2606:4700::6810:85e5]:443"),
                (
                    Some("2606:4700::6810:85e5".parse::<IpAddr>().unwrap()),
                    Some(443)
                )
            );
        }

        #[test]
        fn parses_bare_ipv6_with_trailing_port() {
            assert_eq!(
                parse_endpoint("2606:4700::6810:85e5:443"),
                (
                    Some("2606:4700::6810:85e5".parse::<IpAddr>().unwrap()),
                    Some(443)
                )
            );
        }

        #[test]
        fn canonicalises_v4_mapped_ipv6_to_v4() {
            // ss prints dual-stack peers in v4-mapped form; the kprobe
            // cache stores them canonicalised to V4, so the parser must
            // agree or those rows never attribute.
            assert_eq!(
                parse_endpoint("[::ffff:93.184.216.34]:80"),
                (Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))), Some(80))
            );
        }

        #[test]
        fn loopback_v6_without_port_yields_no_ip() {
            assert_eq!(parse_endpoint("::1").0, None);
            assert_eq!(
                parse_endpoint("[::1]:8080"),
                (Some(IpAddr::V6(Ipv6Addr::LOCALHOST)), Some(8080))
            );
        }

        #[test]
        fn wildcard_remote_yields_none() {
            assert_eq!(parse_endpoint("*:*"), (None, None));
        }
    }

    /// Live seam test: make a real `::1` connection, run the actual `ss`
    /// collector path, and check the verbatim remote_addr it stored parses
    /// back to the same `(IpAddr, port)` the eBPF cache would be keyed on.
    /// Unit tests cover the formats we *expect* ss to emit; this catches
    /// the format it *actually* emits on the host. No root needed.
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    #[test]
    fn live_ss_v6_remote_addr_round_trips_through_parse_endpoint() {
        use std::net::{IpAddr, Ipv6Addr, TcpListener, TcpStream};

        let listener = TcpListener::bind("[::1]:0").expect("bind ::1 listener");
        let port = listener.local_addr().unwrap().port();
        let _conn = TcpStream::connect((Ipv6Addr::LOCALHOST, port)).expect("connect to ::1");

        let conns = parse_linux_connections();
        if conns.is_empty() {
            eprintln!("ss produced no rows (not installed?); skipping");
            return;
        }

        // Our client row: TCP, established, remote port == the listener's.
        // Locating it *via parse_endpoint* is the point — if ss's v6
        // format defeats the parser, the row is unfindable and we fail.
        let row = conns
            .iter()
            .find(|c| {
                c.protocol.eq_ignore_ascii_case("tcp")
                    && c.state == "ESTABLISHED"
                    && parse_endpoint(&c.remote_addr)
                        == (Some(IpAddr::V6(Ipv6Addr::LOCALHOST)), Some(port))
            })
            .unwrap_or_else(|| {
                panic!(
                    "no ss row parsed back to ([::1], {port}); raw remotes: {:?}",
                    conns
                        .iter()
                        .filter(|c| c.protocol.eq_ignore_ascii_case("tcp"))
                        .map(|c| c.remote_addr.as_str())
                        .collect::<Vec<_>>()
                )
            });
        eprintln!("matched ss row remote_addr={:?}", row.remote_addr);
    }

    #[test]
    fn new_timeline_is_empty() {
        let tl = ConnectionTimeline::new();
        assert!(tl.tracked.is_empty());
    }

    #[test]
    fn proc_net_hex_ipv4_localhost() {
        // Kernel renders 127.0.0.1:53 as little-endian "0100007F:0035".
        let (ip, port) = parse_proc_net_hex("0100007F:0035").unwrap();
        assert_eq!(ip, "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(port, 53);
    }

    #[test]
    fn proc_net_hex_ipv4_routable_port() {
        let (ip, port) = parse_proc_net_hex("0F02000A:1F90").unwrap();
        assert_eq!(ip, "10.0.2.15".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(port, 8080);
    }

    #[test]
    fn proc_net_hex_ipv6_loopback() {
        // ::1 → three zero words then 01000000 (little-endian last word).
        let (ip, port) = parse_proc_net_hex("00000000000000000000000001000000:0050").unwrap();
        assert_eq!(ip, "::1".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(port, 80);
    }

    #[test]
    fn proc_net_hex_rejects_garbage() {
        assert!(parse_proc_net_hex("nope").is_none());
        assert!(parse_proc_net_hex("0100007F").is_none());
        assert!(parse_proc_net_hex("12:0035").is_none());
    }

    #[test]
    fn normalize_addr_v4_v6_and_wildcards() {
        assert_eq!(
            normalize_addr("1.2.3.4:443"),
            Some(("1.2.3.4".parse().unwrap(), 443))
        );
        assert_eq!(
            normalize_addr("[2001:db8::1]:22"),
            Some(("2001:db8::1".parse().unwrap(), 22))
        );
        assert_eq!(normalize_addr("*:*"), None);
        assert_eq!(normalize_addr("0.0.0.0:*"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ss_process_field_with_space_in_name() {
        // Regression: Firefox child processes have spaces in comm. The whole
        // `users:((...))` field must reach the parser intact (the caller now
        // slices from `users:((` rather than a whitespace column).
        let (pid, name) = parse_ss_process(r#"users:(("Isolated Web Co",pid=4242,fd=91))"#);
        assert_eq!(pid, Some(4242));
        assert_eq!(name.as_deref(), Some("Isolated Web Co"));
    }

    #[test]
    fn update_adds_new_connections() {
        let mut tl = ConnectionTimeline::new();
        let conns = vec![
            make_conn("TCP", "127.0.0.1:8080", "10.0.0.1:443", "ESTABLISHED", 100),
            make_conn("UDP", "0.0.0.0:53", "*:*", "", 200),
        ];
        tl.update(&conns);
        assert_eq!(tl.tracked.len(), 2);
        assert!(tl.tracked.iter().all(|t| t.is_active));
    }

    #[test]
    fn update_marks_existing_connections_active() {
        let mut tl = ConnectionTimeline::new();
        let conns = vec![make_conn(
            "TCP",
            "127.0.0.1:8080",
            "10.0.0.1:443",
            "ESTABLISHED",
            100,
        )];
        tl.update(&conns);
        tl.update(&conns);
        assert_eq!(tl.tracked.len(), 1);
        assert!(tl.tracked[0].is_active);
    }

    #[test]
    fn update_marks_disappeared_connections_inactive() {
        let mut tl = ConnectionTimeline::new();
        let conns = vec![make_conn(
            "TCP",
            "127.0.0.1:8080",
            "10.0.0.1:443",
            "ESTABLISHED",
            100,
        )];
        tl.update(&conns);
        tl.update(&[]);
        assert_eq!(tl.tracked.len(), 1);
        assert!(!tl.tracked[0].is_active);
    }

    #[test]
    fn update_changes_state() {
        let mut tl = ConnectionTimeline::new();
        let c1 = vec![make_conn(
            "TCP",
            "127.0.0.1:8080",
            "10.0.0.1:443",
            "ESTABLISHED",
            100,
        )];
        tl.update(&c1);
        assert_eq!(tl.tracked[0].state, "ESTABLISHED");

        let c2 = vec![make_conn(
            "TCP",
            "127.0.0.1:8080",
            "10.0.0.1:443",
            "TIME_WAIT",
            100,
        )];
        tl.update(&c2);
        assert_eq!(tl.tracked[0].state, "TIME_WAIT");
    }

    #[test]
    fn connection_key_equality() {
        let k1 = ConnectionKey {
            protocol: "TCP".into(),
            local_addr: "127.0.0.1:80".into(),
            remote_addr: "10.0.0.1:443".into(),
            pid: Some(42),
        };
        let k2 = ConnectionKey {
            protocol: "TCP".into(),
            local_addr: "127.0.0.1:80".into(),
            remote_addr: "10.0.0.1:443".into(),
            pid: Some(42),
        };
        assert_eq!(k1, k2);

        let k3 = ConnectionKey {
            protocol: "UDP".into(),
            local_addr: "127.0.0.1:80".into(),
            remote_addr: "10.0.0.1:443".into(),
            pid: Some(42),
        };
        assert_ne!(k1, k3);
    }

    #[test]
    fn connection_key_deduplicates_in_timeline() {
        let mut tl = ConnectionTimeline::new();
        let conn = make_conn("TCP", "127.0.0.1:8080", "10.0.0.1:443", "ESTABLISHED", 100);
        tl.update(&[conn.clone(), conn.clone()]);
        assert_eq!(tl.tracked.len(), 1);
    }

    #[test]
    fn inactive_connection_becomes_active_on_reappearance() {
        let mut tl = ConnectionTimeline::new();
        let conns = vec![make_conn(
            "TCP",
            "127.0.0.1:8080",
            "10.0.0.1:443",
            "ESTABLISHED",
            100,
        )];
        tl.update(&conns);
        tl.update(&[]);
        assert!(!tl.tracked[0].is_active);
        tl.update(&conns);
        assert!(tl.tracked[0].is_active);
    }

    #[test]
    fn eviction_removes_oldest_inactive_over_limit() {
        let mut tl = ConnectionTimeline::new();

        // Add MAX_TRACKED_CONNECTIONS active connections
        let conns: Vec<Connection> = (0..MAX_TRACKED_CONNECTIONS as u32)
            .map(|i| {
                make_conn(
                    "TCP",
                    &format!("127.0.0.1:{}", i),
                    "10.0.0.1:443",
                    "ESTABLISHED",
                    i,
                )
            })
            .collect();
        tl.update(&conns);
        assert_eq!(tl.tracked.len(), MAX_TRACKED_CONNECTIONS);

        // Mark all as inactive, then add new ones to exceed the limit
        tl.update(&[]);
        let extra: Vec<Connection> = (0..10u32)
            .map(|i| {
                make_conn(
                    "TCP",
                    &format!("192.168.0.1:{}", i),
                    "10.0.0.1:443",
                    "ESTABLISHED",
                    50000 + i,
                )
            })
            .collect();
        tl.update(&extra);

        // Should have evicted enough inactive to get back to MAX_TRACKED_CONNECTIONS
        assert_eq!(tl.tracked.len(), MAX_TRACKED_CONNECTIONS);
        // All extra connections should still be present
        for i in 0..10u32 {
            let key = ConnectionKey {
                protocol: "TCP".into(),
                local_addr: format!("192.168.0.1:{}", i),
                remote_addr: "10.0.0.1:443".into(),
                pid: Some(50000 + i),
            };
            assert!(tl.known_keys.contains_key(&key));
        }
    }

    #[test]
    fn multiple_protocols_tracked_separately() {
        let mut tl = ConnectionTimeline::new();
        let conns = vec![
            make_conn("TCP", "127.0.0.1:80", "10.0.0.1:443", "ESTABLISHED", 100),
            make_conn("UDP", "127.0.0.1:80", "10.0.0.1:443", "", 100),
        ];
        tl.update(&conns);
        assert_eq!(tl.tracked.len(), 2);
    }

    #[test]
    fn export_json_creates_valid_file() {
        let dir = std::env::temp_dir().join("netwatch_test_export");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.json");

        let conns = vec![make_conn(
            "TCP",
            "127.0.0.1:80",
            "10.0.0.1:443",
            "ESTABLISHED",
            100,
        )];
        let count = export_json(&conns, path.to_str().unwrap()).unwrap();
        assert_eq!(count, 1);

        let contents = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_csv_creates_valid_file() {
        let dir = std::env::temp_dir().join("netwatch_test_export_csv");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.csv");

        let conns = vec![
            make_conn("TCP", "127.0.0.1:80", "10.0.0.1:443", "ESTABLISHED", 100),
            make_conn("UDP", "0.0.0.0:53", "*:*", "", 200),
        ];
        let count = export_csv(&conns, path.to_str().unwrap()).unwrap();
        assert_eq!(count, 2);

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3); // header + 2 data rows
        assert!(lines[0].contains("process,pid,protocol"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_host_port_ipv4() {
        assert_eq!(
            parse_host_port("127.0.0.1:8080"),
            Some(("127.0.0.1".into(), 8080))
        );
    }

    #[test]
    fn parse_host_port_ipv6_bracketed() {
        assert_eq!(parse_host_port("[::1]:443"), Some(("::1".into(), 443)));
    }

    #[test]
    fn parse_host_port_ipv6_unbracketed() {
        // ss -n occasionally emits unbracketed IPv6 with the last colon as
        // the port separator.
        assert_eq!(parse_host_port("fe80::1:22"), Some(("fe80::1".into(), 22)));
    }

    #[test]
    fn parse_host_port_wildcard_rejected() {
        assert_eq!(parse_host_port("*:*"), None);
        assert_eq!(parse_host_port("*:22"), None);
        assert_eq!(parse_host_port(""), None);
    }

    #[test]
    fn normalize_ipv4_mapped_ipv6() {
        assert_eq!(normalize_ip("::ffff:1.2.3.4"), "1.2.3.4");
        // Non-mapped v6 is left untouched.
        assert_eq!(normalize_ip("::1"), "::1");
        assert_eq!(normalize_ip("fe80::1"), "fe80::1");
    }

    #[test]
    fn connection_stream_key_orients_local() {
        let conn = make_conn("TCP", "10.0.0.2:50000", "1.1.1.1:443", "ESTABLISHED", 42);
        let (key, side) = connection_stream_key(&conn).expect("canonicalized");
        // StreamKey sorts addr_a <= addr_b. 1.1.1.1 < 10.0.0.2 alphabetically,
        // so 1.1.1.1 is addr_a and our local (10.0.0.2) is addr_b.
        assert_eq!(key.addr_a, ("1.1.1.1".into(), 443));
        assert_eq!(key.addr_b, ("10.0.0.2".into(), 50000));
        assert_eq!(side, LocalSide::B);
    }

    #[test]
    fn connection_stream_key_rejects_udp_with_wildcard_remote() {
        let conn = make_conn("UDP", "0.0.0.0:53", "*:*", "", 1);
        assert!(connection_stream_key(&conn).is_none());
    }

    #[test]
    fn rate_state_computes_delta() {
        use std::time::Duration;
        let key = StreamKey::new(StreamProtocol::Tcp, "1.1.1.1", 443, "10.0.0.2", 50000);
        let mut state = RateState::new();
        // First tick establishes the baseline; no rates yet.
        let t0 = Instant::now();
        state.prev_time = t0;
        let mut snap1 = HashMap::new();
        snap1.insert(key.clone(), (0u64, 0u64));
        state.tick(snap1, t0 + Duration::from_millis(1));
        assert!(state.rates.is_empty());

        // Second tick: 1000 bytes a→b, 2000 bytes b→a over 1 second.
        let mut snap2 = HashMap::new();
        snap2.insert(key.clone(), (1_000u64, 2_000u64));
        state.tick(snap2, t0 + Duration::from_millis(1001));
        let &(a_to_b, b_to_a) = state.rates.get(&key).unwrap();
        assert!((a_to_b - 1000.0).abs() < 1.0);
        assert!((b_to_a - 2000.0).abs() < 1.0);
    }

    #[test]
    fn rate_state_orients_by_local_side() {
        let key = StreamKey::new(StreamProtocol::Tcp, "1.1.1.1", 443, "10.0.0.2", 50000);
        let mut state = RateState::new();
        state.rates.insert(key.clone(), (1000.0, 2000.0));
        // Local is addr_a (1.1.1.1): rx = b_to_a = 2000, tx = a_to_b = 1000.
        assert_eq!(state.rate_for(&key, LocalSide::A), Some((2000.0, 1000.0)));
        // Local is addr_b (10.0.0.2): rx = a_to_b = 1000, tx = b_to_a = 2000.
        assert_eq!(state.rate_for(&key, LocalSide::B), Some((1000.0, 2000.0)));
    }
}
