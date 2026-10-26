use crate::app::{safe_lock, safe_read, safe_write};
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
    /// FreeBSD: parsed from `sockstat`'s own PID/COMMAND columns — a direct
    /// kernel socket-table walk, but still a point-in-time poll like `Lsof`,
    /// not an independently corroborated event.
    Sockstat,
    /// Windows: the owning PID the kernel's TCP and UDP tables keep for each
    /// socket, read through IP Helper (`GetExtendedTcpTable`). Kernel data,
    /// but a point-in-time poll like `Sockstat`, with no process-start
    /// identity behind the PID. Rows from the `netstat -ano` fallback stay
    /// `Lsof`, the label Linux's scraped `ss` rows carry too.
    IpHelper,
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

/// The address as packet capture reports it, so the row keys to its stream:
/// see [`canonical_ip`](crate::collectors::packets::canonical_ip) for what
/// that undoes. A host that is not an address is kept as printed.
fn normalize_ip(ip: &str) -> String {
    crate::collectors::packets::canonical_ip(ip).unwrap_or_else(|| ip.to_string())
}

/// Last-resort match for UDP Connections whose remote is wildcard
/// (typical of `lsof`'s view of QUIC sockets on macOS). Returns the
/// AppProtocol of any tracked Stream that shares the Connection's
/// local endpoint, or `None` if no such Stream exists. `by_local` is
/// [`udp_app_protocols_by_local`] of the poll's stream snapshot.
fn match_udp_app_protocol_by_local(
    conn: &Connection,
    by_local: &HashMap<(String, u16), crate::dpi::AppProtocol>,
) -> Option<crate::dpi::AppProtocol> {
    if stream_protocol(&conn.protocol)? != StreamProtocol::Udp {
        return None;
    }
    by_local.get(&parse_host_port(&conn.local_addr)?).cloned()
}

/// Each UDP stream's AppProtocol under both of its endpoints, built once per
/// poll. Searching every stream for each wildcard row instead cost the poll
/// O(rows × streams). Where streams share an endpoint, the first in
/// `app_protos`'s order wins, as it did in that search.
fn udp_app_protocols_by_local(
    app_protos: &HashMap<StreamKey, crate::dpi::AppProtocol>,
) -> HashMap<(String, u16), crate::dpi::AppProtocol> {
    let mut by_local = HashMap::new();
    for (key, ap) in app_protos {
        if key.protocol != StreamProtocol::Udp {
            continue;
        }
        for endpoint in [&key.addr_a, &key.addr_b] {
            by_local
                .entry(endpoint.clone())
                .or_insert_with(|| ap.clone());
        }
    }
    by_local
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
    /// Latest connection list and its generation, published via the
    /// `Arc<RwLock<…Arc<…>>>` snapshot pattern. Readers clone the inner `Arc`
    /// in O(1) instead of contending with the background `update()` thread
    /// on an exclusive lock across an arbitrarily large `Vec<Connection>`.
    snapshot: Arc<RwLock<Published>>,
    /// What [`Self::connections`] last returned, reused until the next
    /// publish or until another of its rows goes stale.
    served: Mutex<Option<Served>>,
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
    /// The `ss` the Linux poll runs: [`SS_PROGRAM`], except in tests that
    /// need one that is missing or cannot run.
    #[cfg(target_os = "linux")]
    ss_program: &'static str,
}

impl ConnectionCollector {
    pub fn new(stream_tracker: Arc<Mutex<StreamTracker>>) -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(Published::default())),
            served: Mutex::new(None),
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
            #[cfg(target_os = "linux")]
            ss_program: SS_PROGRAM,
        }
    }

    /// Cheap snapshot of the most recent connection list. Rows whose
    /// evidence is older than `MAX_MATCH_AGE` show without an owner or rates.
    /// The same `Arc` comes back until the next publish or until another row
    /// goes stale, so a call is a refcount bump regardless of connection
    /// count, and a caller can tell the table changed when the pointer does.
    /// The returned `Arc` derefs to `&Vec<Connection>` so call sites work
    /// with it like a slice.
    pub fn connections(&self) -> Arc<Vec<Connection>> {
        self.connections_with_generation().1
    }

    /// [`Self::connections`], and a generation that changes whenever the
    /// table it returns does: one more after every publish, and one more
    /// each time a row goes stale between publishes, which blanks its owner
    /// with no new poll. A view built from the table can key on the
    /// generation alone. Both come from one call, so a poll that publishes
    /// in between cannot pair one table's generation with another's rows.
    pub fn connections_with_generation(&self) -> (u64, Arc<Vec<Connection>>) {
        let mut served = safe_lock(&self.served, "connections::served");
        // Read under `served`, so a reader holding an older publish cannot
        // replace a newer one there and take the generation backwards.
        let (snapshot, published) = {
            let published = safe_read(&self.snapshot, "connections::snapshot");
            (Arc::clone(&published.rows), published.generation)
        };
        let now = Instant::now();
        if let Some(hit) = served
            .as_ref()
            .filter(|s| s.published == published && s.until.is_none_or(|until| now <= until))
        {
            return (hit.generation(), Arc::clone(&hit.rows));
        }
        // The same publish served again means another row went stale.
        let strips = served
            .as_ref()
            .map_or(0, |s| s.strips + u64::from(s.published == published));
        let (rows, until) = strip_stale(snapshot, now);
        let next = Served {
            published,
            strips,
            rows,
            until,
        };
        let generation = next.generation();
        let rows = Arc::clone(&next.rows);
        *served = Some(next);
        (generation, rows)
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
    pub fn with_proc_snapshot(mut self, snapshot: Arc<ProcSnapshot>) -> Self {
        self.proc_snapshot = Some(snapshot);
        self
    }

    /// Attach the unconfined socket-ownership broker (see [`ProcBroker`]),
    /// started in `App::prepare` before any worker confinement.
    #[cfg(target_os = "linux")]
    pub fn with_proc_broker(mut self, broker: Arc<ProcBroker>) -> Self {
        self.proc_broker = Some(broker);
        self
    }

    /// Run `program` in place of `ss`, to exercise the `/proc/net` fallback.
    #[cfg(all(target_os = "linux", test))]
    pub(crate) fn with_ss_program(mut self, program: &'static str) -> Self {
        self.ss_program = program;
        self
    }

    /// Publish `rows` as if a poll had produced them, for render tests.
    #[cfg(test)]
    pub(crate) fn publish_for_test(&self, rows: Vec<Connection>) {
        publish(&self.snapshot, rows);
    }

    /// Whether the poll [`Self::update`] spawned is still running, for tests
    /// that time one.
    #[cfg(all(target_os = "linux", test))]
    pub(crate) fn poll_in_flight(&self) -> bool {
        self.busy.load(Ordering::SeqCst)
    }

    /// Record `coverage` as if a poll had measured it, for render tests.
    #[cfg(all(target_os = "linux", test))]
    pub(crate) fn set_coverage_for_test(&self, coverage: super::attribution::Coverage) {
        *safe_write(&self.coverage, "connections::coverage") = coverage;
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
        #[cfg(target_os = "linux")]
        let ss_program = self.ss_program;
        crate::sandbox::worker::spawn("connections", move || {
            #[cfg(target_os = "macos")]
            let mut result = parse_lsof();
            #[cfg(target_os = "freebsd")]
            let mut result = parse_sockstat();
            #[cfg(target_os = "linux")]
            let collected = parse_linux_connections_result(ss_program, brokered.as_deref());
            #[cfg(target_os = "linux")]
            let collection_succeeded = collected.is_ok();
            #[cfg(target_os = "linux")]
            let (mut result, table_source, table_note) = match collected {
                Ok(table) => (table.rows, Some(table.source), table.note),
                Err(error) => (Vec::new(), None, Some(error)),
            };
            #[cfg(not(target_os = "linux"))]
            let collection_succeeded = false;
            #[cfg(not(target_os = "linux"))]
            let (table_source, table_note) = (None, None);
            #[cfg(target_os = "windows")]
            let mut result = parse_windows_connections();
            #[cfg(not(any(
                target_os = "macos",
                target_os = "linux",
                target_os = "freebsd",
                target_os = "windows"
            )))]
            let mut result: Vec<Connection> = Vec::new();

            let (stream_bytes, app_protos, anomalies, handshake_rtts, generations) = {
                let tracker = safe_lock(&stream_tracker, "connections::stream_snapshot");
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
            let udp_by_local = udp_app_protocols_by_local(&app_protos);
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
                    if let Some(proto) = match_udp_app_protocol_by_local(conn, &udp_by_local) {
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
            sanitize_process_names(&mut result);

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
            let mut measured = measure_coverage(&result, &increments);
            measured.collection_succeeded = collection_succeeded;
            measured.table_source = table_source;
            measured.table_note = table_note;
            #[cfg(target_os = "linux")]
            log_table_source_change(&safe_read(&coverage, "connections::coverage"), &measured);
            *safe_write(&coverage, "connections::coverage") = measured;
            let count = result.len();
            publish(&snapshot, result);
            tracing::trace!(target: "netwatch::connections", count, "published connection snapshot");
            busy.store(false, Ordering::SeqCst);
        });
    }
}

/// A poll's table, and how many tables have been published up to and
/// including it. The count sits in the lock with the table rather than in an
/// `AtomicU64`, which armv5te does not have, and a reader gets both from one
/// read.
#[derive(Default)]
struct Published {
    rows: Arc<Vec<Connection>>,
    generation: u64,
}

/// What [`ConnectionCollector::connections`] returned for one publish.
struct Served {
    /// The [`Published::generation`] `rows` came from.
    published: u64,
    /// How many times a row went stale between publishes, counting every
    /// publish so far.
    strips: u64,
    rows: Arc<Vec<Connection>>,
    /// When the next of `rows`' fresh rows goes stale; `None` when every row
    /// already has.
    until: Option<Instant>,
}

impl Served {
    /// What [`ConnectionCollector::connections_with_generation`] reports:
    /// each publish and each strip adds one, so no two tables share it.
    fn generation(&self) -> u64 {
        self.published + self.strips
    }
}

/// Replace the published table and count it, in one write.
fn publish(snapshot: &RwLock<Published>, rows: Vec<Connection>) {
    let mut published = safe_write(snapshot, "connections::publish");
    published.rows = Arc::new(rows);
    published.generation += 1;
}

/// `snapshot` as readers see it at `now`: a row whose evidence is older than
/// `MAX_MATCH_AGE` loses its owner and rates, since neither can be vouched
/// for any more. Also returns when the next of the remaining fresh rows will
/// go stale. The table is copied only when some row is stale.
fn strip_stale(
    snapshot: Arc<Vec<Connection>>,
    now: Instant,
) -> (Arc<Vec<Connection>>, Option<Instant>) {
    // When a row's evidence goes stale, or `None` if it already has: the
    // test `MatchEvidence::fresh` makes, at `now`.
    let fresh_until = |c: &Connection| {
        c.evidence
            .observed_at
            .and_then(|t| t.checked_add(super::attribution::MAX_MATCH_AGE))
            .filter(|&until| now <= until)
    };
    let until = snapshot.iter().filter_map(fresh_until).min();
    if snapshot.iter().all(|c| fresh_until(c).is_some()) {
        return (snapshot, until);
    }
    let mut rows = (*snapshot).clone();
    for row in &mut rows {
        if fresh_until(row).is_none() {
            row.pid = None;
            row.process_name = None;
            row.evidence.process = None;
            row.evidence.unknown_reason = Some(super::attribution::UnknownReason::StaleSnapshot);
            row.rx_rate = None;
            row.tx_rate = None;
        }
    }
    (Arc::new(rows), until)
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
/// Resolution is memoised within a poll by PID: the identity is read once
/// before the executable lookup and once after it, however many rows the
/// process owns. Reading it twice per row cost a 10,000-socket poll about
/// 200 ms. Identity changes invalidate names rather than promoting old event
/// names to a new PID: a row recorded for another process than the one this
/// poll read, or a PID whose identity changed across the lookup, loses its
/// owner.
fn canonicalize_process_names(connections: &mut [Connection]) {
    /// One PID's identity as this poll read it, and once a row has asked,
    /// the name `stable_name` gave and whether the identity held across it.
    struct Memo {
        before: Option<super::attribution::ProcessIdentity>,
        resolved: Option<(Option<String>, bool)>,
    }
    let mut memo: HashMap<u32, Memo> = HashMap::new();
    for conn in connections {
        let Some(pid) = conn.pid else {
            continue;
        };
        let Memo { before, resolved } = memo.entry(pid).or_insert_with(|| Memo {
            before: super::attribution::process_identity(pid),
            resolved: None,
        });
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
        let (name, unchanged) = resolved.get_or_insert_with(|| {
            let name = crate::platform::procname::stable_name(pid);
            let after = super::attribution::process_identity(pid);
            (name, *before == after)
        });
        if *unchanged {
            if let Some(name) = name {
                conn.process_name = Some(name.clone());
            }
        } else {
            conn.pid = None;
            conn.process_name = None;
            conn.evidence.process = None;
            conn.evidence.unknown_reason = Some(super::attribution::UnknownReason::IdentityChanged);
        }
    }
}

/// Make every process name safe to draw. Any local user can name a process
/// whatever they like through the executable's file name, or through
/// `prctl(PR_SET_NAME)` when its path can't be read, and netwatch often runs
/// with more privilege than they have. Runs after every attribution source
/// has settled the name.
fn sanitize_process_names(connections: &mut [Connection]) {
    for conn in connections {
        conn.process_name = conn
            .process_name
            .take()
            .map(crate::ui::sanitize::display_owned);
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

/// Closed connections the timeline keeps: the most recently closed, by
/// `last_seen`. Active ones are never evicted, however many there are, so
/// this bounds the history and not the table. It used to count active
/// entries too, and with 2,000 or more open every closed one was evicted on
/// the tick it closed.
pub(crate) const MAX_CLOSED_HISTORY: usize = 2_000;
/// The fewest closed entries evicted at once, so the index is rebuilt once
/// per batch rather than on every tick that something closes. StreamTracker
/// evicts in batches of the same size.
const CLOSED_EVICT_BATCH: usize = 256;

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
    /// Entries not active at the last update.
    closed: usize,
    /// Whether closed entries have been evicted since the timeline started.
    trimmed: bool,
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
            closed: 0,
            trimmed: false,
        }
    }

    /// Closed entries held, at most [`MAX_CLOSED_HISTORY`], for the `M`
    /// debug overlay.
    pub fn closed_len(&self) -> usize {
        self.closed
    }

    /// Whether the timeline has evicted closed connections, so it no longer
    /// holds every one that closed since it started.
    pub fn closed_trimmed(&self) -> bool {
        self.trimmed
    }

    /// When the timeline first saw `key`, without a search of every entry.
    pub fn first_seen(&self, key: &ConnectionKey) -> Option<Instant> {
        self.known_keys
            .get(key)
            .map(|&i| self.tracked[i].first_seen)
    }

    pub fn update(&mut self, connections: &[Connection]) {
        let now = Instant::now();

        // Closed unless this table still lists it.
        for tracked in &mut self.tracked {
            tracked.is_active = false;
        }

        for conn in connections {
            let key = ConnectionKey {
                protocol: conn.protocol.clone(),
                local_addr: conn.local_addr.clone(),
                remote_addr: conn.remote_addr.clone(),
                pid: conn.pid,
            };

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

        self.closed = self.tracked.iter().filter(|t| !t.is_active).count();
        if self.closed > MAX_CLOSED_HISTORY {
            self.evict_closed((self.closed - MAX_CLOSED_HISTORY).max(CLOSED_EVICT_BATCH));
        }
    }

    /// Drop the `count` closed entries that closed longest ago. Among those
    /// that closed on the same tick, the one first seen earliest goes first.
    fn evict_closed(&mut self, count: usize) {
        let mut closed: Vec<usize> = (0..self.tracked.len())
            .filter(|&i| !self.tracked[i].is_active)
            .collect();
        closed
            .sort_unstable_by_key(|&i| (self.tracked[i].last_seen, self.tracked[i].first_seen, i));
        closed.truncate(count);

        let mut evict = vec![false; self.tracked.len()];
        for &i in &closed {
            evict[i] = true;
            self.known_keys.remove(&self.tracked[i].key);
        }
        let mut index = 0;
        self.tracked.retain(|_| {
            let keep = !evict[index];
            index += 1;
            keep
        });
        for (i, tracked) in self.tracked.iter().enumerate() {
            if let Some(idx) = self.known_keys.get_mut(&tracked.key) {
                *idx = i;
            }
        }
        self.closed -= closed.len();
        self.trimmed = true;
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

/// FreeBSD: `sockstat` is a base-system tool (unlike `lsof`, which FreeBSD
/// only ships via `pkg install lsof` — this project already prefers
/// base-system tools where one exists). It walks the kernel's socket tables
/// directly and prints numeric addresses without a flag.
///
/// Confirmed on a real FreeBSD 15.1 host. `sockstat(1)`'s column shape is
/// `USER COMMAND PID FD PROTO LOCAL-ADDRESS FOREIGN-ADDRESS CONN-STATE`
/// (the last column header is two words, "CONN STATE", like "LOCAL ADDRESS"
/// below). Originally written with `-S` on the theory that it appended
/// state for TCP rows only (a UDP row short one column) — real
/// `sockstat(1)` disagreed on both points: `-S` ("Display the protocol
/// stack") prints a STACK column (e.g. the vnet stack name "freebsd"), not
/// state at all, and the actual state flag is lowercase `-s` ("Display the
/// protocol state"). With the correct `-s`, every row — TCP *and* UDP —
/// has the same column count; UDP rows just carry `??` in that slot since
/// sockstat only implements state tracking for TCP/SCTP. The code below
/// already discards the column for non-TCP protocols regardless, so no
/// parsing logic needed to change, only the flag and these comments.
#[cfg(target_os = "freebsd")]
fn parse_sockstat() -> Vec<Connection> {
    // -4/-6: both address families. -c: connected sockets. -l: listening
    // sockets (parity with lsof -i on macOS / ss -a on Linux). -s: append
    // protocol state (lowercase — uppercase -S is the unrelated "protocol
    // stack" column). No numeric-address flag is passed: sockstat does not
    // do reverse DNS by default (unlike netstat without -n).
    let output = match Command::new("sockstat")
        .args(["-4", "-6", "-c", "-l", "-s"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    parse_sockstat_output(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(target_os = "freebsd")]
fn parse_sockstat_output(text: &str) -> Vec<Connection> {
    // Header: USER COMMAND PID FD PROTO LOCAL-ADDRESS FOREIGN-ADDRESS
    // CONN-STATE. Hardcoded positions (like macOS's netstat parser above)
    // rather than header-driven lookup: the header's "LOCAL ADDRESS"/
    // "FOREIGN ADDRESS"/"CONN STATE" are each two whitespace-separated
    // words, but the data row's value is one token, so position-by-
    // header-name doesn't actually line up — don't try it.
    const COMMAND: usize = 1;
    const PID: usize = 2;
    const PROTO: usize = 4;
    const LOCAL: usize = 5;
    const FOREIGN: usize = 6;
    const CONN_STATE: usize = 7;

    let mut connections = Vec::new();
    for line in text.lines().skip(1) {
        let row: Vec<&str> = line.split_whitespace().collect();
        if row.len() <= FOREIGN {
            continue;
        }
        let proto_raw = row[PROTO].to_ascii_lowercase();
        let protocol = if proto_raw.starts_with("tcp") {
            "TCP"
        } else if proto_raw.starts_with("udp") {
            "UDP"
        } else {
            // Unix-domain and other non-IP sockets — no 5-tuple to draw.
            continue;
        };
        let local_addr = row[LOCAL].to_string();
        if local_addr.is_empty() {
            continue;
        }
        let remote_addr = row[FOREIGN].to_string();
        let pid = row.get(PID).and_then(|s| s.parse::<u32>().ok());
        let process_name = row.get(COMMAND).map(|s| s.to_string());
        // Real `sockstat -s` always prints this column (UDP rows get the
        // placeholder "??", since sockstat only tracks state for TCP/SCTP)
        // — filtering on protocol still discards it for UDP regardless of
        // whether the column happens to be present.
        let state = row
            .get(CONN_STATE)
            .filter(|_| protocol == "TCP")
            .map(|s| s.to_string())
            .unwrap_or_default();

        connections.push(Connection {
            protocol: protocol.to_string(),
            local_addr,
            remote_addr,
            state,
            pid,
            process_name,
            handshake_rtt_us: None,
            rx_rate: None,
            tx_rate: None,
            attribution: AttributionSource::Sockstat,
            evidence: Default::default(),
            app_protocol: None,
            retransmits: 0,
            out_of_order: 0,
        });
    }
    connections
}

#[cfg(target_os = "freebsd")]
#[cfg(test)]
mod sockstat_tests {
    use super::*;

    // Sample data matching real `sockstat -4 -6 -c -l -s` output on
    // FreeBSD 15.1 — see parse_sockstat's doc comment. Every row carries
    // the CONN STATE column (from lowercase -s); UDP just gets "??" since
    // sockstat only tracks state for TCP/SCTP.
    const SOCKSTAT_OUTPUT: &str = "\
USER     COMMAND    PID   FD PROTO  LOCAL ADDRESS         FOREIGN ADDRESS       CONN STATE
root     sshd       1234  3  tcp4   192.168.1.5:22        192.168.1.100:54321   ESTABLISHED
root     sshd       1234  4  tcp4   0.0.0.0:22            *:*                   LISTEN
_dhcp    dhclient   567   5  udp4   *:68                  *:*                   ??";

    #[test]
    fn parses_tcp_row_with_state() {
        let conns = parse_sockstat_output(SOCKSTAT_OUTPUT);
        let est = conns
            .iter()
            .find(|c| c.state == "ESTABLISHED")
            .expect("established row should parse");
        assert_eq!(est.protocol, "TCP");
        assert_eq!(est.local_addr, "192.168.1.5:22");
        assert_eq!(est.remote_addr, "192.168.1.100:54321");
        assert_eq!(est.pid, Some(1234));
        assert_eq!(est.process_name.as_deref(), Some("sshd"));
        assert_eq!(est.attribution, AttributionSource::Sockstat);
    }

    #[test]
    fn parses_udp_row_ignoring_its_placeholder_state() {
        let conns = parse_sockstat_output(SOCKSTAT_OUTPUT);
        let udp = conns
            .iter()
            .find(|c| c.protocol == "UDP")
            .expect("udp row should parse");
        assert_eq!(udp.local_addr, "*:68");
        assert_eq!(udp.remote_addr, "*:*");
        assert_eq!(
            udp.state, "",
            "UDP sockets have no state — sockstat's literal \"??\" is discarded"
        );
        assert_eq!(udp.pid, Some(567));
    }

    #[test]
    fn empty_input_yields_no_connections() {
        assert!(parse_sockstat_output("").is_empty());
    }

    #[test]
    fn header_only_yields_no_connections() {
        assert!(parse_sockstat_output(
            "USER COMMAND PID FD PROTO LOCAL-ADDRESS FOREIGN-ADDRESS STATE\n"
        )
        .is_empty());
    }

    #[test]
    fn short_row_does_not_panic() {
        assert!(parse_sockstat_output("root sshd 1\n").is_empty());
    }
}

#[cfg(all(target_os = "linux", test))]
fn parse_linux_connections() -> Vec<Connection> {
    parse_linux_connections_result(SS_PROGRAM, None)
        .map(|table| table.rows)
        .unwrap_or_default()
}

/// The iproute2 tool the Linux connection table comes from when it can.
#[cfg(target_os = "linux")]
pub const SS_PROGRAM: &str = "ss";

/// One Linux poll's connection table and where it came from.
#[cfg(target_os = "linux")]
struct LinuxTable {
    rows: Vec<Connection>,
    source: super::attribution::TableSource,
    /// Why `ss` did not provide the rows, when it did not.
    note: Option<String>,
}

/// Read the connection table from `ss`, or from `/proc/net` when `ss` is
/// missing or fails.
///
/// Without the fallback, a host with no iproute2 (minimal containers, some NAS
/// distributions), or a sandbox that cannot execute `ss`, showed an empty
/// connection table and nothing said why. `ss` stays first because it is the
/// long-tested path, and because it labels a socket bound to a device
/// (`127.0.0.53%lo:53`), which `/proc/net` does not record. Process owners come
/// from the same `/proc` overlay either way, so attribution does not change.
///
/// `ss` runs without `-p`: the overlay replaces every owner it reports, and
/// the per-process fd walk `-p` makes tripled its time at 10,000 sockets.
#[cfg(target_os = "linux")]
fn parse_linux_connections_result(
    program: &str,
    brokered: Option<&ProcSnapshot>,
) -> Result<LinuxTable, String> {
    use super::attribution::TableSource;
    let ss_error = match Command::new(program).args(["-tuna"]).output() {
        Ok(output) => match parse_ss_command_output(output, brokered) {
            Ok(rows) => {
                return Ok(LinuxTable {
                    rows,
                    source: TableSource::Ss,
                    note: None,
                })
            }
            Err(error) => error,
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "ss not found".to_string(),
        Err(error) => format!("ss could not start: {error}"),
    };
    let mut rows = read_proc_net_connections().map_err(|error| format!("{ss_error}; {error}"))?;
    overlay_proc_attribution(&mut rows, brokered);
    Ok(LinuxTable {
        rows,
        source: TableSource::ProcNet,
        note: Some(ss_error),
    })
}

/// Log when the poll changes table, not on every poll: a host without `ss`
/// would otherwise repeat the same warning every two seconds.
#[cfg(target_os = "linux")]
fn log_table_source_change(
    previous: &super::attribution::Coverage,
    current: &super::attribution::Coverage,
) {
    let previous = previous.completed_at.map(|_| previous.table_source);
    let note = current.table_note.as_deref().unwrap_or_default();
    match table_change(previous, current.table_source) {
        Some(TableChange::ProcNet) => {
            tracing::warn!(target: "netwatch::connections", note, "connection table read from /proc/net")
        }
        Some(TableChange::SsAgain) => {
            tracing::info!(target: "netwatch::connections", "connection table read from ss again")
        }
        Some(TableChange::NoTable) => {
            tracing::warn!(target: "netwatch::connections", note, "no connection table")
        }
        None => {}
    }
}

/// What [`log_table_source_change`] reports.
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
enum TableChange {
    ProcNet,
    SsAgain,
    NoTable,
}

/// `previous` is the last poll's source, and `None` before the first poll.
/// Comparing sources alone could not tell a first poll that read no table
/// from a repeat of one, so a session that never had a table logged nothing.
#[cfg(target_os = "linux")]
fn table_change(
    previous: Option<Option<super::attribution::TableSource>>,
    current: Option<super::attribution::TableSource>,
) -> Option<TableChange> {
    use super::attribution::TableSource;
    if previous == Some(current) {
        return None;
    }
    match current {
        Some(TableSource::ProcNet) => Some(TableChange::ProcNet),
        Some(TableSource::Ss) => previous.is_some().then_some(TableChange::SsAgain),
        None => Some(TableChange::NoTable),
    }
}

/// Where `Command::new(program)` would find `program` on `path`, as `execvp`
/// searches it: the first entry holding an executable regular file of that
/// name. Doctor uses it to say whether a live session will read `ss` or fall
/// back to `/proc/net`, without running anything.
#[cfg(target_os = "linux")]
pub fn find_on_path(program: &str, path: &std::ffi::OsStr) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    std::env::split_paths(path)
        .map(|dir| dir.join(program))
        .find(|candidate| {
            std::fs::metadata(candidate)
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
}

/// [`find_on_path`] for [`SS_PROGRAM`] on this process's `PATH`. An unset
/// `PATH` searches glibc's default, as `execvp` does.
#[cfg(target_os = "linux")]
pub fn ss_on_path() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/bin:/usr/bin".into());
    find_on_path(SS_PROGRAM, &path)
}

#[cfg(target_os = "linux")]
fn parse_ss_command_output(
    output: std::process::Output,
    brokered: Option<&ProcSnapshot>,
) -> Result<Vec<Connection>, String> {
    let mut connections = Vec::new();
    if !output.status.success() {
        return Err(format!("ss failed ({})", output.status));
    }
    {
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

            connections.push(Connection {
                protocol,
                local_addr,
                remote_addr,
                state,
                pid: None,
                process_name: None,
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

    // Owners come straight from the kernel's tables, never from `ss -p`,
    // which only attributes sockets the caller is privileged to see: as a
    // normal user it returns NO process info — not even for the box's own
    // daemons — and on some hosts it stays empty even under sudo (see issue
    // #40). /proc/net/{tcp,udp}{,6} maps a 5-tuple → socket inode, and
    // /proc/<pid>/fd/* maps that inode → owning process. Same source ss uses,
    // no subprocess, and it degrades to "attribute what this uid can see"
    // instead of all-or-nothing.
    overlay_proc_attribution(&mut connections, brokered);

    Ok(connections)
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

/// The kernel's socket tables, in the order they are read. They hold exactly
/// the sockets `ss -tuna` lists: TCP and UDP, both families.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const PROC_NET_TABLES: [(&str, StreamProtocol); 4] = [
    ("/proc/net/tcp", StreamProtocol::Tcp),
    ("/proc/net/tcp6", StreamProtocol::Tcp),
    ("/proc/net/udp", StreamProtocol::Udp),
    ("/proc/net/udp6", StreamProtocol::Udp),
];

/// One socket from a `/proc/net/{tcp,udp}*` table, reduced to the columns
/// netwatch reads.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcNetSocket {
    local: (std::net::IpAddr, u16),
    remote: (std::net::IpAddr, u16),
    /// `st`: the kernel's TCP state number. UDP sockets use the same numbers.
    state: u8,
    /// Zero for sockets no file refers to (TIME_WAIT, embryonic SYN_RECV).
    inode: u64,
}

/// Parse one `/proc/net/{tcp,udp}*` table: columns 1 and 2 are the hex
/// endpoints, 3 the state and 9 the inode. The header and any malformed line
/// are skipped; the kernel's own output never produces one.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_proc_net_table(text: &str) -> impl Iterator<Item = ProcNetSocket> + '_ {
    text.lines().skip(1).filter_map(|line| {
        let mut cols = line.split_whitespace();
        let local = parse_proc_net_hex(cols.nth(1)?)?;
        let remote = parse_proc_net_hex(cols.next()?)?;
        let state = u8::from_str_radix(cols.next()?, 16).ok()?;
        let inode = cols.nth(5)?.parse().ok()?;
        Some(ProcNetSocket {
            local,
            remote,
            state,
            inode,
        })
    })
}

/// `ss`'s name for a kernel socket state (`include/net/tcp_states.h`), with
/// `ESTAB` spelled out as [`parse_ss_command_output`] spells it, so the state
/// filter and colours treat rows from either source alike. A UDP socket is
/// ESTABLISHED once connected and CLOSE otherwise, which `ss` calls UNCONN.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn ss_state_name(state: u8) -> &'static str {
    match state {
        0x01 => "ESTABLISHED",
        0x02 => "SYN-SENT",
        // NEW_SYN_RECV is a request socket; ss shows those as SYN-RECV, and
        // /proc/net already prints them with SYN_RECV's number.
        0x03 | 0x0C => "SYN-RECV",
        0x04 => "FIN-WAIT-1",
        0x05 => "FIN-WAIT-2",
        0x06 => "TIME-WAIT",
        0x07 => "UNCONN",
        0x08 => "CLOSE-WAIT",
        0x09 => "LAST-ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        _ => "UNKNOWN",
    }
}

/// Render an endpoint as `ss -n` prints it: `a.b.c.d:port`, `[v6]:port`, a
/// v4-mapped address as `[::ffff:a.b.c.d]:port`, and port 0 as `*`. Matching
/// it exactly is what lets [`socket_key`], [`connection_stream_key`], the
/// timeline and the flow registry treat a fallback row as the same connection
/// an `ss` row was.
///
/// Two spellings cannot match, because `/proc/net` lacks what `ss` reads to
/// choose them: the `%dev` suffix of a socket bound to a device, and `*` in
/// place of `[::]` for a dual-stack wildcard. `ss` rows spelled either way
/// fail [`socket_key`], so the plain form joins where they did not; what the
/// table loses is the device name. Either spelling of a device-bound socket
/// keys to its stream, because [`connection_stream_key`] drops the zone, which
/// no packet carries.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn format_ss_endpoint((ip, port): (std::net::IpAddr, u16)) -> String {
    let port = if port == 0 {
        "*".to_string()
    } else {
        port.to_string()
    };
    match ip {
        std::net::IpAddr::V4(v4) => format!("{v4}:{port}"),
        std::net::IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

/// A connection row for one `/proc/net` socket, shaped as the `ss` parser
/// shapes its rows. The owner is left for [`overlay_proc_attribution`], as it
/// is for `ss` rows.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn proc_net_connection(protocol: StreamProtocol, socket: &ProcNetSocket) -> Connection {
    Connection {
        protocol: match protocol {
            StreamProtocol::Tcp => "TCP",
            StreamProtocol::Udp => "UDP",
        }
        .into(),
        local_addr: format_ss_endpoint(socket.local),
        remote_addr: format_ss_endpoint(socket.remote),
        state: ss_state_name(socket.state).into(),
        pid: None,
        process_name: None,
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

/// Build connection rows straight from the kernel's socket tables, for when
/// `ss` is missing or fails.
///
/// The IPv4 tables must be readable. The IPv6 ones do not exist when the
/// kernel runs with IPv6 disabled, and that is not a failure. The sandbox
/// already grants `/proc` for the attribution overlay, so this works inside
/// the confined worker.
#[cfg(target_os = "linux")]
fn read_proc_net_connections() -> Result<Vec<Connection>, String> {
    let mut rows = Vec::new();
    for (path, protocol) in PROC_NET_TABLES {
        match std::fs::read_to_string(path) {
            Ok(text) => rows.extend(
                parse_proc_net_table(&text).map(|socket| proc_net_connection(protocol, &socket)),
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && path.ends_with('6') => {}
            Err(error) => return Err(format!("{path}: {error}")),
        }
    }
    Ok(rows)
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
impl ProcNetIndex {
    fn add(&mut self, protocol: StreamProtocol, text: &str) {
        for socket in parse_proc_net_table(text) {
            let ProcNetSocket {
                local,
                remote,
                inode,
                ..
            } = socket;
            if inode == 0 {
                continue;
            }
            // SO_REUSEPORT and shared endpoints must not select an arbitrary owner.
            self.by_pair
                .entry((protocol, local, remote))
                .and_modify(|old| {
                    if *old != inode {
                        *old = 0;
                    }
                })
                .or_insert(inode);
        }
    }
}
#[cfg(target_os = "linux")]
fn proc_net_inode_index() -> ProcNetIndex {
    let mut idx = ProcNetIndex::default();
    for (path, protocol) in PROC_NET_TABLES {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        idx.add(protocol, &text);
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
/// `checked` is when the owner was seen holding the socket, as UTC ms: some
/// time from the first to the second (see `MatchEvidence::owner_checked_utc_ms`).
#[cfg(target_os = "linux")]
fn apply_owner(conn: &mut Connection, owner: &SocketOwner, checked: (u64, u64)) {
    conn.attribution = AttributionSource::Procfs;
    conn.pid = Some(owner.identity.pid);
    conn.process_name = Some(owner.comm.clone());
    conn.evidence.process = Some(owner.identity.clone());
    conn.evidence.unknown_reason = None;
    conn.evidence.observe();
    conn.evidence.owner_checked_utc_ms = Some(checked);
}
/// Revalidate every Linux polling match, including ss-provided PIDs. A PID name
/// alone cannot establish that the socket still belongs to that process.
///
/// A sandboxed worker cannot read other processes' `/proc/<pid>/fd` (Landlock
/// denies ptrace-mode access outside its domain), so when a [`ProcBroker`]
/// snapshot no older than `MAX_MATCH_AGE` is supplied, owners come from it.
/// The broker validated identity around each fd scan; here the socket inode
/// must still be the one the broker saw for this exact 5-tuple. Such an owner
/// was seen during the broker's scan, not now, and its evidence says so.
#[cfg(target_os = "linux")]
fn overlay_proc_attribution(connections: &mut [Connection], brokered: Option<&ProcSnapshot>) {
    // Before the socket tables are read, so a local scan's owner check below
    // falls between this and the time taken once it has passed.
    let checked_from = super::attribution::utc_ms();
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
                apply_owner(conn, owner, snap.scanned_utc_ms);
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
                apply_owner(conn, owner, (checked_from, super::attribution::utc_ms()));
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
/// only reads kernel procfs tables, never packet data. Its thread gives up
/// every capability but the two that scan needs before it reads anything
/// (`worker::relinquish`). It holds no strong reference to itself, so its
/// thread exits when the collector is dropped.
#[cfg(target_os = "linux")]
pub struct ProcBroker {
    latest: RwLock<Option<Arc<ProcSnapshot>>>,
}

#[cfg(target_os = "linux")]
impl ProcBroker {
    /// Must be called from a thread that has not applied the sandbox. The
    /// first snapshot is taken here, on that thread, so owners are available
    /// before the broker's own thread first scans one `interval` later.
    pub fn start(interval: std::time::Duration) -> Arc<Self> {
        let broker = Arc::new(Self {
            latest: RwLock::new(Some(Arc::new(capture_proc_snapshot()))),
        });
        let weak = Arc::downgrade(&broker);
        let spawned = std::thread::Builder::new()
            .name("netwatch-proc-broker".into())
            .spawn(move || {
                crate::sandbox::worker::relinquish("proc-broker");
                loop {
                    std::thread::sleep(interval);
                    let Some(broker) = weak.upgrade() else {
                        break;
                    };
                    let snapshot = Arc::new(capture_proc_snapshot());
                    *safe_write(&broker.latest, "proc_broker::publish") = Some(snapshot);
                }
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
    /// When the scan ran, as UTC ms. Each owner in it was seen holding its
    /// socket at some point between the two, however much later a poll
    /// applies it.
    scanned_utc_ms: (u64, u64),
}
#[cfg(target_os = "linux")]
pub fn capture_proc_snapshot() -> ProcSnapshot {
    let started = super::attribution::utc_ms();
    let index = proc_net_inode_index();
    let owners = socket_inode_owners();
    let scanned_utc_ms = (started, super::attribution::utc_ms());
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
        scanned_utc_ms,
    }
}
#[cfg(target_os = "linux")]
fn overlay_proc_snapshot(connections: &mut [Connection], snap: &ProcSnapshot) {
    // The owner is rechecked live below, so it was seen during this poll.
    let checked_from = super::attribution::utc_ms();
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
            apply_owner(conn, owner, (checked_from, super::attribution::utc_ms()));
        } else {
            conn.evidence.unknown_reason =
                Some(super::attribution::UnknownReason::IdentityUnavailable);
        }
    }
}

/// Windows: the kernel's TCP and UDP tables through IP Helper, each socket
/// with the PID that owns it, named from one process snapshot.
///
/// This used to be `netstat -ano` and `tasklist /FO CSV` on every tick: two
/// processes, and text in the display language, so German Windows reported
/// `HERGESTELLT` where every filter and counter looks for `ESTABLISHED`, and
/// English reported `LISTENING`, which nothing matched either. Both commands
/// remain only as fallbacks, used when the API call they stand in for fails.
#[cfg(target_os = "windows")]
fn parse_windows_connections() -> Vec<Connection> {
    use crate::platform::windows::tcp_table;

    let (sockets, attribution) = match tcp_table::sockets() {
        Ok(sockets) => (sockets, AttributionSource::IpHelper),
        Err(code) => {
            static WARNED: std::sync::Once = std::sync::Once::new();
            WARNED.call_once(|| {
                tracing::warn!(
                    target: "netwatch::connections",
                    code,
                    "GetExtendedTcpTable/GetExtendedUdpTable failed; reading netstat -ano instead"
                );
            });
            let Ok(output) = Command::new("netstat").args(["-ano"]).output() else {
                return Vec::new();
            };
            (
                parse_netstat_output(&String::from_utf8_lossy(&output.stdout)),
                AttributionSource::Lsof,
            )
        }
    };

    let pids: HashSet<u32> = sockets.iter().filter_map(|s| s.pid).collect();
    let names = if pids.is_empty() {
        HashMap::new()
    } else {
        // tasklist prints the same image names; it is only asked when the
        // snapshot itself fails.
        tcp_table::process_names(&pids).unwrap_or_else(|_| tasklist_names(&pids))
    };
    windows_connections(sockets, &names, attribution)
}

/// Rows of the Windows socket tables, named from `names`, as connections.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn windows_connections(
    sockets: Vec<crate::platform::socket_table::Socket>,
    names: &HashMap<u32, String>,
    attribution: AttributionSource,
) -> Vec<Connection> {
    sockets
        .into_iter()
        .map(|s| Connection {
            protocol: s.protocol.to_string(),
            local_addr: s.local_addr,
            remote_addr: s.remote_addr,
            state: s.state,
            process_name: s.pid.and_then(|p| names.get(&p).cloned()),
            pid: s.pid,
            handshake_rtt_us: None,
            rx_rate: None,
            tx_rate: None,
            attribution,
            evidence: Default::default(),
            app_protocol: None,
            retransmits: 0,
            out_of_order: 0,
        })
        .collect()
}

/// `netstat -ano`, for when the socket tables cannot be read through the API.
/// Brought into line with what the API path reports wherever netstat's text
/// allows: English state names become netwatch's, a listener's `0.0.0.0:0`
/// or `[::]:0` peer becomes `*:*`, a link-local address loses its `%12`
/// scope, and PID 0 is no owner. A state in another display language is kept
/// as netstat printed it; only the API path can name it.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_netstat_output(text: &str) -> Vec<crate::platform::socket_table::Socket> {
    use crate::platform::socket_table::{netstat_state_name, owner, Socket};

    let mut sockets = Vec::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let (protocol, state, pid) = match cols.as_slice() {
            // TCP lines: Proto LocalAddr ForeignAddr State PID
            ["TCP", _, _, state, pid, ..] => (
                "TCP",
                netstat_state_name(state)
                    .map(str::to_string)
                    .unwrap_or_else(|| state.to_string()),
                pid,
            ),
            // UDP lines: Proto LocalAddr ForeignAddr PID (no state)
            ["UDP", _, _, pid, ..] => ("UDP", String::new(), pid),
            _ => continue,
        };
        let remote = match cols[2] {
            "0.0.0.0:0" | "[::]:0" => "*:*".to_string(),
            other => without_scope(other),
        };
        sockets.push(Socket {
            protocol,
            local_addr: without_scope(cols[1]),
            remote_addr: remote,
            state,
            pid: pid.parse().ok().and_then(owner),
        });
    }
    sockets
}

/// A netstat endpoint without the scope it prints on a link-local IPv6
/// address (`[fe80::1%12]:1900`). The API rows carry none, so a socket read
/// through either path has the same endpoint, and the same flow key.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn without_scope(endpoint: &str) -> String {
    match (endpoint.find('%'), endpoint.find(']')) {
        (Some(scope), Some(close)) if scope < close => {
            format!("{}{}", &endpoint[..scope], &endpoint[close..])
        }
        _ => endpoint.to_string(),
    }
}

/// PID -> image name from `tasklist`, for when a process snapshot fails.
#[cfg(target_os = "windows")]
fn tasklist_names(pids: &HashSet<u32>) -> HashMap<u32, String> {
    match Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .output()
    {
        Ok(output) => parse_tasklist_output(&String::from_utf8_lossy(&output.stdout), pids),
        Err(_) => HashMap::new(),
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_tasklist_output(text: &str, pids: &HashSet<u32>) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        // Format: "process.exe","1234","Console","1","12,345 K"
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 2 {
            continue;
        }
        let name = fields[0].trim_matches('"');
        let pid_str = fields[1].trim_matches('"');
        if let Ok(pid) = pid_str.parse::<u32>() {
            if pids.contains(&pid) {
                map.insert(pid, name.to_string());
            }
        }
    }
    map
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

    /// `cp /bin/sleep $'/tmp/sh\e]0;owned\a'` and running the copy is all it
    /// takes for any local user to put an escape sequence in the process
    /// column.
    #[test]
    fn process_name_control_characters_are_replaced() {
        let mut conns = vec![
            make_conn("TCP", "1.2.3.4:1", "5.6.7.8:443", "ESTABLISHED", 1),
            make_conn("TCP", "1.2.3.4:2", "5.6.7.9:443", "ESTABLISHED", 2),
        ];
        conns[0].process_name = Some("sh\x1b]0;owned\x07\u{202E}".into());
        conns[1].process_name = None;
        sanitize_process_names(&mut conns);
        assert_eq!(conns[0].process_name.as_deref(), Some("sh·]0;owned··"));
        assert_eq!(conns[1].process_name, None);
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
    /// The memo reads a pid's identity once per poll and still judges every
    /// row against it: a row recorded for an earlier process with this pid
    /// loses its owner, before or after a row that keeps it.
    #[cfg(target_os = "linux")]
    #[test]
    fn canonicalize_rejects_reused_pid_with_memo() {
        use super::super::attribution::{process_identity, ProcessIdentity, UnknownReason};
        let me = std::process::id();
        let identity = process_identity(me).unwrap();
        for current in [[true, false, true], [false, true, false]] {
            let mut rows: Vec<Connection> = current
                .iter()
                .enumerate()
                .map(|(i, &current)| {
                    let mut c = make_conn(
                        "TCP",
                        &format!("127.0.0.1:{}", 100 + i),
                        "127.0.0.1:200",
                        "ESTABLISHED",
                        me,
                    );
                    c.process_name = Some("scraped".into());
                    c.evidence.unknown_reason = None;
                    c.evidence.process = Some(ProcessIdentity {
                        start_token: if current {
                            identity.start_token.clone()
                        } else {
                            "an earlier process".into()
                        },
                        ..identity.clone()
                    });
                    c
                })
                .collect();
            canonicalize_process_names(&mut rows);
            for (row, current) in rows.iter().zip(current) {
                if current {
                    assert_eq!(row.pid, Some(me));
                    let name = row.process_name.as_deref().unwrap_or_default();
                    assert!(name.contains("netwatch"), "{name:?}");
                } else {
                    assert_eq!((row.pid, row.process_name.as_deref()), (None, None));
                    assert_eq!(
                        row.evidence.unknown_reason,
                        Some(UnknownReason::IdentityChanged)
                    );
                }
            }
        }
    }
    /// A /proc snapshot in which `conn` is attributed to this process.
    ///
    /// Between fork and exec, a child spawned by another test shares every
    /// socket this process holds, and a snapshot taken in that window rightly
    /// sees two owners and names neither. Capture again rather than race it.
    #[cfg(target_os = "linux")]
    fn snapshot_owning(conn: &Connection) -> ProcSnapshot {
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let snap = capture_proc_snapshot();
            let mut c = conn.clone();
            c.pid = None;
            c.process_name = None;
            overlay_proc_snapshot(std::slice::from_mut(&mut c), &snap);
            if c.pid == Some(std::process::id()) || Instant::now() >= deadline {
                return snap;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn brokered_snapshot_attributes_without_local_fd_scan_and_rejects_stale_or_reused() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect("127.0.0.1:45679").unwrap();
        let local = socket.local_addr().unwrap().to_string();
        let conn = || make_conn("UDP", &local, "127.0.0.1:45679", "", 1);
        let mut snap = snapshot_owning(&conn());

        // The owner was seen when the broker scanned, which may be well
        // before this poll; the evidence carries the scan's time.
        snap.scanned_utc_ms = (1_000, 1_250);
        let mut c = conn();
        overlay_proc_attribution(std::slice::from_mut(&mut c), Some(&snap));
        assert_eq!(c.pid, Some(std::process::id()));
        assert_eq!(c.attribution, AttributionSource::Procfs);
        assert_eq!(c.evidence.owner_checked_utc_ms, Some((1_000, 1_250)));
        assert!(c.evidence.observed_at_utc_ms > Some(1_250));

        // A stale broker snapshot is ignored in favour of the local scan,
        // which reads live /proc state across every pid on the box. That can
        // take a while on a loaded test runner: poll, don't race (same
        // precaution as proc_broker_publishes_fresh_snapshots_and_stops_with_its_owner).
        snap.captured_at = Instant::now() - std::time::Duration::from_secs(10);
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let mut c;
        loop {
            c = conn();
            overlay_proc_attribution(std::slice::from_mut(&mut c), Some(&snap));
            if c.pid == Some(std::process::id()) || Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(c.pid, Some(std::process::id()));
        // The local scan checked the owner during this poll.
        let (from, until) = c.evidence.owner_checked_utc_ms.unwrap();
        assert!(from > 1_250 && from <= until);

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
        // Its thread gave up its capabilities before that first scan.
        let record = crate::sandbox::worker::relinquished().remove("proc-broker");
        assert!(
            record.as_ref().is_some_and(|r| r.mode.warnings.is_empty()),
            "{record:?}"
        );
        let weak = Arc::downgrade(&broker);
        drop(broker);
        assert!(eventually(&|| weak.upgrade().is_none()));
    }
    /// The broker's thread sleeps a whole interval before its first scan, so
    /// `start` publishes a scan of its own, taken on the calling thread. A
    /// confined poller therefore has owners from the first poll and does not
    /// fall back to its own fd scan, which it may lack the capabilities for.
    #[cfg(target_os = "linux")]
    #[test]
    fn proc_broker_attributes_before_its_thread_first_scans() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect("127.0.0.1:45680").unwrap();
        let local = socket.local_addr().unwrap().to_string();
        let conn = || make_conn("UDP", &local, "127.0.0.1:45680", "", 1);
        // Retry for the same fork-to-exec window `snapshot_owning` waits out.
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        loop {
            // Far longer than this test runs: the thread never scans here.
            let broker = ProcBroker::start(std::time::Duration::from_secs(600));
            let returned = Instant::now();
            let snap = broker.latest().expect("start publishes a snapshot");
            assert!(snap.captured_at <= returned);
            let mut c = conn();
            overlay_proc_attribution(std::slice::from_mut(&mut c), Some(&snap));
            if c.pid == Some(std::process::id()) || Instant::now() >= deadline {
                assert_eq!(c.pid, Some(std::process::id()));
                // From that snapshot, not from a local scan.
                assert_eq!(c.evidence.owner_checked_utc_ms, Some(snap.scanned_utc_ms));
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn startup_snapshot_expires_and_revalidates_socket_identity() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect("127.0.0.1:45678").unwrap();
        let mut c = make_conn(
            "UDP",
            &socket.local_addr().unwrap().to_string(),
            "127.0.0.1:45678",
            "",
            1,
        );
        let mut snap = snapshot_owning(&c);
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

    // ── /proc/net fallback (ss missing or failing) ──────────────────────

    /// A name no host has on PATH, standing in for an absent `ss`.
    #[cfg(target_os = "linux")]
    const MISSING_SS: &str = "netwatch-test-no-such-ss";

    /// Every fallback row with a socket inode must reach that inode through
    /// `socket_key`, the join the attribution overlay depends on.
    #[cfg(target_os = "linux")]
    #[test]
    fn fallback_rows_join_the_inode_index() {
        use super::proc_net_tests::{fixture_rows, TCP, TCP6, UDP, UDP6};
        let mut index = ProcNetIndex::default();
        index.add(StreamProtocol::Tcp, TCP);
        index.add(StreamProtocol::Tcp, TCP6);
        index.add(StreamProtocol::Udp, UDP);
        index.add(StreamProtocol::Udp, UDP6);
        let joined: Vec<_> = fixture_rows()
            .iter()
            .map(|c| socket_key(c).and_then(|key| index.by_pair.get(&key).copied()))
            .collect();
        assert_eq!(
            joined,
            [
                Some(41001),
                Some(41002),
                None, // TIME-WAIT: no inode, nothing to attribute
                Some(42001),
                Some(42002),
                Some(42003),
                Some(43001),
                Some(43002),
                Some(44001),
            ]
        );
    }

    /// The same sockets as `proc_net_tests`' fixtures, as `ss -tuna` prints
    /// them. Both sources must produce identical rows.
    #[cfg(target_os = "linux")]
    #[test]
    fn ss_and_proc_net_fixtures_produce_identical_rows() {
        use std::os::unix::process::ExitStatusExt;
        let ss = "\
Netid State     Recv-Q Send-Q          Local Address:Port      Peer Address:Port
tcp   LISTEN    0      4096                127.0.0.1:8080           0.0.0.0:*
tcp   ESTAB     0      0                  192.0.2.10:51234     198.51.100.7:443
tcp   TIME-WAIT 0      0                   127.0.0.1:41394        127.0.0.1:8080
tcp   LISTEN    0      128                      [::]:22              [::]:*
tcp   ESTAB     0      0               [2001:db8::1]:443    [2001:db8::2]:50000
tcp   ESTAB     0      0         [::ffff:127.0.0.1]:8080 [::ffff:192.0.2.10]:51234
udp   UNCONN    0      0                     0.0.0.0:5353           0.0.0.0:*
udp   ESTAB     0      0                  192.0.2.10:54321     203.0.113.53:53
udp   UNCONN    0      0                       [::1]:323             [::]:*
";
        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: ss.as_bytes().to_vec(),
            stderr: vec![],
        };
        let shape = |rows: Vec<Connection>| {
            let mut rows: Vec<_> = rows
                .into_iter()
                .map(|c| (c.protocol, c.local_addr, c.remote_addr, c.state))
                .collect();
            rows.sort();
            rows
        };
        assert_eq!(
            shape(parse_ss_command_output(output, None).unwrap()),
            shape(super::proc_net_tests::fixture_rows())
        );
    }

    /// `/proc/net` rows for sockets this test holds must be the rows the
    /// installed `ss` prints for them, or the timeline, flow registry and
    /// egress would see new connections whenever the source changed.
    #[cfg(target_os = "linux")]
    #[test]
    fn live_proc_net_rows_match_live_ss_rows() {
        use std::net::{TcpListener, TcpStream, UdpSocket};
        let mut held: Vec<Box<dyn std::any::Any>> = Vec::new();
        let mut expected = Vec::new();
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let Ok(listener) = TcpListener::bind(bind) else {
                continue;
            };
            let server = listener.local_addr().unwrap();
            let client = TcpStream::connect(server).unwrap();
            let (accepted, _) = listener.accept().unwrap();
            let client_addr = client.local_addr().unwrap();
            expected.push(("TCP", server.to_string(), None));
            expected.push(("TCP", client_addr.to_string(), Some(server.to_string())));
            expected.push(("TCP", server.to_string(), Some(client_addr.to_string())));
            held.extend([
                Box::new(listener) as Box<dyn std::any::Any>,
                Box::new(client),
                Box::new(accepted),
            ]);
            let unconnected = UdpSocket::bind(bind).unwrap();
            let connected = UdpSocket::bind(bind).unwrap();
            connected
                .connect(unconnected.local_addr().unwrap())
                .unwrap();
            expected.push(("UDP", unconnected.local_addr().unwrap().to_string(), None));
            expected.push((
                "UDP",
                connected.local_addr().unwrap().to_string(),
                Some(unconnected.local_addr().unwrap().to_string()),
            ));
            held.extend([
                Box::new(unconnected) as Box<dyn std::any::Any>,
                Box::new(connected),
            ]);
        }
        // A v4-mapped flow: an IPv6 client socket reaching an IPv4 listener.
        let v4 = TcpListener::bind("127.0.0.1:0").unwrap();
        let mapped_server = format!("[::ffff:127.0.0.1]:{}", v4.local_addr().unwrap().port());
        if let Ok(client) = TcpStream::connect(mapped_server.as_str()) {
            expected.push((
                "TCP",
                client.local_addr().unwrap().to_string(),
                Some(mapped_server.clone()),
            ));
            held.push(Box::new(client));
        }
        held.push(Box::new(v4));

        let ss = match parse_linux_connections_result(SS_PROGRAM, None) {
            Ok(table) if table.source == super::super::attribution::TableSource::Ss => table.rows,
            other => {
                eprintln!(
                    "ss unavailable here ({:?}); skipping",
                    other.map(|t| t.note)
                );
                return;
            }
        };
        let proc = read_proc_net_connections().unwrap();
        for (protocol, local, remote) in &expected {
            // `None` is a wildcard peer: the listener, not a socket it accepted.
            let find = |rows: &[Connection]| {
                rows.iter()
                    .find(|c| {
                        c.protocol == *protocol
                            && c.local_addr == *local
                            && remote
                                .as_ref()
                                .map_or(c.remote_addr.ends_with(":*"), |r| c.remote_addr == *r)
                    })
                    .map(|c| (c.remote_addr.clone(), c.state.clone()))
            };
            let from_ss = find(&ss);
            assert!(from_ss.is_some(), "ss has no row for {protocol} {local}");
            assert_eq!(find(&proc), from_ss, "{protocol} {local} {remote:?}");
        }
        drop(held);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn missing_ss_falls_back_to_proc_net_with_owners() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = listener.local_addr().unwrap().to_string();
        // Another test's child holds this socket between fork and exec, and
        // a shared socket rightly has no owner: poll, don't race.
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let table = parse_linux_connections_result(MISSING_SS, None).unwrap();
            assert_eq!(
                table.source,
                super::super::attribution::TableSource::ProcNet
            );
            assert_eq!(table.note.as_deref(), Some("ss not found"));
            let row = table
                .rows
                .iter()
                .find(|c| c.protocol == "TCP" && c.local_addr == local)
                .expect("listener row from /proc/net");
            assert_eq!(row.state, "LISTEN");
            assert_eq!(row.remote_addr, "0.0.0.0:*");
            if row.pid == Some(std::process::id()) || Instant::now() >= deadline {
                assert_eq!(row.pid, Some(std::process::id()));
                assert_eq!(row.attribution, AttributionSource::Procfs);
                assert!(row.evidence.verified());
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failing_ss_falls_back_to_proc_net() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let local = socket.local_addr().unwrap().to_string();
        // `false` exists everywhere and exits 1, as a broken `ss` would.
        let table = parse_linux_connections_result("false", None).unwrap();
        assert_eq!(
            table.source,
            super::super::attribution::TableSource::ProcNet
        );
        assert_eq!(table.note.as_deref(), Some("ss failed (exit status: 1)"));
        assert!(table
            .rows
            .iter()
            .any(|c| c.protocol == "UDP" && c.local_addr == local && c.state == "UNCONN"));
    }

    /// The real worker, end to end: the coverage the capability report reads
    /// says where the table came from and why.
    #[cfg(target_os = "linux")]
    #[test]
    fn collector_records_the_fallback_in_coverage() {
        use std::time::Duration;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = listener.local_addr().unwrap().to_string();
        let collector = ConnectionCollector::new(Arc::new(Mutex::new(StreamTracker::new())))
            .with_ss_program(MISSING_SS);
        collector.update();
        let deadline = Instant::now() + Duration::from_secs(20);
        while collector.busy.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let coverage = collector.coverage();
        assert!(coverage.collection_succeeded, "{coverage:?}");
        assert_eq!(
            coverage.table_source,
            Some(super::super::attribution::TableSource::ProcNet)
        );
        assert_eq!(coverage.table_note.as_deref(), Some("ss not found"));
        assert!(collector
            .connections()
            .iter()
            .any(|c| c.protocol == "TCP" && c.local_addr == local && c.state == "LISTEN"));
    }

    #[test]
    fn connections_generation_bumps_per_publish() {
        let generation = |c: &ConnectionCollector| c.connections_with_generation().0;
        let collector = ConnectionCollector::new(Arc::new(Mutex::new(StreamTracker::new())));
        assert_eq!(generation(&collector), 0);
        collector.publish_for_test(Vec::new());
        collector.publish_for_test(Vec::new());
        assert_eq!(generation(&collector), 2);
        assert_eq!(generation(&collector), 2);

        // A poll publishes once.
        #[cfg(target_os = "linux")]
        {
            use std::time::Duration;
            let collector = collector.with_ss_program(MISSING_SS);
            collector.update();
            let deadline = Instant::now() + Duration::from_secs(20);
            while collector.busy.load(Ordering::SeqCst) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(generation(&collector), 3);
        }
    }

    /// A table with stale rows is copied once to strip them, not on every
    /// call, and again only when a publish, or another row going stale,
    /// changes what readers see. The generation changes with it, so a view
    /// keyed on the generation alone sees an owner blanked between polls.
    #[test]
    fn stale_strip_is_cached() {
        use super::super::attribution::{UnknownReason, MAX_MATCH_AGE};
        use std::time::Duration;
        let collector = ConnectionCollector::new(Arc::new(Mutex::new(StreamTracker::new())));
        let row = |port: u16, pid: u32, observed_at: Instant| {
            let mut c = make_conn(
                "TCP",
                &format!("127.0.0.1:{port}"),
                "127.0.0.1:9",
                "ESTABLISHED",
                pid,
            );
            c.evidence.observed_at = Some(observed_at);
            c
        };
        let now = Instant::now();
        let fresh = row(1, 1, now);
        let stale = row(2, 2, now - MAX_MATCH_AGE - Duration::from_secs(1));
        // Goes stale two seconds from now.
        let ageing = row(3, 3, now - MAX_MATCH_AGE + Duration::from_secs(2));
        collector.publish_for_test(vec![fresh.clone(), stale, ageing.clone()]);

        let (first_generation, first) = collector.connections_with_generation();
        assert!(Arc::ptr_eq(&first, &collector.connections()));
        assert_eq!(collector.connections_with_generation().0, first_generation);
        assert_eq!(
            first.iter().map(|c| c.pid).collect::<Vec<_>>(),
            [Some(1), None, Some(3)]
        );
        assert_eq!(
            first[1].evidence.unknown_reason,
            Some(UnknownReason::StaleSnapshot)
        );

        let deadline = Instant::now() + Duration::from_secs(5);
        while ageing.evidence.fresh() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let (second_generation, second) = collector.connections_with_generation();
        assert!(!Arc::ptr_eq(&first, &second));
        assert!(second_generation > first_generation);
        assert_eq!(
            second.iter().map(|c| c.pid).collect::<Vec<_>>(),
            [Some(1), None, None]
        );
        assert!(Arc::ptr_eq(&second, &collector.connections()));
        assert_eq!(collector.connections_with_generation().0, second_generation);

        // A table with nothing stale is served as published, not copied.
        // Its generation is past the strip's, not the publish count, which
        // the strip already reached.
        let mut fresh = fresh;
        fresh.evidence.observe();
        collector.publish_for_test(vec![fresh]);
        let (third_generation, third) = collector.connections_with_generation();
        assert!(third_generation > second_generation);
        assert_eq!(third[0].pid, Some(1));
        assert!(Arc::ptr_eq(
            &third,
            &safe_read(&collector.snapshot, "connections::snapshot").rows
        ));
    }

    #[test]
    fn wildcard_udp_rows_find_a_stream_by_local_endpoint() {
        use crate::dpi::AppProtocol;
        let stun = AppProtocol::Stun {
            message_type: "Binding Request".into(),
        };
        let ssh = AppProtocol::Ssh {
            version: "SSH-2.0".into(),
        };
        let app_protos = HashMap::from([
            (
                StreamKey::new(
                    StreamProtocol::Udp,
                    "198.51.100.7",
                    3478,
                    "192.0.2.10",
                    50000,
                ),
                stun.clone(),
            ),
            (
                StreamKey::new(StreamProtocol::Tcp, "192.0.2.10", 50001, "198.51.100.7", 22),
                ssh,
            ),
        ]);
        let by_local = udp_app_protocols_by_local(&app_protos);
        let found = |proto: &str, local: &str| {
            match_udp_app_protocol_by_local(&make_conn(proto, local, "*:*", "UNCONN", 1), &by_local)
        };
        // Either side of the stream can be the local one.
        assert_eq!(found("UDP", "192.0.2.10:50000"), Some(stun.clone()));
        assert_eq!(found("UDP", "198.51.100.7:3478"), Some(stun));
        assert_eq!(found("UDP", "192.0.2.10:50002"), None);
        // TCP streams and TCP rows take no part.
        assert_eq!(found("UDP", "192.0.2.10:50001"), None);
        assert_eq!(found("TCP", "192.0.2.10:50000"), None);
    }

    /// The log notes each change of table once, including a session whose
    /// very first poll reads no table, which compared equal to "not polled".
    #[cfg(target_os = "linux")]
    #[test]
    fn table_changes_are_logged_once_from_the_first_poll() {
        use super::super::attribution::TableSource::{ProcNet, Ss};
        let cases = [
            (None, Some(Ss), None),
            (None, Some(ProcNet), Some(TableChange::ProcNet)),
            (None, None, Some(TableChange::NoTable)),
            (Some(None), None, None),
            (Some(None), Some(Ss), Some(TableChange::SsAgain)),
            (Some(None), Some(ProcNet), Some(TableChange::ProcNet)),
            (Some(Some(Ss)), Some(Ss), None),
            (Some(Some(Ss)), Some(ProcNet), Some(TableChange::ProcNet)),
            (Some(Some(ProcNet)), Some(ProcNet), None),
            (Some(Some(ProcNet)), Some(Ss), Some(TableChange::SsAgain)),
            (Some(Some(ProcNet)), None, Some(TableChange::NoTable)),
        ];
        for (previous, current, want) in cases {
            assert_eq!(
                table_change(previous, current),
                want,
                "{previous:?} -> {current:?}"
            );
        }
    }

    /// The fallback inside the confined worker. Landlock grants `/proc` but
    /// not execution outside the system paths, so an `ss` elsewhere (as on a
    /// host that installs it under another prefix) cannot start, and the poll
    /// must read `/proc/net` rather than publish an empty table.
    #[cfg(target_os = "linux")]
    #[test]
    fn proc_net_fallback_works_inside_the_worker_sandbox() {
        use std::time::Duration;
        const CHILD: &str = "NETWATCH_PROC_NET_SANDBOX_TEST";
        let Ok(root) = std::env::var(CHILD) else {
            struct TestDir(std::path::PathBuf);
            impl Drop for TestDir {
                fn drop(&mut self) {
                    let _ = std::fs::remove_dir_all(&self.0);
                }
            }
            let temp = TestDir(
                std::env::temp_dir().join(format!("netwatch-procnet-{}", uuid::Uuid::new_v4())),
            );
            std::fs::create_dir(&temp.0).unwrap();
            // Runs and fails outside the sandbox; inside it, may not run at all.
            let fake_ss = temp.0.join("ss");
            std::fs::write(&fake_ss, "#!/bin/sh\nexit 1\n").unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fake_ss, std::fs::Permissions::from_mode(0o755)).unwrap();
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "collectors::connections::tests::proc_net_fallback_works_inside_the_worker_sandbox",
                    "--nocapture",
                ])
                .env(CHILD, &temp.0)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            return;
        };
        let root = std::path::PathBuf::from(root);
        let paths = crate::sandbox::SandboxPaths {
            cache_dir: Some(root.join("cache")),
            config_dir: Some(root.join("config")),
            state_dir: Some(root.join("state")),
            cwd: Some(root.join("exports")),
            ..Default::default()
        };
        paths.prepare().unwrap();
        crate::sandbox::worker::install(crate::sandbox::Mode::Strict, paths).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = listener.local_addr().unwrap().to_string();
        let fake_ss: &'static str = Box::leak(
            root.join("ss")
                .into_os_string()
                .into_string()
                .unwrap()
                .into_boxed_str(),
        );
        let collector = ConnectionCollector::new(Arc::new(Mutex::new(StreamTracker::new())))
            .with_ss_program(fake_ss);
        collector.update();
        let deadline = Instant::now() + Duration::from_secs(20);
        while collector.busy.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let worker = crate::sandbox::worker::snapshot().remove("connections");
        assert!(
            worker
                .as_ref()
                .is_some_and(|w| w.ready && w.error.is_none()),
            "the connections worker did not enter the sandbox: {worker:?}"
        );
        let coverage = collector.coverage();
        assert!(coverage.collection_succeeded, "{coverage:?}");
        assert_eq!(
            coverage.table_source,
            Some(super::super::attribution::TableSource::ProcNet)
        );
        let note = coverage.table_note.unwrap_or_default();
        assert!(
            note.starts_with("ss could not start"),
            "the sandbox let a binary outside its grants run: {note}"
        );
        assert!(collector
            .connections()
            .iter()
            .any(|c| c.protocol == "TCP" && c.local_addr == local && c.state == "LISTEN"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn find_on_path_wants_an_executable_file() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("netwatch-path-{}", uuid::Uuid::new_v4()));
        let (dir, plain, exec) = (root.join("dir"), root.join("plain"), root.join("exec"));
        for d in [&dir, &plain, &exec] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::create_dir(dir.join("ss")).unwrap();
        std::fs::write(plain.join("ss"), "").unwrap();
        std::fs::write(exec.join("ss"), "").unwrap();
        std::fs::set_permissions(exec.join("ss"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = |dirs: &[&std::path::PathBuf]| std::env::join_paths(dirs).unwrap();
        assert_eq!(find_on_path("ss", &path(&[&dir, &plain])), None);
        assert_eq!(
            find_on_path("ss", &path(&[&dir, &plain, &exec])),
            Some(exec.join("ss"))
        );
        let _ = std::fs::remove_dir_all(&root);
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

        // Only rows from ss: the /proc/net fallback would pass on any host
        // and say nothing about the format ss prints.
        let conns = match parse_linux_connections_result(SS_PROGRAM, None) {
            Ok(table) if table.source == super::super::attribution::TableSource::Ss => table.rows,
            other => {
                eprintln!(
                    "ss unavailable here ({:?}); skipping",
                    other.map(|t| t.note)
                );
                return;
            }
        };

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

    fn numbered(local: &str, n: u32) -> Vec<Connection> {
        (0..n)
            .map(|i| {
                make_conn(
                    "TCP",
                    &format!("{local}:{i}"),
                    "10.0.0.1:443",
                    "ESTABLISHED",
                    i,
                )
            })
            .collect()
    }

    fn key_of(c: &Connection) -> ConnectionKey {
        ConnectionKey {
            protocol: c.protocol.clone(),
            local_addr: c.local_addr.clone(),
            remote_addr: c.remote_addr.clone(),
            pid: c.pid,
        }
    }

    /// Every entry is indexed at its own position, and nothing else is.
    fn assert_indexed(tl: &ConnectionTimeline) {
        assert_eq!(tl.known_keys.len(), tl.tracked.len());
        for (i, t) in tl.tracked.iter().enumerate() {
            assert_eq!(tl.known_keys.get(&t.key), Some(&i));
            assert_eq!(tl.first_seen(&t.key), Some(t.first_seen));
        }
    }

    #[test]
    fn closed_history_keeps_every_active_entry_and_the_last_closed() {
        let mut tl = ConnectionTimeline::new();
        let old = numbered("127.0.0.1", MAX_CLOSED_HISTORY as u32);
        tl.update(&old);
        tl.update(&[]);
        assert_eq!(tl.closed_len(), MAX_CLOSED_HISTORY);

        // At the bound, new connections evict nothing: the bound is on what
        // has closed, not on what the timeline holds.
        let new = numbered("192.168.0.1", 10);
        tl.update(&new);
        assert_eq!(tl.tracked.len(), MAX_CLOSED_HISTORY + 10);
        assert!(!tl.closed_trimmed());

        // Past it, a whole batch of the longest closed goes at once.
        tl.update(&[]);
        assert_eq!(
            tl.closed_len(),
            MAX_CLOSED_HISTORY + 10 - CLOSED_EVICT_BATCH
        );
        assert_eq!(tl.tracked.len(), tl.closed_len());
        assert!(tl.closed_trimmed());
        for c in &old[..CLOSED_EVICT_BATCH] {
            assert_eq!(tl.first_seen(&key_of(c)), None, "{} kept", c.local_addr);
        }
        for c in old[CLOSED_EVICT_BATCH..].iter().chain(&new) {
            assert!(
                tl.first_seen(&key_of(c)).is_some(),
                "{} evicted",
                c.local_addr
            );
        }
        assert_indexed(&tl);
    }

    #[test]
    fn closed_history_evicts_what_closed_longest_ago() {
        let mut tl = ConnectionTimeline::new();
        // First seen with the rest, and first in the table, but the last to
        // close: eviction by first sight would take it first.
        let long_lived = make_conn("TCP", "10.9.9.9:22", "10.0.0.2:50000", "ESTABLISHED", 7);
        let mut rows = vec![long_lived.clone()];
        rows.extend(numbered("127.0.0.1", MAX_CLOSED_HISTORY as u32));
        tl.update(&rows);
        tl.update(std::slice::from_ref(&long_lived));
        assert!(!tl.closed_trimmed());
        tl.update(&[]);

        assert!(tl.closed_trimmed());
        assert_eq!(tl.closed_len(), MAX_CLOSED_HISTORY + 1 - CLOSED_EVICT_BATCH);
        assert!(tl.first_seen(&key_of(&long_lived)).is_some());
        assert!(rows[1..=CLOSED_EVICT_BATCH]
            .iter()
            .all(|c| tl.first_seen(&key_of(c)).is_none()));
        assert_indexed(&tl);
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

    /// The capture thread shares the stream tracker. A poll after it panicked
    /// holding the tracker used to die on the poisoned lock with `busy` still
    /// set, and the connection list never updated again.
    #[test]
    fn update_finishes_with_a_poisoned_stream_tracker() {
        use std::time::Duration;
        let tracker = Arc::new(Mutex::new(StreamTracker::new()));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = tracker.lock().unwrap();
            panic!("parser bug");
        }));
        assert!(tracker.is_poisoned());
        let collector = ConnectionCollector::new(tracker);
        collector.update();
        let deadline = Instant::now() + Duration::from_secs(20);
        while collector.busy.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !collector.busy.load(Ordering::SeqCst),
            "the poll died on the poisoned tracker"
        );
    }
}

#[cfg(test)]
mod windows_table_tests {
    use super::*;
    use crate::platform::socket_table::Socket;

    // `netstat -ano` from an English Windows 11, trimmed.
    const NETSTAT_EN: &str = "
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1116
  TCP    127.0.0.1:50443        127.0.0.1:50444        ESTABLISHED     8812
  TCP    192.168.1.20:50611     140.82.112.25:443      TIME_WAIT       0
  TCP    192.168.1.20:50612     140.82.112.25:443      CLOSE_WAIT      8812
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::1]:50500            [::1]:8080             SYN_SENT        8812
  UDP    0.0.0.0:5353           *:*                                    2260
  UDP    [::]:5353              *:*                                    2260
";

    // The same listener and connection on a German install.
    const NETSTAT_DE: &str = "
Aktive Verbindungen

  Proto  Lokale Adresse         Remoteadresse          Status           PID
  TCP    0.0.0.0:135            0.0.0.0:0              ABHÖREN          1116
  TCP    127.0.0.1:50443        127.0.0.1:50444        HERGESTELLT      8812
";

    #[test]
    fn english_netstat_rows_read_like_the_api_rows() {
        let rows = parse_netstat_output(NETSTAT_EN);
        assert_eq!(rows.len(), 8, "header and blank lines are skipped");
        assert_eq!(
            rows[0],
            Socket {
                protocol: "TCP",
                local_addr: "0.0.0.0:135".into(),
                remote_addr: "*:*".into(),
                state: "LISTEN".into(),
                pid: Some(1116),
            }
        );
        let states: Vec<&str> = rows.iter().map(|r| r.state.as_str()).collect();
        assert_eq!(
            states,
            [
                "LISTEN",
                "ESTABLISHED",
                "TIME-WAIT",
                "CLOSE-WAIT",
                "LISTEN",
                "SYN-SENT",
                "",
                ""
            ]
        );
        assert_eq!(rows[2].pid, None, "TIME_WAIT's PID 0 owns nothing");
        assert_eq!(rows[4].remote_addr, "*:*");
        assert_eq!(rows[5].local_addr, "[::1]:50500");
        assert_eq!(rows[6].protocol, "UDP");
        assert_eq!(rows[6].remote_addr, "*:*");
        assert_eq!(rows[6].pid, Some(2260));
    }

    /// The fallback cannot translate, and does not pretend to: the API is
    /// what fixes a German install. The rest of the row still reads.
    #[test]
    fn a_translated_netstat_state_is_kept_verbatim() {
        let rows = parse_netstat_output(NETSTAT_DE);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].state, "ABHÖREN");
        assert_eq!(rows[0].remote_addr, "*:*");
        assert_eq!(rows[1].state, "HERGESTELLT");
        assert_eq!(rows[1].pid, Some(8812));
    }

    /// The API rows carry no IPv6 scope; the fallback drops netstat's, so
    /// the same socket keeps one endpoint whichever path read it.
    #[test]
    fn netstat_link_local_endpoints_lose_their_scope() {
        let rows = parse_netstat_output(
            "  TCP    [fe80::a5d1:f1c0:5bd4:3f7b%12]:50700  [fe80::1%12]:445  ESTABLISHED  8812
  UDP    [fe80::a5d1:f1c0:5bd4:3f7b%12]:1900  *:*  2260
",
        );
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].local_addr, "[fe80::a5d1:f1c0:5bd4:3f7b]:50700");
        assert_eq!(rows[0].remote_addr, "[fe80::1]:445");
        assert_eq!(rows[1].local_addr, "[fe80::a5d1:f1c0:5bd4:3f7b]:1900");
        assert_eq!(rows[1].remote_addr, "*:*");
        assert_eq!(
            normalize_addr(&rows[0].local_addr),
            Some(("fe80::a5d1:f1c0:5bd4:3f7b".parse().unwrap(), 50700))
        );
    }

    #[test]
    fn short_netstat_rows_are_skipped() {
        assert!(parse_netstat_output("  TCP    0.0.0.0:135\n  UDP 0.0.0.0:53\n").is_empty());
        assert!(parse_netstat_output("").is_empty());
    }

    #[test]
    fn tasklist_names_only_the_pids_asked_for() {
        let text = "\"System Idle Process\",\"0\",\"Services\",\"0\",\"8 K\"\n\
                    \"svchost.exe\",\"1116\",\"Services\",\"0\",\"12,345 K\"\n\
                    \"chrome.exe\",\"8812\",\"Console\",\"1\",\"250,000 K\"\n";
        let names = parse_tasklist_output(text, &HashSet::from([8812, 1116, 77]));
        assert_eq!(names.len(), 2);
        assert_eq!(names[&8812], "chrome.exe");
        assert_eq!(names[&1116], "svchost.exe");
    }

    #[test]
    fn table_rows_become_named_connections_with_their_source() {
        let sockets = vec![
            Socket {
                protocol: "TCP",
                local_addr: "127.0.0.1:50443".into(),
                remote_addr: "127.0.0.1:8080".into(),
                state: "ESTABLISHED".into(),
                pid: Some(8812),
            },
            Socket {
                protocol: "TCP",
                local_addr: "127.0.0.1:50444".into(),
                remote_addr: "127.0.0.1:8080".into(),
                state: "TIME-WAIT".into(),
                pid: None,
            },
            Socket {
                protocol: "UDP",
                local_addr: "0.0.0.0:5353".into(),
                remote_addr: "*:*".into(),
                state: String::new(),
                pid: Some(31337),
            },
        ];
        let names = HashMap::from([(8812, "chrome.exe".to_string())]);
        let conns = windows_connections(sockets, &names, AttributionSource::IpHelper);
        assert_eq!(conns.len(), 3);
        assert!(conns
            .iter()
            .all(|c| c.attribution == AttributionSource::IpHelper));
        assert_eq!(conns[0].process_name.as_deref(), Some("chrome.exe"));
        assert_eq!(conns[0].pid, Some(8812));
        assert_eq!(
            process_label(conns[1].process_name.as_deref(), conns[1].pid),
            UNATTRIBUTED
        );
        // An exited process keeps its pid and reads as `pid:N`.
        assert_eq!(
            process_label(conns[2].process_name.as_deref(), conns[2].pid),
            "pid:31337"
        );
        assert_eq!(
            connection_stream_key(&conns[0]).map(|(k, _)| k),
            Some(StreamKey::new(
                StreamProtocol::Tcp,
                "127.0.0.1",
                50443,
                "127.0.0.1",
                8080
            ))
        );
    }

    #[test]
    fn ip_helper_rows_serialise_as_iphelper() {
        assert_eq!(
            serde_json::to_value(AttributionSource::IpHelper).unwrap(),
            serde_json::json!("iphelper")
        );
    }

    /// The whole Windows path, API to named row: a listener this test opens
    /// comes back under its own pid and image name, labelled as IP Helper.
    #[cfg(target_os = "windows")]
    #[test]
    fn live_windows_collector_names_its_own_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1");
        let local = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let conns = parse_windows_connections();
        let row = conns
            .iter()
            .find(|c| c.protocol == "TCP" && c.local_addr == local)
            .unwrap_or_else(|| panic!("no row for {local}"));
        assert_eq!(row.state, "LISTEN");
        assert_eq!(row.remote_addr, "*:*");
        assert_eq!(row.pid, Some(std::process::id()));
        assert_eq!(row.attribution, AttributionSource::IpHelper);
        let name = row.process_name.as_deref().unwrap_or_default();
        assert!(name.starts_with("netwatch"), "named {name:?}");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod diagnose_poll_tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    #[test]
    fn failed_socket_dump_is_not_a_successful_empty_dump() {
        let output = |status| std::process::Output {
            status: std::process::ExitStatus::from_raw(status),
            stdout: b"Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
                .to_vec(),
            stderr: vec![],
        };
        assert!(parse_ss_command_output(output(256), None).is_err());
        assert!(parse_ss_command_output(output(0), None).unwrap().is_empty());
        assert!(!super::super::attribution::Coverage::default().collection_succeeded);
    }
}

/// The `/proc/net` fallback's decoding, from fixtures, on every platform.
///
/// Addresses are from the documentation ranges, hex-encoded as a
/// little-endian kernel prints them.
#[cfg(test)]
mod proc_net_tests {
    use super::*;

    pub(super) const TCP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 41001 1 0000000000000000 100 0 0 10 0
   1: 0A0200C0:C822 076433C6:01BB 01 00000000:00000000 02:000A3B5C 00000000  1000        0 41002 2 0000000000000000 20 4 30 10 -1
   2: 0100007F:A1B2 0100007F:1F90 06 00000000:00000000 03:00001770 00000000     0        0 0 3 0000000000000000
";
    pub(super) const TCP6: &str = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 42001 1 0000000000000000 100 0 0 10 0
   1: B80D0120000000000000000001000000:01BB B80D0120000000000000000002000000:C350 01 00000000:00000000 02:00000A3B 00000000     0        0 42002 2 0000000000000000 20 4 30 10 -1
   2: 0000000000000000FFFF00000100007F:1F90 0000000000000000FFFF00000A0200C0:C822 01 00000000:00000000 00:00000000 00000000  1000        0 42003 1 0000000000000000 20 4 30 10 -1
";
    pub(super) const UDP: &str = "\
   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  236: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000    70        0 43001 2 0000000000000000 0
12198: 0A0200C0:D431 357100CB:0035 01 00000000:00000000 00:00000000 00000000  1000        0 43002 2 0000000000000000 0
";
    pub(super) const UDP6: &str = "\
   sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  323: 00000000000000000000000001000000:0143 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 44001 2 0000000000000000 0
";

    /// Every fixture row, as the fallback builds it.
    pub(super) fn fixture_rows() -> Vec<Connection> {
        [
            (TCP, StreamProtocol::Tcp),
            (TCP6, StreamProtocol::Tcp),
            (UDP, StreamProtocol::Udp),
            (UDP6, StreamProtocol::Udp),
        ]
        .into_iter()
        .flat_map(|(text, protocol)| {
            parse_proc_net_table(text)
                .map(move |socket| proc_net_connection(protocol, &socket))
                .collect::<Vec<_>>()
        })
        .collect()
    }

    fn rows(text: &str, protocol: StreamProtocol) -> Vec<[String; 4]> {
        parse_proc_net_table(text)
            .map(|socket| proc_net_connection(protocol, &socket))
            .map(|c| [c.protocol, c.local_addr, c.remote_addr, c.state])
            .collect()
    }

    fn row(protocol: &str, local: &str, remote: &str, state: &str) -> [String; 4] {
        [protocol, local, remote, state].map(String::from)
    }

    #[test]
    fn ipv4_tcp_listen_established_and_time_wait() {
        assert_eq!(
            rows(TCP, StreamProtocol::Tcp),
            [
                row("TCP", "127.0.0.1:8080", "0.0.0.0:*", "LISTEN"),
                row("TCP", "192.0.2.10:51234", "198.51.100.7:443", "ESTABLISHED"),
                row("TCP", "127.0.0.1:41394", "127.0.0.1:8080", "TIME-WAIT"),
            ]
        );
    }

    #[test]
    fn ipv6_tcp_is_bracketed_and_v4_mapped_keeps_its_ss_spelling() {
        assert_eq!(
            rows(TCP6, StreamProtocol::Tcp),
            [
                row("TCP", "[::]:22", "[::]:*", "LISTEN"),
                row(
                    "TCP",
                    "[2001:db8::1]:443",
                    "[2001:db8::2]:50000",
                    "ESTABLISHED"
                ),
                row(
                    "TCP",
                    "[::ffff:127.0.0.1]:8080",
                    "[::ffff:192.0.2.10]:51234",
                    "ESTABLISHED"
                ),
            ]
        );
    }

    #[test]
    fn udp_unconnected_is_unconn_and_connected_is_established() {
        assert_eq!(
            rows(UDP, StreamProtocol::Udp),
            [
                row("UDP", "0.0.0.0:5353", "0.0.0.0:*", "UNCONN"),
                row("UDP", "192.0.2.10:54321", "203.0.113.53:53", "ESTABLISHED"),
            ]
        );
        assert_eq!(
            rows(UDP6, StreamProtocol::Udp),
            [row("UDP", "[::1]:323", "[::]:*", "UNCONN")]
        );
    }

    #[test]
    fn inode_and_state_columns_are_read() {
        let sockets: Vec<_> = parse_proc_net_table(TCP).collect();
        assert_eq!(
            sockets
                .iter()
                .map(|s| (s.state, s.inode))
                .collect::<Vec<_>>(),
            [(0x0A, 41001), (0x01, 41002), (0x06, 0)]
        );
    }

    /// The capture side sees a v4-mapped socket's packets as plain IPv4, so
    /// the row must key to the IPv4 stream, as an `ss` row for it does.
    #[test]
    fn v4_mapped_row_joins_the_ipv4_stream() {
        let rows = fixture_rows();
        let mapped = rows
            .iter()
            .find(|c| c.local_addr == "[::ffff:127.0.0.1]:8080")
            .unwrap();
        let (key, side) = connection_stream_key(mapped).unwrap();
        assert_eq!(
            key,
            StreamKey::new(StreamProtocol::Tcp, "127.0.0.1", 8080, "192.0.2.10", 51234)
        );
        assert_eq!(
            key.addr_a == ("127.0.0.1".to_string(), 8080),
            side == LocalSide::A
        );
    }

    #[test]
    fn established_rows_key_to_their_streams_and_wildcard_peers_do_not() {
        for c in fixture_rows() {
            let keyed = connection_stream_key(&c).is_some();
            assert_eq!(keyed, !c.remote_addr.ends_with(":*"), "{c:?}");
        }
    }

    #[test]
    fn every_kernel_state_has_its_ss_name() {
        let names: Vec<_> = (0x01..=0x0C).map(ss_state_name).collect();
        assert_eq!(
            names,
            [
                "ESTABLISHED",
                "SYN-SENT",
                "SYN-RECV",
                "FIN-WAIT-1",
                "FIN-WAIT-2",
                "TIME-WAIT",
                "UNCONN",
                "CLOSE-WAIT",
                "LAST-ACK",
                "LISTEN",
                "CLOSING",
                "SYN-RECV",
            ]
        );
        assert_eq!(ss_state_name(0), "UNKNOWN");
        assert_eq!(ss_state_name(0xFF), "UNKNOWN");
    }

    #[test]
    fn endpoints_render_as_ss_prints_them() {
        let ep = |ip: &str, port| format_ss_endpoint((ip.parse().unwrap(), port));
        assert_eq!(ep("10.0.2.15", 22), "10.0.2.15:22");
        assert_eq!(ep("0.0.0.0", 0), "0.0.0.0:*");
        assert_eq!(ep("::", 0), "[::]:*");
        assert_eq!(ep("fe80::1", 546), "[fe80::1]:546");
        assert_eq!(ep("::ffff:10.0.2.15", 443), "[::ffff:10.0.2.15]:443");
    }

    #[test]
    fn header_short_and_malformed_lines_are_skipped() {
        let header = TCP.lines().next().unwrap();
        assert_eq!(parse_proc_net_table(header).count(), 0);
        assert_eq!(parse_proc_net_table("").count(), 0);
        let text = format!(
            "{header}\n\
             0: 0100007F:1F90 00000000:0000 0A 00000000:00000000\n\
             1: nothex:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1\n\
             2: 0100007F:1F90 00000000:0000 ZZ 00000000:00000000 00:00000000 00000000 0 0 1\n\
             3: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 x\n\
             4: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 7\n"
        );
        let parsed: Vec<_> = parse_proc_net_table(&text).collect();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].inode, 7);
    }
}
