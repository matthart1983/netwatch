use crate::app::{safe_read, safe_write};
use crate::collectors::packets::{StreamKey, StreamProtocol, StreamTracker};
#[cfg(target_os = "macos")]
use crate::platform::pktap::PktapAttributor;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Instant;

/// Where the (pid, process_name) on a Connection came from.
///
/// `Lsof` is the userspace fallback (lsof/ss/netstat polling). `Pktap`
/// means the attribution came from the macOS PKTAP kernel-level capture
/// path. `Ebpf` means it came from netwatch-sdk's tcp_v4_connect kprobe
/// on Linux. Both kernel paths catch short-lived flows that lsof misses
/// and report the *thread* comm rather than the parent binary's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AttributionSource {
    #[default]
    Lsof,
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
    /// Kernel-measured smoothed RTT in microseconds (from eBPF tcp_probe).
    pub kernel_rtt_us: Option<f64>,
    /// Inbound (remote→local) payload bytes per second, derived from the
    /// ambient packet capture. `None` when capture isn't running or the
    /// connection hasn't been seen on the wire yet.
    pub rx_rate: Option<f64>,
    /// Outbound (local→remote) payload bytes per second.
    pub tx_rate: Option<f64>,
    #[serde(default)]
    pub attribution: AttributionSource,
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
}

impl RateState {
    fn new() -> Self {
        Self {
            prev: HashMap::new(),
            prev_time: Instant::now(),
            rates: HashMap::new(),
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
    #[cfg(target_os = "macos")]
    pktap: Option<Arc<PktapAttributor>>,
    #[cfg(feature = "ebpf")]
    ebpf: Option<Arc<crate::ebpf::conn_tracker::EbpfAttributor>>,
    /// Pre-sandbox `/proc` attribution snapshot for connections that predate
    /// startup (see [`ProcSnapshot`]). `None` until attached.
    #[cfg(target_os = "linux")]
    proc_snapshot: Option<Arc<ProcSnapshot>>,
}

impl ConnectionCollector {
    pub fn new(stream_tracker: Arc<Mutex<StreamTracker>>) -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(Arc::new(Vec::new()))),
            busy: Arc::new(AtomicBool::new(false)),
            stream_tracker,
            rate_state: Arc::new(Mutex::new(RateState::new())),
            #[cfg(target_os = "macos")]
            pktap: None,
            #[cfg(feature = "ebpf")]
            ebpf: None,
            #[cfg(target_os = "linux")]
            proc_snapshot: None,
        }
    }

    /// Cheap snapshot of the most recent connection list. Single atomic
    /// refcount bump regardless of connection count — the returned `Arc`
    /// derefs to `&Vec<Connection>` so call sites work with it like a slice.
    pub fn connections(&self) -> Arc<Vec<Connection>> {
        Arc::clone(&safe_read(&self.snapshot, "connections::snapshot"))
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
    /// overlay (pid, comm) from the SDK's `tcp_v4_connect` kprobe onto
    /// matching ss/lsof-discovered connections — same shape as the PKTAP
    /// overlay on macOS.
    #[cfg(feature = "ebpf")]
    pub fn with_ebpf(mut self, ebpf: Arc<crate::ebpf::conn_tracker::EbpfAttributor>) -> Self {
        self.ebpf = Some(ebpf);
        self
    }

    /// Attach the pre-sandbox `/proc` attribution snapshot. Set in `App::new`
    /// before `sandbox::apply` so pre-existing connections stay attributable
    /// even after Landlock blocks live `/proc/<pid>/fd` reads.
    #[cfg(target_os = "linux")]
    pub fn with_proc_snapshot(mut self, snapshot: Arc<ProcSnapshot>) -> Self {
        self.proc_snapshot = Some(snapshot);
        self
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
        #[cfg(target_os = "macos")]
        let pktap = self.pktap.clone();
        #[cfg(feature = "ebpf")]
        let ebpf = self.ebpf.clone();
        #[cfg(target_os = "linux")]
        let proc_snapshot = self.proc_snapshot.clone();
        thread::spawn(move || {
            #[cfg(target_os = "macos")]
            let mut result = parse_lsof();
            #[cfg(target_os = "linux")]
            let mut result = parse_linux_connections();
            #[cfg(target_os = "windows")]
            let mut result = parse_windows_connections();
            #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
            let mut result: Vec<Connection> = Vec::new();

            let (stream_bytes, app_protos, anomalies) = {
                let tracker = stream_tracker.lock().unwrap();
                (
                    tracker.snapshot_bytes(),
                    tracker.snapshot_app_protocols(),
                    tracker.snapshot_anomalies(),
                )
            };
            let mut state = rate_state.lock().unwrap();
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

            let count = result.len();
            *safe_write(&snapshot, "connections::publish") = Arc::new(result);
            tracing::trace!(target: "netwatch::connections", count, "published connection snapshot");
            busy.store(false, Ordering::SeqCst);
        });
    }
}

/// For each lsof-discovered connection whose 5-tuple appears in the PKTAP
/// cache, replace the userspace-scraped (pid, process_name) with the
/// kernel-attributed values and flip `attribution` to `Pktap`. Connections
/// not present in the cache are left untouched.
#[cfg(target_os = "macos")]
fn overlay_pktap_attribution(connections: &mut [Connection], pktap: &PktapAttributor) {
    for conn in connections {
        if let Some((key, _)) = connection_stream_key(conn) {
            if let Some(attr) = pktap.lookup(&key) {
                conn.pid = Some(attr.pid);
                conn.process_name = Some(attr.comm);
                conn.attribution = AttributionSource::Pktap;
            }
        }
    }
}

/// Overlay (pid, comm) from netwatch-sdk's `tcp_v4_connect`/`tcp_v6_connect`
/// kprobes onto matching connections. Cache key is `(daddr, dport)` — the
/// kprobes can't read the socket's source addr/port at connect-entry. Only
/// TCP rows are candidates; everything else is left untouched.
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
            conn.pid = Some(attr.pid);
            conn.process_name = Some(attr.comm);
            conn.attribution = AttributionSource::Ebpf;
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
                kernel_rtt_us: None,
                rx_rate: None,
                tx_rate: None,
                attribution: AttributionSource::Lsof,
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

#[cfg(target_os = "linux")]
fn parse_linux_connections() -> Vec<Connection> {
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
                kernel_rtt_us: None,
                rx_rate: None,
                tx_rate: None,
                attribution: AttributionSource::Lsof,
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
    overlay_proc_attribution(&mut connections);

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

/// socket inode → (pid, comm), built by scanning `/proc/<pid>/fd/*` for
/// `socket:[<inode>]` symlinks. Only sees PIDs the current uid is allowed to
/// inspect — that's the kernel's call, and it's strictly more than `ss -p`
/// surfaces for an unprivileged caller (which is nothing).
#[cfg(target_os = "linux")]
fn socket_inode_owners() -> HashMap<u64, (u32, String)> {
    let mut map: HashMap<u64, (u32, String)> = HashMap::new();
    let Ok(proc) = std::fs::read_dir("/proc") else {
        return map;
    };
    for entry in proc.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        let mut comm: Option<String> = None;
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
            let name = comm.get_or_insert_with(|| read_proc_comm(pid)).clone();
            map.entry(inode).or_insert((pid, name));
        }
    }
    map
}

/// Index of the kernel socket tables: a 5-tuple map for precise matches and a
/// local-endpoint map as a fallback for sockets with no distinct peer (UDP,
/// LISTEN). Values are socket inodes joined against `socket_inode_owners()`.
#[cfg(target_os = "linux")]
#[derive(Default)]
struct ProcNetIndex {
    by_pair: HashMap<((std::net::IpAddr, u16), (std::net::IpAddr, u16)), u64>,
    by_local: HashMap<(std::net::IpAddr, u16), u64>,
}

#[cfg(target_os = "linux")]
fn proc_net_inode_index() -> ProcNetIndex {
    let mut idx = ProcNetIndex::default();
    for path in [
        "/proc/net/tcp",
        "/proc/net/tcp6",
        "/proc/net/udp",
        "/proc/net/udp6",
    ] {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines().skip(1) {
            // sl local rem st tx:rx tr:when retrnsmt uid timeout inode ...
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 {
                continue;
            }
            let Some(local) = parse_proc_net_hex(cols[1]) else {
                continue;
            };
            let Ok(inode) = cols[9].parse::<u64>() else {
                continue;
            };
            if inode == 0 {
                continue;
            }
            if let Some(remote) = parse_proc_net_hex(cols[2]) {
                idx.by_pair.entry((local, remote)).or_insert(inode);
            }
            idx.by_local.entry(local).or_insert(inode);
        }
    }
    idx
}

/// Fill `process_name`/`pid` on any connection `ss` left nameless, using the
/// native `/proc` join. No-op (and no `/proc` scan) when everything is already
/// attributed — the common privileged case where `ss -p` worked.
#[cfg(target_os = "linux")]
fn overlay_proc_attribution(connections: &mut [Connection]) {
    if connections.iter().all(|c| c.process_name.is_some()) {
        return;
    }
    let index = proc_net_inode_index();
    let owners = socket_inode_owners();
    if owners.is_empty() {
        return;
    }
    for conn in connections.iter_mut() {
        if conn.process_name.is_some() {
            continue;
        }
        let Some(local) = normalize_addr(&conn.local_addr) else {
            continue;
        };
        let inode = normalize_addr(&conn.remote_addr)
            .and_then(|remote| index.by_pair.get(&(local, remote)).copied())
            .or_else(|| index.by_local.get(&local).copied());
        if let Some((pid, comm)) = inode.and_then(|i| owners.get(&i)) {
            conn.pid = Some(*pid);
            conn.process_name = Some(comm.clone());
        }
    }
}

/// Pre-sandbox `/proc` attribution snapshot: `(local, remote) → (pid, comm)`
/// for every socket visible at capture time. Built ONCE at startup, *before*
/// the Landlock sandbox is applied — Landlock's process-introspection scoping
/// otherwise blocks reading other processes' `/proc/<pid>/fd`, so this is the
/// only way to attribute connections that predate netwatch when sandboxed.
/// (eBPF covers connections opened after startup.)
#[cfg(target_os = "linux")]
pub type ProcSnapshot = HashMap<((std::net::IpAddr, u16), (std::net::IpAddr, u16)), (u32, String)>;

/// Capture the snapshot. Must be called before `sandbox::apply`. As root this
/// sees every process; unprivileged it sees the caller's own — same visibility
/// rules as `ss`/`/proc`.
#[cfg(target_os = "linux")]
pub fn capture_proc_snapshot() -> ProcSnapshot {
    let index = proc_net_inode_index();
    let owners = socket_inode_owners();
    let mut out = HashMap::new();
    for (pair, inode) in index.by_pair {
        if let Some(owner) = owners.get(&inode) {
            out.insert(pair, owner.clone());
        }
    }
    out
}

/// Fill nameless connections from the pre-sandbox snapshot — sandbox-safe
/// (no live `/proc` read). Matches on the full `(local, remote)` 5-tuple.
#[cfg(target_os = "linux")]
fn overlay_proc_snapshot(connections: &mut [Connection], snap: &ProcSnapshot) {
    if snap.is_empty() {
        return;
    }
    for conn in connections.iter_mut() {
        if conn.process_name.is_some() {
            continue;
        }
        let (Some(local), Some(remote)) = (
            normalize_addr(&conn.local_addr),
            normalize_addr(&conn.remote_addr),
        ) else {
            continue;
        };
        if let Some((pid, comm)) = snap.get(&(local, remote)) {
            conn.pid = Some(*pid);
            conn.process_name = Some(comm.clone());
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
            kernel_rtt_us: None,
            rx_rate: None,
            tx_rate: None,
            attribution: AttributionSource::Lsof,
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

    fn make_conn(proto: &str, local: &str, remote: &str, state: &str, pid: u32) -> Connection {
        Connection {
            protocol: proto.into(),
            local_addr: local.into(),
            remote_addr: remote.into(),
            state: state.into(),
            pid: Some(pid),
            process_name: Some("test".into()),
            kernel_rtt_us: None,
            rx_rate: None,
            tx_rate: None,
            attribution: AttributionSource::Lsof,
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
