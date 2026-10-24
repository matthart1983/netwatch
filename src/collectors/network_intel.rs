use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

// ── Configuration defaults ─────────────────────────────────

const PORT_SCAN_WINDOW_SECS: u64 = 30;
const PORT_SCAN_THRESHOLD: usize = 20;
const BEACON_MIN_SAMPLES: usize = 5;
const BEACON_MAX_SAMPLES: usize = 8;
const BEACON_JITTER_THRESHOLD: f64 = 0.15;
const BEACON_REALERT_COOLDOWN_SECS: u64 = 300; // re-surface a live beacon at most this often
const DNS_TUNNEL_QNAME_LEN: usize = 80;
const DNS_TUNNEL_QUERY_RATE: u32 = 50; // per minute per base domain
const DNS_TUNNEL_UNIQUE_SUBS: usize = 30;
const DNS_TUNNEL_ALERT_COOLDOWN_SECS: u64 = 60; // one alert per base domain per window
const DNS_OUTSTANDING_TIMEOUT_SECS: u64 = 5;
const STALE_ENTRY_SECS: u64 = 300;
pub(crate) const MAX_TRACKED_IPS: usize = 1000;
const MAX_TRACKED_DOMAINS: usize = 500;
pub(crate) const MAX_TRACKED_BEACONS: usize = 500;
const BW_ALERT_CONSECUTIVE: u32 = 2;
const BW_ALERT_CLEAR_RATIO: f64 = 0.9;
const TOP_DOMAINS_COUNT: usize = 20;

// ── Alert types ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum AlertSeverity {
    Warning,
    Critical,
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub severity: AlertSeverity,
    pub category: AlertCategory,
    pub message: String,
    pub detail: String,
    pub timestamp: Instant,
}

#[derive(Debug, Clone)]
pub enum AlertCategory {
    PortScan,
    Beaconing,
    DnsTunnel,
    Bandwidth,
    PolicyViolation,
}

impl AlertCategory {
    pub fn label(&self) -> &'static str {
        match self {
            Self::PortScan => "Port Scan",
            Self::Beaconing => "Beaconing",
            Self::DnsTunnel => "DNS Tunnel",
            Self::Bandwidth => "Bandwidth",
            Self::PolicyViolation => "Egress Policy",
        }
    }
}

// ── Events fed from other collectors ───────────────────────

pub struct ConnAttemptEvent {
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
}

pub struct DnsQueryEvent {
    pub txid: u16,
    pub client_ip: String,
    pub server_ip: String,
    pub qname: String,
}

pub struct DnsResponseEvent {
    pub txid: u16,
    pub client_ip: String,
    pub server_ip: String,
    pub rcode: u8, // 0=NOERROR, 3=NXDOMAIN, etc.
}

pub struct InterfaceRateEvent {
    pub iface: String,
    pub rx_bps: u64,
    pub tx_bps: u64,
}

/// A data-carrying packet observed on an already-established flow, used to
/// detect persistent-connection (single-socket) C2 beaconing that emits no
/// new SYNs. Fed from the packet pump in `App::feed_network_intel`.
pub struct FlowActivityEvent {
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
}

// ── Anomaly detection state ────────────────────────────────

struct ScanState {
    window_start: Instant,
    last_seen: Instant,
    ports: HashSet<u16>,
    alerted: bool,
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct BeaconKey {
    src: String,
    dst: String,
    dst_port: u16,
}

struct BeaconState {
    last_seen: Instant,
    deltas: VecDeque<Duration>,
    /// Last time this beacon raised an alert, gating a re-alert cooldown
    /// so a persistent beacon resurfaces periodically rather than firing
    /// once and never again.
    last_alert: Option<Instant>,
}

// ── DNS analytics state ────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct DnsAnalytics {
    pub total_queries: u64,
    pub total_responses: u64,
    pub nxdomain_count: u64,
    pub latency_buckets: [u64; 8], // <5ms, <10ms, <25ms, <50ms, <100ms, <250ms, <500ms, >=500ms
    pub top_domains: Vec<(String, u32)>,
}

struct DnsTxnKey {
    txid: u16,
    client_ip: String,
    server_ip: String,
}

impl std::hash::Hash for DnsTxnKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.txid.hash(state);
        self.client_ip.hash(state);
        self.server_ip.hash(state);
    }
}

impl PartialEq for DnsTxnKey {
    fn eq(&self, other: &Self) -> bool {
        self.txid == other.txid
            && self.client_ip == other.client_ip
            && self.server_ip == other.server_ip
    }
}

impl Eq for DnsTxnKey {}

struct OutstandingDns {
    sent_at: Instant,
    #[allow(dead_code)]
    qname: String,
}

struct DomainStats {
    count: u32,
    max_qname_len: usize,
    unique_prefixes: HashSet<String>,
    window_start: Instant,
    /// Last time we raised a DNS-tunnel alert for this base domain.
    /// Gates a per-domain cooldown so a flood of tunneled queries
    /// collapses to one alert instead of one-per-query.
    last_alert: Option<Instant>,
}

// ── Bandwidth alert state ──────────────────────────────────

struct BwAlertState {
    consecutive_over: u32,
    active: bool,
    threshold_rx: u64,
    threshold_tx: u64,
}

// ── Main collector ─────────────────────────────────────────

pub struct NetworkIntelCollector {
    // Anomaly
    scan_states: HashMap<String, ScanState>,
    beacon_states: HashMap<BeaconKey, BeaconState>,

    // DNS
    domain_counts: HashMap<String, u32>,
    domain_tunnel_stats: HashMap<String, DomainStats>,
    outstanding_dns: HashMap<DnsTxnKey, OutstandingDns>,
    dns_total_queries: u64,
    dns_total_responses: u64,
    dns_nxdomain: u64,
    dns_latency_buckets: [u64; 8],

    // Bandwidth
    bw_states: HashMap<String, BwAlertState>,
    bw_default_threshold: u64, // bytes/sec, 0 = disabled

    // Alerts
    active_alerts: Vec<Alert>,
    alert_history: VecDeque<Alert>,

    // Housekeeping
    last_prune: Instant,
}

impl Default for NetworkIntelCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkIntelCollector {
    pub fn new() -> Self {
        Self {
            scan_states: HashMap::new(),
            beacon_states: HashMap::new(),
            domain_counts: HashMap::new(),
            domain_tunnel_stats: HashMap::new(),
            outstanding_dns: HashMap::new(),
            dns_total_queries: 0,
            dns_total_responses: 0,
            dns_nxdomain: 0,
            dns_latency_buckets: [0; 8],
            bw_states: HashMap::new(),
            bw_default_threshold: 100_000_000, // 100 MB/s default
            active_alerts: Vec::new(),
            alert_history: VecDeque::new(),
            last_prune: Instant::now(),
        }
    }

    // ── Public API ─────────────────────────────────────────

    pub fn active_alerts(&self) -> &[Alert] {
        &self.active_alerts
    }

    pub fn alert_history(&self) -> &VecDeque<Alert> {
        &self.alert_history
    }

    /// Raise an egress-policy-violation warning (Horizon 3). Warning
    /// severity — a lint, not an incident — so it surfaces in the alert feed
    /// but never auto-freezes the recorder. Per-flow dedup is handled
    /// upstream by the egress profiler's cooldown.
    pub fn raise_policy_violation(&mut self, message: String, detail: String) {
        self.push_alert(
            AlertSeverity::Warning,
            AlertCategory::PolicyViolation,
            message,
            detail,
        );
    }

    // ── Memory-stats accessors (drive the `M` debug overlay) ──────────
    pub fn scan_states_len(&self) -> usize {
        self.scan_states.len()
    }
    pub fn beacon_states_len(&self) -> usize {
        self.beacon_states.len()
    }
    pub fn alert_history_len(&self) -> usize {
        self.alert_history.len()
    }

    pub fn dns_analytics(&self) -> DnsAnalytics {
        let mut top: Vec<(String, u32)> = self
            .domain_counts
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        top.sort_by_key(|b| std::cmp::Reverse(b.1));
        top.truncate(TOP_DOMAINS_COUNT);
        DnsAnalytics {
            total_queries: self.dns_total_queries,
            total_responses: self.dns_total_responses,
            nxdomain_count: self.dns_nxdomain,
            latency_buckets: self.dns_latency_buckets,
            top_domains: top,
        }
    }

    pub fn active_alert_count(&self) -> usize {
        self.active_alerts.len()
    }

    pub fn set_bandwidth_threshold(&mut self, threshold: u64) {
        self.bw_default_threshold = threshold;
    }

    /// Call periodically (e.g., every tick) to expire stale state
    pub fn tick(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_prune) > Duration::from_secs(30) {
            self.last_prune = now;
            self.prune_stale(now);
        }
        // Expire outstanding DNS queries
        self.outstanding_dns.retain(|_, v| {
            now.duration_since(v.sent_at) < Duration::from_secs(DNS_OUTSTANDING_TIMEOUT_SECS)
        });
        // Expire old active alerts (older than 60s)
        self.active_alerts
            .retain(|a| now.duration_since(a.timestamp) < Duration::from_secs(60));
    }

    // ── Event handlers ─────────────────────────────────────

    pub fn on_conn_attempt(&mut self, event: ConnAttemptEvent) {
        let now = Instant::now();
        let key = BeaconKey {
            src: event.src_ip.clone(),
            dst: event.dst_ip.clone(),
            dst_port: event.dst_port,
        };
        self.detect_port_scan(&event, now);
        self.detect_beacon(key, now);
    }

    /// Feed a data-carrying packet on an established flow. This catches the
    /// dominant modern C2 shape — a single persistent TCP/TLS connection
    /// that heartbeats on a fixed interval — which emits no new SYNs and is
    /// therefore invisible to `on_conn_attempt`. Routes into the same
    /// beacon jitter analysis; the detector's 5s–3600s delta window means a
    /// chatty download (sub-5s gaps) never registers as a beacon.
    pub fn on_flow_activity(&mut self, event: FlowActivityEvent) {
        let now = Instant::now();
        let key = BeaconKey {
            src: event.src_ip,
            dst: event.dst_ip,
            dst_port: event.dst_port,
        };
        self.detect_beacon(key, now);
    }

    pub fn on_dns_query(&mut self, event: DnsQueryEvent) {
        let now = Instant::now();
        self.dns_total_queries += 1;

        // Track domain counts
        let base_domain = extract_base_domain(&event.qname);
        *self.domain_counts.entry(base_domain.clone()).or_insert(0) += 1;

        // Bound domain_tunnel_stats: a DNS flood with endlessly unique base
        // domains would otherwise grow it without limit inside the 5-minute
        // prune window. Evict the oldest-window entry on a genuinely new key
        // at cap (same LRU pattern as scan/beacon state).
        if self.domain_tunnel_stats.len() >= MAX_TRACKED_DOMAINS
            && !self.domain_tunnel_stats.contains_key(&base_domain)
        {
            if let Some(oldest) = self
                .domain_tunnel_stats
                .iter()
                .min_by_key(|(_, s)| s.window_start)
                .map(|(k, _)| k.clone())
            {
                self.domain_tunnel_stats.remove(&oldest);
            }
        }

        // Track for tunnel detection
        let stats = self
            .domain_tunnel_stats
            .entry(base_domain)
            .or_insert_with(|| DomainStats {
                count: 0,
                max_qname_len: 0,
                unique_prefixes: HashSet::new(),
                window_start: now,
                last_alert: None,
            });
        stats.count += 1;
        if event.qname.len() > stats.max_qname_len {
            stats.max_qname_len = event.qname.len();
        }
        if let Some(prefix) = event.qname.split('.').next() {
            if stats.unique_prefixes.len() < 200 {
                stats.unique_prefixes.insert(prefix.to_string());
            }
        }

        // Check tunnel heuristics
        self.detect_dns_tunnel(&event, now);

        // Track outstanding for latency
        let key = DnsTxnKey {
            txid: event.txid,
            client_ip: event.client_ip,
            server_ip: event.server_ip,
        };
        self.outstanding_dns.insert(
            key,
            OutstandingDns {
                sent_at: now,
                qname: event.qname,
            },
        );
    }

    pub fn on_dns_response(&mut self, event: DnsResponseEvent) {
        let now = Instant::now();
        self.dns_total_responses += 1;

        if event.rcode == 3 {
            self.dns_nxdomain += 1;
        }

        let key = DnsTxnKey {
            txid: event.txid,
            client_ip: event.client_ip,
            server_ip: event.server_ip,
        };
        if let Some(outstanding) = self.outstanding_dns.remove(&key) {
            let latency = now.duration_since(outstanding.sent_at);
            let ms = latency.as_secs_f64() * 1000.0;
            let bucket = if ms < 5.0 {
                0
            } else if ms < 10.0 {
                1
            } else if ms < 25.0 {
                2
            } else if ms < 50.0 {
                3
            } else if ms < 100.0 {
                4
            } else if ms < 250.0 {
                5
            } else if ms < 500.0 {
                6
            } else {
                7
            };
            self.dns_latency_buckets[bucket] += 1;
        }
    }

    pub fn on_interface_rate(&mut self, event: InterfaceRateEvent) {
        let state = self
            .bw_states
            .entry(event.iface.clone())
            .or_insert_with(|| BwAlertState {
                consecutive_over: 0,
                active: false,
                threshold_rx: self.bw_default_threshold,
                threshold_tx: self.bw_default_threshold,
            });

        let over = event.rx_bps > state.threshold_rx || event.tx_bps > state.threshold_tx;
        if over {
            state.consecutive_over += 1;
            if state.consecutive_over >= BW_ALERT_CONSECUTIVE && !state.active {
                state.active = true;
                let msg = format!("{}: bandwidth threshold exceeded", event.iface);
                let detail = format!(
                    "RX: {}/s, TX: {}/s (threshold: {}/s)",
                    format_bytes(event.rx_bps),
                    format_bytes(event.tx_bps),
                    format_bytes(state.threshold_rx),
                );
                self.push_alert(
                    AlertSeverity::Warning,
                    AlertCategory::Bandwidth,
                    msg,
                    detail,
                );
            }
        } else {
            let clear_rx = (state.threshold_rx as f64 * BW_ALERT_CLEAR_RATIO) as u64;
            let clear_tx = (state.threshold_tx as f64 * BW_ALERT_CLEAR_RATIO) as u64;
            if event.rx_bps < clear_rx && event.tx_bps < clear_tx {
                state.consecutive_over = 0;
                state.active = false;
            }
        }
    }

    // ── Internal detection logic ───────────────────────────

    fn detect_port_scan(&mut self, event: &ConnAttemptEvent, now: Instant) {
        // At cap with a genuinely new key: evict the oldest-last_seen
        // entry rather than silently dropping the new one. Otherwise a
        // burst of 1k concurrent source IPs makes us blind to new
        // attackers until prune_stale's next sweep ~5 minutes later.
        if self.scan_states.len() >= MAX_TRACKED_IPS
            && !self.scan_states.contains_key(&event.src_ip)
        {
            if let Some(oldest_ip) = self
                .scan_states
                .iter()
                .min_by_key(|(_, s)| s.last_seen)
                .map(|(k, _)| k.clone())
            {
                self.scan_states.remove(&oldest_ip);
            }
        }

        let state = self
            .scan_states
            .entry(event.src_ip.clone())
            .or_insert_with(|| ScanState {
                window_start: now,
                last_seen: now,
                ports: HashSet::new(),
                alerted: false,
            });

        // Reset window if expired
        if now.duration_since(state.window_start) > Duration::from_secs(PORT_SCAN_WINDOW_SECS) {
            state.window_start = now;
            state.ports.clear();
            state.alerted = false;
        }

        state.last_seen = now;
        state.ports.insert(event.dst_port);

        if state.ports.len() >= PORT_SCAN_THRESHOLD && !state.alerted {
            state.alerted = true;
            let msg = format!("Port scan from {}", event.src_ip);
            let detail = format!(
                "{} → {} unique ports in {}s targeting {}",
                event.src_ip,
                state.ports.len(),
                PORT_SCAN_WINDOW_SECS,
                event.dst_ip,
            );
            self.push_alert(
                AlertSeverity::Critical,
                AlertCategory::PortScan,
                msg,
                detail,
            );
        }
    }

    /// Feed one timing sample for a `(src, dst, dst_port)` flow into the
    /// beacon detector. Called both from new-SYN connection attempts and
    /// from per-flow data bursts on already-established connections, so a
    /// single long-lived heartbeat C2 (no new SYNs) is still caught. The
    /// 5s–3600s delta filter coalesces the packets of one burst into a
    /// single sample and ignores continuous transfers (sub-5s deltas).
    fn detect_beacon(&mut self, key: BeaconKey, now: Instant) {
        // Same LRU-evict-on-overflow pattern as detect_port_scan. A
        // sufficiently noisy set of beaconing flows shouldn't lock us
        // out of detecting newer ones.
        if self.beacon_states.len() >= MAX_TRACKED_BEACONS && !self.beacon_states.contains_key(&key)
        {
            if let Some(oldest_key) = self
                .beacon_states
                .iter()
                .min_by_key(|(_, s)| s.last_seen)
                .map(|(k, _)| k.clone())
            {
                self.beacon_states.remove(&oldest_key);
            }
        }

        let state = self
            .beacon_states
            .entry(key.clone())
            .or_insert_with(|| BeaconState {
                last_seen: now,
                deltas: VecDeque::new(),
                last_alert: None,
            });

        let delta = now.duration_since(state.last_seen);
        state.last_seen = now;

        // Only track deltas in a reasonable range (5s to 1h)
        if delta.as_secs() >= 5 && delta.as_secs() <= 3600 {
            state.deltas.push_back(delta);
            if state.deltas.len() > BEACON_MAX_SAMPLES {
                state.deltas.pop_front();
            }
        }

        // Re-arm after a cooldown instead of firing once and going silent
        // forever. A live beacon that keeps ticking should resurface
        // periodically — the recorder may have been re-armed since — but
        // not on every interval. Mirrors the DNS-tunnel cooldown.
        let cooled_down = state.last_alert.is_none_or(|t| {
            now.duration_since(t) >= Duration::from_secs(BEACON_REALERT_COOLDOWN_SECS)
        });
        if state.deltas.len() >= BEACON_MIN_SAMPLES && cooled_down {
            let mean = state.deltas.iter().map(|d| d.as_secs_f64()).sum::<f64>()
                / state.deltas.len() as f64;
            let variance = state
                .deltas
                .iter()
                .map(|d| {
                    let diff = d.as_secs_f64() - mean;
                    diff * diff
                })
                .sum::<f64>()
                / state.deltas.len() as f64;
            let stddev = variance.sqrt();
            let jitter = if mean > 0.0 { stddev / mean } else { 1.0 };

            if jitter < BEACON_JITTER_THRESHOLD {
                state.last_alert = Some(now);
                let msg = format!(
                    "Beaconing: {} → {}",
                    key.src,
                    super::packets::format_endpoint(&key.dst, key.dst_port)
                );
                let detail = format!(
                    "Regular interval {:.1}s (jitter {:.1}%), {} samples",
                    mean,
                    jitter * 100.0,
                    state.deltas.len()
                );
                // Critical so the Flight Recorder auto-freezes on it — a
                // low-jitter periodic beacon is the canonical C2 signature
                // and is exactly the incident the recorder exists to capture.
                self.push_alert(
                    AlertSeverity::Critical,
                    AlertCategory::Beaconing,
                    msg,
                    detail,
                );
            }
        }
    }

    fn detect_dns_tunnel(&mut self, event: &DnsQueryEvent, now: Instant) {
        let base = extract_base_domain(&event.qname);

        // Per-base-domain cooldown. A live tunnel sprays thousands of
        // queries; without this gate each one would inject its own alert
        // and bury everything else in `active_alerts`/`alert_history`.
        // Suppress repeats for the same base domain inside the window.
        if let Some(stats) = self.domain_tunnel_stats.get(&base) {
            if let Some(last) = stats.last_alert {
                if now.duration_since(last) < Duration::from_secs(DNS_TUNNEL_ALERT_COOLDOWN_SECS) {
                    return;
                }
            }
        }

        // Evaluate both heuristics without holding a mutable borrow, so we
        // can update the cooldown and push the alert afterward.
        let alert = if event.qname.len() > DNS_TUNNEL_QNAME_LEN {
            // Check 1: very long qname.
            let msg = format!("Suspicious DNS: long query name ({}b)", event.qname.len());
            // A byte cap, so back off to a char boundary: a label may be any
            // UTF-8, and the `·` that replaces a control character is two bytes.
            let mut end = event.qname.len().min(120);
            while !event.qname.is_char_boundary(end) {
                end -= 1;
            }
            let detail = format!("Query: {}", &event.qname[..end]);
            Some((AlertSeverity::Warning, msg, detail))
        } else if let Some(stats) = self.domain_tunnel_stats.get(&base) {
            // Check 2: high rate + many unique subdomains to one base domain.
            let elapsed = now
                .duration_since(stats.window_start)
                .as_secs_f64()
                .max(1.0);
            let rate_per_min = stats.count as f64 / elapsed * 60.0;
            if rate_per_min > DNS_TUNNEL_QUERY_RATE as f64
                && stats.unique_prefixes.len() > DNS_TUNNEL_UNIQUE_SUBS
            {
                let msg = format!("DNS tunnel suspect: {}", base);
                let detail = format!(
                    "{:.0} queries/min, {} unique subdomains",
                    rate_per_min,
                    stats.unique_prefixes.len()
                );
                Some((AlertSeverity::Critical, msg, detail))
            } else {
                None
            }
        } else {
            None
        };

        if let Some((severity, msg, detail)) = alert {
            if let Some(stats) = self.domain_tunnel_stats.get_mut(&base) {
                stats.last_alert = Some(now);
            }
            self.push_alert(severity, AlertCategory::DnsTunnel, msg, detail);
        }
    }

    fn push_alert(
        &mut self,
        severity: AlertSeverity,
        category: AlertCategory,
        message: String,
        detail: String,
    ) {
        let alert = Alert {
            severity,
            category,
            message,
            detail,
            timestamp: Instant::now(),
        };
        self.active_alerts.push(alert.clone());
        self.alert_history.push_back(alert);
        if self.alert_history.len() > 100 {
            self.alert_history.pop_front();
        }
    }

    fn prune_stale(&mut self, now: Instant) {
        let stale = Duration::from_secs(STALE_ENTRY_SECS);
        self.scan_states
            .retain(|_, v| now.duration_since(v.last_seen) < stale);
        self.beacon_states
            .retain(|_, v| now.duration_since(v.last_seen) < stale);
        self.domain_tunnel_stats
            .retain(|_, v| now.duration_since(v.window_start) < stale);

        // Prune domain counts to top N
        if self.domain_counts.len() > MAX_TRACKED_DOMAINS * 2 {
            let mut entries: Vec<(String, u32)> = self.domain_counts.drain().collect();
            entries.sort_by_key(|b| std::cmp::Reverse(b.1));
            entries.truncate(MAX_TRACKED_DOMAINS);
            self.domain_counts = entries.into_iter().collect();
        }
    }
}

// ── Helpers ────────────────────────────────────────────────

/// Common two-label public suffixes. Not a full Public Suffix List (that
/// would mean a data file + dependency), but enough that `a.example.co.uk`
/// buckets as `example.co.uk` rather than collapsing every `*.co.uk` domain
/// into one `co.uk` bucket — which would smear unrelated domains together
/// and skew the DNS-tunnel heuristics.
const MULTI_LABEL_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "co.jp", "or.jp", "ne.jp", "com.au", "net.au",
    "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "co.za", "com.br", "com.cn", "com.mx",
    "co.in", "co.kr", "com.sg", "com.tr", "co.il", "com.hk", "com.tw",
];

fn extract_base_domain(qname: &str) -> String {
    let parts: Vec<&str> = qname.trim_end_matches('.').split('.').collect();
    if parts.len() < 2 {
        return qname.to_string();
    }
    let last_two = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
    // If the final two labels form a known multi-label suffix and a third
    // label exists, keep that third label so the registrable domain — not
    // the public suffix — becomes the bucket key.
    if parts.len() >= 3 && MULTI_LABEL_SUFFIXES.contains(&last_two.as_str()) {
        return format!("{}.{}", parts[parts.len() - 3], last_two);
    }
    last_two
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.1} GB", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_base_domain() {
        assert_eq!(extract_base_domain("www.example.com"), "example.com");
        // Multi-label public suffix: keep the registrable label, don't
        // collapse to the bare suffix.
        assert_eq!(
            extract_base_domain("sub.deep.example.co.uk"),
            "example.co.uk"
        );
        assert_eq!(extract_base_domain("example.com.au"), "example.com.au");
        assert_eq!(extract_base_domain("localhost"), "localhost");
        assert_eq!(extract_base_domain("a.b.c.d.example.com."), "example.com");
    }

    #[test]
    fn test_port_scan_detection() {
        let mut intel = NetworkIntelCollector::new();
        for port in 1..=25 {
            intel.on_conn_attempt(ConnAttemptEvent {
                src_ip: "192.168.1.100".into(),
                dst_ip: "10.0.0.1".into(),
                dst_port: port,
            });
        }
        assert_eq!(intel.active_alerts.len(), 1);
        assert!(matches!(
            intel.active_alerts[0].category,
            AlertCategory::PortScan
        ));
    }

    #[test]
    fn test_no_port_scan_under_threshold() {
        let mut intel = NetworkIntelCollector::new();
        for port in 1..=10 {
            intel.on_conn_attempt(ConnAttemptEvent {
                src_ip: "192.168.1.100".into(),
                dst_ip: "10.0.0.1".into(),
                dst_port: port,
            });
        }
        assert!(intel.active_alerts.is_empty());
    }

    #[test]
    fn test_dns_long_qname_alert() {
        let mut intel = NetworkIntelCollector::new();
        let long_name = "a".repeat(90) + ".example.com";
        intel.on_dns_query(DnsQueryEvent {
            txid: 1,
            client_ip: "192.168.1.1".into(),
            server_ip: "8.8.8.8".into(),
            qname: long_name,
        });
        assert_eq!(intel.active_alerts.len(), 1);
        assert!(matches!(
            intel.active_alerts[0].category,
            AlertCategory::DnsTunnel
        ));
    }

    /// A qname whose 120th byte falls inside a multi-byte character, here the
    /// `·` that ingest put in place of an ESC, used to panic the UI thread.
    #[test]
    fn long_qname_alert_cuts_on_a_char_boundary() {
        let mut intel = NetworkIntelCollector::new();
        let prefix = "a".repeat(119);
        intel.on_dns_query(DnsQueryEvent {
            txid: 1,
            client_ip: "192.168.1.1".into(),
            server_ip: "8.8.8.8".into(),
            qname: format!("{prefix}{}.example.com", crate::ui::sanitize::REPLACEMENT),
        });
        assert_eq!(intel.active_alerts[0].detail, format!("Query: {prefix}"));
    }

    #[test]
    fn test_dns_latency_tracking() {
        let mut intel = NetworkIntelCollector::new();
        intel.on_dns_query(DnsQueryEvent {
            txid: 42,
            client_ip: "192.168.1.1".into(),
            server_ip: "8.8.8.8".into(),
            qname: "example.com".into(),
        });
        // Simulate small delay
        std::thread::sleep(Duration::from_millis(2));
        intel.on_dns_response(DnsResponseEvent {
            txid: 42,
            client_ip: "192.168.1.1".into(),
            server_ip: "8.8.8.8".into(),
            rcode: 0,
        });
        let analytics = intel.dns_analytics();
        assert_eq!(analytics.total_queries, 1);
        assert_eq!(analytics.total_responses, 1);
        assert_eq!(analytics.nxdomain_count, 0);
        // Should land in some latency bucket
        assert!(analytics.latency_buckets.iter().sum::<u64>() > 0);
    }

    #[test]
    fn test_dns_nxdomain_counting() {
        let mut intel = NetworkIntelCollector::new();
        intel.on_dns_response(DnsResponseEvent {
            txid: 1,
            client_ip: "192.168.1.1".into(),
            server_ip: "8.8.8.8".into(),
            rcode: 3,
        });
        intel.on_dns_response(DnsResponseEvent {
            txid: 2,
            client_ip: "192.168.1.1".into(),
            server_ip: "8.8.8.8".into(),
            rcode: 0,
        });
        let analytics = intel.dns_analytics();
        assert_eq!(analytics.nxdomain_count, 1);
        assert_eq!(analytics.total_responses, 2);
    }

    #[test]
    fn test_bandwidth_alert() {
        let mut intel = NetworkIntelCollector::new();
        // Default threshold is 100MB/s
        for _ in 0..3 {
            intel.on_interface_rate(InterfaceRateEvent {
                iface: "eth0".into(),
                rx_bps: 200_000_000,
                tx_bps: 0,
            });
        }
        assert_eq!(intel.active_alerts.len(), 1);
        assert!(matches!(
            intel.active_alerts[0].category,
            AlertCategory::Bandwidth
        ));
    }

    #[test]
    fn test_top_domains() {
        let mut intel = NetworkIntelCollector::new();
        for _ in 0..10 {
            intel.on_dns_query(DnsQueryEvent {
                txid: 1,
                client_ip: "1.1.1.1".into(),
                server_ip: "8.8.8.8".into(),
                qname: "www.example.com".into(),
            });
        }
        for _ in 0..5 {
            intel.on_dns_query(DnsQueryEvent {
                txid: 2,
                client_ip: "1.1.1.1".into(),
                server_ip: "8.8.8.8".into(),
                qname: "api.google.com".into(),
            });
        }
        let analytics = intel.dns_analytics();
        assert_eq!(analytics.top_domains[0].0, "example.com");
        assert_eq!(analytics.top_domains[0].1, 10);
    }

    // ── Memory-cap stress tests ─────────────────────────────────────────

    #[test]
    fn scan_states_evicts_oldest_at_cap_instead_of_silent_drop() {
        // Fill scan_states to MAX_TRACKED_IPS with synthetic source IPs.
        // Then send one more event from a brand-new IP and verify it
        // gets tracked (not silently dropped) by evicting the oldest.
        let mut intel = NetworkIntelCollector::new();
        for i in 0..MAX_TRACKED_IPS {
            intel.on_conn_attempt(ConnAttemptEvent {
                src_ip: format!("10.0.{}.{}", i / 256, i % 256),
                dst_ip: "1.1.1.1".into(),
                dst_port: 80,
            });
        }
        assert_eq!(intel.scan_states.len(), MAX_TRACKED_IPS);

        // The very first inserted IP becomes the LRU victim.
        let victim = "10.0.0.0".to_string();
        let newcomer = "192.0.2.99".to_string();
        assert!(intel.scan_states.contains_key(&victim));
        assert!(!intel.scan_states.contains_key(&newcomer));

        intel.on_conn_attempt(ConnAttemptEvent {
            src_ip: newcomer.clone(),
            dst_ip: "1.1.1.1".into(),
            dst_port: 80,
        });

        assert!(
            intel.scan_states.contains_key(&newcomer),
            "newcomer must be inserted via LRU eviction"
        );
        assert_eq!(
            intel.scan_states.len(),
            MAX_TRACKED_IPS,
            "cap holds — count stays at MAX_TRACKED_IPS"
        );
    }

    #[test]
    fn beacon_states_evicts_oldest_at_cap() {
        let mut intel = NetworkIntelCollector::new();
        for i in 0..MAX_TRACKED_BEACONS {
            intel.on_conn_attempt(ConnAttemptEvent {
                src_ip: format!("10.1.{}.{}", i / 256, i % 256),
                dst_ip: "8.8.8.8".into(),
                dst_port: 53,
            });
        }
        assert_eq!(intel.beacon_states.len(), MAX_TRACKED_BEACONS);

        let newcomer_src = "192.0.2.42".to_string();
        intel.on_conn_attempt(ConnAttemptEvent {
            src_ip: newcomer_src.clone(),
            dst_ip: "8.8.8.8".into(),
            dst_port: 53,
        });
        assert!(intel
            .beacon_states
            .keys()
            .any(|k| k.src == newcomer_src && k.dst_port == 53));
        assert_eq!(intel.beacon_states.len(), MAX_TRACKED_BEACONS);
    }

    #[test]
    fn persistent_flow_beacon_fires_critical() {
        // H2: a single long-lived connection that heartbeats on a fixed
        // interval emits no new SYNs, so it reaches the beacon detector
        // only through the flow-activity path. Drive `detect_beacon`
        // directly with synthetic timestamps (the public entry points use
        // a real clock) to exercise the shared jitter analysis.
        let mut intel = NetworkIntelCollector::new();
        let key = BeaconKey {
            src: "192.168.1.50".into(),
            dst: "203.0.113.9".into(),
            dst_port: 443,
        };
        let base = Instant::now();
        // 6 bursts exactly 60s apart → 5 deltas, zero jitter.
        for i in 0..6 {
            intel.detect_beacon(key.clone(), base + Duration::from_secs(60 * i));
        }
        assert_eq!(intel.active_alerts.len(), 1, "one beacon alert expected");
        assert!(matches!(
            intel.active_alerts[0].category,
            AlertCategory::Beaconing
        ));
        assert!(
            matches!(intel.active_alerts[0].severity, AlertSeverity::Critical),
            "beacon must be Critical so the recorder auto-freezes"
        );
    }

    /// The alert names an IPv6 peer `[addr]:port`. Bare, `2001:db8::5:443`
    /// in an incident's alerts.json would read as the host 2001:db8::5:443.
    #[test]
    fn an_ipv6_beacon_alert_brackets_the_peer() {
        let mut intel = NetworkIntelCollector::new();
        let key = BeaconKey {
            src: "2001:db8::10".into(),
            dst: "2001:db8::5".into(),
            dst_port: 443,
        };
        let base = Instant::now();
        for i in 0..6 {
            intel.detect_beacon(key.clone(), base + Duration::from_secs(60 * i));
        }
        assert_eq!(
            intel.active_alerts[0].message,
            "Beaconing: 2001:db8::10 → [2001:db8::5]:443"
        );
    }

    #[test]
    fn beacon_re_alerts_after_cooldown() {
        // A persistent beacon must resurface periodically, not fire once and
        // go silent forever. First alert at the 6th sample; after the
        // cooldown elapses, a continuing beacon alerts again.
        let mut intel = NetworkIntelCollector::new();
        let key = BeaconKey {
            src: "192.168.1.50".into(),
            dst: "203.0.113.9".into(),
            dst_port: 443,
        };
        // Beacon continuously every 60s. First alert lands at the 6th
        // sample (t=300s). Re-alert is gated by the cooldown, so it fires
        // again once `now - last_alert >= cooldown` while jitter stays low.
        let base = Instant::now();
        let realert_at = 5 + BEACON_REALERT_COOLDOWN_SECS / 60; // sample index
        for i in 0..6 {
            intel.detect_beacon(key.clone(), base + Duration::from_secs(60 * i));
        }
        assert_eq!(intel.active_alerts.len(), 1, "first beacon alert");

        for i in 6..=realert_at {
            intel.detect_beacon(key.clone(), base + Duration::from_secs(60 * i));
        }
        assert_eq!(
            intel.active_alerts.len(),
            2,
            "beacon should re-alert once the cooldown has passed"
        );
    }

    #[test]
    fn dns_tunnel_alerts_are_deduped_per_domain() {
        // H6: a live tunnel sprays thousands of queries; without the
        // per-domain cooldown each long-qname query would inject its own
        // alert. A flood to one base domain must collapse to one alert.
        let mut intel = NetworkIntelCollector::new();
        for i in 0..500 {
            let qname = format!("{}{}.tunnel.example.com", "a".repeat(90), i);
            intel.on_dns_query(DnsQueryEvent {
                txid: i as u16,
                client_ip: "192.168.1.1".into(),
                server_ip: "8.8.8.8".into(),
                qname,
            });
        }
        assert_eq!(
            intel.active_alerts.len(),
            1,
            "500 tunneled queries to one domain must collapse to a single alert"
        );
        assert!(matches!(
            intel.active_alerts[0].category,
            AlertCategory::DnsTunnel
        ));
    }

    #[test]
    fn scan_states_never_exceeds_cap_under_sustained_load() {
        // Simulate a botnet: 5× MAX_TRACKED_IPS distinct attackers in
        // tight succession. The collector should stay bounded the
        // entire time, not just at the end.
        let mut intel = NetworkIntelCollector::new();
        for i in 0..(MAX_TRACKED_IPS * 5) {
            intel.on_conn_attempt(ConnAttemptEvent {
                src_ip: format!("203.0.113.{}.{}", i / 256, i),
                dst_ip: "1.1.1.1".into(),
                dst_port: (i as u16 % 65534) + 1,
            });
            assert!(
                intel.scan_states.len() <= MAX_TRACKED_IPS,
                "scan_states grew past cap at iteration {}",
                i
            );
        }
    }
}
