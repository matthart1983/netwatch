use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

// ── Configuration defaults ─────────────────────────────────

const PORT_SCAN_WINDOW_SECS: u64 = 30;
const PORT_SCAN_THRESHOLD: usize = 20;
const BEACON_MIN_SAMPLES: usize = 5;
const BEACON_MAX_SAMPLES: usize = 8;
const BEACON_JITTER_THRESHOLD: f64 = 0.15;
const DNS_TUNNEL_QNAME_LEN: usize = 80;
const DNS_TUNNEL_QUERY_RATE: u32 = 50; // per minute per base domain
const DNS_TUNNEL_UNIQUE_SUBS: usize = 30;
const DNS_OUTSTANDING_TIMEOUT_SECS: u64 = 5;
const STALE_ENTRY_SECS: u64 = 300;
const MAX_TRACKED_IPS: usize = 1000;
const MAX_TRACKED_DOMAINS: usize = 500;
const MAX_TRACKED_BEACONS: usize = 500;
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
}

impl AlertCategory {
    pub fn label(&self) -> &'static str {
        match self {
            Self::PortScan => "Port Scan",
            Self::Beaconing => "Beaconing",
            Self::DnsTunnel => "DNS Tunnel",
            Self::Bandwidth => "Bandwidth",
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
    alerted: bool,
}

// ── DNS analytics state ────────────────────────────────────

#[derive(Clone, Debug)]
pub struct DnsAnalytics {
    pub total_queries: u64,
    pub total_responses: u64,
    pub nxdomain_count: u64,
    pub latency_buckets: [u64; 8], // <5ms, <10ms, <25ms, <50ms, <100ms, <250ms, <500ms, >=500ms
    pub top_domains: Vec<(String, u32)>,
}

impl Default for DnsAnalytics {
    fn default() -> Self {
        Self {
            total_queries: 0,
            total_responses: 0,
            nxdomain_count: 0,
            latency_buckets: [0; 8],
            top_domains: Vec::new(),
        }
    }
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
        self.txid == other.txid && self.client_ip == other.client_ip && self.server_ip == other.server_ip
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

    pub fn dns_analytics(&self) -> DnsAnalytics {
        let mut top: Vec<(String, u32)> = self.domain_counts.iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        top.sort_by(|a, b| b.1.cmp(&a.1));
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
        self.active_alerts.retain(|a| now.duration_since(a.timestamp) < Duration::from_secs(60));
    }

    // ── Event handlers ─────────────────────────────────────

    pub fn on_conn_attempt(&mut self, event: ConnAttemptEvent) {
        let now = Instant::now();
        self.detect_port_scan(&event, now);
        self.detect_beacon(&event, now);
    }

    pub fn on_dns_query(&mut self, event: DnsQueryEvent) {
        let now = Instant::now();
        self.dns_total_queries += 1;

        // Track domain counts
        let base_domain = extract_base_domain(&event.qname);
        *self.domain_counts.entry(base_domain.clone()).or_insert(0) += 1;

        // Track for tunnel detection
        let stats = self.domain_tunnel_stats.entry(base_domain).or_insert_with(|| DomainStats {
            count: 0,
            max_qname_len: 0,
            unique_prefixes: HashSet::new(),
            window_start: now,
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
        self.outstanding_dns.insert(key, OutstandingDns {
            sent_at: now,
            qname: event.qname,
        });
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
            let bucket = if ms < 5.0 { 0 }
                else if ms < 10.0 { 1 }
                else if ms < 25.0 { 2 }
                else if ms < 50.0 { 3 }
                else if ms < 100.0 { 4 }
                else if ms < 250.0 { 5 }
                else if ms < 500.0 { 6 }
                else { 7 };
            self.dns_latency_buckets[bucket] += 1;
        }
    }

    pub fn on_interface_rate(&mut self, event: InterfaceRateEvent) {
        let state = self.bw_states.entry(event.iface.clone()).or_insert_with(|| BwAlertState {
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
                self.push_alert(AlertSeverity::Warning, AlertCategory::Bandwidth, msg, detail);
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
        if self.scan_states.len() >= MAX_TRACKED_IPS && !self.scan_states.contains_key(&event.src_ip) {
            return;
        }

        let state = self.scan_states.entry(event.src_ip.clone()).or_insert_with(|| ScanState {
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
            self.push_alert(AlertSeverity::Critical, AlertCategory::PortScan, msg, detail);
        }
    }

    fn detect_beacon(&mut self, event: &ConnAttemptEvent, now: Instant) {
        let key = BeaconKey {
            src: event.src_ip.clone(),
            dst: event.dst_ip.clone(),
            dst_port: event.dst_port,
        };

        if self.beacon_states.len() >= MAX_TRACKED_BEACONS && !self.beacon_states.contains_key(&key) {
            return;
        }

        let state = self.beacon_states.entry(key.clone()).or_insert_with(|| BeaconState {
            last_seen: now,
            deltas: VecDeque::new(),
            alerted: false,
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

        if state.deltas.len() >= BEACON_MIN_SAMPLES && !state.alerted {
            let mean = state.deltas.iter().map(|d| d.as_secs_f64()).sum::<f64>() / state.deltas.len() as f64;
            let variance = state.deltas.iter()
                .map(|d| {
                    let diff = d.as_secs_f64() - mean;
                    diff * diff
                })
                .sum::<f64>() / state.deltas.len() as f64;
            let stddev = variance.sqrt();
            let jitter = if mean > 0.0 { stddev / mean } else { 1.0 };

            if jitter < BEACON_JITTER_THRESHOLD {
                state.alerted = true;
                let msg = format!("Beaconing: {} → {}:{}", key.src, key.dst, key.dst_port);
                let detail = format!(
                    "Regular interval {:.1}s (jitter {:.1}%), {} samples",
                    mean, jitter * 100.0, state.deltas.len()
                );
                self.push_alert(AlertSeverity::Warning, AlertCategory::Beaconing, msg, detail);
            }
        }
    }

    fn detect_dns_tunnel(&mut self, event: &DnsQueryEvent, now: Instant) {
        // Check 1: very long qname
        if event.qname.len() > DNS_TUNNEL_QNAME_LEN {
            let msg = format!("Suspicious DNS: long query name ({}b)", event.qname.len());
            let detail = format!("Query: {}", &event.qname[..event.qname.len().min(120)]);
            self.push_alert(AlertSeverity::Warning, AlertCategory::DnsTunnel, msg, detail);
            return;
        }

        // Check 2: high rate + many unique subdomains to one base domain
        let base = extract_base_domain(&event.qname);
        if let Some(stats) = self.domain_tunnel_stats.get(&base) {
            let elapsed = now.duration_since(stats.window_start).as_secs_f64().max(1.0);
            let rate_per_min = stats.count as f64 / elapsed * 60.0;

            if rate_per_min > DNS_TUNNEL_QUERY_RATE as f64
                && stats.unique_prefixes.len() > DNS_TUNNEL_UNIQUE_SUBS
            {
                let msg = format!("DNS tunnel suspect: {}", base);
                let detail = format!(
                    "{:.0} queries/min, {} unique subdomains",
                    rate_per_min, stats.unique_prefixes.len()
                );
                self.push_alert(AlertSeverity::Critical, AlertCategory::DnsTunnel, msg, detail);
            }
        }
    }

    fn push_alert(&mut self, severity: AlertSeverity, category: AlertCategory, message: String, detail: String) {
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
        self.scan_states.retain(|_, v| now.duration_since(v.last_seen) < stale);
        self.beacon_states.retain(|_, v| now.duration_since(v.last_seen) < stale);
        self.domain_tunnel_stats.retain(|_, v| now.duration_since(v.window_start) < stale);

        // Prune domain counts to top N
        if self.domain_counts.len() > MAX_TRACKED_DOMAINS * 2 {
            let mut entries: Vec<(String, u32)> = self.domain_counts.drain().collect();
            entries.sort_by(|a, b| b.1.cmp(&a.1));
            entries.truncate(MAX_TRACKED_DOMAINS);
            self.domain_counts = entries.into_iter().collect();
        }
    }
}

// ── Helpers ────────────────────────────────────────────────

fn extract_base_domain(qname: &str) -> String {
    let parts: Vec<&str> = qname.trim_end_matches('.').split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        qname.to_string()
    }
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
        assert_eq!(extract_base_domain("sub.deep.example.co.uk"), "co.uk");
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
        assert!(matches!(intel.active_alerts[0].category, AlertCategory::PortScan));
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
        assert!(matches!(intel.active_alerts[0].category, AlertCategory::DnsTunnel));
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
        // Should be in first bucket (<5ms)
        assert!(analytics.latency_buckets[0] > 0);
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
        assert!(matches!(intel.active_alerts[0].category, AlertCategory::Bandwidth));
    }

    #[test]
    fn test_top_domains() {
        let mut intel = NetworkIntelCollector::new();
        for _ in 0..10 {
            intel.on_dns_query(DnsQueryEvent {
                txid: 1, client_ip: "1.1.1.1".into(), server_ip: "8.8.8.8".into(),
                qname: "www.example.com".into(),
            });
        }
        for _ in 0..5 {
            intel.on_dns_query(DnsQueryEvent {
                txid: 2, client_ip: "1.1.1.1".into(), server_ip: "8.8.8.8".into(),
                qname: "api.google.com".into(),
            });
        }
        let analytics = intel.dns_analytics();
        assert_eq!(analytics.top_domains[0].0, "example.com");
        assert_eq!(analytics.top_domains[0].1, 10);
    }
}
