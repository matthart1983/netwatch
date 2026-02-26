use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::collectors::connections::Connection;
use crate::collectors::health::HealthStatus;
use crate::collectors::packets::{CapturedPacket, ExpertSeverity};

const ANALYSIS_INTERVAL: Duration = Duration::from_secs(15);
const OLLAMA_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct Insight {
    pub timestamp: String,
    pub text: String,
}

#[derive(Clone, Debug)]
pub struct NetworkSnapshot {
    pub total_packets: usize,
    pub protocol_counts: HashMap<String, usize>,
    pub top_talkers: Vec<(String, usize)>,
    pub dns_queries: Vec<String>,
    pub expert_errors: Vec<String>,
    pub expert_warnings: Vec<String>,
    pub connections_established: usize,
    pub connections_other: usize,
    pub gateway_rtt_ms: Option<f64>,
    pub gateway_loss_pct: f64,
    pub dns_rtt_ms: Option<f64>,
    pub dns_loss_pct: f64,
    pub bandwidth_rx: String,
    pub bandwidth_tx: String,
}

impl NetworkSnapshot {
    pub fn build(
        packets: &[CapturedPacket],
        connections: &[Connection],
        health: &HealthStatus,
        rx_rate: &str,
        tx_rate: &str,
    ) -> Self {
        let total_packets = packets.len();

        let mut protocol_counts: HashMap<String, usize> = HashMap::new();
        let mut dst_counts: HashMap<String, usize> = HashMap::new();
        let mut dns_queries: Vec<String> = Vec::new();
        let mut expert_errors: Vec<String> = Vec::new();
        let mut expert_warnings: Vec<String> = Vec::new();

        // Only analyze the last 500 packets for performance
        let recent = if packets.len() > 500 {
            &packets[packets.len() - 500..]
        } else {
            packets
        };

        for pkt in recent {
            *protocol_counts.entry(pkt.protocol.clone()).or_insert(0) += 1;

            if !pkt.dst_ip.is_empty() {
                *dst_counts.entry(pkt.dst_ip.clone()).or_insert(0) += 1;
            }

            if pkt.protocol == "DNS" && pkt.info.contains("Standard query") && !pkt.info.contains("response") {
                if let Some(domain) = pkt.info.split_whitespace().last() {
                    if !dns_queries.contains(&domain.to_string()) && dns_queries.len() < 20 {
                        dns_queries.push(domain.to_string());
                    }
                }
            }

            match pkt.expert {
                ExpertSeverity::Error => {
                    if expert_errors.len() < 10 {
                        expert_errors.push(format!("{} {} → {} {}", pkt.protocol, pkt.src_ip, pkt.dst_ip, pkt.info));
                    }
                }
                ExpertSeverity::Warn => {
                    if expert_warnings.len() < 10 {
                        expert_warnings.push(format!("{} {} → {} {}", pkt.protocol, pkt.src_ip, pkt.dst_ip, pkt.info));
                    }
                }
                _ => {}
            }
        }

        let mut top_talkers: Vec<(String, usize)> = dst_counts.into_iter().collect();
        top_talkers.sort_by(|a, b| b.1.cmp(&a.1));
        top_talkers.truncate(10);

        let connections_established = connections.iter().filter(|c| c.state == "ESTABLISHED").count();
        let connections_other = connections.len() - connections_established;

        NetworkSnapshot {
            total_packets,
            protocol_counts,
            top_talkers,
            dns_queries,
            expert_errors,
            expert_warnings,
            connections_established,
            connections_other,
            gateway_rtt_ms: health.gateway_rtt_ms,
            gateway_loss_pct: health.gateway_loss_pct,
            dns_rtt_ms: health.dns_rtt_ms,
            dns_loss_pct: health.dns_loss_pct,
            bandwidth_rx: rx_rate.to_string(),
            bandwidth_tx: tx_rate.to_string(),
        }
    }

    fn to_prompt(&self) -> String {
        let mut parts = Vec::new();

        parts.push(format!("Total packets captured: {}", self.total_packets));

        if !self.protocol_counts.is_empty() {
            let mut protos: Vec<_> = self.protocol_counts.iter().collect();
            protos.sort_by(|a, b| b.1.cmp(a.1));
            let proto_str: Vec<String> = protos.iter().map(|(k, v)| format!("{}: {}", k, v)).collect();
            parts.push(format!("Protocol distribution: {}", proto_str.join(", ")));
        }

        parts.push(format!("Bandwidth: RX {} / TX {}", self.bandwidth_rx, self.bandwidth_tx));

        if !self.top_talkers.is_empty() {
            let talkers: Vec<String> = self.top_talkers.iter()
                .take(5)
                .map(|(ip, count)| format!("{} ({} pkts)", ip, count))
                .collect();
            parts.push(format!("Top destinations: {}", talkers.join(", ")));
        }

        parts.push(format!("Active connections: {} established, {} other", self.connections_established, self.connections_other));

        if let Some(gw_rtt) = self.gateway_rtt_ms {
            parts.push(format!("Gateway: {:.1}ms RTT, {:.0}% loss", gw_rtt, self.gateway_loss_pct));
        }
        if let Some(dns_rtt) = self.dns_rtt_ms {
            parts.push(format!("DNS: {:.1}ms RTT, {:.0}% loss", dns_rtt, self.dns_loss_pct));
        }

        if !self.dns_queries.is_empty() {
            parts.push(format!("Recent DNS lookups: {}", self.dns_queries.join(", ")));
        }

        if !self.expert_errors.is_empty() {
            parts.push(format!("Errors detected:\n  {}", self.expert_errors.join("\n  ")));
        }

        if !self.expert_warnings.is_empty() {
            parts.push(format!("Warnings:\n  {}", self.expert_warnings.join("\n  ")));
        }

        parts.join("\n")
    }
}

pub struct InsightsCollector {
    pub insights: Arc<Mutex<Vec<Insight>>>,
    pub status: Arc<Mutex<InsightsStatus>>,
    snapshot_tx: std::sync::mpsc::Sender<NetworkSnapshot>,
    pub model: String,
}

#[derive(Clone, Debug)]
pub enum InsightsStatus {
    Idle,
    Analyzing,
    Available,
    Error(String),
    OllamaUnavailable,
}

const SYSTEM_PROMPT: &str = r#"You are a network security and performance analyst embedded in a real-time network monitoring TUI called NetWatch. You receive periodic snapshots of network activity.

Your job is to provide concise, actionable analysis. Focus on:
- Security concerns (unusual destinations, unencrypted sensitive traffic, port scans, suspicious patterns)
- Performance issues (high latency, packet loss, retransmissions, bandwidth hogs)
- Anomalies (unexpected protocols, unusual traffic patterns, DNS issues)
- Connection health (failed connections, RST floods, SYN storms)

Rules:
- Be concise — 3-6 bullet points max
- Lead each bullet with an emoji: 🔴 critical, 🟡 warning, 🟢 healthy, 🔵 info
- Skip obvious/normal observations — only report what's noteworthy
- If everything looks normal, say so briefly
- Never recommend installing other tools — the user is already using NetWatch
- Use plain language, avoid jargon where possible"#;

impl InsightsCollector {
    pub fn new(model: &str) -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<NetworkSnapshot>();
        let insights: Arc<Mutex<Vec<Insight>>> = Arc::new(Mutex::new(Vec::new()));
        let status: Arc<Mutex<InsightsStatus>> = Arc::new(Mutex::new(InsightsStatus::Idle));

        let insights_clone = Arc::clone(&insights);
        let status_clone = Arc::clone(&status);
        let model_clone = model.to_string();

        thread::spawn(move || {
            analysis_loop(rx, insights_clone, status_clone, &model_clone);
        });

        Self {
            insights,
            status,
            snapshot_tx: tx,
            model: model.to_string(),
        }
    }

    pub fn submit_snapshot(&self, snapshot: NetworkSnapshot) {
        let _ = self.snapshot_tx.send(snapshot);
    }

    pub fn get_insights(&self) -> Vec<Insight> {
        self.insights.lock().unwrap().clone()
    }

    pub fn get_status(&self) -> InsightsStatus {
        self.status.lock().unwrap().clone()
    }
}

fn analysis_loop(
    rx: std::sync::mpsc::Receiver<NetworkSnapshot>,
    insights: Arc<Mutex<Vec<Insight>>>,
    status: Arc<Mutex<InsightsStatus>>,
    model: &str,
) {
    let mut last_analysis = Instant::now() - ANALYSIS_INTERVAL;

    loop {
        // Drain to get the latest snapshot, waiting up to 1s
        let snapshot = match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(snap) => {
                // Drain any additional queued snapshots to get the freshest one
                let mut latest = snap;
                while let Ok(newer) = rx.try_recv() {
                    latest = newer;
                }
                Some(latest)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
        };

        let snapshot = match snapshot {
            Some(s) => s,
            None => continue,
        };

        // Rate limit
        if last_analysis.elapsed() < ANALYSIS_INTERVAL {
            continue;
        }

        if snapshot.total_packets == 0 {
            continue;
        }

        *status.lock().unwrap() = InsightsStatus::Analyzing;

        let prompt = snapshot.to_prompt();
        match call_ollama(model, &prompt) {
            Ok(response) => {
                let timestamp = chrono::Local::now().format("%H:%M:%S").to_string();
                let mut ins = insights.lock().unwrap();
                ins.push(Insight {
                    timestamp,
                    text: response,
                });
                // Keep last 20 insights
                if ins.len() > 20 {
                    ins.remove(0);
                }
                *status.lock().unwrap() = InsightsStatus::Available;
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("Connection refused") || msg.contains("connection refused") {
                    *status.lock().unwrap() = InsightsStatus::OllamaUnavailable;
                } else {
                    *status.lock().unwrap() = InsightsStatus::Error(msg);
                }
            }
        }

        last_analysis = Instant::now();
    }
}

fn call_ollama(model: &str, prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    let body = serde_json::json!({
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ],
        "stream": false,
        "options": {
            "temperature": 0.3,
            "num_predict": 512
        }
    });

    let resp = ureq::post("http://localhost:11434/api/chat")
        .timeout(OLLAMA_TIMEOUT)
        .send_string(&body.to_string())?;

    let body_str = resp.into_string()?;
    let json: serde_json::Value = serde_json::from_str(&body_str)?;
    let content = json["message"]["content"]
        .as_str()
        .unwrap_or("No response from model")
        .to_string();

    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::connections::Connection;
    use crate::collectors::health::HealthStatus;
    use crate::collectors::packets::{CapturedPacket, ExpertSeverity};
    use std::collections::VecDeque;

    fn make_health() -> HealthStatus {
        HealthStatus {
            gateway_rtt_ms: Some(5.0),
            gateway_loss_pct: 0.0,
            dns_rtt_ms: Some(10.0),
            dns_loss_pct: 0.0,
            gateway_rtt_history: VecDeque::new(),
            dns_rtt_history: VecDeque::new(),
        }
    }

    fn make_packet(proto: &str, src: &str, dst: &str, info: &str, expert: ExpertSeverity) -> CapturedPacket {
        CapturedPacket {
            id: 1,
            timestamp: "00:00:00.000".into(),
            src_ip: src.into(),
            dst_ip: dst.into(),
            src_host: None,
            dst_host: None,
            protocol: proto.into(),
            length: 100,
            src_port: None,
            dst_port: None,
            info: info.into(),
            details: vec![],
            payload_text: String::new(),
            raw_hex: String::new(),
            raw_ascii: String::new(),
            raw_bytes: vec![],
            stream_index: None,
            tcp_flags: None,
            expert,
            timestamp_ns: 0,
        }
    }

    fn make_conn(state: &str) -> Connection {
        Connection {
            protocol: "TCP".into(),
            local_addr: "127.0.0.1:1234".into(),
            remote_addr: "8.8.8.8:443".into(),
            state: state.into(),
            pid: None,
            process_name: None,
        }
    }

    #[test]
    fn empty_snapshot() {
        let snap = NetworkSnapshot::build(&[], &[], &make_health(), "0 B/s", "0 B/s");
        assert_eq!(snap.total_packets, 0);
        assert!(snap.protocol_counts.is_empty());
        assert!(snap.top_talkers.is_empty());
        assert!(snap.dns_queries.is_empty());
        assert!(snap.expert_errors.is_empty());
        assert!(snap.expert_warnings.is_empty());
        assert_eq!(snap.connections_established, 0);
        assert_eq!(snap.connections_other, 0);
    }

    #[test]
    fn protocol_counting() {
        let packets: Vec<CapturedPacket> = (0..3)
            .map(|_| make_packet("TCP", "10.0.0.1", "10.0.0.2", "", ExpertSeverity::Chat))
            .chain((0..2).map(|_| make_packet("DNS", "10.0.0.1", "8.8.8.8", "", ExpertSeverity::Chat)))
            .collect();

        let snap = NetworkSnapshot::build(&packets, &[], &make_health(), "0 B/s", "0 B/s");
        assert_eq!(snap.protocol_counts.get("TCP"), Some(&3));
        assert_eq!(snap.protocol_counts.get("DNS"), Some(&2));
        assert_eq!(snap.total_packets, 5);
    }

    #[test]
    fn top_talkers_sorted_and_truncated() {
        // Create 12 distinct destinations with varying counts
        let mut packets = Vec::new();
        for i in 0..12 {
            let dst = format!("10.0.0.{}", i);
            let count = (i + 1) as usize; // 1, 2, 3, ... 12
            for _ in 0..count {
                packets.push(make_packet("TCP", "192.168.1.1", &dst, "", ExpertSeverity::Chat));
            }
        }

        let snap = NetworkSnapshot::build(&packets, &[], &make_health(), "0 B/s", "0 B/s");
        assert_eq!(snap.top_talkers.len(), 10);
        // First entry should be the highest count destination
        assert_eq!(snap.top_talkers[0].1, 12);
        // Verify sorted descending
        for w in snap.top_talkers.windows(2) {
            assert!(w[0].1 >= w[1].1);
        }
    }

    #[test]
    fn dns_queries_extracted() {
        let packets = vec![
            make_packet("DNS", "10.0.0.1", "8.8.8.8", "Standard query A example.com", ExpertSeverity::Chat),
            make_packet("DNS", "10.0.0.1", "8.8.8.8", "Standard query A test.org", ExpertSeverity::Chat),
            // Response should NOT be included
            make_packet("DNS", "8.8.8.8", "10.0.0.1", "Standard query response A example.com 1.2.3.4", ExpertSeverity::Note),
        ];

        let snap = NetworkSnapshot::build(&packets, &[], &make_health(), "0 B/s", "0 B/s");
        assert_eq!(snap.dns_queries.len(), 2);
        assert!(snap.dns_queries.contains(&"example.com".to_string()));
        assert!(snap.dns_queries.contains(&"test.org".to_string()));
    }

    #[test]
    fn expert_errors_and_warnings() {
        let packets = vec![
            make_packet("TCP", "10.0.0.1", "10.0.0.2", "RST", ExpertSeverity::Error),
            make_packet("TCP", "10.0.0.1", "10.0.0.3", "Zero window", ExpertSeverity::Warn),
            make_packet("TCP", "10.0.0.1", "10.0.0.4", "normal", ExpertSeverity::Chat),
        ];

        let snap = NetworkSnapshot::build(&packets, &[], &make_health(), "0 B/s", "0 B/s");
        assert_eq!(snap.expert_errors.len(), 1);
        assert!(snap.expert_errors[0].contains("RST"));
        assert_eq!(snap.expert_warnings.len(), 1);
        assert!(snap.expert_warnings[0].contains("Zero window"));
    }

    #[test]
    fn connection_counting() {
        let conns = vec![
            make_conn("ESTABLISHED"),
            make_conn("ESTABLISHED"),
            make_conn("TIME_WAIT"),
            make_conn("CLOSE_WAIT"),
        ];

        let snap = NetworkSnapshot::build(&[], &conns, &make_health(), "0 B/s", "0 B/s");
        assert_eq!(snap.connections_established, 2);
        assert_eq!(snap.connections_other, 2);
    }

    #[test]
    fn to_prompt_contains_key_metrics() {
        let packets = vec![
            make_packet("TCP", "10.0.0.1", "10.0.0.2", "data", ExpertSeverity::Chat),
        ];
        let conns = vec![make_conn("ESTABLISHED")];
        let snap = NetworkSnapshot::build(&packets, &conns, &make_health(), "1.5 MB/s", "200 KB/s");
        let prompt = snap.to_prompt();

        assert!(prompt.contains("Total packets captured: 1"));
        assert!(prompt.contains("TCP: 1"));
        assert!(prompt.contains("RX 1.5 MB/s"));
        assert!(prompt.contains("TX 200 KB/s"));
        assert!(prompt.contains("1 established"));
        assert!(prompt.contains("Gateway: 5.0ms RTT"));
        assert!(prompt.contains("DNS: 10.0ms RTT"));
    }

    #[test]
    fn large_dataset_only_last_500() {
        let packets: Vec<CapturedPacket> = (0..600)
            .map(|i| {
                if i < 500 {
                    make_packet("OLD", "10.0.0.1", "10.0.0.2", "", ExpertSeverity::Chat)
                } else {
                    make_packet("NEW", "10.0.0.1", "10.0.0.3", "", ExpertSeverity::Chat)
                }
            })
            .collect();

        let snap = NetworkSnapshot::build(&packets, &[], &make_health(), "0 B/s", "0 B/s");
        // total_packets reflects the full slice length
        assert_eq!(snap.total_packets, 600);
        // protocol_counts only reflect the last 500 (indices 100..600)
        assert_eq!(snap.protocol_counts.get("OLD").copied().unwrap_or(0), 400);
        assert_eq!(snap.protocol_counts.get("NEW").copied().unwrap_or(0), 100);
    }
}
