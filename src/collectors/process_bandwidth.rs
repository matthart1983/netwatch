use serde::Serialize;
use std::collections::HashMap;

use super::connections::Connection;
use super::traffic::InterfaceTraffic;

#[derive(Debug, Clone, Serialize)]
pub struct ProcessBandwidth {
    pub process_name: String,
    pub pid: Option<u32>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_rate: f64,
    pub tx_rate: f64,
    pub connection_count: u32,
}

pub struct ProcessBandwidthCollector {
    ranked: Vec<ProcessBandwidth>,
    /// Baseline interface byte totals captured on the first `update()` call,
    /// so we attribute only bytes that flowed since netwatch started — not the
    /// kernel's since-interface-up counter (which can be GBs at startup).
    baseline_rx_bytes: Option<u64>,
    baseline_tx_bytes: Option<u64>,
}

impl Default for ProcessBandwidthCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessBandwidthCollector {
    pub fn new() -> Self {
        Self {
            ranked: Vec::new(),
            baseline_rx_bytes: None,
            baseline_tx_bytes: None,
        }
    }

    pub fn update(&mut self, connections: &[Connection], interfaces: &[InterfaceTraffic]) {
        // Sum total interface bandwidth across all interfaces
        let total_rx_rate: f64 = interfaces.iter().map(|i| i.rx_rate).sum();
        let total_tx_rate: f64 = interfaces.iter().map(|i| i.tx_rate).sum();
        let raw_rx_bytes: u64 = interfaces.iter().map(|i| i.rx_bytes_total).sum();
        let raw_tx_bytes: u64 = interfaces.iter().map(|i| i.tx_bytes_total).sum();

        let baseline_rx = *self.baseline_rx_bytes.get_or_insert(raw_rx_bytes);
        let baseline_tx = *self.baseline_tx_bytes.get_or_insert(raw_tx_bytes);
        let total_rx_bytes = raw_rx_bytes.saturating_sub(baseline_rx);
        let total_tx_bytes = raw_tx_bytes.saturating_sub(baseline_tx);

        // Count ESTABLISHED connections per process, keyed by (process_name, pid)
        let mut process_conns: HashMap<(String, Option<u32>), u32> = HashMap::new();
        let mut total_established: u32 = 0;

        for conn in connections {
            if conn.state != "ESTABLISHED" {
                continue;
            }
            let name = conn
                .process_name
                .clone()
                .unwrap_or_else(|| format!("pid:{}", conn.pid.map_or(0, |p| p)));
            let key = (name, conn.pid);
            *process_conns.entry(key).or_insert(0) += 1;
            total_established += 1;
        }

        if total_established == 0 {
            self.ranked.clear();
            return;
        }

        let mut ranked: Vec<ProcessBandwidth> = process_conns
            .into_iter()
            .map(|((process_name, pid), count)| {
                let fraction = count as f64 / total_established as f64;
                ProcessBandwidth {
                    process_name,
                    pid,
                    rx_bytes: (total_rx_bytes as f64 * fraction) as u64,
                    tx_bytes: (total_tx_bytes as f64 * fraction) as u64,
                    rx_rate: total_rx_rate * fraction,
                    tx_rate: total_tx_rate * fraction,
                    connection_count: count,
                }
            })
            .collect();

        ranked.sort_by(|a, b| {
            let bw_b = b.rx_rate + b.tx_rate;
            let bw_a = a.rx_rate + a.tx_rate;
            bw_b.partial_cmp(&bw_a).unwrap_or(std::cmp::Ordering::Equal)
        });

        self.ranked = ranked;
    }

    pub fn ranked(&self) -> &[ProcessBandwidth] {
        &self.ranked
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn make_conn(name: &str, pid: u32, state: &str) -> Connection {
        Connection {
            protocol: "TCP".into(),
            local_addr: "127.0.0.1:8080".into(),
            remote_addr: "10.0.0.1:443".into(),
            state: state.into(),
            pid: Some(pid),
            process_name: Some(name.into()),
            kernel_rtt_us: None,
            rx_rate: None,
            tx_rate: None,
        }
    }

    fn make_interface(rx_rate: f64, tx_rate: f64) -> InterfaceTraffic {
        InterfaceTraffic {
            name: "en0".into(),
            rx_rate,
            tx_rate,
            rx_bytes_total: 1_000_000,
            tx_bytes_total: 500_000,
            rx_packets: 0,
            tx_packets: 0,
            rx_errors: 0,
            tx_errors: 0,
            rx_drops: 0,
            tx_drops: 0,
            rx_history: VecDeque::new(),
            tx_history: VecDeque::new(),
        }
    }

    #[test]
    fn empty_connections_produces_empty_ranking() {
        let mut collector = ProcessBandwidthCollector::new();
        collector.update(&[], &[make_interface(1000.0, 500.0)]);
        assert!(collector.ranked().is_empty());
    }

    #[test]
    fn non_established_connections_are_ignored() {
        let mut collector = ProcessBandwidthCollector::new();
        let conns = vec![make_conn("firefox", 100, "TIME_WAIT")];
        collector.update(&conns, &[make_interface(1000.0, 500.0)]);
        assert!(collector.ranked().is_empty());
    }

    #[test]
    fn single_process_gets_all_bandwidth() {
        let mut collector = ProcessBandwidthCollector::new();
        let conns = vec![make_conn("firefox", 100, "ESTABLISHED")];
        collector.update(&conns, &[make_interface(1000.0, 500.0)]);
        assert_eq!(collector.ranked().len(), 1);
        let p = &collector.ranked()[0];
        assert_eq!(p.process_name, "firefox");
        assert!((p.rx_rate - 1000.0).abs() < 0.01);
        assert!((p.tx_rate - 500.0).abs() < 0.01);
        assert_eq!(p.connection_count, 1);
    }

    #[test]
    fn bandwidth_split_proportionally() {
        let mut collector = ProcessBandwidthCollector::new();
        let conns = vec![
            make_conn("firefox", 100, "ESTABLISHED"),
            make_conn("firefox", 100, "ESTABLISHED"),
            make_conn("firefox", 100, "ESTABLISHED"),
            make_conn("curl", 200, "ESTABLISHED"),
        ];
        collector.update(&conns, &[make_interface(1000.0, 500.0)]);
        assert_eq!(collector.ranked().len(), 2);
        let firefox = collector
            .ranked()
            .iter()
            .find(|p| p.process_name == "firefox")
            .unwrap();
        let curl = collector
            .ranked()
            .iter()
            .find(|p| p.process_name == "curl")
            .unwrap();
        assert_eq!(firefox.connection_count, 3);
        assert_eq!(curl.connection_count, 1);
        assert!((firefox.rx_rate - 750.0).abs() < 0.01);
        assert!((curl.rx_rate - 250.0).abs() < 0.01);
    }

    #[test]
    fn ranked_sorted_by_total_bandwidth_descending() {
        let mut collector = ProcessBandwidthCollector::new();
        let conns = vec![
            make_conn("curl", 200, "ESTABLISHED"),
            make_conn("firefox", 100, "ESTABLISHED"),
            make_conn("firefox", 100, "ESTABLISHED"),
            make_conn("firefox", 100, "ESTABLISHED"),
        ];
        collector.update(&conns, &[make_interface(1000.0, 500.0)]);
        assert_eq!(collector.ranked()[0].process_name, "firefox");
        assert_eq!(collector.ranked()[1].process_name, "curl");
    }
}
