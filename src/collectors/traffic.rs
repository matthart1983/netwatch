use crate::platform::{self, InterfaceStats};
use std::collections::HashMap;
use std::time::Instant;

const SPARKLINE_HISTORY: usize = 60;

#[derive(Debug, Clone)]
pub struct InterfaceTraffic {
    pub name: String,
    pub rx_rate: f64,
    pub tx_rate: f64,
    pub rx_bytes_total: u64,
    pub tx_bytes_total: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_drops: u64,
    pub tx_drops: u64,
    pub rx_history: Vec<u64>,
    pub tx_history: Vec<u64>,
}

pub struct TrafficCollector {
    prev_stats: HashMap<String, InterfaceStats>,
    prev_time: Instant,
    pub interfaces: Vec<InterfaceTraffic>,
}

impl TrafficCollector {
    pub fn new() -> Self {
        let stats = platform::collect_interface_stats().unwrap_or_default();
        Self {
            prev_stats: stats,
            prev_time: Instant::now(),
            interfaces: Vec::new(),
        }
    }

    pub fn update(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.prev_time).as_secs_f64();
        if elapsed < 0.01 {
            return;
        }

        let current = match platform::collect_interface_stats() {
            Ok(s) => s,
            Err(_) => return,
        };

        let mut updated: Vec<InterfaceTraffic> = Vec::new();

        for (name, cur) in &current {
            let (rx_rate, tx_rate) = if let Some(prev) = self.prev_stats.get(name) {
                let rx_diff = cur.rx_bytes.saturating_sub(prev.rx_bytes);
                let tx_diff = cur.tx_bytes.saturating_sub(prev.tx_bytes);
                (rx_diff as f64 / elapsed, tx_diff as f64 / elapsed)
            } else {
                (0.0, 0.0)
            };

            // Find existing history or start fresh
            let (mut rx_hist, mut tx_hist) = self
                .interfaces
                .iter()
                .find(|i| i.name == *name)
                .map(|i| (i.rx_history.clone(), i.tx_history.clone()))
                .unwrap_or_default();

            rx_hist.push(rx_rate as u64);
            tx_hist.push(tx_rate as u64);
            if rx_hist.len() > SPARKLINE_HISTORY {
                rx_hist.remove(0);
            }
            if tx_hist.len() > SPARKLINE_HISTORY {
                tx_hist.remove(0);
            }

            updated.push(InterfaceTraffic {
                name: name.clone(),
                rx_rate,
                tx_rate,
                rx_bytes_total: cur.rx_bytes,
                tx_bytes_total: cur.tx_bytes,
                rx_packets: cur.rx_packets,
                tx_packets: cur.tx_packets,
                rx_errors: cur.rx_errors,
                tx_errors: cur.tx_errors,
                rx_drops: cur.rx_drops,
                tx_drops: cur.tx_drops,
                rx_history: rx_hist,
                tx_history: tx_hist,
            });
        }

        updated.sort_by(|a, b| a.name.cmp(&b.name));
        self.interfaces = updated;
        self.prev_stats = current;
        self.prev_time = now;
    }
}
