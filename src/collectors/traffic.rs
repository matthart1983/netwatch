use crate::platform::{self, InterfaceStats};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
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
    pub rx_history: VecDeque<u64>,
    pub tx_history: VecDeque<u64>,
}

struct TrafficState {
    prev_stats: HashMap<String, InterfaceStats>,
    prev_time: Instant,
    interfaces: Vec<InterfaceTraffic>,
}

pub struct TrafficCollector {
    state: Arc<Mutex<TrafficState>>,
    busy: Arc<AtomicBool>,
}

impl Default for TrafficCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficCollector {
    pub fn new() -> Self {
        let stats = platform::collect_interface_stats().unwrap_or_default();
        Self {
            state: Arc::new(Mutex::new(TrafficState {
                prev_stats: stats,
                prev_time: Instant::now(),
                interfaces: Vec::new(),
            })),
            busy: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn interfaces(&self) -> Vec<InterfaceTraffic> {
        self.state.lock().unwrap().interfaces.clone()
    }

    pub fn interface_count(&self) -> usize {
        self.state.lock().unwrap().interfaces.len()
    }

    pub fn interface_at(&self, index: usize) -> Option<InterfaceTraffic> {
        self.state.lock().unwrap().interfaces.get(index).cloned()
    }

    pub fn update(&self) {
        if self
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }

        let state = Arc::clone(&self.state);
        let busy = Arc::clone(&self.busy);

        thread::spawn(move || {
            let now = Instant::now();
            let (prev_stats, prev_time, prev_interfaces) = {
                let state = state.lock().unwrap();
                let elapsed = now.duration_since(state.prev_time).as_secs_f64();
                if elapsed < 0.01 {
                    busy.store(false, Ordering::SeqCst);
                    return;
                }
                (
                    state.prev_stats.clone(),
                    state.prev_time,
                    state.interfaces.clone(),
                )
            };

            let elapsed = now.duration_since(prev_time).as_secs_f64();
            let current = match platform::collect_interface_stats() {
                Ok(s) => s,
                Err(_) => {
                    busy.store(false, Ordering::SeqCst);
                    return;
                }
            };

            let mut updated: Vec<InterfaceTraffic> = Vec::new();

            for (name, cur) in &current {
                let (rx_rate, tx_rate) = if let Some(prev) = prev_stats.get(name) {
                    let rx_diff = cur.rx_bytes.saturating_sub(prev.rx_bytes);
                    let tx_diff = cur.tx_bytes.saturating_sub(prev.tx_bytes);
                    (rx_diff as f64 / elapsed, tx_diff as f64 / elapsed)
                } else {
                    (0.0, 0.0)
                };

                let (mut rx_hist, mut tx_hist) = prev_interfaces
                    .iter()
                    .find(|i| i.name == *name)
                    .map(|i| (i.rx_history.clone(), i.tx_history.clone()))
                    .unwrap_or_default();

                rx_hist.push_back(rx_rate as u64);
                tx_hist.push_back(tx_rate as u64);
                if rx_hist.len() > SPARKLINE_HISTORY {
                    rx_hist.pop_front();
                }
                if tx_hist.len() > SPARKLINE_HISTORY {
                    tx_hist.pop_front();
                }
                rx_hist.make_contiguous();
                tx_hist.make_contiguous();

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
            let mut state = state.lock().unwrap();
            state.interfaces = updated;
            state.prev_stats = current;
            state.prev_time = now;
            busy.store(false, Ordering::SeqCst);
        });
    }
}
