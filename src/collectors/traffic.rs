use crate::platform::{self, InterfaceStats};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

// One sample per refresh tick, retained for `HISTORY_WINDOW_SECS` so this
// series covers the same span as the health probes it is stacked against on
// the dashboard timeline. Per-interface cost at the default 1 Hz is ~9.4 KiB
// (600 × 8 bytes × 2 series), which is trivial.
const SPARKLINE_HISTORY: usize = crate::app::tick_history_len(1000);

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
    pub signal_dbm: Option<i32>,
    pub tx_retries: Option<u64>,
    pub rx_history: VecDeque<u64>,
    pub tx_history: VecDeque<u64>,
    /// Actual completion times aligned with both rate histories.
    pub sample_times: VecDeque<Instant>,
}

struct TrafficState {
    prev_stats: HashMap<String, InterfaceStats>,
    prev_time: Instant,
}

type TimedInterfaces = (Arc<Vec<InterfaceTraffic>>, Option<Instant>);

pub struct TrafficCollector {
    state: Arc<Mutex<TrafficState>>,
    /// Most recent interface snapshot, shared via Arc so reads are O(1)
    /// regardless of interface count or per-interface history depth.
    /// `update()` swaps in a fresh Arc each tick; readers hold their own
    /// reference until they drop it. Avoids the deep-clone hot path that
    /// previously dominated allocator pressure on Linux (issue #27).
    snapshot: Arc<RwLock<TimedInterfaces>>,
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
            })),
            snapshot: Arc::new(RwLock::new((Arc::new(Vec::new()), None))),
            busy: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Cheap snapshot of the current interface state. Returned `Arc` shares
    /// the underlying `Vec<InterfaceTraffic>` (including each interface's
    /// 600-sample history VecDeques) with all other readers and the
    /// collector itself, so this call is a single atomic refcount bump
    /// regardless of interface count.
    pub fn interfaces(&self) -> Arc<Vec<InterfaceTraffic>> {
        Arc::clone(&self.snapshot.read().unwrap().0)
    }

    pub fn timed_snapshot(&self) -> (Arc<Vec<InterfaceTraffic>>, Option<Instant>) {
        self.snapshot.read().unwrap().clone()
    }

    pub fn interface_count(&self) -> usize {
        self.snapshot.read().unwrap().0.len()
    }

    #[cfg(test)]
    pub(crate) fn publish_for_test(&self, rows: Vec<InterfaceTraffic>) {
        self.snapshot.write().unwrap().0 = Arc::new(rows);
    }

    pub fn interface_at(&self, index: usize) -> Option<InterfaceTraffic> {
        self.snapshot.read().unwrap().0.get(index).cloned()
    }

    pub fn update(&self) {
        if self
            .busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let state = Arc::clone(&self.state);
        let snapshot = Arc::clone(&self.snapshot);
        let busy = Arc::clone(&self.busy);

        crate::sandbox::worker::spawn("traffic", move || {
            let now = Instant::now();
            // Snapshot prev state without holding the state lock for the whole
            // collection: prev_stats is moderate (one entry per interface),
            // prev_interfaces is read via Arc::clone (refcount bump only).
            let (prev_stats, prev_time) = {
                let state = state.lock().unwrap();
                let elapsed = now.duration_since(state.prev_time).as_secs_f64();
                if elapsed < 0.01 {
                    busy.store(false, Ordering::Release);
                    return;
                }
                (state.prev_stats.clone(), state.prev_time)
            };
            let prev_interfaces: Arc<Vec<InterfaceTraffic>> =
                Arc::clone(&snapshot.read().unwrap().0);

            let elapsed = now.duration_since(prev_time).as_secs_f64();
            let current = match platform::collect_interface_stats() {
                Ok(s) => s,
                Err(_) => {
                    busy.store(false, Ordering::Release);
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

                let (mut rx_hist, mut tx_hist, mut sample_times) = prev_interfaces
                    .iter()
                    .find(|i| i.name == *name)
                    .map(|i| {
                        (
                            i.rx_history.clone(),
                            i.tx_history.clone(),
                            i.sample_times.clone(),
                        )
                    })
                    .unwrap_or_default();

                sample_times.push_back(now);
                rx_hist.push_back(rx_rate as u64);
                tx_hist.push_back(tx_rate as u64);
                if rx_hist.len() > SPARKLINE_HISTORY {
                    rx_hist.pop_front();
                    sample_times.pop_front();
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
                    signal_dbm: cur.signal_dbm,
                    tx_retries: cur.tx_retries,
                    rx_history: rx_hist,
                    tx_history: tx_hist,
                    sample_times,
                });
            }

            updated.sort_by(|a, b| a.name.cmp(&b.name));
            // Publish the new snapshot first (cheap pointer swap), then
            // record prev_stats / prev_time. Readers transitioning across
            // these two writes see either the old snapshot with old prev_*,
            // or the new snapshot with new prev_* — never a torn pair.
            *snapshot.write().unwrap() = (Arc::new(updated), Some(now));
            let mut state = state.lock().unwrap();
            state.prev_stats = current;
            state.prev_time = now;
            busy.store(false, Ordering::Release);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression for issue #27 (RSS climb on Dashboard-only, non-sudo Linux):
    /// `interfaces()` must not deep-clone the underlying Vec on every call.
    /// Two consecutive reads without an intervening `update()` should hand
    /// back Arcs pointing to the same allocation. Pre-fix this test fails
    /// because each call returned a fresh `Vec<InterfaceTraffic>` clone,
    /// which on a multi-interface host generated hundreds of KB/sec of
    /// allocator churn that glibc retained in per-thread arenas.
    #[test]
    fn interfaces_read_path_is_arc_shared() {
        let collector = TrafficCollector::new();
        // Seed the snapshot with a known payload so we're not asserting on
        // an empty Vec (which Arc dedupes via the empty-allocation special
        // case and would pass trivially).
        collector.snapshot.write().unwrap().0 = Arc::new(vec![InterfaceTraffic {
            name: "test0".into(),
            rx_rate: 0.0,
            tx_rate: 0.0,
            rx_bytes_total: 0,
            tx_bytes_total: 0,
            rx_packets: 0,
            tx_packets: 0,
            rx_errors: 0,
            tx_errors: 0,
            rx_drops: 0,
            tx_drops: 0,
            signal_dbm: None,
            tx_retries: None,
            rx_history: VecDeque::new(),
            tx_history: VecDeque::new(),
            sample_times: VecDeque::new(),
        }]);

        let a = collector.interfaces();
        let b = collector.interfaces();
        assert!(
            Arc::ptr_eq(&a, &b),
            "interfaces() should hand out the same Arc until update() swaps in a new snapshot"
        );
        // And the slice content is the same (sanity).
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].name, "test0");
    }
}
