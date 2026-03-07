use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// Sliding-window RTT anomaly detector for a single connection.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RttWindow {
    window: VecDeque<f64>,
    sum: f64,
    sum_sq: f64,
    max_samples: usize,
}

#[allow(dead_code)]
impl RttWindow {
    pub fn new(max_samples: usize) -> Self {
        Self {
            window: VecDeque::with_capacity(max_samples),
            sum: 0.0,
            sum_sq: 0.0,
            max_samples,
        }
    }

    /// Push a new RTT sample in microseconds. Returns true if it is anomalous.
    pub fn push(&mut self, sample_us: f64) -> bool {
        let anomalous = self.is_anomalous(sample_us);

        if self.window.len() == self.max_samples {
            if let Some(old) = self.window.pop_front() {
                self.sum -= old;
                self.sum_sq -= old * old;
            }
        }
        self.window.push_back(sample_us);
        self.sum += sample_us;
        self.sum_sq += sample_us * sample_us;

        anomalous
    }

    pub fn mean(&self) -> f64 {
        if self.window.is_empty() {
            return 0.0;
        }
        self.sum / self.window.len() as f64
    }

    pub fn std_dev(&self) -> f64 {
        let n = self.window.len() as f64;
        if n < 2.0 {
            return 0.0;
        }
        let variance = (self.sum_sq / n) - (self.mean() * self.mean());
        variance.max(0.0).sqrt()
    }

    /// Returns true if the sample is > 3 standard deviations from the mean.
    /// Requires at least 10 samples before flagging anomalies.
    pub fn is_anomalous(&self, sample_us: f64) -> bool {
        if self.window.len() < 10 {
            return false;
        }
        let threshold = self.mean() + 3.0 * self.std_dev();
        sample_us > threshold
    }

    pub fn latest(&self) -> Option<f64> {
        self.window.back().copied()
    }
}

/// Key identifying a connection for RTT tracking.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct RttConnectionKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

/// RTT sample from the eBPF tcp_probe tracepoint.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RttSample {
    pub key: RttConnectionKey,
    pub srtt_us: f64,
    pub timestamp_ns: u64,
}

/// Aggregates per-connection RTT data and detects anomalies.
#[allow(dead_code)]
pub struct RttMonitor {
    /// Per-connection RTT windows.
    pub connections: Arc<Mutex<HashMap<RttConnectionKey, RttWindow>>>,
    /// Set of connections currently flagged as anomalous.
    pub anomalies: Arc<Mutex<HashMap<RttConnectionKey, f64>>>,
    max_window: usize,
}

#[allow(dead_code)]
impl RttMonitor {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            anomalies: Arc::new(Mutex::new(HashMap::new())),
            max_window: 100,
        }
    }

    /// Process a batch of RTT samples (called from the eBPF reader task).
    pub fn process_samples(&self, samples: &[RttSample]) {
        let mut conns = self.connections.lock().unwrap();
        let mut anomalies = self.anomalies.lock().unwrap();

        for sample in samples {
            let window = conns
                .entry(sample.key.clone())
                .or_insert_with(|| RttWindow::new(self.max_window));

            if window.push(sample.srtt_us) {
                anomalies.insert(sample.key.clone(), sample.srtt_us);
            } else {
                anomalies.remove(&sample.key);
            }
        }
    }

    /// Get the current smoothed RTT for a connection, if tracked.
    pub fn get_rtt(&self, key: &RttConnectionKey) -> Option<f64> {
        self.connections.lock().unwrap().get(key).and_then(|w| w.latest())
    }

    /// Check if a connection's RTT is currently anomalous.
    pub fn is_anomalous(&self, key: &RttConnectionKey) -> bool {
        self.anomalies.lock().unwrap().contains_key(key)
    }

    /// Get count of currently anomalous connections.
    pub fn anomaly_count(&self) -> usize {
        self.anomalies.lock().unwrap().len()
    }

    /// Evict connections that haven't received samples recently.
    /// Call periodically to prevent unbounded growth.
    pub fn evict_stale(&self, max_connections: usize) {
        let mut conns = self.connections.lock().unwrap();
        if conns.len() > max_connections {
            // Remove connections with fewest samples (least active)
            let mut entries: Vec<_> = conns.keys().cloned().collect();
            entries.sort_by_key(|k| {
                conns.get(k).map(|w| w.window.len()).unwrap_or(0)
            });
            let to_remove = conns.len() - max_connections;
            for key in entries.into_iter().take(to_remove) {
                conns.remove(&key);
                self.anomalies.lock().unwrap().remove(&key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtt_window_basic() {
        let mut w = RttWindow::new(100);
        for _ in 0..20 {
            w.push(10.0);
        }
        assert!((w.mean() - 10.0).abs() < 0.001);
        assert!(w.std_dev() < 0.001);
    }

    #[test]
    fn test_rtt_anomaly_detection() {
        let mut w = RttWindow::new(100);
        // Build a stable baseline
        for _ in 0..50 {
            assert!(!w.push(10.0));
        }
        // A huge spike should be anomalous
        assert!(w.is_anomalous(1000.0));
    }

    #[test]
    fn test_rtt_window_eviction() {
        let mut w = RttWindow::new(5);
        for i in 0..10 {
            w.push(i as f64);
        }
        assert_eq!(w.window.len(), 5);
        assert_eq!(*w.window.front().unwrap() as i32, 5);
    }

    #[test]
    fn test_rtt_monitor_process_samples() {
        let monitor = RttMonitor::new();
        let key = RttConnectionKey {
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
        };
        let samples: Vec<RttSample> = (0..20)
            .map(|_| RttSample {
                key: key.clone(),
                srtt_us: 1000.0,
                timestamp_ns: 0,
            })
            .collect();
        monitor.process_samples(&samples);
        assert!((monitor.get_rtt(&key).unwrap() - 1000.0).abs() < 0.001);
        assert!(!monitor.is_anomalous(&key));
    }
}
