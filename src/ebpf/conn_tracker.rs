//! Wrapper around `netwatch_sdk::ebpf::EventSource`.
//!
//! Owns the eBPF event source and a background thread that drains decoded
//! `EbpfEvent`s from the SDK's mpsc receiver into an attribution cache.
//! `ConnectionCollector` consults the cache when overlaying kernel-derived
//! `(pid, comm)` onto lsof/ss-discovered connections — the same shape as
//! the macOS PKTAP integration, just with a different kernel data source.
//!
//! Phase 1 of the SDK's eBPF roadmap covered `tcp_v4_connect`; Phase 2
//! adds `tcp_v6_connect` (IPv4 + IPv6 TCP) plus the connected-UDP probes
//! `ip4_datagram_connect`/`ip6_datagram_connect`, so QUIC and other
//! `connect()`ed UDP flows are attributed too. *Unconnected* UDP
//! (`sendto`/`sendmsg`) is still pending. Shared caveat:
//! - All four kprobes fire at connect-entry, where the destination (from the
//!   `uaddr` arg) is valid but the socket's own source addr/port aren't yet
//!   assigned. So `saddr`/`sport` are reported as 0 and we key the cache by
//!   `(protocol, daddr, dport)`, accepting that two concurrent same-protocol
//!   connections to the same `daddr:dport` would alias. Rare in practice.
//!
//! The SDK canonicalises v4-mapped IPv6 destinations (`::ffff:a.b.c.d`,
//! i.e. IPv4 traffic on dual-stack sockets) to `IpAddr::V4` before they
//! reach us, so cache keys line up with the v4 endpoints lsof/ss report.
//!
//! Compiles on non-Linux targets when `--features ebpf` is set so
//! cross-platform builds keep working; `EventSource::new` returns
//! `EbpfError::UnsupportedPlatform` at runtime there.

use netwatch_sdk::ebpf::{ConnectEvent, EbpfError, EbpfEvent, EventSource, Protocol};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Lifetime of a cache entry after the matching kprobe last fired. Matches
/// the PKTAP TTL — long enough to span a few lsof poll cycles, short
/// enough that closed connections age out.
const ATTRIBUTION_TTL: Duration = Duration::from_secs(60);

/// Cached attribution from a `tcp_v4_connect`/`tcp_v6_connect` kprobe firing.
#[derive(Debug, Clone)]
pub struct EbpfAttribution {
    pub pid: u32,
    pub comm: String,
    pub seen_at: Instant,
}

/// `(protocol, daddr, dport)` — keyed on transport plus destination. The
/// connect kprobes fire at connect-entry, before the kernel assigns the
/// socket's source address, so `saddr` is unavailable (reported as 0);
/// `sport` was never captured either. Protocol is part of the key so a TCP
/// and a (connected) UDP flow to the same `daddr:dport` — e.g. both to
/// `:443` — don't cross-attribute. Two same-protocol flows to the same
/// `daddr:dport` concurrently still alias — rare in practice.
type AttrKey = (Protocol, IpAddr, u16);

/// Shared cache of `AttrKey → EbpfAttribution`. Populated by the background
/// drain thread, consulted by the connection collector.
#[derive(Default)]
pub struct EbpfAttributor {
    cache: Mutex<HashMap<AttrKey, EbpfAttribution>>,
}

impl EbpfAttributor {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn lookup(&self, proto: Protocol, daddr: IpAddr, dport: u16) -> Option<EbpfAttribution> {
        self.cache.lock().ok()?.get(&(proto, daddr, dport)).cloned()
    }

    fn record(&self, key: AttrKey, attr: EbpfAttribution) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(key, attr);
        }
    }

    fn evict_stale(&self, ttl: Duration) {
        if let Ok(mut cache) = self.cache.lock() {
            let now = Instant::now();
            cache.retain(|_, a| now.duration_since(a.seen_at) < ttl);
        }
    }
}

/// Owns the SDK's `EventSource` plus a background thread draining its
/// receiver into the attributor cache. Drop to stop the thread.
pub struct ConnTracker {
    pub attributor: Arc<EbpfAttributor>,
    /// `EventSource` is held to keep the BPF programs attached for the
    /// lifetime of the tracker. Dropping it detaches the kprobe.
    _source: EventSource,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl ConnTracker {
    /// Load and attach the BPF programs, spawn the drain thread, and
    /// return a tracker. On non-Linux or when the BPF object is missing
    /// returns the `EbpfError` from the SDK so the caller can surface it
    /// to the UI.
    pub fn new() -> Result<Self, EbpfError> {
        let (source, rx) = EventSource::new()?;
        let attributor = EbpfAttributor::new();
        let stop = Arc::new(AtomicBool::new(false));

        let thread_attr = Arc::clone(&attributor);
        let thread_stop = Arc::clone(&stop);
        let join = thread::Builder::new()
            .name("ebpf-attributor".into())
            .spawn(move || {
                let mut last_evict = Instant::now();
                while !thread_stop.load(Ordering::Relaxed) {
                    // recv_timeout so the loop checks the stop flag even
                    // when the kprobe is silent for long stretches.
                    match rx.recv_timeout(Duration::from_millis(500)) {
                        Ok(EbpfEvent::Connect(evt)) => record_connect(&thread_attr, evt),
                        // `EbpfEvent` is non_exhaustive; ignore variants
                        // from future SDK phases (accept/close/…) until
                        // we have a use for them.
                        Ok(_) => {}
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                        // Sender hung up (EventSource dropped) — exit loop.
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                    if last_evict.elapsed() >= Duration::from_secs(10) {
                        thread_attr.evict_stale(ATTRIBUTION_TTL);
                        last_evict = Instant::now();
                    }
                }
            })
            .ok();

        Ok(Self {
            attributor,
            _source: source,
            stop,
            join,
        })
    }
}

impl Drop for ConnTracker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.join.take() {
            let _ = h.join();
        }
    }
}

fn record_connect(attributor: &Arc<EbpfAttributor>, evt: ConnectEvent) {
    // `saddr` is intentionally 0 — it isn't assigned until after connect-entry
    // where the kprobe fires — so we key on the destination only. Skip events
    // with no usable destination (kernel-internal sockets, etc.).
    if evt.daddr.is_unspecified() || evt.dport == 0 {
        return;
    }
    attributor.record(
        (evt.protocol, evt.daddr, evt.dport),
        EbpfAttribution {
            // tgid, not pid: connect(2) often fires on a worker thread,
            // and the "PID" userspace tools (and our UI) report is the
            // thread-group id. evt.pid is the thread id — wrong for any
            // multithreaded process.
            pid: evt.tgid,
            comm: evt.comm,
            seen_at: Instant::now(),
        },
    );
}

#[cfg(all(test, target_os = "linux"))]
mod live_tests {
    use super::*;
    use std::net::{Ipv6Addr, TcpListener, TcpStream};

    /// End-to-end on a live kernel: SDK event source → drain thread →
    /// attribution cache, for an IPv6 connect. Loading BPF needs
    /// CAP_BPF/CAP_PERFMON, so this skips (and stays green) on an
    /// unprivileged `cargo test`; run the test binary under sudo for the
    /// real assertion.
    #[test]
    fn v6_connect_lands_in_attribution_cache() {
        let tracker = match ConnTracker::new() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("ConnTracker::new failed ({e}); skipping — needs root/CAP_BPF");
                return;
            }
        };

        let listener = TcpListener::bind("[::1]:0").expect("bind ::1 listener");
        let port = listener.local_addr().unwrap().port();
        // Let the kprobe attach settle before generating the event.
        thread::sleep(Duration::from_millis(50));
        let _conn = TcpStream::connect((Ipv6Addr::LOCALHOST, port)).expect("connect to ::1");

        // The drain thread polls the SDK receiver on a 500ms timeout;
        // give the event up to 2s to land in the cache.
        let key = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut attr = None;
        while Instant::now() < deadline {
            if let Some(a) = tracker.attributor.lookup(Protocol::Tcp, key, port) {
                attr = Some(a);
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }

        let attr = attr.expect("no attribution cached for our ::1 connect within 2s");
        // Must be the thread-GROUP id — the test runs on a worker thread,
        // so this fails if record_connect regresses to evt.pid.
        assert_eq!(
            attr.pid,
            std::process::id(),
            "cached pid should be the process (tgid), not the connecting thread"
        );
    }

    /// Connected-UDP twin of the TCP test: `UdpSocket::connect` to a `[::1]`
    /// peer must land in the cache under `Protocol::Udp` (the QUIC client
    /// pattern). Verifies the `ip6_datagram_connect` kprobe and the
    /// protocol-keyed cache end-to-end. Self-skips without CAP_BPF.
    #[test]
    fn udp_v6_connect_lands_in_attribution_cache() {
        use std::net::UdpSocket;

        let tracker = match ConnTracker::new() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("ConnTracker::new failed ({e}); skipping — needs root/CAP_BPF");
                return;
            }
        };

        // A bound peer gives us a fixed destination port to key on; we never
        // send — `connect()` alone fires ip6_datagram_connect.
        let peer = UdpSocket::bind("[::1]:0").expect("bind ::1 udp peer");
        let port = peer.local_addr().unwrap().port();
        thread::sleep(Duration::from_millis(50));
        let sock = UdpSocket::bind("[::1]:0").expect("bind ::1 udp sender");
        sock.connect((Ipv6Addr::LOCALHOST, port))
            .expect("connect udp to ::1");

        let key = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut attr = None;
        while Instant::now() < deadline {
            if let Some(a) = tracker.attributor.lookup(Protocol::Udp, key, port) {
                attr = Some(a);
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }

        let attr = attr.expect("no UDP attribution cached for our ::1 connect within 2s");
        assert_eq!(
            attr.pid,
            std::process::id(),
            "cached pid should be the process (tgid)"
        );
        // The TCP cache must not be populated by a UDP connect — proves the
        // protocol key actually discriminates.
        assert!(
            tracker
                .attributor
                .lookup(Protocol::Tcp, key, port)
                .is_none(),
            "UDP connect must not alias into the TCP cache slot"
        );
    }
}
