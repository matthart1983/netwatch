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
//!   `(protocol, daddr, dport)`. This is only a hint: concurrent connections
//!   to one destination alias. The collector requires independently verified
//!   socket ownership and never lets an event overwrite that owner.
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
/// `daddr:dport` concurrently still alias; callers must corroborate ownership.
type AttrKey = (Protocol, IpAddr, u16);

/// Hard cap on cached attributions, so a `connect()` storm can't grow the
/// map without bound inside the TTL window.
const MAX_ATTR_ENTRIES: usize = 4096;

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
        self.cache
            .lock()
            .ok()?
            .get(&(proto, daddr, dport))
            .filter(|a| a.seen_at.elapsed() <= crate::collectors::attribution::MAX_MATCH_AGE)
            .cloned()
    }

    #[cfg(test)]
    pub(crate) fn record_for_test(&self, proto: Protocol, addr: IpAddr, port: u16, pid: u32) {
        self.record(
            (proto, addr, port),
            EbpfAttribution {
                pid,
                comm: "test".into(),
                seen_at: Instant::now(),
            },
        );
    }

    fn record(&self, key: AttrKey, attr: EbpfAttribution) {
        if let Ok(mut cache) = self.cache.lock() {
            // Bound the cache: a connect() storm could otherwise add entries
            // faster than the TTL evicts them within the window. On overflow
            // for a new key, drop the oldest entry by `seen_at`.
            if cache.len() >= MAX_ATTR_ENTRIES && !cache.contains_key(&key) {
                if let Some(oldest) = cache.iter().min_by_key(|(_, a)| a.seen_at).map(|(k, _)| *k) {
                    cache.remove(&oldest);
                }
            }
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
    stop: Arc<AtomicBool>,
    /// The worker owns the `EventSource`, so the programs stay attached for
    /// as long as it runs and detach when it exits. Held here to join on
    /// drop.
    worker: Option<crate::sandbox::worker::WorkerHandle>,
}

impl ConnTracker {
    /// Load and attach the BPF programs, then drain decoded events into the
    /// attribution cache.
    ///
    /// Both happen on one sandbox worker, in this order:
    ///
    /// 1. The worker enters the sandbox with the filesystem policy applied
    ///    and CAP_BPF/CAP_PERFMON held, because the load needs them and
    ///    ordinary entry drops them.
    /// 2. `EventSource::new()` loads and attaches. The SDK spawns its own
    ///    reader thread here; created after enforcement, it inherits this
    ///    thread's Landlock domain.
    /// 3. The worker drops the load capabilities itself.
    /// 4. Only then does it read an event.
    ///
    /// This used to refuse outright whenever the sandbox was on, which left
    /// every sandboxed run — the default — on socket polling. What it cannot
    /// yet do is confine the SDK's reader thread *separately*: that thread
    /// inherits the filesystem policy but keeps whatever capabilities it was
    /// created with, until the SDK offers an entry hook of its own. The
    /// residual is recorded against the `ebpf-reader` component rather than
    /// being left for someone to discover.
    pub fn start() -> Result<Self, EbpfError> {
        use crate::sandbox::{worker, Mode, Retain};

        let attributor = EbpfAttributor::new();
        let stop = Arc::new(AtomicBool::new(false));
        let (loaded_tx, loaded_rx) = std::sync::mpsc::sync_channel::<Result<(), EbpfError>>(1);

        let thread_attr = Arc::clone(&attributor);
        let thread_stop = Arc::clone(&stop);
        let sandboxed = !matches!(worker::mode(), Mode::Disabled);
        let handle = worker::spawn_retaining("ebpf", Retain::BpfLoad, move || {
            // Bound, never used again: the programs stay attached for as
            // long as this binding lives, and detach when the worker exits.
            // An explicit `drop` at the end of the loop said the same thing,
            // but the type is a stub with no `Drop` on non-Linux, where that
            // reads as dropping something that cannot be dropped.
            let (_source, rx) = match EventSource::new() {
                Ok(pair) => {
                    let _ = loaded_tx.send(Ok(()));
                    pair
                }
                Err(e) => {
                    let _ = loaded_tx.send(Err(e));
                    return;
                }
            };
            // Attached. Nothing below needs the load capabilities, and the
            // next statement reads kernel-produced bytes.
            worker::drop_load_caps("ebpf");
            if sandboxed {
                worker::note(
                    "ebpf-reader",
                    "confined by inheritance: the SDK reader thread takes this \
                     worker's Landlock layers, TCP deny included, but has no \
                     entry hook of its own",
                );
            }

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
        });

        // The worker reports the load's outcome before it reads anything, so
        // a failure surfaces as this call's error rather than as silence.
        match loaded_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => Ok(Self {
                attributor,
                stop,
                worker: Some(handle),
            }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(EbpfError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "eBPF worker did not report a load result",
            ))),
        }
    }
}

impl Drop for ConnTracker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
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

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn a_sandboxed_run_attempts_the_load_instead_of_refusing_it() {
        // The tracker used to return PermissionDenied whenever the sandbox
        // was anything but disabled, which left every default run on socket
        // polling. Whatever this machine's privileges are, the error it
        // reports now has to come from the load, not from that check.
        let Err(error) = ConnTracker::start() else {
            // Loaded: this machine has CAP_BPF, which is the outcome the
            // change exists to allow.
            return;
        };
        let text = error.to_string();
        assert!(
            !text.contains("eBPF disabled"),
            "refused before trying: {text}"
        );
        assert!(
            !text.contains("pre-processing confinement hook"),
            "refused before trying: {text}"
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod live_tests {
    use super::*;
    use std::net::{Ipv6Addr, TcpListener, TcpStream};
    use std::thread;

    /// End-to-end on a live kernel: SDK event source → drain thread →
    /// attribution cache, for an IPv6 connect. Loading BPF needs
    /// CAP_BPF/CAP_PERFMON, so this skips (and stays green) on an
    /// unprivileged `cargo test`; run the test binary under sudo for the
    /// real assertion.
    #[test]
    fn v6_connect_lands_in_attribution_cache() {
        let tracker = match ConnTracker::start() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("ConnTracker::start failed ({e}); skipping — needs root/CAP_BPF");
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

        let tracker = match ConnTracker::start() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("ConnTracker::start failed ({e}); skipping — needs root/CAP_BPF");
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

#[cfg(test)]
mod freshness_tests {
    use super::*;
    #[test]
    fn stopped_event_worker_cannot_keep_old_matches_alive() {
        let a = EbpfAttributor::new();
        let addr = "127.0.0.1".parse().unwrap();
        a.record(
            (Protocol::Tcp, addr, 443),
            EbpfAttribution {
                pid: 1,
                comm: "old".into(),
                seen_at: Instant::now() - Duration::from_secs(6),
            },
        );
        assert!(a.lookup(Protocol::Tcp, addr, 443).is_none());
    }
}
