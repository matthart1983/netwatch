//! Reverse-DNS cache: asynchronous PTR resolution on a background worker
//! thread, with bounded eviction and pending-entry expiry.
//!
//! Only addresses in this host's own connections, at either end, are looked
//! up (see [`DnsCache::set_peers`]). Every captured packet asks for both of
//! its addresses, and anyone can send a packet from any address, so looking
//! up every source let a flood of spoofed sources fill the queue and the
//! cache.

use std::collections::HashSet;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};

use super::format::parse_ip;
use crate::collectors::lru::BoundedLru;

const DNS_CACHE_MAX: usize = 4096; // max entries kept in memory, pending ones included

/// Lookups queued for the resolver thread at most. A request that finds the
/// queue full is dropped and asked again on a later lookup. `host -W 1` can
/// take a second each, so a full queue is minutes of work; a request waiting
/// in it never expires ([`DnsEntry::Queued`]), so it is never queued twice.
const DNS_QUEUE_MAX: usize = 256;

#[derive(Clone)]
pub struct DnsCache {
    cache: Arc<Mutex<Entries>>,
    tx: std_mpsc::SyncSender<String>,
    pending_rx: Arc<Mutex<Option<std_mpsc::Receiver<String>>>>,
    /// Addresses a PTR lookup may be queued for. Anything else is only read
    /// from the cache.
    peers: Arc<Mutex<HashSet<IpAddr>>>,
}

/// The cache's entries, evicted least recently used first.
type Entries = BoundedLru<String, DnsEntry>;

impl Entries {
    /// The resolver thread taking `ip` off the queue: `Queued` becomes
    /// `Pending`. False when there is nothing to look up, because the entry
    /// was answered or evicted while it waited.
    fn take(&mut self, ip: &str) -> bool {
        match self.peek_mut(ip) {
            Some(entry) if matches!(entry, DnsEntry::Queued) => {
                *entry = DnsEntry::Pending {
                    started: std::time::Instant::now(),
                };
                true
            }
            _ => false,
        }
    }
}

/// Per-IP resolution state in `DnsCache`.
///
/// Transitions:
///   None → Queued    (first lookup of a peer: request queued to resolver
///                     thread; stays None if the queue is full)
///   Queued → Pending (resolver thread takes the request)
///   Pending → Resolved | Failed  (resolver thread writes result back)
///
/// A `Queued` entry never expires. Its request is still ahead of the
/// resolver, and asking again would queue a duplicate that takes a slot from
/// a peer not yet asked for and runs `host` twice. `Pending` entries carry
/// the time the resolver took them so stale ones can be retried after
/// `DNS_PENDING_TIMEOUT`. Without a timeout, a resolver stuck on one lookup
/// would leave its entry `Pending` forever.
#[derive(Clone, Debug)]
enum DnsEntry {
    Resolved(String),
    Failed,
    /// Waiting in the resolver's queue.
    Queued,
    /// Lookup in flight. `started` is used to expire stale pending entries.
    Pending {
        started: std::time::Instant,
    },
}

const DNS_PENDING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

impl DnsCache {
    pub(crate) fn new() -> Self {
        let (tx, rx) = std_mpsc::sync_channel::<String>(DNS_QUEUE_MAX);
        let cache = Arc::new(Mutex::new(Entries::new(DNS_CACHE_MAX)));
        Self {
            cache,
            tx,
            pending_rx: Arc::new(Mutex::new(Some(rx))),
            peers: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Replace the set of addresses PTR lookups may be queued for with
    /// `addrs`: both ends of each row in the connection table, as `ip:port`
    /// (or `[ip]:port`) strings. Wildcards and unspecified addresses are
    /// skipped.
    ///
    /// A connection in the table has one end on this host, so the rule is:
    /// resolve this host's own addresses and the peers it is talking to,
    /// never an address merely seen on the wire. A spoofed source gets a row
    /// only as a half-open connection, and the kernel bounds how many of
    /// those it keeps.
    pub fn set_peers<'a>(&self, addrs: impl IntoIterator<Item = &'a str>) {
        let peers: HashSet<IpAddr> = addrs
            .into_iter()
            .filter_map(|addr| crate::app::parse_addr_parts(addr).0)
            .filter_map(|ip| parse_ip(&ip))
            .filter(|ip| !ip.is_unspecified())
            .collect();
        *crate::app::safe_lock(&self.peers, "dns_cache::set_peers") = peers;
    }

    fn is_peer(&self, ip: &str) -> bool {
        parse_ip(ip).is_some_and(|ip| {
            crate::app::safe_lock(&self.peers, "dns_cache::is_peer").contains(&ip)
        })
    }

    /// Start PTR resolution explicitly, once across all clones.
    pub fn start(&self) -> bool {
        let Some(rx) = self.pending_rx.lock().unwrap().take() else {
            return false;
        };
        let resolver_cache = Arc::clone(&self.cache);
        crate::sandbox::worker::spawn("reverse-dns", move || {
            while let Some(ip) = crate::sandbox::worker::receive(&rx) {
                if !crate::app::safe_lock(&resolver_cache, "dns_cache::take").take(&ip) {
                    continue;
                }
                let hostname = resolve_ip(&ip);
                let mut c = crate::app::safe_lock(&resolver_cache, "dns_cache::resolve");
                match hostname {
                    Some(name) => c.put(ip, DnsEntry::Resolved(name)),
                    None => c.put(ip, DnsEntry::Failed),
                }
            }
        });
        true
    }

    pub fn lookup(&self, ip: &str) -> Option<String> {
        if ip == "—" || ip.is_empty() {
            return None;
        }
        let mut cache = crate::app::safe_lock(&self.cache, "dns_cache::lookup");
        match cache.get(ip) {
            Some(DnsEntry::Resolved(name)) => return Some(name.clone()),
            Some(DnsEntry::Failed | DnsEntry::Queued) => return None,
            Some(DnsEntry::Pending { started }) => {
                // Still resolving — unless the lookup has stalled
                if started.elapsed() < DNS_PENDING_TIMEOUT {
                    return None;
                }
                // Timed out: fall through to re-queue below
            }
            None => {}
        }
        if !self.is_peer(ip) {
            return None;
        }
        match self.tx.try_send(ip.to_string()) {
            Ok(()) => cache.put(ip.to_string(), DnsEntry::Queued),
            // Queue full: record nothing, so the next lookup asks again.
            Err(std_mpsc::TrySendError::Full(_)) => {}
            Err(e @ std_mpsc::TrySendError::Disconnected(_)) => {
                // Channel send only fails if the resolver thread has died.
                // Symptom would be lookups silently stalled forever — log so
                // we can tell that's what happened.
                tracing::error!(target: "netwatch::dns_cache", error = %e, "resolver thread is gone; reverse-DNS will not progress");
            }
        }
        None
    }
}

fn resolve_ip(ip: &str) -> Option<String> {
    // Use getaddrinfo reverse lookup via the system resolver
    let addr = format!("{}:0", ip);
    let socket_addr = addr.to_socket_addrs().ok()?.next()?;
    // Use DNS PTR lookup via std
    dns_lookup_reverse(&socket_addr.ip())
}

fn dns_lookup_reverse(ip: &std::net::IpAddr) -> Option<String> {
    use std::process::Command;
    // Use host command for reverse DNS (available on macOS and most Linux)
    let output = Command::new("host")
        .arg("-W")
        .arg("1")
        .arg(ip.to_string())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_host_output(&String::from_utf8_lossy(&output.stdout))
}

/// The PTR name from `host` output, made safe to draw. Whoever controls the
/// reverse zone for an address chooses this name, and `host` does not escape
/// everything a terminal acts on.
fn parse_host_output(text: &str) -> Option<String> {
    // Parse "X.X.X.X.in-addr.arpa domain name pointer hostname."
    let hostname = text
        .lines()
        .find(|l| l.contains("domain name pointer"))?
        .rsplit("pointer ")
        .next()?
        .trim_end_matches('.');
    if hostname.is_empty() {
        None
    } else {
        Some(crate::ui::sanitize::display(hostname).into_owned())
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[test]
    fn prepared_cache_queues_until_explicit_start_and_clones_share_one_worker() {
        let cache = DnsCache::new();
        cache.set_peers(["192.0.2.1:443"]);
        cache.lookup("192.0.2.1");
        assert_eq!(
            cache
                .pending_rx
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .try_recv()
                .unwrap(),
            "192.0.2.1"
        );
        let clone = cache.clone();
        assert!(clone.start());
        assert!(!cache.start());
    }

    #[test]
    fn lookup_reads_through_a_cache_the_capture_thread_poisoned() {
        let cache = DnsCache::new();
        cache.cache.lock().unwrap().put(
            "192.0.2.1".into(),
            DnsEntry::Resolved("host.example".into()),
        );
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = cache.cache.lock().unwrap();
            panic!("parser bug");
        }));
        assert!(cache.cache.is_poisoned());
        assert_eq!(cache.lookup("192.0.2.1").as_deref(), Some("host.example"));
        assert_eq!(cache.lookup("192.0.2.2"), None);
    }

    /// What the resolver thread would be handed next, drained.
    fn queued(cache: &DnsCache) -> Vec<String> {
        let rx = cache.pending_rx.lock().unwrap();
        rx.as_ref().unwrap().try_iter().collect()
    }

    #[test]
    fn only_addresses_in_this_hosts_connections_are_looked_up() {
        let cache = DnsCache::new();
        cache.set_peers([
            // A row's local end: this host's own address, resolved too.
            "192.0.2.10:50514",
            "198.51.100.7:443",
            "[2001:db8::7]:443",
            "[::ffff:198.51.100.8]:22",
            "*:*",
            "0.0.0.0:*",
        ]);
        // A source merely seen on the wire, say a spoofed one: cache only.
        assert_eq!(cache.lookup("203.0.113.9"), None);
        assert_eq!(cache.lookup("0.0.0.0"), None);
        assert!(queued(&cache).is_empty());
        assert_eq!(cache.cache.lock().unwrap().len(), 0);

        cache.lookup("192.0.2.10");
        cache.lookup("198.51.100.7");
        cache.lookup("2001:db8::7");
        // The v4-mapped row and the plain v4 packet address are one peer.
        cache.lookup("198.51.100.8");
        assert_eq!(
            queued(&cache),
            ["192.0.2.10", "198.51.100.7", "2001:db8::7", "198.51.100.8"]
        );

        // The next refresh replaces the set: a closed connection's peer is
        // no longer looked up once its pending entry is gone.
        cache.set_peers(["192.0.2.1:80"]);
        cache.cache.lock().unwrap().clear();
        cache.lookup("198.51.100.7");
        assert!(queued(&cache).is_empty());
    }

    #[test]
    fn a_full_queue_drops_the_request_and_records_nothing() {
        let cache = DnsCache::new();
        let peers: Vec<String> = (0..DNS_QUEUE_MAX + 10)
            .map(|i| format!("10.{}.{}.1:443", i / 256, i % 256))
            .collect();
        cache.set_peers(peers.iter().map(String::as_str));
        for peer in &peers {
            cache.lookup(peer.trim_end_matches(":443"));
        }
        assert_eq!(cache.cache.lock().unwrap().len(), DNS_QUEUE_MAX);
        assert_eq!(queued(&cache).len(), DNS_QUEUE_MAX);
        // With room again, a dropped request is asked for on its next lookup.
        let dropped = peers.last().unwrap().trim_end_matches(":443");
        cache.lookup(dropped);
        assert_eq!(queued(&cache), [dropped]);
    }

    #[test]
    fn a_request_waiting_in_the_queue_is_not_queued_again() {
        let cache = DnsCache::new();
        let ip = "198.51.100.7";
        cache.set_peers(["198.51.100.7:443"]);
        cache.lookup(ip);
        // However long it waits behind other lookups, it is not asked for
        // again, so it holds one slot and `host` runs once.
        assert!(matches!(
            cache.cache.lock().unwrap().get(ip),
            Some(DnsEntry::Queued)
        ));
        cache.lookup(ip);
        assert_eq!(queued(&cache), [ip]);

        // The timeout starts when the resolver takes it...
        assert!(cache.cache.lock().unwrap().take(ip));
        cache.lookup(ip);
        assert!(queued(&cache).is_empty());
        // ...and a lookup stuck past it is asked for again.
        let started = std::time::Instant::now()
            .checked_sub(DNS_PENDING_TIMEOUT * 2)
            .unwrap();
        cache
            .cache
            .lock()
            .unwrap()
            .put(ip.into(), DnsEntry::Pending { started });
        cache.lookup(ip);
        assert_eq!(queued(&cache), [ip]);

        // If the stuck one answers first, the resolver skips the repeat.
        cache
            .cache
            .lock()
            .unwrap()
            .put(ip.into(), DnsEntry::Resolved("peer.example".into()));
        assert!(!cache.cache.lock().unwrap().take(ip));
        // As it does one evicted while it waited.
        cache.cache.lock().unwrap().clear();
        assert!(!cache.cache.lock().unwrap().take(ip));
    }

    #[test]
    fn ptr_name_control_characters_are_replaced() {
        let out = "7.113.0.203.in-addr.arpa domain name pointer evil\x1b]52;c;AAAA\x07\u{202E}.example.\n";
        assert_eq!(
            parse_host_output(out).as_deref(),
            Some("evil·]52;c;AAAA··.example")
        );
        assert_eq!(
            parse_host_output("Host 1.2.3.4 not found: 3(NXDOMAIN)\n"),
            None
        );
    }
}
