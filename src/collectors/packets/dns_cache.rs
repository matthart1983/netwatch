//! Reverse-DNS cache: asynchronous PTR resolution on a background worker
//! thread, with bounded eviction and pending-entry expiry.

use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

const DNS_CACHE_MAX: usize = 4096; // max resolved hostname entries kept in memory

#[derive(Clone)]
pub struct DnsCache {
    cache: Arc<Mutex<HashMap<String, DnsEntry>>>,
    tx: std_mpsc::Sender<String>,
}

/// Per-IP resolution state in `DnsCache`.
///
/// Transitions:
///   None → Pending   (first lookup: request queued to resolver thread)
///   Pending → Resolved | Failed  (resolver thread writes result back)
///
/// `Pending` entries carry the time they were inserted so stale ones can be
/// retried after `DNS_PENDING_TIMEOUT`. Without a timeout, a stalled resolver
/// thread would leave entries stuck as `Pending` forever.
#[derive(Clone, Debug)]
enum DnsEntry {
    Resolved(String),
    Failed,
    /// Lookup in flight. `queued_at` is used to expire stale pending entries.
    Pending {
        queued_at: std::time::Instant,
    },
}

const DNS_PENDING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

impl DnsCache {
    pub(crate) fn new() -> Self {
        let (tx, rx) = std_mpsc::channel::<String>();
        let cache = Arc::new(Mutex::new(HashMap::new()));
        let resolver_cache = Arc::clone(&cache);
        thread::spawn(move || {
            while let Ok(ip) = rx.recv() {
                let hostname = resolve_ip(&ip);
                let mut c = resolver_cache.lock().unwrap();
                match hostname {
                    Some(name) => {
                        c.insert(ip, DnsEntry::Resolved(name));
                    }
                    None => {
                        c.insert(ip, DnsEntry::Failed);
                    }
                }
                if c.len() > DNS_CACHE_MAX {
                    let keys: Vec<String> = c.keys().take(DNS_CACHE_MAX / 4).cloned().collect();
                    for k in keys {
                        c.remove(&k);
                    }
                }
            }
        });
        Self { cache, tx }
    }

    pub fn lookup(&self, ip: &str) -> Option<String> {
        if ip == "—" || ip.is_empty() {
            return None;
        }
        let mut cache = self.cache.lock().unwrap();
        match cache.get(ip) {
            Some(DnsEntry::Resolved(name)) => return Some(name.clone()),
            Some(DnsEntry::Failed) => return None,
            Some(DnsEntry::Pending { queued_at }) => {
                // Still waiting — unless the entry has expired
                if queued_at.elapsed() < DNS_PENDING_TIMEOUT {
                    return None;
                }
                // Timed out: fall through to re-queue below
            }
            None => {}
        }
        cache.insert(
            ip.to_string(),
            DnsEntry::Pending {
                queued_at: std::time::Instant::now(),
            },
        );
        if let Err(e) = self.tx.send(ip.to_string()) {
            // Channel send only fails if the resolver thread has died.
            // Symptom would be lookups silently stalled forever — log so
            // we can tell that's what happened.
            tracing::error!(target: "netwatch::dns_cache", error = %e, "resolver thread is gone; reverse-DNS will not progress");
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
    let text = String::from_utf8_lossy(&output.stdout);
    // Parse "X.X.X.X.in-addr.arpa domain name pointer hostname."
    let hostname = text
        .lines()
        .find(|l| l.contains("domain name pointer"))?
        .rsplit("pointer ")
        .next()?
        .trim_end_matches('.')
        .to_string();
    if hostname.is_empty() {
        None
    } else {
        Some(hostname)
    }
}
