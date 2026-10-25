use std::net::IpAddr;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::geo::lookup_addr;
use super::lru::BoundedLru;

const WHOIS_CACHE_MAX: usize = 2048;

/// Where a W press sends the selected address. rdap.org is free, needs no key,
/// answers in JSON and redirects to the registry that holds the address.
pub const RDAP_URL: &str = "https://rdap.org/ip/";

#[derive(Clone, Debug)]
pub struct WhoisInfo {
    pub net_name: String,
    pub net_range: String,
    pub org: String,
    pub country: String,
    pub description: String,
}

#[derive(Clone, Debug)]
enum WhoisEntry {
    Resolved(WhoisInfo),
    Failed,
    Pending,
}

#[derive(Clone)]
pub struct WhoisCache {
    /// Keyed by [`lookup_addr`]'s canonical address.
    cache: Arc<Mutex<BoundedLru<IpAddr, WhoisEntry>>>,
    tx: std_mpsc::Sender<IpAddr>,
    pending_rx: Arc<Mutex<Option<std_mpsc::Receiver<IpAddr>>>>,
}

impl Default for WhoisCache {
    fn default() -> Self {
        Self::new()
    }
}

impl WhoisCache {
    pub fn new() -> Self {
        let (tx, rx) = std_mpsc::channel::<IpAddr>();
        let cache = Arc::new(Mutex::new(BoundedLru::new(WHOIS_CACHE_MAX)));

        Self {
            cache,
            tx,
            pending_rx: Arc::new(Mutex::new(Some(rx))),
        }
    }

    /// Start the prepared lookup worker once, shared across cache clones.
    /// Construction only opens local resources and creates a request channel.
    pub fn start(&self) -> bool {
        let Some(rx) = self.pending_rx.lock().unwrap().take() else {
            return false;
        };
        let resolver_cache = Arc::clone(&self.cache);
        crate::sandbox::worker::spawn("whois", move || {
            let now = Instant::now();
            let mut last_request = now.checked_sub(Duration::from_millis(2000)).unwrap_or(now);
            while let Some(ip) = crate::sandbox::worker::receive(&rx) {
                // Rate limit: ~1 request per 2s
                let elapsed = last_request.elapsed();
                if elapsed < Duration::from_millis(2000) {
                    thread::sleep(Duration::from_millis(2000) - elapsed);
                }
                last_request = Instant::now();

                if crate::sandbox::worker::stopping() {
                    break;
                }
                let result = lookup_whois(ip);
                let mut c = resolver_cache.lock().unwrap();
                match result {
                    Some(info) => c.put(ip, WhoisEntry::Resolved(info)),
                    None => c.put(ip, WhoisEntry::Failed),
                }
            }
        });
        true
    }

    /// What an earlier `request` found for `ip`, if it has finished. Reads
    /// the cache only. The detail panes call this on every frame for the
    /// selected row, and drawing a row must not send its address anywhere.
    pub fn lookup(&self, ip: &str) -> Option<WhoisInfo> {
        let addr = lookup_addr(ip)?;
        match self.cache.lock().unwrap().get(&addr) {
            Some(WhoisEntry::Resolved(info)) => Some(info.clone()),
            Some(WhoisEntry::Failed) | Some(WhoisEntry::Pending) | None => None,
        }
    }

    /// Queue `ip` for an RDAP lookup unless it is not a global unicast
    /// address (see [`lookup_addr`]) or is already cached. Only the W key
    /// calls this.
    pub fn request(&self, ip: &str) {
        let Some(addr) = lookup_addr(ip) else {
            return;
        };
        let mut cache = self.cache.lock().unwrap();
        if cache.contains_key(&addr) {
            return;
        }
        cache.put(addr, WhoisEntry::Pending);
        if let Err(e) = self.tx.send(addr) {
            tracing::error!(target: "netwatch::whois", error = %e, "whois resolver thread is gone; lookups will not progress");
        }
    }

    /// Drain the addresses queued for the worker, for tests. Empty once the
    /// worker has started and taken the receiver.
    #[cfg(test)]
    pub(crate) fn queued_for_test(&self) -> Vec<String> {
        let rx = self.pending_rx.lock().unwrap();
        rx.as_ref()
            .map(|rx| rx.try_iter().map(|ip| ip.to_string()).collect())
            .unwrap_or_default()
    }
}

fn lookup_whois(ip: IpAddr) -> Option<WhoisInfo> {
    let url = format!("{RDAP_URL}{ip}");
    let body = crate::http::get_text(&url).ok()?;
    parse_rdap(&body)
}

/// The fields we show from an RDAP reply. Each is whatever the registrant
/// typed, so each is made safe to draw.
fn parse_rdap(body: &str) -> Option<WhoisInfo> {
    use crate::ui::sanitize::display_owned;

    let v: serde_json::Value = serde_json::from_str(body).ok()?;

    let name = v
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let handle = v
        .get("handle")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Build net range from startAddress/endAddress
    let start = v.get("startAddress").and_then(|v| v.as_str()).unwrap_or("");
    let end = v.get("endAddress").and_then(|v| v.as_str()).unwrap_or("");
    let net_range = if !start.is_empty() && !end.is_empty() {
        format!("{} - {}", start, end)
    } else {
        String::new()
    };

    // Country from country field
    let country = v
        .get("country")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Org from entities array
    let org = extract_entity_name(&v).unwrap_or_default();

    // Description from remarks
    let description = v
        .get("remarks")
        .and_then(|r| r.as_array())
        .and_then(|arr| arr.first())
        .and_then(|r| r.get("description"))
        .and_then(|d| d.as_array())
        .and_then(|arr| arr.first())
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();

    let net_name = if !name.is_empty() { name } else { handle };

    Some(WhoisInfo {
        net_name: display_owned(net_name),
        net_range: display_owned(net_range),
        org: display_owned(org),
        country: display_owned(country),
        description: display_owned(description),
    })
}

fn extract_entity_name(v: &serde_json::Value) -> Option<String> {
    let entities = v.get("entities")?.as_array()?;
    for entity in entities {
        let roles = entity.get("roles").and_then(|r| r.as_array());
        let is_registrant = roles.is_some_and(|r| {
            r.iter().any(|role| {
                role.as_str()
                    .is_some_and(|s| s == "registrant" || s == "administrative")
            })
        });
        if is_registrant {
            // Try vcardArray for the org/fn name
            if let Some(name) = extract_vcard_name(entity) {
                return Some(name);
            }
            // Fallback to handle
            if let Some(handle) = entity.get("handle").and_then(|h| h.as_str()) {
                return Some(handle.to_string());
            }
        }
    }
    // Fallback: first entity handle
    entities.first().and_then(|e| {
        extract_vcard_name(e).or_else(|| {
            e.get("handle")
                .and_then(|h| h.as_str())
                .map(|s| s.to_string())
        })
    })
}

fn extract_vcard_name(entity: &serde_json::Value) -> Option<String> {
    let vcard = entity.get("vcardArray")?.as_array()?;
    let entries = vcard.get(1)?.as_array()?;
    for entry in entries {
        let arr = entry.as_array()?;
        if arr.first()?.as_str()? == "fn" {
            return arr.get(3)?.as_str().map(|s| s.to_string());
        }
    }
    None
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[test]
    fn prepared_cache_queues_until_explicit_start_and_clones_share_one_worker() {
        let cache = WhoisCache::new();
        cache.request("8.8.8.8");
        assert_eq!(
            cache
                .pending_rx
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .try_recv()
                .unwrap(),
            IpAddr::from([8, 8, 8, 8])
        );
        let clone = cache.clone();
        assert!(clone.start());
        assert!(!cache.start());
    }

    #[test]
    fn lookup_never_queues() {
        // The detail panes call `lookup` on every frame for whatever row is
        // selected. A miss must not send the address to rdap.org.
        let cache = WhoisCache::new();
        assert!(cache.lookup("8.8.8.8").is_none());
        assert!(cache.lookup("8.8.8.8").is_none());
        assert!(cache.lookup("2606:4700:4700::1111").is_none());
        assert!(cache.queued_for_test().is_empty());

        // Nor may it leave a marker behind that makes a later W a no-op.
        cache.request("8.8.8.8");
        assert_eq!(cache.queued_for_test(), ["8.8.8.8"]);
    }

    #[test]
    fn lookup_returns_resolved_entry() {
        let cache = WhoisCache::new();
        let info = WhoisInfo {
            net_name: "GOGL".into(),
            net_range: "8.8.8.0 - 8.8.8.255".into(),
            org: "Google LLC".into(),
            country: "US".into(),
            description: String::new(),
        };
        cache
            .cache
            .lock()
            .unwrap()
            .put(IpAddr::from([8, 8, 8, 8]), WhoisEntry::Resolved(info));
        assert_eq!(cache.lookup("8.8.8.8").unwrap().org, "Google LLC");
        assert!(cache.queued_for_test().is_empty());
    }

    #[test]
    fn request_queues_once() {
        let cache = WhoisCache::new();
        cache.request("8.8.8.8");
        cache.request("8.8.8.8");
        assert_eq!(cache.queued_for_test(), ["8.8.8.8"]);
        assert!(cache.lookup("8.8.8.8").is_none(), "pending shows nothing");
    }

    #[test]
    fn request_skips_non_global() {
        let cache = WhoisCache::new();
        for ip in [
            "",
            "—",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "::",
            "::1",
            "fe80::1",
            "fd00::1",
            // Sent to rdap.org before W used geo's global-unicast check.
            "::ffff:192.168.1.5",
            "100.64.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "2001:db8::1",
            "fe90::1",
            "64:ff9b::a00:1",
            "255.255.255.255",
            "64:ff9b:1::a00:1",
            "2001:2::1",
            "5f00::1",
            "[::ffff:192.168.1.5]",
        ] {
            cache.request(ip);
        }
        assert!(cache.queued_for_test().is_empty());
    }

    #[test]
    fn a_v4_mapped_request_asks_for_the_ipv4_address() {
        let cache = WhoisCache::new();
        cache.request("::ffff:8.8.8.8");
        cache.request("8.8.8.8");
        assert_eq!(cache.queued_for_test(), ["8.8.8.8"]);
    }

    /// The worker cut the cache by whichever quarter the map listed first,
    /// so the entry a detail pane was showing could go while ones nobody had
    /// looked at for hours stayed.
    #[test]
    fn eviction_is_lru() {
        let cache = WhoisCache::new();
        let addr = |i: u32| IpAddr::from(std::net::Ipv4Addr::from(0x0800_0000 + i));
        let info = WhoisInfo {
            net_name: "LVLT-ORG-8-8".into(),
            net_range: "8.0.0.0 - 8.127.255.255".into(),
            org: "Level 3".into(),
            country: "US".into(),
            description: String::new(),
        };
        {
            let mut c = cache.cache.lock().unwrap();
            c.put(addr(0), WhoisEntry::Resolved(info));
            for i in 1..WHOIS_CACHE_MAX as u32 {
                c.put(addr(i), WhoisEntry::Failed);
            }
        }
        // The detail pane draws the oldest entry, so it is in use.
        assert!(cache.lookup("8.0.0.0").is_some());
        cache.request("9.9.9.9");
        assert_eq!(cache.queued_for_test(), ["9.9.9.9"]);

        let c = cache.cache.lock().unwrap();
        assert_eq!(c.len(), WHOIS_CACHE_MAX - WHOIS_CACHE_MAX / 4 + 1);
        assert!(c.contains_key(&addr(0)));
        assert!(!c.contains_key(&addr(1)));
        assert!(!c.contains_key(&addr(WHOIS_CACHE_MAX as u32 / 4)));
        assert!(c.contains_key(&addr(WHOIS_CACHE_MAX as u32 / 4 + 1)));
    }

    #[test]
    fn rdap_control_characters_are_replaced() {
        let body = serde_json::json!({
            "name": "NET\u{1b}]52;c;AAAA\u{7}",
            "startAddress": "203.0.113.0",
            "endAddress": "203.0.113.255\u{202E}",
            "country": "AU\u{9b}2J",
            "entities": [{
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Evil\u{200B}Corp"]]],
            }],
            "remarks": [{"description": ["line one\nline two"]}],
        })
        .to_string();
        let info = parse_rdap(&body).unwrap();
        assert_eq!(info.net_name, "NET·]52;c;AAAA·");
        assert_eq!(info.net_range, "203.0.113.0 - 203.0.113.255·");
        assert_eq!(info.country, "AU·2J");
        assert_eq!(info.org, "Evil·Corp");
        assert_eq!(info.description, "line one·line two");
    }
}
