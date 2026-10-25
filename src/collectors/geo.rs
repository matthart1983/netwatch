use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::lru::BoundedLru;

const GEO_CACHE_MAX: usize = 4096;

#[derive(Clone, Debug)]
pub struct GeoInfo {
    pub country_code: String,
    pub country: String,
    pub city: String,
    pub org: String,
}

impl GeoInfo {
    /// Every field comes from a database file or an HTTP reply we did not
    /// write (ip-api is cleartext, so anyone on path writes it), so each is
    /// made safe to draw on the way in.
    fn new(country_code: String, country: String, city: String, org: String) -> Self {
        use crate::ui::sanitize::display_owned;
        Self {
            country_code: display_owned(country_code),
            country: display_owned(country),
            city: display_owned(city),
            org: display_owned(org),
        }
    }
}

#[derive(Clone, Debug)]
enum GeoEntry {
    Resolved(GeoInfo),
    Failed,
    Pending,
}

// ── MaxMind offline reader ─────────────────────────────────

struct MaxMindReader {
    city_reader: Option<maxminddb::Reader<Vec<u8>>>,
    asn_reader: Option<maxminddb::Reader<Vec<u8>>>,
}

impl MaxMindReader {
    fn open(city_path: &str, asn_path: &str) -> Self {
        let city_reader = if !city_path.is_empty() {
            maxminddb::Reader::open_readfile(city_path).ok()
        } else {
            None
        };
        let asn_reader = if !asn_path.is_empty() {
            maxminddb::Reader::open_readfile(asn_path).ok()
        } else {
            None
        };
        Self {
            city_reader,
            asn_reader,
        }
    }

    fn lookup(&self, addr: IpAddr) -> Option<GeoInfo> {
        // Try the City/Country DB first
        // `?` rather than `if let ... else { return None }`: no City/Country
        // database configured means no lookup is possible, which is the same
        // early return every other failure here takes.
        let reader = self.city_reader.as_ref()?;
        let (country_code, country, city) = {
            let result = reader.lookup(addr).ok()?;
            // Try City decode first (superset of Country)
            if let Some(city_rec) = result.decode::<maxminddb::geoip2::City>().ok().flatten() {
                let cc = city_rec.country.iso_code.unwrap_or_default().to_string();
                let cn = city_rec
                    .country
                    .names
                    .english
                    .unwrap_or_default()
                    .to_string();
                let ct = city_rec.city.names.english.unwrap_or_default().to_string();
                (cc, cn, ct)
            } else {
                let result = reader.lookup(addr).ok()?;
                let country_rec = result
                    .decode::<maxminddb::geoip2::Country>()
                    .ok()
                    .flatten()?;
                let cc = country_rec.country.iso_code.unwrap_or_default().to_string();
                let cn = country_rec
                    .country
                    .names
                    .english
                    .unwrap_or_default()
                    .to_string();
                (cc, cn, String::new())
            }
        };

        // Enrich with ASN/org if available
        let org = if let Some(ref reader) = self.asn_reader {
            reader
                .lookup(addr)
                .ok()
                .and_then(|r| r.decode::<maxminddb::geoip2::Asn>().ok().flatten())
                .and_then(|asn| asn.autonomous_system_organization.map(|s| s.to_string()))
                .unwrap_or_default()
        } else {
            String::new()
        };

        Some(GeoInfo::new(country_code, country, city, org))
    }
}

// ── GeoCache ───────────────────────────────────────────────

#[derive(Clone)]
pub struct GeoCache {
    /// Keyed by [`lookup_addr`]'s canonical address.
    cache: Arc<Mutex<BoundedLru<IpAddr, GeoEntry>>>,
    mmdb: Arc<Option<MaxMindReader>>,
    online_tx: std_mpsc::Sender<IpAddr>,
    pending_rx: Arc<Mutex<Option<std_mpsc::Receiver<IpAddr>>>>,
    /// Opt-in: without it, an IP with no offline DB hit simply has no geo
    /// info rather than being sent to ip-api.com. See `geoip_online` in
    /// `NetwatchConfig` for why this defaults to off.
    online_enabled: bool,
}

impl Default for GeoCache {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoCache {
    /// No offline DB, no online fallback — used by tests and any caller
    /// that hasn't opted into `geoip_online`.
    pub fn new() -> Self {
        Self::with_mmdb("", "")
    }

    /// No online fallback. Prefer `with_mmdb_and_online` when wiring up a
    /// real config that may have `geoip_online` set.
    pub fn with_mmdb(city_path: &str, asn_path: &str) -> Self {
        Self::with_mmdb_and_online(city_path, asn_path, false)
    }

    pub fn with_mmdb_and_online(city_path: &str, asn_path: &str, online_enabled: bool) -> Self {
        Self::with_reader(MaxMindReader::open(city_path, asn_path), online_enabled)
    }

    fn with_reader(reader: MaxMindReader, online_enabled: bool) -> Self {
        let has_db = reader.city_reader.is_some();
        let mmdb = Arc::new(if has_db { Some(reader) } else { None });

        let (tx, rx) = std_mpsc::channel::<IpAddr>();
        let cache = Arc::new(Mutex::new(BoundedLru::new(GEO_CACHE_MAX)));

        Self {
            online_enabled,
            cache,
            mmdb,
            online_tx: tx,
            pending_rx: Arc::new(Mutex::new(Some(rx))),
        }
    }

    /// Start the prepared lookup worker once, shared across cache clones.
    /// Construction only opens local resources and creates a request channel.
    pub fn start(&self) -> bool {
        let Some(rx) = self.pending_rx.lock().unwrap().take() else {
            return false;
        };
        if !self.online_enabled {
            // `lookup()` never sends on this channel when online lookups are
            // disabled, so there is nothing for a worker to do — `rx` drops
            // here. `pending_rx` was still taken above, so a second `start()`
            // call correctly reports "already started" either way.
            return true;
        }
        let resolver_cache = Arc::clone(&self.cache);

        // Online fallback thread (ip-api.com) — only needed without a local DB
        crate::sandbox::worker::spawn("geoip", move || {
            let now = Instant::now();
            let mut last_request = now.checked_sub(Duration::from_millis(1500)).unwrap_or(now);
            while let Some(ip) = crate::sandbox::worker::receive(&rx) {
                let elapsed = last_request.elapsed();
                if elapsed < Duration::from_millis(1400) {
                    thread::sleep(Duration::from_millis(1400) - elapsed);
                }
                last_request = Instant::now();

                if crate::sandbox::worker::stopping() {
                    break;
                }
                let result = lookup_geo_online(ip);
                let mut c = resolver_cache.lock().unwrap();
                match result {
                    Some(info) => c.put(ip, GeoEntry::Resolved(info)),
                    None => c.put(ip, GeoEntry::Failed),
                }
            }
        });

        true
    }

    pub fn has_offline_db(&self) -> bool {
        self.mmdb.is_some()
    }

    pub fn lookup(&self, ip: &str) -> Option<GeoInfo> {
        let addr = lookup_addr(ip)?;

        // Fast path: check cache first
        {
            let mut cache = self.cache.lock().unwrap();
            match cache.get(&addr) {
                Some(GeoEntry::Resolved(info)) => return Some(info.clone()),
                Some(GeoEntry::Failed) => return None,
                Some(GeoEntry::Pending) => return None,
                None => {}
            }
        }

        // Try offline MaxMind DB (instant, no rate limit)
        if let Some(ref reader) = *self.mmdb {
            let result = reader.lookup(addr);
            let mut cache = self.cache.lock().unwrap();
            match result {
                Some(info) => {
                    cache.put(addr, GeoEntry::Resolved(info.clone()));
                    return Some(info);
                }
                None => {
                    cache.put(addr, GeoEntry::Failed);
                    return None;
                }
            }
        }

        // Fall back to online lookup (async via background thread) — opt-in
        // only. Without a local DB and without this, an IP just has no geo
        // info rather than being sent to ip-api.com.
        if !self.online_enabled {
            return None;
        }
        let mut cache = self.cache.lock().unwrap();
        cache.put(addr, GeoEntry::Pending);
        if let Err(e) = self.online_tx.send(addr) {
            tracing::error!(target: "netwatch::geo", error = %e, "online geo resolver thread is gone; falling back to local DB only");
        }
        None
    }
}

/// The address a GeoIP or WHOIS lookup is made for, or None when `ip` should
/// not be looked up at all. A `%zone` is dropped and a v4-mapped address
/// becomes the IPv4 one it carries, so `::ffff:8.8.8.8` and `8.8.8.8` share
/// a cache entry. Anything that is not global unicast is None: a private,
/// shared, documentation or multicast address has no location or owner
/// worth showing, and asking a remote service about one tells it about the
/// local network.
///
/// Stricter than [`is_private_ip`], which stays as it is: topology, egress,
/// beacon detection and diagnose use it to decide what counts as local, and
/// widening it would change what they report.
pub(crate) fn lookup_addr(ip: &str) -> Option<IpAddr> {
    let ip = ip.split_once('%').map_or(ip, |(addr, _zone)| addr);
    let addr = ip.parse::<IpAddr>().ok()?.to_canonical();
    let global = match addr {
        IpAddr::V4(v4) => is_global_v4(v4),
        IpAddr::V6(v6) => is_global_v6(v6),
    };
    global.then_some(addr)
}

/// IPv4 networks that are not global unicast (RFC 6890 and its updates).
const NON_GLOBAL_V4: [(Ipv4Addr, u32); 14] = [
    (Ipv4Addr::new(0, 0, 0, 0), 8),       // "this network"
    (Ipv4Addr::new(10, 0, 0, 0), 8),      // private
    (Ipv4Addr::new(100, 64, 0, 0), 10),   // shared: carrier-grade NAT, Tailscale
    (Ipv4Addr::new(127, 0, 0, 0), 8),     // loopback
    (Ipv4Addr::new(169, 254, 0, 0), 16),  // link-local
    (Ipv4Addr::new(172, 16, 0, 0), 12),   // private
    (Ipv4Addr::new(192, 0, 0, 0), 24),    // IETF protocol assignments
    (Ipv4Addr::new(192, 0, 2, 0), 24),    // documentation
    (Ipv4Addr::new(192, 168, 0, 0), 16),  // private
    (Ipv4Addr::new(198, 18, 0, 0), 15),   // benchmarking
    (Ipv4Addr::new(198, 51, 100, 0), 24), // documentation
    (Ipv4Addr::new(203, 0, 113, 0), 24),  // documentation
    (Ipv4Addr::new(224, 0, 0, 0), 4),     // multicast
    (Ipv4Addr::new(240, 0, 0, 0), 4),     // reserved, and 255.255.255.255
];

/// IPv6 networks that are not global unicast. NAT64 and 6to4 addresses are
/// left to [`is_global_v6`], which judges them by the IPv4 address inside.
const NON_GLOBAL_V6: [(Ipv6Addr, u32); 8] = [
    (Ipv6Addr::UNSPECIFIED, 127),                         // :: and ::1
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),      // unique local
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),     // link-local
    (Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0), 10),     // site-local, deprecated
    (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),      // multicast
    (Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32), // documentation
    (Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20),     // documentation
    (Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 0), 64),      // discard-only
];

fn is_global_v4(ip: Ipv4Addr) -> bool {
    let bits = u32::from(ip);
    !NON_GLOBAL_V4
        .iter()
        .any(|&(net, len)| bits >> (32 - len) == u32::from(net) >> (32 - len))
}

fn is_global_v6(ip: Ipv6Addr) -> bool {
    let seg = ip.segments();
    let embedded = |hi: u16, lo: u16| Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo));
    // A NAT64 address (64:ff9b::/96) ends in the IPv4 peer, and a 6to4 one
    // (2002::/16) carries the site's IPv4 address after the prefix.
    if seg[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return is_global_v4(embedded(seg[6], seg[7]));
    }
    if seg[0] == 0x2002 {
        return is_global_v4(embedded(seg[1], seg[2]));
    }
    let bits = u128::from(ip);
    !NON_GLOBAL_V6
        .iter()
        .any(|&(net, len)| bits >> (128 - len) == u128::from(net) >> (128 - len))
}

pub fn is_private_ip(ip: &str) -> bool {
    ip.starts_with("10.")
        || ip.starts_with("172.16.")
        || ip.starts_with("172.17.")
        || ip.starts_with("172.18.")
        || ip.starts_with("172.19.")
        || ip.starts_with("172.20.")
        || ip.starts_with("172.21.")
        || ip.starts_with("172.22.")
        || ip.starts_with("172.23.")
        || ip.starts_with("172.24.")
        || ip.starts_with("172.25.")
        || ip.starts_with("172.26.")
        || ip.starts_with("172.27.")
        || ip.starts_with("172.28.")
        || ip.starts_with("172.29.")
        || ip.starts_with("172.30.")
        || ip.starts_with("172.31.")
        || ip.starts_with("192.168.")
        || ip.starts_with("127.")
        || ip == "0.0.0.0"
        || ip == "::"
        || ip == "::1"
        || ip.starts_with("fe80:")
        || ip.starts_with("fc")
        || ip.starts_with("fd")
        || ip.starts_with("ff") // multicast
        || ip.starts_with("169.254.") // link-local
        || ip.starts_with("224.")
        || ip.starts_with("239.") // multicast v4
}

/// Cleartext because it has to be: ip-api.com serves HTTPS only on its paid
/// tier. Anyone on the path sees which peers are looked up and can rewrite
/// the answer. That is why `geoip_online` is off by default, and why doctor,
/// Settings and the config reference call it cleartext.
fn lookup_geo_online(ip: IpAddr) -> Option<GeoInfo> {
    let url = format!(
        "http://ip-api.com/json/{}?fields=status,country,countryCode,city,org,as",
        ip
    );
    let body = crate::http::get_text(&url).ok()?;
    parse_ip_api(&body)
}

fn parse_ip_api(body: &str) -> Option<GeoInfo> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;

    if v.get("status")?.as_str()? != "success" {
        return None;
    }

    Some(GeoInfo::new(
        v.get("countryCode")?.as_str()?.to_string(),
        v.get("country")?.as_str()?.to_string(),
        v.get("city")?.as_str().unwrap_or("").to_string(),
        v.get("org")
            .or_else(|| v.get("as"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_class_a() {
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("10.255.255.255"));
    }

    #[test]
    fn private_class_b() {
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("172.31.255.255"));
    }

    #[test]
    fn not_private_class_b_boundary() {
        assert!(!is_private_ip("172.15.0.1"));
        assert!(!is_private_ip("172.32.0.1"));
    }

    #[test]
    fn private_class_c() {
        assert!(is_private_ip("192.168.1.1"));
    }

    #[test]
    fn not_private_192() {
        assert!(!is_private_ip("192.169.1.1"));
    }

    #[test]
    fn loopback_v4() {
        assert!(is_private_ip("127.0.0.1"));
    }

    #[test]
    fn all_zeros() {
        assert!(is_private_ip("0.0.0.0"));
    }

    #[test]
    fn public_ips() {
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("1.1.1.1"));
    }

    #[test]
    fn ipv6_unspecified_and_loopback() {
        assert!(is_private_ip("::"));
        assert!(is_private_ip("::1"));
    }

    #[test]
    fn ipv6_link_local() {
        assert!(is_private_ip("fe80::1"));
    }

    #[test]
    fn ipv6_ula() {
        assert!(is_private_ip("fc00::1"));
        assert!(is_private_ip("fd00::1"));
    }

    #[test]
    fn ipv6_multicast() {
        assert!(is_private_ip("ff02::1"));
    }

    #[test]
    fn link_local_v4() {
        assert!(is_private_ip("169.254.1.1"));
    }

    #[test]
    fn multicast_v4() {
        assert!(is_private_ip("224.0.0.1"));
        assert!(is_private_ip("239.255.255.255"));
    }

    #[test]
    fn ipv6_documentation_prefix_not_caught() {
        assert!(!is_private_ip("2001:db8::1"));
    }

    #[test]
    fn empty_and_invalid() {
        assert!(!is_private_ip(""));
        assert!(!is_private_ip("not-an-ip"));
    }

    #[test]
    fn geocache_skips_private() {
        let cache = GeoCache::new();
        assert!(cache.lookup("10.0.0.1").is_none());
        assert!(cache.lookup("192.168.1.1").is_none());
        assert!(cache.lookup("127.0.0.1").is_none());
        assert!(cache.lookup("").is_none());
        assert!(cache.lookup("—").is_none());
    }

    #[test]
    fn geocache_no_db_returns_none_first_call() {
        let cache = GeoCache::new();
        // No DB and online lookups off (the default): nothing is queued,
        // this just returns None.
        assert!(cache.lookup("8.8.8.8").is_none());
        assert!(cache
            .pending_rx
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .try_recv()
            .is_err());
    }

    #[test]
    fn geocache_online_disabled_by_default_does_not_queue() {
        // Same IP, both constructors: without opting in, ip-api.com never
        // sees a request queued for it.
        for cache in [GeoCache::new(), GeoCache::with_mmdb("", "")] {
            assert!(cache.lookup("8.8.8.8").is_none());
            assert!(cache
                .pending_rx
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .try_recv()
                .is_err());
        }
    }

    #[test]
    fn geocache_online_opt_in_queues_the_lookup() {
        let cache = GeoCache::with_mmdb_and_online("", "", true);
        assert!(cache.lookup("8.8.8.8").is_none());
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
    }

    #[test]
    fn has_offline_db_without_db() {
        let cache = GeoCache::new();
        assert!(!cache.has_offline_db());
    }

    #[test]
    fn has_offline_db_with_bad_path() {
        let cache = GeoCache::with_mmdb("/nonexistent/path.mmdb", "");
        assert!(!cache.has_offline_db());
    }

    #[test]
    fn with_mmdb_bad_path_falls_back() {
        let cache = GeoCache::with_mmdb("/nonexistent.mmdb", "/also-bad.mmdb");
        assert!(!cache.has_offline_db());
        // Should still work via online fallback path
        assert!(cache.lookup("192.168.1.1").is_none()); // private
    }

    #[test]
    fn ip_api_control_characters_are_replaced() {
        let body = serde_json::json!({
            "status": "success",
            "countryCode": "AU",
            "country": "Aus\u{202E}tralia",
            "city": "Syd\u{1b}]52;c;AAAA\u{7}",
            "org": "Evil\u{FEFF}Net",
        })
        .to_string();
        let info = parse_ip_api(&body).unwrap();
        assert_eq!(info.country_code, "AU");
        assert_eq!(info.country, "Aus·tralia");
        assert_eq!(info.city, "Syd·]52;c;AAAA·");
        assert_eq!(info.org, "Evil·Net");
    }

    /// A MaxMind DB that puts every address, v4 or v6, in the United States:
    /// one search-tree node whose two records both point at the only data
    /// record. Enough to drive the offline path without a database file.
    fn every_address_us() -> MaxMindReader {
        // A UTF-8 string shorter than 29 bytes: type 2 in the top three
        // bits, length in the low five.
        fn text(s: &str) -> Vec<u8> {
            assert!(s.len() < 29);
            let mut out = vec![0x40 | s.len() as u8];
            out.extend_from_slice(s.as_bytes());
            out
        }
        // One node, 24-bit records. A record past the node count points
        // into the data section, which starts 16 bytes after the tree:
        // 1 + 16 + offset 0.
        let mut db = vec![0, 0, 17, 0, 0, 17];
        db.extend_from_slice(&[0; 16]);
        // {country: {iso_code: "US", names: {en: "United States"}}}
        db.push(0xE1);
        db.extend(text("country"));
        db.push(0xE2);
        db.extend(text("iso_code"));
        db.extend(text("US"));
        db.extend(text("names"));
        db.push(0xE1);
        db.extend(text("en"));
        db.extend(text("United States"));
        db.extend_from_slice(b"\xab\xcd\xefMaxMind.com");
        let metadata: [(&str, &[u8]); 9] = [
            ("binary_format_major_version", &[0xA1, 2]), // uint16
            ("binary_format_minor_version", &[0xA0]),
            ("build_epoch", &[0x04, 0x02, 0x68, 0xE7, 0xB7, 0x00]), // uint64
            ("database_type", b"\x49Test-City"),
            ("description", &[0xE0]), // empty map
            ("ip_version", &[0xA1, 6]),
            ("languages", b"\x01\x04\x42en"), // array of one string
            ("node_count", &[0xC1, 1]),       // uint32
            ("record_size", &[0xA1, 24]),
        ];
        db.push(0xE0 | metadata.len() as u8);
        for (key, value) in metadata {
            db.extend(text(key));
            db.extend_from_slice(value);
        }
        MaxMindReader {
            city_reader: Some(maxminddb::Reader::from_source(db).unwrap()),
            asn_reader: None,
        }
    }

    /// What the online worker would be handed next, drained.
    fn queued(cache: &GeoCache) -> Vec<String> {
        let rx = cache.pending_rx.lock().unwrap();
        rx.as_ref()
            .unwrap()
            .try_iter()
            .map(|ip| ip.to_string())
            .collect()
    }

    /// The offline path inserted with no eviction at all, so a long-running
    /// host with a database kept every distinct peer it ever saw.
    #[test]
    fn offline_cache_stays_bounded() {
        let cache = GeoCache::with_reader(every_address_us(), false);
        assert!(cache.has_offline_db());
        for i in 0..100_000u32 {
            let ip = Ipv4Addr::from(0x0800_0000 + i).to_string();
            assert_eq!(cache.lookup(&ip).unwrap().country_code, "US");
            assert!(cache.cache.lock().unwrap().len() <= GEO_CACHE_MAX);
        }
    }

    #[test]
    fn v4_mapped_and_plain_share_one_entry() {
        let cache = GeoCache::with_reader(every_address_us(), false);
        assert!(cache.lookup("8.8.8.8").is_some());
        assert!(cache.lookup("::ffff:8.8.8.8").is_some());
        assert_eq!(cache.cache.lock().unwrap().len(), 1);

        // Online, the mapped form is asked for once, as the IPv4 address.
        let online = GeoCache::with_mmdb_and_online("", "", true);
        online.lookup("::ffff:8.8.8.8");
        online.lookup("8.8.8.8");
        assert_eq!(queued(&online), ["8.8.8.8"]);
    }

    #[test]
    fn non_global_addresses_are_never_looked_up() {
        // Every address is in the fake database, so None means skipped.
        let offline = GeoCache::with_reader(every_address_us(), false);
        let online = GeoCache::with_mmdb_and_online("", "", true);
        for ip in [
            "::ffff:192.168.1.5",
            "::ffff:10.0.0.1",
            "100.64.0.1",
            "100.100.100.100",
            "192.0.2.1",
            "198.18.0.1",
            "2001:db8::1",
            "fe90::1",
            "64:ff9b::a00:1",
            "255.255.255.255",
            // The edges of the same networks, and the rest of the tables.
            "0.0.0.0",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.1.1",
            "172.31.255.255",
            "192.0.0.9",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "::",
            "::1",
            "fd00::1",
            "fe80::1%eth0",
            "fec0::1",
            "ff02::1",
            "3fff::1",
            "100::1",
            // 6to4 for 192.168.1.1.
            "2002:c0a8:101::1",
            "",
            "—",
            "not-an-ip",
        ] {
            assert!(offline.lookup(ip).is_none(), "{ip}");
            online.lookup(ip);
        }
        assert_eq!(offline.cache.lock().unwrap().len(), 0);
        assert!(queued(&online).is_empty());

        for ip in [
            "8.8.8.8",
            "2606:4700:4700::1111",
            "2606:4700:4700::1111%eth0",
            "100.63.255.255",
            "100.128.0.0",
            "172.32.0.1",
            "198.17.255.255",
            "198.20.0.0",
            "223.255.255.255",
            "64:ff9b::808:808",
            "2002:808:808::1",
        ] {
            assert!(offline.lookup(ip).is_some(), "{ip}");
        }
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[test]
    fn prepared_cache_queues_until_explicit_start_and_clones_share_one_worker() {
        // Online lookups must be opted into for this to exercise the
        // worker-sharing path at all (see geo.rs's `online_enabled` gate).
        let cache = GeoCache::with_mmdb_and_online("", "", true);
        cache.lookup("8.8.8.8");
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
}
