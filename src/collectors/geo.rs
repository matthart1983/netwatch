use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

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

    fn lookup(&self, ip: &str) -> Option<GeoInfo> {
        let addr: IpAddr = ip.parse().ok()?;

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
    cache: Arc<Mutex<HashMap<String, GeoEntry>>>,
    mmdb: Arc<Option<MaxMindReader>>,
    online_tx: std_mpsc::Sender<String>,
    pending_rx: Arc<Mutex<Option<std_mpsc::Receiver<String>>>>,
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
        let reader = MaxMindReader::open(city_path, asn_path);
        let has_db = reader.city_reader.is_some();
        let mmdb = Arc::new(if has_db { Some(reader) } else { None });

        let (tx, rx) = std_mpsc::channel::<String>();
        let cache = Arc::new(Mutex::new(HashMap::new()));

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
                let result = lookup_geo_online(&ip);
                let mut c = resolver_cache.lock().unwrap();
                match result {
                    Some(info) => {
                        c.insert(ip, GeoEntry::Resolved(info));
                    }
                    None => {
                        c.insert(ip, GeoEntry::Failed);
                    }
                }
                if c.len() > GEO_CACHE_MAX {
                    let keys: Vec<String> = c.keys().take(GEO_CACHE_MAX / 4).cloned().collect();
                    for k in keys {
                        c.remove(&k);
                    }
                }
            }
        });

        true
    }

    pub fn has_offline_db(&self) -> bool {
        self.mmdb.is_some()
    }

    pub fn lookup(&self, ip: &str) -> Option<GeoInfo> {
        if ip == "—" || ip.is_empty() || is_private_ip(ip) {
            return None;
        }

        // Fast path: check cache first
        {
            let cache = self.cache.lock().unwrap();
            match cache.get(ip) {
                Some(GeoEntry::Resolved(info)) => return Some(info.clone()),
                Some(GeoEntry::Failed) => return None,
                Some(GeoEntry::Pending) => return None,
                None => {}
            }
        }

        // Try offline MaxMind DB (instant, no rate limit)
        if let Some(ref reader) = *self.mmdb {
            let result = reader.lookup(ip);
            let mut cache = self.cache.lock().unwrap();
            match result {
                Some(info) => {
                    cache.insert(ip.to_string(), GeoEntry::Resolved(info.clone()));
                    return Some(info);
                }
                None => {
                    cache.insert(ip.to_string(), GeoEntry::Failed);
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
        cache.insert(ip.to_string(), GeoEntry::Pending);
        if let Err(e) = self.online_tx.send(ip.to_string()) {
            tracing::error!(target: "netwatch::geo", error = %e, "online geo resolver thread is gone; falling back to local DB only");
        }
        None
    }
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
fn lookup_geo_online(ip: &str) -> Option<GeoInfo> {
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
            "8.8.8.8"
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
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[test]
    fn prepared_cache_queues_until_explicit_start_and_clones_share_one_worker() {
        // Online lookups must be opted into for this to exercise the
        // worker-sharing path at all (see geo.rs's `online_enabled` gate).
        let cache = GeoCache::with_mmdb_and_online("", "", true);
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
}
