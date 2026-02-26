use std::collections::HashMap;
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

#[derive(Clone, Debug)]
enum GeoEntry {
    Resolved(GeoInfo),
    Failed,
    Pending,
}

#[derive(Clone)]
pub struct GeoCache {
    cache: Arc<Mutex<HashMap<String, GeoEntry>>>,
    tx: std_mpsc::Sender<String>,
}

impl GeoCache {
    pub fn new() -> Self {
        let (tx, rx) = std_mpsc::channel::<String>();
        let cache = Arc::new(Mutex::new(HashMap::new()));
        let resolver_cache = Arc::clone(&cache);
        thread::spawn(move || {
            let mut last_request = Instant::now() - Duration::from_millis(1500);
            while let Ok(ip) = rx.recv() {
                // Rate limit: ip-api.com allows 45 requests/minute
                let elapsed = last_request.elapsed();
                if elapsed < Duration::from_millis(1400) {
                    thread::sleep(Duration::from_millis(1400) - elapsed);
                }
                last_request = Instant::now();

                let result = lookup_geo(&ip);
                let mut c = resolver_cache.lock().unwrap();
                match result {
                    Some(info) => { c.insert(ip, GeoEntry::Resolved(info)); }
                    None => { c.insert(ip, GeoEntry::Failed); }
                }
                if c.len() > GEO_CACHE_MAX {
                    let keys: Vec<String> = c.keys().take(GEO_CACHE_MAX / 4).cloned().collect();
                    for k in keys { c.remove(&k); }
                }
            }
        });
        Self { cache, tx }
    }

    pub fn lookup(&self, ip: &str) -> Option<GeoInfo> {
        if ip == "—" || ip.is_empty() || is_private_ip(ip) {
            return None;
        }
        let mut cache = self.cache.lock().unwrap();
        match cache.get(ip) {
            Some(GeoEntry::Resolved(info)) => Some(info.clone()),
            Some(GeoEntry::Failed) | Some(GeoEntry::Pending) => None,
            None => {
                cache.insert(ip.to_string(), GeoEntry::Pending);
                let _ = self.tx.send(ip.to_string());
                None
            }
        }
    }
}

fn is_private_ip(ip: &str) -> bool {
    ip.starts_with("10.")
        || ip.starts_with("172.16.") || ip.starts_with("172.17.") || ip.starts_with("172.18.")
        || ip.starts_with("172.19.") || ip.starts_with("172.20.") || ip.starts_with("172.21.")
        || ip.starts_with("172.22.") || ip.starts_with("172.23.") || ip.starts_with("172.24.")
        || ip.starts_with("172.25.") || ip.starts_with("172.26.") || ip.starts_with("172.27.")
        || ip.starts_with("172.28.") || ip.starts_with("172.29.") || ip.starts_with("172.30.")
        || ip.starts_with("172.31.")
        || ip.starts_with("192.168.")
        || ip.starts_with("127.")
        || ip == "0.0.0.0"
        || ip == "::" || ip == "::1"
        || ip.starts_with("fe80:") || ip.starts_with("fc") || ip.starts_with("fd")
        || ip.starts_with("ff") // multicast
        || ip.starts_with("169.254.") // link-local
        || ip.starts_with("224.") || ip.starts_with("239.") // multicast v4
}

fn lookup_geo(ip: &str) -> Option<GeoInfo> {
    let url = format!("http://ip-api.com/json/{}?fields=status,country,countryCode,city,org,as", ip);
    let resp = ureq::get(&url).call().ok()?;
    let body = resp.into_string().ok()?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;

    if v.get("status")?.as_str()? != "success" {
        return None;
    }

    Some(GeoInfo {
        country_code: v.get("countryCode")?.as_str()?.to_string(),
        country: v.get("country")?.as_str()?.to_string(),
        city: v.get("city")?.as_str().unwrap_or("").to_string(),
        org: v.get("org")
            .or_else(|| v.get("as"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    })
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
}
