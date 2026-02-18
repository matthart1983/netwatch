use std::collections::HashMap;
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
    pending: Arc<Mutex<Vec<String>>>,
}

impl GeoCache {
    pub fn new() -> Self {
        let geo = Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(Vec::new())),
        };
        geo.start_resolver();
        geo
    }

    fn start_resolver(&self) {
        let cache = Arc::clone(&self.cache);
        let pending = Arc::clone(&self.pending);
        thread::spawn(move || {
            let mut last_request = Instant::now() - Duration::from_millis(1500);
            loop {
                let ip = {
                    let mut q = pending.lock().unwrap();
                    if q.is_empty() {
                        drop(q);
                        thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    q.pop().unwrap()
                };

                // Rate limit: ip-api.com allows 45 requests/minute
                // We space requests at least 1.4s apart to stay well under
                let elapsed = last_request.elapsed();
                if elapsed < Duration::from_millis(1400) {
                    thread::sleep(Duration::from_millis(1400) - elapsed);
                }
                last_request = Instant::now();

                let result = lookup_geo(&ip);
                let mut c = cache.lock().unwrap();
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
    }

    pub fn lookup(&self, ip: &str) -> Option<GeoInfo> {
        if ip == "—" || ip.is_empty() || is_private_ip(ip) {
            return None;
        }
        let cache = self.cache.lock().unwrap();
        match cache.get(ip) {
            Some(GeoEntry::Resolved(info)) => Some(info.clone()),
            Some(GeoEntry::Failed) | Some(GeoEntry::Pending) => None,
            None => {
                drop(cache);
                let mut c = self.cache.lock().unwrap();
                c.insert(ip.to_string(), GeoEntry::Pending);
                drop(c);
                let mut q = self.pending.lock().unwrap();
                q.push(ip.to_string());
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
