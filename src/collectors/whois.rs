use std::collections::HashMap;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const WHOIS_CACHE_MAX: usize = 2048;

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
    cache: Arc<Mutex<HashMap<String, WhoisEntry>>>,
    tx: std_mpsc::Sender<String>,
}

impl WhoisCache {
    pub fn new() -> Self {
        let (tx, rx) = std_mpsc::channel::<String>();
        let cache = Arc::new(Mutex::new(HashMap::new()));
        let resolver_cache = Arc::clone(&cache);
        thread::spawn(move || {
            let now = Instant::now();
            let mut last_request = now.checked_sub(Duration::from_millis(2000)).unwrap_or(now);
            while let Ok(ip) = rx.recv() {
                // Rate limit: ~1 request per 2s
                let elapsed = last_request.elapsed();
                if elapsed < Duration::from_millis(2000) {
                    thread::sleep(Duration::from_millis(2000) - elapsed);
                }
                last_request = Instant::now();

                let result = lookup_whois(&ip);
                let mut c = resolver_cache.lock().unwrap();
                match result {
                    Some(info) => { c.insert(ip, WhoisEntry::Resolved(info)); }
                    None => { c.insert(ip, WhoisEntry::Failed); }
                }
                if c.len() > WHOIS_CACHE_MAX {
                    let keys: Vec<String> = c.keys().take(WHOIS_CACHE_MAX / 4).cloned().collect();
                    for k in keys { c.remove(&k); }
                }
            }
        });
        Self { cache, tx }
    }

    pub fn lookup(&self, ip: &str) -> Option<WhoisInfo> {
        if ip == "—" || ip.is_empty() || is_private_ip(ip) {
            return None;
        }
        let mut cache = self.cache.lock().unwrap();
        match cache.get(ip) {
            Some(WhoisEntry::Resolved(info)) => Some(info.clone()),
            Some(WhoisEntry::Failed) | Some(WhoisEntry::Pending) => None,
            None => {
                cache.insert(ip.to_string(), WhoisEntry::Pending);
                let _ = self.tx.send(ip.to_string());
                None
            }
        }
    }

    /// Queue an IP for lookup if not already cached (explicit trigger)
    pub fn request(&self, ip: &str) {
        if ip == "—" || ip.is_empty() || is_private_ip(ip) {
            return;
        }
        let mut cache = self.cache.lock().unwrap();
        if cache.contains_key(ip) {
            return;
        }
        cache.insert(ip.to_string(), WhoisEntry::Pending);
        let _ = self.tx.send(ip.to_string());
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
        || ip.starts_with("ff")
        || ip.starts_with("169.254.")
        || ip.starts_with("224.") || ip.starts_with("239.")
}

fn lookup_whois(ip: &str) -> Option<WhoisInfo> {
    // Use rdap.org (free, no auth, JSON WHOIS)
    let url = format!("https://rdap.org/ip/{}", ip);
    let resp = ureq::get(&url).call().ok()?;
    let body = resp.into_string().ok()?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;

    let name = v.get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let handle = v.get("handle")
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
    let country = v.get("country")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Org from entities array
    let org = extract_entity_name(&v).unwrap_or_default();

    // Description from remarks
    let description = v.get("remarks")
        .and_then(|r| r.as_array())
        .and_then(|arr| arr.first())
        .and_then(|r| r.get("description"))
        .and_then(|d| d.as_array())
        .and_then(|arr| arr.first())
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();

    let net_name = if !name.is_empty() {
        name
    } else {
        handle
    };

    Some(WhoisInfo {
        net_name,
        net_range,
        org,
        country,
        description,
    })
}

fn extract_entity_name(v: &serde_json::Value) -> Option<String> {
    let entities = v.get("entities")?.as_array()?;
    for entity in entities {
        let roles = entity.get("roles").and_then(|r| r.as_array());
        let is_registrant = roles.map_or(false, |r| {
            r.iter().any(|role| {
                role.as_str().map_or(false, |s| s == "registrant" || s == "administrative")
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
    entities.first()
        .and_then(|e| {
            extract_vcard_name(e)
                .or_else(|| e.get("handle").and_then(|h| h.as_str()).map(|s| s.to_string()))
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
