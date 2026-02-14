use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};
use std::thread;

const MAX_PACKETS: usize = 5000;
const DNS_CACHE_MAX: usize = 4096;

#[derive(Debug, Clone)]
pub struct CapturedPacket {
    pub id: u64,
    pub timestamp: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_host: Option<String>,
    pub dst_host: Option<String>,
    pub protocol: String,
    pub length: u32,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub info: String,
    pub details: Vec<String>,
    pub payload_text: String,
    pub raw_hex: String,
    pub raw_ascii: String,
}

#[derive(Clone)]
pub struct DnsCache {
    cache: Arc<Mutex<HashMap<String, DnsEntry>>>,
    pending: Arc<Mutex<Vec<String>>>,
}

#[derive(Clone, Debug)]
enum DnsEntry {
    Resolved(String),
    Failed,
    Pending,
}

impl DnsCache {
    fn new() -> Self {
        let dns = Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(Vec::new())),
        };
        dns.start_resolver();
        dns
    }

    fn start_resolver(&self) {
        let cache = Arc::clone(&self.cache);
        let pending = Arc::clone(&self.pending);
        thread::spawn(move || {
            loop {
                let ip = {
                    let mut q = pending.lock().unwrap();
                    if q.is_empty() {
                        drop(q);
                        thread::sleep(std::time::Duration::from_millis(50));
                        continue;
                    }
                    q.pop().unwrap()
                };

                let hostname = resolve_ip(&ip);
                let mut c = cache.lock().unwrap();
                match hostname {
                    Some(name) => { c.insert(ip, DnsEntry::Resolved(name)); }
                    None => { c.insert(ip, DnsEntry::Failed); }
                }
                if c.len() > DNS_CACHE_MAX {
                    let keys: Vec<String> = c.keys().take(DNS_CACHE_MAX / 4).cloned().collect();
                    for k in keys { c.remove(&k); }
                }
            }
        });
    }

    pub fn lookup(&self, ip: &str) -> Option<String> {
        if ip == "—" || ip.is_empty() {
            return None;
        }
        let cache = self.cache.lock().unwrap();
        match cache.get(ip) {
            Some(DnsEntry::Resolved(name)) => Some(name.clone()),
            Some(DnsEntry::Failed) | Some(DnsEntry::Pending) => None,
            None => {
                drop(cache);
                let mut c = self.cache.lock().unwrap();
                c.insert(ip.to_string(), DnsEntry::Pending);
                drop(c);
                let mut q = self.pending.lock().unwrap();
                q.push(ip.to_string());
                None
            }
        }
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
    let hostname = text.lines()
        .find(|l| l.contains("domain name pointer"))?
        .rsplit("pointer ")
        .next()?
        .trim_end_matches('.')
        .to_string();
    if hostname.is_empty() { None } else { Some(hostname) }
}

pub struct PacketCollector {
    pub packets: Arc<Mutex<Vec<CapturedPacket>>>,
    pub capturing: Arc<Mutex<bool>>,
    pub error: Arc<Mutex<Option<String>>>,
    pub dns_cache: DnsCache,
    counter: Arc<Mutex<u64>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl PacketCollector {
    pub fn new() -> Self {
        Self {
            packets: Arc::new(Mutex::new(Vec::new())),
            capturing: Arc::new(Mutex::new(false)),
            error: Arc::new(Mutex::new(None)),
            dns_cache: DnsCache::new(),
            counter: Arc::new(Mutex::new(0)),
            handle: None,
        }
    }

    pub fn start_capture(&mut self, interface: &str) {
        {
            let mut cap = self.capturing.lock().unwrap();
            if *cap {
                return;
            }
            *cap = true;
        }
        *self.error.lock().unwrap() = None;

        let packets = Arc::clone(&self.packets);
        let capturing = Arc::clone(&self.capturing);
        let error = Arc::clone(&self.error);
        let counter = Arc::clone(&self.counter);
        let dns = self.dns_cache.clone();
        let iface = interface.to_string();

        self.handle = Some(thread::spawn(move || {
            // Try with promiscuous mode first, fall back to non-promiscuous
            // (some interfaces like loopback don't support promisc on macOS)
            let cap = pcap::Capture::from_device(iface.as_str())
                .and_then(|c| c.promisc(true).snaplen(65535).timeout(100).open())
                .or_else(|_| {
                    pcap::Capture::from_device(iface.as_str())
                        .and_then(|c| c.promisc(false).snaplen(65535).timeout(100).open())
                });

            let mut cap = match cap {
                Ok(c) => c,
                Err(e) => {
                    let msg = if e.to_string().contains("Permission denied") {
                        "Permission denied — run with sudo".to_string()
                    } else {
                        format!("Capture failed: {e}")
                    };
                    *error.lock().unwrap() = Some(msg);
                    *capturing.lock().unwrap() = false;
                    return;
                }
            };

            while *capturing.lock().unwrap() {
                match cap.next_packet() {
                    Ok(packet) => {
                        if let Some(parsed) = parse_packet(packet.data, &counter, &dns) {
                            let mut pkts = packets.lock().unwrap();
                            pkts.push(parsed);
                            if pkts.len() > MAX_PACKETS {
                                let excess = pkts.len() - MAX_PACKETS;
                                pkts.drain(0..excess);
                            }
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => continue,
                    Err(_) => break,
                }
            }
        }));
    }

    pub fn stop_capture(&mut self) {
        *self.capturing.lock().unwrap() = false;
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }

    pub fn clear(&self) {
        self.packets.lock().unwrap().clear();
    }

    pub fn is_capturing(&self) -> bool {
        *self.capturing.lock().unwrap()
    }

    pub fn get_error(&self) -> Option<String> {
        self.error.lock().unwrap().clone()
    }

    pub fn get_packets(&self) -> Vec<CapturedPacket> {
        self.packets.lock().unwrap().clone()
    }
}

impl Drop for PacketCollector {
    fn drop(&mut self) {
        self.stop_capture();
    }
}

// ── Packet parsing ──────────────────────────────────────────

fn parse_packet(data: &[u8], counter: &Arc<Mutex<u64>>, dns: &DnsCache) -> Option<CapturedPacket> {
    if data.len() < 14 {
        return None;
    }

    let mut details = vec![format!("Frame: {} bytes on wire", data.len())];

    let src_mac = format_mac(&data[6..12]);
    let dst_mac = format_mac(&data[0..6]);
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    let ether_name = match ethertype {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86DD => "IPv6",
        _ => "Unknown",
    };
    details.push(format!("Ethernet: {} → {}, Type: {} (0x{:04x})", src_mac, dst_mac, ether_name, ethertype));

    match ethertype {
        0x0800 => parse_ipv4_packet(data, &data[14..], &mut details, counter, dns),
        0x0806 => {
            let info = parse_arp(&data[14..], &mut details);
            Some(build_packet(counter, "ARP", data.len() as u32, "—", "—", None, None, &info, details, &[], data, dns))
        }
        0x86DD => parse_ipv6_packet(data, &data[14..], &mut details, counter, dns),
        _ => None,
    }
}

// Transport parse result: (protocol, src_port, dst_port, info, app_payload_offset)
// app_payload_offset is relative to the transport data start
type TransportResult = (String, Option<u16>, Option<u16>, String, usize);

fn parse_ipv4_packet(
    raw: &[u8], data: &[u8], details: &mut Vec<String>, counter: &Arc<Mutex<u64>>, dns: &DnsCache,
) -> Option<CapturedPacket> {
    if data.len() < 20 {
        return None;
    }
    let ihl = ((data[0] & 0x0F) as usize) * 4;
    let total_len = u16::from_be_bytes([data[2], data[3]]);
    let ttl = data[8];
    let protocol_num = data[9];
    let src = format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]);
    let dst = format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]);

    details.push(format!(
        "IPv4: {} → {}, TTL: {}, Proto: {} ({}), Len: {}",
        src, dst, ttl, ip_protocol_name(protocol_num), protocol_num, total_len
    ));

    let transport_data = if data.len() > ihl { &data[ihl..] } else { &[] };
    let (protocol, src_port, dst_port, info, payload_off) =
        parse_transport(protocol_num, transport_data, &src, &dst, details);

    let app_payload = if transport_data.len() > payload_off {
        &transport_data[payload_off..]
    } else {
        &[]
    };

    Some(build_packet(
        counter, &protocol, raw.len() as u32,
        &src, &dst, src_port, dst_port, &info, details.clone(), app_payload, raw, dns,
    ))
}

fn parse_ipv6_packet(
    raw: &[u8], data: &[u8], details: &mut Vec<String>, counter: &Arc<Mutex<u64>>, dns: &DnsCache,
) -> Option<CapturedPacket> {
    if data.len() < 40 {
        return None;
    }
    let payload_len = u16::from_be_bytes([data[4], data[5]]);
    let next_header = data[6];
    let hop_limit = data[7];
    let src = format_ipv6(&data[8..24]);
    let dst = format_ipv6(&data[24..40]);

    details.push(format!(
        "IPv6: {} → {}, Hop Limit: {}, Next: {} ({}), Payload: {}",
        src, dst, hop_limit, ip_protocol_name(next_header), next_header, payload_len
    ));

    let transport_data = if data.len() > 40 { &data[40..] } else { &[] };
    let (protocol, src_port, dst_port, info, payload_off) =
        parse_transport(next_header, transport_data, &src, &dst, details);

    let app_payload = if transport_data.len() > payload_off {
        &transport_data[payload_off..]
    } else {
        &[]
    };

    Some(build_packet(
        counter, &protocol, raw.len() as u32,
        &src, &dst, src_port, dst_port, &info, details.clone(), app_payload, raw, dns,
    ))
}

fn parse_transport(
    proto: u8, data: &[u8], src_ip: &str, dst_ip: &str, details: &mut Vec<String>,
) -> TransportResult {
    match proto {
        6 if data.len() >= 20 => parse_tcp(data, src_ip, dst_ip, details),
        17 if data.len() >= 8 => parse_udp(data, src_ip, dst_ip, details),
        1 => {
            let r = parse_icmp(data, src_ip, dst_ip, details);
            (r.0, r.1, r.2, r.3, data.len())
        }
        58 => {
            let r = parse_icmpv6(data, src_ip, dst_ip, details);
            (r.0, r.1, r.2, r.3, data.len())
        }
        _ => {
            let name = ip_protocol_name(proto);
            details.push(format!("{}: {} → {}", name, src_ip, dst_ip));
            (name.clone(), None, None, format!("{} → {} {}", src_ip, dst_ip, name), data.len())
        }
    }
}

fn parse_tcp(
    data: &[u8], src_ip: &str, dst_ip: &str, details: &mut Vec<String>,
) -> TransportResult {
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset = ((data[12] >> 4) as usize) * 4;
    let flags = data[13];
    let window = u16::from_be_bytes([data[14], data[15]]);
    let flag_str = tcp_flags(flags);

    let src_svc = port_label(src_port);
    let dst_svc = port_label(dst_port);

    let mut detail = format!(
        "TCP: {} ({}) → {} ({}), Seq: {}, Flags: [{}], Win: {}",
        src_port, src_svc, dst_port, dst_svc, seq, flag_str, window
    );
    if flags & 0x10 != 0 {
        detail.push_str(&format!(", Ack: {}", ack));
    }
    details.push(detail);

    // Check for application-layer protocols in TCP payload
    let payload = if data.len() > data_offset { &data[data_offset..] } else { &[] };

    // DNS over TCP (port 53)
    if (src_port == 53 || dst_port == 53) && payload.len() > 2 {
        let dns_data = &payload[2..];
        if let Some((dns_info, dns_detail)) = parse_dns(dns_data) {
            details.push(dns_detail);
            let info = format!("{} → {} {}", src_ip, dst_ip, dns_info);
            return ("DNS".into(), Some(src_port), Some(dst_port), info, data_offset);
        }
    }

    // TLS
    if !payload.is_empty() {
        if let Some((tls_info, tls_detail)) = parse_tls(payload) {
            details.push(tls_detail);
            let info = format!(
                "{}:{} → {}:{} {} [{}]",
                src_ip, src_port, dst_ip, dst_port, tls_info, flag_str
            );
            return ("TLS".into(), Some(src_port), Some(dst_port), info, data_offset);
        }
    }

    // HTTP
    if !payload.is_empty() {
        if let Some((http_info, http_detail)) = parse_http(payload) {
            details.push(http_detail);
            let info = format!("{}:{} → {}:{} {}", src_ip, src_port, dst_ip, dst_port, http_info);
            return ("HTTP".into(), Some(src_port), Some(dst_port), info, data_offset);
        }
    }

    let payload_len = payload.len();
    let info = format!(
        "{}:{} → {}:{} [{}] Seq={} Win={}{} Payload={}",
        src_ip, src_port, dst_ip, dst_port, flag_str, seq, window,
        if flags & 0x10 != 0 { format!(" Ack={}", ack) } else { String::new() },
        payload_len
    );

    let proto = if dst_svc != "—" {
        dst_svc.to_string()
    } else if src_svc != "—" {
        src_svc.to_string()
    } else {
        "TCP".into()
    };

    (proto, Some(src_port), Some(dst_port), info, data_offset)
}

fn parse_udp(
    data: &[u8], src_ip: &str, dst_ip: &str, details: &mut Vec<String>,
) -> TransportResult {
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let udp_len = u16::from_be_bytes([data[4], data[5]]);

    let src_svc = port_label(src_port);
    let dst_svc = port_label(dst_port);

    details.push(format!(
        "UDP: {} ({}) → {} ({}), Len: {}",
        src_port, src_svc, dst_port, dst_svc, udp_len
    ));

    let payload = if data.len() > 8 { &data[8..] } else { &[] };

    // DNS
    if (src_port == 53 || dst_port == 53 || src_port == 5353 || dst_port == 5353)
        && !payload.is_empty()
    {
        let proto_name = if src_port == 5353 || dst_port == 5353 { "mDNS" } else { "DNS" };
        if let Some((dns_info, dns_detail)) = parse_dns(payload) {
            details.push(dns_detail);
            let info = format!("{} → {} {}", src_ip, dst_ip, dns_info);
            return (proto_name.into(), Some(src_port), Some(dst_port), info, 8);
        }
    }

    // DHCP
    if (src_port == 67 || src_port == 68) && (dst_port == 67 || dst_port == 68) {
        let dhcp_info = parse_dhcp(payload);
        details.push(format!("DHCP: {}", dhcp_info));
        let info = format!("{} → {} {}", src_ip, dst_ip, dhcp_info);
        return ("DHCP".into(), Some(src_port), Some(dst_port), info, 8);
    }

    // NTP
    if src_port == 123 || dst_port == 123 {
        let ntp_info = parse_ntp(payload);
        details.push(format!("NTP: {}", ntp_info));
        let info = format!("{} → {} {}", src_ip, dst_ip, ntp_info);
        return ("NTP".into(), Some(src_port), Some(dst_port), info, 8);
    }

    let svc = if dst_svc != "—" { dst_svc } else { src_svc };
    let info = format!(
        "{}:{} → {}:{} Len={}{}",
        src_ip, src_port, dst_ip, dst_port, udp_len,
        if svc != "—" { format!(" ({})", svc) } else { String::new() }
    );

    let proto = if svc != "—" { svc.to_string() } else { "UDP".into() };
    (proto, Some(src_port), Some(dst_port), info, 8)
}

fn parse_icmp(
    data: &[u8], src_ip: &str, dst_ip: &str, details: &mut Vec<String>,
) -> (String, Option<u16>, Option<u16>, String) {
    if data.len() < 4 {
        details.push("ICMP: (truncated)".into());
        return ("ICMP".into(), None, None, format!("{} → {} ICMP", src_ip, dst_ip));
    }
    let icmp_type = data[0];
    let icmp_code = data[1];
    let type_name = icmp_type_name(icmp_type, icmp_code);

    let extra = if (icmp_type == 0 || icmp_type == 8) && data.len() >= 8 {
        let id = u16::from_be_bytes([data[4], data[5]]);
        let seq = u16::from_be_bytes([data[6], data[7]]);
        format!(", Id={}, Seq={}", id, seq)
    } else {
        String::new()
    };

    details.push(format!("ICMP: {}{}", type_name, extra));
    let info = format!("{} → {} {}{}", src_ip, dst_ip, type_name, extra);
    ("ICMP".into(), None, None, info)
}

fn parse_icmpv6(
    data: &[u8], src_ip: &str, dst_ip: &str, details: &mut Vec<String>,
) -> (String, Option<u16>, Option<u16>, String) {
    if data.len() < 4 {
        details.push("ICMPv6: (truncated)".into());
        return ("ICMPv6".into(), None, None, format!("{} → {} ICMPv6", src_ip, dst_ip));
    }
    let icmp_type = data[0];
    let type_name = icmpv6_type_name(icmp_type);
    details.push(format!("ICMPv6: {}", type_name));
    let info = format!("{} → {} {}", src_ip, dst_ip, type_name);
    ("ICMPv6".into(), None, None, info)
}

// ── Application-layer parsers ───────────────────────────────

fn parse_dns(data: &[u8]) -> Option<(String, String)> {
    if data.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let is_response = flags & 0x8000 != 0;
    let qd_count = u16::from_be_bytes([data[4], data[5]]);
    let an_count = u16::from_be_bytes([data[6], data[7]]);

    if is_response {
        let rcode = flags & 0x000F;
        let rcode_str = match rcode {
            0 => "No Error",
            1 => "Format Error",
            2 => "Server Failure",
            3 => "Name Error (NXDOMAIN)",
            4 => "Not Implemented",
            5 => "Refused",
            _ => "Unknown",
        };
        let info = format!("DNS Response, {} answers, {}", an_count, rcode_str);
        let detail = format!("DNS: Response, Answers: {}, Rcode: {}", an_count, rcode_str);
        Some((info, detail))
    } else {
        // Parse query name
        let name = parse_dns_name(data, 12).unwrap_or_else(|| "?".into());
        let qtype = dns_query_type(data, 12, &name);
        let info = format!("DNS Query {} {}", qtype, name);
        let detail = format!("DNS: Query, Questions: {}, Name: {}, Type: {}", qd_count, name, qtype);
        Some((info, detail))
    }
}

fn parse_dns_name(data: &[u8], offset: usize) -> Option<String> {
    let mut name = String::new();
    let mut pos = offset;
    let mut first = true;
    for _ in 0..128 {
        if pos >= data.len() {
            return None;
        }
        let len = data[pos] as usize;
        if len == 0 {
            break;
        }
        if len >= 0xC0 {
            break;
        }
        if !first {
            name.push('.');
        }
        first = false;
        pos += 1;
        if pos + len > data.len() {
            return None;
        }
        name.push_str(&String::from_utf8_lossy(&data[pos..pos + len]));
        pos += len;
    }
    if name.is_empty() { None } else { Some(name) }
}

fn dns_query_type(data: &[u8], start: usize, _name: &str) -> &'static str {
    // Skip past the name to find the QTYPE
    let mut pos = start;
    for _ in 0..128 {
        if pos >= data.len() { return "?"; }
        let len = data[pos] as usize;
        if len == 0 { pos += 1; break; }
        if len >= 0xC0 { pos += 2; break; }
        pos += 1 + len;
    }
    if pos + 2 > data.len() { return "?"; }
    let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        255 => "ANY",
        65 => "HTTPS",
        _ => "?",
    }
}

fn parse_tls(data: &[u8]) -> Option<(String, String)> {
    if data.len() < 6 {
        return None;
    }
    let content_type = data[0];
    if content_type != 0x16 {
        return None; // Not a TLS handshake
    }
    let tls_major = data[1];
    let tls_minor = data[2];
    if tls_major < 3 {
        return None;
    }
    let version = match (tls_major, tls_minor) {
        (3, 0) => "SSL 3.0",
        (3, 1) => "TLS 1.0",
        (3, 2) => "TLS 1.1",
        (3, 3) => "TLS 1.2",
        (3, 4) => "TLS 1.3",
        _ => "TLS",
    };

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + 1 || record_len < 1 {
        return None;
    }
    let handshake_type = data[5];
    match handshake_type {
        1 => {
            // ClientHello — try to extract SNI
            let sni = extract_sni(&data[5..]);
            let sni_str = sni.as_deref().unwrap_or("—");
            let info = format!("Client Hello ({}), SNI: {}", version, sni_str);
            let detail = format!("TLS: Client Hello, Version: {}, SNI: {}", version, sni_str);
            Some((info, detail))
        }
        2 => {
            let info = format!("Server Hello ({})", version);
            let detail = format!("TLS: Server Hello, Version: {}", version);
            Some((info, detail))
        }
        11 => Some(("Certificate".into(), format!("TLS: Certificate, Version: {}", version))),
        14 => Some(("Server Hello Done".into(), format!("TLS: Server Hello Done"))),
        16 => Some(("Client Key Exchange".into(), format!("TLS: Client Key Exchange"))),
        _ => {
            let info = format!("Handshake type {}", handshake_type);
            let detail = format!("TLS: Handshake type {}, Version: {}", handshake_type, version);
            Some((info, detail))
        }
    }
}

fn extract_sni(handshake: &[u8]) -> Option<String> {
    // ClientHello structure:
    // handshake_type(1) + length(3) + client_version(2) + random(32) = 38 bytes
    // then session_id_length(1) + session_id(var)
    if handshake.len() < 39 {
        return None;
    }
    let mut pos = 38;
    // Session ID
    if pos >= handshake.len() { return None; }
    let sid_len = handshake[pos] as usize;
    pos += 1 + sid_len;
    // Cipher suites
    if pos + 2 > handshake.len() { return None; }
    let cs_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2 + cs_len;
    // Compression methods
    if pos >= handshake.len() { return None; }
    let cm_len = handshake[pos] as usize;
    pos += 1 + cm_len;
    // Extensions length
    if pos + 2 > handshake.len() { return None; }
    let ext_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;

    while pos + 4 <= ext_end && pos + 4 <= handshake.len() {
        let ext_type = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
        pos += 4;
        if ext_type == 0 {
            // SNI extension
            if pos + 5 <= handshake.len() && ext_data_len >= 5 {
                let name_len = u16::from_be_bytes([handshake[pos + 3], handshake[pos + 4]]) as usize;
                let name_start = pos + 5;
                if name_start + name_len <= handshake.len() {
                    return Some(String::from_utf8_lossy(&handshake[name_start..name_start + name_len]).to_string());
                }
            }
            return None;
        }
        pos += ext_data_len;
    }
    None
}

fn parse_http(data: &[u8]) -> Option<(String, String)> {
    let methods = [
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "PATCH ", "OPTIONS ", "HTTP/",
    ];
    let start = String::from_utf8_lossy(&data[..data.len().min(256)]);
    for method in &methods {
        if start.starts_with(method) {
            let first_line = start.lines().next().unwrap_or(&start);
            let truncated = if first_line.len() > 80 {
                format!("{}…", &first_line[..80])
            } else {
                first_line.to_string()
            };
            let detail = format!("HTTP: {}", truncated);
            return Some((truncated.to_string(), detail));
        }
    }
    None
}

fn parse_dhcp(data: &[u8]) -> String {
    if data.is_empty() {
        return "DHCP".into();
    }
    let op = data[0];
    match op {
        1 => "DHCP Discover/Request".into(),
        2 => "DHCP Offer/ACK".into(),
        _ => format!("DHCP op={}", op),
    }
}

fn parse_ntp(data: &[u8]) -> String {
    if data.is_empty() {
        return "NTP".into();
    }
    let li_vn_mode = data[0];
    let mode = li_vn_mode & 0x07;
    let version = (li_vn_mode >> 3) & 0x07;
    let mode_str = match mode {
        1 => "Symmetric Active",
        2 => "Symmetric Passive",
        3 => "Client",
        4 => "Server",
        5 => "Broadcast",
        6 => "Control",
        _ => "Unknown",
    };
    format!("NTPv{} {}", version, mode_str)
}

// ── Build packet ────────────────────────────────────────────

fn build_packet(
    counter: &Arc<Mutex<u64>>,
    protocol: &str,
    length: u32,
    src_ip: &str,
    dst_ip: &str,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    info: &str,
    details: Vec<String>,
    payload: &[u8],
    raw: &[u8],
    dns: &DnsCache,
) -> CapturedPacket {
    let mut cnt = counter.lock().unwrap();
    *cnt += 1;
    let id = *cnt;
    let timestamp = chrono::Local::now().format("%H:%M:%S%.3f").to_string();

    // Queue reverse DNS lookups (non-blocking — results appear on next render)
    let src_host = dns.lookup(src_ip);
    let dst_host = dns.lookup(dst_ip);

    let hex_lines = raw
        .chunks(16)
        .enumerate()
        .map(|(i, chunk)| {
            let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
            format!("{:04x}  {}", i * 16, hex.join(" "))
        })
        .collect::<Vec<_>>()
        .join("\n");

    let ascii_lines = raw
        .chunks(16)
        .enumerate()
        .map(|(i, chunk)| {
            let ascii: String = chunk
                .iter()
                .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                .collect();
            format!("{:04x}  {}", i * 16, ascii)
        })
        .collect::<Vec<_>>()
        .join("\n");

    // Extract readable text from the application payload
    let payload_text = extract_readable_payload(payload);

    // Add resolved hostnames to the details
    let mut details = details;
    if src_host.is_some() || dst_host.is_some() {
        let src_label = src_host.as_deref().unwrap_or(src_ip);
        let dst_label = dst_host.as_deref().unwrap_or(dst_ip);
        details.push(format!("DNS: {} → {}", src_label, dst_label));
    }

    CapturedPacket {
        id,
        timestamp,
        src_ip: src_ip.to_string(),
        dst_ip: dst_ip.to_string(),
        src_host,
        dst_host,
        protocol: protocol.to_string(),
        length,
        src_port,
        dst_port,
        info: info.to_string(),
        details,
        payload_text,
        raw_hex: hex_lines,
        raw_ascii: ascii_lines,
    }
}

fn extract_readable_payload(payload: &[u8]) -> String {
    if payload.is_empty() {
        return String::new();
    }

    // Check how much of the payload is printable text
    let printable = payload.iter()
        .take(2048)
        .filter(|&&b| b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\r' || b == b'\t')
        .count();

    let sample_len = payload.len().min(2048);
    let ratio = printable as f64 / sample_len as f64;

    if ratio > 0.7 {
        // Mostly text — show it cleaned up
        let text: String = payload.iter()
            .take(2048)
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' || b == b'\t' { b as char }
                else if b == b'\n' || b == b'\r' { '\n' }
                else { '·' }
            })
            .collect();
        // Collapse multiple newlines and trim
        let mut result = String::new();
        let mut prev_newline = false;
        for ch in text.chars() {
            if ch == '\n' {
                if !prev_newline {
                    result.push('\n');
                }
                prev_newline = true;
            } else {
                prev_newline = false;
                result.push(ch);
            }
        }
        let trimmed = result.trim().to_string();
        if payload.len() > 2048 {
            format!("{}\n… ({} bytes total)", trimmed, payload.len())
        } else {
            trimmed
        }
    } else if !payload.is_empty() {
        // Binary data — show a summary
        format!("[{} bytes binary data]", payload.len())
    } else {
        String::new()
    }
}

// ── Helpers ─────────────────────────────────────────────────

fn format_mac(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

fn format_ipv6(bytes: &[u8]) -> String {
    bytes.chunks(2)
        .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
        .collect::<Vec<_>>()
        .join(":")
}

fn tcp_flags(flags: u8) -> String {
    let mut s = Vec::new();
    if flags & 0x01 != 0 { s.push("FIN"); }
    if flags & 0x02 != 0 { s.push("SYN"); }
    if flags & 0x04 != 0 { s.push("RST"); }
    if flags & 0x08 != 0 { s.push("PSH"); }
    if flags & 0x10 != 0 { s.push("ACK"); }
    if flags & 0x20 != 0 { s.push("URG"); }
    if s.is_empty() { "NONE".into() } else { s.join(",") }
}

fn ip_protocol_name(proto: u8) -> String {
    match proto {
        1 => "ICMP".into(),
        2 => "IGMP".into(),
        6 => "TCP".into(),
        17 => "UDP".into(),
        41 => "IPv6-encap".into(),
        47 => "GRE".into(),
        58 => "ICMPv6".into(),
        89 => "OSPF".into(),
        132 => "SCTP".into(),
        _ => format!("Proto({})", proto),
    }
}

pub fn port_label(port: u16) -> &'static str {
    match port {
        20 => "FTP-Data",
        21 => "FTP",
        22 => "SSH",
        25 => "SMTP",
        53 => "DNS",
        67 => "DHCP-S",
        68 => "DHCP-C",
        80 => "HTTP",
        110 => "POP3",
        123 => "NTP",
        143 => "IMAP",
        443 => "HTTPS",
        465 => "SMTPS",
        587 => "Submission",
        993 => "IMAPS",
        995 => "POP3S",
        1883 => "MQTT",
        3306 => "MySQL",
        3389 => "RDP",
        5222 => "XMPP",
        5353 => "mDNS",
        5432 => "PostgreSQL",
        6379 => "Redis",
        8080 => "HTTP-Alt",
        8443 => "HTTPS-Alt",
        27017 => "MongoDB",
        _ => "—",
    }
}

fn icmp_type_name(icmp_type: u8, code: u8) -> String {
    match icmp_type {
        0 => "Echo Reply".into(),
        3 => {
            let reason = match code {
                0 => "Network Unreachable",
                1 => "Host Unreachable",
                2 => "Protocol Unreachable",
                3 => "Port Unreachable",
                4 => "Fragmentation Needed",
                13 => "Administratively Prohibited",
                _ => "Unreachable",
            };
            format!("Dest Unreachable: {}", reason)
        }
        4 => "Source Quench".into(),
        5 => {
            let redir = match code {
                0 => "for Network",
                1 => "for Host",
                _ => "",
            };
            format!("Redirect {}", redir)
        }
        8 => "Echo Request".into(),
        9 => "Router Advertisement".into(),
        10 => "Router Solicitation".into(),
        11 => {
            let reason = if code == 0 { "TTL Exceeded" } else { "Fragment Reassembly Exceeded" };
            format!("Time Exceeded: {}", reason)
        }
        _ => format!("Type {} Code {}", icmp_type, code),
    }
}

fn icmpv6_type_name(icmp_type: u8) -> String {
    match icmp_type {
        1 => "Dest Unreachable".into(),
        2 => "Packet Too Big".into(),
        3 => "Time Exceeded".into(),
        128 => "Echo Request".into(),
        129 => "Echo Reply".into(),
        133 => "Router Solicitation".into(),
        134 => "Router Advertisement".into(),
        135 => "Neighbor Solicitation".into(),
        136 => "Neighbor Advertisement".into(),
        _ => format!("Type {}", icmp_type),
    }
}

fn parse_arp(data: &[u8], details: &mut Vec<String>) -> String {
    if data.len() < 28 {
        details.push("ARP: (truncated)".into());
        return "ARP (truncated)".into();
    }
    let op = u16::from_be_bytes([data[6], data[7]]);
    let sender_mac = format_mac(&data[8..14]);
    let sender_ip = format!("{}.{}.{}.{}", data[14], data[15], data[16], data[17]);
    let target_mac = format_mac(&data[18..24]);
    let target_ip = format!("{}.{}.{}.{}", data[24], data[25], data[26], data[27]);

    let info = match op {
        1 => {
            details.push(format!("ARP: Request — Who has {}? Tell {} ({})", target_ip, sender_ip, sender_mac));
            format!("Who has {}? Tell {}", target_ip, sender_ip)
        }
        2 => {
            details.push(format!("ARP: Reply — {} is at {}", sender_ip, sender_mac));
            format!("{} is at {}", sender_ip, sender_mac)
        }
        _ => {
            details.push(format!("ARP: op={}, {} ({}) → {} ({})", op, sender_ip, sender_mac, target_ip, target_mac));
            format!("ARP op={}", op)
        }
    };
    info
}
