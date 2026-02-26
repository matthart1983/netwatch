use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};
use std::thread;

const MAX_PACKETS: usize = 5000;
const DNS_CACHE_MAX: usize = 4096;
const MAX_STREAM_SEGMENTS: usize = 10_000;
const MAX_STREAM_BYTES: usize = 2 * 1024 * 1024;

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
    pub raw_bytes: Vec<u8>,
    pub stream_index: Option<u32>,
    pub tcp_flags: Option<u8>,
    pub expert: ExpertSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpertSeverity {
    Chat,     // normal informational (SYN, DNS query)
    Note,     // noteworthy (FIN, DNS response)
    Warn,     // warning (zero window, ICMP unreachable)
    Error,    // error (RST, DNS NXDOMAIN/SERVFAIL)
}

pub fn classify_expert(protocol: &str, info: &str, tcp_flags: Option<u8>) -> ExpertSeverity {
    // TCP RST → Error
    if let Some(flags) = tcp_flags {
        if flags & 0x04 != 0 {
            return ExpertSeverity::Error;
        }
        // SYN (without ACK) → Chat (connection initiation)
        if flags & 0x02 != 0 && flags & 0x10 == 0 {
            return ExpertSeverity::Chat;
        }
        // FIN → Note (connection teardown)
        if flags & 0x01 != 0 {
            return ExpertSeverity::Note;
        }
    }

    // DNS errors
    if protocol == "DNS" {
        if info.contains("NXDOMAIN") || info.contains("Server Failure") || info.contains("Refused") {
            return ExpertSeverity::Error;
        }
        if info.contains("Format Error") {
            return ExpertSeverity::Warn;
        }
        if info.contains("Response") {
            return ExpertSeverity::Note;
        }
        // DNS query
        return ExpertSeverity::Chat;
    }

    // ICMP errors
    if protocol == "ICMP" || protocol == "ICMPv6" {
        if info.contains("Unreachable") || info.contains("Time Exceeded") {
            return ExpertSeverity::Warn;
        }
        if info.contains("Redirect") {
            return ExpertSeverity::Note;
        }
    }

    // ARP
    if protocol == "ARP" {
        return ExpertSeverity::Chat;
    }

    // TCP zero window in info string
    if info.contains("Win=0 ") || info.contains("Win=0,") {
        return ExpertSeverity::Warn;
    }

    // TLS
    if protocol == "TLS" {
        if info.contains("Client Hello") {
            return ExpertSeverity::Chat;
        }
        if info.contains("Server Hello") {
            return ExpertSeverity::Note;
        }
    }

    // HTTP errors  
    if protocol == "HTTP" {
        if info.contains("HTTP/1.1 4") || info.contains("HTTP/1.1 5") ||
           info.contains("HTTP/1.0 4") || info.contains("HTTP/1.0 5") {
            return ExpertSeverity::Warn;
        }
    }

    ExpertSeverity::Chat
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

// ── Stream tracking ─────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct StreamKey {
    pub protocol: StreamProtocol,
    pub addr_a: (String, u16),
    pub addr_b: (String, u16),
}

impl StreamKey {
    pub fn new(protocol: StreamProtocol, ip1: &str, port1: u16, ip2: &str, port2: u16) -> Self {
        let a = (ip1.to_string(), port1);
        let b = (ip2.to_string(), port2);
        if a <= b {
            Self { protocol, addr_a: a, addr_b: b }
        } else {
            Self { protocol, addr_a: b, addr_b: a }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirection {
    AtoB,
    BtoA,
}

#[derive(Debug, Clone)]
pub struct StreamSegment {
    #[allow(dead_code)]
    pub packet_id: u64,
    #[allow(dead_code)]
    pub timestamp: String,
    pub direction: StreamDirection,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Stream {
    #[allow(dead_code)]
    pub index: u32,
    pub key: StreamKey,
    pub segments: Vec<StreamSegment>,
    pub total_bytes_a_to_b: u64,
    pub total_bytes_b_to_a: u64,
    pub packet_count: u32,
    pub initiator: Option<(String, u16)>,
    total_payload_bytes: usize,
}

pub struct StreamTracker {
    streams: HashMap<StreamKey, u32>,
    pub all_streams: Vec<Stream>,
    next_index: u32,
}

impl StreamTracker {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            all_streams: Vec::new(),
            next_index: 0,
        }
    }

    pub fn track_packet(
        &mut self,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
        protocol: StreamProtocol,
        payload: &[u8],
        packet_id: u64,
        timestamp: &str,
        tcp_flags: Option<u8>,
    ) -> u32 {
        let key = StreamKey::new(protocol, src_ip, src_port, dst_ip, dst_port);

        let stream_index = if let Some(&idx) = self.streams.get(&key) {
            idx
        } else {
            let idx = self.next_index;
            self.next_index += 1;
            self.streams.insert(key.clone(), idx);
            self.all_streams.push(Stream {
                index: idx,
                key: key.clone(),
                segments: Vec::new(),
                total_bytes_a_to_b: 0,
                total_bytes_b_to_a: 0,
                packet_count: 0,
                initiator: None,
                total_payload_bytes: 0,
            });
            idx
        };

        let stream = &mut self.all_streams[stream_index as usize];
        stream.packet_count += 1;

        let is_a_to_b = key.addr_a == (src_ip.to_string(), src_port);
        let direction = if is_a_to_b {
            StreamDirection::AtoB
        } else {
            StreamDirection::BtoA
        };

        if stream.initiator.is_none() {
            if let Some(flags) = tcp_flags {
                if flags & 0x02 != 0 {
                    stream.initiator = Some((src_ip.to_string(), src_port));
                }
            }
            if stream.initiator.is_none() {
                stream.initiator = Some((src_ip.to_string(), src_port));
            }
        }

        if is_a_to_b {
            stream.total_bytes_a_to_b += payload.len() as u64;
        } else {
            stream.total_bytes_b_to_a += payload.len() as u64;
        }

        if !payload.is_empty()
            && stream.segments.len() < MAX_STREAM_SEGMENTS
            && stream.total_payload_bytes < MAX_STREAM_BYTES
        {
            stream.total_payload_bytes += payload.len();
            stream.segments.push(StreamSegment {
                packet_id,
                timestamp: timestamp.to_string(),
                direction,
                payload: payload.to_vec(),
            });
        }

        stream_index
    }

    pub fn get_stream(&self, index: u32) -> Option<&Stream> {
        self.all_streams.get(index as usize)
    }

    pub fn clear(&mut self) {
        self.streams.clear();
        self.all_streams.clear();
        self.next_index = 0;
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
    pub stream_tracker: Arc<Mutex<StreamTracker>>,
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
            stream_tracker: Arc::new(Mutex::new(StreamTracker::new())),
            counter: Arc::new(Mutex::new(0)),
            handle: None,
        }
    }

    pub fn start_capture(&mut self, interface: &str, bpf_filter: Option<&str>) {
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
        let tracker = Arc::clone(&self.stream_tracker);
        let dns = self.dns_cache.clone();
        let iface = interface.to_string();
        let bpf = bpf_filter.map(|s| s.to_string());

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

            // Apply BPF capture filter if specified
            if let Some(filter) = bpf.as_deref() {
                if let Err(e) = cap.filter(filter, true) {
                    *error.lock().unwrap() = Some(format!("BPF filter error: {e}"));
                    *capturing.lock().unwrap() = false;
                    return;
                }
            }

            while *capturing.lock().unwrap() {
                match cap.next_packet() {
                    Ok(packet) => {
                        if let Some(mut parsed) = parse_packet(packet.data, &counter, &dns) {
                            if let (Some(sp), Some(dp)) = (parsed.src_port, parsed.dst_port) {
                                let proto = if parsed.tcp_flags.is_some() {
                                    StreamProtocol::Tcp
                                } else {
                                    StreamProtocol::Udp
                                };
                                let payload = extract_app_payload(packet.data, proto);
                                let idx = tracker.lock().unwrap().track_packet(
                                    &parsed.src_ip, sp,
                                    &parsed.dst_ip, dp,
                                    proto, &payload,
                                    parsed.id, &parsed.timestamp,
                                    parsed.tcp_flags,
                                );
                                parsed.stream_index = Some(idx);
                            }
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
        self.stream_tracker.lock().unwrap().clear();
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

    pub fn get_stream(&self, index: u32) -> Option<Stream> {
        self.stream_tracker.lock().unwrap().get_stream(index).cloned()
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
            Some(build_packet(counter, "ARP", data.len() as u32, "—", "—", None, None, &info, details, &[], data, dns, None))
        }
        0x86DD => parse_ipv6_packet(data, &data[14..], &mut details, counter, dns),
        _ => None,
    }
}

// Transport parse result: (protocol, src_port, dst_port, info, app_payload_offset, tcp_flags)
// app_payload_offset is relative to the transport data start
type TransportResult = (String, Option<u16>, Option<u16>, String, usize, Option<u8>);

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
    let (protocol, src_port, dst_port, info, payload_off, flags) =
        parse_transport(protocol_num, transport_data, &src, &dst, details);

    let app_payload = if transport_data.len() > payload_off {
        &transport_data[payload_off..]
    } else {
        &[]
    };

    Some(build_packet(
        counter, &protocol, raw.len() as u32,
        &src, &dst, src_port, dst_port, &info, details.clone(), app_payload, raw, dns, flags,
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
    let (protocol, src_port, dst_port, info, payload_off, flags) =
        parse_transport(next_header, transport_data, &src, &dst, details);

    let app_payload = if transport_data.len() > payload_off {
        &transport_data[payload_off..]
    } else {
        &[]
    };

    Some(build_packet(
        counter, &protocol, raw.len() as u32,
        &src, &dst, src_port, dst_port, &info, details.clone(), app_payload, raw, dns, flags,
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
            (r.0, r.1, r.2, r.3, data.len(), None)
        }
        58 => {
            let r = parse_icmpv6(data, src_ip, dst_ip, details);
            (r.0, r.1, r.2, r.3, data.len(), None)
        }
        _ => {
            let name = ip_protocol_name(proto);
            details.push(format!("{}: {} → {}", name, src_ip, dst_ip));
            (name.clone(), None, None, format!("{} → {} {}", src_ip, dst_ip, name), data.len(), None)
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
            return ("DNS".into(), Some(src_port), Some(dst_port), info, data_offset, Some(flags));
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
            return ("TLS".into(), Some(src_port), Some(dst_port), info, data_offset, Some(flags));
        }
    }

    // HTTP
    if !payload.is_empty() {
        if let Some((http_info, http_detail)) = parse_http(payload) {
            details.push(http_detail);
            let info = format!("{}:{} → {}:{} {}", src_ip, src_port, dst_ip, dst_port, http_info);
            return ("HTTP".into(), Some(src_port), Some(dst_port), info, data_offset, Some(flags));
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

    (proto, Some(src_port), Some(dst_port), info, data_offset, Some(flags))
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
            return (proto_name.into(), Some(src_port), Some(dst_port), info, 8, None);
        }
    }

    // DHCP
    if (src_port == 67 || src_port == 68) && (dst_port == 67 || dst_port == 68) {
        let dhcp_info = parse_dhcp(payload);
        details.push(format!("DHCP: {}", dhcp_info));
        let info = format!("{} → {} {}", src_ip, dst_ip, dhcp_info);
        return ("DHCP".into(), Some(src_port), Some(dst_port), info, 8, None);
    }

    // NTP
    if src_port == 123 || dst_port == 123 {
        let ntp_info = parse_ntp(payload);
        details.push(format!("NTP: {}", ntp_info));
        let info = format!("{} → {} {}", src_ip, dst_ip, ntp_info);
        return ("NTP".into(), Some(src_port), Some(dst_port), info, 8, None);
    }

    let svc = if dst_svc != "—" { dst_svc } else { src_svc };
    let info = format!(
        "{}:{} → {}:{} Len={}{}",
        src_ip, src_port, dst_ip, dst_port, udp_len,
        if svc != "—" { format!(" ({})", svc) } else { String::new() }
    );

    let proto = if svc != "—" { svc.to_string() } else { "UDP".into() };
    (proto, Some(src_port), Some(dst_port), info, 8, None)
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
    tcp_flags: Option<u8>,
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

    let expert = classify_expert(protocol, info, tcp_flags);

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
        raw_bytes: raw.to_vec(),
        stream_index: None,
        tcp_flags,
        expert,
    }
}

fn extract_app_payload(raw: &[u8], proto: StreamProtocol) -> Vec<u8> {
    if raw.len() < 14 {
        return Vec::new();
    }
    let ethertype = u16::from_be_bytes([raw[12], raw[13]]);
    let ip_start = 14;
    let transport_start = match ethertype {
        0x0800 => {
            if raw.len() < ip_start + 20 { return Vec::new(); }
            let ihl = ((raw[ip_start] & 0x0F) as usize) * 4;
            ip_start + ihl
        }
        0x86DD => ip_start + 40,
        _ => return Vec::new(),
    };
    if raw.len() <= transport_start {
        return Vec::new();
    }
    match proto {
        StreamProtocol::Tcp => {
            if raw.len() < transport_start + 20 { return Vec::new(); }
            let data_offset = ((raw[transport_start + 12] >> 4) as usize) * 4;
            let payload_start = transport_start + data_offset;
            if raw.len() > payload_start { raw[payload_start..].to_vec() } else { Vec::new() }
        }
        StreamProtocol::Udp => {
            let payload_start = transport_start + 8;
            if raw.len() > payload_start { raw[payload_start..].to_vec() } else { Vec::new() }
        }
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

// ── PCAP export ─────────────────────────────────────────────

pub fn export_pcap(packets: &[CapturedPacket], path: &str) -> Result<usize, String> {
    use std::io::Write;

    let mut file = std::fs::File::create(path)
        .map_err(|e| format!("Failed to create {path}: {e}"))?;

    // Global header: magic, version 2.4, thiszone=0, sigfigs=0, snaplen=65535, network=1 (Ethernet)
    let global_header: [u8; 24] = [
        0xd4, 0xc3, 0xb2, 0xa1, // magic (little-endian)
        0x02, 0x00, 0x04, 0x00, // version 2.4
        0x00, 0x00, 0x00, 0x00, // thiszone
        0x00, 0x00, 0x00, 0x00, // sigfigs
        0xff, 0xff, 0x00, 0x00, // snaplen 65535
        0x01, 0x00, 0x00, 0x00, // network: Ethernet
    ];
    file.write_all(&global_header)
        .map_err(|e| format!("Write error: {e}"))?;

    let mut count = 0;
    for pkt in packets {
        if pkt.raw_bytes.is_empty() {
            continue;
        }
        let len = pkt.raw_bytes.len() as u32;
        // Use current time as a fallback; ideally we'd store capture timestamps
        // Parse HH:MM:SS.mmm from pkt.timestamp
        let (ts_sec, ts_usec) = parse_timestamp_for_pcap(&pkt.timestamp);

        let mut rec_header = [0u8; 16];
        rec_header[0..4].copy_from_slice(&ts_sec.to_le_bytes());
        rec_header[4..8].copy_from_slice(&ts_usec.to_le_bytes());
        rec_header[8..12].copy_from_slice(&len.to_le_bytes());
        rec_header[12..16].copy_from_slice(&len.to_le_bytes());

        file.write_all(&rec_header)
            .map_err(|e| format!("Write error: {e}"))?;
        file.write_all(&pkt.raw_bytes)
            .map_err(|e| format!("Write error: {e}"))?;
        count += 1;
    }

    file.flush().map_err(|e| format!("Flush error: {e}"))?;
    Ok(count)
}

fn parse_timestamp_for_pcap(ts: &str) -> (u32, u32) {
    // Format: "HH:MM:SS.mmm" → seconds since midnight, microseconds
    let parts: Vec<&str> = ts.split(':').collect();
    if parts.len() < 3 {
        return (0, 0);
    }
    let hours: u32 = parts[0].parse().unwrap_or(0);
    let minutes: u32 = parts[1].parse().unwrap_or(0);
    let sec_parts: Vec<&str> = parts[2].split('.').collect();
    let seconds: u32 = sec_parts[0].parse().unwrap_or(0);
    let millis: u32 = sec_parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    let total_sec = hours * 3600 + minutes * 60 + seconds;
    let usec = millis * 1000;
    (total_sec, usec)
}

// ── Display filters ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum FilterExpr {
    Protocol(String),
    SrcIp(String),
    DstIp(String),
    Ip(String),
    Port(u16),
    Stream(u32),
    Contains(String),
    Not(Box<FilterExpr>),
    And(Box<FilterExpr>, Box<FilterExpr>),
    Or(Box<FilterExpr>, Box<FilterExpr>),
}

pub fn parse_filter(input: &str) -> Option<FilterExpr> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }
    let tokens = tokenize(input);
    if tokens.is_empty() {
        return None;
    }
    let (expr, rest) = parse_or(&tokens)?;
    if rest.is_empty() { Some(expr) } else { None }
}

fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&ch) = chars.peek() {
        if ch.is_whitespace() {
            chars.next();
            continue;
        }
        if ch == '!' {
            tokens.push("!".to_string());
            chars.next();
            continue;
        }
        if ch == '=' {
            chars.next();
            if chars.peek() == Some(&'=') { chars.next(); }
            tokens.push("==".to_string());
            continue;
        }
        if ch == '"' || ch == '\'' {
            chars.next();
            let mut s = String::new();
            while let Some(&c) = chars.peek() {
                if c == ch { chars.next(); break; }
                s.push(c);
                chars.next();
            }
            tokens.push(format!("\"{s}\""));
            continue;
        }
        let mut word = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() || c == '=' || c == '!' { break; }
            word.push(c);
            chars.next();
        }
        tokens.push(word);
    }
    tokens
}

fn parse_or<'a>(tokens: &'a [String]) -> Option<(FilterExpr, &'a [String])> {
    let (mut left, mut rest) = parse_and(tokens)?;
    while !rest.is_empty() && rest[0].eq_ignore_ascii_case("or") {
        let (right, r) = parse_and(&rest[1..])?;
        left = FilterExpr::Or(Box::new(left), Box::new(right));
        rest = r;
    }
    Some((left, rest))
}

fn parse_and<'a>(tokens: &'a [String]) -> Option<(FilterExpr, &'a [String])> {
    let (mut left, mut rest) = parse_not(tokens)?;
    while !rest.is_empty() && rest[0].eq_ignore_ascii_case("and") {
        let (right, r) = parse_not(&rest[1..])?;
        left = FilterExpr::And(Box::new(left), Box::new(right));
        rest = r;
    }
    Some((left, rest))
}

fn parse_not<'a>(tokens: &'a [String]) -> Option<(FilterExpr, &'a [String])> {
    if tokens.is_empty() { return None; }
    if tokens[0] == "!" || tokens[0].eq_ignore_ascii_case("not") {
        let (expr, rest) = parse_not(&tokens[1..])?;
        return Some((FilterExpr::Not(Box::new(expr)), rest));
    }
    parse_atom(tokens)
}

fn parse_atom<'a>(tokens: &'a [String]) -> Option<(FilterExpr, &'a [String])> {
    if tokens.is_empty() { return None; }

    // ip.src == x
    if tokens[0].eq_ignore_ascii_case("ip.src") && tokens.len() >= 3 && tokens[1] == "==" {
        return Some((FilterExpr::SrcIp(tokens[2].to_lowercase()), &tokens[3..]));
    }
    // ip.dst == x
    if tokens[0].eq_ignore_ascii_case("ip.dst") && tokens.len() >= 3 && tokens[1] == "==" {
        return Some((FilterExpr::DstIp(tokens[2].to_lowercase()), &tokens[3..]));
    }
    // port [==] N
    if tokens[0].eq_ignore_ascii_case("port") && tokens.len() >= 2 {
        if tokens[1] == "==" && tokens.len() >= 3 {
            if let Ok(p) = tokens[2].parse::<u16>() {
                return Some((FilterExpr::Port(p), &tokens[3..]));
            }
        }
        if let Ok(p) = tokens[1].parse::<u16>() {
            return Some((FilterExpr::Port(p), &tokens[2..]));
        }
    }
    // stream N
    if tokens[0].eq_ignore_ascii_case("stream") && tokens.len() >= 2 {
        if let Ok(n) = tokens[1].parse::<u32>() {
            return Some((FilterExpr::Stream(n), &tokens[2..]));
        }
    }
    // contains "x"
    if tokens[0].eq_ignore_ascii_case("contains") && tokens.len() >= 2 {
        let val = tokens[1].trim_matches('"').to_lowercase();
        return Some((FilterExpr::Contains(val), &tokens[2..]));
    }

    let word = &tokens[0];

    // Bare IP address (contains a dot and digits)
    if word.contains('.') && word.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Some((FilterExpr::Ip(word.to_string()), &tokens[1..]));
    }

    // Known protocol names
    let protocols = ["tcp", "udp", "dns", "mdns", "tls", "http", "arp", "icmp", "icmpv6",
                     "dhcp", "ntp", "ssh", "https", "smtp", "ftp", "imap", "pop3"];
    if protocols.iter().any(|p| word.eq_ignore_ascii_case(p)) {
        return Some((FilterExpr::Protocol(word.to_uppercase()), &tokens[1..]));
    }

    // Bare word → text search
    let val = word.trim_matches('"').to_lowercase();
    Some((FilterExpr::Contains(val), &tokens[1..]))
}

pub fn matches_packet(expr: &FilterExpr, pkt: &CapturedPacket) -> bool {
    match expr {
        FilterExpr::Protocol(p) => pkt.protocol.eq_ignore_ascii_case(p),
        FilterExpr::SrcIp(ip) => pkt.src_ip.contains(ip.as_str()),
        FilterExpr::DstIp(ip) => pkt.dst_ip.contains(ip.as_str()),
        FilterExpr::Ip(ip) => pkt.src_ip.contains(ip.as_str()) || pkt.dst_ip.contains(ip.as_str()),
        FilterExpr::Port(p) => pkt.src_port == Some(*p) || pkt.dst_port == Some(*p),
        FilterExpr::Stream(n) => pkt.stream_index == Some(*n),
        FilterExpr::Contains(s) => {
            pkt.info.to_lowercase().contains(s)
                || pkt.src_ip.to_lowercase().contains(s)
                || pkt.dst_ip.to_lowercase().contains(s)
                || pkt.protocol.to_lowercase().contains(s)
                || pkt.payload_text.to_lowercase().contains(s)
                || pkt.src_host.as_ref().map_or(false, |h| h.to_lowercase().contains(s))
                || pkt.dst_host.as_ref().map_or(false, |h| h.to_lowercase().contains(s))
        }
        FilterExpr::Not(inner) => !matches_packet(inner, pkt),
        FilterExpr::And(a, b) => matches_packet(a, pkt) && matches_packet(b, pkt),
        FilterExpr::Or(a, b) => matches_packet(a, pkt) || matches_packet(b, pkt),
    }
}
