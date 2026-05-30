//! PCAP export: write captured packets to a libpcap-format file, plus the
//! timestamp helper it uses.

use super::CapturedPacket;

pub fn export_pcap(packets: &[CapturedPacket], path: &str) -> Result<usize, String> {
    use std::io::Write;

    let mut file =
        std::fs::File::create(path).map_err(|e| format!("Failed to create {path}: {e}"))?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcap_timestamp_normal() {
        let (sec, usec) = parse_timestamp_for_pcap("12:30:45.123");
        assert_eq!(sec, 12 * 3600 + 30 * 60 + 45);
        assert_eq!(usec, 123_000);
    }
    #[test]
    fn test_pcap_timestamp_midnight() {
        let (sec, usec) = parse_timestamp_for_pcap("00:00:00.000");
        assert_eq!(sec, 0);
        assert_eq!(usec, 0);
    }
    #[test]
    fn test_pcap_timestamp_invalid() {
        assert_eq!(parse_timestamp_for_pcap("garbage"), (0, 0));
    }
}
