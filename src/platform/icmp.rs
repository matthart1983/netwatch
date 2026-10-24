//! What one ICMP echo came back as, decoded from the status Windows' ICMP API
//! (`IcmpSendEcho2`, `Icmp6SendEcho2`) reports. Platform-neutral so the
//! decoding is unit-tested on every host; only the calls that produce the
//! status (`platform::windows::icmp`) are Windows-only.
//!
//! The API answers with a number where `ping.exe` and `tracert` print a
//! sentence in the display language. Parsing those sentences is why every
//! gateway, DNS and internet probe came back empty on a German install, and
//! why a tracert hop that timed out was stored with "out." as its address.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

// IP_STATUS codes from ipexport.h. Declared here so the decoder builds and is
// tested off Windows; on Windows the block below checks each one against
// windows-sys, which takes them from Microsoft's metadata.
const IP_SUCCESS: u32 = 0;
const IP_DEST_NET_UNREACHABLE: u32 = 11002;
const IP_DEST_HOST_UNREACHABLE: u32 = 11003;
const IP_DEST_PROT_UNREACHABLE: u32 = 11004;
const IP_DEST_PORT_UNREACHABLE: u32 = 11005;
const IP_PACKET_TOO_BIG: u32 = 11009;
const IP_REQ_TIMED_OUT: u32 = 11010;
/// Also `IP_HOP_LIMIT_EXCEEDED`, the IPv6 name for the same code.
const IP_TTL_EXPIRED_TRANSIT: u32 = 11013;
const IP_DEST_UNREACHABLE: u32 = 11040;
const IP_TIME_EXCEEDED: u32 = 11041;
const IP_DEST_SCOPE_MISMATCH: u32 = 11045;

#[cfg(windows)]
const _: () = {
    use windows_sys::Win32::NetworkManagement::IpHelper as w;
    assert!(IP_SUCCESS == w::IP_SUCCESS);
    assert!(IP_DEST_NET_UNREACHABLE == w::IP_DEST_NET_UNREACHABLE);
    assert!(IP_DEST_HOST_UNREACHABLE == w::IP_DEST_HOST_UNREACHABLE);
    assert!(IP_DEST_PROT_UNREACHABLE == w::IP_DEST_PROT_UNREACHABLE);
    assert!(IP_DEST_PORT_UNREACHABLE == w::IP_DEST_PORT_UNREACHABLE);
    assert!(IP_PACKET_TOO_BIG == w::IP_PACKET_TOO_BIG);
    assert!(IP_REQ_TIMED_OUT == w::IP_REQ_TIMED_OUT);
    assert!(IP_TTL_EXPIRED_TRANSIT == w::IP_TTL_EXPIRED_TRANSIT);
    assert!(IP_TTL_EXPIRED_TRANSIT == w::IP_HOP_LIMIT_EXCEEDED);
    assert!(IP_DEST_UNREACHABLE == w::IP_DEST_UNREACHABLE);
    assert!(IP_TIME_EXCEEDED == w::IP_TIME_EXCEEDED);
    assert!(IP_DEST_SCOPE_MISMATCH == w::IP_DEST_SCOPE_MISMATCH);
};

/// The outcome of one echo request.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Echo {
    /// An echo reply: the destination answered.
    Reply { from: IpAddr, rtt_ms: f64 },
    /// The TTL (hop limit) ran out on the way, and the router where it did
    /// said so. One traceroute hop.
    ///
    /// `from` here and in `Unreachable` is `None` when the API reported the
    /// status with no reply to read; `rtt_ms` then holds only the call's
    /// own time, and `Echo::rtt_ms` gives no round trip.
    TimeExceeded { from: Option<IpAddr>, rtt_ms: f64 },
    /// The destination, or a router before it, said the packet cannot be
    /// delivered: unreachable, prohibited, or too big to forward.
    Unreachable { from: Option<IpAddr>, rtt_ms: f64 },
    /// Sent, and nothing answered before the timeout.
    TimedOut,
    /// Nothing to read: the stack refused to send the request (no route, no
    /// resources, a general failure), or reported a status this decoder does
    /// not know. Carries the code, an IP_STATUS or a Win32 error.
    Failed(u32),
}

impl Echo {
    /// Whether the request left this host. A request the stack refused is not
    /// a lost packet, any more than a refused socket is on Unix.
    pub fn was_sent(&self) -> bool {
        !matches!(self, Self::Failed(_))
    }

    /// Whoever answered, when someone did.
    pub fn answered_by(&self) -> Option<IpAddr> {
        match *self {
            Self::Reply { from, .. } => Some(from),
            Self::TimeExceeded { from, .. } | Self::Unreachable { from, .. } => from,
            Self::TimedOut | Self::Failed(_) => None,
        }
    }

    /// The round trip of an answer of any kind; `None` for no answer.
    ///
    /// An unreachable or time-exceeded the API reports with no reply
    /// (`from: None`) came back from nobody, so it has no round trip: the
    /// call's time is the stack's own wait, not a packet's.
    pub fn rtt_ms(&self) -> Option<f64> {
        match *self {
            Self::Reply { rtt_ms, .. }
            | Self::TimeExceeded {
                from: Some(_),
                rtt_ms,
            }
            | Self::Unreachable {
                from: Some(_),
                rtt_ms,
            } => Some(rtt_ms),
            Self::TimeExceeded { from: None, .. }
            | Self::Unreachable { from: None, .. }
            | Self::TimedOut
            | Self::Failed(_) => None,
        }
    }
}

/// Decode one `IcmpSendEcho2` or `Icmp6SendEcho2` call.
///
/// `status` is the reply's `Status` when the call returned a reply, or
/// `GetLastError` when it returned none; the API reports a timeout and most
/// local failures that second way, with no address. `from` is the reply's
/// `Address`, `api_rtt_ms` its `RoundTripTime`, and `elapsed` the wall-clock
/// time the synchronous call took.
pub fn decode(status: u32, from: Option<IpAddr>, api_rtt_ms: u32, elapsed: Duration) -> Echo {
    let rtt_ms = rtt_ms(api_rtt_ms, elapsed);
    match status {
        IP_SUCCESS => match from {
            Some(from) => Echo::Reply { from, rtt_ms },
            // Success with no reply to read is not an answer.
            None => Echo::Failed(status),
        },
        IP_TTL_EXPIRED_TRANSIT | IP_TIME_EXCEEDED => Echo::TimeExceeded { from, rtt_ms },
        IP_DEST_NET_UNREACHABLE
        | IP_DEST_HOST_UNREACHABLE
        | IP_DEST_PROT_UNREACHABLE
        | IP_DEST_PORT_UNREACHABLE
        | IP_DEST_UNREACHABLE
        | IP_DEST_SCOPE_MISMATCH
        | IP_PACKET_TOO_BIG => Echo::Unreachable { from, rtt_ms },
        IP_REQ_TIMED_OUT => Echo::TimedOut,
        other => Echo::Failed(other),
    }
}

/// The round trip of one answer, in milliseconds.
///
/// `RoundTripTime` is whole milliseconds and reads 0 for anything faster, so
/// a LAN gateway at 0.3 ms would show as 0.0, a figure the Unix path never
/// gives: it times each echo itself and reports the fraction. Under a
/// millisecond, then, the call's own wall-clock time stands in, capped at the
/// 1 ms the API vouches for. From 1 ms up the API's figure is used as it is,
/// since it leaves out the call's own overhead.
pub fn rtt_ms(api_rtt_ms: u32, elapsed: Duration) -> f64 {
    if api_rtt_ms == 0 {
        (elapsed.as_secs_f64() * 1000.0).min(1.0)
    } else {
        f64::from(api_rtt_ms)
    }
}

/// Bytes an ICMP error may quote of the packet that caused it: ICMPv6 quotes
/// up to its 1280-byte minimum MTU, ICMPv4 routers up to 576 bytes in all.
const ERROR_QUOTE: usize = 1280;

/// Bytes of reply buffer to hand the API for one echo of `payload` bytes.
///
/// The documented minimum is one reply structure, the payload echoed back,
/// 8 bytes for an ICMP error and an `IO_STATUS_BLOCK`. A router's
/// time-exceeded or unreachable message also carries the start of our own
/// packet, and a buffer too small for it turns a hop that answered into
/// `IP_BUF_TOO_SMALL`, so there is room for a full quote as well.
pub fn reply_buffer_len(reply_struct: usize, payload: usize, io_status_block: usize) -> usize {
    reply_struct + payload + 8 + io_status_block + ERROR_QUOTE
}

/// An `IPAddr`, which is an `in_addr` held in a `u32`: its bytes in memory
/// are the address in network order.
pub fn ipv4_from_in_addr(raw: u32) -> Ipv4Addr {
    Ipv4Addr::from(raw.to_ne_bytes())
}

/// The `IPAddr` the API takes for `ip`.
pub fn in_addr_from_ipv4(ip: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(ip.octets())
}

/// `IPV6_ADDRESS_EX::sin6_addr`: eight 16-bit words, each in network order in
/// memory.
pub fn ipv6_from_words(words: [u16; 8]) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    for (pair, word) in octets.as_chunks_mut::<2>().0.iter_mut().zip(words) {
        *pair = word.to_ne_bytes();
    }
    Ipv6Addr::from(octets)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GATEWAY: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    const ROUTER: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn an_echo_reply_is_a_reply_from_its_sender() {
        assert_eq!(
            decode(IP_SUCCESS, Some(GATEWAY), 12, ms(13)),
            Echo::Reply {
                from: GATEWAY,
                rtt_ms: 12.0
            }
        );
        // A success the call returned no reply for has nothing to read.
        assert_eq!(decode(IP_SUCCESS, None, 0, ms(1)), Echo::Failed(0));
    }

    #[test]
    fn ttl_expiry_is_a_hop_on_both_families() {
        for status in [IP_TTL_EXPIRED_TRANSIT, IP_TIME_EXCEEDED] {
            let e = decode(status, Some(ROUTER), 4, ms(5));
            assert_eq!(
                e,
                Echo::TimeExceeded {
                    from: Some(ROUTER),
                    rtt_ms: 4.0
                }
            );
            assert_eq!(e.answered_by(), Some(ROUTER));
            assert!(e.was_sent());
        }
    }

    #[test]
    fn unreachable_and_too_big_are_answers_that_end_a_path() {
        for status in [
            IP_DEST_NET_UNREACHABLE,
            IP_DEST_HOST_UNREACHABLE,
            IP_DEST_PROT_UNREACHABLE,
            IP_DEST_PORT_UNREACHABLE,
            IP_DEST_UNREACHABLE,
            IP_DEST_SCOPE_MISMATCH,
            IP_PACKET_TOO_BIG,
        ] {
            let e = decode(status, Some(ROUTER), 9, ms(9));
            assert!(matches!(e, Echo::Unreachable { .. }), "{status}");
            assert_eq!(e.rtt_ms(), Some(9.0));
        }
    }

    #[test]
    fn a_status_with_no_reply_has_no_round_trip() {
        // The call returned no reply after 3 s and GetLastError gave the
        // status: ping.exe's bare "Destination host unreachable.".
        for status in [IP_DEST_HOST_UNREACHABLE, IP_TTL_EXPIRED_TRANSIT] {
            let e = decode(status, None, 0, ms(3000));
            assert!(e.was_sent(), "{status}");
            assert_eq!(e.answered_by(), None, "{status}");
            assert_eq!(e.rtt_ms(), None, "{status}");
        }
    }

    #[test]
    fn a_timeout_was_sent_but_not_answered() {
        let e = decode(IP_REQ_TIMED_OUT, None, 0, ms(1000));
        assert_eq!(e, Echo::TimedOut);
        assert!(e.was_sent());
        assert_eq!(e.rtt_ms(), None);
        assert_eq!(e.answered_by(), None);
    }

    #[test]
    fn local_failures_and_unknown_codes_were_not_sent() {
        // IP_GENERAL_FAILURE, IP_BUF_TOO_SMALL, IP_NO_RESOURCES, and the
        // Win32 errors ERROR_INVALID_PARAMETER and ERROR_NETWORK_UNREACHABLE,
        // which tracert prints as "Transmit error: code 1231".
        for status in [11050, 11001, 11006, 87, 1231] {
            let e = decode(status, None, 0, ms(0));
            assert_eq!(e, Echo::Failed(status));
            assert!(!e.was_sent());
            assert_eq!(e.rtt_ms(), None);
        }
    }

    #[test]
    fn a_sub_millisecond_reply_keeps_its_fraction() {
        // The API says 0; the call took 0.31 ms.
        let rtt = rtt_ms(0, Duration::from_micros(310));
        assert!((rtt - 0.31).abs() < 1e-9, "{rtt}");
        // A slow call cannot make a sub-millisecond reply read as more than
        // the API allows.
        assert_eq!(rtt_ms(0, ms(4)), 1.0);
        // From 1 ms up the API's figure stands, whatever the call cost.
        assert_eq!(rtt_ms(1, ms(3)), 1.0);
        assert_eq!(rtt_ms(23, ms(24)), 23.0);
    }

    #[test]
    fn the_reply_buffer_holds_a_quoted_packet() {
        // 64-bit ICMP_ECHO_REPLY is 40 bytes and IO_STATUS_BLOCK 16.
        let len = reply_buffer_len(40, 8, 16);
        assert!(len >= 40 + 8 + 8 + 16, "documented minimum");
        assert!(len >= 40 + ERROR_QUOTE, "room for a router's quote");
    }

    #[test]
    fn addresses_come_out_in_network_order() {
        let v4 = Ipv4Addr::new(192, 0, 2, 33);
        let raw = in_addr_from_ipv4(v4);
        assert_eq!(raw.to_ne_bytes(), [192, 0, 2, 33]);
        assert_eq!(ipv4_from_in_addr(raw), v4);

        let v6: Ipv6Addr = "2001:db8::a:1".parse().unwrap();
        let octets = v6.octets();
        let mut words = [0u16; 8];
        for (word, pair) in words.iter_mut().zip(octets.as_chunks::<2>().0) {
            *word = u16::from_ne_bytes(*pair);
        }
        assert_eq!(ipv6_from_words(words), v6);
    }
}
