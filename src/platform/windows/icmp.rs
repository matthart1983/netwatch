//! Echo requests through iphlpapi's ICMP API: `IcmpSendEcho2` for IPv4 and
//! `Icmp6SendEcho2` for IPv6. Neither needs administrator rights or a raw
//! socket. Each call answers with an IP_STATUS code, which
//! [`crate::platform::icmp::decode`] reads; `ping.exe` and `tracert` print
//! the same outcomes as text in the display language.
//!
//! Calls are synchronous, with no event and no APC routine: every caller is
//! already on a worker thread of its own and waits for the answer anyway.

use crate::platform::icmp::{self, Echo};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    Icmp6CreateFile, Icmp6SendEcho2, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho2,
    ICMPV6_ECHO_REPLY_LH, ICMP_ECHO_REPLY, IP_OPTION_INFORMATION,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET6, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN6};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

/// The echo payload, the same eight bytes the Unix ping path sends.
const PAYLOAD: &[u8] = b"netwatch";

/// Windows' own default TTL, the one `ping.exe` sends with.
pub const DEFAULT_TTL: u8 = 128;

/// An ICMP handle for one destination's address family, closed on drop.
pub struct IcmpHandle {
    handle: HANDLE,
    dst: IpAddr,
}

impl IcmpHandle {
    /// `None` when the handle cannot be created, the one case in which
    /// callers fall back to `ping.exe` or `tracert` for an address.
    pub fn open(dst: IpAddr) -> Option<Self> {
        // SAFETY: both functions take no arguments and return either a new
        // handle or INVALID_HANDLE_VALUE; nothing else is touched.
        let handle = unsafe {
            match dst {
                IpAddr::V4(_) => IcmpCreateFile(),
                IpAddr::V6(_) => Icmp6CreateFile(),
            }
        };
        (handle != INVALID_HANDLE_VALUE && !handle.is_null()).then_some(Self { handle, dst })
    }

    /// One echo to the destination with `ttl`, waiting up to `timeout_ms`.
    pub fn echo(&self, ttl: u8, timeout_ms: u32) -> Echo {
        let options = IP_OPTION_INFORMATION {
            Ttl: ttl,
            Tos: 0,
            Flags: 0,
            OptionsSize: 0,
            OptionsData: std::ptr::null_mut(),
        };
        match self.dst {
            IpAddr::V4(dst) => self.echo_v4(dst, &options, timeout_ms),
            IpAddr::V6(dst) => self.echo_v6(dst, &options, timeout_ms),
        }
    }

    fn echo_v4(&self, dst: Ipv4Addr, options: &IP_OPTION_INFORMATION, timeout_ms: u32) -> Echo {
        let mut buf = reply_buffer::<ICMP_ECHO_REPLY>();
        let len = byte_len(&buf);
        let start = Instant::now();
        // SAFETY: `self.handle` came from IcmpCreateFile (this is an IPv4
        // destination) and stays open until drop. PAYLOAD and `options` are
        // live for the whole call, `buf` is writable for `len` bytes and
        // 8-byte aligned as ICMP_ECHO_REPLY needs, and with no event and no
        // APC routine the call returns only once a reply or the timeout is in,
        // so nothing writes to `buf` after it returns.
        let replies = unsafe {
            IcmpSendEcho2(
                self.handle,
                std::ptr::null_mut(),
                None,
                std::ptr::null(),
                icmp::in_addr_from_ipv4(dst),
                PAYLOAD.as_ptr().cast(),
                PAYLOAD.len() as u16,
                options,
                buf.as_mut_ptr().cast(),
                len,
                timeout_ms,
            )
        };
        let elapsed = start.elapsed();
        if replies == 0 {
            return icmp::decode(last_error(), None, 0, elapsed);
        }
        // SAFETY: a non-zero return means the call wrote at least one
        // ICMP_ECHO_REPLY at the start of `buf`, which is aligned for it.
        let reply = unsafe { buf.as_ptr().cast::<ICMP_ECHO_REPLY>().read() };
        icmp::decode(
            reply.Status,
            Some(IpAddr::V4(icmp::ipv4_from_in_addr(reply.Address))),
            reply.RoundTripTime,
            elapsed,
        )
    }

    fn echo_v6(&self, dst: Ipv6Addr, options: &IP_OPTION_INFORMATION, timeout_ms: u32) -> Echo {
        // The unspecified source lets the stack pick one, as ping.exe does.
        let source = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            ..Default::default()
        };
        let dest = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_addr: IN6_ADDR {
                u: IN6_ADDR_0 { Byte: dst.octets() },
            },
            ..Default::default()
        };
        let mut buf = reply_buffer::<ICMPV6_ECHO_REPLY_LH>();
        let len = byte_len(&buf);
        let start = Instant::now();
        // SAFETY: as in `echo_v4`, with a handle from Icmp6CreateFile; the two
        // SOCKADDR_IN6 values are fully initialised and live for the call.
        let replies = unsafe {
            Icmp6SendEcho2(
                self.handle,
                std::ptr::null_mut(),
                None,
                std::ptr::null(),
                &source,
                &dest,
                PAYLOAD.as_ptr().cast(),
                PAYLOAD.len() as u16,
                options,
                buf.as_mut_ptr().cast(),
                len,
                timeout_ms,
            )
        };
        let elapsed = start.elapsed();
        if replies == 0 {
            return icmp::decode(last_error(), None, 0, elapsed);
        }
        // SAFETY: a non-zero return means the call wrote an
        // ICMPV6_ECHO_REPLY_LH at the start of `buf`, which is aligned for it.
        let reply = unsafe { buf.as_ptr().cast::<ICMPV6_ECHO_REPLY_LH>().read() };
        // IPV6_ADDRESS_EX is packed; copy the words out rather than borrow.
        let words = reply.Address.sin6_addr;
        icmp::decode(
            reply.Status,
            Some(IpAddr::V6(icmp::ipv6_from_words(words))),
            reply.RoundTripTime,
            elapsed,
        )
    }
}

impl Drop for IcmpHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from Icmp(6)CreateFile, is valid, and is
        // closed exactly once, here.
        unsafe {
            IcmpCloseHandle(self.handle);
        }
    }
}

/// `count` echoes to `dst`, one after another, each waiting up to
/// `timeout_ms`. `None` when no ICMP handle could be opened.
pub fn echoes(dst: IpAddr, count: usize, timeout_ms: u32) -> Option<Vec<Echo>> {
    let icmp = IcmpHandle::open(dst)?;
    Some(
        (0..count)
            .map(|_| icmp.echo(DEFAULT_TTL, timeout_ms))
            .collect(),
    )
}

/// A zeroed reply buffer for one echo whose reply structure is `R`, in u64s so
/// it is aligned for the structure's pointers.
fn reply_buffer<R>() -> Vec<u64> {
    let bytes = icmp::reply_buffer_len(
        std::mem::size_of::<R>(),
        PAYLOAD.len(),
        std::mem::size_of::<IO_STATUS_BLOCK>(),
    );
    vec![0u64; bytes.div_ceil(8)]
}

fn byte_len(buf: &[u64]) -> u32 {
    (std::mem::size_of_val(buf)) as u32
}

/// The calling thread's last Win32 error, which is where the API reports a
/// timeout or a failure to send.
fn last_error() -> u32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .map_or(0, |code| code as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CI's Windows runners can reach loopback but not the internet, so the
    /// live tests stay there.
    #[test]
    fn loopback_answers_on_both_families() {
        for dst in ["127.0.0.1", "::1"] {
            let dst: IpAddr = dst.parse().unwrap();
            let got = echoes(dst, 3, 1000).expect("an ICMP handle opens");
            assert_eq!(got.len(), 3);
            for echo in got {
                let Echo::Reply { from, rtt_ms } = echo else {
                    panic!("{dst}: expected a reply, got {echo:?}");
                };
                assert_eq!(from, dst);
                // Loopback is the sub-millisecond case: never 0, and never
                // above what the API allows.
                assert!(rtt_ms > 0.0 && rtt_ms < 1000.0, "{dst}: {rtt_ms}");
            }
        }
    }

    #[test]
    fn a_ttl_of_one_still_reaches_loopback() {
        for dst in ["127.0.0.1", "::1"] {
            let dst: IpAddr = dst.parse().unwrap();
            let icmp = IcmpHandle::open(dst).expect("an ICMP handle opens");
            assert!(
                matches!(icmp.echo(1, 1000), Echo::Reply { from, .. } if from == dst),
                "{dst}"
            );
        }
    }

    #[test]
    fn an_unrouted_address_is_never_a_reply() {
        // 192.0.2.0/24 is TEST-NET-1: a timeout, an unreachable or a refusal
        // are all fine; a reply would mean the decoding is wrong.
        let icmp = IcmpHandle::open("192.0.2.1".parse().unwrap()).expect("handle");
        let echo = icmp.echo(DEFAULT_TTL, 500);
        assert!(!matches!(echo, Echo::Reply { .. }), "{echo:?}");
    }
}
