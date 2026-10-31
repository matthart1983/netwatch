//! The IP Helper calls netwatch makes: `GetAdaptersAddresses` for adapters,
//! their DNS servers and gateways, `GetIfTable2` for interface counters and
//! `GetIpForwardTable2` for the default route.
//!
//! The record layouts come from windows-sys, so from Microsoft's metadata
//! rather than a hand-declared prefix. Each call copies the fields netwatch
//! reads into the plain structs in `platform::ip_helper` while the API's
//! buffer is alive; the decoding and every choice made from it live there,
//! where they are tested on every platform.
#![allow(unsafe_code)]

use super::super::ip_helper::{self, Adapter, IfCounters, IfRow, Route};
use super::{InterfaceInfo, InterfaceStats};
use std::collections::HashMap;
use std::ffi::CStr;
use std::net::IpAddr;
use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, ERROR_SUCCESS, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetAdaptersAddresses, GetIfTable2, GetIpForwardTable2,
    GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST,
    GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST,
    IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH,
    MIB_IF_ROW2, MIB_IF_TABLE2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET, SOCKET_ADDRESS,
};

// `ip_helper` decodes with its own copies of these numbers so it can build
// off Windows; hold them to Microsoft's.
const _: () = assert!(ip_helper::AF_INET == AF_INET && ip_helper::AF_INET6 == AF_INET6);
const _: () = assert!(
    ip_helper::IF_TYPE_ETHERNET_CSMACD == IF_TYPE_ETHERNET_CSMACD
        && ip_helper::IF_TYPE_SOFTWARE_LOOPBACK == IF_TYPE_SOFTWARE_LOOPBACK
        && ip_helper::IF_TYPE_IEEE80211 == IF_TYPE_IEEE80211
);

/// The interface list needs unicast addresses and nothing else.
const FLAGS_INTERFACES: u32 =
    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
/// Counters, GUIDs and the default route need only each adapter's identity,
/// which keeps the per-tick call small.
const FLAGS_IDENTITY: u32 = GAA_FLAG_SKIP_UNICAST
    | GAA_FLAG_SKIP_ANYCAST
    | GAA_FLAG_SKIP_MULTICAST
    | GAA_FLAG_SKIP_DNS_SERVER;
/// GUIDs for every NDIS interface, not only those with IP bound, as
/// `Get-NetAdapter -IncludeHidden` gave them: a capture-only NIC with its
/// protocols unbound still has an Npcap device to open.
const FLAGS_GUIDS: u32 = FLAGS_IDENTITY | GAA_FLAG_INCLUDE_ALL_INTERFACES;
/// DNS servers come by default; gateways have to be asked for.
const FLAGS_CONFIG: u32 = GAA_FLAG_SKIP_UNICAST
    | GAA_FLAG_SKIP_ANYCAST
    | GAA_FLAG_SKIP_MULTICAST
    | GAA_FLAG_INCLUDE_GATEWAYS;

/// Every adapter with an IP stack bound, loopback excluded: the set ipconfig
/// listed. `Err` carries the Win32 error code, here and below.
pub fn adapters() -> Result<Vec<InterfaceInfo>, u32> {
    Ok(read_adapters(FLAGS_INTERFACES)?
        .iter()
        .filter_map(ip_helper::interface_info)
        .collect())
}

/// Friendly name -> interface GUID, from each adapter's `AdapterName`.
///
/// The adapters with IP bound are read first, so theirs is the GUID kept
/// should a hidden interface carry the same name; the wider list only adds
/// names, and is skipped if that call fails.
pub fn adapter_guids() -> Result<HashMap<String, String>, u32> {
    let mut adapters = read_adapters(FLAGS_IDENTITY)?;
    adapters.extend(read_adapters(FLAGS_GUIDS).unwrap_or_default());
    Ok(ip_helper::adapter_guids(&adapters))
}

/// Per-interface counters, keyed by the names [`adapters`] returns, and for
/// a NIC with IP unbound by its alias, which [`adapter_guids`] has too.
pub fn interface_stats() -> Result<HashMap<String, InterfaceStats>, u32> {
    let adapters = read_adapters(FLAGS_IDENTITY)?;
    Ok(ip_helper::stats_by_name(&adapters, &if_rows()?))
}

/// Friendly name of the adapter carrying the best default route.
pub fn default_route_interface() -> Result<Option<String>, u32> {
    let adapters = read_adapters(FLAGS_IDENTITY)?;
    let routes = routes()?;
    Ok(ip_helper::default_routes(&routes, &adapters)
        .first()
        .map(|r| r.adapter.name.clone()))
}

/// The default gateway, from the routing table. `collectors::config` falls
/// back to `route print` on `Err`.
pub fn default_gateway() -> Result<Option<String>, u32> {
    let adapters = read_adapters(FLAGS_IDENTITY)?;
    let routes = routes()?;
    Ok(ip_helper::default_gateway(&ip_helper::default_routes(
        &routes, &adapters,
    )))
}

/// DNS servers, the default-route adapter's first: plain addresses, and a
/// link-local one with its adapter's zone index. `collectors::config` falls
/// back to ipconfig on `Err`.
pub fn dns_servers() -> Result<Vec<String>, u32> {
    let adapters = read_adapters(FLAGS_CONFIG)?;
    // Without the routing table the order is the API's, which is still a
    // usable list; only the adapter records are essential.
    let default_luid = routes().ok().and_then(|routes| {
        ip_helper::default_routes(&routes, &adapters)
            .first()
            .map(|r| r.adapter.luid)
    });
    Ok(ip_helper::dns_servers(&adapters, default_luid))
}

/// Run `GetAdaptersAddresses` with `flags` and copy every record out.
fn read_adapters(flags: u32) -> Result<Vec<Adapter>, u32> {
    // Microsoft's suggested starting size; the call reports the size it needs
    // if adapters appeared in between, so retry a few times.
    let mut size: u32 = 15_000;
    for _ in 0..4 {
        // u64 elements keep the buffer 8-byte aligned for the records.
        const { assert!(align_of::<IP_ADAPTER_ADDRESSES_LH>() <= align_of::<u64>()) };
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: `buf` is at least `size` bytes, writable and aligned for
        // the records the API places in it, and `size` is a live u32 the call
        // may overwrite.
        let rc = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                flags,
                std::ptr::null(),
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        match rc {
            // SAFETY: on success the buffer holds a valid list, and it lives
            // until `walk` returns.
            ERROR_SUCCESS => return Ok(unsafe { walk(buf.as_ptr().cast()) }),
            ERROR_NO_DATA => return Ok(Vec::new()),
            ERROR_BUFFER_OVERFLOW => continue,
            other => return Err(other),
        }
    }
    Err(ERROR_BUFFER_OVERFLOW)
}

/// # Safety
///
/// `first` is the head of a list `GetAdaptersAddresses` filled in, and the
/// buffer holding it outlives the call.
unsafe fn walk(first: *const IP_ADAPTER_ADDRESSES_LH) -> Vec<Adapter> {
    let mut out = Vec::new();
    let mut cur = first;
    // SAFETY: `cur` is the list head or a `Next` from a record in it, so it is
    // null or a record in the same live buffer.
    while let Some(a) = unsafe { cur.as_ref() } {
        cur = a.Next.cast_const();
        let mac_len = (a.PhysicalAddressLength as usize).min(a.PhysicalAddress.len());
        // SAFETY: in a record the API filled, `AdapterName` and
        // `FriendlyName` are null or NUL-terminated strings, and the three
        // address lists are null or lists of their node type, all in the same
        // live buffer, which is what `narrow_to_string`, `wide_to_string` and
        // `list_ips` require. `Luid` is a union of a u64 and a bitfield over
        // that same u64, so reading `Value` reads initialised plain data.
        let adapter = unsafe {
            Adapter {
                luid: a.Luid.Value,
                guid: narrow_to_string(a.AdapterName.cast_const()),
                name: wide_to_string(a.FriendlyName.cast_const()),
                if_type: a.IfType,
                is_up: a.OperStatus == IfOperStatusUp,
                mtu: a.Mtu,
                mac: a.PhysicalAddress[..mac_len].to_vec(),
                unicast: list_ips(a.FirstUnicastAddress.cast_const(), |n| {
                    (n.Next.cast_const(), n.Address)
                }),
                dns_servers: list_ips(a.FirstDnsServerAddress.cast_const(), |n| {
                    (n.Next.cast_const(), n.Address)
                }),
                gateways: list_ips(a.FirstGatewayAddress.cast_const(), |n| {
                    (n.Next.cast_const(), n.Address)
                }),
                ipv6_if_index: a.Ipv6IfIndex,
                ipv4_metric: a.Ipv4Metric,
                ipv6_metric: a.Ipv6Metric,
            }
        };
        out.push(adapter);
    }
    out
}

/// The addresses on one of a record's lists. The unicast, DNS server and
/// gateway nodes are three types with the same `Next` and `Address` fields,
/// which `link` reads.
///
/// # Safety
///
/// `first` is null or the head of such a list in a live
/// `GetAdaptersAddresses` buffer.
unsafe fn list_ips<T>(
    first: *const T,
    link: impl Fn(&T) -> (*const T, SOCKET_ADDRESS),
) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut cur = first;
    // SAFETY: `cur` is the head or a `Next` from a node in the same list, so
    // it is null or a node in the live buffer.
    while let Some(node) = unsafe { cur.as_ref() } {
        let (next, address) = link(node);
        cur = next;
        // SAFETY: a SOCKET_ADDRESS the API filled points at
        // `iSockaddrLength` bytes in the same buffer, or is null.
        if let Some(ip) = unsafe { socket_address_ip(address) } {
            out.push(ip);
        }
    }
    out
}

/// # Safety
///
/// `sa.lpSockaddr` is null or points at `sa.iSockaddrLength` readable bytes.
unsafe fn socket_address_ip(sa: SOCKET_ADDRESS) -> Option<IpAddr> {
    let len = usize::try_from(sa.iSockaddrLength).ok()?;
    if sa.lpSockaddr.is_null() {
        return None;
    }
    // SAFETY: non-null, with `len` readable bytes by the caller's contract.
    let raw = unsafe { std::slice::from_raw_parts(sa.lpSockaddr.cast::<u8>(), len) };
    ip_helper::sockaddr_ip(raw)
}

/// The address in a `SOCKADDR_INET`, the form the route table uses.
fn sockaddr_inet_ip(sa: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: SOCKADDR_INET is a union of sockaddr_in, sockaddr_in6 and the
    // family word, all integers, and `sa` is a live reference, so its
    // `size_of` bytes are readable. They are initialised for every caller:
    // `route` passes rows the API wrote whole, and the test a zeroed value.
    // A SOCKADDR_INET built in Rust from its IPv4 member alone would leave
    // the rest uninitialised, which this safe fn cannot check.
    let raw = unsafe {
        std::slice::from_raw_parts(
            (sa as *const SOCKADDR_INET).cast::<u8>(),
            std::mem::size_of::<SOCKADDR_INET>(),
        )
    };
    ip_helper::sockaddr_ip(raw)
}

/// # Safety
///
/// `p` is null or points at a NUL-terminated UTF-16 string.
unsafe fn wide_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0;
    // SAFETY: the string is NUL-terminated, so every unit up to and including
    // the terminator is readable.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: the `len` units before the terminator were just read.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

/// # Safety
///
/// `p` is null or points at a NUL-terminated byte string.
unsafe fn narrow_to_string(p: *const u8) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: non-null and NUL-terminated by the caller's contract.
    unsafe { CStr::from_ptr(p.cast()) }
        .to_string_lossy()
        .into_owned()
}

/// A table one of the `Get*Table2` calls allocated, freed on every way out.
struct MibTable<T>(*mut T);

impl<T> Drop for MibTable<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a successful `Get*Table2` call,
            // and this is the only place it is freed.
            unsafe { FreeMibTable(self.0.cast_const().cast()) };
        }
    }
}

/// Every row of `GetIfTable2`: counters, alias and flags.
fn if_rows() -> Result<Vec<IfRow>, u32> {
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    // SAFETY: `table` is a live out-pointer; on success the API stores a
    // table it allocated there, which `MibTable` frees.
    let rc = unsafe { GetIfTable2(&mut table) };
    if rc != NO_ERROR {
        return Err(rc);
    }
    let table = MibTable(table);
    // SAFETY: a table GetIfTable2 returned holds `NumEntries` rows from
    // `Table` on; its declared length of 1 is C's flexible-array idiom. The
    // slice is dropped before `table` frees the memory.
    let rows: &[MIB_IF_ROW2] = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*table.0).Table).cast::<MIB_IF_ROW2>(),
            (*table.0).NumEntries as usize,
        )
    };
    Ok(rows.iter().map(if_row).collect())
}

fn if_row(r: &MIB_IF_ROW2) -> IfRow {
    IfRow {
        // SAFETY: as for `Adapter::luid` above, `Value` covers the whole
        // union.
        luid: unsafe { r.InterfaceLuid.Value },
        alias: ip_helper::wide_array_text(&r.Alias),
        flags: r.InterfaceAndOperStatusFlags._bitfield,
        counters: counters(r),
    }
}

fn counters(r: &MIB_IF_ROW2) -> IfCounters {
    IfCounters {
        in_octets: r.InOctets,
        in_ucast_pkts: r.InUcastPkts,
        in_nucast_pkts: r.InNUcastPkts,
        in_discards: r.InDiscards,
        in_errors: r.InErrors,
        out_octets: r.OutOctets,
        out_ucast_pkts: r.OutUcastPkts,
        out_nucast_pkts: r.OutNUcastPkts,
        out_discards: r.OutDiscards,
        out_errors: r.OutErrors,
    }
}

/// The routing table from `GetIpForwardTable2`, both families.
fn routes() -> Result<Vec<Route>, u32> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: as in `if_rows`.
    let rc = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
    if rc != NO_ERROR {
        return Err(rc);
    }
    let table = MibTable(table);
    // SAFETY: as in `if_rows`, for the route table's rows.
    let rows: &[MIB_IPFORWARD_ROW2] = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*table.0).Table).cast::<MIB_IPFORWARD_ROW2>(),
            (*table.0).NumEntries as usize,
        )
    };
    Ok(rows.iter().filter_map(route).collect())
}

fn route(r: &MIB_IPFORWARD_ROW2) -> Option<Route> {
    Some(Route {
        // SAFETY: as for `Adapter::luid` above.
        luid: unsafe { r.InterfaceLuid.Value },
        destination: sockaddr_inet_ip(&r.DestinationPrefix.Prefix)?,
        prefix_len: r.DestinationPrefix.PrefixLength,
        next_hop: sockaddr_inet_ip(&r.NextHop)?,
        metric: r.Metric,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Networking::WinSock::{IN_ADDR, IN_ADDR_0, SOCKADDR_IN};

    /// A SOCKET_ADDRESS that points nowhere is skipped, not dereferenced.
    #[test]
    fn null_socket_address_is_none() {
        let sa = SOCKET_ADDRESS {
            lpSockaddr: std::ptr::null_mut(),
            iSockaddrLength: 16,
        };
        // SAFETY: null is allowed by the contract.
        assert!(unsafe { socket_address_ip(sa) }.is_none());
    }

    /// The windows-sys union decodes through the same byte path as the
    /// lists' sockaddrs.
    #[test]
    fn decodes_sockaddr_inet() {
        // SAFETY: SOCKADDR_INET is plain integers, so all-zero is a valid
        // value; zeroing first keeps the bytes past the IPv4 member, which
        // the decoder reads too, initialised.
        let mut sa: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        sa.Ipv4 = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR {
                // Network byte order in memory: 192.168.1.1.
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes([192, 168, 1, 1]),
                },
            },
            sin_zero: [0; 8],
        };
        assert_eq!(sockaddr_inet_ip(&sa), Some(IpAddr::from([192, 168, 1, 1])));
    }

    /// Against the machine's real adapters: every name must be one the
    /// Get-NetAdapter lookups can key on — non-empty, and free of the
    /// replacement character a code-page mismatch leaves behind.
    #[test]
    fn live_adapter_names_are_clean_unicode() {
        let adapters = adapters().expect("GetAdaptersAddresses");
        for a in &adapters {
            assert!(!a.name.is_empty());
            assert!(!a.name.contains('\u{FFFD}'), "mangled name {:?}", a.name);
        }
    }

    /// The runner has a network: at least one adapter is up, and an up
    /// adapter has counters under the same name the interface list uses,
    /// with traffic on them. A counter row outside the list is a NIC with IP
    /// unbound, named as capture names it.
    #[test]
    fn live_up_adapter_has_counters() {
        let adapters = adapters().expect("GetAdaptersAddresses");
        assert!(!adapters.is_empty(), "no adapters");
        let stats = interface_stats().expect("GetIfTable2");
        let up: Vec<_> = adapters.iter().filter(|a| a.is_up).collect();
        assert!(!up.is_empty(), "no adapter is up: {adapters:?}");
        assert!(
            up.iter().any(|a| stats
                .get(&a.name)
                .is_some_and(|s| s.rx_bytes > 0 && s.tx_bytes > 0)),
            "no up adapter has traffic counters: {stats:?}"
        );
        let guids = adapter_guids().expect("GetAdaptersAddresses");
        for name in stats.keys() {
            assert!(
                adapters.iter().any(|a| &a.name == name) || guids.contains_key(name),
                "{name} is neither listed nor an adapter capture can open"
            );
        }
    }

    /// Whatever the routing table and adapters say, what reaches the probes
    /// must parse as a plain address, or be a link-local resolver with the
    /// zone index that makes the probes skip it; and a host with a default
    /// route has a resolver.
    #[test]
    fn live_route_gateway_and_dns_are_probe_ready() {
        let names: Vec<String> = adapters()
            .expect("GetAdaptersAddresses")
            .into_iter()
            .map(|a| a.name)
            .collect();
        let iface = default_route_interface().expect("GetIpForwardTable2");
        if let Some(iface) = &iface {
            assert!(names.contains(iface), "{iface} not in {names:?}");
        }
        let gateway = default_gateway().expect("GetIpForwardTable2");
        if let Some(gw) = &gateway {
            assert!(gw.parse::<IpAddr>().is_ok(), "gateway {gw}");
        }
        let dns = dns_servers().expect("GetAdaptersAddresses");
        println!("default route via {iface:?}, gateway {gateway:?}, dns {dns:?}");
        for server in &dns {
            let addr = match server.split_once('%') {
                Some((addr, zone)) => {
                    assert!(zone.parse::<u32>().is_ok_and(|z| z != 0), "{server}");
                    let ip: std::net::Ipv6Addr = addr.parse().expect("an IPv6 address");
                    assert_eq!(ip.segments()[0] & 0xffc0, 0xfe80, "{server}");
                    addr
                }
                None => server,
            };
            assert!(addr.parse::<IpAddr>().is_ok(), "dns server {server}");
        }
        if iface.is_some() {
            assert!(!dns.is_empty(), "a default route but no DNS server");
        }
    }

    /// Every adapter the interface list shows has the GUID capture needs.
    #[test]
    fn live_listed_adapters_have_guids() {
        let guids = adapter_guids().expect("GetAdaptersAddresses");
        for a in adapters().expect("GetAdaptersAddresses") {
            let guid = guids.get(&a.name);
            assert!(
                guid.is_some_and(|g| g.starts_with('{') && g.ends_with('}') && g.len() == 38),
                "{}: {guid:?}",
                a.name
            );
        }
    }
}
