//! A connection table the size and shape of a busy host's.

use crate::collectors::attribution::{
    session_id, utc_ms, FlowIdentity, MatchEvidence, ProcessIdentity, UnknownReason,
};
use crate::collectors::connections::{AttributionSource, Connection};
use crate::dpi::AppProtocol;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Owning processes in the table.
const PROCESSES: u64 = 150;

/// Knuth's MMIX linear congruential generator: the same sequence on every
/// platform and run, with no dev-dependency.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
}

/// `n` connections, the same ones for the same `n` and `seed`:
///
/// - about 150 processes, with skewed shares: the busiest owns about 7% of
///   the rows, as a browser or a proxy does
/// - n/3 distinct remote hosts, 10% of them IPv6
/// - states 70/15/5/5/5: ESTABLISHED, TIME_WAIT, LISTEN, CLOSE_WAIT and
///   unconnected UDP
/// - capture rates on 1 row in 7 and a TLS SNI on 1 in 3, among rows with a
///   peer
/// - verified owner evidence and a flow identity, as a fresh Linux poll
///   leaves them
///
/// Rows look the way a Linux poll publishes them. TIME_WAIT sockets belong
/// to the kernel, so they have no owner. LISTEN and unconnected UDP sockets
/// have a wildcard peer.
///
/// Peers are in 198.18.0.0/15 (RFC 2544) and 2001:db8::/32 (RFC 3849), which
/// nothing routes but `geo::is_private_ip` treats as public, so geo, egress
/// and Topology do their full work on them. Each row has its own local
/// endpoint, so no two rows share a key.
pub(crate) fn synthetic_connections(n: usize, seed: u64) -> Vec<Connection> {
    let mut rng = Lcg(0x5eed ^ seed);
    let hosts = (n as u64 / 3).max(1);
    let observed_ms = utc_ms();
    (0..n)
        .map(|i| {
            // Squaring a uniform draw skews it towards zero.
            let draw = rng.next() % 1_000;
            let p = draw * draw * PROCESSES / 1_000_000;
            let host = rng.next() % hosts;
            let port = [443u16, 443, 443, 80, 53, 5228][(rng.next() % 6) as usize];
            let v6 = host.is_multiple_of(10);
            let local_port = 1_024 + (i % 64_000) as u16;
            let local_host = (i / 64_000) as u8;
            let local = if v6 {
                let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10 + local_host as u16);
                format!("[{ip}]:{local_port}")
            } else {
                format!("{}:{local_port}", Ipv4Addr::new(192, 0, 2, 10 + local_host))
            };
            let peer = if v6 {
                let ip = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, (host >> 16) as u16, host as u16);
                format!("[{ip}]:{port}")
            } else {
                let h = host % 131_072;
                let ip = Ipv4Addr::new(198, 18 + (h >> 16) as u8, (h >> 8) as u8, h as u8);
                format!("{ip}:{port}")
            };
            let wildcard = if v6 { "[::]:*" } else { "0.0.0.0:*" };
            let (protocol, state, remote, owned) = match i % 20 {
                0..=13 => ("TCP", "ESTABLISHED", peer, true),
                14..=16 => ("TCP", "TIME_WAIT", peer, false),
                17 => ("TCP", "LISTEN", wildcard.to_string(), true),
                18 => ("TCP", "CLOSE_WAIT", peer, true),
                _ => ("UDP", "UNCONN", wildcard.to_string(), true),
            };
            let has_peer = !remote.ends_with(":*");

            let pid = 20_000 + p as u32;
            let identity = owned.then(|| ProcessIdentity {
                session: session_id().into(),
                pid,
                start_token: (1_000 + p).to_string(),
                executable: Some(format!("253:1:{}", 900_000 + p)),
                network_namespace: Some("net:[4026531840]".into()),
            });
            let mut evidence = MatchEvidence::default();
            evidence.observe();
            evidence.flow = Some(FlowIdentity {
                session: session_id().into(),
                generation: i as u64 + 1,
                capture_generation: None,
                protocol: protocol.into(),
                local: local.clone(),
                remote: remote.clone(),
                network_namespace: identity
                    .as_ref()
                    .and_then(|id| id.network_namespace.clone()),
            });
            if owned {
                evidence.unknown_reason = None;
                evidence.owner_checked_utc_ms = Some((observed_ms, observed_ms));
            } else {
                // What the poll records for a socket whose inode is 0.
                evidence.unknown_reason = Some(UnknownReason::AmbiguousEndpoint);
            }
            evidence.process = identity;

            let rated = has_peer && i % 7 == 0;
            Connection {
                protocol: protocol.into(),
                local_addr: local,
                remote_addr: remote,
                state: state.into(),
                pid: owned.then_some(pid),
                process_name: owned.then(|| format!("proc-{p:03}")),
                handshake_rtt_us: (has_peer && i % 5 == 0)
                    .then_some(12_000.0 + (i % 97) as f64 * 100.0),
                rx_rate: rated.then(|| (rng.next() % 1_000_000) as f64),
                tx_rate: rated.then(|| (rng.next() % 100_000) as f64),
                attribution: if owned {
                    AttributionSource::Procfs
                } else {
                    AttributionSource::default()
                },
                evidence,
                app_protocol: (has_peer && i % 3 == 0).then(|| AppProtocol::Tls {
                    sni: Some(format!("h{host}.example.net")),
                    alpn: Some("h2".into()),
                    ech: false,
                    ja4: None,
                }),
                retransmits: if has_peer && i % 50 == 0 { 3 } else { 0 },
                out_of_order: 0,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn the_same_seed_gives_the_same_table() {
        let key = |c: &Connection| {
            (
                c.protocol.clone(),
                c.local_addr.clone(),
                c.remote_addr.clone(),
                c.state.clone(),
                c.pid,
                c.rx_rate.map(f64::to_bits),
            )
        };
        let a: Vec<_> = synthetic_connections(3_000, 7).iter().map(key).collect();
        let b: Vec<_> = synthetic_connections(3_000, 7).iter().map(key).collect();
        let c: Vec<_> = synthetic_connections(3_000, 8).iter().map(key).collect();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn the_table_has_the_documented_shape() {
        let n = 10_000;
        let rows = synthetic_connections(n, 1);
        assert_eq!(rows.len(), n);

        let keys: HashSet<_> = rows
            .iter()
            .map(|c| (&c.protocol, &c.local_addr, &c.remote_addr, c.pid))
            .collect();
        assert_eq!(keys.len(), n, "two rows share a key");

        let share = |state: &str| rows.iter().filter(|c| c.state == state).count() * 100 / n;
        assert_eq!(share("ESTABLISHED"), 70);
        assert_eq!(share("TIME_WAIT"), 15);
        assert_eq!(share("LISTEN"), 5);
        assert_eq!(share("CLOSE_WAIT"), 5);
        assert_eq!(share("UNCONN"), 5);

        let peers: Vec<_> = rows
            .iter()
            .filter(|c| !c.remote_addr.ends_with(":*"))
            .collect();
        let hosts: HashSet<_> = peers
            .iter()
            .map(|c| crate::app::parse_addr_parts(&c.remote_addr).0.unwrap())
            .collect();
        // 9,000 draws from n/3 hosts: all but about 7% of them come up.
        assert!((2_800..=n / 3).contains(&hosts.len()), "{}", hosts.len());
        assert!(hosts
            .iter()
            .all(|h| !crate::collectors::geo::is_private_ip(h)));
        let v6 = peers
            .iter()
            .filter(|c| c.remote_addr.starts_with('['))
            .count();
        assert!((7..=13).contains(&(v6 * 100 / peers.len())), "{v6}");

        let processes: HashSet<_> = rows.iter().filter_map(|c| c.pid).collect();
        assert!(
            (120..=150).contains(&processes.len()),
            "{}",
            processes.len()
        );
        let busiest = rows.iter().filter(|c| c.pid == Some(20_000)).count();
        assert!((5..=12).contains(&(busiest * 100 / n)), "{busiest}");

        let rated = rows.iter().filter(|c| c.rx_rate.is_some()).count();
        assert!((10..=15).contains(&(rated * 100 / n)), "{rated}");
        let sni = rows.iter().filter(|c| c.app_protocol.is_some()).count();
        assert!((27..=33).contains(&(sni * 100 / n)), "{sni}");

        for c in &rows {
            assert!(c.evidence.flow.is_some());
            assert_eq!(c.evidence.verified(), c.state != "TIME_WAIT", "{c:?}");
            assert_eq!(c.pid.is_some(), c.state != "TIME_WAIT");
        }
    }
}
