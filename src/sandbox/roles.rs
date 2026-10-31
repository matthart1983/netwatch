//! Which policy a thread enters with, looked up by the name it was spawned
//! under.
//!
//! Spawn sites pass only a name, so a name missing from the table is a
//! parser: a network worker left out loses its connections, rather than a
//! parser keeping network it should not have. The tests read every spawn
//! site's name from the source and fail on a name without a row.

/// What a thread does, and so which policy it takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The UI or daemon thread. It starts network workers after its own
    /// entry, and a thread keeps every layer it inherits, so it keeps the
    /// network.
    Main,
    /// Workers whose job is a lookup, a probe or a publish. The filesystem
    /// policy only.
    Network,
    /// Everything else: workers that read packets, files, kernel tables or
    /// subprocess output and have no reason to connect anywhere. On top of
    /// the filesystem policy they lose TCP bind and connect, Unix sockets and
    /// signals outside their domain where the kernel can deny them, and
    /// CAP_NET_RAW.
    Parser,
    /// The packet capture thread: the parser policy, with the read grants
    /// and none of the write grants.
    Capture,
    /// The ProcBroker, which never enters. It keeps CAP_SYS_PTRACE and
    /// CAP_DAC_READ_SEARCH and drops the rest (`worker::relinquish`). Were it
    /// ever to enter, it would take the parser policy.
    Broker,
}

impl Role {
    /// The Landlock layer stacked on the filesystem one, or `None` for the
    /// roles that keep the network.
    pub fn layer(self) -> Option<&'static str> {
        match self {
            Role::Main | Role::Network => None,
            Role::Parser | Role::Broker => Some("parser"),
            Role::Capture => Some("capture"),
        }
    }
}

/// The role of the worker spawned as `name`.
pub fn role_for(name: &str) -> Role {
    match name {
        // `host` retries a truncated answer over TCP, the traceroute binary
        // resolves names through NSS, and the runtime's blocking pool takes
        // any blocking job, a name lookup among them. The rest connect by
        // design.
        "tokio-blocking" | "reverse-dns" | "whois" | "health" | "traceroute" | "insights"
        | "remote" | "diagnose-active" | "diagnose-test" | "diagnose-targets" => Role::Network,
        "capture" => Role::Capture,
        "proc-broker" => Role::Broker,
        // keylog, metrics-listener, metrics-client, ebpf, connections,
        // tcp-info, traffic, process-cpu, terminal, logging, capture-export,
        // policy-preflight, geoip-update and pktap, and any name added
        // without a row here.
        // shutdown-deadline never enters; as a parser it relinquishes every
        // capability.
        _ => Role::Parser,
    }
}

/// Whether the worker spawned as `name` takes the no-socket filter, on top of
/// its role's layers, on Linux. These read packets, a keylog file or accepted
/// streams and never open a socket after entry: capture opens its device
/// first, the metrics listener binds first and accept4 is not socket(2).
///
/// Everything else goes without. connections, tcp-info and traffic start ss,
/// ip and iw, which need netlink. The rest, terminal and ebpf among them, have not
/// been audited for it. A name missing from the table goes without too: unlike
/// the network, nothing here fails closed, because a worker that needs a socket
/// would only find out when it failed.
pub fn no_sockets(name: &str) -> bool {
    matches!(
        name,
        "capture" | "keylog" | "metrics-listener" | "metrics-client"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every worker name, the role it must have, and whether it takes the
    /// no-socket filter. A spawn site using a name that is not here fails
    /// `every_spawned_name_has_a_row`.
    const KNOWN: &[(&str, Role, bool)] = &[
        ("tokio-blocking", Role::Network, false),
        ("reverse-dns", Role::Network, false),
        ("whois", Role::Network, false),
        ("health", Role::Network, false),
        ("traceroute", Role::Network, false),
        ("insights", Role::Network, false),
        ("remote", Role::Network, false),
        ("diagnose-active", Role::Network, false),
        ("diagnose-test", Role::Network, false),
        ("diagnose-targets", Role::Network, false),
        ("capture", Role::Capture, true),
        ("proc-broker", Role::Broker, false),
        ("keylog", Role::Parser, true),
        ("metrics-listener", Role::Parser, true),
        ("metrics-client", Role::Parser, true),
        ("ebpf", Role::Parser, false),
        ("connections", Role::Parser, false),
        ("tcp-info", Role::Parser, false),
        ("traffic", Role::Parser, false),
        ("process-cpu", Role::Parser, false),
        ("terminal", Role::Parser, false),
        ("logging", Role::Parser, false),
        ("capture-export", Role::Parser, false),
        ("policy-preflight", Role::Parser, false),
        ("geoip-update", Role::Parser, false),
        ("pktap", Role::Parser, false),
        ("shutdown-deadline", Role::Parser, false),
    ];

    #[test]
    fn every_known_worker_name_maps_to_its_role() {
        for &(name, role, sockets) in KNOWN {
            assert_eq!(role_for(name), role, "{name}");
            assert_eq!(no_sockets(name), sockets, "{name}");
        }
    }

    #[test]
    fn threat_model_lists_the_no_socket_workers() {
        let doc = include_str!("../../docs/THREAT-MODEL.md");
        let listed = doc
            .split_once("<!-- policy:no-sockets -->")
            .and_then(|(_, rest)| rest.split_once("<!-- /policy:no-sockets -->"))
            .map(|(block, _)| block.trim())
            .expect("the threat model has a policy:no-sockets block");
        let filtered: Vec<_> = KNOWN
            .iter()
            .filter(|&&(_, _, sockets)| sockets)
            .map(|&(name, _, _)| name)
            .collect();
        // `lines`, because a Windows checkout has CRLF endings.
        assert_eq!(listed.lines().collect::<Vec<_>>(), filtered);
    }

    /// The name each `worker::` spawn, entry or relinquish call under `src`
    /// passes, with the file and line it is on.
    fn spawned_names() -> Vec<(String, String)> {
        let mut pending = vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
        let mut found = Vec::new();
        while let Some(path) = pending.pop() {
            if path.is_dir() {
                pending.extend(std::fs::read_dir(&path).unwrap().map(|e| e.unwrap().path()));
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            // Assembled, so this file does not match itself.
            for function in [
                "spawn",
                "spawn_retaining",
                "enter",
                "enter_retaining",
                "relinquish",
            ] {
                let call = format!("worker::{function}(");
                for (at, _) in text.match_indices(&call) {
                    let site = format!(
                        "{}:{}",
                        path.display(),
                        text[..at].matches('\n').count() + 1
                    );
                    let name = text[at + call.len()..]
                        .trim_start()
                        .strip_prefix('"')
                        .and_then(|rest| rest.split_once('"'))
                        .unwrap_or_else(|| panic!("{site}: the worker name is not a literal"))
                        .0;
                    found.push((name.to_string(), site));
                }
            }
        }
        found
    }

    #[test]
    fn every_spawned_name_has_a_row() {
        // A name role_for does not know is a parser, so renaming a network
        // worker's spawn site would take its network away and only the three
        // workers isolated_worker_boundaries probes would notice.
        let found = spawned_names();
        let unlisted: Vec<_> = found
            .iter()
            .filter(|(name, _)| !KNOWN.iter().any(|(known, _, _)| known == name))
            .collect();
        assert!(
            unlisted.is_empty(),
            "give these names a row in role_for and KNOWN: {unlisted:?}"
        );
        for &(name, role, _) in KNOWN {
            if role == Role::Network {
                assert!(
                    found.iter().any(|(spawned, _)| spawned == name),
                    "no spawn site uses the network worker name {name:?}"
                );
            }
        }
    }

    #[test]
    fn unknown_name_is_parser() {
        // Fails closed: a worker added without a row loses the network.
        // geoip was the online lookup worker, removed in 0.39. It has no row.
        for name in ["", "new-worker", "Capture", "whois ", "smoke", "geoip"] {
            assert_eq!(role_for(name), Role::Parser, "{name:?}");
            assert!(!no_sockets(name), "{name:?}");
        }
    }

    #[test]
    fn only_main_and_network_keep_the_network() {
        assert_eq!(Role::Main.layer(), None);
        assert_eq!(Role::Network.layer(), None);
        assert_eq!(Role::Parser.layer(), Some("parser"));
        assert_eq!(Role::Broker.layer(), Some("parser"));
        assert_eq!(Role::Capture.layer(), Some("capture"));
    }
}
