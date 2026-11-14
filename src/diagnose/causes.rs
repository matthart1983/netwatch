//! Every cause each rule can rank and the checks behind it, by stable id.
//!
//! The detectors build causes in code, often from runtime values; this table is
//! the fixed list a feature schema or a label vocabulary can be built from.
//! `every_emitted_id_is_catalogued` and the source scan in the tests keep it in
//! step with `detectors.rs`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CauseSpec {
    pub rule: &'static str,
    pub cause: &'static str,
    pub checks: &'static [&'static str],
}

pub const CAUSES: &[CauseSpec] = &[
    CauseSpec {
        rule: "ipv6.broken",
        cause: "ipv6_path_failure",
        checks: &["paired_family_failures"],
    },
    CauseSpec {
        rule: "captive.portal",
        cause: "http_interception",
        checks: &["independent_http_redirects"],
    },
    CauseSpec {
        rule: "pmtu.blackhole",
        cause: "size_dependent_path_failure",
        checks: &["mss_restores_transfer"],
    },
    CauseSpec {
        rule: "tcp.connect_failures",
        cause: "namespace_handshake_failures",
        checks: &["attempt_fails_increased"],
    },
    CauseSpec {
        rule: "tcp.timewait_exhaustion",
        cause: "ephemeral_timewait_pressure",
        checks: &["distinct_timewait_ports"],
    },
    CauseSpec {
        rule: "egress.drift",
        cause: "new_public_destination",
        checks: &["outside_learned_baseline"],
    },
    CauseSpec {
        rule: "egress.policy_violation",
        cause: "blocked_by_policy",
        checks: &["policy_blocks_destination"],
    },
    CauseSpec {
        rule: "egress.policy_violation",
        cause: "outside_declared_policy",
        checks: &["policy_rejects_destination"],
    },
    CauseSpec {
        rule: "link.down",
        cause: "unplugged_or_port_down",
        checks: &["carrier"],
    },
    CauseSpec {
        rule: "link.down",
        cause: "wifi_disassociated",
        checks: &["wireless"],
    },
    CauseSpec {
        rule: "iface.errors",
        cause: "ring_buffer_small",
        checks: &["drops_dominate"],
    },
    CauseSpec {
        rule: "iface.errors",
        cause: "bad_cable_or_duplex",
        checks: &["errors_dominate"],
    },
    CauseSpec {
        rule: "wifi.weak_signal",
        cause: "weak_signal",
        checks: &["signal_weak"],
    },
    CauseSpec {
        rule: "wifi.weak_signal",
        cause: "congested_channel",
        checks: &["retries_high", "signal_fine"],
    },
    CauseSpec {
        rule: "iface.saturated",
        cause: "link_at_capacity",
        checks: &["utilisation"],
    },
    CauseSpec {
        rule: "gateway.unreachable",
        cause: "icmp_filtered",
        checks: &[
            "arp_resolves",
            "icmp_reaches_the_gateway",
            "nothing_beyond_the_gateway_answers_either",
        ],
    },
    CauseSpec {
        rule: "gateway.unreachable",
        cause: "wrong_vlan_or_address_conflict",
        checks: &["arp_fails", "nothing_beyond_the_gateway_answers_either"],
    },
    CauseSpec {
        rule: "gateway.rtt_spike",
        cause: "local_network_congested",
        checks: &["gateway_rtt_above_baseline"],
    },
    CauseSpec {
        rule: "gateway.rtt_spike",
        cause: "gateway_loaded",
        checks: &["gateway_cpu"],
    },
    CauseSpec {
        rule: "dns.failing",
        cause: "resolver_down",
        checks: &[
            "resolver_unreachable",
            "reference_answers_over_the_same_uplink",
        ],
    },
    CauseSpec {
        rule: "dns.failing",
        cause: "resolver_erroring",
        checks: &["servfail_replies"],
    },
    CauseSpec {
        rule: "dns.failing",
        cause: "uplink_down",
        checks: &["reference_also_unanswered"],
    },
    CauseSpec {
        rule: "dns.failing",
        cause: "udp53_filtered",
        checks: &["resolver_reachable"],
    },
    CauseSpec {
        rule: "dns.truncation_retry",
        cause: "no_edns",
        checks: &["truncated_replies"],
    },
    CauseSpec {
        rule: "dns.truncation_retry",
        cause: "middlebox_clamps_udp",
        checks: &["edns_through_the_path"],
    },
    CauseSpec {
        rule: "dns.hijack_suspect",
        cause: "interceptor",
        checks: &["private_answer_for_a_public_name"],
    },
    CauseSpec {
        rule: "dns.hijack_suspect",
        cause: "forged_records",
        checks: &["disagrees_with_reference", "reference_validated"],
    },
    CauseSpec {
        rule: "dns.hijack_suspect",
        cause: "split_horizon",
        checks: &["private_answer_for_a_public_name"],
    },
    CauseSpec {
        rule: "dns.slow_resolver",
        cause: "upstream_slow",
        checks: &[
            "alt_resolver_is_fast",
            "resolver_itself_is_reachable",
            "cached_names_still_fast",
        ],
    },
    CauseSpec {
        rule: "dns.slow_resolver",
        cause: "resolver_overloaded",
        checks: &["icmp_rtt_raised", "timeouts_or_servfail_present"],
    },
    CauseSpec {
        rule: "dns.slow_resolver",
        cause: "local_udp_path",
        checks: &[
            "alt_resolver_over_the_same_path_is_also_slow",
            "interface_drops",
            "local_drop_counters",
        ],
    },
    CauseSpec {
        rule: "path.rtt_spike",
        cause: "hop_adds_latency",
        checks: &["one_hop_dominates"],
    },
    CauseSpec {
        rule: "path.rtt_spike",
        cause: "route_change",
        checks: &["the_path_changed"],
    },
    CauseSpec {
        rule: "path.changed",
        cause: "provider_reroute",
        checks: &["asn_changed", "asn_unchanged", "hop_address_changed"],
    },
    CauseSpec {
        rule: "path.changed",
        cause: "local_route_change",
        checks: &["change_is_at_hop_1_or_2"],
    },
    CauseSpec {
        rule: "path.high_loss",
        cause: "hop_dropping",
        checks: &[
            "loss_propagates_to_later_hops",
            "destination_answered_the_trace",
        ],
    },
    CauseSpec {
        rule: "path.high_loss",
        cause: "icmp_rate_limit",
        checks: &["later_hops_are_clean", "destination_answered_the_trace"],
    },
    CauseSpec {
        rule: "tcp.bufferbloat_remote",
        cause: "unlocalised_queueing",
        checks: &[
            "link_level_bufferbloat_test_passed",
            "rtt_tracks_this_socket_s_own_tx",
        ],
    },
    CauseSpec {
        rule: "tcp.bufferbloat_remote",
        cause: "receiver_queueing",
        checks: &[
            "link_level_bufferbloat_test_passed",
            "rtt_tracks_this_socket_s_own_tx",
        ],
    },
    CauseSpec {
        rule: "tcp.bufferbloat_remote",
        cause: "path_loss",
        checks: &["the_path_to_this_peer_is_losing_packets"],
    },
    CauseSpec {
        rule: "tcp.retrans_burst",
        cause: "packet_loss",
        checks: &["retransmits_observed", "socket_rtt_below_queueing_line"],
    },
    CauseSpec {
        rule: "tcp.zero_window",
        cause: "peer_not_reading",
        checks: &["rwnd_is_zero"],
    },
    CauseSpec {
        rule: "tcp.zero_window",
        cause: "peer_reading_slowly",
        checks: &["cwnd_exceeds_rwnd"],
    },
    CauseSpec {
        rule: "nat.symmetric",
        cause: "address_dependent_nat",
        checks: &["mapping_depends_on_destination"],
    },
    CauseSpec {
        rule: "nat.symmetric",
        cause: "router_symmetric_nat",
        checks: &["single_nat_layer"],
    },
    CauseSpec {
        rule: "tcp.bufferbloat_local",
        cause: "no_aqm_upstream",
        checks: &["rtt_rises_under_our_own_load"],
    },
    CauseSpec {
        rule: "target.resolve_failed",
        cause: "vpn_split_dns_missing",
        checks: &["vpn_interface_up", "another_resolver_answers"],
    },
    CauseSpec {
        rule: "target.resolve_failed",
        cause: "resolver_failing",
        checks: &["lookup_failed_not_nxdomain", "public_names_failing_too"],
    },
    CauseSpec {
        rule: "target.resolve_failed",
        cause: "name_does_not_exist",
        checks: &["every_resolver_says_nxdomain", "no_vpn_interface"],
    },
    CauseSpec {
        rule: "target.connect_failed",
        cause: "service_down",
        checks: &["connection_refused"],
    },
    CauseSpec {
        rule: "target.connect_failed",
        cause: "firewall_or_route",
        checks: &[
            "no_proxy_configured",
            "connection_timed_out",
            "internet_reachable",
            "other_address_family_also_fails",
        ],
    },
    CauseSpec {
        rule: "target.connect_failed",
        cause: "ipv6_path_broken",
        checks: &["ipv6_fails_ipv4_works"],
    },
    CauseSpec {
        rule: "target.connect_failed",
        cause: "proxy_required",
        checks: &["proxy_configured", "connection_timed_out"],
    },
    CauseSpec {
        rule: "target.tls_failed",
        cause: "cert_untrusted",
        checks: &["issuer_unknown", "no_proxy_configured"],
    },
    CauseSpec {
        rule: "target.tls_failed",
        cause: "clock_skew",
        checks: &["certificate_outside_validity", "clock_offset_large"],
    },
    CauseSpec {
        rule: "target.tls_failed",
        cause: "tls_intercepting_proxy",
        checks: &["issuer_unknown", "proxy_configured"],
    },
    CauseSpec {
        rule: "target.http_error",
        cause: "service_error",
        checks: &["status_5xx"],
    },
    CauseSpec {
        rule: "target.http_error",
        cause: "proxy_rejected",
        checks: &["status_407_or_403", "proxy_configured"],
    },
    CauseSpec {
        rule: "target.slow_stage",
        cause: "dns_stage_slow",
        checks: &["dns_stage_above_baseline"],
    },
    CauseSpec {
        rule: "target.slow_stage",
        cause: "connect_stage_slow",
        checks: &["connect_stage_above_baseline"],
    },
    CauseSpec {
        rule: "target.slow_stage",
        cause: "tls_stage_slow",
        checks: &["tls_stage_above_baseline"],
    },
    CauseSpec {
        rule: "target.slow_stage",
        cause: "server_stage_slow",
        checks: &["server_stage_above_baseline"],
    },
];

pub fn lookup(rule: &str, cause: &str) -> Option<&'static CauseSpec> {
    CAUSES.iter().find(|c| c.rule == rule && c.cause == cause)
}

/// Whether a detector's output is in the catalogue: the cause under its rule,
/// and every check under that cause.
pub fn is_catalogued(rule: &str, cause: &super::issue::Cause) -> bool {
    lookup(rule, &cause.id).is_some_and(|spec| {
        cause
            .checks
            .iter()
            .all(|k| spec.checks.contains(&k.id.as_str()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn cause_keys_are_unique_and_rules_exist() {
        let mut seen = HashSet::new();
        for c in CAUSES {
            assert!(
                seen.insert((c.rule, c.cause)),
                "{}/{} listed twice",
                c.rule,
                c.cause
            );
            assert!(
                super::super::rules::lookup(c.rule).is_some(),
                "{} is not a rule",
                c.rule
            );
            let checks: HashSet<_> = c.checks.iter().collect();
            assert_eq!(
                checks.len(),
                c.checks.len(),
                "{}/{} repeats a check",
                c.rule,
                c.cause
            );
        }
    }

    /// Every literal id in the detector source is catalogued, and nothing in
    /// the catalogue is missing from the source.
    #[test]
    fn the_catalogue_matches_the_detector_source() {
        let body = [
            include_str!("detectors.rs"),
            include_str!("egress.rs"),
            include_str!("kernel.rs"),
            include_str!("active.rs"),
        ]
        .iter()
        .map(|src| &src[..src.find("#[cfg(test)]").unwrap()])
        .collect::<Vec<_>>()
        .join("\n");
        let literal_ids = |needle: &str| -> HashSet<String> {
            body.match_indices(needle)
                .filter_map(|(at, _)| {
                    let rest = body[at + needle.len()..].trim_start().strip_prefix('"')?;
                    Some(rest.split_once('"')?.0.to_string())
                })
                .collect()
        };
        let source_causes = literal_ids("Cause::new(");
        let mut source_checks = HashSet::new();
        for n in [
            "CheckResult::pass(",
            "CheckResult::fail(",
            "CheckResult::not_run(",
            "stage_check(",
        ] {
            source_checks.extend(literal_ids(n));
        }
        let causes: HashSet<String> = CAUSES.iter().map(|c| c.cause.to_string()).collect();
        let checks: HashSet<String> = CAUSES
            .iter()
            .flat_map(|c| c.checks.iter().map(|k| k.to_string()))
            .collect();
        assert_eq!(causes, source_causes);
        assert_eq!(checks, source_checks);
    }
}
