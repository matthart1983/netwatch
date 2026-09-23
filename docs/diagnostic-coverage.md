# Diagnose rule coverage

Generated from `rules::CATALOGUE` by `netwatch diagnose coverage --doc`. Do not edit by hand: `rules.rs` holds the source of truth, and a test fails when this file and the catalogue disagree.

The catalogue contains **30 rules**, of which **30** are active. **8** have been through a contract review: evidence, lookalikes, recovery and platform limits all stated. The rest are listed as not yet contracted, which is a statement about this document, not about whether the detector runs.

Runtime availability is a separate question, answered per host by `netwatch diagnose coverage`: a rule with a detector may still have no inputs on the machine in front of you. An empty issue list says "no findings", never "this host is healthy".

## Contracted rules

### `dns.hijack_suspect`

dns answers disagree · severity High

**Fires when:** a private address for a public name, or disagreement with a validating reference on most cycles

**Evidence required:**

- the same name asked of the configured resolver and of a reference resolver
- whether the answer is private, and whether the reference validated it

**Healthy lookalikes:**

- split-horizon dns on a corporate network, which is by design
- a cdn answering differently by geography

**Recovery:** the two resolvers agree again, or the private answer stops

**Platforms:** anywhere a reference resolver is reachable; blocked outbound dns leaves it unmeasured

### `gateway.unreachable`

gateway unreachable · severity Critical

**Fires when:** arp or icmp to the default gateway fails

**Evidence required:**

- arp or icmp probe to the default gateway, with its result
- an internet probe beyond the gateway, to tell a quiet router from a broken one

**Healthy lookalikes:**

- a router that does not answer icmp but forwards normally
- an unprivileged run that cannot send icmp at all

**Recovery:** the gateway answers again, or something beyond it does

**Platforms:** linux and macos; no arp probe exists yet, so arp is reported as unmeasured

**Suppresses:** `dns.slow_resolver`, `dns.failing`, `gateway.rtt_spike`, `path.high_loss`, `path.rtt_spike`, `tcp.retrans_burst`, `tcp.connect_failures`, `target.resolve_failed`, `target.connect_failed`, `target.tls_failed`, `target.http_error`, `target.slow_stage`

### `path.high_loss`

loss on the path · severity High

**Fires when:** a hop loses packets and the loss propagates to later hops

**Evidence required:**

- per-hop loss from a trace, with silent hops distinguished from lossy ones
- whether the destination itself answered the trace

**Healthy lookalikes:**

- a hop rate-limiting its own icmp while forwarding traffic normally
- a firewalled tail that answers nothing, so propagation cannot be seen

**Recovery:** a later trace to the same target shows no hop losing packets

**Platforms:** native trace on linux ipv4; elsewhere a traceroute subprocess, which cannot always tell whether the destination replied

**Suppresses:** `tcp.retrans_burst`

### `tcp.bufferbloat_remote`

receiver-side bufferbloat · severity Medium

**Fires when:** one socket's rtt rises with its own tx while the link-level test passes

**Evidence required:**

- socket rtt and tx rate from the kernel, held for the verdict window
- an idle-versus-loaded rtt comparison on our own uplink, to place the queue

**Healthy lookalikes:**

- a stable distant peer, whose rtt is distance rather than queueing
- our own uplink bloating, which is the local rule, not this one

**Recovery:** socket rtt returns to its baseline while the socket is still sending

**Platforms:** linux and macos; without the loaded-rtt test the finding names an unlocalised queue

### `target.resolve_failed`

target name does not resolve · severity Medium

**Fires when:** a configured target's name fails to resolve for 3 probes

**Evidence required:**

- a lookup for the configured target, with the resolver that answered
- the outcome per resolver: answered, nxdomain, servfail or no reply

**Healthy lookalikes:**

- a name that genuinely does not exist
- split-horizon dns where the name only resolves on another link

**Recovery:** the same target resolves again on its own probe

**Platforms:** all platforms; resolver identity comes from systemd-resolved where available

**Suppresses:** `target.connect_failed`, `target.tls_failed`, `target.http_error`, `target.slow_stage`

### `target.connect_failed`

target refuses or drops connections · severity Medium

**Fires when:** a configured target's first address fails to connect for 3 probes

**Evidence required:**

- a connect attempt per address and family, with the error each returned

**Healthy lookalikes:**

- a service that is down, which is not a network fault
- one address family broken while the other works

**Recovery:** the same target connects again on its own probe

**Platforms:** all platforms

**Suppresses:** `target.tls_failed`, `target.http_error`, `target.slow_stage`

### `target.tls_failed`

target tls handshake fails · severity Medium

**Fires when:** a configured target's TLS handshake fails for 3 probes

**Evidence required:**

- the tls handshake result on the connection that succeeded, with the certificate error

**Healthy lookalikes:**

- an enterprise ca that netwatch does not trust
- a clock skew that makes a valid certificate look expired

**Recovery:** the handshake completes again on the same target

**Platforms:** all platforms; system trust stores are read where available

**Suppresses:** `target.http_error`, `target.slow_stage`

### `target.http_error`

target returns an error · severity Medium

**Fires when:** a configured target answers 5xx, or not the expected status, for 3 probes

**Evidence required:**

- the response status on the configured target, against the expected status

**Healthy lookalikes:**

- an authentication or redirect response that is expected for this endpoint
- a proxy answering instead of the service

**Recovery:** the target returns its expected status again

**Platforms:** all platforms

## Not yet contracted

These rules have detectors and can open issues. What they have not had is a written statement of the evidence they need and the healthy situations they must not mistake for a fault.

| Rule | Category | Fires when | Status |
|---|---|---|---|
| `dns.slow_resolver` | dns | resolver p50 > 3σ above baseline for 3 samples, or p50 > 100ms with no baseline | active |
| `dns.failing` | dns | servfail/timeout rate > 5%, or the pipeline dns stage fails | active |
| `dns.truncation_retry` | dns | more than 10% of probe replies carry the TC bit | active |
| `link.down` | link | interface carrier lost | active |
| `gateway.rtt_spike` | link | gateway rtt > 3σ above baseline for 3 samples | active |
| `iface.errors` | link | rx/tx error, drop, overrun or fifo counters increment | active |
| `iface.saturated` | link | throughput above 90% of link rate for 30s | active |
| `wifi.weak_signal` | link | signal at or below −70 dBm, or more than 20% of frames retried over a minute | active |
| `path.changed` | path | a hop differs between consecutive traces to the same target | active |
| `path.rtt_spike` | path | end-to-end rtt > 3σ above baseline | active |
| `tcp.bufferbloat_local` | tcp | rtt under load exceeds idle rtt by more than 100ms | active |
| `tcp.retrans_burst` | tcp | 5 or more retransmits per minute on a socket whose rtt is under the queueing threshold | active |
| `tcp.zero_window` | tcp | rwnd is zero, or cwnd greatly exceeds rwnd | active |
| `tcp.connect_failures` | tcp | more than 5 failed active or passive TCP handshakes per minute in this namespace | active |
| `tcp.timewait_exhaustion` | tcp | distinct TIME_WAIT local ports exceed 60% of the ephemeral range for one address; not exhaustion proof | active |
| `pmtu.blackhole` | mtu | small DF probes work, large probes time out, and reducing TCP MSS restores a transfer to the same endpoint | active |
| `nat.symmetric` | nat | two stun servers see different public ports from one socket | active |
| `ipv6.broken` | ipv6 | a v6 default route exists but v6 probes fail while v4 works | active |
| `captive.portal` | captive | the http 204 probe is redirected | active |
| `target.slow_stage` | target | a target's dns, connect, tls or first-byte time > 3σ above its baseline for 3 probes | active |
| `egress.drift` | egress | a destination outside the learned egress baseline (only with alert = "all") | active |
| `egress.policy_violation` | egress | an observed destination is blocked by the loaded policy, or with alert = "all" falls outside it (warning only) | active |
