# Configuration and privacy

Use the [configuration reference](@repo@/docs/REFERENCE.md#configuration) for defaults, allowed values and platform paths. Settings persist when saved; sessions can also retain baselines, uptime and recovery evidence. Exports may contain payloads, addresses and names.

Read [what NetWatch sends](@repo@/docs/REFERENCE.md#what-netwatch-sends-off-this-machine) before enabling or disabling features. Health/startup probes and configured Diagnose targets can send traffic automatically. WHOIS, explicit experiments, traceroute and GeoIP updates have their own triggers. AI and remote ingestion are opt-in.

`third_party_probes = false` disables the named default probes, not all outbound traffic: configured targets, user actions, Insights, remote ingestion and resolver/gateway checks have separate behavior. Local GeoIP lookup does not contact an online lookup service.

See the [outbound inventory](@repo@/docs/THREAT-MODEL.md#outbound-inventory), [[AI Insights]] and [[Daemon and Metrics]].

<!-- include: docs/REFERENCE.md#what-netwatch-sends-off-this-machine -->

<!-- include: docs/REFERENCE.md#configuration -->

<!-- include: docs/ARCHITECTURE.md#configuration-and-persistence -->
