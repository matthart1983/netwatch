# Traceroute

Press `T` on a selected connection or topology host to start an explicit trace. Traceroute sends probes; no response can reflect filtering and does not by itself establish a failed destination.

Linux prefers a native UDP/TTL path; Windows has a native ICMP API path. Subprocess fallbacks and macOS use depend on platform and target support. Installing a `traceroute` command or running as root is not the universal first fix.

See the [implementation](@repo@/src/collectors/traceroute.rs), [[Doctor]] and [outbound inventory](@repo@/docs/THREAT-MODEL.md#outbound-inventory). Startup traces and configured diagnostic traces have separate triggers and controls.

## Run and read a trace

1. Select the remote connection in Connections or a remote host in Topology.
2. Press `T` to open a trace. This actively sends traffic toward the selected host.
3. Read the sequence of responding hops, returned addresses and RTT samples.
4. Compare repeated runs with the same destination before attributing a change to
   the network; routing and reply policies can change between probes.
5. Close the overlay with `Esc`; keep any relevant timestamps with your report.

| Result | What it establishes | What it does not establish |
| --- | --- | --- |
| A hop replies | That probe elicited a reply from that address. | That all application traffic follows an identical path. |
| Intermediate hop is silent | No reply was observed for those probes. | That forwarding stopped there. Later hops can still answer. |
| One hop has high RTT | Its reply arrived late. | That it delays transit traffic by the same amount; routers can deprioritize replies. |
| Destination does not reply | The trace did not establish a destination response. | That the application's TCP/TLS service is unreachable. |

## Platform paths and failures

Linux's native path uses UDP with TTL and the socket error queue, so a missing
`traceroute` executable is not necessarily a problem. Windows uses its ICMP API
where supported. Subprocess fallback depends on an available platform command;
macOS uses that path. Hostnames, address families and errors can influence which
path is available.

Check the reported error before installing utilities or changing privileges. If
tracing is inconclusive, use a configured Diagnose target to test DNS, TCP, TLS
and HTTP for the actual service. Startup traces have their own target and opt-out
rules; pressing `T` is a separate explicit action.
