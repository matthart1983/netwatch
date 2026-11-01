# Traceroute

Press `T` on a selected connection or topology host to start an explicit trace. Traceroute sends probes; no response can reflect filtering and does not by itself establish a failed destination.

Linux prefers a native UDP/TTL path; Windows has a native ICMP API path. Subprocess fallbacks and macOS use depend on platform and target support. Installing a `traceroute` command or running as root is not the universal first fix.

See the [implementation](@repo@/src/collectors/traceroute.rs), [[Doctor]] and [outbound inventory](@repo@/docs/THREAT-MODEL.md#outbound-inventory). Startup traces and configured diagnostic traces have separate triggers and controls.
