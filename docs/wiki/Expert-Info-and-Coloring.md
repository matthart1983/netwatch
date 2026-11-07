# Packet expert information

Packet colors and expert markers summarize protocol observations, such as resets, DNS errors or handshake messages. They are packet-level heuristics, not a diagnosis that a host is compromised or that a connection failed.

The [packet collector source](@repo@/src/collectors/packets) owns classification and the [packet UI](@repo@/src/ui/packets.rs) renders it. Avoid relying on a copied severity/color table across versions or themes.

Use [[Diagnose and Coverage]] for findings supported by diagnostic rules, and retain surrounding traffic when investigating an individual marker.

## Severity examples

The classifier checks packet flags and decoded summary text. Its categories are
clues about individual packets:

| Observation | Category | How to investigate |
| --- | --- | --- |
| TCP RST | Error | Inspect direction and preceding packets; a reset can be an intentional refusal or application close. |
| DNS NXDOMAIN, server failure or refusal | Error | Read the query and response; a nonexistent name need not indicate a resolver outage. |
| DNS format error | Warn | Inspect the request/response context and parser visibility. |
| ICMP unreachable or time exceeded | Warn | Identify which flow/probe triggered it; time exceeded is normal in traceroute. |
| TCP zero-window text | Warn | Look for repeated receiver backpressure and subsequent recovery. |
| HTTP 4xx/5xx | Warn | Distinguish application status from a transport failure. |
| TCP FIN, DNS response or TLS ServerHello | Note | Normal connection/protocol progress can produce these markers. |
| SYN initiation, DNS query, ARP or TLS ClientHello | Chat | Routine traffic, not a positive health verdict. |

Matching order matters: a packet with a reset flag is classified before later
protocol-specific checks. A parser that lacks the required decoded text cannot
apply a text-based heuristic. Themes affect presentation; use the category and
packet detail rather than relying on a remembered color.

## Investigate a marker

1. In Packets, press `x` to narrow the retained list to expert findings.
2. Select a packet and inspect direction, time and protocol detail.
3. Use `s` to inspect its retained stream; turn off the expert-only filter to see
   surrounding normal traffic as well.
4. Compare with Diagnose evidence and the application's observed failure.
5. Preview an export with `w` if the capture is needed for further analysis.

A filtered export contains the shown selection. Retain enough surrounding traffic
to explain the marker; a reset packet alone rarely explains why it happened.
