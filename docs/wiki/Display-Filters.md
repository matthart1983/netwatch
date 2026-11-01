# Display filters

Use `/` on Packets to filter retained packets. Capture continues independently. Examples include `tcp and port 443`, `app:tls`, `sni:example.com` and `decrypted:true`.

See the [filter grammar and examples](@repo@/docs/REFERENCE.md#display-filters) for operators, metadata matching and supported syntax. A missing metadata match may reflect an incomplete or unsupported decode.

BPF capture filters are separate: they limit packets before NetWatch processes them. Set them using the capture controls described in the [Packets key reference](@repo@/docs/REFERENCE.md#packets).

## Work from a question to a filter

| Question | Display filter | Interpretation |
| --- | --- | --- |
| Which retained TCP packets use HTTPS's usual port? | `tcp and port 443` | Transport/port selection; not proof that the payload is HTTPS. |
| What names were visible in TLS? | `app:tls` then `sni:example.com` | Depends on a captured, supported ClientHello; ECH can hide the real name. |
| What belongs to one retained conversation? | `stream 7` | Uses the selected capture's stream index, not a persistent global ID. |
| What came from this host? | `ip.src == 10.0.0.1` | Source direction only; use the appropriate observed address. |
| Which records were decrypted? | `decrypted:true` | Successful supported decryption, not every encrypted packet. |

Start broad, confirm the traffic is retained, then add one condition at a time.
An empty result can mean the filter is too narrow, metadata was unavailable,
the ring evicted the packets, or the interface never saw them.

## Display filtering versus capture filtering

A display filter narrows the retained packet list; removing it can reveal other
packets that are still retained. A BPF capture filter discards nonmatching traffic
before NetWatch processes it. Removing that filter cannot recover packets never
captured. For example, BPF `tcp port 443` excludes ordinary UDP DNS and QUIC,
which can remove the evidence needed to explain an HTTPS problem.

Use the `b` capture control to configure BPF, with capture stopped. In particular,
NetWatch's `sni:` and `ja4:` display operators are not BPF syntax.

<!-- include: docs/REFERENCE.md#display-filters -->

<!-- include: docs/REFERENCE.md#packets -->
