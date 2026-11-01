# JA4 fingerprints

JA4/JA4Q summarize observed TLS/QUIC ClientHello characteristics. Similar stacks can share a fingerprint, and versions/configuration can change it; a match is an investigation clue, not unique process identity or a malware verdict.

Use `ja4:<fingerprint>` in [[Display Filters]]. Missing/incomplete handshakes can prevent fingerprinting; ECH outer metadata does not reveal the hidden destination.

See the [fingerprint reference](@repo@/docs/REFERENCE.md#threat-hunting-with-ja4) and [[eBPF Process Attribution]] for the separate ownership evidence model.
