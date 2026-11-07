# JA4 fingerprints

JA4/JA4Q summarize observed TLS/QUIC ClientHello characteristics. Similar stacks can share a fingerprint, and versions/configuration can change it; a match is an investigation clue, not unique process identity or a malware verdict.

Use `ja4:<fingerprint>` in [[Display Filters]]. Missing/incomplete handshakes can prevent fingerprinting; ECH outer metadata does not reveal the hidden destination.

See the [fingerprint reference](@repo@/docs/REFERENCE.md#threat-hunting-with-ja4) and [[eBPF Process Attribution]] for the separate ownership evidence model.

## Investigate a fingerprint

1. Start capture before the connection's handshake.
2. Find a TLS/QUIC packet with a decoded ClientHello and inspect its fingerprint.
3. Copy the actual observed value into `ja4:<value>` in the display filter.
4. Compare destinations, times and available process evidence across matches.
5. Validate any hypothesis against other evidence before labeling software or traffic.

A shared TLS library can make unrelated applications look alike. A single
application can produce different fingerprints after an update or configuration
change. The database label is a hint, not a verified executable identity.

## Why a fingerprint might be absent

- Capture began after the handshake or missed required packets.
- The link framing or protocol path was not decoded.
- The ClientHello exceeds the release's supported reconstruction behavior.
- ECH obscures information needed for the interpretation you want to make.

v0.39.0 lacks the later contiguous split-TCP-ClientHello fix. Turning on decryption
does not recover a handshake that NetWatch never captured or could not parse.

<!-- include: docs/REFERENCE.md#threat-hunting-with-ja4 -->
