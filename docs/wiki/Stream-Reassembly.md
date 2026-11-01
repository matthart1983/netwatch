# Stream tracking and reassembly

Stream tracking groups bidirectional flows and retains payloads for inspection. It does not guarantee complete TCP reconstruction or recovery from capture gaps. Press `s` on a packet for the stream view; use the [key reference](@repo@/docs/REFERENCE.md#stream-view).

Retention has per-stream limits, a stream-count limit and a global stream budget: one eighth of detected host memory, capped at 256 MiB (the cap is used when memory is unknown). The packet ring has a separate 32 MiB byte budget. These are not total process RSS limits. See [PERFORMANCE](@repo@/docs/PERFORMANCE.md) and the [tracker](@repo@/src/collectors/packets/mod.rs).

v0.39.0 does not include the subsequent split-TCP-ClientHello fix. That development improvement still does not handle out-of-order segments or a ClientHello split across TLS records. See [release distinctions](@repo@/docs/REFERENCE.md#deep-packet-inspection).
