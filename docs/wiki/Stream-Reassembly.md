# Stream tracking and reassembly

Stream tracking groups bidirectional flows and retains payloads for inspection. It does not guarantee complete TCP reconstruction or recovery from capture gaps. Press `s` on a packet for the stream view; use the [key reference](@repo@/docs/REFERENCE.md#stream-view).

Retention has per-stream limits, a stream-count limit and a global stream budget: one eighth of detected host memory, capped at 256 MiB (the cap is used when memory is unknown). The packet ring has a separate 32 MiB byte budget. These are not total process RSS limits. See [PERFORMANCE](@repo@/docs/PERFORMANCE.md) and the [tracker](@repo@/src/collectors/packets/mod.rs).

v0.39.0 does not include the subsequent split-TCP-ClientHello fix. That development improvement still does not handle out-of-order segments or a ClientHello split across TLS records. See [release distinctions](@repo@/docs/REFERENCE.md#deep-packet-inspection).

## Inspect one conversation

Select a packet, press `s`, and use the direction controls to separate client and
server data. Text view is convenient for readable payloads; hex view preserves
bytes that cannot be rendered as text. A stream is bidirectional and depends on
the captured endpoints, protocol and the tracker's capture/generation context.

Do not concatenate the displayed text and assume it is the complete application
message. Capturing only one direction, missing a segment or evicting retained
payload can all leave a partial conversation. TCP sequence-anomaly tracking is
not full out-of-order reconstruction. UDP grouping is not a reliability guarantee.

## Retention and capture completeness

The per-stream limits (10,000 retained segments and 2 MiB payload) are only part
of the memory policy. Stream-count and global byte budgets can evict older flows.
The packet ring and stream buffers have different budgets, so their visible
history need not cover exactly the same interval.

For incident evidence, export while the relevant packets are still retained and
read the export preview's omission/limitation information. A stopped capture does
not reconstruct lost history. Start a new connection after capture begins when
investigating a handshake-dependent feature.

<!-- include: docs/PERFORMANCE.md#memory-ceiling -->

<!-- include: docs/REFERENCE.md#stream-view -->
