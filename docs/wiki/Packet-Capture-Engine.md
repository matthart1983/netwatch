# Packet capture engine

Capture requires libpcap/BPF or Npcap access and visibility on the selected interface. [[Doctor]] can inspect setup and perform an optional bounded capture-open check.

Capture decodes packets, tracks flows and retains bounded packet/stream history. Display filtering does not change what is captured; BPF capture filtering does. Packet/stream eviction and capture gaps limit later analysis and exports.

See the [capture/export reference](@repo@/docs/REFERENCE.md#capture-export), [measured retention limits](@repo@/docs/PERFORMANCE.md), [[Stream Reassembly]] and [[Deep Packet Inspection]]. Capture is not a full out-of-order TCP reconstruction engine.
