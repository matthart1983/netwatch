# Packet expert information

Packet colors and expert markers summarize protocol observations, such as resets, DNS errors or handshake messages. They are packet-level heuristics, not a diagnosis that a host is compromised or that a connection failed.

The [packet collector source](@repo@/src/collectors/packets) owns classification and the [packet UI](@repo@/src/ui/packets.rs) renders it. Avoid relying on a copied severity/color table across versions or themes.

Use [[Diagnose and Coverage]] for findings supported by diagnostic rules, and retain surrounding traffic when investigating an individual marker.
