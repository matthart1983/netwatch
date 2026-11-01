# Display filters

Use `/` on Packets to filter retained packets. Capture continues independently. Examples include `tcp and port 443`, `app:tls`, `sni:example.com` and `decrypted:true`.

See the [filter grammar and examples](@repo@/docs/REFERENCE.md#display-filters) for operators, metadata matching and supported syntax. A missing metadata match may reflect an incomplete or unsupported decode.

BPF capture filters are separate: they limit packets before NetWatch processes them. Set them using the capture controls described in the [Packets key reference](@repo@/docs/REFERENCE.md#packets).
