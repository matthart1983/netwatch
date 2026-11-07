# TLS and QUIC decryption

With usable session secrets and a supported capture, NetWatch can decrypt TLS 1.3, TLS 1.2 AEAD and QUIC 1-RTT application traffic. HTTP/3 decoding is available over supported decrypted QUIC traffic. Use this for traffic you are authorized to inspect.

Follow the [protected keylog setup and cipher support](@repo@/docs/REFERENCE.md#tls-13--12-decryption). Start capture before the connection; verify that the client's TLS backend actually exports keys. Keylogs and decrypted exports contain sensitive data. Stop their producers and clean up keys after the test.

TLS 1.2 legacy CBC is unsupported. TLS 1.3 observed KeyUpdate is handled, but missed-update recovery and capture gaps have limits; see the [decryptor contract](@repo@/src/dpi/tls_decrypt.rs). v0.39.0 lacks the later split-TCP-ClientHello fix. Missing keys or insufficient handshake data leave traffic opaque.

[[Sandbox]] is defense in depth, not a guarantee that the configured keylog is the only secret reachable by the process. The origin of traffic does not itself determine decryptability.

<!-- include: docs/REFERENCE.md#tls-13--12-decryption -->
