# Deep packet inspection

NetWatch parses application metadata where the captured bytes and protocol implementation allow it. Classifiers, lower-layer parsers, decryption and HTTP/3 decoding are different capabilities; adding their names together produces a misleading protocol count.

The [protocol table](@repo@/docs/REFERENCE.md#protocol-decoders) is the maintained support list. DNS-over-TCP is not classified; DoT/DoH surface at the TLS layer. Encrypted application data needs supported session secrets; ECH can hide the real destination name.

See [[Stream Reassembly]], [[TLS Decryption]], [[JA4 Fingerprinting]] and [[Display Filters]]. Partial capture can mean partial metadata, not proof that the protocol or destination is absent.

<!-- include: docs/REFERENCE.md#protocol-decoders -->

<!-- include: docs/REFERENCE.md#tls-13--12-decryption -->
