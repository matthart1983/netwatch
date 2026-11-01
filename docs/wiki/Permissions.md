# Capture permissions

Start with `netwatch doctor`, then use `netwatch doctor --check-capture` if you want the bounded capture-open check. DNS queries and many interface/connection observations do not inherently need root.

On Linux, follow the [restricted group and file-capability recipe](@repo@/docs/REFERENCE.md#running-without-sudo-linux). Apply ownership and execute restrictions before capabilities, log in again after changing group membership, and repeat the recipe after upgrades. Do not grant capture capabilities to a world-executable binary.

The [systemd service](@repo@/packaging/README.md) grants capabilities to its service user; its binary needs no file capabilities. Do not apply the file-capability recipe indiscriminately to that deployment.

macOS/FreeBSD require administrator-managed BPF access; do not make every `/dev/bpf*` device globally readable. Windows requires Npcap and its configured access policy. See [platform permissions](@repo@/docs/REFERENCE.md#permissions). Root access does not establish complete attribution or sandbox containment.

<!-- include: docs/REFERENCE.md#permissions -->
