# Getting started

1. Choose your platform's install method in the [README](@repo@/README.md) or [packaging guide](@repo@/docs/PACKAGING.md).
2. Run `netwatch --version` and `netwatch doctor`. Inspect missing capabilities before changing privileges.
3. Run `netwatch`; use [[Permissions]] if you need live capture. Ordinary interface/configuration observations can work without capture.
4. Use `?` for help, `9` for Diagnose or `4` for Packets in the full view. See [[Tab System]].

Read [[Configuration and Privacy]] before capturing sensitive traffic or enabling AI/remote export. This wiki describes the release in its header; development documentation labels unreleased improvements.

## Install and verify

Choose one installation method for your machine; these are alternatives, not a sequence:

```sh
brew install netwatch                  # Homebrew
scoop install netwatch                 # Windows; Npcap is separate
conda install -c conda-forge netwatch   # Linux/macOS
cargo install netwatch-tui             # build with Rust/native prerequisites
```

Package channels can lag a release. Check the installed version instead of assuming
it matches this wiki. For a standalone asset, download the correct OS/architecture
from the release page and follow the checksum/provenance instructions.

```sh
netwatch --version
netwatch doctor
netwatch doctor --json
```

Doctor runs without starting normal collectors. A missing capture capability need
not prevent interface statistics or connection observations. Resolve only the
capability required for the task; the permissions instructions below explain how.

## Capture a controlled request

1. Start `netwatch` and open Packets (`4`) in the full view.
2. Select the interface carrying the request (`i` cycles capture interfaces).
3. Start capture with `c`, then make a request from another terminal or application.
4. Press `/` and filter with `tcp and port 443` for HTTPS transport, or `app:tls`
   for packets with decoded TLS metadata. The latter can miss unsupported or
   incomplete handshakes.
5. Select a packet and press `s` for its retained stream. This does not automatically
   decrypt HTTPS; see [[TLS Decryption]] for keylog prerequisites.
6. Stop capture with `c`. Use `w` to preview an export; inspect its contents and
   destination before confirming it.

`p` pauses UI-driven updates, not all background activity. `x` filters expert
findings; **`X` clears the retained capture**. Do not clear a capture you still need.

## Choose a view

```sh
netwatch --lite          # compact terminal, at least 80×24
netwatch --view dense    # at least 130×44
netwatch                # full tabbed view
```

The `V` key cycles views. Full-view digit navigation does not describe every
interaction in lite/dense or an overlay; `?` shows the relevant help.

<!-- include: docs/REFERENCE.md#permissions -->

<!-- include: docs/REFERENCE.md#geoip-databases -->
