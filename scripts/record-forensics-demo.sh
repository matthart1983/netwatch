#!/usr/bin/env bash
# Record the "forensics hero" demo GIF (live TLS 1.3 decryption) for the README.
#
# Usage:
#   NETWATCH_DEMO_PASSWORD='your-sudo-password' ./scripts/record-forensics-demo.sh
#
# Produces demo-forensics.gif in the repo root. Once recorded, swap the README
# hero from demo.gif to demo-forensics.gif (one <img src=...> line).
set -euo pipefail
cd "$(dirname "$0")/.."

command -v vhs  >/dev/null || { echo "error: vhs not installed — https://github.com/charmbracelet/vhs"; exit 1; }
command -v curl >/dev/null || { echo "error: curl not installed"; exit 1; }

if [[ -z "${NETWATCH_DEMO_PASSWORD:-}" ]]; then
  echo "error: set NETWATCH_DEMO_PASSWORD (sudo password used for live capture)"; exit 1
fi

echo ">> building release binary..."
cargo build --release

echo ">> recording demo-forensics.tape (live capture needs sudo + a real interface)..."
vhs demo-forensics.tape

echo ">> done: demo-forensics.gif"
echo "   Next: update the README hero <img> from demo.gif to demo-forensics.gif."
