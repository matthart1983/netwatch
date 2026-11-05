#!/usr/bin/env bash
# Build a macOS (Apple Silicon) .dmg with the netwatch binary, the launchd
# daemon definition and an installer.
#
#   scripts/build-dmg.sh [DMG_VERSION]   # default: <crate version>+flowlog5
#   -> target/dmg/netwatch-<DMG_VERSION>-macos-arm64.dmg
#
# The crate version in Cargo.toml is unchanged; the suffix marks our build, the
# same way the .deb does (dist/netwatch_0.40.0+flowlog4_amd64.deb).
#
# Must run on macOS arm64: it uses hdiutil, plutil and builds for the host target.
# Needs a Rust toolchain >= the crate's rust-version (rustup is enough).
# Nothing here runs as root or changes anything outside target/.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

[ "$(uname -s)" = Darwin ] || { echo "run this on macOS" >&2; exit 1; }
[ "$(uname -m)" = arm64 ] || { echo "this script builds for Apple Silicon (arm64) only" >&2; exit 1; }
command -v hdiutil >/dev/null || { echo "hdiutil not found" >&2; exit 1; }
command -v plutil >/dev/null || { echo "plutil not found" >&2; exit 1; }
command -v cargo >/dev/null || { echo "cargo not on PATH" >&2; exit 1; }

CRATE_VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
VERSION="${1:-${CRATE_VERSION}+flowlog5}"
DMG_DIR="$ROOT/target/dmg"
STAGE="$DMG_DIR/stage"
DMG="$DMG_DIR/netwatch-${VERSION}-macos-arm64.dmg"

cargo build --release --locked --bin netwatch

rm -rf "$STAGE" "$DMG"
mkdir -p "$STAGE"
install -m 0755 "$ROOT/target/release/netwatch" "$STAGE/netwatch"

# The daemon plist. Written here rather than copied from packaging/launchd: that
# copy carries a placeholder remote endpoint and API key, and this one runs the
# daemon with the flow log on, in /var/log/netwatch.
cat > "$STAGE/com.netwatch.agent.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.netwatch.agent</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/netwatch</string>
        <string>daemon</string>
        <string>--flow-log</string>
        <string>file</string>
        <string>--flow-log-dir</string>
        <string>/var/log/netwatch</string>
    </array>

    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>

    <!-- Graceful stop: SIGTERM, then allow the queue flush to complete. -->
    <key>ExitTimeOut</key>
    <integer>15</integer>

    <key>StandardErrorPath</key>
    <string>/var/log/netwatch-agent.err.log</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
EOF
plutil -lint "$STAGE/com.netwatch.agent.plist"

cat > "$STAGE/Install netwatch.command" <<'EOF'
#!/usr/bin/env bash
# Double-click in Finder. Installs netwatch to /usr/local/bin and, if you say
# yes, registers it as a background LaunchDaemon. Asks for your password via sudo.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DEST=/usr/local/bin/netwatch
LABEL=com.netwatch.agent
PLIST=/Library/LaunchDaemons/$LABEL.plist

echo "Installing netwatch to $DEST"
sudo mkdir -p /usr/local/bin
sudo install -m 0755 "$HERE/netwatch" "$DEST"
# Files copied from a downloaded DMG can carry the quarantine flag; drop it
# from the installed copy only.
sudo xattr -d com.apple.quarantine "$DEST" 2>/dev/null || true
echo "Installed: $("$DEST" --version)"

echo
read -r -p "Also run netwatch as a background daemon (starts at boot)? [y/N] " ans
if [ "$ans" = y ] || [ "$ans" = Y ]; then
    # Replace an existing registration, if any.
    if launchctl print "system/$LABEL" >/dev/null 2>&1; then
        sudo launchctl bootout "system/$LABEL" || true
    fi
    # Flow log directory: root-owned, 0700 (the daemon runs as root).
    sudo mkdir -p /var/log/netwatch
    sudo chown root:wheel /var/log/netwatch
    sudo chmod 0700 /var/log/netwatch
    sudo install -m 0644 -o root -g wheel "$HERE/$LABEL.plist" "$PLIST"
    sudo plutil -lint "$PLIST"
    sudo launchctl bootstrap system "$PLIST"
    echo "Daemon started. Status: sudo launchctl print system/$LABEL"
    echo "Log: /var/log/netwatch-agent.err.log"
    echo "Flow log: /var/log/netwatch/flows.YYYY-MM-DD.ndjson"
    echo "Stop and remove: sudo launchctl bootout system/$LABEL && sudo rm $PLIST"
fi

echo
echo "Done. Run: netwatch --version   (capture: sudo netwatch)"
read -r -p "Press Enter to close..." _
EOF
chmod 0755 "$STAGE/Install netwatch.command"

cat > "$STAGE/README.txt" <<EOF
netwatch ${VERSION} for macOS (Apple Silicon)

Install: double-click "Install netwatch.command". It copies netwatch to /usr/local/bin
and, if you answer y, starts it as a background daemon at boot. The daemon writes
the flow log to /var/log/netwatch (root-owned, mode 0700).
Run:     netwatch            (no privileges needed for the overview)
Capture: sudo netwatch       (packet capture needs root or /dev/bpf access)

Docs: https://github.com/matthart1983/netwatch
EOF

hdiutil create -quiet -volname "netwatch ${VERSION}" -srcfolder "$STAGE" \
    -ov -format UDZO "$DMG"
rm -rf "$STAGE"

echo "Built: $DMG"
shasum -a 256 "$DMG"
