#!/usr/bin/env bash
# Audit a real `netwatch daemon` the way an operator would, from outside it.
#
#   scripts/capture-authority-audit.sh path/to/netwatch
#
# Re-runs itself as root in a new user and network namespace, makes a veth pair
# v0/v1, starts the daemon capturing on v0, and reads /proc/<pid>/task. Passes when
# no task holds CAP_NET_RAW or CAP_NET_ADMIN in any of its four sets and
# /proc/<pid>/net/packet still lists a socket on v0: capture keeps the descriptor
# it opened, and nothing can open another. Prints what it found either way.
#
# tests/capture_authority.rs measures the same on threads it can reach into. This
# is the same claim for the binary as shipped, its tokio runtime and logging
# included, which that test does not start.
set -euo pipefail

NETWATCH="${1:?usage: capture-authority-audit.sh path/to/netwatch}"
NETWATCH="$(realpath "$NETWATCH")"

if [ -z "${NETWATCH_CAP_AUDIT_INNER:-}" ]; then
  exec env NETWATCH_CAP_AUDIT_INNER=1 \
    unshare --user --map-root-user --net "$(realpath "$0")" "$NETWATCH"
fi

ip link set lo up
ip link add v0 type veth peer name v1
ip link set v0 up
ip link set v1 up
# /sys shows the namespace it was mounted in, not this one, so ask ip.
V0_INDEX="$(ip -o link show v0 | cut -d: -f1)"

HOME_DIR="$(mktemp -d)"
DAEMON_PID=""
cleanup() {
  if [ -n "$DAEMON_PID" ]; then
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  rm -rf "$HOME_DIR"
}
trap cleanup EXIT

mkdir -p "$HOME_DIR/config/netwatch"
printf 'capture_interface = "v0"\n' >"$HOME_DIR/config/netwatch/config.toml"
HOME="$HOME_DIR" XDG_CONFIG_HOME="$HOME_DIR/config" XDG_CACHE_HOME="$HOME_DIR/cache" \
  XDG_STATE_HOME="$HOME_DIR/state" "$NETWATCH" daemon \
  >"$HOME_DIR/daemon.out" 2>&1 &
DAEMON_PID=$!

# Sets one thread's status file holds, ORed together.
held_caps() {
  local held=0 hex
  for hex in $(awk '/^Cap(Inh|Prm|Eff|Amb):/ {print $2}' "$1" 2>/dev/null); do
    held=$((held | 16#$hex))
  done
  echo "$held"
}

# Fills TASKS, HOLDERS and PACKET_ON_V0 from the daemon as it is now.
audit() {
  TASKS=0
  HOLDERS=""
  local task held
  for task in "/proc/$DAEMON_PID/task/"*; do
    [ -r "$task/status" ] || continue
    TASKS=$((TASKS + 1))
    held="$(held_caps "$task/status")"
    # CAP_NET_ADMIN is bit 12 and CAP_NET_RAW bit 13.
    if [ $(((held >> 12) & 3)) -ne 0 ]; then
      HOLDERS="$HOLDERS $(cat "$task/comm" 2>/dev/null)($(basename "$task"))"
    fi
  done
  # sk RefCnt Type Proto Iface R Rmem User Inode
  PACKET_ON_V0="$(awk -v iface="$V0_INDEX" 'NR > 1 && $5 == iface' \
    "/proc/$DAEMON_PID/net/packet" | wc -l)"
}

daemon_is_running() {
  kill -0 "$DAEMON_PID" 2>/dev/null && return
  echo "FAIL: the daemon exited" >&2
  cat "$HOME_DIR/daemon.out" >&2
  exit 1
}

# Main drops once its workers have started, and capture opens on its own thread.
for _ in $(seq 1 100); do
  daemon_is_running
  audit
  if [ -z "$HOLDERS" ] && [ "$PACKET_ON_V0" -gt 0 ]; then
    break
  fi
  sleep 0.1
done

# Once more after the first ticks, which start workers of their own.
sleep 2
daemon_is_running
audit

HOLDING="$(echo "$HOLDERS" | wc -w)"
echo "tasks holding CAP_NET_RAW or CAP_NET_ADMIN: $HOLDING of $TASKS$HOLDERS"
echo "packet sockets on v0 (ifindex $V0_INDEX) in /proc/$DAEMON_PID/net/packet: $PACKET_ON_V0"
if [ "$HOLDING" -ne 0 ] || [ "$PACKET_ON_V0" -eq 0 ]; then
  echo "FAIL: capture authority audit" >&2
  cat "$HOME_DIR/daemon.out" >&2
  exit 1
fi
echo "capture authority audit: pass"
