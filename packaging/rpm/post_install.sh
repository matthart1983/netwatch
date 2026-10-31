#!/bin/sh
# See packaging/debian/postinst — capabilities are the administrator's call,
# so this prints the command rather than running it.
cat <<'MSG'

netwatch is installed. Packet capture needs elevated access. Prefer to
restrict the binary to a group and grant the capabilities to it:

  sudo groupadd -f netwatch
  sudo usermod -aG netwatch "$USER"   # takes effect at your next login
  sudo chown root:netwatch /usr/bin/netwatch
  sudo chmod 0750 /usr/bin/netwatch
  sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' /usr/bin/netwatch

An upgrade resets the file, so re-run the last three after each one. Without
the group restriction every local account could capture. `sudo netwatch` also
works, but as root the sandbox is defence in depth only.

MSG
exit 0
