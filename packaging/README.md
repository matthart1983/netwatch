# Packaging — netwatch fleet agent

Service definitions for running `netwatch daemon` (the headless agent) as a
long-running service that streams to a netwatch cloud / NetWatch Core backend.

The daemon runs the same collectors as the TUI with no rendering, buffers
snapshots in a durable bounded queue, and flushes that queue on SIGTERM before
exiting.

## Configuration

Both units pass the backend endpoint and API key via environment variables
(`NETWATCH_REMOTE_URL`, `NETWATCH_API_KEY`) rather than CLI flags, so the key
never appears in `ps`. The equivalent manual invocation is:

```sh
NETWATCH_API_KEY=<key> netwatch daemon --remote https://cloud.example.com
```

`--api-key <key>` is deprecated. It stays accepted through 1.x, with a warning, and
goes in 2.0, and it puts the key where any user on the host can read it with `ps`.

The URL must be `https://`. netwatch refuses an `http://` URL, which would
send the API key in cleartext, unless `--insecure-remote` is also given; for
a unit, that means adding the flag to `ExecStart` or `ProgramArguments`.

## Linux (systemd)

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin netwatch
sudo install -m0755 target/release/netwatch /usr/bin/netwatch
sudo install -d -m0750 -o netwatch -g netwatch /etc/netwatch
printf 'NETWATCH_REMOTE_URL=%s\nNETWATCH_API_KEY=%s\n' \
  "https://cloud.example.com" "<key>" | sudo tee /etc/netwatch/agent.env >/dev/null
sudo chmod 0640 /etc/netwatch/agent.env && sudo chown root:netwatch /etc/netwatch/agent.env
sudo cp packaging/systemd/netwatch.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now netwatch
journalctl -u netwatch -f
```

The unit runs unprivileged with only `CAP_NET_RAW`, `CAP_BPF`, and
`CAP_PERFMON` (eBPF process attribution needs the latter two). netwatch applies
its own Landlock sandbox on top after startup, and drops `CAP_NET_RAW` from its
threads once capture has opened. The open capture descriptor can still capture
and inject on any interface in the network namespace. The unit grants these
capabilities to its service user, so the binary carries none and can stay 0755:
it needs no `setcap` and no group restriction.

## macOS (launchd)

```sh
sudo install -m0755 target/release/netwatch /usr/local/bin/netwatch
sudo cp packaging/launchd/com.netwatch.agent.plist /Library/LaunchDaemons/
# edit NETWATCH_REMOTE_URL / NETWATCH_API_KEY in the plist, then:
sudo launchctl bootstrap system /Library/LaunchDaemons/com.netwatch.agent.plist
```

Full eBPF/PKTAP attribution on macOS requires root; without it the daemon falls
back to lsof/ss-based attribution.
