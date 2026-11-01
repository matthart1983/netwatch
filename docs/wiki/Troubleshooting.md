# Troubleshooting

Start with `netwatch --version` and `netwatch doctor --json`. Read the reason for each unavailable, degraded or not-checked capability before changing privileges. Use the optional `doctor --check-capture` only when you want to open an interface for a bounded check.

| Symptom | Next step |
| --- | --- |
| Capture denied | Check selected interface, [[Permissions]] and the doctor capture result. |
| Windows capture library missing | Install/repair Npcap and inspect doctor's library reason; SDK installation alone is not runtime installation. |
| No GeoIP context | Check configured local files or explicitly run `netwatch geoip update`; there is no online lookup fallback. |
| No owner or partial coverage | Read [[eBPF Process Attribution]]; visibility, identity freshness and platform limits matter. |
| No Diagnose findings | Inspect [[Diagnose and Coverage]] for unmeasured, learning or stale evidence. |
| AI waiting/unavailable | Follow [[AI Insights]]; confirm opt-in, endpoint/model and a retained packet snapshot. |
| Trace incomplete | See [[Traceroute]]; missing replies need not mean the destination is down. |

For a bug report, include version, OS, reproduction and relevant doctor reasons. Review addresses, names, tokens and payload-derived data before sharing logs or exports.

## Capture opens but there are no useful packets

Check that the selected interface carries the traffic, that capture is running,
and that neither a BPF filter nor a display filter excludes it. Remove the
display filter first: it can reveal retained packets without changing capture.
A capture filter cannot recover packets it already excluded.

`Raw` packets can indicate link framing that NetWatch retains without decoding,
such as Linux cooked capture or tunnel framing. A successful open therefore does
not prove useful L7 decode on that interface. Prefer the relevant Ethernet-framed
interface when investigating supported protocol parsing.

## TLS traffic exists but names or plaintext are missing

Start capture before creating a fresh connection. Verify that the client writes
the configured keylog and that NetWatch was restarted after setting its exact
path. Check cipher/protocol support and the release's handshake reconstruction
limits. `port 443` can match traffic whose SNI was never decoded; `sni:` cannot.
Follow [[TLS Decryption]] for the complete supported procedure.

## The version did not change after an upgrade

Check `netwatch --version` and which executable your shell finds. A restricted
Linux copy in `/usr/local/bin` can still be the old binary while Cargo, Homebrew
or another package manager replaced its own file. Reapply the documented copy,
ownership, mode and capability recipe to the new executable; do not remove the
execution restriction merely to make it start.

## Diagnose is empty or a finding stays open

Open coverage and distinguish learning, unmeasured and stale evidence. A blocked
gateway probe can resemble an unreachable gateway; an empty result is not proof
of health. In a bounded CLI run, exit 2 means no usable observation, while exit 0
means no issue from the rules that could be evaluated. Preserve the coverage
object when sharing JSON output.

## Prepare a useful report

Include the installed version, OS/kernel, capture interface, view, exact action,
expected behavior and relevant doctor reasons. Record whether the issue occurs
without a display filter and whether packets are decoded or Raw. Review captures,
logs and JSON for secrets, addresses, names and payloads before sharing them.
