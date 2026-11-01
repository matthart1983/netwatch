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
