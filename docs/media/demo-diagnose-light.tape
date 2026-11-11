# netwatch — Diagnose on a light terminal: issue → cause → remediation →
# verified close. The README's second image.
#
# The beats and their reasons are demo-diagnose.tape's; read that file's header
# before changing a Sleep. The look is demo-dense-light.tape's: the `paper`
# theme, switched by a hidden sed on the scratch config, on GitHub's light
# palette. Do not record light demos in `terminal`: its selected row is ANSI 8,
# which shows as a dark band on white.
#
# Recorded against `--demo`, which replays the fixture scenario through the
# real engine, rules and UI at 6×. The DEMO banner must stay in frame.
#
# Record with:  vhs docs/media/demo-diagnose-light.tape
# Needs: ./target/release/netwatch, vhs, scripts/demo-lite-env.sh. Not
# demo-dense-env.sh: its 250 ms refresh runs the replay four times too fast,
# and the scenario ends before the issue can close.
#
# THEN RE-ENCODE IT at 10 fps, as demo-dense.tape describes: vhs writes 25 fps
# whatever `Set Framerate` says.

Output docs/media/demo-diagnose-light.gif

Set Shell "bash"
Set FontSize 15
Set Width 1660
Set Height 900
Set Theme {"name": "netwatch paper", "black": "#ffffff", "red": "#cf222e", "green": "#1f883d", "yellow": "#9a6700", "blue": "#0969da", "magenta": "#8250df", "cyan": "#1b7c83", "white": "#59636e", "brightBlack": "#818b98", "brightRed": "#a40e26", "brightGreen": "#0f5323", "brightYellow": "#7d4e00", "brightBlue": "#0a3069", "brightMagenta": "#6639ba", "brightCyan": "#0e5a60", "brightWhite": "#1f2328", "background": "#f5f5f2", "foreground": "#1f2328", "selection": "#b6e3ff", "cursor": "#1f2328"}
Set TypingSpeed 30ms
Set Framerate 10
Set Padding 10

Hide
Type "unset NO_COLOR; export COLORTERM=truecolor"
Enter
Type "export PATH=$PWD/target/release:$PATH"
Enter
Type "NW_DEMO_HOME=$(./scripts/demo-lite-env.sh) && export HOME=$NW_DEMO_HOME XDG_CONFIG_HOME=$NW_DEMO_HOME/.config"
Enter
Type `sed -i 's/^theme = .*/theme = "paper"/' "$XDG_CONFIG_HOME/netwatch/config.toml"`
Enter
Type "clear"
Enter
Show

# ── 1. The finding ─────────────────────────────────────────────────────
# Opens on Diagnose. The verdict line names the worst issue, when it
# started, and what to press; the detail pane opens on the resolver.
Type "netwatch --demo"
Enter
Sleep 9s

# ── 2. The cause, and what ruled the others out ────────────────────────
# Three ranked causes. The top one carries its checks: the alternate
# resolver is fast, the resolver itself is reachable, cached names still
# answer — which together say the recursion is slow, not the box.
Sleep 6s

# ── 3. The other findings ──────────────────────────────────────────────
# Down through the reroute (whose latency cost is filed underneath it, not
# counted twice) and the socket the receiver is queueing on.
Down
Sleep 5s
Down
Sleep 5s
Up
Up
Sleep 3s

# ── 4. The report is the screen ────────────────────────────────────────
# The preview already sits under the detail pane, built from the same
# `Vec<Issue>`; `o` gives it the whole screen to be read at length, and
# `o` again comes back. Same objects, same numbers as `e` would export.
Type "o"
Sleep 7s
Type "o"
Sleep 2s

# ── 5. Apply, and confirm ──────────────────────────────────────────────
# `↵` stages the remediation and asks. Nothing has been written yet.
Enter
Sleep 4s
Type "y"
Sleep 4s

# ── 6. Verify closes it ────────────────────────────────────────────────
# The engine is not told the problem is fixed. It watches the resolver, and
# when `dns.rtt_p50 < 5ms` has held for 60 scenario-seconds the issue
# auto-closes and drops off the verdict line by itself.
Sleep 14s

Type "q"
Sleep 1s
