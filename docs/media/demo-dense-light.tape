# NetWatch Dense on a light terminal: demo-dense.tape in netwatch's `paper` theme.
#
# Everything about the take (size, pre-roll, namespace, traffic, the tour and
# the re-encode) is documented in demo-dense.tape and applies here unchanged.
# Only the theme differs. demo-dense-env.sh writes `theme = "terminal"`; the
# hidden setup below switches the scratch config to `paper`, netwatch's
# built-in light theme, which paints its own #f5f5f2 panel and has
# contrast-checked text and rate colours (see the `contrast` tests in
# src/theme.rs).
#
# Why not `terminal` with a light palette, as the first light take did: the
# terminal theme fills the selected row with ANSI 8 (bright black) on purpose,
# and the same slot colours borders and muted text. On white, any grey dark
# enough for muted text is too dark under the selected row's green and blue
# rates, so the selection bar read as a dark band. `paper` has its own light
# selection colour.
#
# The vhs palette below only colours the padding around netwatch's panel, so
# its background matches paper's.
#
# Record on Linux with: vhs docs/media/demo-dense-light.tape
# then re-encode as demo-dense.tape describes, with demo-dense-light.gif.

Output docs/media/demo-dense-light.gif

Set Shell "bash"
Set FontSize 14
Set Width 1250
Set Height 930
Set Theme {"name": "netwatch paper", "black": "#ffffff", "red": "#cf222e", "green": "#1f883d", "yellow": "#9a6700", "blue": "#0969da", "magenta": "#8250df", "cyan": "#1b7c83", "white": "#59636e", "brightBlack": "#818b98", "brightRed": "#a40e26", "brightGreen": "#0f5323", "brightYellow": "#7d4e00", "brightBlue": "#0a3069", "brightMagenta": "#6639ba", "brightCyan": "#0e5a60", "brightWhite": "#1f2328", "background": "#f5f5f2", "foreground": "#1f2328", "selection": "#b6e3ff", "cursor": "#1f2328"}
Set TypingSpeed 30ms
Set Framerate 10
Set Padding 10

# Hidden setup, as in the Lite tape: point `netwatch` at this repo's release
# build for the recording only, use a scratch config so the GIF
# doesn't inherit the operator's theme, and arm the traffic generator to start
# once capture is up.
Hide
Type "unset NO_COLOR; export COLORTERM=truecolor"
Enter
Type "export PATH=$PWD/target/release:$PATH"
Enter
Type "NW_DEMO_HOME=$(./scripts/demo-dense-env.sh) && export XDG_CONFIG_HOME=$NW_DEMO_HOME/.config"
Enter
Type `sed -i 's/^theme = .*/theme = "paper"/' "$XDG_CONFIG_HOME/netwatch/config.toml"`
Enter
# Disable job control so setsid does not fork away from the PID we save.
Type "set +m"
Enter
Type "setsid bash -c 'sleep 5; exec ./scripts/demo-dense-traffic.sh' >$NW_DEMO_HOME/traffic.log 2>&1 & NW_DEMO_TRAFFIC_PID=$!"
Enter
Type "clear"
Enter

# Launch and pre-roll off-camera until the throughput window has filled and the
# health probes have a baseline. Nothing is faked here — the recording simply
# starts at the point a real session becomes worth looking at.
Type "netwatch --view dense"
Enter
Sleep 95s
# Connections now start grouped and folded. Expand them before the reveal so
# the tour's selection keys show individual sockets and their TCP details.
Type "z"
Sleep 1s
Show

# The screen, in full. Four boxes: the mirrored graph over per-interface rates
# and hop latency budgets, over the connection table. Watch the plot scroll —
# one sample per sub-column, one sub-column per tick.
Sleep 7s

# Walk down the connection list. The detail block at the top of the box follows
# the selection: socket pair, rates, RTT, retransmits, the decoded protocol, and
# cwnd / ssthresh / mss / rwnd read straight from the kernel.
Type "j"
Sleep 4s
Type "j"
Sleep 5s

# Back up to the busiest flow and sit on it, so the detail row and its 60-second
# rate plot are readable.
Type "k"
Sleep 5s

# Pause freezes the collectors; the screen stays legible rather than greying
# out, because pause is when you want to read it.
Type "p"
Sleep 3s
Type "p"
Sleep 2s

# The dark take ends with `V` into the full view. This one stops here: the
# full view's active tab and numbered panel badges draw bold text_inverse
# (ANSI black), and xterm.js, which vhs records through, renders bold ANSI
# colours 0-7 as their bright variants. Bold black becomes brightBlack, mid
# grey on amber and teal fills, which is hard to read. Dense draws no bold
# inverse text, so everything up to here is unaffected.

Hide
Type "q"
Enter
Sleep 500ms

# Tear down the traffic generator.
Type "kill -- -$NW_DEMO_TRAFFIC_PID 2>/dev/null; wait $NW_DEMO_TRAFFIC_PID 2>/dev/null"
Enter
Sleep 500ms
