# NetWatch Dense on a white terminal: demo-dense.tape with a light palette.
#
# Everything about the take (size, pre-roll, namespace, traffic, the tour and
# the re-encode) is documented in demo-dense.tape and applies here unchanged.
# Only the palette differs. demo-dense-env.sh pins `theme = "terminal"`, so
# netwatch draws in the ANSI tokens below and this palette decides the look:
#
#   - foreground is primary text; `white` (ANSI 7) is secondary text, so it is
#     a dark grey here, not white.
#   - `brightBlack` colours borders and muted text AND fills the selected row,
#     whose text is promoted to the foreground colour. #818b98 is the
#     compromise that keeps muted text readable on white and dark text
#     readable on the selection.
#   - Graphs step from a base token to its bright variant as magnitude rises.
#     On white, intensity means darker, so every bright variant is darker than
#     its base: green #1f883d -> #0f5323, blue #0969da -> #0a3069.
#   - `black` is only ever text_inverse, drawn on brand, tab and warning
#     fills, so it is white here.
#   - Yellow is GitHub's amber (#9a6700): pure yellow vanishes on white.
#
# Colours are GitHub's light palette, to match the profile README's light
# banner.
#
# Record on Linux with: vhs docs/media/demo-dense-light.tape
# then re-encode as demo-dense.tape describes, with demo-dense-light.gif.

Output docs/media/demo-dense-light.gif

Set Shell "bash"
Set FontSize 14
Set Width 1250
Set Height 930
Set Theme {"name": "netwatch light", "black": "#ffffff", "red": "#cf222e", "green": "#1f883d", "yellow": "#9a6700", "blue": "#0969da", "magenta": "#8250df", "cyan": "#1b7c83", "white": "#59636e", "brightBlack": "#818b98", "brightRed": "#a40e26", "brightGreen": "#0f5323", "brightYellow": "#7d4e00", "brightBlue": "#0a3069", "brightMagenta": "#6639ba", "brightCyan": "#0e5a60", "brightWhite": "#1f2328", "background": "#ffffff", "foreground": "#1f2328", "selection": "#b6e3ff", "cursor": "#1f2328"}
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
