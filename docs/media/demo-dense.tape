# NetWatch Dense — everything at once, on a terminal that can take it.
#
# Story: Lite spends 80x24 answering one question. The tabbed TUI spends ten
# tabs on ten. Dense spends a large terminal showing the lot — four boxes, no
# header bar, no menu bar, no status bar, every row carrying data. The headline
# is the mirrored graph: download grows up from the time axis, upload grows
# down from it, so traffic symmetry is a shape you recognise before you read a
# number. Underneath, the selected connection's detail is hoisted into the top
# of the same box, carrying kernel TCP state — no second screen, no back button.
#
# Prereqs learned the hard way:
#   - Dense needs 130x44 or it renders the compact fallback. Width/Height below
#     were measured, not guessed. Measure them again on any machine that
#     records this: cell metrics depend on the installed font and the vhs
#     build, so the pixel sizes are not portable. Record a throwaway tape with
#     the same FontSize/Padding/Theme that runs `stty size` and read the grid
#     off the frame. On this machine 1250x770 gives 133x38 — 133 columns clears
#     the width floor, but 38 rows is six short of 44, and netwatch responds by
#     dropping the interfaces and latency boxes, leaving the throughput graph
#     and the connection table alone. That is the compact fallback, and it
#     records the four-box layout as two. 1250x930 gives 133x47.
#   - The netwatch theme must be RGB. The Lite demo pins `theme = "terminal"`
#     so colours come from the user's palette — right there, fatal here. Dense
#     encodes magnitude as a colour ramp, and a palette-deferring theme flattens
#     every ramp to one token by design. `demo-dense-env.sh` pins `dark`.
#   - Traffic must start AFTER netwatch is capturing, or REMOTE shows raw IPs:
#     the name comes from the ClientHello's SNI, so a handshake that predates
#     capture is unreadable. Hence the delayed generator below.
#   - The generator uploads as well as downloads. Without an upload leg the
#     mirrored graph's lower half is flat, which records the headline feature
#     as half a graph.
#   - The plot carries one sample per braille sub-column and fills from the
#     right, so a cold start shows an empty left half for a full minute. The
#     recording pre-rolls hidden until the window is populated, then reveals a
#     screen that looks like one you've had open — which is the honest picture,
#     not a doctored one.
#
# Record on Linux with: vhs docs/media/demo-dense.tape
# Needs: ./target/release/netwatch with capture permission, vhs, setsid,
#        scripts/demo-dense-{env,traffic}.sh.
# The take uses a separate network/PID namespace for the terminal
# session, with /proc and /sys mounted there. Keep the recorder outside it
# so its browser sockets do not appear in the connection table. That needs no
# setcap: a `bash` first on vhs's PATH execs this, with resolv.conf holding
# `nameserver 10.0.2.3` and the wrapper's directory taken off PATH again:
#
#   pasta --config-net -q -t none -u none -T none -U none -m 1500 -I demo0 \
#     -a 10.0.2.15 -n 24 -g 10.0.2.2 --dns-forward 10.0.2.3 -- \
#     unshare --pid --fork --mount-proc --mount /usr/bin/bash -c \
#     'mount -t sysfs sysfs /sys; mount --bind RESOLV /etc/resolv.conf;
#      exec /usr/bin/bash "$@"' bash "$@"
#
#   - No port forwards, not even DNS. pasta holds a socket in the namespace per
#     forwarded port and per forwarded DNS query, and they fill the connection
#     table with unattributed 127.0.0.1 UDP rows.
#   - pasta's default MTU shows `mss 43520` and a 10 Gb link. `-m 1500` gives a
#     normal MSS. It needs a build newer than 0.39.0, which read only a flow's
#     first segment, so at 1500 its ClientHellos lost their hostnames.

# THEN RE-ENCODE IT, for the same reason the hero tape documents: vhs v0.11.0
# ignores `Set Framerate` for the GIF and writes 25 fps whatever the tape says,
# which is 2.5x the frames this needs. The 19 September take was 5.0 MB at
# 25 fps; the same recording at 10 fps is 2.8 MB.
#
#   ffmpeg -i docs/media/demo-dense.gif \
#     -vf "fps=10,palettegen=stats_mode=full:max_colors=128" -y /tmp/pal.png
#   ffmpeg -i docs/media/demo-dense.gif -i /tmp/pal.png \
#     -lavfi "fps=10[x];[x][1:v]paletteuse=dither=none:diff_mode=rectangle" \
#     -loop 0 -y /tmp/demo-dense-optimized.gif
#   mv /tmp/demo-dense-optimized.gif docs/media/demo-dense.gif
#
# `dither=none` is deliberate: terminal output is flat colour, so dithering
# buys nothing visible and costs most of the inter-frame compression.
# A full-frame palette keeps the static accents; a 64-colour diff-only
# palette spent too many entries on the graph and washed out those accents.

Output docs/media/demo-dense.gif

Set Shell "bash"
Set FontSize 14
Set Width 1250
Set Height 930
Set Theme { "name": "Catppuccin Mocha on the tools background", "black": "#45475a", "red": "#f38ba8", "green": "#a6e3a1", "yellow": "#f9e2af", "blue": "#89b4fa", "magenta": "#f5c2e7", "cyan": "#94e2d5", "white": "#bac2de", "brightBlack": "#585b70", "brightRed": "#f38ba8", "brightGreen": "#a6e3a1", "brightYellow": "#f9e2af", "brightBlue": "#89b4fa", "brightMagenta": "#f5c2e7", "brightCyan": "#94e2d5", "brightWhite": "#a6adc8", "background": "#081114", "foreground": "#cdd6f4", "selection": "#585b70", "cursor": "#f5e0dc" }
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

# `V` cycles full → lite → dense from any view. One keypress to the ten-tab
# instrument, sharing the same warm collectors — no restart, no lost history.
Type "V"
Sleep 5s

# Deliberately NOT shown: the third stop on the cycle. Lite is built for 80x24
# and renders its layout into the left third of this 133-column frame — an
# honest picture that reads as a broken one. Same call the Lite tape made in
# reverse.

Hide
Type "q"
Enter
Sleep 500ms

# Tear down the traffic generator.
Type "kill -- -$NW_DEMO_TRAFFIC_PID 2>/dev/null; wait $NW_DEMO_TRAFFIC_PID 2>/dev/null"
Enter
Sleep 500ms
