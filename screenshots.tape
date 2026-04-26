Output screenshots/.vhs-trash.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 700
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms
Set Framerate 18
Set Padding 10

# Requires NETWATCH_DEMO_PASSWORD env var:
#   NETWATCH_DEMO_PASSWORD='...' vhs screenshots.tape

Hide
Type `echo "$NETWATCH_DEMO_PASSWORD" | sudo -S ./target/release/netwatch`
Enter
Sleep 6s
Show

# Tab 1 — Dashboard (default)
Sleep 3s
Screenshot screenshots/dashboard.png

# Tab 2 — Connections
Type "2"
Sleep 2s
Screenshot screenshots/connections.png

# Tab 3 — Interfaces
Type "3"
Sleep 2s
Screenshot screenshots/interfaces.png

# Tab 4 — Packets
Type "4"
Sleep 3s
Screenshot screenshots/packets.png

# Tab 5 — Stats
Type "5"
Sleep 2s
Screenshot screenshots/stats.png

# Tab 6 — Topology
Type "6"
Sleep 2s
Screenshot screenshots/topology.png

# Tab 7 — Timeline
Type "7"
Sleep 2s
Screenshot screenshots/timeline.png

# Tab 8 — Processes
Type "8"
Sleep 2s
Screenshot screenshots/processes.png

# Tab 9 — Insights
Type "9"
Sleep 2s
Screenshot screenshots/insights.png

# Quit
Type "q"
Sleep 500ms
