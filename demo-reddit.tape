Output demo-reddit.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 700
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms
Set Framerate 18
Set Padding 10

# Requires NETWATCH_DEMO_PASSWORD env var
Hide
Type `echo "$NETWATCH_DEMO_PASSWORD" | sudo -S ./target/release/netwatch`
Enter
Sleep 6s
Show

# Live dashboard loop — counters / sparklines tick visibly across ~18s,
# which gives the GIF enough motion to reward a re-watch on autoplay.
Sleep 18s

Hide
Type "q"
Sleep 500ms
