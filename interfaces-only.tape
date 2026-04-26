Output screenshots/.vhs-trash.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 700
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms
Set Framerate 18
Set Padding 10

Hide
Type `echo "$NETWATCH_DEMO_PASSWORD" | sudo -S ./target/release/netwatch`
Enter
Sleep 6s
Show

# Switch to Interfaces tab
Type "3"
Sleep 3s
Screenshot screenshots/interfaces.png

Type "q"
Sleep 500ms
