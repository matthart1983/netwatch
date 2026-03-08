Output demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 800
Set Theme "Catppuccin Mocha"
Set TypingSpeed 50ms

Type "./target/release/netwatch"
Enter
Sleep 4s

# Show Connections tab
Type "2"
Sleep 3s

# Show Interfaces tab
Type "3"
Sleep 3s

# Back to Dashboard
Type "1"
Sleep 2s

# Show help overlay
Type "?"
Sleep 3s

# Close help
Type "?"
Sleep 1s

# Quit
Type "q"
Sleep 1s
