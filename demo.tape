Output demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 800
Set Theme "Catppuccin Mocha"
Set TypingSpeed 50ms

Type "sudo ./target/release/netwatch"
Enter
Sleep 5s

# Dashboard tab - show live stats
Sleep 2s

# Switch to Connections tab
Type "2"
Sleep 3s

# Switch to Interfaces tab
Type "3"
Sleep 3s

# Switch to Packets tab
Type "4"
Sleep 2s

# Start packet capture
Type "c"
Sleep 5s

# Stop capture
Type "c"
Sleep 2s

# Switch to Stats tab
Type "5"
Sleep 3s

# Switch to Insights tab (AI/Ollama)
Type "8"
Sleep 2s

# Trigger on-demand AI analysis
Type "a"
Sleep 8s

# Back to Dashboard
Type "1"
Sleep 3s

# Show help overlay
Type "?"
Sleep 3s

# Close help
Type "?"
Sleep 1s

# Quit
Type "q"
Sleep 1s
