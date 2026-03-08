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

# Dashboard - live interface stats, bandwidth, health
Sleep 3s

# Connections tab
Type "2"
Sleep 3s

# Interfaces tab
Type "3"
Sleep 3s

# Packets tab
Type "4"
Sleep 2s

# Start packet capture
Type "c"
Sleep 6s

# Scroll through captured packets
Down
Sleep 1s
Down
Sleep 1s
Down
Sleep 1s

# Select a packet to see detail
Enter
Sleep 3s

# Open stream view for selected packet
Type "s"
Sleep 3s

# Close stream view
Escape
Sleep 1s

# Stop capture
Type "c"
Sleep 2s

# Stats tab - protocol hierarchy
Type "5"
Sleep 3s

# Topology tab
Type "6"
Sleep 3s

# Timeline tab
Type "7"
Sleep 3s

# Insights tab - AI analysis with minimax cloud
Type "8"
Sleep 2s

# Trigger on-demand AI analysis
Type "a"
Sleep 12s

# Back to Dashboard
Type "1"
Sleep 3s

# Show help overlay
Type "?"
Sleep 3s

# Close help and quit
Type "?"
Sleep 1s
Type "q"
Sleep 1s
