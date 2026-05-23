# README hero demo for compose-lint.
#
# Source recording script for the README GIF. To regenerate, see
# scripts/demo/README.md.

Output demo.gif

Require compose-lint

# A normal-width terminal at a large, legible font. `tput rmam` (below) turns
# off line wrapping so compose-lint's long finding and reference lines clip at
# the right edge instead of wrapping raggedly — the structured left side
# (severity, rule id, message, carets, fix/ref) stays clean.
Set Shell bash
Set FontSize 22
Set Width 1500
Set Height 760
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 45ms
Set Framerate 12

# Quiet prompt + disable line wrapping. The steady block cursor stays visible in
# every frame; retime.py detects it and synthesizes the blink. Hidden from the
# recording.
Hide
Type "export PS1='$ '"
Enter
Type "tput rmam"
Enter
Type "clear"
Enter
Show

Sleep 1s

# 1. Lint a small, ordinary-looking compose file. Five findings, landing on the
#    HIGH one — a port bound to every interface (CL-0005, with line carets) —
#    then the FAIL verdict. Pause on the typed command, then on the output.
Type "compose-lint docker-compose.yml"
Sleep 1900ms
Enter
Sleep 8s

# 2. Drill into the exposed-port finding with the offline rule docs.
Type "compose-lint --explain CL-0005"
Sleep 1900ms
Enter
Sleep 9s
