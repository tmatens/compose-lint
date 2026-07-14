# README hero demo for compose-lint.
#
# Source recording script for the README GIF. To regenerate, see
# scripts/demo/README.md.

Output demo.gif

Require compose-lint

# A normal-width terminal at a large, legible font. `tput rmam` (below) turns
# off line wrapping so compose-lint's long finding and reference lines clip at
# the right edge instead of wrapping raggedly — the structured left side
# (severity, rule id, message, underline, fix/ref) stays clean. Height gives
# 28 rows at this font, one more than the lint step needs (command + 25 output
# lines + prompt), so the banner stays on screen.
Set Shell bash
Set FontSize 22
Set Width 1500
Set Height 880
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

# 1. Lint a small, mostly-hardened compose file. Three findings, severity-sorted
#    so the CRITICAL one leads — a mounted Docker socket (CL-0001, with a
#    box-drawing underline) above a HIGH sensitive host mount (CL-0013) and a
#    MEDIUM tag-only image pin (CL-0019) — then the FAIL verdict. Pause on the
#    typed command, then on the output.
Type "compose-lint docker-compose.yml"
Sleep 1900ms
Enter
Sleep 8s

# 2. Drill into the socket finding with the offline rule docs. The doc is longer
#    than the screen; the settled tail shows the hardened socket-proxy fix and
#    the "when to suppress" guidance that names Watchtower — the very service
#    the demo just linted.
Type "compose-lint --explain CL-0001"
Sleep 1900ms
Enter
Sleep 9s
