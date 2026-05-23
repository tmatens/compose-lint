# README hero demo for compose-lint.
#
# Source recording script for the README GIF. Deterministic: VHS replays this
# headlessly, so the cast re-renders identically against any version.
# To regenerate, see scripts/demo/README.md.

Output demo.gif

Require compose-lint

# Wide terminal (~185 cols) so compose-lint's long finding/ref lines fit on one
# line instead of hard-wrapping at the margin. compose-lint does not wrap to the
# terminal width, so the terminal must be wide enough to hold whole lines.
Set Shell bash
Set FontSize 14
Set Width 1780
Set Height 720
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 45ms

# Quiet, predictable prompt — no hostname/cwd noise in the frame.
Hide
Type "export PS1='$ '"
Enter
Type "clear"
Enter
Show

Sleep 800ms

# 1. Lint a small, ordinary-looking compose file. Five findings stream past:
#    an unpinned image (CL-0019) and missing hardening, landing on the HIGH
#    one — a port bound to every interface (CL-0005, with line carets) — then
#    the FAIL verdict.
Type "compose-lint docker-compose.yml"
Sleep 600ms
Enter
Sleep 5s

# 2. Drill into the exposed-port finding with the offline rule docs —
#    no browser, no network.
Type "compose-lint --explain CL-0005"
Sleep 600ms
Enter
Sleep 5s
