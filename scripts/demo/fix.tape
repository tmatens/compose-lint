# README demo for `compose-lint fix`.
#
# Source recording script for docs/assets/demo-fix.gif. To regenerate, see
# scripts/demo/README.md.

Output fix.gif

Require compose-lint

# Same terminal as the hero cast (demo.tape) so the two GIFs sit at the same
# width in the README. `tput rmam` turns off line wrapping so the three long
# behavior-changing caveat lines clip at the right edge instead of wrapping
# and pushing the diff off screen.
#
# Height gives 30 rows, exactly what the taller of the two screens needs on
# 0.25.0 (its no-config Note line took the spare row):
#   screen 1 — command + 28 lines of dry-run output + prompt       = 30 rows
#   screen 2 — apply (command + 5) + check (command + 16) + prompt = 24 rows
# A release that adds a line to either output overflows and scrolls, which
# tests/test_demo_fixture.py is what catches (it pins the finding set the two
# screens are sized around).
Set Shell bash
Set FontSize 22
Set Width 1500
Set Height 940
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 45ms
Set Framerate 12

# Quiet prompt, no line wrapping, and a scratch copy of the fixture: `fix
# --apply` rewrites the file in place, and the committed fixture has to stay
# pristine for the next render. Hidden from the recording.
Hide
Type "export PS1='$ '"
Enter
Type "tput rmam"
Enter
Type "mkdir -p /tmp/cast && cp fix-compose.yml /tmp/cast/docker-compose.yml && cd /tmp/cast"
Enter
Type "clear"
Enter
Show

Sleep 1s

# 1. Dry run. `fix` writes nothing by default: it prints the unified diff it
#    would apply, led by a behavior-changing caveat for each fix that can
#    change how the container runs (CL-0009's re-applied seccomp profile,
#    CL-0007's read_only, CL-0005's rebind to 127.0.0.1). The summary line
#    names what it will not touch — the tag-only image pin (CL-0019), which
#    has no safe automatic fix.
Type "compose-lint fix docker-compose.yml"
Sleep 1900ms
Enter
Sleep 7s

# Clear so the second screen starts clean — the two steps together are taller
# than the terminal. Hidden: the viewer sees a cut, not a `clear` command.
Hide
Type "clear"
Enter
Show

Sleep 500ms

# 2. Apply the same three edits for real, then re-lint. The file went from
#    FAIL (the unconfined seccomp profile is HIGH) to PASS at the default
#    threshold, with the one un-auto-fixable MEDIUM left reported rather than
#    silently dropped.
Type "compose-lint fix --apply docker-compose.yml"
Sleep 1900ms
Enter
Sleep 3s

Type "compose-lint check docker-compose.yml"
Sleep 1900ms
Enter
Sleep 8s
