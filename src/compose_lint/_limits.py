"""Bounds on the work one untrusted scalar can cause.

A Compose file is a human-authored document, but nothing stops one from
carrying a 200 KB environment value. Several rules scan such values with
regexes whose worst case is quadratic, so the size of a value decides how long
the run takes — which makes a cheap denial of service out of a file that
produces no findings at all and exits 0, so nothing in the output signals it.

Capping the input is the layer that closes the whole class: a pattern can be
rewritten to remove one backtracking path, but the next pattern added to a rule
brings its own. Above the cap the caller returns its conservative answer without
scanning.
"""

from __future__ import annotations

# Chosen far above anything a real Compose scalar reaches — the largest value
# in a 5,417-file corpus is a fraction of this — so the cap only ever fires on
# input written to be pathological. Below it, even a quadratic pattern is
# bounded at a few milliseconds.
MAX_SCAN_LEN = 8192
