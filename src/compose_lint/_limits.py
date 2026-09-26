"""Bounds on the work one untrusted scalar, or one document, can cause.

A Compose file is a human-authored document, but nothing stops one from
carrying a 200 KB environment value. Several rules scan such values with
regexes whose worst case is quadratic, so the size of a value decides how long
the run takes — which makes a cheap denial of service out of a file that
produces no findings at all and exits 0, so nothing in the output signals it.

Capping the input is the layer that closes the whole class: a pattern can be
rewritten to remove one backtracking path, but the next pattern added to a rule
brings its own. Above the cap the caller returns its conservative answer without
scanning.

The same holds one level up. `MAX_FILE_BYTES` bounds what a document *reads*,
not what it *builds*: YAML lets a few bytes stand for a whole subtree, so a
file far under that cap can construct gigabytes before any rule sees it. The
document-level caps at the end of this module bound the construction itself.
Above them there is no conservative answer to return — the document was never
built — so the file is refused with the reason, exit 2, like an oversized one.
The reference caps in `parser` (`MAX_REFERENCE_DEPTH`, `MAX_REFERENCE_FILES`,
ADR-036 §4) bound the other expansion, across files.
"""

from __future__ import annotations

# Chosen far above anything a real Compose scalar reaches — the largest value
# in a 5,417-file corpus is a fraction of this — so the cap only ever fires on
# input written to be pathological. Below it, even a quadratic pattern is
# bounded at a few milliseconds.
MAX_SCAN_LEN = 8192

# The cap above bounds what is *scanned*; this one bounds what substitution
# *produces*. They are different quantities: `${A}${A}` is four characters of
# input whose result is twice whatever `A` holds, so a chain of definitions
# that each reference the one below doubles per level. Thirty levels of that
# is a 489-byte `.env` whose expansion is gigabytes — the input cap never
# fires, because no single value is ever large.
#
# Sixteen times MAX_SCAN_LEN: far above any real interpolated value (a scalar
# larger than MAX_SCAN_LEN is not scanned by the rules anyway), and small
# enough that reaching it costs nothing. Above it the caller returns the same
# conservative "unknowable" answer it already returns for a name it cannot
# resolve.
MAX_SUBSTITUTED_LEN = MAX_SCAN_LEN * 16

# A merge key (`<<: *common`) copies every pair of its anchor into each mapping
# that uses it, so N keys merged into M services is N*M constructed pairs from
# N+M lines. 2,000 of each is a 122 KB file that took 1.1 GB and 5 s to load.
#
# Counted per document as pairs the merges add, before the mapping is built, so
# the refusal lands after a few dozen services rather than after the gigabyte.
# The largest count in an 11,111-file corpus of real Compose files is 968, and
# the test suite's is 3,000; at this cap a load costs tens of megabytes.
MAX_MERGED_PAIRS = 65536

# A bare alias (`s1: *base`) is a whole service for one token, so services per
# document are bounded by nothing but the byte cap: 90,000 of them was a 1.6 MB
# file that cost 1.6 GB and printed 587 MB of JSON. Loading them is cheap; the
# cost is every rule, finding and output line per service after that.
#
# Checked on each document as parsed and again once its `include:` files are
# folded in, so a stack cannot pass by spreading its services across files. The
# largest count in the corpus is 64 services, and the test suite's is 2,000.
MAX_SERVICES = 4096
