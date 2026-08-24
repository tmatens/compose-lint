# ADR-029: A Scheduled Python-EOL Drop Is MINOR, Post-1.0 Included

**Status:** Accepted

**Context:** Until this ADR, dropping a supported Python version was MINOR
pre-1.0 and MAJOR post-1.0. The Python 3.10 drop
([#643](https://github.com/tmatens/compose-lint/issues/643), shipped ahead of
the interpreter's October 2026 upstream EOL) showed what that rule costs: the
ordering of an unrelated release — the 1.0 cut — had to bend around a routine
calendar event, because landing the drop after 1.0 would have forced a choice
between a 2.0 that communicates nothing about the tool's contract and carrying
an end-of-life interpreter inside the stability promise indefinitely. CPython
minors EOL every October, forever; under the old rule every one of them is a
potential forced MAJOR, and 3.11 (October 2027) would have recreated the trap
about a year after any plausible 1.0.

MAJOR exists to signal *surprise*: a pinned, working setup breaks because the
tool changed underneath it. A Python drop at upstream EOL is the opposite of a
surprise — the date is published by CPython half a decade in advance, the
[EOL radar](../../.github/workflows/eol-watch.yml) surfaces it 180 days out,
the release that announces the deprecation warns on stderr from every run on
the affected interpreter, and at least one MINOR of grace passes before the
drop. It is also the *softest* removal the tool performs: `requires-python`
never breaks an existing environment — pip resolves an affected interpreter to
the last release that allowed it, so a pinned setup keeps working verbatim and
even an unpinned `pip install -U` keeps working, frozen, rather than failing.

**Decision:** Dropping a CPython minor is a **MINOR** change at any point in
the project's life, provided the drop is *scheduled* — all of:

1. The interpreter has reached, or reaches within the release's support
   window, its published upstream end-of-life; the drop ships **no earlier
   than the upstream EOL date**.
2. The deprecation was announced in `CHANGELOG.md` and warned on stderr at
   runtime, both starting **at least 180 days** before the drop ships (the
   radar's window — sized so announce → warn → grace → drop runs at a
   calendar pace, not a version-count pace; the 3.10 cycle's one-day gap
   between warning release and eligible drop is the failure mode the floor
   exists to prevent).
3. At least one MINOR release carried the warning before the release that
   drops.

A drop that misses any condition — an interpreter dropped before its EOL, or
without the announcement runway — is **MAJOR**, post-1.0. The schedule is the
license for the smaller bump.

**Rationale:**

- The pre-EOL exception #643 used was justified by 1.0 ordering pressure that
  no longer exists once 1.0 ships; anchoring post-1.0 drops to the EOL date
  keeps the policy defensible against its sharpest criticism (an Ubuntu
  22.04 user's system Python losing updates while the OS is still supported).
- This follows the same reasoning as "new findings are not a breaking change"
  (compatibility.md): the contract promises *no surprises*, not *no change*,
  and names the escape hatch — pin the version — which a `requires-python`
  drop uniquely cannot break.
- A security linter carrying an interpreter that no longer receives security
  fixes inside its own stability contract is the wrong trade in both
  directions.

**Consequences:**

- `docs/compatibility.md` (Python versions, deprecation lifecycle),
  `docs/RELEASING.md` (post-1.0 rules and the cheat sheet) and
  `docs/ROADMAP.md` (Python version support) are amended alongside this ADR.
- The deprecation lifecycle's "removal happens only in a MAJOR" gains its one
  carve-out, stated there: a scheduled interpreter drop per this ADR.
- The 3.11 drop (EOL October 2027) will be the first exercise: announce and
  start warning by ~April 2027 (the radar files the issue), drop in the first
  MINOR on or after the EOL date.
