# ADR-041: Suppressions Can Expire

**Status:** Accepted

**Context:** A suppression in `.compose-lint.yml` lasts until someone removes
it. An accepted risk is usually accepted for a while: until a migration lands,
until a base image changes, until the next review. The only place to record
that deadline was the free-text `reason`, which nothing reads. The project's
own documentation recommended dated exceptions it could not enforce: the
configuration guide's example reason ended "expires 2026-07-01", and the
examples library calls a waiver with no date the thing to avoid. A user asked
for exactly this (#1207): an exceptions file with a required reason and an
expiry date per service, "so CI stays strict without training people to
ignore the red output."

Two facts measured while this was designed shape what expiry can and cannot
do:

- **GitHub Code Scanning does not read SARIF `suppressions[]`.** A suppressed
  result becomes an ordinary open alert (#1223). So in Code Scanning, expiry
  is visible only to a workflow that sets `skip-suppressed`, which leaves
  suppressed results out of the upload. For everyone else it acts on the exit
  code and on the text, JSON and SARIF output.
- **`init` writes placeholders, not decisions.** Every entry it writes reads
  `TODO: justify or fix`. That shaped the decision not to make expiry part of
  `init` (§7).

This amends [ADR-010](010-per-service-rule-overrides.md), whose config schema
it extends.

**Decision:**

1. **Shape.** An `exclude_services` entry may be a mapping with `reason` and
   `expires`. A rule block may carry `expires` beside `enabled: false`. The
   string form (`web: "reason"`) and the list form keep meaning exactly what
   they meant, and never expire. A mapping entry with no `expires` is the
   string form written longhand. An unknown key inside an entry warns, as an
   unknown rule key does, so a later key (an evidence scope, a cap on matches)
   has somewhere to go without designing it now.

2. **A dated entry needs a reason.** `expires` with a missing or empty
   `reason` is a config error (exit 2). ADR-010's reasonless forms are
   unchanged for entries with no date. A deadline with no recorded reason is
   the exception this feature exists to prevent, and since #888 a present
   `suppression_reason` is always text from the config, so the check means
   something.

3. **The date.** `YYYY-MM-DD` only, quoted or not (YAML makes an unquoted
   one a date). A time of day, a compact or week date, or anything else is a
   config error, not a guess. It is compared with the **UTC date**, and the
   entry **suppresses through the named day**: an entry dated 2027-03-31
   suppresses on 2027-03-31 and not on 2027-04-01. A day is all a review
   deadline needs, and one timezone means a laptop and a CI runner agree.

4. **After the date the entry is not in force.** The finding is graded as if
   the entry were not written: it counts toward `--fail-on`, a severity
   override applies to it, and a lapsed rule-level disable falls through to
   the rule's `exclude_services`. The finding carries the date it lapsed, so a
   reader can tell why a run that passed yesterday fails today. Nothing
   rewrites or removes the entry; a person fixes the finding, deletes the
   entry, or sets a new date in a reviewed change.

5. **The countdown is display, never a gate.** In the 14 days before the date
   the text report adds `(expires in N days)` to the suppressed finding, on
   its own line so `--quiet` keeps it. The window is fixed, not configurable.
   It is not a config diagnostic and `--strict-config` does not promote it:
   exit 2 means a config that has no effect or a stack that was not fully
   read, and an approaching date is the config working as written. A
   pipeline that wants an earlier or louder notice reads the date from JSON
   or SARIF (§6) and decides for itself.

6. **Output.** All additive (MINOR, `docs/compatibility.md`):
   - JSON: `suppression_expires` on a suppressed finding whose entry has a
     date, and `suppression_expired` on a finding reported because its
     entry's date passed. Each appears only on its own branch.
   - SARIF: the suppression's `properties.expires`, because SARIF's
     suppression object has no expiry field, and the result's
     `properties.suppressionExpired`.
   - Text: the countdown (§5), and `(suppression expired YYYY-MM-DD)` on a
     lapsed finding.

7. **`init`, `skip-suppressed` and the Action's upload are unchanged.**
   `init` writes no dates; adding one is part of triaging its entries. The
   Action keeps uploading suppressed results unless `skip-suppressed` is set.

8. **Results depend on the date, and that is accepted.** The same commit and
   config can pass one day and fail the next, with no change anyone can point
   to in the diff. That is what a deadline is, and it is the trade the request
   asks for. Every other input to a run is still the files and flags, and a
   config with no `expires:` is exactly as reproducible as before. To
   reproduce a past run, or pin the day in a test, `check` and `fix` take
   `--as-of YYYY-MM-DD`. It is a flag rather than an environment variable,
   because [ADR-037](037-environment-variables-are-cli-surface.md) makes
   every variable the CLI reads part of its contract. The Action fixes the
   UTC date once and passes it to both of its runs, so its verdict and its
   SARIF file cannot fall on different sides of midnight; it probes for the
   flag first, because its `version` input can install a release that
   predates it. The date's first red build lands on whichever change runs
   first after it, which is why the countdown exists.

9. **Identity is untouched.** Suppression is not part of a finding's identity
   ([ADR-024](024-finding-identity-is-not-prose.md)), so an entry lapsing
   never re-keys an alert. Under `skip-suppressed`, the finding reappears in
   the upload with the fingerprint it had before it was suppressed.

**Recorded, not built: a deferral is not an acceptance.** The design review
for this ADR found that "suppressed" covers two states. An entry with a
reason records a decision. An entry `init` wrote, or one with no reason,
records that nobody has decided yet. Code Scanning cannot tell them apart,
which is why `skip-suppressed` is not the default: it would close a newly
adopted repository's whole backlog as fixed. The principled fix is to make the
two states distinct: `init` writes entries with no reason; SARIF marks those
`suppressions[].status: "underReview"` and reasoned ones `"accepted"`, the
vocabulary SARIF already has; and the Action's upload can then omit accepted
results only. That keeps "never hide a risk nobody accepted" without tying it
to a date. It waits for a user to ask, the same gate #1206 applied. Syncing
exclusions to Code Scanning dismissals stays rejected: no API maps a result's
fingerprint to its alert, so matching by rule, file and line can dismiss the
wrong one.

**Alternatives rejected:**

- **`init` writes a default expiry.** It would not protect Code Scanning users
  until the date, and every entry would then lapse on the same day and turn
  every open change red at once. The easy response to that is a bulk date
  bump, which is the "ignore the red" habit the request wanted to end.
- **Omit suppressed results from the Action's upload by default, shipped with
  expiry.** It closes existing alerts on an Action upgrade with nobody
  reviewing them, and with an untriaged `init` config it closes the whole
  backlog. Of the options considered it is the one that can hide a risk nobody
  accepted.
- **Warn on stderr in the window, error under `--strict-config`.** A team that
  follows the documented CI advice would go red 14 days before the date it
  wrote, with exit 2 meaning something new.
- **Move every config warning onto JSON `warnings[]` and a SARIF notification
  first, so the window reaches machine readers.** Not needed: the dates are on
  the findings (§6). It also changes every existing config warning, which is a
  separate decision.
- **Warn instead of stopping.** An exception that only warns when it ends is
  one more line people learn to ignore, which is what the request is about.
- **A full timestamp, or the runner's local timezone.** Precision a review
  deadline does not need, and results that differ between a laptop and CI.
