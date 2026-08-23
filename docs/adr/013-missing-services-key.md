# ADR-013: Handling Compose Files Without a Top-Level `services:` Key

**Status:** Accepted

**Context:** Running compose-lint 0.5.2 over a 1,554-file real-world corpus
from public GitHub repos showed that **18% of files (286 / 1,554)** failed
with `Not a valid Compose file: missing 'services' key` and exited 2. Those
files fall into two broadly recognisable buckets that a sweep-mode user
(`compose-lint **/*.yml`, pre-commit, CI lint over a monorepo) does not
care about:

1. **Compose v1 files** — services declared at the top level, no
   `services:` wrapper. Docker
   [retired Compose v1 in 2023](https://www.docker.com/blog/new-docker-compose-v2-and-v1-deprecation/#compose-v-1-so-long-and-farewell-old-friend),
   but plenty of v1 files are still in the wild.
2. **Fragments / overrides** — partial files designed to be merged via
   `extends:` or layered with `-f override.yml`. Top-level `volumes:`,
   `networks:`, `version:`, or `x-*` blocks only.

The status-quo behaviour conflated both of these with genuinely malformed
input, made directory sweeps noisy, and — combined with multi-file
fail-fast (issue #158) — silently dropped findings on later files in argv.
Issue #155 enumerated four options for the policy. This ADR records the
chosen one.

**Decision:** Adopt **Option D** from #155: distinguish "not a v2/v3
Compose file" from "broken Compose file" at the parser layer, and route
the not-applicable case to a per-file skip with **exit 0**. Genuinely
malformed input continues to **exit 2**.

Concretely:

- `parser.ComposeNotApplicableError` is introduced as a `ComposeError`
  subtype. Existing callers that catch `ComposeError` continue to handle
  the new case (no breakage); callers that want to special-case "skip"
  catch the subtype.
- `_validate_compose` invokes `_classify_missing_services(data)` when
  `services:` is absent, returning either the new subtype (skip) or the
  existing `ComposeError` (hard fail).
- The CLI catches `ComposeNotApplicableError` per file, prints a
  `<filepath>: Skipped: …` line to stderr, and `continue`s. The file is
  not counted as a failure for exit-code purposes.

**Heuristic for classifying a missing-`services:` file:**

```text
non_meta = top-level keys, excluding `__lines__`, fragment-skeleton keys
           {version, name, volumes, networks, configs, secrets, include},
           and anything starting with `x-`

if non_meta is non-empty and every key is a
     compose-lint config top-level key                → own-config skip
elif non_meta is empty                                → fragment skip
elif every non_meta value is a mapping containing
     at least one key from the v1 service-marker set  → v1 skip
else                                                  → hard error
                                                        ("missing 'services' key")
```

> **Amended.** The `include` branch of this pseudocode no longer matches the
> code — see the 2026-08-23 amendment at the end of this ADR.

The v1 service-marker set is the set of v1-schema keys that strongly
identify a top-level mapping value as a service definition (`image`,
`build`, `command`, `entrypoint`, `ports`, `volumes`, `environment`,
`env_file`, `depends_on`, `container_name`, `restart`, `links`, `expose`,
`working_dir`, `user`, `cap_add`, `cap_drop`, `privileged`, `read_only`,
`devices`, `security_opt`, `network_mode`, `networks`, `extends`).

**Skip messages:**

- Own config: `Skipped: file appears to be a compose-lint config (top-level
  'rules' and no 'services:' key), not a Compose file. compose-lint reads
  its config via --config; it is not a lint target.`
- Fragment: `Skipped: file appears to be a Compose fragment (no 'services:'
  key; only top-level structural keys present). Fragments are typically
  merged via 'extends:' or '-f' overlays and have no services to lint on
  their own.`
- v1: `Skipped: file appears to be Compose v1 (services declared at the
  top level, no 'services:' wrapper). Docker retired Compose v1 in 2023;
  compose-lint targets v2/v3. Migrate the file under a top-level
  'services:' key to enable linting.`

**Alternatives rejected:**

- **Option A — status quo (hard-fail every missing-`services:` file).**
  Loses 18% of real-world inputs in sweep mode. Conflates v1 and fragments
  with malformed input under one error message users read as "your file is
  broken."
- **Option B — soft-skip everything as an info-level finding (exit 0).**
  Hides genuinely broken files behind a low-severity finding. CI gates
  scanning for non-zero exit codes wouldn't notice a malformed compose
  that happens to drop `services:`.
- **Option C — auto-detect v1 and lint it as if it were v2.** Recovers
  more signal (v1 files do have hardening issues to flag), but commits
  compose-lint to maintaining a v1-to-v2 shim for a format Docker has
  retired. Adds a heuristic that will silently mis-lint borderline cases.
  Worth revisiting only if users explicitly ask for v1 support; until
  then, "skip with a clear migration message" is the right default.
- **Lumping v1 and fragments under one skip message.** The v1 case has
  remediation guidance (migrate under `services:`); the fragment case
  does not. Two messages cost a few extra lines and pay off in clarity.

**Rationale:**

- Sweep-mode UX. `compose-lint **/*.yml` over a monorepo no longer
  exits 2 on the first v1 file or `-f` overlay it encounters. This is
  the workflow the corpus run exposed as broken.
- Honest semantics. Exit 2 keeps meaning "the linter could not run on
  this input"; exit 0 + skip means "the linter ran, this file is outside
  scope, nothing to report." Distinct outcomes get distinct exit codes.
  A single-file invocation against a v1 file exits 0 with a clear stderr
  message — the file isn't broken, the linter just doesn't apply.
- Defence-in-depth against masking real bugs. The "hard error" branch is
  preserved for the unrecognised case (top-level mapping with non-meta
  keys whose values aren't service-shaped). A user with a typo'd
  `srvices:` still gets exit 2.
- Public API stability. `ComposeNotApplicableError` subclasses
  `ComposeError`, so library callers that already do
  `except ComposeError` keep their behaviour; only callers that *want*
  to discriminate need the new type.

**Interaction with other work:**

- **ADR-006 (exit codes)** is unchanged. Exit 2 still means "usage /
  file errors"; this ADR carves out a subset that exits 0 because the
  file isn't actually a usage error.
- **#158 (multi-file fail-fast for `ComposeError`)** is independent. The
  new skip path uses `continue`; the existing hard-fail path still calls
  `sys.exit(2)`. When #158 lands, both paths will collect into the same
  per-file outcome bookkeeping and the exit-code policy will be revisited
  end-to-end.
- **#156 (grouped text output)** will eventually want a "skipped files"
  count in the aggregate footer. Out of scope here; the per-file stderr
  line is enough signal until #156 lands.

**Implementation notes (non-binding):**

- `parser.py` exposes `_TOP_LEVEL_FRAGMENT_KEYS` and `_V1_SERVICE_MARKERS`
  as module-private frozensets so the heuristic can be tuned in one
  place.
- Fixtures live alongside the existing invalid-Compose files in
  `tests/compose_files/`: `fragment_volumes_only.yml` and
  `legacy_v1_compose.yml`. The pre-existing `invalid_no_services.yml`
  was repurposed to cover the unrecognised-shape branch (no `services:`,
  no fragment-skeleton keys, no v1-shaped values).
- The heuristic is intentionally narrow on the fragment side: a top-level
  mapping with `version: "3"` and a single `volumes:` block is a
  fragment; a top-level mapping with `mystery_key: 5` is not. False
  positives on fragment detection silently lose findings, so the
  whitelist of "what counts as fragment scaffolding" stays small and
  obvious. The v1 side is broader because v1 files have visibly
  service-shaped top-level values, which gives a cleaner positive
  signal.

**Amendment (2026-08-08, issue #499) — compose-lint's own config as a third
not-applicable bucket:**

The original heuristic recognised two not-applicable shapes. A third was
found in the field: compose-lint's own config file. `.compose-lint.yml`
carries a top-level `rules:` key, which is not fragment scaffolding, and
its nested values are rule-id blocks (`enabled`, `reason`, `severity`,
`exclude_services`) which carry no v1 service markers — so it fell through
to the hard error and exited 2.

That surfaced as issue #465: `compose-lint init` writes `.compose-lint.yml`,
the pre-commit hook's `files` pattern then matched it, and the hook could
never pass on a repo that had run `init`. It was mitigated at the hook layer
in #495/#496 by narrowing `files` and adding an `exclude`, but that is a
pattern workaround for a linter behaviour, and it is defeatable: pre-commit
merges a user's hook settings over the manifest, so anyone who sets their
own `exclude:` (excluding fixtures, carving out a legacy backlog, scoping a
monorepo) drops ours and can reintroduce the failure with a dotless
`compose-lint.yml`.

The classifier now recognises a file whose non-meta top-level keys are a
non-empty subset of `config.KNOWN_TOP_LEVEL_KEYS` as compose-lint's own
config and skips it. This is a new bucket under the existing decision, not
a change of policy: "not a v2/v3 Compose file" still skips, "broken Compose
file" still exits 2.

Deliberately narrow, for the same reason the fragment side is narrow. The
check requires *every* non-meta key to be a config key, so a file mixing
`rules:` with anything else is still a hard error — a blanket "skip any
unrecognised YAML" would silently swallow a genuinely malformed Compose
file, which is a worse failure than the one being fixed. `KNOWN_TOP_LEVEL_KEYS`
is read from `config.py` rather than duplicated, so a future config key
cannot drift out of this check.

This leaves a known gap: a non-Compose YAML that merely *matches* a compose
glob (a `compose-values.yml` Helm file, say) still exits 2, and no hook
`exclude` covers it. Whether more buckets are worth recognising, or whether
sweep users should scope their globs, is left open rather than settled here.

**Amendment (2026-08-22, issue #671) — a fragment that is an *overlay*, not a
lint target:**

This ADR decided what to do with a file that has no `services:` key. Every case
it weighed was a file linted **on its own** — that is the wording of the skip
message itself, and the sweep-mode UX in the rationale is a directory of
independent files. Merging did not exist yet: [ADR-025](025-lint-the-merged-configuration.md)
arrived on 2026-08-20, almost four months after this decision was accepted, and
taught compose-lint to load a base file together with its overlays.

At that intersection the skip policy produces a result neither ADR intended. A
valid base file carrying `privileged: true`, beside a `compose.override.yml`
containing only `volumes:`, `networks:`, or `{}`, reports `✓ PASS` at exit 0.
The fragment classifier fires on the overlay, `load_merged` propagates
`ComposeNotApplicableError`, and the CLI's per-file skip handler — correct for
one file, blind to the merge set — discards the whole project. Docker Compose
merges that same pair and deploys the privileged container. A two-byte
`compose.override.yml` containing `{}` turns a failing merge gate green.

**A fragment appearing as an overlay in a merge set is merged, not skipped.**
Compose treats it as an ordinary document that happens to contribute only
top-level keys, and ADR-025 says compose-lint grades the configuration Compose
runs. Skipping it was never a decision this ADR made; it is what a single-file
policy did when handed a case it had not seen.

Two things are deliberately unchanged. **A fragment linted on its own still
skips at exit 0** — that is what this ADR decided, the sweep-mode reasoning
still holds, and nothing above touches it. And **the classifier is untouched**:
what counts as a fragment stays exactly as narrow as it was, because a false
positive there still silently loses findings.

The choice between merging the fragment and ignoring the overlay was, in
practice, not observable: no rule reads top-level `volumes:`, `networks:`,
`configs:` or `secrets:`, and `engine.py` iterates `data["services"]`, to which
a fragment contributes none. Both options yield identical findings today.
Merging is recorded here because it is what ADR-025 claims the tool does and
what Compose actually does, so it leaves no trap for a future rule that does
read a top-level key.

**Scope: fragments only.** The other two not-applicable buckets reach the same
skip path and produce the same false pass, but Compose does not accept them, so
merging would be wrong. Captured against Docker Compose 5.4.0:

| overlay | Compose | compose-lint |
|---|---|---|
| fragment (`volumes:` / `networks:` / `{}`) | merges; project deploys | merge it |
| v1-shaped (services at top level) | `additional properties 'db' not allowed` | error |
| compose-lint's own config | `additional properties 'rules' not allowed` | error |

Those two are tracked in [#673](https://github.com/tmatens/compose-lint/issues/673)
and are not settled here.

**Interaction with ADR-006.** Exit codes are unchanged. This removes an exit 0
that was asserting a clean grade on an ungraded project; it does not add a code
or move a boundary. Affected files move from `PASS` to `FAIL` where the base
carries a finding, which is new findings appearing on tightened coverage — the
MINOR behaviour `docs/compatibility.md` already describes, and the shape #648,
#657 and #668 each shipped under.

**Amendment (2026-08-23, issue #673) — the remaining two buckets, plus two
corrections to the record above:**

**1. A v1-shaped or own-config overlay is an error, not a skip.**

The amendment above closed with "Those two are tracked in [#673] and are not
settled here." They are settled now, along exactly the line its table
predicted.

A v1-shaped or own-config document appearing *anywhere in a merge set* raises
`ComposeFileError`, which the CLI already reports at exit 2 against the file
that caused it. Compose refuses a project containing either — `additional
properties 'db' not allowed`, `additional properties 'rules' not allowed` — so
unlike the fragment case there is no configuration for ADR-025 to grade.
Merging would grade a document that never deploys; skipping asserted a clean
grade on a project that was never read.

The own-config half is worth stating on its own: a file whose entire purpose
is to disable rules could, if named in `COMPOSE_FILE`, silence the linter
completely rather than disabling one rule.

Two things are unchanged, for the same reasons the fragment amendment gives.
**A v1 file or a stray `.compose-lint.yml` linted on its own still skips at
exit 0** — that is what this ADR decided and sweep-mode UX still rests on it.
And **the classifier is untouched**: which bucket a file falls into is decided
exactly as before; only what a merge does with the answer has changed.

This also settles the second defect recorded in #671. The skip handler
attributed its message to the primary path, so a valid v2 base was reported as
the unlintable file. An error carrying a path names the overlay instead.

**Interaction with ADR-006 — and how it differs from the amendment above.**
That amendment could say exit codes were unchanged: the fragment fix moved
affected projects from `PASS` to `FAIL`, both inside the finding contract. This
one moves them from **exit 0 to exit 2**. No code is added and no code changes
meaning — exit 2 still means "the linter could not run on this input", which is
the property [`docs/compatibility.md`](../compatibility.md) protects when it
says adding a new non-zero code is a MAJOR change. What changed is that a
project with an unlintable overlay was being classified as "the linter ran,
nothing to report" when it had not run at all.

The user-visible consequence is real even so: a pinned pipeline that was green
on such a project goes red. That is release-note material in its own right,
not the tightened-coverage shape #648, #657, #668 and #671 shipped under.

**2. Correction: the heuristic above no longer describes `include:`.**

The pseudocode lists `include` among the fragment-skeleton keys excluded from
`non_meta`, so an include-only file reaches the `non_meta is empty` branch and
reads there as a fragment skip at exit 0. The code refuses it instead, with a
plain `ComposeError` at exit 2.

This is not a new decision and does not belong to this ADR to make. It is
[ADR-023](023-deploy-host-independent-claims.md)'s principle — "`include:` /
cross-file `extends:` are refused loudly as coverage gaps rather than resolved
through the lint host's filesystem" — which [ADR-025](025-lint-the-merged-configuration.md)
cites as "the `include:` precedent" and states in its own words: an unresolved
`include:` is a gap because compose-lint *cannot* read the file. Issue #516
established the consequence for a services-less file specifically: admitting
one as a harmless fragment reports a clean pass on a deployable stack.

The branch as the code implements it:

```text
if 'include' in data                                  → hard error
                                                        (ADR-023; issue #516)
elif non_meta is non-empty and every key is a
     compose-lint config top-level key                → own-config skip
elif non_meta is empty                                → fragment skip
elif every non_meta value is service-shaped           → v1 skip
else                                                  → hard error
```

The `include` test runs first and is unconditional, so an include-only file
never reaches the fragment branch regardless of what else it carries.

**3. A merge set has a fourth skip, and it describes a set rather than a file.**

The three skip messages recorded above each describe one file. #671's
implementation added one that does not: when *every* document in a merge set is
a fragment, no document contributes `services:`, and `load_merged` raises a
bare `ComposeNotApplicableError` —

- All-fragment set: `Skipped: merged configuration has no 'services:' key
  (every selected file appears to be a Compose fragment), so there are no
  services to lint.`

It is deliberately not the fragment subtype: this is a property of the merged
set, not a classification of any one file, so naming the fragment bucket would
misdescribe it. The outcome is a skip at exit 0, which is this ADR's policy
applied to a set — merging the fragments would produce a vacuous `PASS` on a
project with nothing in it, which is the failure this ADR's amendments exist to
prevent.
