# Compatibility and Stability Policy

compose-lint follows [Semantic Versioning](https://semver.org/). This page is
the user-facing promise: what stays stable across upgrades, what may change, and
how changes are signalled. The maintainer-facing bump-decision rules live in
[RELEASING.md](RELEASING.md#choosing-the-version-number); this policy is the
contract those rules implement.

## The 1.0 commitment

From `1.0.0` onward, the following are **stable** and change only under the
SemVer rules below:

- **CLI surface** — subcommands, flags, and their documented behavior,
  including the environment variables the CLI reads: `NO_COLOR`, `FORCE_COLOR`,
  `PAGER`, `NO_PAGER` and `TERM`, with the semantics
  [cli.md](cli.md#color) states
  ([ADR-037](adr/037-environment-variables-are-cli-surface.md)).
- **Exit codes** — the `0` / `1` / `2` contract ([ADR-006](adr/006-exit-codes.md))
  and the default `--fail-on` threshold.
- **Config schema** — the `.compose-lint.yml` keys and their semantics
  ([ADR-010](adr/010-per-service-rule-overrides.md)).
- **Machine output** — the JSON envelope and the SARIF 2.1.0 log shapes
  ([ADR-015](adr/015-machine-readable-output-contract.md)). Within them,
  `rule_id` (JSON) / `ruleId` (SARIF) is an **opaque string**: match exact
  values, never the `CL-\d{4}` pattern. Every value today happens to match
  it, but the format is not promised — a future rule source (e.g. the
  shellcheck integration of [ADR-007](adr/007-shellcheck-integration.md))
  may emit ids of a different shape as an additive, MINOR change.

  The SARIF fields a consumer may rely on are listed in ADR-015's
  [SARIF contract](adr/015-machine-readable-output-contract.md#sarif-contract)
  amendment. A diagnostic's `kind` is a closed set within a version and open
  across versions: a new value is a MINOR, so handle an unknown `kind` by its
  channel. An `errors[]` entry of any kind means the run exited 2, and a
  `warnings[]` entry never changes the exit code. `kind` and the channel are
  independent: the same kind can appear on either. `severity` stays a closed
  set of four, because it is the grading model rather than a catalogue.

## What is explicitly NOT covered

These may change in any release, including PATCH, without a major bump:

- **Human text output** — the exact wording, layout, colour, and ordering of
  `--format text`. It is for humans; parse JSON or SARIF if you need a stable
  shape. (The JSON `version` field exists precisely so you can.)
- **Prose inside JSON and SARIF** — every `message` and `message.text`, rule
  and notification descriptor text, fix guidance, the order of results, and
  which results a truncated SARIF log keeps beyond "the most severe 5,000,
  plus a notification". Match `rule_id`, `kind` and the other fields
  [the SARIF contract](adr/015-machine-readable-output-contract.md#sarif-contract)
  names, never text.
- **The dry-run `fix` diff as a patch format** — it is for review. Lines that
  a CI runner could read as a workflow command are escaped, so the output is
  not promised to `git apply`. To change the files, use `fix --apply`; for a
  patch, run `git diff` after it.
- **Internal Python API** — anything beyond `compose_lint.__version__` and the
  documented CLI. compose-lint is a CLI / GitHub Action, not an importable
  library; rule classes, the engine, parser, and formatters are implementation
  details.

## New findings are not a breaking change

This is the most important expectation for CI users. compose-lint **adds and
tightens rules in MINOR releases** — the same convention as Hadolint,
ShellCheck, and ruff. A file that is clean on `1.2.0` may report new findings on
`1.3.0`. That is intentional, not a contract break.

Three escape hatches keep a pipeline deterministic:

- **Pin the version** (`==1.2.0` in this example, or the digest-pinned Action /
  image) for identical results across runs.
- **Use `--fail-on`** to gate CI on a severity threshold, so new lower-severity
  findings surface without failing the build.
- **Use `--allow-partial-coverage`** for the one thing `--fail-on` cannot
  reach: a *coverage gap*, which exits 2 rather than reporting a finding. See
  below.

A rule's **severity** is part of the contract: post-1.0, *downgrading* a
severity is a MINOR, and *upgrading* one is a **MINOR with a one-release
runway** ([ADR-031](adr/031-severity-upgrades-are-minor-with-runway.md)): the
release before the move announces it under `Changed`, and the next MINOR
applies it. A pinned user is untouched either way; a threshold-gated
`--fail-on` user gets a full release of warning instead of a surprise red
build. Every upgrade must still be *derived* — the two-axis model has to
produce the new number (an axis correction or a declared override), so a
severity never moves on judgment alone.

### Coverage gaps are not findings

When compose-lint cannot see part of a stack, it does not guess. It reports a
**coverage gap**: a stderr `Error:` line, a JSON `errors[]` entry of kind
`coverage_gap`, a SARIF `toolExecutionNotifications` record with
`executionSuccessful: false`, and **exit 2**. That is deliberate: reporting 0
findings on a file whose real configuration was never read would be a false
pass. A reference that *does* resolve inside the project is followed and
merged, so it is not a gap
([ADR-036](adr/036-resolve-references-that-stay-inside-the-project.md)).

This is the complete list of what raises one. Other pages link here rather
than keep a list of their own. "Out of reach" means a symlink whose target is
outside both the project directory and the directory compose-lint was run
from.

- **An `include:` or cross-file `extends: {file: ...}` target that cannot be
  followed**, because its path:
  - is written out of the project directory, with `..` or as an absolute path;
  - is a symlink out of reach;
  - is interpolated (`${...}`) and has no shipped value;
  - names a file that is missing, is not valid UTF-8, or fails the bounded
    read (too large, or not a regular file);
  - leads back to a file the chain already pulled in (a cycle);
  - is more than 8 files deep, or would take one document past 64 opened
    files.
- **An included file that is not a Compose document compose-lint can read**:
  a Compose v1 file, a compose-lint config, or YAML that does not parse. A
  fragment declaring only `volumes:`, `networks:`, `configs:`, `secrets:` or
  `x-*` keys is merged, not a gap.
- **An `include:` entry whose `project_directory:` cannot be placed**:
  written with `..` out of the project, absolute, interpolated, or a directory
  symlink out of reach. Every file in the entry is reported.
- **An `extends:` whose base cannot be found**: a cross-file one with no
  `service:`, or whose file declares no such service; an in-file one naming a
  service the file does not declare, or forming a cycle. Compose refuses all
  of these.
- **A `.env` Compose reads that compose-lint could not**: the project's, or
  an included file's own, that exists but is not valid UTF-8, is larger than
  the 256 KiB read cap, or is a symlink out of reach.
- **A refused `COMPOSE_FILE` list**: one entry that is absolute, climbs out of
  the project directory, is a symlink out of reach, or is missing refuses the
  whole list.
- **A Compose file or `compose.override.yml` that is a symlink out of
  reach**, whether it was discovered or named on the command line.
- **A document that reaches the 20,000-findings limit**: grading stops there.
  The findings graded before the stop are still reported.
- **A document whose interpolation would add more than 8 MiB**: past that,
  a `${VAR}` value is left as written, so a rule grades the spelling rather
  than the value Compose deploys.
- **A `!reset` or `!override` tag that could not be applied**: a document
  that repeats one aliased mapping across hundreds of thousands of paths
  exhausts the line budget, and a tagged mapping reached again after that
  keeps its tags only where they were already recorded.

Because a gap is not a finding, `--fail-on` does not gate it. It exits 2 at
every threshold, `--fail-on critical` included. The flag that clears one is
`--allow-partial-coverage`, which downgrades the gap to a stderr warning and a
`warnings[]` entry. It is run-level, so it accepts every gap in that run, not
a chosen one. It cannot produce a verdict from nothing: when every file the
run selected was refused, nothing is left to grade, and the run still exits 2.
An `include:`-only file whose references all fail is a parse error rather
than a gap, and it exits 2 as well.

`fix` reports gaps without failing on them, so it does not take the flag. The
exception is the findings limit. A partial set of findings cannot be fixed
safely, so `fix` writes nothing to that file and exits 2, and `init` writes no
baseline and exits 2.

That makes the two hatches above insufficient for a release that **adds** a gap
condition: a pinned user is fine, but a threshold-gated one goes red on a
document the tool never called insecure. So, post-1.0:

- **Adding an exit-2 coverage-gap condition is a MINOR with a one-release
  runway.** The release before it announces the condition and emits it as a
  stderr warning plus a machine-readable note; the next release enforces it as
  exit 2. Same shape as a severity upgrade
  ([ADR-031](adr/031-severity-upgrades-are-minor-with-runway.md)).
- **Retiring one is a plain MINOR**, no runway — it can only turn a red build
  green. It is not a PATCH, because a reference that is now resolved can
  surface findings that were previously invisible, and that is the
  new-findings class above.

Neither is a change to the exit-code contract: `0` / `1` / `2` keep their
meanings and no code is added. The reasoning is recorded in
[ADR-036](adr/036-resolve-references-that-stay-inside-the-project.md), which
also decided that a reference resolving inside the project directory should be
read rather than refused.

### YAML Compose accepts that compose-lint refuses

Three YAML shapes Compose deploys are refused as invalid YAML with exit 2: a
tab before a comment, a multi-document file, and a bare `=` value (listed in
[What a run reads](what-a-run-reads.md#yaml-that-compose-accepts-and-compose-lint-refuses)).
They are known parser limitations, not a contract: each fails closed and
never passes a file unread. Lifting one is a MINOR, for the same reason as
retiring a gap: it can only turn exit 2 into a verdict, but that verdict can
carry findings that were invisible before, which is the new-findings class
above.

### Resource limits

A few limits keep a crafted file from costing gigabytes. They are part of the
contract, so the bump rules match coverage gaps: lowering a limit, or adding a
refusal, is a MINOR announced one release ahead, the same runway as a new gap
condition; raising one is a plain MINOR, because the extra input graded can
carry findings. Today's values, and what reaching each does:

| Limit | Value | Reaching it |
| --- | --- | --- |
| Compose file size | 8 MiB | exit 2, `parse` (an included or extended file: a coverage gap) |
| Services in one document, after `include:` | 4,096 | exit 2, `parse` |
| Key/value pairs `<<:` merge keys copy | 65,536 | exit 2, `parse` |
| `include:` / `extends: {file:}` depth, and files one document opens | 8 deep, 64 files | coverage gap |
| `.env` size | 256 KiB | coverage gap |
| Findings in one document | 20,000 | coverage gap; the findings graded before it are reported |
| Text interpolation adds to one document | 8 MiB | coverage gap |
| Repeated line records in one load | 262,144 | a `!reset`/`!override` not applied is a coverage gap; a lost line is not |
| `env_file:` target size | 256 KiB | `unread_input` warning |
| One interpolated value | 128 KiB | left as written ([ADR-026](adr/026-read-the-sibling-env-file.md) §3) |
| One scalar a rule scans | 8 KiB | not scanned ([ADR-026](adr/026-read-the-sibling-env-file.md) §3) |
| SARIF results | 5,000 | the most severe are kept, with a warning notification; the exit code counts every finding |

The environment variables the CLI reads follow the flag rows: adding one is a
MINOR, and removing one or changing what it means is a MAJOR.

### Alert identity

SARIF results carry `partialFingerprints`, which is what GitHub Code Scanning
uses to decide whether an alert it already has is *this* alert. The digest is
derived from a finding's `evidence` — the specific construct that tripped the
rule ([ADR-024](adr/024-finding-identity-is-not-prose.md)) — deliberately, so
that rewording a message never re-keys an alert and cosmetic edits to a Compose
file never split one.

The consequence is worth stating plainly, because nothing in the output makes
it visible: **changing how a rule derives its evidence changes that rule's alert
identities.** Every existing alert closes as "fixed" and the same findings
reopen as new. No field is renamed and no shape moves, so a consumer parsing
JSON or SARIF sees nothing unusual — the churn appears only in the alert list.

That is a **MINOR**, announced under `Changed` in `CHANGELOG.md`. A pinned user
is untouched; an unpinned one sees the churn once and, because it was
announced, knows why. `tests/test_finding_identity.py` pins each rule's
derivation so the change has to be deliberate rather than a side effect of
tidying a predicate.

## Deprecation lifecycle

Nothing stable is removed without warning. When a flag, config key, output
field, rule, or supported Python version is slated for removal:

1. **Announce** — mark it deprecated under `Deprecated` in `CHANGELOG.md` and in
   the relevant doc, in the release that introduces the deprecation.
2. **Warn at runtime** — where the deprecated surface is user-invoked (a flag, a
   config key, the interpreter the tool is running on), emit a one-line
   `Warning:` to **stderr** when it is used, naming the replacement. Warnings
   never change exit codes or stdout.
3. **Grace period** — the deprecated surface keeps working for **at least one
   MINOR release** after the announcement.
4. **Remove** — removal happens only in a **MAJOR** release, listed under
   `Removed` in `CHANGELOG.md`. Two carve-outs, both gated on calendar or
   evidence rather than discretion: a *scheduled* Python interpreter drop
   ([ADR-029](adr/029-scheduled-python-drops-are-minor.md)) and an
   evidence-refuted rule retirement
   ([ADR-032](adr/032-rule-retirement-is-minor-with-lifecycle.md)) ship as
   MINOR.

Two things are never reused or quietly repurposed:

- **Rule IDs** — `CL-XXXX` IDs are permanent; a retired rule's ID is never
  reassigned ([ADR-005](adr/005-rule-id-scheme.md)). Retiring a rule is a
  MINOR, but only through the full deprecation lifecycle and only on
  evidence that refutes the rule's premise
  ([ADR-032](adr/032-rule-retirement-is-minor-with-lifecycle.md)) — never
  on noise or preference. One narrow exception: a rule that
  [ADR-028](adr/028-pre-1.0-rule-id-sweep.md) records as admitted on
  *judgment* rather than on the grounding bar may be withdrawn on judgment,
  through the same lifecycle and with its own ADR. That set was closed at
  the 1.0 sweep and is currently `{CL-0014}`; every rule admitted on
  evidence still needs refutation. A config referencing a retired ID still loads:
  the override simply has no rule to apply. It is reported the same way a
  typo'd ID is — `Warning: config: unknown rule id 'CL-XXXX'` — which
  `--strict-config` promotes to an error, so a strict CI pipeline does
  fail on one. Distinguishing "retired" from "mistyped" needs the retired
  set to be known to the tool rather than only to its tests; until it is,
  drop the stale entry or stop passing `--strict-config`.
- **Exit-code meanings** — `0` / `1` / `2` keep their meanings; adding a new
  non-zero code is a MAJOR change. Adding or retiring a *condition* under the
  existing exit 2 is not — see [Coverage gaps are not
  findings](#coverage-gaps-are-not-findings).

## Changing this policy

This policy is itself part of the 1.0 surface: users choose version ranges
based on what it promises, so the promise cannot be quietly rewritten by a
"docs-only" release. Amendments require an ADR
([ADR-030](adr/030-the-policy-is-part-of-the-contract.md)), and the bump an
amendment requires depends on its direction:

- **Clarifications** — same obligations, better words — may ship in any
  release.
- **Tightenings** — promising more than before — are a MINOR.
- **Loosenings** — promising less than before — are a **MAJOR**, and are
  never retroactive: a change already shipped is judged under the policy in
  force when it shipped.

## Operating systems

Linux is the fully gated platform: every PR runs the complete suite there
across all supported Python versions. macOS and Windows are exercised by a
separate smoke workflow (pytest plus the pre-commit hook, currently at one
Python version) that runs on every merge and weekly, but does not yet gate
merges. Bind-source resolution is deploy-host-independent
([ADR-023](adr/023-deploy-host-independent-claims.md)): findings are facts
about the document, not the linting machine, so the climb-to-root
detections fire on every platform, and `~` bind sources are claimed by
their spelling — the deploying user's home, whoever that is — identically
everywhere. The GitHub Action and the Docker image are Linux by
construction.

## Python versions

Supported CPython versions track upstream: a version is added to the matrix
within ~3 months of its October release (additive), and dropped at upstream
end-of-life. A *scheduled* drop — announced and warning at runtime for at
least 180 days and one MINOR release, shipping no earlier than the upstream
EOL date — is a **MINOR** change, post-1.0 included
([ADR-029](adr/029-scheduled-python-drops-are-minor.md)): the date is
published by CPython years ahead, and the change cannot break a pinned or
even an unpinned environment (see below). An *unscheduled* drop remains
MAJOR post-1.0. The authoritative list is `requires-python` in
`pyproject.toml`; see the [roadmap](ROADMAP.md#python-version-support) for
the schedule.

A drop follows the [deprecation lifecycle](#deprecation-lifecycle) above: the
release that announces it warns on stderr when run on that interpreter, and the
drop lands no earlier than the next MINOR. The warning matters more here than
for a flag, because the removal itself is silent — `requires-python` does not
fail an install on an unsupported interpreter, it makes pip resolve to the last
release that allowed it. Without the warning, `pip install -U compose-lint`
leaves that user on a frozen version indefinitely, with nothing printed in
either direction.
