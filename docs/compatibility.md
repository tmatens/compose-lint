# Compatibility and Stability Policy

compose-lint follows [Semantic Versioning](https://semver.org/). This page is
the user-facing promise: what stays stable across upgrades, what may change, and
how changes are signalled. The maintainer-facing bump-decision rules live in
[RELEASING.md](RELEASING.md#choosing-the-version-number); this policy is the
contract those rules implement.

## The 1.0 commitment

From `1.0.0` onward, the following are **stable** and change only under the
SemVer rules below:

- **CLI surface** — subcommands, flags, and their documented behavior.
- **Exit codes** — the `0` / `1` / `2` contract ([ADR-006](adr/006-exit-codes.md))
  and the default `--fail-on` threshold.
- **Config schema** — the `.compose-lint.yml` keys and their semantics
  ([ADR-010](adr/010-per-service-rule-overrides.md)).
- **Machine output** — the JSON envelope and the SARIF 2.1.0 log shapes
  ([ADR-015](adr/015-machine-readable-output-contract.md)).

## What is explicitly NOT covered

These may change in any release, including PATCH, without a major bump:

- **Human text output** — the exact wording, layout, colour, and ordering of
  `--format text`. It is for humans; parse JSON or SARIF if you need a stable
  shape. (The JSON `version` field exists precisely so you can.)
- **Internal Python API** — anything beyond `compose_lint.__version__` and the
  documented CLI. compose-lint is a CLI / GitHub Action, not an importable
  library; rule classes, the engine, parser, and formatters are implementation
  details.

## New findings are not a breaking change

This is the most important expectation for CI users. compose-lint **adds and
tightens rules in MINOR releases** — the same convention as Hadolint,
ShellCheck, and ruff. A file that is clean on `1.2.0` may report new findings on
`1.3.0`. That is intentional, not a contract break.

Two escape hatches keep a pipeline deterministic:

- **Pin the version** (`==1.2.0` in this example, or the digest-pinned Action /
  image) for identical results across runs.
- **Use `--fail-on`** to gate CI on a severity threshold, so new lower-severity
  findings surface without failing the build.

A rule's **severity** is part of the contract: post-1.0, *downgrading* a
severity is a MINOR, and *upgrading* one is a **MINOR with a one-release
runway** ([ADR-031](adr/031-severity-upgrades-are-minor-with-runway.md)): the
release before the move announces it under `Changed`, and the next MINOR
applies it. A pinned user is untouched either way; a threshold-gated
`--fail-on` user gets a full release of warning instead of a surprise red
build. Every upgrade must still be *derived* — the two-axis model has to
produce the new number (an axis correction or a declared override), so a
severity never moves on judgment alone.

## Deprecation lifecycle

Nothing stable is removed without warning. When a flag, config key, output
field, rule, or supported Python version is slated for removal:

1. **Announce** — mark it deprecated under `Deprecated` in `CHANGELOG.md` and in
   the relevant doc, in the release that introduces the deprecation.
2. **Warn at runtime** — where the deprecated surface is user-invoked (a flag, a
   config key, the interpreter the tool is running on), emit a one-line
   `warning:` to **stderr** when it is used, naming the replacement. Warnings
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
  on noise or preference. A config referencing a retired ID keeps working,
  `--strict-config` included.
- **Exit-code meanings** — `0` / `1` / `2` keep their meanings; adding a new
  non-zero code is a MAJOR change.

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
