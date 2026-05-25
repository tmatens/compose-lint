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

- **Pin the version** (`compose-lint==1.2.0`, or the digest-pinned Action /
  image) for identical results across runs.
- **Use `--fail-on`** to gate CI on a severity threshold, so new lower-severity
  findings surface without failing the build.

A rule's **severity** is part of the contract: post-1.0, *downgrading* a
severity is a MINOR, but *upgrading* one (which can newly fail a pinned user's
CI) is a MAJOR.

## Deprecation lifecycle

Nothing stable is removed without warning. When a flag, config key, output
field, or rule is slated for removal:

1. **Announce** — mark it deprecated under `Deprecated` in `CHANGELOG.md` and in
   the relevant doc, in the release that introduces the deprecation.
2. **Warn at runtime** — where the deprecated surface is user-invoked (a flag, a
   config key), emit a one-line `warning:` to **stderr** when it is used, naming
   the replacement. Warnings never change exit codes or stdout.
3. **Grace period** — the deprecated surface keeps working for **at least one
   MINOR release** after the announcement.
4. **Remove** — removal happens only in a **MAJOR** release, listed under
   `Removed` in `CHANGELOG.md`.

Two things are never reused or quietly repurposed:

- **Rule IDs** — `CL-XXXX` IDs are permanent; a retired rule's ID is never
  reassigned ([ADR-005](adr/005-rule-id-scheme.md)). Retiring a rule is a MAJOR
  change.
- **Exit-code meanings** — `0` / `1` / `2` keep their meanings; adding a new
  non-zero code is a MAJOR change.

## Python versions

Supported CPython versions track upstream: a version is added to the matrix
within ~3 months of its October release (additive), and dropped at upstream
end-of-life. Dropping a version is a MAJOR change post-1.0. The authoritative
list is `requires-python` in `pyproject.toml`; see the
[roadmap](ROADMAP.md#python-version-support) for the schedule.
