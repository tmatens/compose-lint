# Governance

compose-lint is intentionally small and single-maintainer. This document
describes how decisions get made and who is accountable for what — so a
new contributor can predict how their PR will be evaluated, and a future
successor can pick up the project without rediscovering the conventions
from `git log`.

For continuity-of-access (what happens if the current maintainer is
unavailable), see [docs/CONTINUITY.md](docs/CONTINUITY.md).

## Roles

There is one role: **maintainer.** The current maintainer is listed in
[MAINTAINERS.md](MAINTAINERS.md). The maintainer:

- Reviews and merges pull requests.
- Triages issues within 14 days (per CONTRIBUTING.md).
- Responds to security reports within 7 days (per [.github/SECURITY.md](.github/SECURITY.md)).
- Cuts releases per [docs/RELEASING.md](docs/RELEASING.md).
- Holds the credentials needed to publish (PyPI Trusted Publisher,
  Docker Hub, GitHub Releases). These are documented in
  [docs/CONTINUITY.md](docs/CONTINUITY.md).

There is no separate "committer," "reviewer," or "TSC" role. The bus
factor is 1; we are honest about that. See
[docs/CONTINUITY.md](docs/CONTINUITY.md) for the mitigations.

Every code change — including changes by the maintainer — goes through
a pull request. There are no direct pushes to `main`, including from
the maintainer's account. Branch protection enforces this.

## Decision-making

Decisions are made by **lazy consensus**: a proposal goes up as an issue
or PR; if no maintainer-level objection is raised within a reasonable
window, it lands. Reasonable means roughly:

- **PRs against an existing rule, doc, or fix** — merge-ready when CI
  passes and a maintainer has reviewed. No waiting period.
- **New rule** — discussion in the linked issue first (use the "Rule
  proposal" template). The bar is authoritative grounding (OWASP
  Docker Security Cheat Sheet, CIS Docker Benchmark, or Docker
  official documentation) and an actionable fix. See
  [CONTRIBUTING.md](CONTRIBUTING.md) §"Rule requirements".
- **New runtime dependency, new CLI flag, severity change to an
  existing rule, change to the public output schema, or anything that
  would force a MAJOR bump under [docs/RELEASING.md](docs/RELEASING.md)
  semantics** — open an issue first. The maintainer's call. If the
  decision is non-obvious, it is documented as an ADR under
  [docs/adr/](docs/adr/) so the rationale survives the decision.

The maintainer may exercise a veto on any change that conflicts with
the project's stated scope (see "Scope" in
[AGENTS.md](AGENTS.md) and "What it catches" in
[README.md](README.md)). Vetoes are explained in writing on the PR or
issue thread.

## Escalation

If you disagree with a decision the maintainer made:

1. Reopen the discussion on the original issue or PR with the
   additional context or evidence you have.
2. If the disagreement persists, open a new issue tagged
   `governance:appeal` summarizing both positions.
3. Because there is currently no second maintainer to break a tie, the
   final call rests with the listed maintainer. The MIT license is the
   structural escape hatch: anyone is free to fork.

When a second maintainer is added (see "Adding a maintainer" below),
this escalation path will become a vote.

## Adding a maintainer

The project would benefit from raising the bus factor to >=2. A
contributor becomes a candidate after demonstrating sustained
high-quality contributions — typically:

- Multiple merged PRs across rules, parser/engine, and CI/release.
- Reviewed at least one new-rule PR end to end.
- Familiar with [docs/RELEASING.md](docs/RELEASING.md) and the supply-
  chain conventions in [AGENTS.md](AGENTS.md).
- Willing to share the on-call load for security reports (7-day SLA)
  and the release ceremony.

Promotion is a maintainer decision documented in a PR that updates
[MAINTAINERS.md](MAINTAINERS.md). The new maintainer is granted GitHub
admin on the repo, added to the PyPI Trusted Publisher environment
allowlist, and added as a Docker Hub repo administrator. The
[docs/CONTINUITY.md](docs/CONTINUITY.md) checklist tracks the exact
access grants.

## Removing a maintainer

A maintainer who steps down opens a PR removing themselves from
[MAINTAINERS.md](MAINTAINERS.md). A maintainer who becomes
non-responsive for >90 days may be removed by another maintainer in a
PR that documents the attempted contacts.

## Code of conduct

All participants agree to the [Contributor Covenant 2.1](.github/CODE_OF_CONDUCT.md).
Enforcement actions (warnings, removal of contributions, bans) are the
maintainer's call; the same lazy-consensus and escalation paths apply.

## Changes to this document

Governance changes go through a PR like any other change. Substantive
changes — adding/removing roles, changing the decision rule, changing
the appeal path — should be tagged `governance` and held open for at
least 7 days to give other contributors time to comment.
