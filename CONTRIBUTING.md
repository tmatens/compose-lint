# Contributing to compose-lint

Thanks for wanting to help. This is a small, focused project, so the bar for
contributions is clarity and authoritative grounding rather than breadth.

## This project is unpaid

compose-lint is volunteer-maintained. There is no budget, no bounty program,
and nobody is paid to work on it — the maintainer included. Contributions are
donated under the project's MIT license and the
[DCO](#developer-certificate-of-origin).

So offers to implement an issue for a fee are declined, and issues labelled
`good first issue` or `help wanted` are invitations to contribute, not work
put out for quote. Wanting to be paid for open-source work is an entirely
reasonable thing to want — it just isn't something this project can offer.

## Before you start

- **Bug reports and feature requests**: open an issue using one of the templates.
- **Security vulnerabilities**: do *not* open a public issue. See [SECURITY.md](.github/SECURITY.md).
- **New rule proposals**: use the "Rule proposal" issue template. Every rule must
  be grounded in an authoritative source (OWASP Docker Security Cheat Sheet, CIS
  Docker Benchmark, or Docker official documentation). Opinion-only rules are
  not accepted.
- **Larger changes**: open an issue to discuss first so you don't sink time into
  a change that doesn't fit the project's scope.

See [AGENTS.md](AGENTS.md) for the full design philosophy — especially the
sections on rule grounding, severity assignment, and what's explicitly out of
scope.

## Maintainers

- Todd Matens ([@tmatens](https://github.com/tmatens)) — repository admin,
  releases, security response.

Maintainers review and merge PRs, triage issues within 14 days, respond to
security reports within 7 days per [SECURITY.md](.github/SECURITY.md), and cut
releases per [docs/RELEASING.md](docs/RELEASING.md).

## Development setup

```bash
git clone https://github.com/tmatens/compose-lint.git
cd compose-lint
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
git config core.hooksPath .githooks
```

The last command activates the repo's git hooks. The `pre-push` hook blocks unsigned commits — see [commit signing](#commit-signing) for setup.

## Local quality checks

All four must pass locally before you push. CI runs the same commands.

```bash
ruff check src/ tests/          # Linting
ruff format --check src/ tests/ # Formatting
mypy src/                       # Type checking (strict mode)
pytest                          # Tests
```

Statement coverage must stay >= 80% on `main`. The CI `coverage` job
enforces this; check locally before pushing a change that touches a lot
of code:

```bash
pytest --cov=compose_lint --cov-report=term-missing --cov-fail-under=80
```

On hosts where `/tmp` is mounted `noexec` (hardened containers), point
pytest's temp directory somewhere executable first — the action-contract
tests run shim executables from it and will skip otherwise:

```bash
TMPDIR=$HOME/.pytest-tmp pytest --basetemp=$HOME/.pytest-tmp/bt
```

## Code standards

- **Python 3.10+** required. Don't use syntax or stdlib features added after
  3.10 (e.g., no `type` aliases from 3.12, no `ExceptionGroup` from 3.11
  without checking availability).
- **Type annotations** on all public functions (`mypy --strict` is enforced).
- **PyYAML is the only runtime dependency.** Do not add others without
  discussion. Dev tooling goes in the `[dev]` extras.
- **Rules receive plain Python types** (`dict`, `list`, `str`, `int`, `bool`).
  Never leak parser-specific types into rule code.
- **Latest stable versions** for any new dependency unless there's a specific,
  documented reason otherwise.

## Adding a new rule

1. Create `src/compose_lint/rules/CL{NNNN}_{snake_name}.py`
2. Inherit from `BaseRule`, use the `@register_rule` decorator
3. Set `id`, `name`, `severity`, `description`, `references` — references must
   cite OWASP, CIS, or Docker official docs
4. Implement `check(service_name, service_config, global_config, lines)`
   yielding `Finding` objects
5. Add test file `tests/test_CL{NNNN}.py` with **both** positive (triggers) and
   negative (clean) cases. Negative cases must include at least one
   *hardened-but-unusual* configuration the rule must not flag (e.g. the
   short-form security_opt, CMD-SHELL healthcheck, named-volume mount,
   digest-pinned image without a tag — whichever pattern is adjacent to the
   rule's trigger and easy to misread). These can live in the rule's mixed
   fixture or in a dedicated `tests/compose_files/safe_*.yml`.
6. Add fixture YAML files in `tests/compose_files/`
7. Add rule documentation in `docs/rules/CL-{NNNN}.md`
8. Fix guidance must be specific and actionable — show the exact YAML change
9. Include a direct link to the supporting OWASP/CIS/Docker docs section
10. If the rule describes container *runtime* state, add a premise check to
    `scripts/validate_rule_premises.py` proving the insecure state is Docker's
    default (absence rules) or that the flagged config produces the insecure
    behavior (presence rules). It runs in CI (`rule-premises`) and guards
    against flagging a Docker default — the CL-0022/CL-0023 failure mode
11. **Derive the severity, don't pick it.** Work through the procedure in
    [docs/severity.md](docs/severity.md) and write the derivation block on the
    rule page — baseline, precondition, impact, qualifier, derived, shipped,
    scoping assumptions, and an **Evidence** line naming the premise check or
    captured observation that backs the impact claim. Write the fields before
    looking at the number you wanted; if the result disagrees with instinct,
    fix an axis definition or file an override, never try a different cell
12. **Add the row to `docs/severity.md`'s assignment table.** The page and the
    table must state the same derivation — `tests/test_severity_matrix.py`
    fails if they drift, if the cell does not produce the printed severity, or
    if a shipped severity differs from the derived one without a declared
    override and a link
13. **List the rule on every surface**: the README table, `docs/index.md`, and
    the mkdocs nav. `tests/test_rule_surfaces.py` checks all of them
14. **Map it to ATT&CK** in `src/compose_lint/attack.py`, or record why no
    technique fits — an unmapped rule needs an entry in the test's
    `UNMAPPED_BY_DESIGN` allow-list with its reason

### Rule requirements

- **Grounded in an authoritative source that demonstrates the need in a
  container context** (CIS Docker, OWASP Docker Cheat Sheet, Docker docs) — not
  generic host/Linux hardening a container's defaults already neutralize. If
  container-context grounding is thin, validate the premise at runtime
  (`scripts/validate_rule_premises.py`). No opinion-only rules.
- **Every finding must be actionable.** If you can't tell the user exactly what
  to change, the finding isn't ready.
- **Severity is derived, not chosen.** It is the value the two-axis matrix
  produces for the rule's cell, under a stated attacker baseline and the
  grounded Docker posture. Shipping a different number is legal only as a
  declared override from the closed reason list, with a link. See
  [docs/severity.md](docs/severity.md) — and note that "I evaluated cells until
  one gave the number I expected" is the documented failure mode the model
  exists to prevent.
- **Rule IDs are permanent from 1.0.** Never reuse or retire a `CL-XXXX` ID once
  1.0 ships; pre-1.0, a mis-grounded rule may be removed and its ID reclaimed.

## Commit conventions

- **One logical change per commit.** Rules, features, and refactors each get
  their own commit. Don't bundle unrelated changes.
- **Imperative subject line, under 72 characters.** "Add CL-0011 rule for X",
  not "Added CL-0011" or "CL-0011".
- **Explain the *why* in the body, not just the *what*.** The diff already
  shows what changed; the commit message exists to explain the reason.
- **Sign your commits.** See [commit signing](#commit-signing) below.
- **Sign off your commits.** Use `git commit -s` to add the
  `Signed-off-by:` trailer required by the
  [DCO](#developer-certificate-of-origin) — this is separate from
  cryptographic signing.
- **No AI credit lines in commit messages.** Do not include `Co-Authored-By`
  trailers naming an assistant, or "generated by" notices. The commit history
  is permanent and a credit line there says an assistant authored the work,
  which is not what the record is for. Enforced by the `No AI authorship
  attribution` CI check, which scans only commit messages.

  This is about *credit*, not *provenance*. If an automated agent produced the
  change, say so in the PR's Origin section instead. That disclosure is
  welcome, it does not affect whether the PR is accepted, and it belongs in the
  PR rather than in `git log`.

We do *not* use [Conventional Commits](https://www.conventionalcommits.org/)
prefixes (`feat:`, `fix:`, etc.). Descriptive imperative subjects are preferred
because they read naturally in `git log` without tooling.

### Commit signing

All commits to `main` must be signed so GitHub shows the "Verified" badge.
Unsigned commits can be spoofed — anyone can set `user.email` to yours and
open a PR from a fork that attributes to you.

SSH signing is the easiest setup because it uses the same key you already
push with:

```bash
git config --global gpg.format ssh
git config --global user.signingkey "key::$(cat ~/.ssh/id_ed25519.pub)"
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

Then add the *same* public key to GitHub as a **Signing Key** (separate list
from authentication keys) at <https://github.com/settings/ssh/new>.

Verify locally with `git log --show-signature`. If it prints
`Good "git" signature`, you're set. On GitHub, your commits will show a green
**Verified** badge.

### Developer Certificate of Origin

All commits must carry a `Signed-off-by:` trailer certifying that you wrote
the change (or have the right to submit it under this project's MIT license).
This is the [Developer Certificate of Origin](https://developercertificate.org).
It is independent of [commit signing](#commit-signing) above: cryptographic
signing proves *who committed*, DCO asserts *right to contribute*.

Add the trailer automatically with `-s`:

```bash
git commit -s -m "Your change"
```

Or enable it once per-clone so every commit gets signed off:

```bash
git config format.signOff true
```

The `Signed-off-by` name and email must match your commit author identity. CI
will block the PR if any commit is missing a matching trailer. Fix existing
commits with `git commit --amend --signoff` or `git rebase --signoff main`.

## Pull requests

All changes to `main` go through a PR — including maintainer changes.

**External contributors:** you won't have push access to this repository.
[Fork it](https://github.com/tmatens/compose-lint/fork), create your branch on
the fork, and open the PR from that branch back to `main` here. Everything
below applies the same way; the DCO and commit-signing checks run on fork PRs
too, so set those up before your first commit.

1. **Create a branch** from `main`. Name it descriptively:
   `docs/contributor-workflow`, `rules/CL-0011-user-namespaces`,
   `fix/parser-merge-keys`.
2. **Make small, focused commits** (see [commit conventions](#commit-conventions)).
3. **Run local checks.** All four must pass before you push.
4. **Open a PR** and fill out the template. Link any related issue.
5. **Wait for CI** — all required checks must be green before merge.
6. **Respond to review comments.** All comments must be resolved before merge.
7. **Squash-merge** when approved. We use squash-merge exclusively so `main`
   stays linear with one commit per logical change. The full PR history is
   preserved on the PR page for context.

### PR expectations

- **Keep PRs small.** Easier to review, easier to revert, easier to bisect.
  A PR that touches 5 files is almost always better than one that touches 30.
- **Don't mix refactors with behavior changes.** Land the refactor first, then
  the behavior change, in separate PRs.
- **Update tests.** New rules need positive and negative tests. Bug fixes need
  a regression test.
- **Update documentation** if you change behavior. Rule changes need
  `docs/rules/CL-XXXX.md`; CLI changes need `README.md`; version-visible
  changes need a CHANGELOG entry.
- **Do not regenerate the corpus snapshot.** If your change touches rule
  predicates, severity, or finding line attribution, say so in the PR and leave
  `tests/corpus_snapshot.json.gz` alone. A maintainer regenerates it and
  reviews the diff. The snapshot is what proves a change did not silently alter
  rule output, so a regenerated blob arriving in the same PR as the change it
  is meant to check cannot serve that purpose. Running the corpus locally to
  see your own impact is encouraged (see "Corpus snapshot" below); just don't
  commit the result.

## Corpus snapshot

`tests/corpus_snapshot.json.gz` locks compose-lint's output across a corpus
of real-world Compose files so unintended rule drift is visible in PR diffs.

- Generate a corpus locally with the helper scripts at
  `~/.cache/compose-lint-corpus/scripts/` (out of tree by design — see
  `LICENSE-corpus.md`). Set `COMPOSE_LINT_BIN` to your in-repo binary.
- **Maintainers** regenerate it after a rule change, via
  `python scripts/snapshot.py generate`, and commit the updated
  `tests/corpus_snapshot.json.gz` separately from the change it checks.
- **Contributors**: run `python scripts/snapshot.py verify` to see your own
  impact and report it in the PR, but leave the committed snapshot alone. A
  blob regenerated in the same PR as the change it is meant to check cannot
  evidence that nothing drifted.
- The schema test (`tests/test_corpus_snapshot_schema.py`) runs in CI on
  every PR and rejects schema changes that would carry third-party content
  into the snapshot. Don't widen the schema beyond rule_id, service, and
  line without revisiting `LICENSE-corpus.md`.
- Don't commit `index.jsonl` or any compose file from the corpus —
  those are third-party content and live only in your local cache.

## Reporting bugs

Use the bug report issue template. Include:

- The minimal Compose file that triggers the behavior
- What you expected to happen
- What actually happened (full command output)
- Your compose-lint version (`compose-lint --version`) and Python version

## Code of conduct

This project follows the [Contributor Covenant](.github/CODE_OF_CONDUCT.md). By
participating you agree to uphold it.
