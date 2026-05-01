# Release checklist

Maintainer-only. This is the step-by-step for cutting a new release of
compose-lint. Contributors don't need to read this; see
[CONTRIBUTING.md](../CONTRIBUTING.md) instead.

The release pipeline is **tag-triggered**: pushing an annotated, signed
`vX.Y.Z` tag to `main` kicks off `.github/workflows/publish.yml`, which
builds, publishes to TestPyPI and runs smoke tests for all channels, then
waits for a single manual approval on the `release` environment before
publishing to all production channels in parallel. Sigstore build
attestations are generated automatically.

## What's automated vs. manual

Most of this checklist is now wired into CI. At a glance:

| Step                                   | Where it runs                                      |
| -------------------------------------- | -------------------------------------------------- |
| Pre-release checks (ruff/mypy/pytest)  | `ci.yml` on every PR                               |
| Version strings in sync                | `ci.yml` → `version-consistency` job               |
| CHANGELOG section exists for bump      | `ci.yml` → `changelog-gate` job                    |
| Open the "Prepare X.Y.Z release" PR    | `release-prep.yml` (`workflow_dispatch`)           |
| Create signed tag and push             | **Manual** (your workstation)                      |
| Build, sign, TestPyPI, smoke tests     | `publish.yml`                                      |
| Release-gate approval                  | **Manual** (GitHub Environment `release`)          |
| PyPI + Docker Hub publish              | `publish.yml`                                      |
| GitHub Release created from CHANGELOG  | `publish.yml` → `create-release` job               |
| Marketplace-smoke pin bump PR          | `publish.yml` → `bump-marketplace-smoke-pin` job   |
| Merge pin bump PR, re-run smoke        | **Manual**                                         |

Tag creation stays manual on purpose. Tags created by `GITHUB_TOKEN`
don't trigger downstream workflows (see "If something goes wrong"), and
the SSH-signed tag is the root of the Sigstore provenance chain for the
built artifact. Release-gate approval stays manual because it's the
human-in-the-loop safety between TestPyPI smoke passing and real PyPI /
Docker Hub publishing.

Everything below is the manual checklist for the steps that are not
automated. If you invoke `Release prep` from the Actions tab, it does
the "Bump the version", "Update the changelog", and "Commit the bump"
sections for you — your job is to review the resulting PR.

## Choosing the version number

compose-lint follows [Semantic Versioning](https://semver.org/), with one
project-specific rule about new rules (see below). Pick the bump before
you touch `pyproject.toml`; "what kind of release is this" is the first
question to answer.

### Pre-1.0 (current)

While the major version is `0`, the guarantees are weaker and the MINOR
slot does the work that MAJOR does post-1.0.

- **PATCH** (`0.2.0 → 0.2.1`) — safe changes only. Bug fixes,
  false-positive fixes, parser fixes, docs, internal refactors,
  dependency digest bumps. A Compose file that passed on `0.2.0` must
  still pass on `0.2.1`, and existing findings must not change their
  rule ID, severity, or message shape.
- **MINOR** (`0.2.0 → 0.3.0`) — everything else. New rules, new CLI
  flags, new formatters, new config keys, severity upgrades, severity
  downgrades, tightening an existing rule's logic, restructuring
  JSON/SARIF output. If a user's CI could newly fail or newly pass
  because of this release, it's a MINOR. Call the behavior change out
  in `CHANGELOG.md` under `Changed` so pinned users know what to
  expect on upgrade.
- **MAJOR** (`0.x → 1.0.0`) — reserved. Cutting `1.0.0` is the
  stabilization commitment: from that point on, the CLI, exit-code
  contract, config schema, and JSON/SARIF output shape are stable
  under the post-1.0 rules below. Don't bump to `1.0.0` casually — do
  it when you're ready to stand behind those guarantees.

### Post-1.0 (future)

Once `1.0.0` ships, the contract tightens:

- **PATCH** (`1.2.3 → 1.2.4`) — bug fixes that don't change which
  findings are emitted for a given input. If the set of findings a
  user sees on an unchanged Compose file could change, it's not a
  patch.
- **MINOR** (`1.2.3 → 1.3.0`) — additive or backward-compatible
  changes. New rules, new CLI flags, new config keys, severity
  *downgrades*, new formatters, additive fields in JSON/SARIF output.
  **New rules are intentionally MINOR, not MAJOR**, following the
  Hadolint / ShellCheck / ruff convention. Users who need
  deterministic results across upgrades should pin the version; the
  `--fail-on` flag is the documented escape hatch for tolerating new
  findings without failing CI.
- **MAJOR** (`1.2.3 → 2.0.0`) — anything that breaks a pinned,
  working setup:
  - Removing or renaming a CLI flag, subcommand, or config key.
  - Removing or retiring a rule ID (note: rule IDs are never reused;
    see `AGENTS.md`).
  - Changing the exit-code contract (e.g., adding a new non-zero
    exit code, changing the default `--fail-on` threshold).
  - Severity *upgrades* on existing rules (`LOW → HIGH` can newly
    fail CI for pinned users).
  - Restructuring JSON/SARIF output in a way that removes or renames
    existing fields.
  - Dropping support for a Python version listed in `pyproject.toml`.

### Judgment-call cheat sheet

| Change                                       | Pre-1.0 | Post-1.0 |
| -------------------------------------------- | ------- | -------- |
| Fix false positive in an existing rule       | PATCH   | PATCH    |
| Fix a parser crash                           | PATCH   | PATCH    |
| Docs-only change                             | PATCH   | PATCH    |
| Add a new rule                               | MINOR   | MINOR    |
| Add a new CLI flag                           | MINOR   | MINOR    |
| Downgrade a rule's severity (HIGH → MEDIUM)  | MINOR   | MINOR    |
| Upgrade a rule's severity (LOW → HIGH)       | MINOR   | MAJOR    |
| Tighten an existing rule (new true positive) | MINOR   | MINOR    |
| Remove or rename a CLI flag                  | MINOR   | MAJOR    |
| Retire a rule ID                             | MINOR   | MAJOR    |
| Change the default `--fail-on` threshold     | MINOR   | MAJOR    |
| Drop a Python version                        | MINOR   | MAJOR    |

When in doubt pre-1.0, pick MINOR. When in doubt post-1.0, pick the
higher bump — MAJOR costs the maintainer some release ceremony, but a
too-low bump breaks users who trusted the version contract.

## Pre-release checks

All of these run on `main`, on a clean working tree, before you touch the
version number.

- [ ] `git status` is clean and you're on `main` (or the release branch
      that will merge to `main`).
- [ ] `git pull --ff-only` — up to date with origin.
- [ ] `ruff check src/ tests/`
- [ ] `ruff format --check src/ tests/`
- [ ] `mypy src/`
- [ ] `pytest`
- [ ] CI on `main` is green for the commit you're about to release.
- [ ] No open Renovate PRs you meant to merge first.
- [ ] `[Unreleased]` in `CHANGELOG.md` covers every user-facing PR
      merged since the last release tag. `release-prep.yml` only
      *renames* `[Unreleased]` → `[X.Y.Z]`; it does not author entries,
      so anything missing here ships with no changelog. Cross-check
      `gh pr list --state merged --search "merged:>$(git log -1 --format=%cI v$(grep -E '^version' pyproject.toml | head -1 | cut -d'"' -f2))"`
      against the bullets in `[Unreleased]` and backfill the gaps in a
      separate chore PR before dispatching `release-prep.yml`. (0.5.2
      tripped on this — four merged PRs had no changelog entries.)
- [ ] `.vex/compose-lint.openvex.json` is current: any new pip (or other
      stripped-component) CVE that a scanner now reports against the image
      is either covered by an existing `not_affected` statement with
      `vulnerable_code_not_present`, or added in a fresh statement after
      you've manually verified the vulnerable code path is absent from
      the runtime image. If the CVE **is** reachable, do not VEX it — fix
      it. Bump `version` and `timestamp` in the VEX doc when statements
      change.
- [ ] Product identifiers in the VEX doc keep using
      `repository_url=index.docker.io/composelint/compose-lint` (not
      `docker.io/...`). The `docker.io` alias is silently ignored by
      Scout, Trivy, and Grype for VEX matching. See ADR-012.

## Bump the version

compose-lint declares the version in **four** places that must stay
in sync. Missing any one of them is a release-blocker — check all
four before opening the bump PR.

- [ ] `pyproject.toml` — `version = "X.Y.Z"` under `[project]`
- [ ] `src/compose_lint/__init__.py` — `__version__ = "X.Y.Z"`
- [ ] `README.md` — version references in copy-paste integration
      snippets. All need bumping each release; otherwise users land
      on a stale version. Four forms exist:
      - `tmatens/compose-lint@<sha> # v0.X.Y` (GitHub Action snippet)
      - `rev: v0.X.Y` (pre-commit snippet)
      - `compose-lint==0.X.Y` (Forgejo Actions snippet — pip pin)
      - `composelint/compose-lint:0.X.Y` (hardened `docker run` snippet
        and the digest-lookup hint immediately below it)

      Verify all four with:
      `grep -nE 'v0\.[0-9]+\.[0-9]+|compose-lint==0\.[0-9]+\.[0-9]+|composelint/compose-lint:0\.[0-9]+\.[0-9]+' README.md`.
- [ ] `.github/workflows/marketplace-smoke.yml` — two
      `uses: tmatens/compose-lint@<sha> # vX.Y.Z` lines. Update both
      the full commit SHA and the trailing `# vX.Y.Z` comment. Get
      the new SHA with `git rev-parse vX.Y.Z^{commit}` **after** you
      push the signed tag in a later step, then open a follow-up PR
      to bump the pin.

Verify the first two match:

```bash
grep -E '^version' pyproject.toml
grep __version__ src/compose_lint/__init__.py
```

The `marketplace-smoke.yml` bump has to land *after* the release
tag exists, because the commit SHA only exists once the tag is
pushed. Treat it as a post-release step, not part of the bump PR —
see "Post-release" below.

## Update the changelog

- [ ] `CHANGELOG.md` — move items under `[Unreleased]` to a new
      `[X.Y.Z] - YYYY-MM-DD` section. Follow
      [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) structure
      (`Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`).
- [ ] Update the comparison link at the bottom of `CHANGELOG.md` if the
      file uses one.

## Commit the bump

Open a PR — even for the release bump. No direct pushes to `main`.

```bash
git checkout -b release/X.Y.Z
git add pyproject.toml src/compose_lint/__init__.py CHANGELOG.md
git commit -m "Prepare X.Y.Z release"
git push -u origin release/X.Y.Z
gh pr create --fill
```

- [ ] CI green on the PR.
- [ ] Squash-merge to `main`.
- [ ] `git checkout main && git pull --ff-only`.

## Tag and release

```bash
git pull --ff-only
git tag -s vX.Y.Z -m "compose-lint X.Y.Z"
git push origin vX.Y.Z
```

- [ ] The tag exists and triggered `Publish` in Actions.

## Watch smoke tests

After the tag push, `publish.yml` runs automatically:

1. Builds the wheel and publishes to TestPyPI.
2. Runs PyPI smoke tests (version check, clean/insecure fixtures) against
   the TestPyPI artifact.
3. Runs Docker smoke tests (version check, clean/insecure fixtures, SARIF)
   against a local image build.

No manual action needed here. Wait for all smoke jobs to go green.

- [ ] `testpypi-smoke` green — TestPyPI artifact is correct.
- [ ] `docker-smoke` green — Docker image builds and behaves correctly.

## Approve the release gate

Once all smoke tests pass, the `release-gate` job waits for approval.
One approval publishes all channels.

- [ ] Open the running workflow. The `release-gate` job will be pending
      approval from the `release` environment.
- [ ] Review the smoke test results, then approve.

After approval, `publish` and `docker-publish` run in parallel.

- [ ] <https://pypi.org/project/compose-lint/> shows the new version.
- [ ] The "Build provenance" section on the PyPI page shows the Sigstore
      attestation linked to this repo and the `publish.yml` workflow.
- [ ] Docker publish completes green (post-push cosign verify and version
      check run automatically).

## Post-release

- [ ] **GitHub Release** — created automatically by `publish.yml`'s
      `create-release` job (runs after both `publish` and
      `docker-publish` succeed). Notes come from the matching
      `## [X.Y.Z]` section in `CHANGELOG.md`. Wheels, sdist, and
      Sigstore bundles are attached as release assets.
- [ ] **Marketplace smoke test pin bump** — `publish.yml`'s
      `bump-marketplace-smoke-pin` job (runs after `create-release`)
      opens a follow-up PR with the new SHA in both
      `uses: tmatens/compose-lint@<sha> # vX.Y.Z` lines. Review and
      squash-merge, then trigger **Actions → Marketplace smoke test →
      Run workflow** to verify the published Action end-to-end.
- [ ] **Docker Hub overview (README) sync** — runs automatically in
      `publish.yml`'s `dockerhub-description` job after `docker-publish`,
      via the first-party composite action at
      `.github/actions/update-dockerhub-description` (which just forwards
      to `scripts/update-dockerhub-description.sh`). Requires
      `DOCKERHUB_TOKEN` to have **Read, Write, Delete** scope — Read &
      Write is not enough for the description PATCH endpoint. Verify
      `https://hub.docker.com/r/composelint/compose-lint` reflects the
      current README.
- [ ] **Fresh `[Unreleased]` section** — already inserted by
      `release-prep.yml` as part of the release bump PR. No follow-up
      PR needed.
- [ ] Announce in Discussions if the release has user-visible changes.

## If something goes wrong

- **One channel's smoke is broken but the other must ship**: use the
  manual escape hatch at **Actions → Publish channel (manual) → Run
  workflow**. Enter the tag and select the channel. That workflow bypasses
  the shared gate but still requires the per-channel environment approval
  (`pypi` or `dockerhub`). Document why you used it in the GitHub Release
  notes.
- **TestPyPI publish fails**: fix forward. Delete the tag locally and on
  origin (`git tag -d vX.Y.Z && git push origin :refs/tags/vX.Y.Z`),
  land the fix via PR, re-tag with the **same** version number, and push
  again. TestPyPI allows overwriting a yanked version on retry; real
  PyPI does not, so always retry on TestPyPI first.
- **Real PyPI publish fails after TestPyPI succeeded**: do **not** reuse
  the version number. Bump to `X.Y.Z+1` (usually a patch), land the fix,
  and cut a new release. PyPI treats deleted versions as permanently
  burned.
- **Wrong files in the wheel**: the `Verify dist contents` step in
  `publish.yml` fails the build if the wheel contains `AGENTS.md`,
  `CLAUDE.md`, `.env`, `tests/`, or `.git/`. If this trips, check
  `[tool.hatch.build.targets.wheel]` exclude patterns in
  `pyproject.toml`.
- **Docker push fails on rolling tag (`0.3`, `latest`)**: Docker Hub
  repo setting "Immutable tags" must be **off**. Rolling tags are
  overwritten on every release by design; immutability blocks that.
  The versioned tag (`0.3.3`) is still effectively immutable because
  the version string itself is never reused.
- **Docker publish succeeded but left an orphan tag on Docker Hub**:
  happens when a release is retried after a burned PyPI version. Delete
  the orphan tag from Docker Hub — an image with no matching PyPI
  release and no GitHub Release is untraceable back to source.
- **Release workflow ran but nothing published**: tags created via the
  GitHub API with `GITHUB_TOKEN` don't trigger downstream workflows.
  Delete the tag and re-push it as a signed tag from your workstation
  (see "Tag and release" above).

## Why this checklist exists

- Two version strings (`pyproject.toml` and `__init__.py`) drift if you
  only bump one. We almost shipped 0.2.0 with a mismatch.
- PyPI version numbers are permanent; a rushed release with a broken
  wheel burns the number forever.
- Signed, annotated tags are the root of the provenance chain that
  Sigstore attestations extend to the built artifact. An unsigned or
  lightweight tag breaks that chain even though the publish workflow
  will still run.
