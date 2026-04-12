# Release checklist

Maintainer-only. This is the step-by-step for cutting a new release of
compose-lint. Contributors don't need to read this; see
[CONTRIBUTING.md](../CONTRIBUTING.md) instead.

The release pipeline is **tag-triggered**: pushing an annotated, signed
`vX.Y.Z` tag to `main` kicks off `.github/workflows/publish.yml`, which
builds, uploads to TestPyPI (gated on a protected environment), then
uploads to real PyPI (gated on a second protected environment). Both
environments require manual approval — the tag push alone does not
release. Sigstore build attestations are generated automatically.

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
- [ ] No open Dependabot PRs you meant to merge first.

## Bump the version

compose-lint declares the version in **three** places that must stay
in sync. Missing any one of them is a release-blocker — check all
three before opening the bump PR.

- [ ] `pyproject.toml` — `version = "X.Y.Z"` under `[project]`
- [ ] `src/compose_lint/__init__.py` — `__version__ = "X.Y.Z"`
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

Go to **Actions → Release → Run workflow**. Enter the version number
(e.g. `0.4.0`). The workflow validates that `pyproject.toml`,
`__init__.py`, and `CHANGELOG.md` all match, checks CI passed on main,
then creates an annotated tag. The tag push triggers `Publish to PyPI`
and `Docker Publish` automatically.

Use **Dry run** to validate everything without creating the tag.

Alternatively, create a signed tag locally:

```bash
git tag -s vX.Y.Z -m "compose-lint X.Y.Z"
git push origin vX.Y.Z
```

- [ ] The tag exists and triggered `Publish to PyPI` and `Docker Publish`
      in Actions.

## Approve the TestPyPI environment

- [ ] Open the running workflow. The `testpypi` job will be pending
      approval from the `testpypi` environment.
- [ ] Approve it. Wait for it to complete.
- [ ] Check <https://test.pypi.org/project/compose-lint/> — the new
      version should be listed. Sigstore attestations should appear on
      the workflow run summary.

The `testpypi-smoke` job runs automatically after TestPyPI publish:
installs the package from TestPyPI, verifies `--version` matches the
tag, and runs clean/insecure fixture smoke tests. The real PyPI publish
is gated on this job succeeding — no manual venv test needed.

## Approve the real PyPI environment

Only proceed once TestPyPI looks correct — a bad TestPyPI build almost
always means a bad real-PyPI build, and PyPI version numbers cannot be
reused even after deletion.

- [ ] Approve the `pypi` environment in the running workflow.
- [ ] Workflow completes green.
- [ ] <https://pypi.org/project/compose-lint/> shows the new version.
- [ ] The "Build provenance" section on the PyPI page shows the Sigstore
      attestation linked to this repo and the `publish.yml` workflow.

## Approve the Docker Hub publish

The tag push also triggers `.github/workflows/docker-publish.yml`, which
builds a multi-arch image (`linux/amd64`, `linux/arm64`), runs smoke tests
(version check, clean/insecure fixtures, SARIF output), pushes to Docker
Hub as `composelint/compose-lint`, and signs the image with cosign
(Sigstore keyless).

- [ ] Docker publish workflow completes green (includes automated
      post-push verification: pull, cosign verify, and version check).

## Post-release

- [ ] Create a GitHub Release from the tag
      (`gh release create vX.Y.Z --notes-from-tag` or use the web UI).
      Copy the relevant CHANGELOG section as the release notes.
- [ ] **Bump the Marketplace smoke test pin.** The commit SHA only
      exists once the tag is pushed, so this can't live in the
      release bump PR. Grab the SHA and update both
      `uses: tmatens/compose-lint@<sha> # vX.Y.Z` lines in
      `.github/workflows/marketplace-smoke.yml`:

      ```bash
      git rev-parse vX.Y.Z^{commit}
      ```

      Open a follow-up PR with the bump. Once it's merged, trigger
      **Actions → Marketplace smoke test → Run workflow** to verify
      the published action end-to-end against the new tag.
- [ ] Announce in Discussions if the release has user-visible changes.
- [ ] Open a follow-up PR adding an empty `[Unreleased]` section at the
      top of `CHANGELOG.md` so the next change has somewhere to land.

## If something goes wrong

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

## Why this checklist exists

- Two version strings (`pyproject.toml` and `__init__.py`) drift if you
  only bump one. We almost shipped 0.2.0 with a mismatch.
- PyPI version numbers are permanent; a rushed release with a broken
  wheel burns the number forever.
- Signed, annotated tags are the root of the provenance chain that
  Sigstore attestations extend to the built artifact. An unsigned or
  lightweight tag breaks that chain even though the publish workflow
  will still run.
