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

compose-lint declares the version in **two** places that must stay in
sync. Missing one is the mistake we almost made on 0.2.0 — check both.

- [ ] `pyproject.toml` — `version = "X.Y.Z"` under `[project]`
- [ ] `src/compose_lint/__init__.py` — `__version__ = "X.Y.Z"`

Verify they match:

```bash
grep -E '^version' pyproject.toml
grep __version__ src/compose_lint/__init__.py
```

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

## Tag and push

Tags must be **annotated and signed**. The publish workflow only
triggers on `v*` tags.

```bash
git tag -s vX.Y.Z -m "compose-lint X.Y.Z"
git push origin vX.Y.Z
```

- [ ] `git tag -v vX.Y.Z` prints a good signature.
- [ ] The tag push triggered `Publish to PyPI` in Actions.

## Approve the TestPyPI environment

- [ ] Open the running workflow. The `testpypi` job will be pending
      approval from the `testpypi` environment.
- [ ] Approve it. Wait for it to complete.
- [ ] Check <https://test.pypi.org/project/compose-lint/> — the new
      version should be listed. Sigstore attestations should appear on
      the workflow run summary.

Smoke test the TestPyPI build in a throwaway venv:

```bash
python -m venv /tmp/compose-lint-test && source /tmp/compose-lint-test/bin/activate
pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ "compose-lint==X.Y.Z"
compose-lint --version
deactivate && rm -rf /tmp/compose-lint-test
```

- [ ] `compose-lint --version` prints `X.Y.Z`.

## Approve the real PyPI environment

Only proceed once TestPyPI looks correct — a bad TestPyPI build almost
always means a bad real-PyPI build, and PyPI version numbers cannot be
reused even after deletion.

- [ ] Approve the `pypi` environment in the running workflow.
- [ ] Workflow completes green.
- [ ] <https://pypi.org/project/compose-lint/> shows the new version.
- [ ] The "Build provenance" section on the PyPI page shows the Sigstore
      attestation linked to this repo and the `publish.yml` workflow.

## Post-release

- [ ] Create a GitHub Release from the tag
      (`gh release create vX.Y.Z --notes-from-tag` or use the web UI).
      Copy the relevant CHANGELOG section as the release notes.
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
  `publish.yml` fails the build if the wheel contains `CLAUDE.md`,
  `.env`, `tests/`, or `.git/`. If this trips, check
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
