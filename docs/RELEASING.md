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
| Moving `v1` Action tag (1.0+ releases) | `publish.yml` → `action-major-tag` job (lightweight, unsigned by design — see the job comment) |
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

The user-facing version of these guarantees — the stability promise and the
deprecation lifecycle — lives in [compatibility.md](compatibility.md).

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

### Cutting 1.0.0

The bump itself is a normal MINOR-shaped release mechanically; what makes it
1.0.0 is the contract coming into force. Before dispatching release-prep with
`1.0.0`, confirm each of these, in the PR that bumps the version:

1. **Contract docs are final.** compatibility.md and this file say what you
   are ready to stand behind: ADR-029 (scheduled interpreter drops),
   ADR-030 (the policy is part of the contract — after this release,
   loosening anything costs a MAJOR), the opaque `rule_id` declaration.
   Anything you still want to relax ships *in or before* this release.
2. **No severity move is pending.** Re-read ADR-028's watch items
   (CL-0029's `IPC_LOCK` friction, CL-0013's `/dev` descendants, CL-0014's
   judgment retention) and state in the PR description that none warrants a
   change now — after this release a severity change follows its post-1.0
   class (downgrade MINOR; upgrade MINOR with ADR-031's one-release
   runway), so a move you already know about belongs in this release, not
   announced immediately after it. This is the roadmap's last GA
   criterion, recorded so "we checked" is verifiable rather than folklore.
3. **Classifier bump** — `Development Status :: 4 - Beta` becomes
   `5 - Production/Stable` in the same commit that sets `version = "1.0.0"`
   (both `pyproject.toml` and `src/compose_lint/__init__.py`, as always).
4. **The moving `v1` Action tag needs no manual step** — publish.yml's
   `action-major-tag` job runs for the first time on this release (it skips
   v0). After the pipeline finishes, verify `v1` exists and points at the
   release commit, and that `uses: tmatens/compose-lint@v1` resolves in the
   marketplace-smoke sense.
5. **After the release**: the post-1.0 rules below are in force, including
   the flipped tie-breaker — when in doubt, pick the higher bump.

### Post-1.0 (future)

Once `1.0.0` ships, the contract tightens:

- **PATCH** (`1.2.3 → 1.2.4`) — bug fixes that don't change which
  *correct* findings are emitted for a given input. Removing findings
  the old behavior emitted in error — a false positive, a crash — is a
  fix (the cheat sheet below says so too); if the set of correct
  findings a user sees on an unchanged Compose file could change, it's
  not a patch.
- **MINOR** (`1.2.3 → 1.3.0`) — additive or backward-compatible
  changes. New rules, new CLI flags, new config keys, severity
  *downgrades*, new formatters, additive fields in JSON/SARIF output.
  Severity *upgrades* too, with ADR-031's one-release runway: announce
  in release N under `Changed`, apply in N+1 — and only when the
  derivation model produces the new number. Where only a *subset* of a
  rule's matches deserves the higher tier, prefer the split pattern
  (CL-0011 → CL-0024): the subset becomes a new rule ID, and existing
  suppressions of the old ID never silently cover the more dangerous
  rule (ADR-028).
  **New rules are intentionally MINOR, not MAJOR**, following the
  Hadolint / ShellCheck / ruff convention. Users who need
  deterministic results across upgrades should pin the version; the
  `--fail-on` flag is the documented escape hatch for tolerating new
  findings without failing CI.
- **MAJOR** (`1.2.3 → 2.0.0`) — anything that breaks a pinned,
  working setup:
  - Removing or renaming a CLI flag, subcommand, or config key.
  - Retiring a rule *without* the evidence bar and lifecycle of ADR-032
    (an evidence-refuted retirement through the lifecycle is MINOR; rule
    IDs are never reused either way — see `AGENTS.md`).
  - Changing the exit-code contract (e.g., adding a new non-zero
    exit code, changing the default `--fail-on` threshold).
  - Restructuring JSON/SARIF output in a way that removes or renames
    existing fields.
  - Dropping support for a Python version *off-schedule* — before its
    upstream EOL, or without ADR-029's announcement runway. A *scheduled*
    drop is MINOR (see the cheat sheet).

### Judgment-call cheat sheet

| Change                                       | Pre-1.0 | Post-1.0 |
| -------------------------------------------- | ------- | -------- |
| Fix false positive in an existing rule       | PATCH   | PATCH    |
| Fix a parser crash                           | PATCH   | PATCH    |
| Docs-only change                             | PATCH   | PATCH    |
| Add a new rule                               | MINOR   | MINOR    |
| Add a new CLI flag                           | MINOR   | MINOR    |
| Downgrade a rule's severity (HIGH → MEDIUM)  | MINOR   | MINOR    |
| Upgrade a rule's severity (LOW → HIGH)       | MINOR   | MINOR, announced one release ahead (ADR-031) |
| Tighten an existing rule (new true positive) | MINOR   | MINOR    |
| Remove or rename a CLI flag                  | MINOR   | MAJOR    |
| Retire a rule ID (refuted, via lifecycle)    | MINOR   | MINOR (ADR-032) |
| Retire a rule admitted on *judgment* (ADR-028 records it as such), via lifecycle | MINOR | MINOR (ADR-032 cond. 1) |
| Retire a rule ID off-lifecycle               | MINOR   | MAJOR    |
| Change the default `--fail-on` threshold     | MINOR   | MAJOR    |
| Drop a Python version on schedule (ADR-029)  | MINOR   | MINOR    |
| Drop a Python version off-schedule           | MINOR   | MAJOR    |
| Add a field to JSON/SARIF output             | MINOR   | MINOR    |
| Remove or rename a JSON/SARIF field          | MINOR   | MAJOR    |
| Change a rule's **evidence** derivation      | MINOR   | MINOR, announced under `Changed` |
| Remove or rename a config key                | MINOR   | MAJOR    |
| Deprecate a flag/key (keep it working)       | PATCH   | MINOR    |
| Amend this policy — *clarification*          | any     | any      |
| Amend this policy — *tightening* (promise more) | MINOR | MINOR   |
| Amend this policy — *loosening* (promise less)  | MINOR | MAJOR   |

When in doubt pre-1.0, pick MINOR. When in doubt post-1.0, pick the
higher bump — MAJOR costs the maintainer some release ceremony, but a
too-low bump breaks users who trusted the version contract.

Three rows need a word of explanation, because each was a real gap rather
than an omission for brevity.

**Evidence.** A rule's `evidence` never appears in text output, so it reads
like an implementation detail. It is not: it is the input to the SARIF
`partialFingerprints` digest, which is the *identity* of a Code Scanning
alert ([ADR-024](adr/024-finding-identity-is-not-prose.md)). Change a
derivation and every existing alert for that rule closes as "fixed" while
the same findings reopen as new — a consumer-visible event with no output
field changed and no test necessarily failing (`tests/test_finding_identity.py`
pins the derivations for exactly this reason). It is MINOR rather than MAJOR
because no *shape* changes and nothing breaks: a pinned user is untouched,
and an unpinned one sees alert churn once. It must be announced under
`Changed` so that churn is expected rather than mysterious.

**Retire-on-judgment.** The row above it covers a rule whose premise
evidence *refutes*. A rule [ADR-028](adr/028-pre-1.0-rule-id-sweep.md)
records as admitted on judgment — a closed set, currently `{CL-0014}` —
can never meet that bar, because its premise holds and what is thin is its
grounding. Without its own row such a rule would be *harder* to remove than
a grounded one, which is backwards.

**Amending this policy.** The ladder comes from
[ADR-030](adr/030-the-policy-is-part-of-the-contract.md) and governs every
other row in this table, so leaving it out of the table meant the one rule
that prices changes to the rules was the one you had to go elsewhere to
find. Note the asymmetry it creates, which is the reason several 1.0
decisions were taken early: a loosening is only affordable *before* the
tag, while the tightening that reverses it stays cheap forever.


### Deprecations

Removing anything stable follows the deprecation lifecycle in
[compatibility.md](compatibility.md#deprecation-lifecycle): announce it under
`Deprecated` in `CHANGELOG.md`, emit a stderr `warning:` for user-invoked
surfaces, keep it working for at least one MINOR, and remove it only in a MAJOR
(listed under `Removed`).

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

      `release-prep.yml` now refuses to run on a `[Unreleased]` that is
      empty, has duplicate `###` sections, or orders them outside Keep a
      Changelog — the three shapes that have reached a release candidate.
      **That checks shape, not completeness:** it cannot know a PR went
      undocumented, so the cross-check above is still yours to do.
- [ ] **Every entry authored by someone other than a maintainer credits
      them.** Append `Thanks [@handle](https://github.com/handle)
      ([#NNN](https://github.com/tmatens/compose-lint/pull/NNN)).` as its own
      indented paragraph at the end of the entry. The GitHub Release body is
      generated verbatim from this section, and it is the only announcement
      channel this repo has, so an uncredited entry is a contribution that
      never gets publicly acknowledged. The same `gh pr list --search
      "merged:>..."` cross-check above surfaces the authors — anyone who is
      not a maintainer gets a line. Bots (`renovate[bot]`,
      `dependabot[bot]`, `github-actions[bot]`) never do, and neither do
      maintainers' own PRs: the credit marks *someone else did this*, which
      is what makes it worth reading. (0.23.0 shipped three outside
      contributions with no attribution and had to be corrected after the
      fact — release bodies are editable, so fix it there too if this is
      caught late.)
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

compose-lint declares the version in **five** places that must stay
in sync. Missing any one of them is a release-blocker — check all
five before opening the bump PR.

- [ ] `pyproject.toml` — `version = "X.Y.Z"` under `[project]`
- [ ] `src/compose_lint/__init__.py` — `__version__ = "X.Y.Z"`
- [ ] `action.yml` — `DEFAULT_VERSION="X.Y.Z"` in the install step. This
      is the package the Action installs when a consumer does not pass
      `version:`, so a stale one means a SHA-pinned `uses:` silently
      installs a different linter than the action it pinned.
      Automated: `release-prep.yml` calls `scripts/bump-version.sh`,
      which rewrites this alongside the two above, and
      `tests/test_action_contract.py` fails the PR if they disagree.
      It was omitted from this list when #554 introduced it, and
      `release-prep.yml` did not bump it either — so the 0.18.0 prep PR
      failed its own required check and needed a hand-pushed commit.
- [ ] `README.md` + `docs/hardening.md` — version references in
      copy-paste integration snippets. All need bumping each release;
      otherwise users land on a stale version (v0.14.0 shipped with all
      of them stale). Four forms exist:
      - `tmatens/compose-lint@<sha> # v0.X.Y` (README — GitHub Action snippet)
      - `rev: v0.X.Y` (README — pre-commit snippet)
      - `compose-lint==0.X.Y` (README — Forgejo Actions snippet, pip pin)
      - `:0.X.Y` image tags (docs/hardening.md — hardened `docker run`
        snippet, plus the digest-lookup prose below it; NOT in README)

      **All four are automated — nothing to do by hand here.** The first
      three are rewritten by `release-prep.yml` in the bump commit itself,
      and CI enforces them (`version-consistency` job, "self-referencing
      version pins" step): any `compose-lint==X.Y.Z`,
      `composelint/compose-lint:X.Y.Z`, or `rev: vX.Y.Z` anywhere in
      `README.md` or `docs/` (historical files excluded) must equal
      `pyproject.toml`'s version, so the prep PR fails CI if the rewrite
      ever misses one — including pins in docs this list doesn't know
      about yet. The action-SHA form cannot be checked pre-tag (the new
      tag's SHA exists only post-release), so `publish.yml`'s
      `bump-marketplace-smoke-pin` job rewrites it in both
      `marketplace-smoke.yml` and `README.md` in the post-release
      follow-up PR.

      This used to be manual, and drifted: the prep PR failed its own
      required check on every release after #443 added the gate (0.14.1
      needed a hand-pushed pin-bump commit), and the README action pin
      stayed a release behind because only `marketplace-smoke.yml` was
      rewritten. Verify rather than re-do — if the prep PR is green and
      the follow-up PR touches `README.md`, this item is satisfied.
- [ ] `.github/workflows/marketplace-smoke.yml` — two
      `uses: tmatens/compose-lint@<sha> # vX.Y.Z` lines plus the
      `CL_RELEASE_TAG: vX.Y.Z` env the published pre-commit smoke
      consumes. Automated by the same `bump-marketplace-smoke-pin` job
      as the README pin above: it resolves
      `git rev-parse vX.Y.Z^{commit}` **after** the signed tag is
      pushed and opens the follow-up PR for you. Review and merge that
      PR; only bump by hand if the job failed.

Verify the first three match:

```bash
grep -E '^version' pyproject.toml
grep __version__ src/compose_lint/__init__.py
grep DEFAULT_VERSION= action.yml
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
git add pyproject.toml src/compose_lint/__init__.py action.yml CHANGELOG.md
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
      `uses: tmatens/compose-lint@<sha> # vX.Y.Z` lines and the new
      tag in the `CL_RELEASE_TAG` env of the published pre-commit
      smoke. Merging it auto-triggers the workflow, which verifies the
      published Action and pre-commit hook end-to-end (it can also be
      re-run from **Actions → Marketplace smoke test**).
- [ ] **Forgejo snippet with the new pin** — optional: the README
      snippet's `compose-lint==X.Y.Z` pin (bumped by release-prep) gets
      its first live execution on the next weekly `forgejo-smoke.yml`
      run; dispatch **Actions → Forgejo smoke test** to verify it
      immediately instead. (It deliberately doesn't run pre-release —
      the new version isn't on PyPI yet.)
- [ ] **Docker Hub overview sync** — runs automatically in
      `publish.yml`'s `dockerhub-description` job after `docker-publish`,
      via the first-party composite action at
      `.github/actions/update-dockerhub-description` (which just forwards
      to `scripts/update-dockerhub-description.sh`). Syncs
      `docs/dockerhub-overview.md` (NOT `README.md` — the Hub overview is
      a separate, trimmed, version-free file, so it needs no per-release
      bump). Requires `DOCKERHUB_TOKEN` to have **Read, Write, Delete**
      scope — Read & Write is not enough for the description PATCH
      endpoint. Verify
      `https://hub.docker.com/r/composelint/compose-lint` reflects the
      current overview file.
- [ ] **README demo GIFs** — only if this release changed the text-output
      appearance (finding layout, verdict line, colors), changed what
      `fix` emits, or you want the banner to show the new version. The
      demo toolchain installs compose-lint from PyPI, so this is
      **post-publish**: bump the `compose-lint==` pin in
      `scripts/demo/requirements.in`, recompile
      `scripts/demo/requirements.lock` (exact `uv pip compile` command in
      the lock's header), run `scripts/demo/render.sh` (both casts), and
      open a follow-up PR with the updated `docs/assets/demo.gif`,
      `docs/assets/demo-fix.gif`, and their README alt text. Output-only
      or docs-only releases can skip this. Each cast is sized to its
      terminal in the tape — if a release adds a line to `check` or `fix`
      output, check the render didn't scroll before committing it.
- [ ] **Fresh `[Unreleased]` section** — already inserted by
      `release-prep.yml` as part of the release bump PR. No follow-up
      PR needed.
- [ ] **Call out user-visible changes in the GitHub release notes** —
      deprecations, new or tightened rules, and behaviour changes. The
      release notes are the announcement channel: Discussions are not
      enabled on this repo, so an item pointing there was one no releaser
      could ever tick. Findings that are new because coverage tightened
      deserve a sentence naming the escape hatches (`--fail-on`, pinning),
      since `docs/compatibility.md` treats them as MINOR rather than
      breaking and a pinned CI user will meet them without warning.

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

## Credential scoping (open items)

Two hardening steps live in GitHub and Docker Hub settings, not in this
repository, so they cannot be landed by a PR. Both are recorded here rather
than left implicit — the workflow side of each is already in place.

### A `dockerhub-description` environment

`dockerhub-description.yml` is dispatched manually and reads the Docker Hub
credential. Its checkout is pinned to the default branch, so a dispatcher
cannot choose the code that runs — but the secrets are still **repo-level**,
which means nothing scopes them to a ref.

To close the rest:

1. Create an environment named `dockerhub-description`.
2. Set its deployment-branch policy to the default branch only. (The existing
   `dockerhub` environment is tags-only, which is why this job could not simply
   reuse it.)
3. Move `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` into it, removing them from
   repo scope.
4. Add `environment: dockerhub-description` to the job, and required reviewers
   if you want a human gate.

Until step 3, a repo-level secret is readable by any workflow in the
repository, so steps 1–2 alone change nothing.

### Split the Docker Hub PAT by capability

One `Read, Write, Delete` PAT is referenced by every Docker Hub job, including
read-only ones (`docker-smoke`, `scout`, `report`). A leak from any of them
carries delete capability for the whole namespace — the scope of the credential
is set by the single most privileged consumer.

Mint three tokens and route them by need:

| Token | Scope | Used by |
|---|---|---|
| `DOCKERHUB_TOKEN_READ` | Read | `docker-smoke`, `scout`, `report` |
| `DOCKERHUB_TOKEN_WRITE` | Read, Write | the four build/publish jobs |
| `DOCKERHUB_TOKEN_ADMIN` | Read, Write, Delete | the two `dockerhub-description` jobs only |

The ADMIN token should live in the `dockerhub-description` environment above,
so the other jobs cannot reference it even by name. Renaming the secrets is a
breaking change to the release pipeline, so do it in one pass: add the new
secrets first, land the workflow change, then revoke the old PAT.

## Why this checklist exists

- Three version strings (`pyproject.toml`, `__init__.py`, and `action.yml`'s
  `DEFAULT_VERSION`) drift if you only bump some. We almost shipped 0.2.0 with a
  mismatch between the first two. `DEFAULT_VERSION` is the package the Action
  installs when a consumer does not pass `version:`, so a stale one means a
  SHA-pinned `uses:` silently gets a different linter than the action it pinned;
  `scripts/bump-version.sh` rewrites all three and
  `tests/test_action_contract.py` fails if they disagree.
- PyPI version numbers are permanent; a rushed release with a broken
  wheel burns the number forever.
- Signed, annotated tags are the root of the provenance chain that
  Sigstore attestations extend to the built artifact. An unsigned or
  lightweight tag breaks that chain even though the publish workflow
  will still run.
