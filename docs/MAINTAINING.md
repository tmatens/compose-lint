# Maintaining

How a maintainer reviews and merges a contribution from outside the
repository. [CONTRIBUTING.md](../CONTRIBUTING.md) is the contributor's side of
the same workflow and stays the source of truth for commits, signing and PR
expectations; this page covers only what a maintainer does that a contributor
cannot see.

Related: [CI.md](CI.md) for what each workflow does, [RELEASING.md](RELEASING.md)
for cutting a release.

## Approving CI on a fork pull request

A pull request from a fork sits with an all-grey checks panel until a maintainer
approves the workflow run. GitHub offers three settings for this
(Settings → Actions → General → Fork pull request workflows); this repository
uses **Require approval for first-time contributors**, defined as users who have
never had a commit or pull request merged into *this* repository. The status is
per-repository and permanent once cleared: a contributor's first merge ends the
gate for every PR they open afterwards.

### What the gate does and does not protect

Approving lets the contributor's code run in CI. It does **not** expose
anything that a merge would not, because a fork pull request already runs
without reach into the repository's secrets:

| Property | State on a fork PR |
|---|---|
| `GITHUB_TOKEN` | Read-only, regardless of what a job declares |
| Repository secrets | Unavailable |
| Runners | GitHub-hosted only |
| Actions cache | Scoped to the PR's own ref; cannot poison `main`'s |
| Code Scanning upload | Blocked — forks never hold `security-events: write` |

Four properties of this repository's workflows are what make that true, and each
is worth preserving:

- **No `pull_request_target` anywhere.** That trigger runs base-branch code with
  secrets and a write token. A `pull_request_target` workflow that checks out
  the PR head is the classic "pwn request" and is the single change most likely
  to turn approval into a real risk.
- **No secrets referenced in PR-triggered workflows.** `ci.yml`, `codeql.yml`
  and `docs.yml` reference none at all; `cflite-pr.yml` uses only
  `secrets.GITHUB_TOKEN`, which is downgraded to read-only for forks.
- **Deny-all default permissions.** Every workflow sets `permissions: {}` at the
  top level and each job grants itself the minimum. `docs.yml`'s `pages: write`
  and `id-token: write` jobs are gated behind `if: github.event_name !=
  'pull_request'`.
- **Actions pinned by commit SHA**, and every `${{ github.event.* }}` value
  passed through an `env:` block rather than interpolated into a `run:` string.
  The second is what keeps a branch name or PR title from becoming shell code.

### What to look at before approving

Read the diff first — approval is the last point before the contributor's code
executes. The paths worth slowing down for:

```
.github/**    action.yml    Dockerfile*    pyproject.toml
*.lock        scripts/**    .githooks/**   .pre-commit-hooks.yaml
```

A PR touching only `src/**`, `tests/**`, `docs/**` and `CHANGELOG.md` is the
ordinary case. Note what that does **not** mean: `src/**` is exactly what the
test matrix executes, so "safe paths" narrows where to look rather than proving
the diff benign. There is no automated check that can make this decision, and
one running from the fork's own tree could be edited by that fork.

### Do not spend an approval on a superseded commit

Each push from a gated contributor re-arms the gate, and approval is bound to
the head SHA. Approving a commit that is about to be rebased burns the approval
for nothing. When a PR needs both a rebase and review fixes, post the review
first so one push clears everything.

## Writing a good first issue

Every `good first issue` here is written by a maintainer, and the review that
follows is graded against what the maintainer knew when writing it — which is
more than the issue says. Of the seven external PRs to date, most of the
review rounds asked for something the issue did not: the rule-doc row that was
in the Scope prose but not in the file list (#685), the `docs/configuration.md`
bullet nothing mentioned (#826), the scoping comment an ADR implied (#795). A
contributor reads **Scope** as the whole boundary — it was written to reassure
— so what it omits is what comes back as a review comment.

Write the review checklist into the issue, before the review. Copy this
skeleton; the boilerplate has drifted when it lived in saved replies (one
issue said `mypy src/` while CI ran `mypy src/ tests/`), so this file is its
only home.

````markdown
## What happens

<!-- Console transcript. Exit codes. Reproduced on which version. -->

## Why

<!-- file:line of the cause, re-checked against main @ <sha>. -->

## The fix

<!-- The approach. Name the traps: what an earlier attempt got wrong. -->

## Also update

<!-- Every file outside the code that has to change, with what changes in it.
     This is the list the reviewer will check. If it is empty, say so. -->

- `docs/…` — …
- `CHANGELOG.md` — not needed; the releaser writes your credit line.

## Tests

<!-- Which file, which existing test to model on, one case per behaviour. -->

## Done when

<!-- Self-checkable, in the contributor's terms. Whatever you would check at
     review goes here instead. -->

- [ ] … (one line per row of the behaviour table above)
- [ ] `scripts/preflight.sh` passes on the branch
- [ ] Every file under *Also update* is in the diff

## Out of scope

<!-- What NOT to touch. This is a boundary, not a summary of the work. -->

---

## Before you start

compose-lint's contribution process is stricter than most, and it — not the
patch — is where a first PR usually stalls. All of it is in
[CONTRIBUTING.md](../blob/main/CONTRIBUTING.md); the short version:

- Fork, then add this repo as `upstream` — `origin` is your fork, and
  `git rebase origin/main` does nothing useful there.
- Run `scripts/preflight.sh` before every push. It runs every gate CI runs,
  including the commit checks (DCO trailer matching your author email
  exactly, subject style) that CI cannot report on a first PR until a
  maintainer approves the run.
- Your first PR's checks stay grey until that approval. That is the fork
  gate, not something you did; a maintainer will get to it.
- Rebase with `--force-with-lease`, never the **Update branch** button.

Ask on the issue if anything is unclear. Happy to help you land it.
````

## Reviewing

Split every review into what the contributor must change and what you will
handle. If the issue and CONTRIBUTING did not ask for it, it is not a change
request on someone's first PR: fix it yourself in a follow-up, or file it, and
say which. And a review comment that could have been a test is a bug in CI,
not a note for the contributor — write the test (`tests/test_config_surfaces.py`
and `tests/test_rule_doc_surfaces.py` are the shape) so the next person is told
by a red check while the branch is still open, not by you a day later.


Post findings as a **review**, not a plain issue comment — a review carries a
state, sets `reviewDecision`, and shows in the Reviewers panel:

```bash
gh pr review <n> --request-changes --body-file <file>   # blocking findings
gh pr review <n> --comment         --body-file <file>   # feedback, no verdict
gh pr review <n> --approve         --body-file <file>
```

Inline comments anchored to lines go through
`POST /repos/{owner}/{repo}/pulls/{n}/reviews` with a `comments` array of
`{path, line, side, body}`. Anchors only work on lines present in the diff, so a
finding about a file the PR does not touch — a rule doc that needs a matching
row, say — has to live in the review body.

A *changes requested* review does **not** clear itself when the contributor
pushes the fix. `dismiss_stale_reviews_on_push` is enabled on the ruleset, but
it dismisses stale *approvals* only — GitHub's own wording for it is "dismiss
stale pull request approvals when new commits are pushed". A changes-requested
review keeps blocking the merge until you act on it, however many times the
branch is rebased or amended in between.

Two ways to clear it, and they say different things. Submitting an approving
review supersedes it, because a reviewer's latest review is the one that counts
— use this when the findings were addressed. Dismissing it leaves the review in
place, marked dismissed with a reason — use this when the findings were waived
or overtaken rather than fixed, since it keeps the objection legible.

## Before merging

| Check | How |
|---|---|
| No blocking state | `gh pr view <n> --json mergeStateStatus` → `CLEAN` |
| Checks ran on the **current** head | Compare the run's `head_sha` to `headRefOid`; a green run on a superseded SHA proves nothing |
| Branch is up to date | `behind_by: 0` — the ruleset sets `strict_required_status_checks_policy` |
| Review threads | All resolved (CONTRIBUTING asks for this; it is not enforced) |
| Rule predicates touched | Regenerate `tests/corpus_snapshot.json.gz` yourself and review the drift — contributors are asked to leave it alone |

`ci-ok` is the only required status check: it is a roll-up whose `needs` list
carries every other job, so one red job shows as two failures (`ci-ok` and the
job itself) and one real cause.

### What the squash commit will say

Merging is squash-only. The repository is configured with
`squash_merge_commit_title: COMMIT_OR_PR_TITLE` and
`squash_merge_commit_message: COMMIT_MESSAGES`, so `main` gets the
contributor's commit message — **not** the PR description. Two consequences
worth knowing:

- A `Signed-off-by:` trailer and a `Fixes #N` reference survive into `main`.
- The PR template's Origin disclosure ("produced primarily by an automated
  agent") stays on the PR page and out of permanent history, which is what
  CONTRIBUTING's no-AI-credit rule wants. It is a disclosure, not a credit line;
  the PR is the right place for it.

GitHub signs the squash commit with its own key, so `main`'s history verifies
regardless of whether the contributor signed — squash is the only merge method
enabled, and every commit on `main` reports `verified: true` from the API.
That is the policy: **contributor signing is recommended, not required.** A
signed PR commit is evidence about the PR — it binds the author field to the
contributor's account, which the DCO trailer alone cannot — not about what
lands. Nothing enforces it and nothing should: there is no
`required_signatures` rule, no CI job, and the pre-push hook and
`scripts/preflight.sh` report an unsigned commit as a note. This matches the
DCO-plus-signed-releases posture of the kernel and CNCF projects; requiring
per-commit signatures from outside contributors would put a setup step in
front of a first PR to protect nothing that ships.

## Known friction

`strict_required_status_checks_policy` requires a PR to be up to date before
merging, and Renovate merges digest PRs daily. An external PR that sits for a
day needs a rebase, the rebase force-push re-arms the approval gate, and the
maintainer approves a second time. Merging external contributions promptly is
the cheapest mitigation; a merge queue would remove the requirement entirely,
at the cost of teaching `ci.yml` the `merge_group` trigger.

Contributor-side friction — the DCO check being invisible until approval, and
the sign-off guidance that does not work — is tracked in
[#686](https://github.com/tmatens/compose-lint/issues/686).
