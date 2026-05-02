# Continuity & Access

compose-lint is currently single-maintainer. This document is the
honest-and-actionable plan for what happens if the maintainer is
unavailable — temporarily, permanently, or anywhere in between. It
satisfies the OpenSSF Best Practices Silver `access_continuity`
criterion and tracks the access grants needed by every credential the
project depends on.

For the related governance question (who decides, how to add a
co-maintainer), see [GOVERNANCE.md](../GOVERNANCE.md). For the
maintainer roster, see [MAINTAINERS.md](../MAINTAINERS.md).

## Short version

If the listed maintainer is permanently unavailable, anyone can
continue compose-lint by forking. The MIT license, the public
reproducible build (hash-pinned `requirements*.lock`, digest-pinned
Docker base images, signed tags), and the documented release process
([docs/RELEASING.md](RELEASING.md)) are deliberately structured so a
successor needs no private state from the original maintainer.

The published namespaces (`tmatens/compose-lint` on GitHub,
`compose-lint` on PyPI, `composelint/compose-lint` on Docker Hub) are
the only continuity assets that cannot be reproduced by a fork. Their
recovery paths are listed below.

## Why bus factor is currently 1

Honest answer: the project is young and no contributor has stepped up
yet. There is no real on-call load to share — security reports have
been zero, the issue queue is light, and releases are infrequent — so
the path to a second maintainer is "someone wants in," not "someone
takes over a burden." The project is structured to mitigate the
bus-factor risk rather than to deny it — see
[GOVERNANCE.md](../GOVERNANCE.md) for the path to adding a second
maintainer.

## What does not depend on the maintainer

Every release artifact and the path to produce a new one is reproducible
without the maintainer's local state:

- **Source of truth**: the `main` branch on
  `https://github.com/tmatens/compose-lint`. The MIT license permits
  anyone to fork and continue.
- **Reproducible build**: `requirements.lock`, `requirements-dev.lock`,
  and `requirements-build.lock` are hash-pinned (`pip install
  --require-hashes`). The Dockerfile pins both stages by SHA256 digest.
  Anyone with a clean clone can produce a byte-identical wheel and a
  determined image build for the same commit.
- **Documented release process**: [docs/RELEASING.md](RELEASING.md)
  is the full checklist. The release pipeline
  ([.github/workflows/publish.yml](../.github/workflows/publish.yml))
  runs from the GitHub Actions runner, not the maintainer's machine —
  no local secrets are used.
- **Tag-rooted provenance**: release tags are SSH-signed with the keys
  in [.github/allowed_signers](../.github/allowed_signers). A successor
  who is added to that file can sign tags that pass the `verify-tag`
  gate without inheriting the prior maintainer's key.
- **Trusted Publisher (PyPI)**: PyPI publish runs via OIDC — no
  long-lived API token exists to be lost. A new maintainer added to
  the GitHub repo and the `pypi` Environment can publish immediately.

## What does depend on the maintainer (and the recovery path for each)

These are the assets a successor needs *transferred* to maintain
continuity of identity. Each row lists the access, who currently holds
it, and the recovery procedure if the maintainer is unavailable.

| Asset                                      | Holder today          | What grants access                                              | Recovery path if maintainer is gone                                                                                                                  |
|--------------------------------------------|-----------------------|------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| GitHub repo `tmatens/compose-lint` admin   | @tmatens              | Personal GitHub account                                          | GitHub Account Recovery if family/successor has account-recovery info. Otherwise: fork to a new namespace and continue under the MIT license.        |
| PyPI project `compose-lint` owner          | @tmatens              | PyPI account (OIDC publishes via the `pypi` GitHub Environment)  | PyPI account-recovery process. If unrecoverable, request project ownership transfer from PyPI admins citing inactivity (PEP 541). Successor projects may publish under a renamed package as a fallback. |
| Docker Hub repo `composelint/compose-lint` | @tmatens              | Docker Hub `composelint` org admin                                | Docker Hub org admin transfer. If unrecoverable, publish under a new namespace and update README + action references.                                |
| `composelint` Docker Hub org               | @tmatens              | Docker Hub account                                                | Same as above — Docker Hub recovery, otherwise namespace migration.                                                                                  |
| `release` GitHub Environment approver      | @tmatens              | Repo-level Environment configuration                              | A new repo admin can edit the `release` Environment to add themselves as a required reviewer.                                                        |
| `MARKETPLACE_SMOKE_PAT` secret             | @tmatens              | Repo Actions secret                                               | A new repo admin generates a fresh PAT (workflow scope) and stores it in the Actions secret. See `docs/CI.md` for the required scopes.               |
| `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN`   | @tmatens              | Repo Actions secret                                               | A new Docker Hub admin generates a token (Read/Write/Delete scope; Read+Write is not enough — see [docs/RELEASING.md](RELEASING.md)) and stores it.   |
| Tag-signing SSH key                        | @tmatens              | Listed in [.github/allowed_signers](../.github/allowed_signers)   | A new maintainer adds their own key in a PR; revoke the old key in the same or a follow-up PR. Old tags remain verifiable as long as the old key entry stays.  |
| Forgejo / personal infra references in docs| @tmatens              | n/a (informational)                                               | Successor scrubs personal infra references; nothing in product depends on them.                                                                       |

## Continuity checklist when promoting a co-maintainer

When a second maintainer is added per
[GOVERNANCE.md](../GOVERNANCE.md) §"Adding a maintainer", grant each
of the following before they take their first on-call shift. The PR
that adds them to [MAINTAINERS.md](../MAINTAINERS.md) should reference
this checklist as completed.

- [ ] GitHub repo: Admin role on `tmatens/compose-lint`.
- [ ] GitHub Environment `release`: added as a required reviewer.
- [ ] GitHub Environment `pypi`: no per-user grant (OIDC), but confirm
      the new maintainer can dispatch the manual `Publish channel`
      escape hatch.
- [ ] PyPI project `compose-lint`: added as a Maintainer.
- [ ] Docker Hub `composelint` org: added as an org Owner.
- [ ] `.github/allowed_signers`: PR adds their SSH signing key,
      `namespaces="git"` scoped.
- [ ] CONTRIBUTING.md, GOVERNANCE.md, MAINTAINERS.md updated to reflect
      the new responsibility split.

## What to do if the maintainer becomes non-responsive

1. **First 14 days**: assume normal latency (per CONTRIBUTING.md
   triage SLA). No action.
2. **14–30 days**: a contributor or co-maintainer opens a tracking
   issue tagged `governance:continuity` listing open security reports,
   pending releases, and any other time-sensitive items.
3. **30–90 days**: if a co-maintainer exists, they take over per
   normal lazy-consensus rules. If not, contributors should:
   - Continue normal PRs against `main`. They will accumulate.
   - For urgent security issues, follow the disclosure process in
     [.github/SECURITY.md](../.github/SECURITY.md) and additionally
     post a public security advisory on a reputable forum if the issue
     warrants it.
4. **90+ days with no response**: per GOVERNANCE.md, an existing
   co-maintainer may remove the inactive maintainer in a PR
   documenting the contact attempts. If there is no co-maintainer, the
   community option is a fork under MIT.

## Reviewing this document

This document is reviewed each time the maintainer roster changes and
at least once per MINOR release window. If you notice a credential or
access grant that is missing from the table above, open a PR adding
it.
