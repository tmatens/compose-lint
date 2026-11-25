# scripts/

Maintainer and CI tooling for this repository. None of it is part of the
linter, and none of it is installed with compose-lint: the wheel on PyPI
contains only the `compose_lint` package. You can check that yourself, since a
wheel is a zip file:

```bash
pip download compose-lint --no-deps -d cl
unzip -l cl/*.whl
```

The project is maintained by one person, so anything that can be checked or
done by a script is. Each script's header says what it does and why it
exists. The tables below say where each one runs.

## Checks on pull requests

| Script | What it does | Runs in |
| --- | --- | --- |
| `preflight.sh` | Runs every gate a pull request faces, from a local checkout, in one command. | Local, `ci.yml` |
| `assert_golden_findings.py` | Compares a JSON or SARIF report against the expected findings for the smoke fixture, so a surface that drops findings fails. | `ci.yml` |
| `smoke_fix_roundtrip.py` | Runs `compose-lint fix --apply` end to end and checks the file it writes. | `ci.yml` |
| `validate_rule_premises.py` | Starts a short container per rule to confirm the behavior the rule warns about is real. | `ci.yml` |
| `verify-dockerfile-digests.sh` | Fails if a pinned base image digest is a single-architecture manifest. Reads registry headers, pulls nothing. | `ci.yml` |
| `check_changelog_unreleased.py` | Validates the shape of the `[Unreleased]` section of `CHANGELOG.md`. | `ci.yml`, `release-prep.yml` |
| `verify_sarif_ingestion.py` | Confirms GitHub code scanning ingested an uploaded SARIF file and produced alerts. | `sarif-ingestion.yml` |

## Releases

| Script | What it does | Runs in |
| --- | --- | --- |
| `bump-version.sh` | Sets the version in `pyproject.toml`, `__init__.py` and `action.yml`. | `release-prep.yml` |
| `release_image_tags.py` | Works out which Docker Hub tags a release image is pushed under. | `publish.yml` |
| `update-dockerhub-description.sh` | Syncs the Docker Hub overview from `docs/dockerhub-overview.md`. | `publish.yml` |

## Scheduled watches

| Script | What it does | Runs in |
| --- | --- | --- |
| `vuln_report.py` | Builds the body of the rolling "fixable vulnerabilities" issue from pip-audit, Docker Scout and zizmor reports. | `vuln-report.yml` |
| `eol_watch.py` | Reports upstream end-of-life dates for the Python floor, the Debian base, the CI runner images and the Docker Engine version the project relies on. | `eol-watch.yml` |
| `compose_spec_watch.py` | Compares the Compose Specification's schema with `compose_spec_keys.json` and opens an issue when Compose adds a key. | `compose-spec-watch.yml` |
| `forgejo_smoke.py` | Runs the snippet from `docs/forgejo.md` against a throwaway Forgejo and runner (`forgejo_smoke/`). | `forgejo-smoke.yml` |
| `forgejo_smoke_bump.py` | Moves that harness to the newest Forgejo and runner releases. | `forgejo-smoke-bump.yml` |

## Docs site

| Script | What it does | Runs in |
| --- | --- | --- |
| `mkdocs_seo_hook.py` | Derives each page's title and meta description at build time. | `mkdocs.yml` build hook |
| `mkdocs_git_dates_hook.py` | Sets each page's sitemap date from its last commit instead of the build date. | `mkdocs.yml` build hook |
| `indexnow.py` | After a docs deploy, tells Bing which pages changed so they are crawled sooner. | `docs.yml` |

## Research and demos

| Path | What it does | Runs in |
| --- | --- | --- |
| [`corpus/`](corpus/README.md) | Fetches public Compose files from GitHub and lints them. Feeds the State of Docker Compose Security report. | Local |
| `snapshot.py` | Builds or diffs the corpus regression snapshot in `tests/corpus_snapshot.json.gz`. | Local |
| [`compare/`](compare/README.md) | Fixtures and scripts behind the tool comparison in `docs/compare.md`. | Local |
| [`demo/`](demo/README.md) | Sources for the README's animated demos. | Local, `marketplace-smoke.yml` |

## Network access

The linter makes no network calls. Some of these scripts do, because their
job is to talk to another service:

- `indexnow.py` posts changed docs URLs to Bing.
- `update-dockerhub-description.sh` calls the Docker Hub API.
- `verify-dockerfile-digests.sh` reads manifest headers from the image registry.
- `verify_sarif_ingestion.py` calls the GitHub API.
- `eol_watch.py` reads endoflife.date.
- `compose_spec_watch.py` reads the Compose Specification repository.
- `forgejo_smoke.py` talks to the throwaway Forgejo it starts on localhost. `forgejo_smoke_bump.py` looks up new Forgejo releases.
- `corpus/` uses the GitHub API.
