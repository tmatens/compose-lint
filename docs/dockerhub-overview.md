# compose-lint

**Security-focused linter for Docker Compose files.** Catches dangerous misconfigurations before they reach production — and auto-fixes the unambiguous ones, dry-run first. Grounded in the [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) and [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker).

In a scan of 5,417 public Docker Compose files on GitHub, **91% of those that parse had at least one security finding** — 32% had a finding rated HIGH or CRITICAL, and 10% had a CRITICAL. [Read the full *State of Docker Compose Security* report →](https://github.com/tmatens/compose-lint/blob/main/docs/state-of-compose.md)

![compose-lint scanning a docker-compose.yml: severity-sorted findings with fix guidance and reference URLs, then the FAIL verdict.](https://raw.githubusercontent.com/tmatens/compose-lint/main/docs/assets/demo.gif)

**What it catches** — 27 rules, each citing its OWASP/CIS grounding ([full rules table](https://github.com/tmatens/compose-lint#rules)):

- Privilege flaws — `privileged: true`, missing `cap_drop`, `no-new-privileges` not set, root user, host namespace sharing
- Network exposure — wildcard port binds, `network_mode: host`
- Supply-chain — unpinned images, missing digest pins
- Filesystem and credential leaks — Docker socket mounts, sensitive host paths, plaintext credentials in `environment:`

## Usage

```bash
docker run --rm -v "$(pwd):/src" composelint/compose-lint            # lint the current directory
docker run --rm -v "$(pwd):/src" composelint/compose-lint fix        # preview auto-fixes (dry-run diff)
docker run --rm -v "$(pwd):/src" composelint/compose-lint --explain CL-0001
```

Auto-detects `compose.yml` / `docker-compose.yml` variants; pass filenames to lint specific files. `fix --apply` writes the mechanically unambiguous fixes in place (atomic, re-parsed and re-linted before writing); context-dependent findings are reported for manual review, never auto-edited. Unambiguous is not harmless — the guarantee is about the edit, not the outcome, so edits that change runtime behavior (e.g. `read_only: true`) are labelled `⚠ behavior-changing` in the diff. Read those before `--apply`. Also on PyPI: `pip install compose-lint` (Python 3.11+).

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings at or above the `--fail-on` threshold (default: `high`) |
| 1 | One or more findings at or above the threshold |
| 2 | compose-lint couldn't run |

Output formats: human `text` (default), `json`, and `sarif` — SARIF uploads render findings and suggested fixes directly on GitHub pull requests. Suppressions live in a reviewable `.compose-lint.yml` with per-service reasons and stay visible in output, marked SUPPRESSED. See [configuration](https://github.com/tmatens/compose-lint/blob/main/docs/configuration.md) and [CI integration recipes](https://github.com/tmatens/compose-lint#ci-integration) (GitHub Actions, GitLab, Forgejo/Gitea, pre-commit).

## This image

- [Distroless Python](https://github.com/GoogleContainerTools/distroless) on Debian, multi-arch (`linux/amd64` + `linux/arm64`), nonroot UID 65532, no shell or package manager at runtime.
- Every release ships SLSA build provenance, Sigstore attestations, and an [OpenVEX](https://openvex.dev/) document; Docker Scout scans the published image daily.
- Tracked on [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/tmatens/compose-lint) and [OpenSSF Best Practices](https://www.bestpractices.dev/projects/12472).
- To run the container itself fully hardened, see [docs/hardening.md](https://github.com/tmatens/compose-lint/blob/main/docs/hardening.md).

## Links

[GitHub](https://github.com/tmatens/compose-lint) · [PyPI](https://pypi.org/project/compose-lint/) · [Rule docs](https://github.com/tmatens/compose-lint/tree/main/docs/rules) · [Changelog](https://github.com/tmatens/compose-lint/blob/main/CHANGELOG.md) · [Security policy](https://github.com/tmatens/compose-lint/blob/main/.github/SECURITY.md) · [MIT license](https://github.com/tmatens/compose-lint/blob/main/LICENSE)
