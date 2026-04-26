# compose-lint

[![CI](https://github.com/tmatens/compose-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/tmatens/compose-lint/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/compose-lint)](https://pypi.org/project/compose-lint/)
[![Docker](https://img.shields.io/badge/docker-composelint%2Fcompose--lint-2496ED?logo=docker&logoColor=white)](https://hub.docker.com/r/composelint/compose-lint)
[![Python](https://img.shields.io/pypi/pyversions/compose-lint)](https://pypi.org/project/compose-lint/)
[![License](https://img.shields.io/github/license/tmatens/compose-lint)](https://github.com/tmatens/compose-lint/blob/main/LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/tmatens/compose-lint/badge)](https://scorecard.dev/viewer/?uri=github.com/tmatens/compose-lint)
[![OpenSSF Baseline 2](https://www.bestpractices.dev/projects/12472/baseline)](https://www.bestpractices.dev/projects/12472)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12472/badge)](https://www.bestpractices.dev/projects/12472)

A security-focused linter for `docker-compose.yml` and `compose.yaml`. Catches dangerous misconfigurations before they reach production.

In a scan of 1,405 public `docker-compose.yml` files on GitHub, **78% had at least one security finding** (45% HIGH or CRITICAL) — virtually all of those skip basic capability restrictions, 33% deploy images without a pinned digest, and 43% bind ports to all interfaces. compose-lint catches these in CI before they ship.

Use it if you ship Compose to production, to ensure defense in depth in a homelab, or want a fast pre-merge gate on IaC. Same niche [Hadolint](https://github.com/hadolint/hadolint) occupies for Dockerfiles and [dclint](https://github.com/zavoloklom/docker-compose-linter) occupies for Compose schema and structure: zero-config, opinionated, fast, and grounded in [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) and [CIS](https://www.cisecurity.org/benchmark/docker) standards.

## Example Output

Given this `docker-compose.yml`:

```yaml
services:
  traefik:
    image: traefik:v3.0@sha256:aaaabbbbccccddddeeeeffff00001111222233334444555566667777888899990
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    ports:
      - "8080:80"
```

and this `.compose-lint.yml` (suppressing CL-0001 for `traefik` with a tracked reason):

```yaml
rules:
  CL-0001:
    exclude_services:
      traefik: "SEC-1234 approved — socket proxy planned for 2026-Q3"
```

running `compose-lint docker-compose.yml` produces:

```
compose-lint 0.5.2
files: docker-compose.yml  ·  config: .compose-lint.yml  ·  fail-on: high

docker-compose.yml

  service: traefik  (line 9)
       9  SUPPRESSED  CL-0001  Docker socket mounted via '/var/run/docker.sock:/var/run/docker.sock'. This gives the container full control over the Docker daemon.
          reason: SEC-1234 approved — socket proxy planned for 2026-Q3
       9  HIGH      CL-0013  Service mounts sensitive host path '/var/run/docker.sock' (under /var/run). This exposes host system files to the container.
          9 │       - /var/run/docker.sock:/var/run/docker.sock
            │         ^^^^^^^^^^^^^^^^^^^^
          fix: Remove the bind mount for /var/run/docker.sock. If the container needs specific files, copy them into the image at build time or use a named volume with only the required data.
          ref: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-8---set-filesystem-and-volumes-to-read-only
      11  HIGH      CL-0005  Port '8080:80' is bound to all interfaces. Docker bypasses host firewalls (UFW/firewalld), potentially exposing this port to the public internet.
          11 │       - "8080:80"
             │          ^^^^^^^
          fix: Bind to localhost: 127.0.0.1:8080:80
               If public access is needed, use a reverse proxy with TLS.
          ref: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-5a---be-careful-when-mapping-container-ports-to-the-host-with-firewalls-like-ufw

docker-compose.yml: 2 high  ·  1 suppressed (not counted)
✗ FAIL  ·  2 findings at or above high
```

Exit code is `1` (two findings at or above the default `--fail-on high` threshold). Suppressed findings are shown for auditability but do not count toward the threshold. Findings are grouped by service; the fix block and reference URL print only once per rule id per file — pass `-v` / `--verbose` to repeat them on every finding.

## Installation

**pip**

```bash
pip install compose-lint
```

**Docker** — [composelint/compose-lint](https://hub.docker.com/r/composelint/compose-lint)

```bash
docker run --rm -v "$(pwd):/src" composelint/compose-lint
```

The Docker image is distroless, multi-arch, and runs nonroot — see [Security posture](#security-posture) below for SLSA, Sigstore, and OpenVEX details.

## Quick Start

Run without arguments to auto-detect `compose.yml`, `compose.yaml`, `docker-compose.yml`, or `docker-compose.yaml` in the current directory:

```bash
compose-lint
```

Or pass files explicitly:

```bash
compose-lint docker-compose.yml docker-compose.prod.yml
```

Don't recognize a rule ID in the output? `--explain` prints the full rule doc — what it catches, why it matters, the fix, and the OWASP/CIS reference — without leaving the terminal:

```bash
compose-lint --explain CL-0005
```

Docker equivalent:

```bash
docker run --rm -v "$(pwd):/src" composelint/compose-lint docker-compose.prod.yml
```

### Compose compatibility

compose-lint targets the [Compose Specification](https://github.com/compose-spec/compose-spec) used by Compose v2 and v3. Compose v1 files (services declared at the top level) are skipped with a stderr note rather than failing the run — Docker [retired Compose v1 in 2023](https://www.docker.com/blog/new-docker-compose-v2-and-v1-deprecation/). Structural fragments (files containing only `volumes:` / `networks:` / `configs:` / `secrets:` / `x-*` keys, typically merged via `-f overlay.yml`) are skipped for the same reason. Genuinely unrecognised shapes still exit 2.

Python 3.10+ is required for the pip install path; the Docker image is self-contained.

## Rules

| ID | Severity | Description | OWASP | CIS |
|----|----------|-------------|-------|-----|
| [CL-0001](https://github.com/tmatens/compose-lint/blob/main/docs/rules/CL-0001.md) | CRITICAL | Docker socket mounted | [Rule #1](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-1---do-not-expose-the-docker-daemon-socket-even-to-the-containers) | 5.31 |
| [CL-0002](https://github.com/tmatens/compose-lint/blob/main/docs/rules/CL-0002.md) | CRITICAL | Privileged mode enabled | [Rule #3](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-3---do-not-run-containers-with-the---privileged-flag) | 5.4 |
| [CL-0003](https://github.com/tmatens/compose-lint/blob/main/docs/rules/CL-0003.md) | MEDIUM | Privilege escalation not blocked | [Rule #4](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-4---add-no-new-privileges-flag) | 5.25 |
| [CL-0004](https://github.com/tmatens/compose-lint/blob/main/docs/rules/CL-0004.md) | MEDIUM | Image not pinned to version | [Rule #13](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-13---enhance-supply-chain-security) | 5.27 |
| [CL-0005](https://github.com/tmatens/compose-lint/blob/main/docs/rules/CL-0005.md) | HIGH | Ports bound to all interfaces | [Rule #5a](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-5a---be-careful-when-mapping-container-ports-to-the-host-with-firewalls-like-ufw) | 5.13 |
| [CL-0006](https://github.com/tmatens/compose-lint/blob/main/docs/rules/CL-0006.md) | MEDIUM | No capability restrictions | [Rule #3](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-3---limit-capabilities-grant-only-specific-capabilities-needed-by-a-container) | 5.3 |
| [CL-0007](https://github.com/tmatens/compose-lint/blob/main/docs/rules/CL-0007.md) | MEDIUM | Filesystem not read-only | [Rule #8](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-8---set-filesystem-and-volumes-to-read-only) | 5.12 |
| [CL-0008](https://github.com/tmatens/compose-lint/blob/main/docs/rules/CL-0008.md) | HIGH | Host network mode | [Rule #5](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-5---be-mindful-of-inter-container-connectivity) | 5.9 |
| [CL-0009](https://github.com/tmatens/compose-lint/blob/main/docs/rules/CL-0009.md) | HIGH | Security profile disabled | [Rule #6](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-6---use-linux-security-module-seccomp-apparmor-or-selinux) | 5.21 |
| [CL-0010](https://github.com/tmatens/compose-lint/blob/main/docs/rules/CL-0010.md) | HIGH | Host namespace sharing | [Rule #3](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-3---limit-capabilities-grant-only-specific-capabilities-needed-by-a-container) | 5.8, 5.15, 5.16, 5.21 |
| [CL-0011](https://github.com/tmatens/compose-lint/blob/main/docs/rules/CL-0011.md) | HIGH | Dangerous capabilities added | [Rule #3](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-3---limit-capabilities-grant-only-specific-capabilities-needed-by-a-container) | 5.5 |
| [CL-0012](https://github.com/tmatens/compose-lint/blob/main/docs/rules/CL-0012.md) | MEDIUM | PIDs cgroup limit disabled | — | 5.29 |
| [CL-0013](https://github.com/tmatens/compose-lint/blob/main/docs/rules/CL-0013.md) | HIGH | Sensitive host path mounted | [Rule #8](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-8---set-filesystem-and-volumes-to-read-only) | 5.5 |
| [CL-0014](https://github.com/tmatens/compose-lint/blob/main/docs/rules/CL-0014.md) | MEDIUM | Logging driver disabled | — | 5.x |
| [CL-0015](https://github.com/tmatens/compose-lint/blob/main/docs/rules/CL-0015.md) | LOW | Healthcheck disabled | — | 4.6, 5.27 |
| [CL-0016](https://github.com/tmatens/compose-lint/blob/main/docs/rules/CL-0016.md) | HIGH | Dangerous host device exposed | — | 5.18 |
| [CL-0017](https://github.com/tmatens/compose-lint/blob/main/docs/rules/CL-0017.md) | MEDIUM | Shared mount propagation | — | 5.20 |
| [CL-0018](https://github.com/tmatens/compose-lint/blob/main/docs/rules/CL-0018.md) | MEDIUM | Explicit root user | [Rule #7](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-7---do-not-run-containers-with-a-root-user) | 5.x |
| [CL-0019](https://github.com/tmatens/compose-lint/blob/main/docs/rules/CL-0019.md) | MEDIUM | Image tag without digest | [Rule #13](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-13---enhance-supply-chain-security) | 5.27 |

## Severity Levels

Findings are rated **LOW**, **MEDIUM**, **HIGH**, or **CRITICAL** based on exploitability and impact scope. See [docs/severity.md](https://github.com/tmatens/compose-lint/blob/main/docs/severity.md) for the full scoring matrix.

## Configuration

Create `.compose-lint.yml` to disable rules, exclude specific services, or adjust severity:

```yaml
rules:
  CL-0001:
    enabled: false
    reason: "SEC-1234 — approved 2026-07-01"
  CL-0003:
    exclude_services:
      minecraft: "entrypoint switches users via su-exec"
  CL-0005:
    severity: medium
```

Disabled and excluded findings still appear marked **SUPPRESSED** with the `reason` flowing to JSON's `suppression_reason` and SARIF's `justification` (recognized by GitHub Code Scanning) — they do not affect exit code. Pass `--skip-suppressed` to hide them.

See [docs/configuration.md](https://github.com/tmatens/compose-lint/blob/main/docs/configuration.md) for per-service exclusion semantics, precedence rules, and the full output-format mapping.

## CLI Reference

```
compose-lint [OPTIONS] [FILE ...]

  --format {text,json,sarif}  Output format (default: text)
  --fail-on SEVERITY          Minimum severity to trigger exit 1 (default: high)
  --skip-suppressed           Hide suppressed findings from output
  --config PATH               Path to config file (default: .compose-lint.yml)
  --explain CL-XXXX           Print the full documentation for a single rule
  --version                   Show version and exit
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings at or above the `--fail-on` threshold |
| 1 | One or more findings at or above the `--fail-on` threshold |
| 2 | Usage error (invalid args, file not found, invalid Compose file) |

The default threshold is `high` — medium and low findings don't fail CI unless you opt in:

```bash
compose-lint --fail-on low docker-compose.yml   # fail on everything
compose-lint --fail-on critical docker-compose.yml  # only critical
```

## CI Integration

### GitHub Actions

The easiest path — runs compose-lint and uploads findings to GitHub Code Scanning. Pinned to immutable SHAs for reproducible CI; [Renovate](https://docs.renovatebot.com/) keeps the pins current:

```yaml
# .github/workflows/lint.yml
name: Compose Lint
on: [push, pull_request]

jobs:
  compose-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - uses: tmatens/compose-lint@93e1c0dea75f123171f00d29f3d238080fbb6d04 # v0.5.2
        with:
          sarif-file: results.sarif
```

Or install from PyPI directly:

```yaml
      - uses: actions/setup-python@v6
        with:
          python-version: "3.13"
      - run: pip install compose-lint
      - run: compose-lint docker-compose.yml
```

### SARIF output

```bash
compose-lint --format sarif docker-compose.yml > results.sarif
```

## Pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/tmatens/compose-lint
    rev: v0.5.2
    hooks:
      - id: compose-lint
```

## How it compares

| Tool | Compose security rules | Scope | Zero config |
|------|----------------------|-------|-------------|
| **compose-lint** | Yes | Docker Compose | Yes |
| **KICS** | Yes | Broad IaC (Terraform, K8s, Compose, ...) | No |
| **Hadolint** | No — Dockerfile only | Dockerfile | Yes |
| **dclint** | Yes — schema/structure only | Docker Compose | Yes |
| **Trivy** | No — Dockerfile + image scanning | Dockerfiles, images, repos | Yes |
| **Checkov** | No — no Compose support | Broad IaC (Terraform, K8s, ...) | No |

If you need broad IaC coverage across Terraform, Kubernetes, and more, KICS covers Docker Compose and is worth evaluating. If you want a lightweight, focused tool with zero config and actionable fix guidance for Compose files specifically, this is it.

**Not in scope**: compose-lint does not validate Compose schema, scan images for CVEs, lint Dockerfiles, or rewrite files. Pair it with [dclint](https://github.com/zavoloklom/docker-compose-linter) for schema/structure, [Hadolint](https://github.com/hadolint/hadolint) for Dockerfiles, and [Trivy](https://github.com/aquasecurity/trivy) for image CVEs.

## Security posture

compose-lint is built to be safe to depend on:

- **Runtime image**: [distroless Python](https://github.com/GoogleContainerTools/distroless) on Debian, multi-arch (`linux/amd64` + `linux/arm64`), nonroot UID 65532, no shell or package manager at runtime. See [ADR-009](https://github.com/tmatens/compose-lint/blob/main/docs/adr/009-runtime-base-image.md).
- **Supply chain**: every release ships SLSA build provenance and Sigstore attestations. Published to PyPI via Trusted Publishers (OIDC) — no manual `twine upload`, no long-lived API tokens.
- **Vulnerability transparency**: each release ships an [OpenVEX](https://openvex.dev/) document declaring known pip CVEs `not_affected` with justification `vulnerable_code_not_present` — pip code is stripped from the runtime venv and only `.dist-info` metadata is retained for SCA scanner attribution.
- **External audit**: tracked on [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/tmatens/compose-lint) and [OpenSSF Best Practices Baseline 2](https://www.bestpractices.dev/projects/12472); CodeQL, Docker Scout, and ClusterFuzzLite run on every PR.
- **Reporting vulnerabilities**: see [SECURITY.md](https://github.com/tmatens/compose-lint/blob/main/.github/SECURITY.md).

## Contributing

See [CONTRIBUTING.md](https://github.com/tmatens/compose-lint/blob/main/CONTRIBUTING.md) for development setup and how to add rules.

## License

[MIT](https://github.com/tmatens/compose-lint/blob/main/LICENSE)
