# compose-lint

[![CI](https://github.com/tmatens/compose-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/tmatens/compose-lint/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/compose-lint)](https://pypi.org/project/compose-lint/)
[![Docker](https://img.shields.io/badge/docker-composelint%2Fcompose--lint-2496ED?logo=docker&logoColor=white)](https://hub.docker.com/r/composelint/compose-lint)
[![Python](https://img.shields.io/pypi/pyversions/compose-lint)](https://pypi.org/project/compose-lint/)
[![License](https://img.shields.io/github/license/tmatens/compose-lint)](LICENSE)

A security-focused linter for Docker Compose files. Catches dangerous misconfigurations before they reach production.

compose-lint targets the same niche [Hadolint](https://github.com/hadolint/hadolint) occupies for Dockerfiles: zero-config, opinionated, fast, and grounded in [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) and [CIS](https://www.cisecurity.org/benchmark/docker) standards.

## Installation

**pip**

```bash
pip install compose-lint
```

**Docker** — [composelint/compose-lint](https://hub.docker.com/r/composelint/compose-lint)

```bash
docker run --rm -v "$(pwd):/src" composelint/compose-lint
```

## Quick Start

Run without arguments to auto-detect `compose.yml`, `compose.yaml`, `docker-compose.yml`, or `docker-compose.yaml` in the current directory:

```bash
compose-lint
```

Or pass files explicitly:

```bash
compose-lint docker-compose.yml docker-compose.prod.yml
```

Docker equivalent:

```bash
docker run --rm -v "$(pwd):/src" composelint/compose-lint docker-compose.prod.yml
```

## Example Output

```
docker-compose.yml:5  CRITICAL  CL-0001  Docker socket mounted via
  '/var/run/docker.sock:/var/run/docker.sock'. This gives the container
  full control over the Docker daemon.
  service: traefik
  fix: Use a Docker socket proxy (e.g., tecnativa/docker-socket-proxy)
       to expose only the API endpoints your service needs.
  ref: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-1

docker-compose.yml:3  HIGH  CL-0005  Port '8080:80' is bound to all
  interfaces. Docker bypasses host firewalls (UFW/firewalld), potentially
  exposing this port to the public internet.
  service: web
  fix: Bind to localhost: 127.0.0.1:8080:80
  ref: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-5a

docker-compose.yml: 1 critical, 1 high
```

## Rules

| ID | Severity | Description | OWASP | CIS |
|----|----------|-------------|-------|-----|
| [CL-0001](docs/rules/CL-0001.md) | CRITICAL | Docker socket mounted | [Rule #1](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-1---do-not-expose-the-docker-daemon-socket-even-to-the-containers) | 5.31 |
| [CL-0002](docs/rules/CL-0002.md) | CRITICAL | Privileged mode enabled | [Rule #3](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-3---do-not-run-containers-with-the---privileged-flag) | 5.4 |
| [CL-0003](docs/rules/CL-0003.md) | MEDIUM | Privilege escalation not blocked | [Rule #4](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-4---add-no-new-privileges-flag) | 5.25 |
| [CL-0004](docs/rules/CL-0004.md) | MEDIUM | Image not pinned to version | [Rule #13](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-13---enhance-supply-chain-security) | 5.27 |
| [CL-0005](docs/rules/CL-0005.md) | HIGH | Ports bound to all interfaces | [Rule #5a](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-5a---be-careful-when-mapping-container-ports-to-the-host-with-firewalls-like-ufw) | 5.13 |
| [CL-0006](docs/rules/CL-0006.md) | MEDIUM | No capability restrictions | [Rule #3](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-3---limit-capabilities-grant-only-specific-capabilities-needed-by-a-container) | 5.3 |
| [CL-0007](docs/rules/CL-0007.md) | MEDIUM | Filesystem not read-only | [Rule #8](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-8---set-filesystem-and-volumes-to-read-only) | 5.12 |
| [CL-0008](docs/rules/CL-0008.md) | HIGH | Host network mode | [Rule #5](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-5---be-mindful-of-inter-container-connectivity) | 5.9 |
| [CL-0009](docs/rules/CL-0009.md) | HIGH | Security profile disabled | [Rule #6](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-6---use-linux-security-module-seccomp-apparmor-or-selinux) | 5.21 |
| [CL-0010](docs/rules/CL-0010.md) | HIGH | Host namespace sharing | [Rule #3](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-3---limit-capabilities-grant-only-specific-capabilities-needed-by-a-container) | 5.8, 5.15, 5.16, 5.21 |
| [CL-0011](docs/rules/CL-0011.md) | HIGH | Dangerous capabilities added | [Rule #3](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-3---limit-capabilities-grant-only-specific-capabilities-needed-by-a-container) | 5.5 |
| [CL-0012](docs/rules/CL-0012.md) | MEDIUM | PIDs cgroup limit disabled | — | 5.29 |
| [CL-0013](docs/rules/CL-0013.md) | HIGH | Sensitive host path mounted | [Rule #8](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-8---set-filesystem-and-volumes-to-read-only) | 5.5 |
| [CL-0014](docs/rules/CL-0014.md) | MEDIUM | Logging driver disabled | — | 5.x |
| [CL-0015](docs/rules/CL-0015.md) | LOW | Healthcheck disabled | — | 4.6, 5.27 |
| [CL-0016](docs/rules/CL-0016.md) | HIGH | Dangerous host device exposed | — | 5.18 |
| [CL-0017](docs/rules/CL-0017.md) | MEDIUM | Shared mount propagation | — | 5.20 |
| [CL-0018](docs/rules/CL-0018.md) | MEDIUM | Explicit root user | [Rule #7](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-7---do-not-run-containers-with-a-root-user) | 5.x |
| [CL-0019](docs/rules/CL-0019.md) | MEDIUM | Image tag without digest | [Rule #13](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-13---enhance-supply-chain-security) | 5.27 |

## Severity Levels

Findings are rated **LOW**, **MEDIUM**, **HIGH**, or **CRITICAL** based on exploitability and impact scope. See [docs/severity.md](docs/severity.md) for the full scoring matrix.

## Configuration

Create `.compose-lint.yml` to disable rules or adjust severity:

```yaml
rules:
  CL-0001:
    enabled: false
  CL-0003:
    enabled: false
    reason: "SEC-1234 — Approved by J. Smith, expires 2026-07-01"
  CL-0005:
    severity: medium
```

Disabled rules still run — findings appear as **SUPPRESSED** without affecting the exit code. The `reason` field is surfaced in all output formats:

- **Text**: shown after the `SUPPRESSED` label
- **JSON**: `suppression_reason` field
- **SARIF**: `suppressions[].justification` (recognized by GitHub Code Scanning)

To hide suppressed findings from output:

```bash
compose-lint --skip-suppressed docker-compose.yml
```

## CLI Reference

```
compose-lint [OPTIONS] [FILE ...]

  --format {text,json,sarif}  Output format (default: text)
  --fail-on SEVERITY          Minimum severity to trigger exit 1 (default: high)
  --skip-suppressed           Hide suppressed findings from output
  --config PATH               Path to config file (default: .compose-lint.yml)
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

The easiest path — runs compose-lint and uploads findings to GitHub Code Scanning:

```yaml
# .github/workflows/lint.yml
name: Compose Lint
on: [push, pull_request]

jobs:
  compose-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: tmatens/compose-lint@v0.3.3
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
    rev: v0.3.3
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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and how to add rules.

## License

[MIT](LICENSE)
