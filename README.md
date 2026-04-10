```
                                                 __ _       __
  _________  ____ ___  ____  ____  ________     / /(_)___  / /_
 / ___/ __ \/ __ `__ \/ __ \/ __ \/ ___/ _ \   / // / __ \/ __/
/ /__/ /_/ / / / / / / /_/ / /_/ (__  )  __/  / // / / / / /_
\___/\____/_/ /_/ /_/ .___/\____/____/\___/  /_//_/_/ /_/\__/
                   /_/
```

[![CI](https://github.com/tmatens/compose-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/tmatens/compose-lint/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/compose-lint)](https://pypi.org/project/compose-lint/)
[![Python](https://img.shields.io/pypi/pyversions/compose-lint)](https://pypi.org/project/compose-lint/)
[![License](https://img.shields.io/github/license/tmatens/compose-lint)](LICENSE)

A security-focused linter for Docker Compose files. Catches dangerous misconfigurations before they reach production.

compose-lint targets the same niche [Hadolint](https://github.com/hadolint/hadolint) occupies for Dockerfiles: zero-config, opinionated, fast, and grounded in [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) and [CIS](https://www.cisecurity.org/benchmark/docker) standards.

## Quick Start

```bash
pip install compose-lint
compose-lint
```

When run without arguments, compose-lint automatically finds `compose.yml`, `compose.yaml`, `docker-compose.yml`, or `docker-compose.yaml` in the current directory. You can also pass files explicitly:

```bash
compose-lint docker-compose.yml docker-compose.prod.yml
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
| [CL-0010](docs/rules/CL-0010.md) | HIGH | Host namespace sharing | [Rule #3](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-3---limit-capabilities-grant-only-specific-capabilities-needed-by-a-container) | 5.8, 5.15, 5.16 |

## Severity Levels

Findings are rated **LOW**, **MEDIUM**, **HIGH**, or **CRITICAL** based on exploitability and impact scope. See [docs/severity.md](docs/severity.md) for the full scoring matrix.

Defaults are opinionated. Override any rule's severity in `.compose-lint.yml` if they don't match your environment.

## Configuration

Create a `.compose-lint.yml` to disable rules or adjust severity:

```yaml
rules:
  CL-0001:
    enabled: false          # Disable a rule
  CL-0003:
    enabled: false
    reason: "SEC-1234 — Approved by J. Smith, expires 2026-07-01"
  CL-0005:
    severity: medium        # Downgrade to medium
```

Disabled rules still run — their findings appear as **SUPPRESSED** in the output without affecting the exit code. This gives reviewers and auditors visibility into what's being intentionally skipped.

The optional `reason` field records why a rule was disabled (e.g., an exception ticket number). It appears in all output formats:

- **Text**: shown after the `SUPPRESSED` label
- **JSON**: `suppression_reason` field
- **SARIF**: native `suppressions[].justification` (recognized by GitHub Code Scanning)

To hide suppressed findings entirely:

```bash
compose-lint --skip-suppressed docker-compose.yml
```

```bash
compose-lint --config .compose-lint.yml docker-compose.yml
```

## CLI Options

```
compose-lint [OPTIONS] [FILE ...]

  --format {text,json,sarif}  Output format (default: text)
  --fail-on SEVERITY          Minimum severity to trigger exit 1 (default: high)
  --skip-suppressed           Hide suppressed findings from output
  --config PATH               Path to .compose-lint.yml config file
  --version                   Show version and exit
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings at or above the `--fail-on` threshold |
| 1 | One or more findings at or above the `--fail-on` threshold |
| 2 | Usage error (invalid args, file not found, invalid Compose file) |

The default threshold is `high`. This means **medium and low findings do not cause a non-zero exit** — you can adopt compose-lint gradually without blocking CI on every finding immediately. To fail on all findings:

```bash
compose-lint --fail-on low docker-compose.yml
```

To only fail on critical issues (container escape, host compromise):

```bash
compose-lint --fail-on critical docker-compose.yml
```

## CI Integration

### GitHub Action

```yaml
# .github/workflows/lint.yml
name: Compose Lint
on: [push, pull_request]

jobs:
  compose-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: tmatens/compose-lint@main
        with:
          sarif-file: results.sarif
```

This runs compose-lint and uploads findings to GitHub Code Scanning, where they appear as annotations on pull requests.

### Manual setup

```yaml
# .github/workflows/lint.yml
name: Compose Lint
on: [push, pull_request]

jobs:
  compose-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v6
        with:
          python-version: "3.13"
      - run: pip install compose-lint
      - run: compose-lint docker-compose.yml
```

### SARIF output for Code Scanning

```bash
compose-lint --format sarif docker-compose.yml > results.sarif
```

## Pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/tmatens/compose-lint
    rev: v0.1.0
    hooks:
      - id: compose-lint
```

## Why not KICS/Checkov?

Those are excellent tools for full infrastructure scanning across Terraform, Kubernetes, Dockerfiles, and more. compose-lint solves a narrower problem:

- **Zero config**: `pip install && compose-lint file.yml`. No policies to write, no plugins to configure.
- **Compose-specific**: Every rule is designed for Docker Compose semantics, not adapted from a generic policy engine.
- **Actionable output**: Every finding includes specific fix guidance and a direct link to the OWASP/CIS reference.
- **Fast**: Sub-second for any compose file. No container runtime needed.

If you're already using KICS or Checkov and happy with the coverage, you don't need this. If you want a lightweight, focused tool for Compose files specifically, this is it.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and how to add rules.

## License

[MIT](LICENSE)
