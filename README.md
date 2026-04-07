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
compose-lint docker-compose.yml
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

docker-compose.yml:3  WARNING  CL-0005  Port '8080:80' is bound to all
  interfaces. Docker bypasses host firewalls (UFW/firewalld), potentially
  exposing this port to the public internet.
  service: web
  fix: Bind to localhost: 127.0.0.1:8080:80
  ref: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-5a

docker-compose.yml: 1 critical, 1 warning
```

## Rules

| ID | Severity | Description | Reference |
|----|----------|-------------|-----------|
| [CL-0001](docs/rules/CL-0001.md) | CRITICAL | Docker socket mounted | [OWASP Rule #1](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-1---do-not-expose-the-docker-daemon-socket-even-to-the-containers) |
| [CL-0002](docs/rules/CL-0002.md) | CRITICAL | Privileged mode enabled | [OWASP Rule #3](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-3---do-not-run-containers-with-the---privileged-flag) |
| [CL-0003](docs/rules/CL-0003.md) | WARNING | Privilege escalation not blocked | [OWASP Rule #4](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-4---add-no-new-privileges-flag) |
| [CL-0004](docs/rules/CL-0004.md) | WARNING | Image not pinned to version | [OWASP Rule #13](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-13---enhance-supply-chain-security) |
| [CL-0005](docs/rules/CL-0005.md) | WARNING | Ports bound to all interfaces | [OWASP Rule #5a](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-5a---be-careful-when-mapping-container-ports-to-the-host-with-firewalls-like-ufw) |

## Configuration

Create a `.compose-lint.yml` to disable rules or adjust severity:

```yaml
rules:
  CL-0001:
    enabled: false          # Disable a rule
  CL-0005:
    severity: error         # Promote to error
```

```bash
compose-lint --config .compose-lint.yml docker-compose.yml
```

## CLI Options

```
compose-lint [OPTIONS] FILE [FILE...]

  --format {text,json}    Output format (default: text)
  --fail-on SEVERITY      Minimum severity to trigger exit 1 (default: error)
  --config PATH           Path to .compose-lint.yml config file
  --version               Show version and exit
```

## CI Integration

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
