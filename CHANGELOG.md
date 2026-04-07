# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-07

### Added

- Initial release with 5 security rules:
  - **CL-0001**: Docker socket mounted (CRITICAL)
  - **CL-0002**: Privileged mode enabled (CRITICAL)
  - **CL-0003**: Privilege escalation not blocked (WARNING)
  - **CL-0004**: Image not pinned to version (WARNING)
  - **CL-0005**: Ports bound to all interfaces (WARNING)
- Text output with colored severity levels, fix guidance, and OWASP/CIS references
- JSON output for CI integration
- Configuration via `.compose-lint.yml` (disable rules, override severity)
- CLI with `--format`, `--fail-on`, `--config`, and `--version` options
- Pre-commit hook support
- Python 3.10-3.13 support

[0.1.0]: https://github.com/tmatens/compose-lint/releases/tag/v0.1.0
