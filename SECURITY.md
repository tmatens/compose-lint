# Security Policy

## Supported Versions

compose-lint follows semantic versioning. Only the latest minor release receives
security fixes.

| Version | Supported |
| ------- | --------- |
| 0.3.x   | Yes       |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use GitHub's private vulnerability reporting:

1. Go to <https://github.com/tmatens/compose-lint/security/advisories/new>
2. Submit a report with reproduction steps and impact

You should receive an acknowledgement within 7 days. If the report is valid, a fix
will be coordinated and released, and the advisory will be published with credit
unless you request otherwise.

## Scope

In scope:

- Code execution or information disclosure via crafted Compose files
- Tampering with the published PyPI package or GitHub Action
- Vulnerabilities in dependencies that are exploitable via compose-lint

Out of scope:

- False positives or false negatives in security rules — file these as normal
  issues
- Findings against vulnerable Compose files in `tests/compose_files/` (these are
  intentionally insecure fixtures)

## Supply Chain

- PyPI releases use [Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
  via GitHub Actions OIDC. No long-lived API tokens exist.
- Releases include [Sigstore build attestations](https://docs.pypi.org/attestations/).
  Verify with `pip install compose-lint --require-hashes` plus the published
  attestation.
- Dependencies are kept current by Renovate. CodeQL and OpenSSF Scorecard run
  on every push and weekly.
