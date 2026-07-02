"""Security profile catalog (see docs/adr/017-security-profile-catalog.md).

This package holds the canonical profile JSON Schema under ``schema/`` and, in
follow-up PRs, the loader and the bundled catalog. No runtime behavior is wired
to it yet: ADR-017 ships the contract (schema + validation) only.
"""
