# ADR-005: Rule ID Scheme

**Status:** Accepted

**Context:** Need a stable, extensible ID scheme that doesn't conflict with other tools.

**Decision:** `CL-XXXX` where CL = Compose Lint, XXXX = zero-padded number. IDs are never reused.

**Alternatives rejected:**

- **Reuse Hadolint's DL prefix:** DL rules are Dockerfile-specific. Sharing a prefix creates confusion.
- **Use CIS benchmark IDs:** Our rules map *to* CIS references but aren't 1:1. Using their IDs implies official endorsement.
- **Use OWASP rule numbers:** Same problem — OWASP rules are broad controls, not individual lint checks.

**Rationale:**
- Own namespace avoids conflicts with every other tool.
- Matches conventions of Hadolint (DL), Dockle (CIS-DI), ShellCheck (SC).
- Stable IDs allow `.compose-lint.yml` ignore lists that survive upgrades.
- Each finding includes the OWASP/CIS reference it maps to, so users can trace authority without ID collisions.
