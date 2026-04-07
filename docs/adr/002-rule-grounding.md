# ADR-002: Rule Grounding in OWASP and CIS

**Status:** Accepted

**Context:** Rules need to be authoritative, not opinion-based.

**Decision:** Every rule maps to at least one of: OWASP Docker Security Cheat Sheet, CIS Docker Benchmark, or Docker official documentation.

**Rationale:**
- Citing OWASP/CIS in output gives users confidence the findings are industry-standard.
- When users question a rule, the reference link ends the debate.
- This matches Hadolint's approach — its DL rules reference Docker's official best practices.
