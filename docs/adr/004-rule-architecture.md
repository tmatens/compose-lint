# ADR-004: Rule Architecture

**Status:** Accepted

**Context:** Rules need to be individually toggleable, severity-adjustable, and easy to add.

**Decision:** Each rule is a Python class inheriting from `BaseRule`, registered via a `@register_rule` decorator. Rules declare their own ID, severity, references, and a `check()` method that yields `Finding` objects.

**Rationale:**
- This pattern (used by pylint, flake8, eslint) is proven and familiar to contributors.
- Class-based rules allow per-rule configuration via `.compose-lint.yml`.
- The yield-based approach allows rules to report multiple findings per service without complex return types.
- Auto-discovery via `pkgutil.iter_modules` means adding a new rule is just creating a file — no manual registration needed.
