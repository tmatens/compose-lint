# ADR-010: Per-Service Rule Overrides

**Status:** Accepted

**Context:** `.compose-lint.yml` currently configures rules globally (enable/disable, severity override, reason). In multi-service compose files different services have different security profiles — a rule may be valid for one service and architecturally impossible for another. The example in issue #5 is CL-0003 (`no-new-privileges`): valid for a web service, but incompatible with a service whose entrypoint switches users via `su-exec`/`gosu`. Today the user chooses between losing the valid finding (global disable) or tolerating unactionable noise (leave enabled). Neither is the right answer.

**Decision:** Extend the existing rule-centric config shape with a per-rule `exclude_services` field. No new top-level section. Excluded services still produce findings, but the findings are marked suppressed with the per-service reason — matching the existing suppression semantics in CLAUDE.md.

**Schema:**

```yaml
rules:
  CL-0003:
    exclude_services:
      minecraft: "entrypoint switches users via su-exec"
      backup: "forks as different user"
  CL-0007:
    exclude_services:
      - legacy-worker   # list form when no reason is needed
```

- Mapping form (service → reason string): reason flows to `suppression_reason` (JSON), `justification` (SARIF), and the text formatter's `SUPPRESSED` trailer, consistent with global suppression.
- List form (service names only): shorthand when the user doesn't want to record a reason. Findings still suppressed, no justification emitted.
- Both forms accepted under the same key; type of the value decides the parse path.
- Service names are matched exactly. Glob patterns are deferred until someone asks for them — keeps the v0.4 surface area small and reversible.

**Interaction with existing config:**

- Global `enabled: false` wins. If a rule is globally disabled, per-service overrides are ignored (all findings are already suppressed).
- Global `severity:` override applies uniformly; per-service severity overrides are out of scope for v0.4 (YAGNI — issue #5 only asks for exclusion).
- Unknown service names in `exclude_services` produce a warning on stderr, not an error. Compose files are edited independently of config; a stale entry shouldn't break the linter.

**Alternatives rejected:**

- **Service-centric schema** (`services.<name>.rules.CL-XXXX.enabled: false`): reads naturally but duplicates the rule-config vocabulary and creates a parallel config surface. Two places to look for "why is this rule not firing" is worse than one.
- **Both shapes (hybrid):** two parsers, two sets of inheritance semantics to document, users pick the wrong one. The existing `rules:` top-level is already the source of truth — extend it, don't fork it.
- **Inline suppression comments** in the Compose file itself (`# compose-lint: ignore CL-0003`): explicitly forbidden by CLAUDE.md ("No inline suppression syntax unless explicitly planned"). Keeping suppression in `.compose-lint.yml` preserves the single-source-of-truth model.
- **Glob patterns on day one:** solves a hypothetical problem. Adding them later is additive and non-breaking.

**Rationale:**

- Rule-centric shape extends `config.py`'s existing `_parse_rules` with one branch; no new top-level keys, no new config file conventions for users to learn.
- Per-service reasons reuse the suppression plumbing that already flows to SARIF `justification` and JSON `suppression_reason`. No new output-format work.
- Producing suppressed-but-visible findings (rather than silently dropping them) preserves auditability — users can see that compose-lint saw the issue and was explicitly told to ignore it, which matters for security review and for catching stale suppressions.
- Exact-match service names cover the motivating case in issue #5 without committing to glob semantics that later turn out to be wrong.

**Known limitation — granularity is rule+service, not per-finding:**

Several rules can fire multiple times within a single service (CL-0004, CL-0005, CL-0011, CL-0013, CL-0016, CL-0017 iterate over ports, mounts, capabilities, or devices). This ADR suppresses all findings for a given rule+service pair; it cannot suppress one port on a service while keeping another visible on the same service.

This is accepted for v0.4. Issue #5's motivating cases are architectural ("this rule does not apply to this service at all"), which rule+service granularity handles cleanly. Finer granularity would require either per-rule discriminator vocabulary in config (`exclude_ports:`, `exclude_mounts:`, …) — which balloons the config surface — or inline suppression comments, which CLAUDE.md currently forbids. Both are larger policy changes and are parked until a user requests finer control.

**Implementation notes (non-binding):**

- `config.py`: extend `load_config` return type to include a third map, `excluded: dict[str, dict[str, str | None]]` (rule_id → service → reason).
- `engine.py`: after a rule produces a finding, if `finding.service in excluded[rule_id]`, mark the finding suppressed and attach the reason. Follows the same code path as global suppression.
- Rules receive plain Python types (per ADR-004) and remain unaware of the config layer — all suppression happens in the engine.
- Test matrix must cover: mapping form, list form, mixed global-disable + per-service (global wins), unknown service warning, and the three output formatters.
