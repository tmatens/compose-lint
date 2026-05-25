# Configuration

compose-lint reads `.compose-lint.yml` from the current working directory by default. Use `--config PATH` to point at a different file.

## Disabling and adjusting rules

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

`enabled: false` keeps the rule running but marks every finding **SUPPRESSED**. Suppressed findings do not count toward the `--fail-on` threshold but remain visible for auditability. The `reason` field is surfaced in every output format:

- **Text**: shown after the `SUPPRESSED` label.
- **JSON**: `suppression_reason` field on each finding.
- **SARIF**: `suppressions[].justification` (recognized by GitHub Code Scanning).

To hide suppressed findings entirely:

```bash
compose-lint --skip-suppressed docker-compose.yml
```

## Per-service exclusions

When a rule is valid for some services but architecturally incompatible with others (e.g. CL-0003 `no-new-privileges` and an image whose entrypoint switches users), use `exclude_services` to suppress it only where needed:

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

Excluded services still produce **SUPPRESSED** findings, with the per-service reason flowing to `suppression_reason` / SARIF `justification` — same shape as a global disable.

### Behaviour

- **Exact-match** service names. Unknown names produce a stderr warning but do not error, since Compose files and config evolve independently.
- **Global `enabled: false` wins** over per-service exclusions: if a rule is disabled globally, every service is suppressed regardless of `exclude_services`.
- **No inline suppression syntax** — there is no `# compose-lint: disable` comment form. Suppressions are tracked in config so reviewers can audit them.

## Validation

A `.compose-lint.yml` that silently fails to take effect is a security risk — the user believes a rule is suppressed or re-tuned when it is not. compose-lint validates the file on load:

- **Unknown rule IDs warn.** `rules:` keys are checked against the registered rule set. A typo (`CL-001`) or a retired ID (`CL-9999`) prints a stderr warning so the override isn't silently dropped.
- **Unknown top-level keys warn.** Only `rules` is recognized at the top level. A misplaced CLI flag (e.g. a top-level `fail_on:`) or any other key warns instead of being ignored.
- **Unknown per-rule keys warn.** Inside a rule block, only `enabled`, `reason`, `severity`, and `exclude_services` are recognized. A typo'd `severty:` warns.
- **`enabled` must be a real boolean.** A quoted `'false'`, `0`, or any non-boolean is a **hard error** (exit 2), not a silent no-op that would leave the rule on. YAML's boolean keywords (`true`/`false`, `yes`/`no`, `on`/`off`) all parse to a real boolean and work as expected.

Warnings never change the exit code; only the hard errors above do.

## Output formats

`--format` selects the output (`text` default, `json`, `sarif`). Text writes a human banner, per-file summary, and verdict; `json` and `sarif` emit only the machine document on stdout so redirects stay clean.

### JSON

JSON output is a versioned envelope (see [ADR-015](adr/015-machine-readable-output-contract.md)):

```json
{
  "version": "1",
  "tool": { "name": "compose-lint", "version": "0.8.0" },
  "findings": [
    {
      "file": "docker-compose.yml",
      "line": 5,
      "rule_id": "CL-0001",
      "severity": "critical",
      "service": "proxy",
      "message": "...",
      "fix": "...",
      "references": ["..."],
      "suppressed": false
    }
  ],
  "errors": [
    { "file": "broken.yml", "message": "missing 'services' key" }
  ]
}
```

- `version` is the envelope schema version. New top-level fields are added without bumping it; a bump signals a breaking change.
- `findings[]` carries one object per finding; `suppression_reason` is present only on suppressed findings.
- `errors[]` lists files that failed to parse (exit 2). Files skipped as not-applicable (Compose v1 / fragments, [ADR-013](adr/013-missing-services-key.md)) are not errors and do not appear here.

### SARIF

`--format sarif` emits a SARIF 2.1.0 log for GitHub Code Scanning. Parse failures appear as `invocations[].toolExecutionNotifications`; suppressed findings use the native `suppressions[]` array with the reason in `justification`.
