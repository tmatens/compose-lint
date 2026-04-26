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
