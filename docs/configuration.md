# Configuration

compose-lint reads `.compose-lint.yml` from the current working directory by default. Use `--config PATH` to point at a different file.

## Generating a starter config

Rather than hand-author the file from this page, run `compose-lint init` to turn a file's current findings into a `.compose-lint.yml` you then triage:

```bash
compose-lint init docker-compose.yml          # writes ./.compose-lint.yml
compose-lint init docker-compose.yml -o ci.yml # write somewhere else
compose-lint init docker-compose.yml --force   # overwrite an existing config
```

Every finding becomes a per-service [`exclude_services`](#per-service-exclusions) entry with a placeholder reason for you to fill in or delete:

```yaml
rules:
  CL-0001:  # CRITICAL — Docker socket mounted
    exclude_services:
      proxy: "TODO: justify or fix"
  CL-0007:  # MEDIUM — Filesystem not read-only
    exclude_services:
      web: "TODO: justify or fix"
      worker: "TODO: justify or fix"
```

- **Per-service, not global.** `init` never writes `enabled: false`; it names the exact services where each rule fired, so a service you add later still trips the rule instead of being silently uncovered.
- **All severities are included** and annotated; review the CRITICAL and HIGH entries first and prefer fixing over suppressing.
- **It refuses to overwrite an existing `.compose-lint.yml`** without `--force`, so a generated file can't clobber suppressions you've already triaged.
- **A clean file writes nothing** — `init` reports that there is nothing to suppress and exits 0.
- Status goes to stderr; `init` takes a single `FILE` (no directory discovery).

The generated file is a starting point. Replace each `TODO` reason with a real justification (`enabled: false` plus a `reason` is the right shape if a rule is universally inapplicable), or delete entries you intend to fix.

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

## Profile enrichment (experimental)

> **Experimental preview.** Off by default and opt-in. Profile fix
> recommendations are **advisory only**: a derived minimum is valid for the exact
> invocation it was produced under (image digest, `user:`, `command:`, mounts,
> …), and compose-lint does static analysis — it can't see your runtime, so it
> can't confirm the recommendation fits your deployment. Treat a hint as a
> pointer to verify, not a validated fact. When enrichment is active, compose-lint
> prints a one-line reminder to stderr.

Opt into image-specific fix guidance derived by container-sec-derive (csd), a
runtime derivation tool (not yet published; every catalog profile carries the
evidence to audit it without the tool).
When enabled, a finding from a rule that a derived profile covers
(CL-0002/0006/0007/0011/0016) gains a `profile hint` line in its fix text stating
the observed minimum for that image — for example, the exact `cap_add` a service
actually needs.

compose-lint **ships no catalog of its own** (ADR-017 §7). You point `profiles.path`
at a catalog you trust — your own derived profiles, or an external
automation-maintained catalog you opt into. The reference catalog is
[container-security-profiles](https://github.com/tmatens/container-security-profiles)
(browsable at
[tmatens.github.io/container-security-profiles](https://tmatens.github.io/container-security-profiles/)):
clone it and point `profiles.path` at its `catalog/` directory. Both keys are
required for enrichment; with `enabled` set but no `path`, compose-lint warns and
enriches nothing.

```yaml
profiles:
  enabled: true            # default: false
  path: ./security-profiles  # directory of profile YAML documents (no default)
```

Enrichment is **advisory and additive only**: it never creates, drops, or
reclassifies a finding, so turning it on cannot change your pass/fail result — it
only makes existing guidance more specific, and the hint is **attributed and
marked unverified** (it names its source and that compose-lint did not
independently reproduce it). It matches a service's `image:` to a profile in your
configured catalog; with no matching profile it is a no-op. See
[ADR-017](adr/017-security-profile-catalog.md) for the profile model and the
trust rationale (§7).

## Validation

A `.compose-lint.yml` that silently fails to take effect is a security risk — the user believes a rule is suppressed or re-tuned when it is not. compose-lint validates the file on load:

- **Unknown rule IDs warn.** `rules:` keys are checked against the registered rule set. A typo (`CL-001`) or a retired ID (`CL-9999`) prints a stderr warning so the override isn't silently dropped.
- **Unknown top-level keys warn.** Only `rules` and `profiles` are recognized at the top level. A misplaced CLI flag (e.g. a top-level `fail_on:`) or any other key warns instead of being ignored.
- **Unknown `profiles` keys warn; `profiles.enabled` must be a real boolean and `profiles.path` a string.** Only `enabled` and `path` are recognized in the `profiles` block; a non-boolean `enabled` or non-string `path` is a hard error (exit 2), like the per-rule `enabled`.
- **Unknown per-rule keys warn.** Inside a rule block, only `enabled`, `reason`, `severity`, and `exclude_services` are recognized. A typo'd `severty:` warns.
- **`enabled` must be a real boolean.** A quoted `'false'`, `0`, or any non-boolean is a **hard error** (exit 2), not a silent no-op that would leave the rule on. YAML's boolean keywords (`true`/`false`, `yes`/`no`, `on`/`off`) all parse to a real boolean and work as expected.

Warnings never change the exit code; only the hard errors above do.

Pass **`--strict-config`** to `check` or `fix` to promote every warning above (unknown rule id, unknown top-level/per-rule/`profiles` key) to a hard error (exit 2). Use it in CI, or wherever stderr is redirected, so a typo can't silently disable the wrong rule.

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
