# Configuration

compose-lint reads `.compose-lint.yml` from the current working directory by default. Use `--config PATH` to point at a different file.

> **Running in Docker: mount the directory, not the file.** The image's working directory is `/src`, so the config has to be *inside* it:
>
> ```bash
> docker run --rm -v "$(pwd):/src" composelint/compose-lint            # config found
> docker run --rm -v "$(pwd)/docker-compose.yml:/src/docker-compose.yml" \
>   composelint/compose-lint                                            # config NOT found
> ```
>
> The second form leaves `.compose-lint.yml` outside the container, so every suppression is silently absent and findings you disabled come back. compose-lint cannot tell that apart from having no config at all, so it does not fail — but when a run reports findings with no config in effect it says so on stderr, naming the directory it looked in.

## Which files get linted

Given explicit paths, compose-lint lints exactly those. With no arguments it looks in the **current directory only**, for exactly four names:

```
compose.yml   compose.yaml   docker-compose.yml   docker-compose.yaml
```

Finding none is an error (exit 2), not a pass — a gate reporting success over an unlinted repository is the one outcome this tool must never produce.

**The pre-commit hook is deliberately broader.** It selects any path matching `(^|/)(docker-)?compose[^/]*\.ya?ml$` — so `compose.prod.yml`, `docker-compose.override.yml` and `stack/compose.yml` are linted by the hook and *not* by a bare `compose-lint` run:

| path | `compose-lint` / GitHub Action | pre-commit hook |
| --- | --- | --- |
| `compose.yml` | linted | linted |
| `compose.prod.yml` | not found | linted |
| `docker-compose.override.yml` | not found | linted |
| `stack/compose.yml` | not found | linted |

The asymmetry is intentional. pre-commit hands the hook a filename-filtered list of files you actually changed, so matching broadly is useful and safe. A bare `compose-lint` has no such list and must not guess which of a repository's YAML files are Compose files.

**What this means for you:** if your Compose files are not among the four default names, pass them explicitly (`compose-lint compose.prod.yml`) — the CLI has no glob flag, so expand one in your shell (`compose-lint compose.*.yml`) or let your runner do it. The GitHub Action does take a glob, via its `pattern:` input (`files:` for explicit paths). Otherwise a repository that passes pre-commit can report "no Compose files found" in CI.

`tests/test_discovery_parity.py` holds all three surfaces to this table, so the hook can never become *narrower* than the CLI and the Action's list cannot drift from it.

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
  CL-0007:  # LOW — Filesystem not read-only
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

`severity:` re-grades a rule's findings rather than suppressing them, and it
leaves its own record so a reader can tell a re-graded finding from one the rule
declared that way. Re-grading is the quietest way to neutralise a rule — three
lines can take a CRITICAL below the default gate — so it is reported:

- **Text**: `(severity overridden from critical)` after the finding.
- **JSON**: `severity_overridden_from` on the finding (absent when not overridden).
- **SARIF**: `properties.severityOverriddenFrom` on the result.

Re-stating a rule's own severity records nothing, because nothing changed.

**Duplicate keys are rejected.** Listing the same rule twice is a config error
rather than a last-wins merge: a policy file that disables a rule "with a
reason" and then re-enables it further down reads, to a human, as the first
entry — and used to behave as the second.

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
- **Unknown top-level keys warn.** Only `rules` is recognized at the top level. A misplaced CLI flag (e.g. a top-level `fail_on:`) or any other key warns instead of being ignored. This is also the path a leftover `profiles:` block now takes — the profile-enrichment preview was withdrawn in 0.15.0 ([ADR-019](adr/019-withdraw-security-profile-catalog.md)), so the key is simply unrecognized and warns like any other.
- **Unknown per-rule keys warn.** Inside a rule block, only `enabled`, `reason`, `severity`, and `exclude_services` are recognized. A typo'd `severty:` warns.
- **`enabled` must be a real boolean.** A quoted `'false'`, `0`, or any non-boolean is a **hard error** (exit 2), not a silent no-op that would leave the rule on. YAML's boolean keywords (`true`/`false`, `yes`/`no`, `on`/`off`) all parse to a real boolean and work as expected.

Warnings never change the exit code; only the hard errors above do.

Pass **`--strict-config`** to `check` or `fix` to promote every warning above (unknown rule id, unknown top-level or per-rule key) to a hard error (exit 2). Use it in CI, or wherever stderr is redirected, so a typo can't silently disable the wrong rule.

## Output formats

`--format` selects the output (`text` default, `json`, `sarif`). Text writes a human banner, per-file summary, and verdict; `json` and `sarif` emit only the machine document on stdout so redirects stay clean.

### JSON

JSON output is a versioned envelope (see [ADR-015](adr/015-machine-readable-output-contract.md)):

```json
{
  "version": "2",
  "tool": { "name": "compose-lint", "version": "0.24.0" },
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
- `findings[]` carries one object per finding. `file` names the document the evidence is written in and `line` is a line **within that document** — the two always agree. `severity` is one of `critical`, `high`, `medium`, `low`. `rule_id` is an **opaque string**: match exact values, never the `CL-XXXX` pattern ([compatibility.md](compatibility.md)).
- Four keys are conditional, present only on the branch that produces them: `suppression_reason` (a suppressed finding whose config gave a reason), `severity_overridden_from` (the config regraded it), `graded_file` (a merged or `env_file:` run, where the graded document differs from `file`), and `source_file` (a deprecated alias of `file`, kept for consumers written against schema 1).
- `errors[]` lists files that failed to parse (exit 2). Files skipped as not-applicable (Compose v1 / fragments / a compose-lint config, [ADR-013](adr/013-missing-services-key.md)) are not errors and do not appear here.

!!! note "Schema 2 changed what `file` means"

    In schema 1, `file` always named the document being *graded* while `line` indexed wherever the evidence came from — so on a merged run or one reading an `env_file:`, both default behaviour, the pair named a real line of the wrong file. `file` now names the evidence's document, and the graded one moved to `graded_file`. If you consumed `source_file` to work around this, `file` answers it directly.

### SARIF

`--format sarif` emits a SARIF 2.1.0 log for GitHub Code Scanning. Parse failures appear as `invocations[].toolExecutionNotifications`; suppressed findings use the native `suppressions[]` array with the reason in `justification`.
