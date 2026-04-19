# Roadmap

compose-lint v0.3.0 shipped 19 rules, PyPI distribution, SARIF/JSON/text output, pre-commit support, and a GitHub Action. v0.4.0 added per-service rule overrides. The product has a solid foundation; the next investments should make the tool more useful to the users already running it, not chase speculative distribution channels.

## Strategic framing

compose-lint's differentiation is depth in Compose-specific security, not distribution breadth. Competitors (KICS, Checkov, Trivy) cover Compose as one format among many; they are wide and shallow per-format. Compose-lint wins by being the one tool that tells you exactly what's wrong with a Compose file and exactly how to fix it. Roadmap priorities are ordered around that thesis.

Open issues #4 (CL-0006 capability profiles) and #111 (real-world examples library) are the live signal from real-world usage now that #5 is closed. Distribution items beyond the already-shipped Docker image have no demand signal and are deprioritized accordingly.

---

## Milestone 1 — Rule Coverage (v0.3) [complete]

Shipped in v0.3.0. Added 9 rules (CL-0011 – CL-0019) plus CL-0010 `uts: host` enhancement, bringing the total to 19 rules. See CHANGELOG.md.

---

## Milestone 2 — Configuration Depth (v0.4) [shipped]

Per-service rule overrides shipped in v0.4.0 (issue #5, [ADR-010](adr/010-per-service-rule-overrides.md)). `.compose-lint.yml` now supports `exclude_services` per rule, with mapping (service → reason) and list forms. Excluded services still produce suppressed findings carrying the per-service reason — same suppression plumbing as global disables.

---

## Milestone 2.5 — Trust Surface + Install Polish (v0.4.x)

The leftover Milestone 2 items, plus the new real-world examples ask. All additive over 0.4.0; no breaking changes.

**CL-0006 capability profiles** _(issue #4)_
- Ship known capability profiles for popular base images (PostgreSQL, Redis, Caddy, Netdata, etc.) so the finding's `fix` field names the specific `cap_add` list instead of a generic `<SPECIFIC_CAP>` placeholder.
- Data-driven: ships as a profile table in the rule, no engine changes.
- Scope-limit: data + docs only. A `--suggest-caps` CLI flag is out of scope here; revisit if the profiles land well.

**Real-world examples library** _(issue #111)_
- `examples/real-world/` with one subdirectory per project (Traefik, Vaultwarden, Immich, Pi-hole, Portainer, Gitea). Each shows upstream Compose file → raw `compose-lint` output → hardened version → suppression config for unfixable findings, with per-finding narrative.
- Doubles as the canonical teaching surface for ADR-010 suppression semantics — the interesting suppression cases only appear against real files.
- **Gating prerequisite:** weekly drift-check job (re-fetch upstream files, open an issue on diff) before landing examples. Stale examples erode trust faster than no examples; ship the watchdog first, even as a stub.

**Homebrew tap**
- `brew install tmatens/tap/compose-lint` — works on macOS (Intel + Apple Silicon) and Linux via Homebrew-on-Linux.
- Closes the "not everyone has pip" gap with working `brew upgrade` UX (which GitHub-Releases-hosted `.deb`/`.rpm` could not match).
- Formula lives in a separate `homebrew-tap` repo; release workflow uses `brew bump-formula-pr` to keep versions in sync with low manual overhead.

_Deferred:_ `.deb`/`.rpm` Linux packages (see [ADR-008](adr/008-linux-packages.md) — no user demand, no upgrade path without hosted repo infrastructure).

---

## Milestone 3 — Remediation (v0.5)

Turn findings into fixes. This is where the product's differentiation grows the most against KICS/Checkov.

**`--explain CL-XXXX`** — print the full prose from `docs/rules/CL-XXXX.md` in the terminal, reducing context-switching to the browser during triage. Small, no new deps, foundation for `--fix` UX.

**`--fix` mode** — auto-fix for safe, unambiguous rules:
- CL-0003: inject `no-new-privileges:true` into `security_opt:`
- CL-0005: prepend `127.0.0.1:` to unbound port mappings
- CL-0007: add `read_only: true`
- Dry run by default; `--fix --apply` writes in-place.
- Out of scope for auto-fix: CL-0001 (socket proxy replacement is non-trivial), CL-0016 (correct secret management is context-dependent).

**Remediation snippets in SARIF** — populate `fix.changes[]` objects so GitHub Code Scanning can display a suggested-change diff inline on pull requests.

**Shellcheck integration** _(pending decision — [ADR-007](adr/007-shellcheck-integration.md))_
- Lint shell commands inside `command` and `entrypoint` (string form) and `healthcheck.test` with `CMD-SHELL`.
- Unique coverage vs. KICS/Checkov — reinforces the "depth" thesis.
- Optional dependency; rule skips silently if shellcheck is not in `PATH`.

---

## Milestone 4 — VS Code Extension + GA (v1.0)

The biggest reach multiplier. Compose authors spend most editing time in editors, not CI. Sequenced after `--fix` because the extension's value pops only once fixes are one-click.

**Architecture:** the extension shells out to `compose-lint --format json` on save. No embedded Python runtime in the extension — this keeps it thin and ensures the user's installed version is always what runs.

- Underlines findings inline with diagnostic severity mapping
- Hover tooltip shows the `fix:` and `ref:` fields
- Command palette: `Compose Lint: Fix All Auto-fixable` (requires Milestone 3)

**GA declaration:** v1.0 moves the PyPI classifier from `3 - Alpha` to `5 - Production/Stable`. Prerequisites: 19+ rules, `--fix` mode, VS Code extension, and a documented upgrade/deprecation policy.

---

## Milestone 5 — Ecosystem Integrations (v1.x)

Pursue based on user demand after v1.0.

| Integration | Notes |
|-------------|-------|
| GitLab SAST template | SARIF upload to GitLab Security Dashboard |
| Azure DevOps task | Published to VS Marketplace |
| JetBrains plugin | Same shell-out pattern as VS Code |
| Custom rule plugins | `entry_points` hook (`compose_lint.rules` group) for third-party rules |
| LSP server | Language Server Protocol support — follows VS Code extension post-v1.0 |
| Linux packages (`.deb`/`.rpm`) | Revisit [ADR-008](adr/008-linux-packages.md) on first concrete user request |

---

## Out of Scope

- **Full Compose schema validation** — intentionally excluded; the niche is security, not correctness
- **Kubernetes/Helm support** — would dilute the zero-config, Compose-specific positioning
- **SaaS offering** — adds infrastructure, compliance, and billing complexity with no clear moat over the CLI

---

## Python version support

Track current CPython: add new minor versions to the CI matrix within ~3 months of each October release, drop versions at upstream end-of-life. Adding a version is additive (PATCH per `docs/RELEASING.md`); dropping a version is a MINOR pre-1.0 and a MAJOR post-1.0.

| Version | Released  | EOL       | In matrix as of |
|---------|-----------|-----------|-----------------|
| 3.10    | 2021-10   | 2026-10   | 0.2.0           |
| 3.11    | 2022-10   | 2027-10   | 0.2.0           |
| 3.12    | 2023-10   | 2028-10   | 0.2.0           |
| 3.13    | 2024-10   | 2029-10   | 0.2.0           |
| 3.14    | 2025-10   | 2030-10   | 0.3.8           |

Python 3.10 is scheduled to age out of the matrix when it reaches upstream EOL in October 2026 (release bump to 0.4.x or later).

---

## Summary

| Milestone | Version | Status |
|-----------|---------|--------|
| Rule Coverage (19 rules) | v0.3 | complete |
| Per-service rule overrides | v0.4 | complete |
| CL-0006 profiles + real-world examples + Homebrew tap | v0.4.x | in progress |
| Remediation (`--explain`, `--fix`, SARIF fixes, shellcheck) | v0.5 | |
| VS Code extension + GA | v1.0 | |
| Ecosystem integrations, custom rules | v1.x | |
