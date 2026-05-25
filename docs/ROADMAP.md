# Roadmap

As of v0.8.0, compose-lint ships 21 security rules, PyPI distribution, a published GitHub Action and Docker image, SARIF/JSON/text output, pre-commit support, per-service rule overrides, and `--explain`. The foundation is solid; the next milestone is the 1.0 stability commitment. Remaining investments make the tool more useful to the users already running it, not chase speculative distribution channels.

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

**`--explain CL-XXXX`** _(shipped in v0.4.x)_ — prints the full prose from `docs/rules/CL-XXXX.md` in the terminal, reducing context-switching to the browser during triage. Rule-doc markdown is force-included into the wheel at build time. No new deps; pulled forward out of Milestone 3 because it's strictly additive and unblocks the `--fix` UX work.

**`fix` subcommand** _(shipped; promoted to the documented, SemVer-covered surface in 0.11.0 — [ADR-014](adr/014-fix-remediation.md))_ — auto-fix for safe, unambiguous rules:
- Six fixers: CL-0003 (`no-new-privileges:true`), CL-0005 (bind published ports to `127.0.0.1`), CL-0007 (`read_only: true`), CL-0009, CL-0014, CL-0015.
- Dry run by default; `fix --apply` writes in-place via an atomic swap; `--only CL-XXXX` scopes to named rules.
- Refuses anchors/merge keys/`${VAR}` regions and guards every apply with a re-parse + verify-apply pass.
- Out of scope for auto-fix: CL-0001 (socket proxy replacement is non-trivial), CL-0006 (capability lists are image-specific), CL-0016 (correct secret management is context-dependent).

**Remediation snippets in SARIF** _(shipped in 0.11.0)_ — `check --format sarif` populates `fixes[].artifactChanges` so GitHub Code Scanning displays a suggested-change diff inline on pull requests.

**Shellcheck integration** _(pending decision — [ADR-007](adr/007-shellcheck-integration.md))_
- Lint shell commands inside `command` and `entrypoint` (string form) and `healthcheck.test` with `CMD-SHELL`.
- Unique coverage vs. KICS/Checkov — reinforces the "depth" thesis.
- Optional dependency; rule skips silently if shellcheck is not in `PATH`.

---

## Milestone 4 — GA / 1.0

v1.0 is the **stability commitment**: the CLI surface, exit codes, configuration schema, and the JSON/SARIF output shapes come under SemVer. Breaking any of them after 1.0 requires a major version bump. The VS Code extension is explicitly *not* a 1.0 blocker — it's a reach multiplier that doesn't gate stability, and moves to Milestone 5.

**GA criteria:**
- **Stable, documented contract** — CLI flags, exit codes ([ADR-006](adr/006-exit-codes.md)), the `.compose-lint.yml` schema, and the JSON + SARIF output shapes are frozen and documented as the 1.0 surface. The JSON output gains a versioned envelope before the freeze, so run-level metadata (tool version, parse errors) can be added later without breaking consumers.
- **`fix` resolved** — _done._ Shipped as GA and brought under the SemVer contract in 0.11.0 ([ADR-014](adr/014-fix-remediation.md)), independently of the 1.0 cut.
- **Grounding + severity audit complete** — every rule cites OWASP/CIS/Docker, and no severity change is pending that would alter a CI gate after the freeze.
- **Documented upgrade/deprecation policy** — the SemVer stability promise (rule additions, severity changes, config and output-shape changes) and the deprecation lifecycle, in [compatibility.md](compatibility.md).

**At GA:** bump the PyPI classifier from `4 - Beta` to `5 - Production/Stable` in the version→1.0.0 commit, and publish a moving `v1` Action tag so users can pin `uses: tmatens/compose-lint@v1`.

---

## Milestone 5 — Ecosystem Integrations (v1.x)

Pursue based on user demand after v1.0.

| Integration | Notes |
|-------------|-------|
| VS Code extension | Shells out to `compose-lint --format json` on save (no embedded Python). Inline diagnostics, hover shows `fix:`/`ref:`, `Fix All Auto-fixable` command. The biggest editor reach multiplier once `fix` lands. |
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
| Remediation (`--explain`, `fix`, SARIF fixes, shellcheck) | v0.5–0.11 | `fix` GA in 0.11.0; shellcheck pending |
| GA / 1.0 — stable contract + `fix` + upgrade policy | v1.0 | next |
| Ecosystem integrations (VS Code, custom rules) | v1.x | |
