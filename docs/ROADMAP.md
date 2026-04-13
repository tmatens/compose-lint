# Roadmap

compose-lint v0.3.0 shipped 19 rules, PyPI distribution, SARIF/JSON/text output, pre-commit support, and a GitHub Action. The gap is distribution reach and developer experience.

---

## Milestone 1 — Rule Coverage (v0.3) [complete]

**Shipped in v0.3.0.** Added 9 rules (CL-0011 – CL-0019) plus CL-0010 `uts: host` enhancement, bringing the total to 19 rules. See CHANGELOG.md for details.

---

## Milestone 2 — Distribution (v0.4)

Reduce friction from "have Python" to "run one command."

**Docker Hub image** (`composelint/compose-lint`) [complete]
- Multi-stage build on `python:3.13-alpine` (digest-pinned), ~25 MB final image
- Multi-arch: `linux/amd64`, `linux/arm64`
- Enables `docker run --rm -v $(pwd):/src composelint/compose-lint`
- Published via GitHub Actions on tag push; signed with cosign (Sigstore keyless)
- Automated smoke tests in CI: version check, clean/insecure fixtures, SARIF output validation
- Primary audience: teams that distrust pip in CI, or non-Python shops

**Linux packages**
- `.deb` and `.rpm` via `nfpm` — self-contained, no Python required
- Published to GitHub Releases as build artifacts on every tag
- Secondary: AUR `compose-lint` PKGBUILD for Arch users

**Homebrew tap**
- `brew install tmatens/tap/compose-lint`
- Widens macOS developer reach beyond pip users

---

## Milestone 3 — Better Remediation (v0.5)

Finding a problem is half the value. Remediation guidance is the differentiator versus KICS, which identifies issues but rarely provides exact Compose-specific fix steps.

**`--fix` mode** — auto-fix for safe, unambiguous rules:
- CL-0003: inject `no-new-privileges:true` into `security_opt:`
- CL-0005: prepend `127.0.0.1:` to unbound port mappings
- CL-0007: add `read_only: true`
- Dry run by default; `--fix --apply` writes in-place
- Out of scope for auto-fix: CL-0001 (socket proxy replacement is non-trivial), CL-0016 (correct secret management is context-dependent)

**Remediation snippets in SARIF** — populate `fix.changes[]` objects so GitHub Code Scanning can display a suggested-change diff inline on pull requests.

**`--explain CL-XXXX`** — print the full prose from `docs/rules/CL-XXXX.md` in the terminal, reducing context-switching to the browser during triage.

---

## Milestone 4 — VS Code Extension + GA (v1.0)

**Why VS Code before LSP**: the extension market is where Docker Compose authors spend most of their editing time. LSP can follow after v1.0.

**Architecture**: the extension shells out to `compose-lint --format json` on save. No embedded Python runtime in the extension — this keeps it thin and ensures the user's installed version is always what runs.

- Underlines findings inline with diagnostic severity mapping
- Hover tooltip shows the `fix:` and `ref:` fields
- Command palette: `Compose Lint: Fix All Auto-fixable` (requires Milestone 3)

**GA declaration**: v1.0 moves the PyPI classifier from `3 - Alpha` to `5 - Production/Stable`. Prerequisites: 19+ rules, `--fix` mode, VS Code extension, and a documented upgrade/deprecation policy.

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

---

## Out of Scope

- **Full Compose schema validation** — intentionally excluded; the niche is security, not correctness
- **Kubernetes/Helm support** — would dilute the zero-config, Compose-specific positioning
- **SaaS offering** — adds infrastructure, compliance, and billing complexity with no clear moat over the CLI

---

## Summary

| Milestone | Version |
|-----------|---------|
| Rule Coverage (19 rules) | v0.3 [complete] |
| Distribution (Docker Hub, packages, Homebrew) | v0.4 [Docker Hub complete] |
| Remediation (`--fix`, SARIF fixes, `--explain`) | v0.5 |
| VS Code extension + GA | v1.0 |
| Ecosystem integrations, custom rules | v1.x |
