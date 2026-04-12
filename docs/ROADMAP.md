# Roadmap

compose-lint v0.2.0 has a proven core engine — 10 rules, PyPI distribution, SARIF/JSON/text output, pre-commit support. The gap is coverage, distribution reach, and developer experience.

---

## Milestone 1 — Rule Coverage (v0.3)

The existing 10 rules cover the most critical OWASP/CIS items. This milestone fills the next tier before expanding distribution. More installs means more exposure to false negatives; completeness comes first.

Each candidate was evaluated against three criteria: (1) actionability — is the finding specific enough to fix without guessing?; (2) false positive rate — does the absence of a field have a legitimate default?; (3) right tool — can a Compose linter detect this without image inspection or runtime state?

**New rules (CL-0011 – CL-0017)**

| Rule ID | Check | Severity | Grounding |
|---------|-------|----------|-----------|
| CL-0011 | Dangerous `cap_add` values (`SYS_ADMIN`, `SYS_PTRACE`, `NET_ADMIN`, `SYS_MODULE`, `SYS_RAWIO`, `SYS_TIME`, `DAC_READ_SEARCH`) | HIGH | OWASP Rule #3, CIS 5.5 |
| CL-0012 | PIDs cgroup limit disabled (`pids_limit: 0` or `pids_limit: -1`) | MEDIUM | CIS 5.29 |
| CL-0013 | Sensitive host paths mounted (`volumes:` containing `/etc`, `/proc`, `/sys`, `/boot`, `/root`) | HIGH | OWASP Rule #8, CIS 5.5 |
| CL-0014 | Logging driver disabled (`logging.driver: none`) | MEDIUM | CIS 5.x |
| CL-0015 | Healthcheck explicitly disabled (`healthcheck: {disable: true}`) | LOW | CIS 4.6, 5.27 |
| CL-0016 | Dangerous host devices exposed (`devices:` matching `/dev/mem`, `/dev/kmem`, `/dev/port`, block devices `/dev/sd*`, `/dev/nvme*`, `/dev/disk/*`) | HIGH | CIS 5.18 |
| CL-0017 | Shared mount propagation (`:shared` suffix or `bind.propagation: shared`) | MEDIUM | CIS 5.20 |
| CL-0018 | Explicit root user (`user: root` or `user: "0"`) — overrides a correctly built image's non-root USER instruction | MEDIUM | OWASP Rule #7, CIS 5.x |
| CL-0019 | Image pinned to tag but not digest (`nginx:1.25.3` without `@sha256:`) — tag can be silently overwritten on the registry | MEDIUM | OWASP Rule #13, CIS 5.27 |

CL-0019 fires only when a version tag is present but no `@sha256:` digest. CL-0004 fires when there is no version tag at all. They are non-overlapping: `nginx` and `nginx:latest` trigger CL-0004 only; `nginx:1.25.3` triggers CL-0019 only; `nginx:1.25.3@sha256:…` triggers neither. Fix guidance should reference Dependabot and Renovate as the practical path for keeping digests current.

**CL-0010 enhancement**: Add `uts: host` to the existing host namespace rule (CIS 5.21 — sharing the UTS namespace lets a container change the host's hostname).

**Rules evaluated and rejected:**

| Candidate | Rejection reason |
|-----------|-----------------|
| Hardcoded secrets in `environment:` | Too many false positives — `CONFIG_KEY`, `NEXT_PUBLIC_API_KEY`, `APP_SECRET_NAME` all match naive patterns but are not secrets. Regex on key names erodes trust. |
| No memory/CPU resource limits | Absence check; fires on every dev Compose file where limits are intentionally omitted. Only explicit opt-outs like `pids_limit: -1` are appropriate. |
| Service running as root (absence of `user:`) | Wrong tool — absence of `user:` does not imply root; the image's USER instruction determines the UID. Unactionable: "add `user:`" is not a specific fix without knowing the image's intended UID. CL-0018 catches the explicit override case instead. |
| `restart: always` without failure limit | Fires on virtually every production Compose file; CIS 5.15 concern is system stability, not a security misconfiguration detectable by static analysis. |
| Ulimit overrides (`ulimits: {nproc: -1}`) | Lower priority — `pids_limit: -1` covers the fork bomb case with higher signal and simpler detection. |

**Section 4 (Container Images) verdict**: Only `healthcheck: {disable: true}` yields a viable rule. All other Section 4 controls require image inspection, Dockerfile analysis, or host-level configuration that a Compose linter cannot access.

---

## Milestone 2 — Distribution (v0.4)

Reduce friction from "have Python" to "run one command."

**Docker Hub image** (`composelint/compose-lint`)
- Minimal image (python:3.13-alpine base, digest-pinned)
- Enables `docker run --rm -v $(pwd):/src composelint/compose-lint`
- Published via GitHub Actions OIDC; signed with cosign
- Primary audience: teams that distrust pip in CI, or non-Python shops

**Linux packages**
- `.deb` and `.rpm` via `nfpm` — self-contained, no Python required
- Published to GitHub Releases as build artifacts on every tag
- Secondary: AUR `compose-lint` PKGBUILD for Arch users

**Homebrew tap**
- `brew install tmatens/tap/compose-lint`
- Widens macOS developer reach beyond pip users

**Implementation note**: The Docker image uses `shiv` to produce a zipapp (works on any Python 3.10+ host without a wheel install). The `.deb`/`.rpm` bundle Python via nfpm. This avoids PyInstaller cross-compilation maintenance.

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
| Rule Coverage (19 rules) | v0.3 |
| Distribution (Docker Hub, packages, Homebrew) | v0.4 |
| Remediation (`--fix`, SARIF fixes, `--explain`) | v0.5 |
| VS Code extension + GA | v1.0 |
| Ecosystem integrations, custom rules | v1.x |
