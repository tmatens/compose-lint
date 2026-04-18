# ADR-009: Runtime Container Base Image

**Status:** Accepted

**Context:** compose-lint ships a Docker image alongside the PyPI wheel. The runtime image was originally `python:3.13-alpine`, then briefly `cgr.dev/chainguard/wolfi-base:latest` with `apk add python-3.13`. Both include a shell, package manager, and busybox-level utilities at runtime, which is larger attack surface than necessary for a local linter. The wolfi-base approach also required Renovate to track apk package versions, which has no built-in datasource in Renovate's free tier — the community workaround (`renovate-apk-indexer`) requires self-hosting an HTTP server and was ruled out.

**Decision:** Runtime image `gcr.io/distroless/python3-debian13:nonroot`; build stage `debian:trixie-slim`. Both digest-pinned.

**Alternatives rejected:**

- **`cgr.dev/chainguard/wolfi-base:latest` + `apk add python-3.13`:** Ships a shell, `apk`, and busybox at runtime. Requires self-hosted Renovate datasource to track apk package versions. Pinned apk versions become unbuildable once Chainguard rotates the index and the old version is removed.
- **`cgr.dev/chainguard/python:latest`:** Truly distroless and otherwise an excellent fit, but the free tier only publishes `:latest`/`:latest-dev`, which currently resolves to Python 3.14. That is outside the `3.10–3.13` CI matrix and would ship users an untested interpreter. Version-pinned tags (`:3.13`, `:3.13-dev`) require a Chainguard subscription.
- **`python:3.13-alpine`:** Ships apk + ash shell. musl-based, occasional compatibility surprises with Python wheels vs. glibc.

**Rationale:**

- **Attack surface.** Distroless removes `/bin/sh`, coreutils, `apt`, and busybox. The runtime image contains only the Python interpreter, stdlib, libc, and the project venv. A container escape has nowhere useful to go.
- **Python version stays inside the CI matrix.** Debian 13 (Trixie) ships Python 3.13; our CI tests 3.10–3.13. No matrix expansion, no policy amendment.
- **Cross-stage venv transfer works unchanged.** `debian:trixie-slim` and `python3-debian13` both install Python at `/usr/bin/python3`, so the venv built in the build stage is shebang-compatible with the runtime. No `pip install --target` gymnastics.
- **Simpler Renovate story.** Both `FROM` lines are tracked by Renovate's built-in `docker` datasource via `pinDigests: true`. The `customManagers` regex for apk ARG markers and the apk-specific `packageRules` entry are both removed.
- **CVE posture is adequate for a local CLI.** Google distroless inherits Debian's security-release cadence — typically 2–7 days behind Chainguard's daily rebuilds. compose-lint has no network listener, no TLS, and no daemon mode; its only attacker-reachable input is a YAML file the operator deliberately handed it. For a networked service the cadence tradeoff would be reconsidered; for this tool the gap is acceptable. Reassess if compose-lint ever grows a long-running or networked mode.
- **Debian-major upgrades stay human-driven.** Moving from `python3-debian13` to a future `python3-debian14` image changes the tag and likely the Python minor version. Renovate does not bump the image's Debian major automatically; this matches the existing "ship only tested Python" policy.
