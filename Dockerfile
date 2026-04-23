# syntax=docker/dockerfile:1@sha256:2780b5c3bab67f1f76c781860de469442999ed1a0d7992a5efdf2cffc0e3d769
# Build: docker build -t composelint/compose-lint .
# Run:   docker run --rm -v "$(pwd):/src" composelint/compose-lint
#
# Runtime: Google distroless Python on Debian 13 (Python 3.13, no shell,
# no package manager, runs as nonroot UID 65532). See docs/adr/009-runtime-base-image.md.
# Build stage uses debian:trixie-slim so the build-time Python path
# (/usr/bin/python3) matches the runtime — the venv transfers across
# stages without shebang rewriting. Both digests are bumped by Renovate.

# --- build stage: produce wheel, install into a venv ---
FROM debian:trixie-slim@sha256:4ffb3a1511099754cddc70eb1b12e50ffdb67619aa0ab6c13fcd800a78ef7c7a AS build
# apt versions intentionally unpinned: the base image digest above is
# immutable, apt verifies package signatures, and Renovate has no
# datasource for Debian apt. Pinning would bitrot when Debian purges
# old versions from the index. See docs/adr/009-runtime-base-image.md.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY requirements.lock requirements-build.lock ./
COPY src/ src/
# Two-venv layout so every package entering the final image is hash-pinned:
#   /build-venv — ephemeral, runs `python -m build` (build + transitives)
#   /venv       — the runtime venv that gets copied into the final stage
# The runtime venv installs PyYAML from requirements.lock, then the locally
# built wheel with --no-deps so the only unpinned artifact is the wheel we
# just produced from this checkout.
RUN python3 -m venv /build-venv \
    && /build-venv/bin/pip install --no-cache-dir --require-hashes -r requirements-build.lock \
    && /build-venv/bin/python -m build --wheel --outdir /dist \
    && python3 -m venv /venv \
    && /venv/bin/pip install --no-cache-dir --require-hashes -r requirements.lock \
    && /venv/bin/pip install --no-cache-dir --no-deps /dist/*.whl \
    && rm -rf /venv/lib/python3.13/site-packages/pip \
        /venv/lib/python3.13/site-packages/pip-*.dist-info \
    && rm -f /venv/bin/pip /venv/bin/pip3 /venv/bin/pip3.13 \
        /venv/bin/activate /venv/bin/activate.csh /venv/bin/activate.fish \
        /venv/bin/Activate.ps1
# Post-install cleanup: pip is only needed during build (the install steps
# above), and the activate* scripts target shells the distroless runtime
# doesn't have. Stripping pip eliminates Docker Scout CVEs in pip itself
# (CVE-2025-8869, CVE-2026-1703 as of pip 25.1.1) — neither is reachable
# at runtime since the entrypoint is /venv/bin/compose-lint and there's no
# shell, but removing the bits also removes their attack surface and
# future-CVE noise. PyYAML, compose_lint, and the Python interpreter
# symlinks remain.

# --- runtime stage: distroless Python, nonroot by default ---
FROM gcr.io/distroless/python3-debian13:nonroot@sha256:51b1acc177d535f20fa30a175a657079ee7dce6e326541cfd83a474d9928e123
LABEL org.opencontainers.image.title="compose-lint" \
      org.opencontainers.image.description="Security-focused linter for Docker Compose files" \
      org.opencontainers.image.url="https://github.com/tmatens/compose-lint" \
      org.opencontainers.image.source="https://github.com/tmatens/compose-lint" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /venv /venv
WORKDIR /src
# Distroless :nonroot already sets USER 65532; restated here so the
# intent survives a future base-image swap that might not default nonroot.
USER 65532:65532
ENTRYPOINT ["/venv/bin/compose-lint"]
