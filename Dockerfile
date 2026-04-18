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
FROM debian:trixie-slim@sha256:5fb70129351edec3723d13f427400ecae3f13b83750e23ad47c46721effcf2db AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
RUN python3 -m venv /venv \
    && /venv/bin/pip install --no-cache-dir build~=1.0 \
    && /venv/bin/python -m build --wheel --outdir /dist \
    && /venv/bin/pip uninstall -y build \
    && /venv/bin/pip install --no-cache-dir /dist/*.whl

# --- runtime stage: distroless Python, nonroot by default ---
FROM gcr.io/distroless/python3-debian13:nonroot@sha256:9b1e35ec38db9ee528a2107c84b7d839b4dd412c5e003186aed8bd5e62900bfc
LABEL org.opencontainers.image.title="compose-lint" \
      org.opencontainers.image.description="Security-focused linter for Docker Compose files" \
      org.opencontainers.image.url="https://github.com/tmatens/compose-lint" \
      org.opencontainers.image.source="https://github.com/tmatens/compose-lint" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /venv /venv
WORKDIR /src
ENTRYPOINT ["/venv/bin/compose-lint"]
