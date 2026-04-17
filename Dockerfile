# syntax=docker/dockerfile:1
# Build: docker build -t composelint/compose-lint .
# Run:   docker run --rm -v "$(pwd):/src" composelint/compose-lint
#
# Base: Chainguard Wolfi (free, daily CVE rebuilds, glibc).
# Base digest refresh: docker buildx imagetools inspect cgr.dev/chainguard/wolfi-base:latest
# apk versions are bumped by Renovate (see renovate.json customManagers).

# renovate: datasource=apk depName=python-3.13 registryUrl=https://packages.wolfi.dev/os
ARG PYTHON_APK_VERSION=3.13.13-r0
# renovate: datasource=apk depName=py3.13-pip registryUrl=https://packages.wolfi.dev/os
ARG PIP_APK_VERSION=26.0.1-r2

# --- build stage: produce wheel, install into a venv ---
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:1af610c4a70668dad46159ee178b20378c79a49b554f76405670fc442d30183a AS build
ARG PYTHON_APK_VERSION
ARG PIP_APK_VERSION
RUN apk add --no-cache \
        "python-3.13=${PYTHON_APK_VERSION}" \
        "py3.13-pip=${PIP_APK_VERSION}"
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
RUN python3.13 -m venv /venv \
    && /venv/bin/pip install --no-cache-dir build~=1.0 \
    && /venv/bin/python -m build --wheel --outdir /dist \
    && /venv/bin/pip uninstall -y build \
    && /venv/bin/pip install --no-cache-dir /dist/*.whl

# --- runtime stage: python interpreter + copied venv, no pip ---
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:1af610c4a70668dad46159ee178b20378c79a49b554f76405670fc442d30183a
ARG PYTHON_APK_VERSION
LABEL org.opencontainers.image.title="compose-lint" \
      org.opencontainers.image.description="Security-focused linter for Docker Compose files" \
      org.opencontainers.image.url="https://github.com/tmatens/compose-lint" \
      org.opencontainers.image.source="https://github.com/tmatens/compose-lint" \
      org.opencontainers.image.licenses="MIT"
RUN apk add --no-cache "python-3.13=${PYTHON_APK_VERSION}" \
    && mkdir -p /src \
    && chown 65532:65532 /src
COPY --from=build /venv /venv
ENV PATH="/venv/bin:${PATH}"
USER nonroot
WORKDIR /src
ENTRYPOINT ["compose-lint"]
