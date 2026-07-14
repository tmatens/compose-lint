# Toolchain for rendering the README demo GIF.
#
# Bundles VHS (the recorder), its ttyd/ffmpeg runtime, and a released
# compose-lint so `demo.tape` runs deterministically anywhere Docker is
# available. See README.md in this directory for usage.
#
# Base is digest-pinned per CLAUDE.md (Docker base images: digest-pin the
# manifest-list index). Bump via Renovate.
FROM ghcr.io/charmbracelet/vhs@sha256:9d5fc3dc0c160b0fb1d2212baff07e6bdf3fa9438c504a3237484567302fcf93

# Pin to a released version so the recorded banner matches a real install.
ARG COMPOSE_LINT_VERSION=0.13.0

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir --break-system-packages \
        "compose-lint==${COMPOSE_LINT_VERSION}" \
        pillow numpy  # retime.py re-times the rendered GIF (see render.sh)
