# Toolchain for rendering the README demo GIF.
#
# Bundles VHS (the recorder), its ttyd/ffmpeg runtime, and a released
# compose-lint so `demo.tape` runs deterministically anywhere Docker is
# available. See README.md in this directory for usage.
#
# Base is digest-pinned per CLAUDE.md (Docker base images: digest-pin the
# manifest-list index). Bump via Renovate.
FROM ghcr.io/charmbracelet/vhs@sha256:9d5fc3dc0c160b0fb1d2212baff07e6bdf3fa9438c504a3237484567302fcf93

# Python deps (compose-lint + retime.py's pillow/numpy) are hash-pinned in
# requirements.lock (uv-compiled from requirements.in; see README.md). The
# compose-lint pin doubles as the recorded version — keep it in step with the
# banner the committed GIF shows.
USER root
COPY requirements.lock /tmp/demo-requirements.lock
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir --break-system-packages --require-hashes \
        -r /tmp/demo-requirements.lock
