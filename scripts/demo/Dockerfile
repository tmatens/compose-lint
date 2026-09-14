# Toolchain for rendering the README demo GIF.
#
# Bundles VHS (the recorder), its ttyd/ffmpeg runtime, and a released
# compose-lint so `demo.tape` runs deterministically anywhere Docker is
# available. See README.md in this directory for usage.
#
# Base is digest-pinned per CLAUDE.md (Docker base images: digest-pin the
# manifest-list index). Bump via Renovate.
FROM ghcr.io/charmbracelet/vhs@sha256:b1afb4f9d0d27000d5feb7e93882dc5b983574fc19462308ee1d94e843afc67d

# Python deps (compose-lint + retime.py's pillow/numpy) are hash-pinned in
# requirements.lock (uv-compiled from requirements.in; see README.md). The
# compose-lint pin doubles as the recorded version — keep it in step with the
# banner the committed GIF shows.
USER root
COPY requirements.lock /tmp/demo-requirements.lock
# `less` is for the hero cast's --explain step (the VHS base ships none);
# on compose-lint >= 0.26.0 (ADR-034) a bare `--explain` pages through it by
# itself. PAGER stays unset: the labeled status prompt (`CL-XXXX · Space next
# · b back · q quit`) rides only on compose-lint's default pager argv, and any
# PAGER value replaces that argv, prompt included. The image has no locale
# files, so LESSCHARSET is what keeps UTF-8 punctuation from rendering as
# <E2><80><94>; LESS adds -S because the cast's terminal runs with autowrap
# off (`tput rmam`), which breaks less's own wrapping — less merges $LESS with
# the argv flags, so the chop and the labeled prompt compose.
ENV LESSCHARSET=utf-8 \
    LESS=-S
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3-pip less \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir --break-system-packages --require-hashes \
        -r /tmp/demo-requirements.lock
