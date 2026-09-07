#!/usr/bin/env bash
# Install one pinned Docker Compose plugin, ahead of the runner image's.
#
# Six suites derive this project's loader semantics from `docker compose` on
# every run. Which binary answers is therefore part of what they assert, and
# until this script it was whatever the runner image happened to ship —
# `images/ubuntu/toolsets/toolset-2404.json` in actions/runner-images pins the
# plugin at 2.38.2 (buildx beside it tracks `latest`; compose does not) while
# docker/compose is on 5.x.
#
# That is not a cosmetic lag. Measured: a service named in both an included
# file and the including document resolves on 5.5.x with the including
# document winning, and is refused outright on 2.38.2 —
# `services.web conflicts with imported resource`. So CI was grading ADR-036's
# `include:` orderings, every one of them measured on 5.5.0, against a binary
# that rejects the documents they describe, and nothing in the output said so.
# The pytest header now names the version (tests/conftest.py).
#
# The pin is not a compatibility promise. `docs/compatibility.md` says nothing
# about Compose versions and this does not add anything; it makes the tested
# version explicit and stable instead of incidental. Renovate manages the tag,
# so a Compose release that changes a loader rule turns this suite red in a PR
# of its own, which is where that gets triaged.
#
# `COMPOSE_VERSION` comes from the workflow, carrying the Renovate annotation.
set -euo pipefail

: "${COMPOSE_VERSION:?COMPOSE_VERSION must be set by the workflow}"

asset="docker-compose-linux-x86_64"
base="https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}"
workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

curl --fail --silent --show-error --location -o "${workdir}/${asset}" "${base}/${asset}"
curl --fail --silent --show-error --location \
  -o "${workdir}/${asset}.sha256" "${base}/${asset}.sha256"

# A GitHub release asset has no digest to pin the way an image or an action
# does, so the release's own published checksum is what there is to verify
# against. It catches a truncated or substituted download; it is not a defence
# against a compromised release, which is what the sigstore attestation beside
# it would be for.
( cd "${workdir}" && sha256sum --check --strict "${asset}.sha256" )

# Ahead of the image's copy on the plugin search path, which reaches
# /usr/libexec/docker/cli-plugins only after /usr/local/lib. Installed into a
# system directory rather than ~/.docker so it is still found by a subprocess
# run with a scrubbed environment — which is how the harness invokes the
# oracle, deliberately (tests/oracle_harness/_oracle.py).
plugin_dir=/usr/local/lib/docker/cli-plugins
sudo mkdir -p "${plugin_dir}"
sudo install -m 0755 "${workdir}/${asset}" "${plugin_dir}/docker-compose"

# Prove the plugin that actually answers is the pinned one. The search-order
# assumption above is the part worth failing loudly on: get it wrong and the
# job silently keeps testing against the image's version, which is the exact
# state this script exists to end.
resolved="$(docker compose version --short)"
expected="${COMPOSE_VERSION#v}"
if [ "${resolved}" != "${expected}" ]; then
  echo "::error::docker compose resolved to ${resolved}, expected ${expected}"
  exit 1
fi
echo "docker compose ${resolved}"
