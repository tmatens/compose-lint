#!/usr/bin/env bash
# Sync a Docker Hub repository's long-description (overview) and short
# description from README.md. First-party replacement for
# peter-evans/dockerhub-description; invoked from CI via
# `.github/actions/update-dockerhub-description` and also runnable locally
# for ad-hoc description refreshes.
#
# Usage:
#   DOCKERHUB_USERNAME=<user> DOCKERHUB_TOKEN=<pat> \
#     [SHORT_DESCRIPTION="..."] \
#     scripts/update-dockerhub-description.sh [repo] [readme-path]
#
# Defaults: repo=composelint/compose-lint, readme-path=./README.md,
# short-description="Security-focused linter for Docker Compose files".
#
# Requires: curl, jq
# Requires DOCKERHUB_TOKEN to be a Docker Hub PAT with "Read, Write, Delete"
# scope — "Read & Write" is enough for `docker push` but NOT for the
# description PATCH endpoint.
set -euo pipefail

repo="${1:-composelint/compose-lint}"
readme="${2:-./README.md}"
short_description="${SHORT_DESCRIPTION:-Security-focused linter for Docker Compose files}"

: "${DOCKERHUB_USERNAME:?DOCKERHUB_USERNAME must be set}"
: "${DOCKERHUB_TOKEN:?DOCKERHUB_TOKEN must be set}"

if [ ! -f "${readme}" ]; then
    echo "Error: ${readme} not found" >&2
    exit 1
fi

for cmd in curl jq; do
    command -v "${cmd}" >/dev/null 2>&1 || {
        echo "Error: ${cmd} not found on PATH" >&2
        exit 1
    }
done

tmp=$(mktemp -d)
trap 'rm -rf "${tmp}"' EXIT

echo "Authenticating to Docker Hub as ${DOCKERHUB_USERNAME}..."
jq -n --arg u "${DOCKERHUB_USERNAME}" --arg p "${DOCKERHUB_TOKEN}" \
    '{username:$u, password:$p}' >"${tmp}/login.json"
jwt=$(curl -fsSL -H 'Content-Type: application/json' \
    --data-binary "@${tmp}/login.json" \
    https://hub.docker.com/v2/users/login/ | jq -r .token)
if [ -z "${jwt}" ] || [ "${jwt}" = "null" ]; then
    echo "Error: failed to acquire JWT — check DOCKERHUB_USERNAME and that" \
         "DOCKERHUB_TOKEN is a valid Docker Hub PAT" >&2
    exit 1
fi

echo "Patching description for ${repo}..."
jq -n --rawfile full "${readme}" --arg short "${short_description}" \
    '{full_description:$full, description:$short}' >"${tmp}/patch.json"
http_code=$(curl -sSL -o "${tmp}/resp" -w '%{http_code}' \
    -X PATCH \
    -H "Authorization: JWT ${jwt}" \
    -H 'Content-Type: application/json' \
    --data-binary "@${tmp}/patch.json" \
    "https://hub.docker.com/v2/repositories/${repo}/")

if [ "${http_code}" != "200" ]; then
    echo "Error: PATCH returned HTTP ${http_code}" >&2
    echo "Response body:" >&2
    cat "${tmp}/resp" >&2
    echo >&2
    if [ "${http_code}" = "403" ]; then
        echo "HTTP 403 Forbidden typically means the PAT lacks" \
             "'Read, Write, Delete' scope." >&2
    fi
    exit 1
fi

echo "Docker Hub overview synced: https://hub.docker.com/r/${repo}"
