#!/usr/bin/env bash
# Fail if any FROM ...@sha256:<digest> in the Dockerfile pins a per-arch
# manifest instead of a multi-arch OCI index (manifest list). Per-arch pins
# work on the build host but fail at runtime on the other arch with an
# "exec format error" — a class of bug that only surfaces during multi-arch
# release builds unless caught here.
#
# Usage: scripts/verify-dockerfile-digests.sh [Dockerfile]
#
# No image pulls; HEAD the registry manifest endpoint and read Content-Type.
set -euo pipefail

dockerfile="${1:-Dockerfile}"

if [ ! -f "${dockerfile}" ]; then
    echo "Error: ${dockerfile} not found" >&2
    exit 1
fi

# Extract "image@sha256:<digest>" refs from FROM lines only. The BuildKit
# "# syntax=" directive is out of scope — scoping to FROM matches the plan
# and avoids false positives from comment directives.
refs=$(grep -iE '^[[:space:]]*FROM[[:space:]]' "${dockerfile}" \
    | grep -oE '[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}' \
    | sort -u || true)

if [ -z "${refs}" ]; then
    echo "No digest-pinned FROM lines found in ${dockerfile}"
    exit 0
fi

status=0
for ref in ${refs}; do
    digest="${ref##*@}"
    image="${ref%@*}"
    repo="${image%%:*}"

    # Split registry from repo. A leading segment with a dot, colon, or
    # "localhost" is a registry host; otherwise it's Docker Hub and an
    # unqualified name is under "library/".
    first="${repo%%/*}"
    case "${first}" in
        *.*|*:*|localhost)
            registry="${first}"
            path="${repo#*/}"
            ;;
        *)
            registry="registry-1.docker.io"
            case "${repo}" in
                */*) path="${repo}" ;;
                *)   path="library/${repo}" ;;
            esac
            ;;
    esac

    url="https://${registry}/v2/${path}/manifests/${digest}"
    accept='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json'

    resp=$(curl -sI -H "Accept: ${accept}" "${url}")

    if printf '%s' "${resp}" | grep -qi '^HTTP/[0-9.]* 401'; then
        hdr=$(printf '%s' "${resp}" | tr -d '\r' | grep -i '^www-authenticate:' || true)
        realm=$(printf '%s' "${hdr}" | grep -oE 'realm="[^"]+"' | head -1 | cut -d'"' -f2)
        service=$(printf '%s' "${hdr}" | grep -oE 'service="[^"]+"' | head -1 | cut -d'"' -f2)
        scope=$(printf '%s' "${hdr}" | grep -oE 'scope="[^"]+"' | head -1 | cut -d'"' -f2)
        if [ -z "${scope}" ]; then
            scope="repository:${path}:pull"
        fi
        token=$(curl -s "${realm}?service=${service}&scope=${scope}" \
            | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("token") or d.get("access_token",""))')
        resp=$(curl -sI -H "Accept: ${accept}" -H "Authorization: Bearer ${token}" "${url}")
    fi

    ct=$(printf '%s' "${resp}" | tr -d '\r' | awk 'tolower($1) == "content-type:" { sub(/^[^:]+: */, ""); print; exit }')

    case "${ct}" in
        *image.index*|*manifest.list*)
            echo "OK: ${ref} -> ${ct}"
            ;;
        *)
            echo "::error::${ref} is NOT a manifest list (Content-Type: ${ct:-<none>})."
            echo "       Pin the OCI index digest so both amd64 and arm64 resolve."
            status=1
            ;;
    esac
done

exit "${status}"
