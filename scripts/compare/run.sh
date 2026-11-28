#!/usr/bin/env bash
# Run every compared tool over the comparison fixtures and keep what each one
# printed. This is the measurement behind docs/compare.md; score.py reads the
# output directory and prints the page's tables.
#
#   scripts/compare/run.sh OUT_DIR
#
# Needs Docker with the Compose plugin. Nothing here starts a fixture: each
# tool reads the files, and `docker compose config` only renders them.
#
# The image tags below are the versions this measurement was last made on.
# They are a record, not a dependency of the project, so Renovate does not
# manage them. To measure newer versions, change the tags, run again, and
# update docs/compare.md from the new output. The digest each tag resolved to
# is written to OUT_DIR/versions.txt.
set -u

COMPOSE_LINT=composelint/compose-lint:1.8.2
DCLINT=zavoloklom/dclint:3.1.0
KICS=checkmarx/kics:v2.2.1
DOCKSEC=owasp/docksec:2026.9.21
SEMGREP=semgrep/semgrep:1.187.0
CHECKOV=bridgecrew/checkov:3.4.11
TRIVY=aquasec/trivy:0.76.2
HADOLINT=hadolint/hadolint:v2.15.1

here=$(cd "$(dirname "$0")" && pwd)
fixtures=$here/fixtures
out=${1:?usage: run.sh OUT_DIR}
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# name image network src_dir out_dir [docker args] -- tool args
run() {
  local name=$1 image=$2 net=$3 src=$4 dest=$5
  shift 5
  local extra=()
  while [ "$1" != "--" ]; do
    extra+=("$1")
    shift
  done
  shift
  docker run --rm --log-driver none --network "$net" \
    -v "$src:/src:ro" "${extra[@]}" "$image" "$@" \
    >"$dest/$name.stdout" 2>"$dest/$name.stderr"
  echo $? >"$dest/$name.exit"
}

# The five tools that read Compose files, on one directory. KICS's separate
# secrets scanner is on for the single-file fixtures, where one row is a
# credential, and off for the multi-file scenarios, which have none.
compose_tools() {
  local src=$1 dest=$2 kics_secrets=$3
  mkdir -p "$dest/kics" "$dest/docksec"
  run compose-lint "$COMPOSE_LINT" none "$src" "$dest" -w /src -- \
    check --format json /src/compose.yaml
  run dclint "$DCLINT" none "$src" "$dest" -- -f json -r /src
  run kics "$KICS" none "$src" "$dest" -v "$dest/kics:/out" -- \
    scan -p /src -o /out --report-formats json -t DockerCompose \
    --no-progress --no-color ${kics_secrets:+"$kics_secrets"}
  run docksec "$DOCKSEC" none "$src" "$dest" \
    -v "$dest/docksec:/root/.docksec/results" -- \
    --compose /src/compose.yaml --format json --scan-only
  run semgrep "$SEMGREP" bridge "$src" "$dest" -- \
    semgrep --metrics=off --config p/docker-compose --json /src
}

# The three that do not, on the two single-file fixtures only.
other_tools() {
  local src=$1 dest=$2
  run checkov "$CHECKOV" none "$src" "$dest" -- -f /src/compose.yaml -o json
  run trivy "$TRIVY" bridge "$src" "$dest" -- config /src -f json
  run hadolint "$HADOLINT" none "$src" "$dest" -- \
    hadolint -f json /src/compose.yaml
}

# A working copy of a fixture. A file named `dot-env` becomes `.env`: the
# repository does not track `.env` files, so the two scenarios that need one
# keep it under that name. The version-key variant also gets the obsolete
# `version:` key at the top of each YAML file, which two of the tools need
# before their rules match.
prepare() {
  local src=$1 dest=$2 variant=$3 f
  cp -a "$src" "$dest"
  if [ -f "$dest/dot-env" ]; then
    mv "$dest/dot-env" "$dest/.env"
  fi
  if [ "$variant" = version-key ]; then
    while IFS= read -r f; do
      { echo 'version: "3.9"'; cat "$f"; } >"$f.tmp" && mv "$f.tmp" "$f"
    done < <(find "$dest" -type f \( -name '*.yml' -o -name '*.yaml' \))
  fi
}

{
  date -u +'run %Y-%m-%dT%H:%M:%SZ'
  docker version --format 'docker {{.Server.Version}}'
  docker compose version
  for image in "$COMPOSE_LINT" "$DCLINT" "$KICS" "$DOCKSEC" "$SEMGREP" \
    "$CHECKOV" "$TRIVY" "$HADOLINT"; do
    docker pull -q "$image" >/dev/null
    docker image inspect --format "$image {{index .RepoDigests 0}}" "$image"
  done
  echo "compose-lint $(docker run --rm --log-driver none "$COMPOSE_LINT" --version 2>&1 | tail -1)"
  echo "dclint $(docker run --rm --log-driver none "$DCLINT" --version 2>&1 | tail -1)"
  echo "kics $(docker run --rm --log-driver none "$KICS" version 2>&1 | tail -1)"
  echo "docksec $(docker run --rm --log-driver none "$DOCKSEC" --version 2>&1 | tail -1)"
  echo "semgrep $(docker run --rm --log-driver none "$SEMGREP" semgrep --version 2>&1 | tail -1)"
  echo "checkov $(docker run --rm --log-driver none "$CHECKOV" --version 2>&1 | tail -1)"
  echo "trivy $(docker run --rm --log-driver none "$TRIVY" --version 2>&1 | head -1)"
  echo "hadolint $(docker run --rm --log-driver none "$HADOLINT" hadolint --version 2>&1 | tail -1)"
} >"$out/versions.txt" 2>&1

for fixture in same-file owasp; do
  for variant in as-written version-key; do
    src=$work/$fixture-$variant
    prepare "$fixtures/$fixture" "$src" "$variant"
    dest=$out/$fixture/$variant
    mkdir -p "$dest"
    compose_tools "$src" "$dest" ""
    other_tools "$src" "$dest"
    echo "done $fixture $variant"
  done
done

for dir in "$fixtures"/multi/*/; do
  scenario=$(basename "$dir")
  for variant in as-written version-key; do
    src=$work/multi-$scenario-$variant
    prepare "${dir%/}" "$src" "$variant"
    dest=$out/multi/$scenario/$variant
    mkdir -p "$dest"
    if [ "$variant" = as-written ]; then
      # What Compose deploys, as the ground truth for the scenario.
      (cd "$src" && docker compose config --format json) \
        >"$out/multi/$scenario/compose-config.json" \
        2>"$out/multi/$scenario/compose-config.stderr"
    fi
    compose_tools "$src" "$dest" --disable-secrets
  done
  echo "done multi/$scenario"
done
echo ALL-DONE
