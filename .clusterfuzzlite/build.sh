#!/usr/bin/env bash
# Build script invoked by ClusterFuzzLite inside the OSS-Fuzz base-builder
# image. Installs compose-lint and its Atheris-instrumented dependencies,
# compiles each fuzzer in fuzz/, and packages a seed corpus derived from
# the existing test fixtures.
set -euo pipefail

pip install --no-cache-dir --require-hashes -r requirements.lock
pip install --no-cache-dir --no-deps .

for fuzzer in "$SRC"/compose-lint/fuzz/fuzz_*.py; do
  fuzzer_basename=$(basename "$fuzzer" .py)
  compile_python_fuzzer "$fuzzer"

  # Seed the fuzzer from the existing Compose fixtures so it starts from
  # structurally valid inputs and gets useful coverage on the first run.
  seed_dir=$(mktemp -d)
  cp "$SRC"/compose-lint/tests/compose_files/*.yml "$seed_dir"/
  (cd "$seed_dir" && zip -q "$OUT/${fuzzer_basename}_seed_corpus.zip" ./*.yml)
  rm -rf "$seed_dir"
done
