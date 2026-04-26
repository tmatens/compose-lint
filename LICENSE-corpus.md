# Corpus snapshot — licensing posture

`tests/corpus_snapshot.json.gz` is a regression digest of compose-lint's
output across a corpus of public Docker Compose files. Its shape is
documented in `scripts/snapshot.py` and enforced by
`tests/test_corpus_snapshot_schema.py`.

## What's in the snapshot

Per file, only:

- the file's SHA256 content hash, used as a key
- a sorted list of `(rule_id, service, line)` tuples for every finding
  compose-lint emitted on that file
- whether the file produced a parse error

Plus run metadata: schema version, corpus manifest hash, compose-lint
version, file count.

## What's not in the snapshot

- No source paths, repo names, repo URLs, or blob SHAs
- No finding messages, fix text, or reference URLs
- No raw or partial Compose YAML

The schema test (`tests/test_corpus_snapshot_schema.py`) blocks any
future change that would widen the schema to include third-party
content.

## Why this matters

The corpus itself (compose files cached at
`~/.cache/compose-lint-corpus/files/` after `scripts/fetch.py`) is third-
party content. Each file retains its original repository's license. We
do not redistribute corpus files: they live only in a developer's local
cache or in scoped CI artifacts, never as a public release asset or as
content checked into this repository.

The snapshot itself is non-derivative — content hashes plus our own
analytical metadata (rule IDs, service names, line numbers) — and ships
under the project's MIT license alongside the rest of the source tree.

If you are extending the corpus tooling, do not commit `index.jsonl`,
any file under `files/`, or any output that contains third-party paths
or YAML content.
