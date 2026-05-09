# scripts/corpus/

Pipeline that fetches real-world Docker Compose files from public GitHub repos and lints them with compose-lint. Outputs feed the **State of Docker Compose Security** report (`docs/state-of-compose.md`) and provide source material for the wild-fixture test set.

Data lives outside the repo at `~/.cache/compose-lint-corpus/` (compose files, lint runs, index). Only this code is in git.

## Pipeline

Run in order; each step is idempotent.

```bash
python scripts/corpus/fetch.py              # longtail (random GH code search)
python scripts/corpus/fetch_popular.py      # popular (>=50★, recent topics)
python scripts/corpus/fetch_canonical.py    # canonical (curated upstream repos)
python scripts/corpus/fetch_selfhosted.py   # selfhosted (curated app stores)
python scripts/corpus/retier.py             # promote curated repos to correct tier
python scripts/corpus/enrich_metadata.py    # backfill stars/pushed_at/topics
python scripts/corpus/run.py                # lint everything → runs/<ts>/
```

If you only edited the curated lists, skip the fetches: `retier.py` then `make_tier_summary.py` regenerates per-tier numbers without re-linting.

## Tiers

- `canonical` — official upstream examples (what people copy from READMEs)
- `popular` — high-star repos with compose files (production-adjacent code)
- `selfhosted` — app-store / template-registry repos (home-lab threat model)
- `longtail` — random GH code-search corpus (what the median wild file looks like)

`retier.py` must run after fetches: the downloader keys on `blob_sha` first-write-wins, so a curated app-store template swept up earlier by `fetch_popular` would otherwise stay tagged `popular`.

## Requirements

- `gh` CLI authenticated (`gh auth status` shows a valid token)
- A built compose-lint in the repo `.venv/` (or set `COMPOSE_LINT_BIN`)
- Python 3.10+

## Output layout

```
~/.cache/compose-lint-corpus/
├── files/<sha256>.yml         # one unique compose file per content hash
├── index.jsonl                # {content_hash, blob_sha, repo, path, url, size, tier, stars, pushed_at, default_branch, topics}
└── runs/<UTC-timestamp>/
    ├── results.jsonl          # per-file lint output (raw compose-lint JSON)
    ├── summary.md             # whole-corpus aggregate
    ├── tier_summary.md        # per-tier counts, severity, top-10 rules
    └── meta.json              # tool version, timing, worker count
```

`results.jsonl` does NOT carry the tier — join against `index.jsonl` on `content_hash`. See `summary.md` for jq snippets.
