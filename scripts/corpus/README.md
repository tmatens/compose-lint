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

## Charts

`charts.py` renders the report's SVGs into `docs/assets/` from a finished run. It reads the same `results.jsonl` + `index.jsonl` via `run.aggregate_tiers`, so the charts can never disagree with `tier_summary.md`.

```bash
pip install -e '.[corpus]'                   # one-time: pulls in matplotlib
python scripts/corpus/charts.py latest       # or a specific runs/<ts>
```

Commit the regenerated `docs/assets/*.svg` alongside the report when the pinned run changes. matplotlib is a maintainer-only extra — it is deliberately absent from every `requirements*.lock` and never reaches the runtime wheel (PyYAML-only).

## Fix gate

`fix_gate.py` is the parallel form of `tests/test_corpus_fix.py` — it runs the three ADR-014 fix-safety invariants (patched text re-parses, is idempotent, and introduces no new finding) over the whole corpus across all cores, ~1-2 min instead of the ~8 min single-process pytest gate.

```bash
python scripts/corpus/fix_gate.py            # all cores
LINT_WORKERS=4 python scripts/corpus/fix_gate.py
```

Use it as the fast local loop while iterating on a fixer; the committed pytest gate stays authoritative (`COMPOSE_LINT_CORPUS=~/.cache/compose-lint-corpus pytest tests/test_corpus_fix.py`). It also prints findings-fixed counts per rule — a quick coverage signal to diff against the baseline after changing a fixer. Exits non-zero if any invariant fails.

## Docker config gate (external validity)

`docker_config_gate.py` answers a question `fix_gate.py` can't: does **Docker's own loader** still accept a file after `compose-lint fix --apply`? The fix gate checks our internal ADR-014 invariants (re-parse, idempotent, no new finding); this one runs `docker compose config -q` on the patched text.

It is **differential** — many real files fail `docker compose config` on their own (missing `include:` targets, env-only required values), which isn't our regression. A file only counts as a REGRESSION when Docker accepted the *original* but rejects the *fixed* version. To stay cheap it validates the fixed file first and only re-checks the original when the fixed one fails.

```bash
python scripts/corpus/docker_config_gate.py            # all cores, full corpus (~9 min)
python scripts/corpus/docker_config_gate.py --limit 300  # quick sample
LINT_WORKERS=4 python scripts/corpus/docker_config_gate.py
```

Requires the Docker Compose CLI plugin. If `docker compose version` fails the gate SKIPs with exit 0, so a Docker-less leg never breaks on it. Install at user level (no root):

```bash
v=v5.1.4; asset="docker-compose-linux-$(uname -m)"
base="https://github.com/docker/compose/releases/download/$v"
cd "$(mktemp -d)"
curl -fsSL -O "$base/$asset" -O "$base/$asset.sha256"
sha256sum -c "$asset.sha256"                       # must print: OK
mkdir -p ~/.docker/cli-plugins
install -m 0755 "$asset" ~/.docker/cli-plugins/docker-compose
docker compose version
```

## Tiers

- `canonical` — official upstream examples (what people copy from READMEs)
- `popular` — high-star repos with compose files (production-adjacent code)
- `selfhosted` — app-store / template-registry repos (home-lab threat model)
- `longtail` — stratified GH code-search corpus (what the median wild file looks like)

`retier.py` must run after fetches: the downloader keys on `blob_sha` first-write-wins, so a curated app-store template swept up earlier by `fetch_popular` would otherwise stay tagged `popular`.

## Longtail sampling methodology

`fetch.py` is **not random sampling** — GitHub's code-search API has no random-document primitive. It is a **stratified sweep** designed to broaden coverage past the search engine's per-query result cap:

- **120 queries** = 6 anchor terms × 4 filenames × 5 size buckets
  - **Anchors**: `services:`, `image:`, `volumes:`, `restart:`, `ports:`, `depends_on:` (every real Compose file contains at least one)
  - **Filenames**: `docker-compose.yml`, `docker-compose.yaml`, `compose.yml`, `compose.yaml`
  - **Size buckets** (KB): `<2`, `2..5`, `5..15`, `15..50`, `>50`
- **Per-query cap**: 200 hits (`--limit 200` to `gh search code`). GitHub's hard ceiling per query is ~1000 results; 200 is fast and the stratification picks up the rest.
- **Dedup**: `(repo, path, sha)` at search time, then `content_hash` (SHA256 of bytes) at download time so identical files in different repos collapse to one corpus entry.

### Known biases (for the report's "limitations" section)

- **GitHub-search ranking bias.** Results are ranked by the search engine, so files in higher-relevance repos surface first. The size-bucket stratification mitigates this for content shape but not for repo popularity.
- **Single-source.** GitHub only — no GitLab, Codeberg, Docker Hub README snippets, or package-manager fragments.
- **Filename-pinned.** Compose files saved under non-standard names (`stack.yml`, `web.compose.yml`, etc.) are missed.
- **Public-only.** Private and enterprise-internal repos are out of scope.

This is **descriptive sampling for prevalence estimation**, not random sampling for statistical inference. The State of Compose report frames findings accordingly.

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
