# docs/publishing/

Derived publication artifacts for the **State of Docker Compose Security** report.
The canonical, citable source is [`docs/state-of-compose.md`](../state-of-compose.md);
everything here is derived from it for distribution. Draft canonical first, then derive
these — never the other way around.

## Venues and order

| Venue | Role | Timing |
| --- | --- | --- |
| `docs/state-of-compose.md` (this repo) | **Canonical** — permanent citable URL; README hero stat links here | always current |
| [dev.to](https://dev.to) | **Primary** — indexed, shareable, the SEO-original | published first |
| [Hashnode](https://hashnode.com) | **Cross-post** — same body, points canonical at dev.to | **+48h** after dev.to |

The 48h gap exists so dev.to is indexed first; the Hashnode post then declares dev.to
as its canonical URL so the two don't compete for search ranking.

## Files

- [`state-of-compose-devto.md`](state-of-compose-devto.md) — the ~7-minute dev.to teaser
  (frontmatter + body). It is a *teaser*: it carries the headline findings and links back
  to the canonical report for the full tables, methodology, and caveats.
- [`state-of-compose-hashnode.md`](state-of-compose-hashnode.md) — Hashnode publish
  settings; reuses the dev.to body verbatim (single-sourced to avoid drift).
- `assets/*.png` — raster copies of the report charts, for the blog posts.
- `assets/cover.png` — the dev.to / Hashnode cover banner (data-driven from the run).

## Canonical-URL strategy

- **dev.to**: leave `canonical_url` blank so dev.to is treated as the original and gets
  indexing priority. (The repo doc is canonical for *citation*; dev.to is canonical for
  *search* — raw GitHub markdown doesn't rank, so handing SEO to dev.to is deliberate.)
- **Hashnode**: set Canonical URL to the live dev.to post.

## Why the blog charts are PNG, not SVG

The report embeds **SVG** (`docs/assets/*.svg`) — crisp and diffable on GitHub. But
dev.to and Hashnode load images cross-origin, and `raw.githubusercontent.com` serves
`.svg` as `text/plain`, so SVGs show up broken. **PNG** is served as `image/png` and
renders everywhere, so the blog bodies reference the PNGs in `assets/` by raw GitHub URL —
no manual upload needed once they're on `main`.

## Regenerating the chart PNGs

```bash
pip install -e '.[corpus]'
python scripts/corpus/charts.py <run-id> --png     # chart PNGs -> docs/publishing/assets/
python scripts/corpus/charts.py <run-id> --cover   # cover.png  -> docs/publishing/assets/
```

Same data path as the report's SVGs (`run.aggregate_tiers`), so the PNGs can't disagree
with the tables. The provenance caption is stamped from the run's `meta.json`, so it names
the compose-lint version that produced the run (e.g. `0.7.0`) regardless of what's
installed — important when re-rendering after a release.

## Publishing checklist

1. Confirm the canonical report on `main` reflects the pinned run, and the chart PNGs are
   committed (so the raw URLs resolve).
2. **dev.to**: paste `state-of-compose-devto.md`, set `published: true`, `canonical_url`
   blank, optionally add a cover image. Publish.
3. Wait ~48h.
4. **Hashnode**: follow `state-of-compose-hashnode.md` — paste the dev.to body, set the
   Canonical URL to the live dev.to link, publish.
5. Update the tracking issue ([#186](https://github.com/tmatens/compose-lint/issues/186))
   with both live URLs.
