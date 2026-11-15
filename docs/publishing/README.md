# docs/publishing/

Publication copies of the **State of Docker Compose Security** report. The
source to cite is [`docs/state-of-compose.md`](../state-of-compose.md), and
everything here is derived from it. Update the report first and these second,
so an article never shows a number the report does not.

## Venues

| Venue | Role |
| --- | --- |
| `docs/state-of-compose.md` (this repo and the docs site) | The report. Its URL is permanent and the README links to it. |
| [dev.to](https://dev.to/tmatens/9-in-10-docker-compose-files-skip-the-basic-security-flags-2dpf) | The article, a shorter read that links back to the report. |
| [Hashnode](https://hashnode.com) | A cross-post of the dev.to article, with its canonical URL set to dev.to. |

## Files

- [`state-of-compose-devto.md`](state-of-compose-devto.md): the dev.to
  article. It carries the headline findings and links to the report for the
  tables, the method and the caveats.
- [`state-of-compose-hashnode.md`](state-of-compose-hashnode.md): the Hashnode
  publish settings. The body is the dev.to body.
- `assets/*.png`: raster copies of the report's charts for the articles.
- `assets/cover.png`: the cover image for both articles, drawn from the run.

## Canonical URLs

- **dev.to**: its canonical URL is itself. Raw GitHub Markdown does not rank
  in search, so the article is the search-facing copy and the report is the
  one to cite.
- **Hashnode**: the canonical URL is the live dev.to post.

## Why the article charts are PNG

The report embeds SVG (`docs/assets/*.svg`), which is sharp and diffs well.
dev.to and Hashnode load images from another origin, and
`raw.githubusercontent.com` serves `.svg` as `text/plain`, so an SVG shows as
a broken image there. A PNG is served as `image/png` and renders. The article
links the PNGs in `assets/` by their raw GitHub URL, so nothing is uploaded by
hand once they are on `main`.

dev.to copies each image to its own storage when an article is saved. A live
article keeps the charts it was saved with, and replacing a PNG on `main` does
not change it until the article is saved again.

## Regenerating the charts

```bash
pip install -e '.[corpus]'
python scripts/corpus/charts.py <run-id>           # SVGs  -> docs/assets/
python scripts/corpus/charts.py <run-id> --png     # PNGs  -> docs/publishing/assets/
python scripts/corpus/charts.py <run-id> --cover   # cover -> docs/publishing/assets/
```

All three read the same run, so the images cannot disagree with the report's
tables. The source line under each chart is taken from the run's `meta.json`,
so it names the compose-lint version that produced the run (for example
`1.6.0`) whatever version is installed when the chart is drawn.

## Updating for a new edition

1. Update the report, regenerate the charts and merge to `main`.
2. Check that the docs site shows the new edition and that the PNG URLs serve
   the new charts.
3. Update the dev.to article from `state-of-compose-devto.md`: title, body and
   cover. The slug does not change.
4. Update the Hashnode post as `state-of-compose-hashnode.md` describes.
5. Note both updates on the tracking issue
   ([#186](https://github.com/tmatens/compose-lint/issues/186)).
