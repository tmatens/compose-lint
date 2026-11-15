# docs/publishing/

Publication copies of two pages: the **State of Docker Compose Security**
report and the **hardening guide**. The source to cite for a number is
[`docs/state-of-compose.md`](../state-of-compose.md), and everything here is
derived from it. Update the report first and these second, so an article never
shows a number the report does not.

## Venues

| Venue | Role |
| --- | --- |
| `docs/state-of-compose.md` (this repo and the docs site) | The report. Its URL is permanent and the README links to it. |
| [dev.to](https://dev.to/tmatens/9-in-10-docker-compose-files-skip-the-basic-security-flags-2dpf) | The article, a shorter read that links back to the report. |
| `docs/hardening.md` (this repo and the docs site) | The hardening guide, the reference copy that follows the rules as they change. |
| [dev.to](https://dev.to/tmatens/docker-compose-security-hardening-one-file-from-12-findings-to-none-4hl7) | The hardening article, scheduled for 2026-11-17. The link works from then. |

## Files

- [`state-of-compose-devto.md`](state-of-compose-devto.md): the dev.to
  article. It carries the headline findings and links to the report for the
  tables, the method and the caveats.
- [`hardening-devto.md`](hardening-devto.md): the dev.to hardening article.
  It is a shorter, first-person version of the guide, and links to the guide
  and the rule pages for the detail it leaves out.
- `assets/*.png`: raster copies of the report's charts for the article.
- `assets/cover.png`: the article's cover image, drawn from the run.

## Canonical URL

The dev.to article's canonical URL is itself. Raw GitHub Markdown does not
rank in search, so the article is the search-facing copy and the report is
the one to cite.

The article is published in one place. A Hashnode cross-post existed until
November 2026 and was deleted: it had to be updated by hand after every edit,
and its canonical URL pointed at dev.to, so it could not rank on its own.

## Why the article charts are PNG

The report embeds SVG (`docs/assets/*.svg`), which is sharp and diffs well.
dev.to loads images from another origin, and
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

## The hardening article

The article and the guide are separate texts. The guide keeps the reference
material the article leaves out, such as the capability measurements and the
question section. Both take their percentages from the report, as shares of
the files that parsed, so a new edition of the report means checking both. The
article has no charts. Its cover is kept on dev.to and is not in this repo.

To change the article, edit `hardening-devto.md`, merge, and paste the body
into the dev.to editor. The slug does not change.

## Updating for a new edition

1. Update the report, regenerate the charts and merge to `main`.
2. Check that the docs site shows the new edition and that the PNG URLs serve
   the new charts.
3. Update the dev.to article from `state-of-compose-devto.md`: title, body and
   cover. The slug does not change.
4. Check every percentage in `docs/hardening.md` and `hardening-devto.md`
   against the new run, and update the hardening article the same way.
5. Note the update on the tracking issue
   ([#186](https://github.com/tmatens/compose-lint/issues/186)).
