"""Per-page <title> and meta description for the docs site, derived at build time.

Both values are computed from content that already exists — the nav title and the
page's own prose — because the markdown under docs/ is the same text `--explain`
prints raw, so it cannot carry YAML front matter, and mkdocs.yml's rule against
duplicating content rules out a hand-maintained table of titles and blurbs here.

What it fixes:

- **Title order.** The nav label leads with the rule code ("CL-0007 read_only —
  Read-only file system errors"), which is what mkdocs-material puts first in
  <title>. Nobody searches "CL-0007"; they search the symptom. The code moves to
  the end so the searchable half leads, while the sidebar label stays short.
- **Homepage title.** mkdocs-material titles the homepage with the bare
  `site_name` ("compose-lint"), which matches no search anyone types. It gets
  the lead clause of `site_description` instead, so the page reads as what it
  is: "Security linter for Docker Compose files - compose-lint".
- **Descriptions.** Without this, all ~45 pages inherit the single
  `site_description` from mkdocs.yml, so every search snippet describes the tool
  rather than the page.

- **Indexing surface.** mkdocs builds every file under docs/, so the 38 ADRs,
  the release/CI/maintainer pages and the Docker Hub overview all shipped as
  self-canonical, indexable URLs — 101 in the sitemap against ~45 in the nav —
  on a site where crawl demand, not content, was the measured bottleneck. Every
  page outside the nav now carries `<meta name="robots" content="noindex,
  follow">` and is dropped from `sitemap.xml` (and its `.gz` twin), so the
  curated nav in mkdocs.yml is also the list of what search engines index.
  The pages still build and stay linkable; `follow` keeps their outbound links
  counting.

- **Share cards and structured data.** The theme emits no Open Graph or Twitter
  tags, so a docs link pasted into Slack, Reddit or a newsletter rendered bare.
  Every indexable page now gets them, built from the title and description
  above and the repository's social preview image, plus JSON-LD: a
  `SoftwareApplication` on the homepage, `TechArticle` + `BreadcrumbList` on
  rule pages and `Article` on the study, with `dateModified` from git. mkdocs
  itself emits none of this, and the search-engine guidance for it is explicit
  about wanting it.
- **Last updated.** The sitemap already carries a real per-page git date (see
  `mkdocs_git_dates_hook.py`); mirroring it into `page.meta.revision_date`
  makes the theme print it under the content as well.

mkdocs-material reads `page.meta.title`, `page.meta.description` and
`page.meta.revision_date` ahead of its own defaults, so setting them here is
enough. The robots, Open Graph and JSON-LD tags have no such hook in the theme,
so they are spliced into the rendered HTML in `on_post_page`, and the sitemap
is rewritten after the build because mkdocs renders it from every documentation
page with no exclusion option.
"""

from __future__ import annotations

import gzip
import html
import json
import re
import tomllib
from pathlib import Path

# "CL-0007 read_only — Read-only file system errors" -> code, remainder.
_RULE_TITLE = re.compile(r"^(CL-\d{4})\s+(.*)$")

_MAX_DESCRIPTION = 155

# Rule pages open with a severity/derivation/references block before any prose, so
# the first paragraph is metadata. "Why it matters" states the risk in prose and
# makes the better snippet; "What it detects" is the fallback.
_PREFERRED_SECTIONS = ("why it matters", "what it detects")

_FENCE = re.compile(r"^\s*(```|~~~)")
_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
_SKIP_LINE = re.compile(
    r"""^\s*(
        [-*+]\s          # bullet list
      | \d+\.\s          # ordered list
      | >                # blockquote
      | \|               # table row
      | !\[              # image
      | \*\*[A-Za-z /]+:\*\*   # **Severity:** and friends — label, not prose
    )""",
    re.VERBOSE,
)

# Inline markdown that should not reach a search snippet. Emphasis markers are
# unwrapped pair-by-pair rather than stripped blindly: a blind strip turns
# `read_only` into "readonly", which is exactly the term the page is about.
_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_STRONG = re.compile(r"\*\*([^*]+)\*\*")
_ITALIC_STAR = re.compile(r"(?<!\w)\*([^*]+)\*(?!\w)")
_ITALIC_UNDERSCORE = re.compile(r"(?<!\w)_([^_]+)_(?!\w)")


def _clean(text: str) -> str:
    text = _LINK.sub(r"\1", text)
    text = _STRONG.sub(r"\1", text)
    text = _ITALIC_STAR.sub(r"\1", text)
    text = _ITALIC_UNDERSCORE.sub(r"\1", text)
    text = text.replace("`", "")
    return re.sub(r"\s+", " ", text).strip()


def _truncate(text: str) -> str:
    if len(text) <= _MAX_DESCRIPTION:
        return text
    clipped = text[:_MAX_DESCRIPTION].rsplit(" ", 1)[0].rstrip(" ,;:—-")
    return f"{clipped}…"


def _paragraphs(markdown: str):
    """Yield (section_title, paragraph) for each prose paragraph, fences skipped."""
    section = ""
    buffer: list[str] = []
    in_fence = False

    def flush():
        if buffer:
            joined = " ".join(buffer)
            buffer.clear()
            return joined
        return None

    for line in markdown.splitlines():
        if _FENCE.match(line):
            in_fence = not in_fence
            paragraph = flush()
            if paragraph:
                yield section, paragraph
            continue
        if in_fence:
            continue

        heading = _HEADING.match(line)
        if heading:
            paragraph = flush()
            if paragraph:
                yield section, paragraph
            section = heading.group(2).strip().lower()
            continue

        if not line.strip() or _SKIP_LINE.match(line):
            paragraph = flush()
            if paragraph:
                yield section, paragraph
            continue

        buffer.append(line.strip())

    paragraph = flush()
    if paragraph:
        yield section, paragraph


def _usable(paragraph: str) -> str | None:
    """A snippet has to stand alone: no list lead-ins, no fragments."""
    cleaned = _clean(paragraph)
    if len(cleaned) < 60 or cleaned.endswith(":"):
        return None
    return cleaned


def _description(markdown: str) -> str | None:
    candidates = list(_paragraphs(markdown))
    for wanted in _PREFERRED_SECTIONS:
        for section, paragraph in candidates:
            if section.startswith(wanted):
                usable = _usable(paragraph)
                if usable:
                    return _truncate(usable)
    for _, paragraph in candidates:
        usable = _usable(paragraph)
        if usable:
            return _truncate(usable)
    return None


def _title(page_title: str | None) -> str | None:
    """Move a leading rule code to the end: search terms belong first."""
    if not page_title:
        return None
    match = _RULE_TITLE.match(page_title.strip())
    if not match:
        return None
    code, remainder = match.group(1), match.group(2).strip(" :—-")
    if not remainder:
        return None
    return f"{remainder} ({code})"


def _home_title(site_description: str | None) -> str | None:
    """The homepage's searchable title: the lead clause of site_description."""
    if not site_description:
        return None
    lead = site_description.split("—", 1)[0].strip(" .")
    return lead or None


_ROBOTS_UNLISTED = "noindex, follow"
_ROBOTS_TAG = '<meta name="robots" content="{}">'
_HEAD_END = "</head>"
_SITEMAP_ENTRY = re.compile(r"\s*<url>\s*<loc>([^<]*)</loc>.*?</url>", re.DOTALL)

# Rebuilt by on_nav on every build (`mkdocs serve` keeps this module loaded
# across rebuilds, so neither may accumulate).
_nav_src_uris: set[str] = set()
_noindexed_locs: set[str] = set()


def on_nav(nav, config, files):  # noqa: ARG001 - mkdocs signature
    _nav_src_uris.clear()
    _nav_src_uris.update(page.file.src_uri for page in nav.pages)
    _noindexed_locs.clear()
    return nav


def _unlisted(page) -> bool:
    return page.file.src_uri not in _nav_src_uris


def on_page_markdown(markdown, page, config, files):  # noqa: ARG001 - mkdocs signature
    meta = page.meta if page.meta is not None else {}

    if "title" not in meta:
        if page.is_homepage:
            retitled = _home_title(config.get("site_description"))
        else:
            retitled = _title(page.title)
        if retitled:
            meta["title"] = retitled

    if "description" not in meta:
        description = _description(markdown)
        if description:
            meta["description"] = description

    if "robots" not in meta and _unlisted(page):
        meta["robots"] = _ROBOTS_UNLISTED
        loc = page.canonical_url or page.abs_url
        if loc:
            _noindexed_locs.add(loc)

    page.meta = meta
    return markdown


def on_page_context(context, page, config, nav):  # noqa: ARG001 - mkdocs signature
    # mkdocs_git_dates_hook sets `update_date` in on_env, which runs after every
    # page's markdown pass and before any template renders — so this is the
    # first event that sees the git date. mkdocs' own value is the build date,
    # which is still a date, so the field is never left empty.
    meta = page.meta if page.meta is not None else {}
    if "revision_date" not in meta and getattr(page, "update_date", None):
        meta["revision_date"] = page.update_date
    page.meta = meta
    return context


_SOCIAL_IMAGE = "assets/social-preview.png"
_PYPI_URL = "https://pypi.org/project/compose-lint/"
_MIT_URL = "https://opensource.org/license/mit"
_RULE_PAGE = re.compile(r"^rules/CL-\d{4}\.md$")
_STUDY_PAGE = "state-of-compose.md"


def _project(config) -> tuple[str | None, str | None]:
    """(version, author) from pyproject.toml beside mkdocs.yml, or Nones."""
    config_path = getattr(config, "config_file_path", None)
    if not config_path:
        return None, None
    pyproject = Path(config_path).resolve().parent / "pyproject.toml"
    try:
        project = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]
    except (OSError, KeyError, tomllib.TOMLDecodeError):
        return None, None
    authors = project.get("authors") or [{}]
    return project.get("version"), authors[0].get("name")


def _page_title(page, meta: dict) -> str:
    return meta.get("title") or page.title or ""


def _social_tags(page, config, meta: dict) -> list[str]:
    site_url = config.get("site_url") or ""
    site_name = config.get("site_name") or ""
    title = _page_title(page, meta)
    full_title = f"{title} - {site_name}" if title and site_name else title or site_name
    description = meta.get("description") or config.get("site_description") or ""
    image = site_url + _SOCIAL_IMAGE
    fields = [
        ("property", "og:type", "website" if page.is_homepage else "article"),
        ("property", "og:site_name", site_name),
        ("property", "og:title", full_title),
        ("property", "og:description", description),
        ("property", "og:url", page.canonical_url or ""),
        ("property", "og:image", image),
        ("name", "twitter:card", "summary_large_image"),
        ("name", "twitter:title", full_title),
        ("name", "twitter:description", description),
        ("name", "twitter:image", image),
    ]
    return [
        f'<meta {attr}="{key}" content="{html.escape(value, quote=True)}">'
        for attr, key, value in fields
        if value
    ]


def _jsonld(page, config, meta: dict) -> dict | None:
    site_url = config.get("site_url") or ""
    site_name = config.get("site_name") or ""
    title = _page_title(page, meta)
    description = meta.get("description") or config.get("site_description") or ""
    url = page.canonical_url or ""
    version, author_name = _project(config)
    author = {"@type": "Person", "name": author_name} if author_name else None
    src_uri = page.file.src_uri

    if page.is_homepage:
        app: dict = {
            "@context": "https://schema.org",
            "@type": "SoftwareApplication",
            "name": site_name,
            "applicationCategory": "DeveloperApplication",
            "operatingSystem": "Linux, macOS, Windows",
            "description": description,
            "url": site_url,
            "downloadUrl": _PYPI_URL,
            "license": _MIT_URL,
            "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
        }
        if config.get("repo_url"):
            app["codeRepository"] = config["repo_url"]
        if version:
            app["softwareVersion"] = version
        if author:
            app["author"] = author
        return app

    article_type = None
    if _RULE_PAGE.match(src_uri):
        article_type = "TechArticle"
    elif src_uri == _STUDY_PAGE:
        article_type = "Article"
    if article_type is None:
        return None

    article: dict = {
        "@context": "https://schema.org",
        "@type": article_type,
        "headline": title,
        "description": description,
        "url": url,
        "isPartOf": {"@type": "WebSite", "name": site_name, "url": site_url},
    }
    if meta.get("revision_date"):
        article["dateModified"] = meta["revision_date"]
    if author:
        article["author"] = author
    if article_type == "TechArticle":
        trail = (("Home", site_url), ("Rules", site_url + "#rules"), (title, url))
        article["breadcrumb"] = {
            "@type": "BreadcrumbList",
            "itemListElement": [
                {"@type": "ListItem", "position": n, "name": name, "item": item}
                for n, (name, item) in enumerate(trail, start=1)
            ],
        }
    return article


def _jsonld_script(data: dict) -> str:
    # "</" cannot appear inside a script element without ending it; JSON allows
    # the escaped form, so a title containing "</script>" stays inert.
    text = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    return f'<script type="application/ld+json">{text}</script>'


def _head_extras(page, config, meta: dict) -> list[str]:
    extras: list[str] = []
    robots = meta.get("robots")
    if robots:
        extras.append(_ROBOTS_TAG.format(robots))
        return extras  # nothing below is worth emitting on a page nobody indexes
    extras.extend(_social_tags(page, config, meta))
    data = _jsonld(page, config, meta)
    if data:
        extras.append(_jsonld_script(data))
    return extras


def on_post_page(output, page, config):
    if _HEAD_END not in output:
        return output
    extras = _head_extras(page, config, page.meta or {})
    if not extras:
        return output
    return output.replace(_HEAD_END, "".join(extras) + _HEAD_END, 1)


def _filter_sitemap(xml: str, drop: set[str]) -> tuple[str, int]:
    """Remove the <url> entries whose <loc> is in `drop`; return (xml, removed)."""
    removed = 0

    def keep(match: re.Match[str]) -> str:
        nonlocal removed
        if match.group(1) in drop:
            removed += 1
            return ""
        return match.group(0)

    return _SITEMAP_ENTRY.sub(keep, xml), removed


def _gzip_mtime(path: Path) -> int:
    """The mtime recorded in a gzip header (bytes 4-8, little-endian)."""
    with path.open("rb") as fh:
        header = fh.read(8)
    return int.from_bytes(header[4:8], "little") if len(header) == 8 else 0


def on_post_build(config):
    if not _noindexed_locs:
        return
    sitemap = Path(config["site_dir"]) / "sitemap.xml"
    if not sitemap.is_file():
        return
    xml, removed = _filter_sitemap(sitemap.read_text(encoding="utf-8"), _noindexed_locs)
    if not removed:
        return
    sitemap.write_text(xml, encoding="utf-8")
    # mkdocs gzips the sitemap right after rendering it; keep the twin in step
    # and keep its header timestamp, which mkdocs derives from the pages.
    twin = sitemap.with_suffix(".xml.gz")
    mtime = _gzip_mtime(twin) if twin.is_file() else 0
    with (
        twin.open("wb") as fh,
        gzip.GzipFile(fileobj=fh, filename=twin.name, mode="wb", mtime=mtime) as gz,
    ):
        gz.write(xml.encode("utf-8"))
