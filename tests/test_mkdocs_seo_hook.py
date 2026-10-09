"""scripts/mkdocs_seo_hook.py — the nav is the indexing surface, and what an
indexable page carries in its <head>.

mkdocs builds every markdown file under docs/, so without the hook the ADRs and
maintainer pages ship as ordinary indexable URLs beside the ~45 user-facing ones
and the sitemap lists all of them. What these tests pin is the rule that
replaces a hand-kept exclusion list: a page is indexable exactly when it is in
the nav. An unlisted page gets `noindex, follow` spliced into its <head> and
leaves the sitemap (and the gzipped twin mkdocs writes beside it); a listed
page is left untouched. A page that already declares `robots` keeps its value,
so a future deliberate override is not silently overwritten.

An indexable page instead gets the share-card tags and JSON-LD the theme does
not emit — built from the same title and description the hook derived — and
the tests pin the shape per page kind, because a wrong `@type` or a missing
`dateModified` is invisible in a browser and only shows up as a rich-result
that never appears.
"""

from __future__ import annotations

import gzip
import importlib.util
import json
import pathlib
import re
import sys
from types import SimpleNamespace

_SPEC = importlib.util.spec_from_file_location(
    "mkdocs_seo_hook",
    pathlib.Path(__file__).resolve().parent.parent / "scripts" / "mkdocs_seo_hook.py",
)
assert _SPEC is not None and _SPEC.loader is not None
hook = importlib.util.module_from_spec(_SPEC)
sys.modules["mkdocs_seo_hook"] = hook
_SPEC.loader.exec_module(hook)

# The hook runs inside mkdocs, but the environment that runs these tests does
# not carry the docs toolchain, so it must import with no mkdocs at runtime.
assert "mkdocs" not in sys.modules

_SITE = "https://example.test/docs/"
_REPO = "https://github.com/example/compose-lint"


class _Config(dict):
    """mkdocs passes a mapping that also exposes `config_file_path`."""

    def __init__(self, config_file_path: str | None = None, **items: str) -> None:
        super().__init__(items)
        self.config_file_path = config_file_path

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, _Config)
            and super().__eq__(other)
            and self.config_file_path == other.config_file_path
        )


def _config(config_file_path: str | None = None) -> _Config:
    return _Config(
        config_file_path,
        site_url=_SITE,
        site_name="compose-lint",
        site_description="Linter — rules.",
        repo_url=_REPO,
    )


def _page(
    src_uri: str,
    *,
    meta: dict[str, str] | None = None,
    update_date: str | None = "2026-09-30",
) -> SimpleNamespace:
    url = src_uri.removesuffix("index.md").removesuffix(".md")
    url = "" if url == "" else url.rstrip("/") + "/"
    return SimpleNamespace(
        file=SimpleNamespace(src_uri=src_uri),
        title=src_uri,
        is_homepage=src_uri == "index.md",
        canonical_url=_SITE + url,
        abs_url="/docs/" + url,
        meta=meta,
        update_date=update_date,
    )


def _build_nav(*listed: SimpleNamespace) -> None:
    hook.on_nav(SimpleNamespace(pages=list(listed)), {}, None)


def _render(page: SimpleNamespace, config: _Config | None = None) -> SimpleNamespace:
    hook.on_page_markdown(
        "Some prose for a description that is long enough to be used.\n",
        page,
        config or _config(),
        None,
    )
    return page


_HTML = "<html><head><title>t</title></head><body></body></html>"


def _head(page: SimpleNamespace, config: _Config | None = None) -> str:
    out = hook.on_post_page(_HTML, page, config or _config())
    match = re.search(r"<head>(.*)</head>", out, re.DOTALL)
    assert match is not None
    return match.group(1)


def _jsonld(head: str) -> dict:
    scripts = re.findall(r'<script type="application/ld\+json">(.*?)</script>', head)
    assert len(scripts) == 1, head
    return json.loads(scripts[0])


# --- indexing surface -----------------------------------------------------


def test_unlisted_page_is_marked_noindex_and_listed_page_is_not() -> None:
    home, guide, adr = _page("index.md"), _page("cli.md"), _page("adr/001.md")
    _build_nav(home, guide)

    for page in (home, guide, adr):
        _render(page)

    assert "robots" not in home.meta
    assert "robots" not in guide.meta
    assert adr.meta["robots"] == "noindex, follow"
    assert hook._noindexed_locs == {_SITE + "adr/001/"}


def test_declared_robots_value_is_kept() -> None:
    page = _page("adr/002.md", meta={"robots": "index"})
    _build_nav()

    _render(page)

    assert page.meta["robots"] == "index"
    assert not hook._noindexed_locs


def test_on_nav_resets_state_between_builds() -> None:
    adr = _page("adr/003.md")
    _build_nav()
    _render(adr)
    assert hook._noindexed_locs

    _build_nav(adr)

    assert not hook._noindexed_locs
    assert "robots" not in _render(_page("adr/003.md")).meta


def _contextualise(page: SimpleNamespace) -> SimpleNamespace:
    hook.on_page_context({}, page, _config(), None)
    return page


def test_revision_date_mirrors_the_git_date_unless_declared() -> None:
    _build_nav()
    dated = _contextualise(_render(_page("cli.md", update_date="2026-05-01")))
    declared = _contextualise(_page("fix.md", meta={"revision_date": "2024-01-01"}))
    undated = _contextualise(_page("severity.md", meta={}, update_date=None))

    assert dated.meta["revision_date"] == "2026-05-01"
    assert declared.meta["revision_date"] == "2024-01-01"
    assert "revision_date" not in undated.meta


def test_noindexed_page_gets_the_robots_tag_and_nothing_else() -> None:
    page = _page("adr/004.md", meta={"robots": "noindex, follow"})

    head = _head(page)

    assert head == '<title>t</title><meta name="robots" content="noindex, follow">'
    assert hook.on_post_page("no head here", page, _config()) == "no head here"


# --- share cards ----------------------------------------------------------


def test_indexable_page_gets_open_graph_and_twitter_tags() -> None:
    meta = {"title": "CLI reference", "description": 'Three "sub" & more'}
    page = _page("cli.md", meta=meta)

    head = _head(page)

    full_title = "CLI reference - compose-lint"
    description = "Three &quot;sub&quot; &amp; more"
    image = f"{_SITE}assets/social-preview.png"
    assert '<meta property="og:type" content="article">' in head
    assert f'<meta property="og:title" content="{full_title}">' in head
    assert f'<meta property="og:description" content="{description}">' in head
    assert f'<meta property="og:url" content="{_SITE}cli/">' in head
    assert f'<meta property="og:image" content="{image}">' in head
    assert '<meta name="twitter:card" content="summary_large_image">' in head
    assert f'<meta name="twitter:title" content="{full_title}">' in head
    assert "application/ld+json" not in head  # a guide page carries no article schema


def test_homepage_is_typed_as_a_website() -> None:
    page = _page("index.md", meta={"title": "Security linter", "description": "d"})

    head = _head(page)

    assert '<meta property="og:type" content="website">' in head


# --- structured data ------------------------------------------------------


def test_homepage_emits_software_application_from_pyproject(
    tmp_path: pathlib.Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "compose-lint"\nversion = "9.9.9"\n'
        'authors = [{ name = "A. Maintainer" }]\n',
        encoding="utf-8",
    )
    config = _config(str(tmp_path / "mkdocs.yml"))
    meta = {"title": "Security linter", "description": "What it is."}
    page = _page("index.md", meta=meta)

    data = _jsonld(_head(page, config))

    assert data["@type"] == "SoftwareApplication"
    assert data["name"] == "compose-lint"
    assert data["softwareVersion"] == "9.9.9"
    assert data["author"] == {"@type": "Person", "name": "A. Maintainer"}
    assert data["codeRepository"] == _REPO
    assert data["downloadUrl"] == "https://pypi.org/project/compose-lint/"
    assert data["offers"]["price"] == "0"
    assert data["description"] == "What it is."


def test_missing_pyproject_drops_version_and_author_rather_than_failing() -> None:
    config = _config("/nonexistent/mkdocs.yml")
    page = _page("index.md", meta={"title": "t", "description": "d"})

    data = _jsonld(_head(page, config))

    assert data["@type"] == "SoftwareApplication"
    assert "softwareVersion" not in data
    assert "author" not in data


def test_rule_page_emits_tech_article_with_breadcrumb_and_date() -> None:
    page = _page(
        "rules/CL-0007.md",
        meta={
            "title": "read_only — Read-only file system errors (CL-0007)",
            "description": "Why it matters.",
            "revision_date": "2026-09-30",
        },
    )

    data = _jsonld(_head(page))

    assert data["@type"] == "TechArticle"
    assert data["headline"] == "read_only — Read-only file system errors (CL-0007)"
    assert data["dateModified"] == "2026-09-30"
    assert data["url"] == _SITE + "rules/CL-0007/"
    site = {"@type": "WebSite", "name": "compose-lint", "url": _SITE}
    assert data["isPartOf"] == site
    crumbs = data["breadcrumb"]["itemListElement"]
    assert [c["name"] for c in crumbs] == ["Home", "Rules", data["headline"]]
    assert [c["item"] for c in crumbs] == [_SITE, _SITE + "#rules", data["url"]]


def test_study_page_emits_article_without_breadcrumb() -> None:
    page = _page("state-of-compose.md", meta={"title": "State", "description": "d"})

    data = _jsonld(_head(page))

    assert data["@type"] == "Article"
    assert "breadcrumb" not in data
    assert "dateModified" not in data


def test_script_terminator_inside_a_title_cannot_close_the_script_element() -> None:
    meta = {"title": "a</script><b>", "description": "d"}
    page = _page("rules/CL-0001.md", meta=meta)

    head = _head(page)

    assert "a</script><b>" not in head
    assert _jsonld(head)["headline"] == "a</script><b>"


# --- sitemap --------------------------------------------------------------

_SITEMAP = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
         <loc>{_SITE}</loc>
         <lastmod>2026-10-07</lastmod>
    </url>
    <url>
         <loc>{_SITE}adr/001/</loc>
         <lastmod>2026-04-07</lastmod>
    </url>
    <url>
         <loc>{_SITE}cli/</loc>
         <lastmod>2026-09-30</lastmod>
    </url>
</urlset>
"""


def test_filter_sitemap_drops_only_the_named_locations() -> None:
    xml, removed = hook._filter_sitemap(_SITEMAP, {_SITE + "adr/001/"})

    assert removed == 1
    assert "adr/001" not in xml
    assert f"<loc>{_SITE}</loc>" in xml
    assert f"<loc>{_SITE}cli/</loc>" in xml
    assert xml.startswith('<?xml version="1.0"') and xml.rstrip().endswith("</urlset>")


def test_post_build_rewrites_sitemap_and_its_gzip_twin(tmp_path: pathlib.Path) -> None:
    sitemap = tmp_path / "sitemap.xml"
    sitemap.write_text(_SITEMAP, encoding="utf-8")
    twin = tmp_path / "sitemap.xml.gz"
    with (
        twin.open("wb") as fh,
        gzip.GzipFile(fileobj=fh, mode="wb", mtime=1_700_000_000) as gz,
    ):
        gz.write(_SITEMAP.encode("utf-8"))
    _build_nav(_page("index.md"), _page("cli.md"))
    _render(_page("adr/001.md"))

    hook.on_post_build({"site_dir": str(tmp_path)})

    rewritten = sitemap.read_text(encoding="utf-8")
    assert "adr/001" not in rewritten
    assert rewritten.count("<url>") == 2
    assert gzip.decompress(twin.read_bytes()).decode("utf-8") == rewritten
    assert hook._gzip_mtime(twin) == 1_700_000_000


def test_post_build_leaves_sitemap_alone_when_nothing_is_unlisted(
    tmp_path: pathlib.Path,
) -> None:
    sitemap = tmp_path / "sitemap.xml"
    sitemap.write_text(_SITEMAP, encoding="utf-8")
    _build_nav(_page("index.md"), _page("adr/001.md"), _page("cli.md"))
    _render(_page("adr/001.md"))

    hook.on_post_build({"site_dir": str(tmp_path)})

    assert sitemap.read_text(encoding="utf-8") == _SITEMAP
    assert not (tmp_path / "sitemap.xml.gz").exists()
