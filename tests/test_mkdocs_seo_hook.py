"""scripts/mkdocs_seo_hook.py — the nav is the indexing surface.

mkdocs builds every markdown file under docs/, so without the hook the ADRs and
maintainer pages ship as ordinary indexable URLs beside the ~45 user-facing ones
and the sitemap lists all of them. What these tests pin is the rule that
replaces a hand-kept exclusion list: a page is indexable exactly when it is in
the nav. An unlisted page gets `noindex, follow` spliced into its <head> and
leaves the sitemap (and the gzipped twin mkdocs writes beside it); a listed
page is left untouched. A page that already declares `robots` keeps its value,
so a future deliberate override is not silently overwritten.
"""

from __future__ import annotations

import gzip
import importlib.util
import pathlib
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


def _page(src_uri: str, *, meta: dict[str, str] | None = None) -> SimpleNamespace:
    url = src_uri.removesuffix("index.md").removesuffix(".md")
    url = "" if url == "" else url.rstrip("/") + "/"
    return SimpleNamespace(
        file=SimpleNamespace(src_uri=src_uri),
        title=src_uri,
        is_homepage=src_uri == "index.md",
        canonical_url=_SITE + url,
        abs_url="/docs/" + url,
        meta=meta,
    )


def _build_nav(*listed: SimpleNamespace) -> None:
    hook.on_nav(SimpleNamespace(pages=list(listed)), {}, None)


_CONFIG = {"site_description": "Linter — rules."}


def _render(page: SimpleNamespace) -> SimpleNamespace:
    hook.on_page_markdown("Some prose for a description.\n", page, _CONFIG, None)
    return page


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


def test_robots_tag_is_spliced_into_head_only_when_set() -> None:
    html = "<html><head><title>t</title></head><body></body></html>"
    marked = SimpleNamespace(meta={"robots": "noindex, follow"})
    plain = SimpleNamespace(meta={})

    assert hook.on_post_page(html, marked, {}) == (
        '<html><head><title>t</title><meta name="robots" content="noindex, follow">'
        "</head><body></body></html>"
    )
    assert hook.on_post_page(html, plain, {}) == html
    assert hook.on_post_page("no head here", marked, {}) == "no head here"


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
