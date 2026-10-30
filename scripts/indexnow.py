"""Tell IndexNow which docs-site pages a deploy changed.

Bing (and through it Copilot, ChatGPT search and DuckDuckGo), Yandex, Seznam
and Naver share the IndexNow protocol: a POST listing changed URLs, which they
treat as a crawl hint, and each engine forwards what it receives to the
others. Without it a retitled or rewritten page waits for the next organic
crawl, which for a small site with few inbound links can take weeks. Google
does not take part; Search Console's Request indexing is its equivalent and
stays manual.

The POST goes to Bing's own endpoint rather than the api.indexnow.org
aggregator. Eleven days of HTTP 200 from the aggregator left a new page
"Discovered but not crawled" on Bing and the Webmaster Tools IndexNow report
empty, while URLs submitted through Webmaster Tools were crawled within three
days; posting to the engine that matters removes one hop from that question.

The protocol proves ownership with a key file served by the site. It lives at
`docs/<key>.txt` (the key is the file's name and its whole content), so it
publishes at the site root below `/compose-lint/`. A key file outside the host
root is allowed, but only URLs below its directory may be submitted, which is
exactly the docs site. The key is public by design: anyone can read it from
the site, and all it lets them do is submit this site's own URLs for crawling.

Which URLs: the pages whose source changed between the push's `before` and
`HEAD`, kept only if the live sitemap lists them. The sitemap is the indexable
surface (the SEO hook drops every `noindex` page from it), so an ADR edit is
never submitted. A change to `mkdocs.yml`, a build hook or the docs toolchain
can alter every page's title, nav or markup, so it submits the whole sitemap,
as does a run with no usable `before` (a manual dispatch, or a first push).

Runs in the docs workflow after the Pages deploy, so the pages and the key file
are live before the engines are told to fetch them. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from xml.etree import ElementTree

SITE_URL = "https://tmatens.github.io/compose-lint/"
ENDPOINT = "https://www.bing.com/indexnow"

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS = "docs/"

# A change to any of these can re-render every page, so it resubmits them all.
SITE_WIDE = (
    re.compile(r"^mkdocs\.yml$"),
    re.compile(r"^scripts/mkdocs_[a-z_]+_hook\.py$"),
    re.compile(r"^requirements-docs\.lock$"),
)

_KEY = re.compile(r"^[0-9a-f]{32}$")
_ZERO_SHA = re.compile(r"^0+$")
_SITEMAP_NS = "{http://www.sitemaps.org/schemas/sitemap/0.9}"


def find_key(docs_dir: Path) -> str:
    """Return the key from the one `docs/<key>.txt` whose content is its name."""
    keys = [
        p.stem
        for p in docs_dir.glob("*.txt")
        if _KEY.match(p.stem) and p.read_text().strip() == p.stem
    ]
    if len(keys) != 1:
        raise SystemExit(
            f"expected exactly one IndexNow key file in {docs_dir}, found {len(keys)}"
        )
    return keys[0]


def page_url(path: str) -> str | None:
    """Map a changed repo path to its page URL, or None if it is not a page.

    mkdocs' directory URLs: `docs/cli.md` is `cli/`, `docs/index.md` is the
    site root, and `docs/examples/index.md` is `examples/`.
    """
    if not path.startswith(DOCS) or not path.endswith(".md"):
        return None
    stem = path[len(DOCS) : -len(".md")]
    if stem == "index":
        return SITE_URL
    if stem.endswith("/index"):
        return f"{SITE_URL}{stem[: -len('index')]}"
    return f"{SITE_URL}{stem}/"


def changed_paths(before: str | None) -> list[str] | None:
    """Paths changed since `before`, or None when there is no usable base."""
    if not before or _ZERO_SHA.match(before):
        return None
    result = subprocess.run(
        ["git", "diff", "--name-only", before, "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return [line for line in result.stdout.splitlines() if line]


def select_urls(changed: list[str] | None, sitemap: list[str]) -> list[str]:
    """The sitemap URLs to submit for a set of changed paths."""
    if changed is None or any(p.match(path) for path in changed for p in SITE_WIDE):
        return list(sitemap)
    listed = set(sitemap)
    urls = {url for url in map(page_url, changed) if url in listed}
    return sorted(urls)


def parse_sitemap(xml: bytes) -> list[str]:
    root = ElementTree.fromstring(xml)
    return [loc.text.strip() for loc in root.iter(f"{_SITEMAP_NS}loc") if loc.text]


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 - fixed https URLs
        data: bytes = response.read()
        return data


def payload(key: str, urls: list[str]) -> dict[str, object]:
    return {
        "host": "tmatens.github.io",
        "key": key,
        "keyLocation": f"{SITE_URL}{key}.txt",
        "urlList": urls,
    }


def submit(body: dict[str, object]) -> int:
    """POST to IndexNow and return the HTTP status (200 and 202 are success)."""
    request = urllib.request.Request(
        ENDPOINT,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            status: int = response.status
            return status
    except urllib.error.HTTPError as err:
        return err.code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--before", help="the push's base commit; omit to submit every page"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="print the request, send nothing"
    )
    args = parser.parse_args(argv)

    key = find_key(REPO_ROOT / DOCS)
    sitemap = parse_sitemap(fetch(f"{SITE_URL}sitemap.xml"))
    urls = select_urls(changed_paths(args.before), sitemap)
    if not urls:
        print("indexnow: no indexable page changed; nothing to submit")
        return 0

    body = payload(key, urls)
    print(f"indexnow: {len(urls)} URL(s)")
    for url in urls:
        print(f"  {url}")
    if args.dry_run:
        return 0

    # Fail before the engines do: a key file that is not live yet makes them
    # reject the whole batch with 403 and nothing in the response says why.
    served = fetch(str(body["keyLocation"])).decode().strip()
    if served != key:
        print(
            f"indexnow: {body['keyLocation']} does not serve the key", file=sys.stderr
        )
        return 1

    status = submit(body)
    print(f"indexnow: HTTP {status}")
    return 0 if status in (200, 202) else 1


if __name__ == "__main__":
    sys.exit(main())
