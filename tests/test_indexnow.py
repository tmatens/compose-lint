"""scripts/indexnow.py — which docs-site URLs a deploy submits to IndexNow.

The script's value rests on submitting the right set: the pages a push really
changed, never a page the site marks `noindex`, and everything when the change
is site-wide (a nav label, a build hook) or the base commit is unknown. A wrong
set either wastes the engines' trust in the hint or, worse, silently leaves a
retitled page uncrawled. The network is patched out throughout; what is tested
is the decision, plus the guard that refuses to submit when the key file the
engines will fetch does not serve the key.
"""

from __future__ import annotations

import email.message
import importlib.util
import json
import pathlib
import subprocess
import sys
import urllib.error
import urllib.request

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "indexnow",
    pathlib.Path(__file__).resolve().parent.parent / "scripts" / "indexnow.py",
)
assert _SPEC is not None and _SPEC.loader is not None
indexnow = importlib.util.module_from_spec(_SPEC)
sys.modules["indexnow"] = indexnow
_SPEC.loader.exec_module(indexnow)

SITE = indexnow.SITE_URL
SITEMAP = [
    SITE,
    f"{SITE}cli/",
    f"{SITE}examples/",
    f"{SITE}examples/portainer-removed/",
    f"{SITE}rules/CL-0005/",
]
SITEMAP_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    + "".join(
        f"<url><loc>{u}</loc><lastmod>2026-10-16</lastmod></url>" for u in SITEMAP
    )
    + "</urlset>"
).encode()
KEY = "0123456789abcdef0123456789abcdef"


@pytest.mark.parametrize(
    ("path", "url"),
    [
        ("docs/index.md", SITE),
        ("docs/cli.md", f"{SITE}cli/"),
        ("docs/examples/index.md", f"{SITE}examples/"),
        ("docs/rules/CL-0005.md", f"{SITE}rules/CL-0005/"),
        ("docs/assets/top-findings.svg", None),
        ("README.md", None),
        ("src/compose_lint/cli.py", None),
    ],
)
def test_page_url_follows_mkdocs_directory_urls(path: str, url: str | None) -> None:
    assert indexnow.page_url(path) == url


def test_submits_only_changed_pages_the_sitemap_lists() -> None:
    changed = ["docs/rules/CL-0005.md", "docs/cli.md", "src/compose_lint/engine.py"]
    assert indexnow.select_urls(changed, SITEMAP) == [
        f"{SITE}cli/",
        f"{SITE}rules/CL-0005/",
    ]


def test_noindexed_page_is_never_submitted() -> None:
    # ADRs build but are noindexed, so the sitemap omits them.
    assert indexnow.select_urls(["docs/adr/013-missing-services-key.md"], SITEMAP) == []


@pytest.mark.parametrize(
    "path",
    [
        "mkdocs.yml",
        "scripts/mkdocs_seo_hook.py",
        "scripts/mkdocs_git_dates_hook.py",
        "requirements-docs.lock",
    ],
)
def test_site_wide_change_submits_every_page(path: str) -> None:
    assert indexnow.select_urls([path], SITEMAP) == SITEMAP


def test_unknown_base_submits_every_page() -> None:
    assert indexnow.select_urls(None, SITEMAP) == SITEMAP


@pytest.mark.parametrize("before", [None, "", "0" * 40])
def test_no_usable_base_commit(before: str | None) -> None:
    # No `before` on a manual dispatch; all zeros on a branch's first push.
    assert indexnow.changed_paths(before) is None


def test_unreachable_base_commit_counts_as_unknown() -> None:
    assert indexnow.changed_paths("f" * 40) is None


def test_changed_paths_reads_git_diff() -> None:
    root = indexnow.REPO_ROOT
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert indexnow.changed_paths(head) == []


def test_parse_sitemap_reads_every_loc() -> None:
    assert indexnow.parse_sitemap(SITEMAP_XML) == SITEMAP


def test_find_key_requires_name_and_content_to_match(tmp_path: pathlib.Path) -> None:
    (tmp_path / f"{KEY}.txt").write_text(KEY)
    (tmp_path / "robots.txt").write_text("User-agent: *")
    (tmp_path / f"{'f' * 32}.txt").write_text("not the key")
    assert indexnow.find_key(tmp_path) == KEY


def test_find_key_refuses_ambiguity(tmp_path: pathlib.Path) -> None:
    with pytest.raises(SystemExit):
        indexnow.find_key(tmp_path)


def test_repository_carries_exactly_one_key_file() -> None:
    key = indexnow.find_key(indexnow.REPO_ROOT / "docs")
    assert indexnow.payload(key, [SITE])["keyLocation"] == f"{SITE}{key}.txt"


def test_payload_shape() -> None:
    body = indexnow.payload(KEY, [f"{SITE}cli/"])
    assert body == {
        "host": "tmatens.github.io",
        "key": KEY,
        "keyLocation": f"{SITE}{KEY}.txt",
        "urlList": [f"{SITE}cli/"],
    }


class _Response:
    def __init__(self, status: int = 200, body: bytes = b"") -> None:
        self.status = status
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


@pytest.mark.parametrize("status", [200, 202])
def test_submit_returns_success_status(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    sent: dict[str, object] = {}

    def fake_urlopen(request: urllib.request.Request, timeout: float) -> _Response:
        assert isinstance(request.data, bytes)
        sent["url"] = request.full_url
        sent["body"] = json.loads(request.data)
        return _Response(status)

    monkeypatch.setattr(indexnow.urllib.request, "urlopen", fake_urlopen)
    assert indexnow.submit(indexnow.payload(KEY, [SITE])) == status
    assert sent["url"] == indexnow.ENDPOINT
    assert sent["body"] == indexnow.payload(KEY, [SITE])


def test_submit_returns_error_status(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: urllib.request.Request, timeout: float) -> _Response:
        raise urllib.error.HTTPError(
            request.full_url, 403, "Forbidden", email.message.Message(), None
        )

    monkeypatch.setattr(indexnow.urllib.request, "urlopen", fake_urlopen)
    assert indexnow.submit(indexnow.payload(KEY, [SITE])) == 403


def _patch_site(
    monkeypatch: pytest.MonkeyPatch, key_served: str, status: int = 200
) -> list[str]:
    calls: list[str] = []
    monkeypatch.setattr(indexnow, "find_key", lambda _docs: KEY)
    monkeypatch.setattr(indexnow, "changed_paths", lambda _before: ["docs/cli.md"])

    def fake_fetch(url: str) -> bytes:
        calls.append(url)
        return SITEMAP_XML if url.endswith("sitemap.xml") else key_served.encode()

    monkeypatch.setattr(indexnow, "fetch", fake_fetch)

    def fake_submit(body: dict[str, object]) -> int:
        calls.append("POST")
        return status

    monkeypatch.setattr(indexnow, "submit", fake_submit)
    return calls


def test_main_submits_after_confirming_the_live_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _patch_site(monkeypatch, KEY)
    assert indexnow.main(["--before", "abc"]) == 0
    assert calls == [f"{SITE}sitemap.xml", f"{SITE}{KEY}.txt", "POST"]


def test_main_refuses_when_key_file_is_not_live(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _patch_site(monkeypatch, "<html>404</html>")
    assert indexnow.main(["--before", "abc"]) == 1
    assert "POST" not in calls


def test_main_fails_on_rejected_submission(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_site(monkeypatch, KEY, status=422)
    assert indexnow.main(["--before", "abc"]) == 1


def test_main_dry_run_sends_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_site(monkeypatch, KEY)
    assert indexnow.main(["--before", "abc", "--dry-run"]) == 0
    assert calls == [f"{SITE}sitemap.xml"]


def test_main_with_nothing_to_submit(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_site(monkeypatch, KEY)
    monkeypatch.setattr(
        indexnow, "changed_paths", lambda _before: ["src/compose_lint/engine.py"]
    )
    assert indexnow.main(["--before", "abc"]) == 0
    assert calls == [f"{SITE}sitemap.xml"]
