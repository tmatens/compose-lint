"""URL-hardening tests for the corpus fetcher's download path.

The corpus scripts pull raw file content from GitHub. A candidate URL whose
prefix doesn't match the github.com->raw rewrite would otherwise be fetched
verbatim, so the download path pins scheme+host (and refuses redirects) as
SSRF defense-in-depth. These tests cover the host guard without touching the
network. The script lives outside the importable package, so it is loaded by
path.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_COMMON = Path(__file__).resolve().parents[1] / "scripts" / "corpus" / "_common.py"


def _load_common():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("_corpus_common", _COMMON)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


common = _load_common()


@pytest.mark.parametrize(
    "url",
    [
        "http://raw.githubusercontent.com/o/r/sha/compose.yml",  # not https
        "https://raw.githubusercontent.com.evil.example/o/r/x.yml",  # lookalike host
        "https://evil.example/o/r/sha/compose.yml",  # wrong host
        "https://github.com/o/r/blob/main/compose.yml",  # un-rewritten, non-raw
        "file:///etc/passwd",  # non-http scheme
    ],
)
def test_validate_raw_url_rejects_non_raw(url: str) -> None:
    with pytest.raises(ValueError):
        common._validate_raw_url(url)


def test_validate_raw_url_accepts_raw_host() -> None:
    # The happy path a real `raw_url(...)` produces must not be rejected.
    common._validate_raw_url(
        "https://raw.githubusercontent.com/owner/repo/abc123/compose.yml"
    )


def test_raw_url_keeps_non_github_host_so_guard_rejects_it() -> None:
    # raw_url only rewrites the github.com host; a non-github candidate keeps
    # its own host, so the host guard is what stops it from being fetched.
    rewritten = common.raw_url("https://gitlab.com/o/r/blob/main/compose.yml")
    assert rewritten.startswith("https://gitlab.com/")
    with pytest.raises(ValueError):
        common._validate_raw_url(rewritten)
