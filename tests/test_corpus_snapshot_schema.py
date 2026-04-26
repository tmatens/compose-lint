"""Schema guard for tests/corpus_snapshot.json.gz.

The snapshot is a digest of third-party Compose files. To preserve the
licensing posture (see LICENSE-corpus.md), only content_hash + finding
tuples may land in the file — never source paths, repo names, message
text, or any other field that would carry third-party content.

This test runs on every CI invocation and fails loudly if a future
contributor widens the snapshot schema.
"""

from __future__ import annotations

import gzip
import json
import re
from pathlib import Path

import pytest

SNAPSHOT_PATH = Path(__file__).parent / "corpus_snapshot.json.gz"

ALLOWED_TOP_LEVEL_KEYS = {
    "schema_version",
    "corpus_manifest_sha256",
    "compose_lint_version",
    "files_processed",
    "findings",
    "parse_errors",
}

CONTENT_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
RULE_ID_RE = re.compile(r"^CL-\d{4}$")


@pytest.fixture(scope="module")
def snapshot() -> dict:
    if not SNAPSHOT_PATH.is_file():
        pytest.skip("no corpus snapshot committed")
    with gzip.open(SNAPSHOT_PATH, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


def test_top_level_keys(snapshot: dict) -> None:
    assert set(snapshot.keys()) == ALLOWED_TOP_LEVEL_KEYS


def test_schema_version(snapshot: dict) -> None:
    assert snapshot["schema_version"] == 1


def test_corpus_manifest_hash_format(snapshot: dict) -> None:
    assert CONTENT_HASH_RE.match(snapshot["corpus_manifest_sha256"])


def test_compose_lint_version_is_string(snapshot: dict) -> None:
    assert isinstance(snapshot["compose_lint_version"], str)
    assert snapshot["compose_lint_version"]


def test_findings_shape(snapshot: dict) -> None:
    findings = snapshot["findings"]
    assert isinstance(findings, dict)
    for content_hash, tuples in findings.items():
        assert CONTENT_HASH_RE.match(content_hash), content_hash
        assert isinstance(tuples, list)
        for t in tuples:
            assert isinstance(t, list) and len(t) == 3, t
            rule_id, service, line = t
            assert RULE_ID_RE.match(rule_id), rule_id
            assert isinstance(service, str)
            assert line is None or isinstance(line, int), line


def test_parse_errors_shape(snapshot: dict) -> None:
    errors = snapshot["parse_errors"]
    assert isinstance(errors, list)
    for h in errors:
        assert CONTENT_HASH_RE.match(h), h


def test_no_third_party_content_leaks(snapshot: dict) -> None:
    """Defence in depth: sanity-check that nothing path-shaped, URL-shaped,
    or repo-name-shaped slipped into the snapshot via a future schema change.
    """
    blob = json.dumps(snapshot)
    forbidden_substrings = (
        "http://",
        "https://",
        "/home/",
        "/var/",
        "/usr/",
        ".yml",
        ".yaml",
        "github.com",
        "docker.io",
        "OWASP",
    )
    for needle in forbidden_substrings:
        assert needle not in blob, f"snapshot leaked substring: {needle!r}"
