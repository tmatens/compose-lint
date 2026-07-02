"""Tests for image-reference normalization used in profile matching (ADR-017)."""

from __future__ import annotations

import pytest

from compose_lint.profiles.refs import normalize_repository, parse_image_ref


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("postgres", "docker.io/library/postgres"),
        ("nginx", "docker.io/library/nginx"),
        ("linuxserver/radarr", "docker.io/linuxserver/radarr"),
        ("docker.io/library/postgres", "docker.io/library/postgres"),
        ("docker.io/postgres", "docker.io/library/postgres"),
        ("lscr.io/linuxserver/radarr", "lscr.io/linuxserver/radarr"),
        ("ghcr.io/tmatens/foo", "ghcr.io/tmatens/foo"),
        ("localhost:5000/foo", "localhost:5000/foo"),
        ("registry.example.com:5000/team/app", "registry.example.com:5000/team/app"),
        ("", ""),
    ],
)
def test_normalize_repository(name: str, expected: str) -> None:
    assert normalize_repository(name) == expected


def test_registry_host_is_lowercased() -> None:
    assert normalize_repository("GHCR.io/Tmatens/Foo") == "ghcr.io/Tmatens/Foo"


def test_parse_strips_tag_and_digest_to_match_key() -> None:
    ref = parse_image_ref("postgres:16")
    assert ref.repository == "docker.io/library/postgres"
    assert ref.tag == "16"
    assert ref.digest is None


def test_parse_captures_digest() -> None:
    digest = "sha256:" + "a" * 64
    ref = parse_image_ref(f"postgres:16@{digest}")
    assert ref.repository == "docker.io/library/postgres"
    assert ref.tag == "16"
    assert ref.digest == digest


def test_parse_digest_only() -> None:
    digest = "sha256:" + "b" * 64
    ref = parse_image_ref(f"lscr.io/linuxserver/radarr@{digest}")
    assert ref.repository == "lscr.io/linuxserver/radarr"
    assert ref.tag is None
    assert ref.digest == digest
