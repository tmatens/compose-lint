"""scripts/forgejo_smoke_bump.py — the pure logic and the registry client, offline.

The dangerous failures are the quiet ones: a stale anchor reporting "up to
date", a floating or `-rootless` tag chosen as a release, or a per-arch
manifest digest pinned where a manifest list belongs (the digest Compose
resolves is the list's). These pin the loud-failure paths as hard as the
bump itself.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from collections.abc import Mapping

_SPEC = importlib.util.spec_from_file_location(
    "forgejo_smoke_bump",
    pathlib.Path(__file__).resolve().parent.parent
    / "scripts"
    / "forgejo_smoke_bump.py",
)
assert _SPEC is not None and _SPEC.loader is not None
bump = importlib.util.module_from_spec(_SPEC)
sys.modules["forgejo_smoke_bump"] = bump
_SPEC.loader.exec_module(bump)

D_OLD = "sha256:" + "1" * 64
D_NEW = "sha256:" + "2" * 64
D_RUN = "sha256:" + "3" * 64

COMPOSE = f"""services:
  forgejo:
    image: codeberg.org/forgejo/forgejo:16.0.3@{D_OLD}
  runner:
    image: data.forgejo.org/forgejo/runner:13.1.0@{D_RUN}
"""
DOCS = "intro\n\nVerified on Forgejo 16.0.3, runner 13.1.0 — checked weekly.\n"


# --- Reading the anchors --------------------------------------------------


class TestAnchors:
    def test_reads_both_pins(self) -> None:
        pins = bump.read_pins(COMPOSE)
        assert pins["forgejo"] == bump.Pin(
            "codeberg.org", "forgejo/forgejo", "16.0.3", D_OLD
        )
        assert pins["runner"].registry == "data.forgejo.org"

    def test_missing_image_fails_loudly(self) -> None:
        """One pin gone must not read as 'nothing to bump' for that image."""
        text = COMPOSE.replace(
            f"data.forgejo.org/forgejo/runner:13.1.0@{D_RUN}", "alpine"
        )
        with pytest.raises(bump.CannotAnswer, match="does not pin runner"):
            bump.read_pins(text)

    def test_unpinned_digest_is_a_stale_anchor(self) -> None:
        text = COMPOSE.replace(f"@{D_OLD}", "")
        with pytest.raises(bump.CannotAnswer):
            bump.read_pins(text)

    def test_unexpected_image_fails(self) -> None:
        text = (
            COMPOSE + f"  extra:\n    image: codeberg.org/forgejo/other:1.0.0@{D_OLD}\n"
        )
        with pytest.raises(bump.CannotAnswer, match="unexpected image"):
            bump.read_pins(text)

    def test_reads_the_claim(self) -> None:
        assert bump.read_claim(DOCS) == ("16.0.3", "13.1.0")

    @pytest.mark.parametrize("text", ["no claim here\n", DOCS + DOCS])
    def test_claim_must_occur_exactly_once(self, text: str) -> None:
        with pytest.raises(bump.CannotAnswer, match="exactly one"):
            bump.read_claim(text)


# --- Choosing a release ---------------------------------------------------


class TestNewestStable:
    def test_picks_the_highest_release_numerically(self) -> None:
        assert bump.newest_stable(["9.0.3", "16.0.4", "16.0.10", "16.0.9"]) == "16.0.10"

    def test_ignores_floating_variant_and_digest_tags(self) -> None:
        tags = [
            "16",
            "16.0",
            "16-rootless",
            "16.0.4-rootless",
            "16.0.5-rc1",
            "sha256:" + "a" * 64,
            "16.0.4",
        ]
        assert bump.newest_stable(tags) == "16.0.4"

    def test_no_release_is_none(self) -> None:
        assert bump.newest_stable(["latest", "16-rootless"]) is None


# --- Rewriting both files together ----------------------------------------


class TestRewrite:
    def test_moves_pin_and_claim_together(self) -> None:
        pins = bump.read_pins(COMPOSE)
        targets = dict(pins)
        targets["forgejo"] = bump.Pin(
            "codeberg.org", "forgejo/forgejo", "16.0.4", D_NEW
        )
        compose, docs = bump.rewrite(COMPOSE, DOCS, pins, targets)
        assert f"codeberg.org/forgejo/forgejo:16.0.4@{D_NEW}" in compose
        assert D_OLD not in compose
        assert f"data.forgejo.org/forgejo/runner:13.1.0@{D_RUN}" in compose
        assert "Verified on Forgejo 16.0.4, runner 13.1.0 — checked weekly." in docs
        assert bump.read_claim(docs) == ("16.0.4", "13.1.0")

    def test_branch_name_carries_both_versions(self) -> None:
        pins = bump.read_pins(COMPOSE)
        assert bump.branch_name(pins) == "forgejo-smoke/forgejo-16.0.3-runner-13.1.0"


# --- The registry client, against a scripted registry ---------------------


class FakeRegistry:
    """A scripted OCI registry: optional bearer challenge, paginated tags per repo."""

    def __init__(
        self,
        *,
        challenge: bool,
        pages: dict[str, list[list[str]]],
        index: bool = True,
    ) -> None:
        self.challenge = challenge
        self.pages = pages
        self.index = index
        self.calls: list[tuple[str, str, Mapping[str, str]]] = []

    def __call__(
        self, url: str, method: str, headers: Mapping[str, str]
    ) -> tuple[int, dict[str, str], bytes]:
        self.calls.append((url, method, headers))
        if url.startswith("https://reg.test/v2/token"):
            assert "scope=repository%3Aforgejo%2F" in url and url.endswith(
                "%3Apull&service=r"
            )
            return 200, {}, json.dumps({"token": "tok"}).encode()
        if self.challenge and headers.get("Authorization") != "Bearer tok":
            return (
                401,
                {
                    "Www-Authenticate": 'Bearer realm="https://reg.test/v2/token",service="r"'
                },
                b'{"errors":[{"code":"UNAUTHORIZED"}]}',
            )
        repo = url.split("/v2/", 1)[1].split("/tags/")[0].split("/manifests/")[0]
        if "/tags/list" in url:
            pages = self.pages[repo]
            page = int(url.rsplit("page=", 1)[1]) if "page=" in url else 0
            link: dict[str, str] = {}
            if page + 1 < len(pages):
                nxt = f"/v2/{repo}/tags/list?page={page + 1}"
                link = {"Link": f'<{nxt}>; rel="next"'}
            return 200, link, json.dumps({"tags": pages[page]}).encode()
        if "/manifests/" in url and method == "HEAD":
            ctype = (
                "application/vnd.oci.image.index.v1+json"
                if self.index
                else "application/vnd.oci.image.manifest.v1+json"
            )
            return 200, {"Content-Type": ctype, "Docker-Content-Digest": D_NEW}, b""
        return 404, {}, b""


def _regs(fake: FakeRegistry) -> dict[str, Any]:
    return {
        "codeberg.org": bump.Registry("reg.test", fetch_fn=fake),
        "data.forgejo.org": bump.Registry("reg.test", fetch_fn=fake),
    }


class TestRegistry:
    def test_answers_a_challenge_then_paginates(self) -> None:
        fake = FakeRegistry(
            challenge=True,
            pages={"forgejo/forgejo": [["16.0.3", "16-rootless"], ["16.0.4"]]},
        )
        reg = bump.Registry("reg.test", fetch_fn=fake)
        assert reg.tags("forgejo/forgejo") == ["16.0.3", "16-rootless", "16.0.4"]
        paths = [u.removeprefix("https://reg.test") for u, _, _ in fake.calls]
        # 401, token, page 0 again, page 1 (already authorised)
        assert paths == [
            "/v2/forgejo/forgejo/tags/list?n=1000",
            "/v2/token?scope=repository%3Aforgejo%2Fforgejo%3Apull&service=r",
            "/v2/forgejo/forgejo/tags/list?n=1000",
            "/v2/forgejo/forgejo/tags/list?page=1",
        ]

    def test_no_challenge_needs_no_token(self) -> None:
        fake = FakeRegistry(challenge=False, pages={"forgejo/runner": [["13.1.0"]]})
        reg = bump.Registry("reg.test", fetch_fn=fake)
        assert reg.tags("forgejo/runner") == ["13.1.0"]
        assert all("/token" not in u for u, _, _ in fake.calls)

    def test_index_digest_comes_from_the_header(self) -> None:
        fake = FakeRegistry(challenge=True, pages={})
        reg = bump.Registry("reg.test", fetch_fn=fake)
        assert reg.index_digest("forgejo/forgejo", "16.0.4") == D_NEW
        head = next(h for u, m, h in fake.calls if m == "HEAD")
        assert "application/vnd.oci.image.index.v1+json" in head["Accept"]

    def test_a_single_manifest_is_refused(self) -> None:
        """A per-arch digest would pin one platform — the manifest-list trap."""
        fake = FakeRegistry(challenge=False, pages={}, index=False)
        reg = bump.Registry("reg.test", fetch_fn=fake)
        with pytest.raises(bump.CannotAnswer, match="not a manifest list"):
            reg.index_digest("forgejo/forgejo", "16.0.4")

    def test_next_link_accepts_absolute_and_relative(self) -> None:
        rel = '</v2/x/tags/list?last=9&n=5>; rel="next"'
        absolute = "<https://reg.test/v2/x/tags/list?last=9&n=5>; rel=next"
        assert bump._next_link(rel) == "/v2/x/tags/list?last=9&n=5"
        assert bump._next_link(absolute) == "/v2/x/tags/list?last=9&n=5"
        assert bump._next_link("") is None


# --- Deciding the targets -------------------------------------------------


class TestResolveTargets:
    def test_unchanged_tags_keep_the_existing_digests(self) -> None:
        pins = bump.read_pins(COMPOSE)
        fake = FakeRegistry(
            challenge=False,
            pages={
                "forgejo/forgejo": [["16.0.3", "16"]],
                "forgejo/runner": [["13.1.0"]],
            },
        )
        targets = bump.resolve_targets(pins, _regs(fake))
        assert targets == pins
        assert not any(m == "HEAD" for _, m, _ in fake.calls)

    def test_newer_tag_is_resolved_to_its_index_digest(self) -> None:
        """Only the image with a newer release moves; the other keeps its pin."""
        pins = bump.read_pins(COMPOSE)
        fake = FakeRegistry(
            challenge=True,
            pages={
                "forgejo/forgejo": [["16.0.3", "16.0.4"]],
                "forgejo/runner": [["13.1.0"]],
            },
        )
        targets = bump.resolve_targets(pins, _regs(fake))
        assert targets["forgejo"] == bump.Pin(
            "codeberg.org", "forgejo/forgejo", "16.0.4", D_NEW
        )
        assert targets["runner"] == pins["runner"]

    def test_a_registry_with_no_release_tag_cannot_answer(self) -> None:
        pins = bump.read_pins(COMPOSE)
        fake = FakeRegistry(
            challenge=False,
            pages={"forgejo/forgejo": [["latest"]], "forgejo/runner": [["13.1.0"]]},
        )
        with pytest.raises(bump.CannotAnswer, match="no X.Y.Z tag"):
            bump.resolve_targets(pins, _regs(fake))


# --- The anchors this script relies on exist in the repository -------------


def test_the_live_anchors_parse() -> None:
    """Guard the guard: the real files must satisfy the same readers."""
    pins = bump.read_pins(bump.COMPOSE_FILE.read_text(encoding="utf-8"))
    claim = bump.read_claim(bump.DOCS_FILE.read_text(encoding="utf-8"))
    assert claim == (pins["forgejo"].tag, pins["runner"].tag)
