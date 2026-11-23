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


class Flaky:
    """A fetch that plays back a script of outcomes, one per attempt."""

    def __init__(self, *outcomes: Exception | int) -> None:
        self.outcomes = list(outcomes)
        self.attempts = 0

    def __call__(
        self, url: str, method: str, headers: Mapping[str, str]
    ) -> tuple[int, dict[str, str], bytes]:
        self.attempts += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome, {}, b""


class TestRetrying:
    """One slow registry response must not end the run (#1209)."""

    URL = "https://reg.test/v2/forgejo/forgejo/tags/list?n=1000"

    def _fetch(self, flaky: Flaky, slept: list[float]) -> Any:
        return bump.retrying(flaky, sleep=slept.append, delays=(5.0, 15.0))

    def test_a_timeout_then_success_is_success(self) -> None:
        flaky = Flaky(bump.CannotAnswer("GET x: timed out"), 200)
        slept: list[float] = []
        assert self._fetch(flaky, slept)(self.URL, "GET", {})[0] == 200
        assert (flaky.attempts, slept) == (2, [5.0])

    @pytest.mark.parametrize("status", [429, 500, 502, 503])
    def test_a_transient_status_is_retried(self, status: int) -> None:
        flaky = Flaky(status, status, 200)
        slept: list[float] = []
        assert self._fetch(flaky, slept)(self.URL, "GET", {})[0] == 200
        assert (flaky.attempts, slept) == (3, [5.0, 15.0])

    @pytest.mark.parametrize("status", [200, 401, 404])
    def test_an_answer_is_returned_at_once(self, status: int) -> None:
        """A 401 is the token dance and a 404 a missing tag, not a hiccup."""
        flaky = Flaky(status)
        slept: list[float] = []
        assert self._fetch(flaky, slept)(self.URL, "GET", {})[0] == status
        assert (flaky.attempts, slept) == (1, [])

    def test_still_unreachable_after_three_tries_cannot_answer(self) -> None:
        flaky = Flaky(*(bump.CannotAnswer(f"GET x: timed out {n}") for n in range(3)))
        slept: list[float] = []
        with pytest.raises(bump.CannotAnswer, match="timed out 2"):
            self._fetch(flaky, slept)(self.URL, "GET", {})
        assert (flaky.attempts, slept) == (3, [5.0, 15.0])

    def test_a_lasting_5xx_reaches_the_caller_as_cannot_answer(self) -> None:
        flaky = Flaky(503, 503, 503)
        reg = bump.Registry("reg.test", fetch_fn=self._fetch(flaky, []))
        with pytest.raises(bump.CannotAnswer, match="503"):
            reg.tags("forgejo/forgejo")
        assert flaky.attempts == 3

    def test_the_default_fetch_retries(self) -> None:
        assert bump.Registry("reg.test")._fetch is bump.fetch
        assert bump.fetch is not bump._fetch_once


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


# --- The guide's checkout pin ----------------------------------------------

SHA_OLD = "a" * 40
SHA_NEW = "b" * 40
CHECKOUT_DOCS = (
    "```yaml\n"
    f"      - uses: https://code.forgejo.org/actions/checkout@{SHA_OLD} # v6.0.2\n"
    "```\n"
)


def _tags_api(pages: list[list[tuple[str, str]]], status: int = 200) -> Any:
    calls: list[str] = []

    def fetch(
        url: str, method: str, headers: Mapping[str, str]
    ) -> tuple[int, dict[str, str], bytes]:
        calls.append(url)
        assert url.startswith(
            "https://code.forgejo.org/api/v1/repos/actions/checkout/tags?"
        )
        page = int(url.split("page=", 1)[1].split("&", 1)[0])
        entries = pages[page - 1] if page <= len(pages) else []
        body = [{"name": n, "commit": {"sha": sha}} for n, sha in entries]
        return status, {}, json.dumps(body).encode()

    fetch.calls = calls  # type: ignore[attr-defined]
    return fetch


class TestCheckout:
    def test_reads_the_pin(self) -> None:
        assert bump.read_checkout(CHECKOUT_DOCS) == bump.Checkout("v6.0.2", SHA_OLD)

    @pytest.mark.parametrize(
        "text",
        [
            "no snippet\n",
            "      - uses: https://code.forgejo.org/actions/checkout@v4\n",
            CHECKOUT_DOCS
            + "      - uses: https://code.forgejo.org/actions/checkout@v4\n",
            CHECKOUT_DOCS + CHECKOUT_DOCS,
        ],
    )
    def test_anything_but_one_pinned_reference_fails(self, text: str) -> None:
        """A reference left on a tag must not sit beside a pin read as current."""
        with pytest.raises(bump.CannotAnswer, match="exactly one checkout"):
            bump.read_checkout(text)

    def test_rewrite_moves_sha_and_tag_together(self) -> None:
        old = bump.Checkout("v6.0.2", SHA_OLD)
        docs = bump.rewrite_checkout(
            CHECKOUT_DOCS, old, bump.Checkout("v7.0.1", SHA_NEW)
        )
        assert bump.read_checkout(docs) == bump.Checkout("v7.0.1", SHA_NEW)

    def test_only_plain_v_releases_are_candidates(self) -> None:
        tags = ["v7", "v10", "v9.9.9", "v10.0.0-beta.1", "10.1.0", "v10.0.0"]
        assert bump.newest_stable(tags, bump.CHECKOUT_TAG_RE) == "v10.0.0"
        assert bump.newest_stable(["v7.0.1"]) is None

    def test_tags_follow_pages_until_an_empty_one(self) -> None:
        fetch = _tags_api(
            [[("v7", SHA_NEW), ("v7.0.1", SHA_NEW)], [("v6.0.2", SHA_OLD)]]
        )
        tags = bump.checkout_tags(fetch)
        assert tags == {"v7": SHA_NEW, "v7.0.1": SHA_NEW, "v6.0.2": SHA_OLD}
        assert len(fetch.calls) == 3

    def test_a_failed_tags_request_cannot_answer(self) -> None:
        with pytest.raises(bump.CannotAnswer, match="404"):
            bump.checkout_tags(_tags_api([], status=404))

    def test_unreadable_tags_cannot_answer(self) -> None:
        def fetch(
            url: str, method: str, headers: Mapping[str, str]
        ) -> tuple[int, dict[str, str], bytes]:
            return 200, {}, b'[{"name": "v7.0.1"}]'

        with pytest.raises(bump.CannotAnswer, match="unreadable"):
            bump.checkout_tags(fetch)

    def test_newer_release_resolves_to_its_commit(self) -> None:
        current = bump.Checkout("v6.0.2", SHA_OLD)
        tags = {"v6.0.2": SHA_OLD, "v7.0.1": SHA_NEW, "v7": SHA_NEW}
        assert bump.resolve_checkout(current, tags) == bump.Checkout("v7.0.1", SHA_NEW)

    def test_same_release_keeps_the_pinned_commit(self) -> None:
        current = bump.Checkout("v7.0.1", SHA_OLD)
        assert bump.resolve_checkout(current, {"v7.0.1": SHA_NEW}) == current

    def test_no_release_or_a_bad_sha_cannot_answer(self) -> None:
        current = bump.Checkout("v6.0.2", SHA_OLD)
        with pytest.raises(bump.CannotAnswer, match="no vX.Y.Z tag"):
            bump.resolve_checkout(current, {"v7": SHA_NEW})
        with pytest.raises(bump.CannotAnswer, match="not a commit SHA"):
            bump.resolve_checkout(current, {"v7.0.1": "abc"})

    def test_branch_name_carries_the_checkout_release(self) -> None:
        pins = bump.read_pins(COMPOSE)
        name = bump.branch_name(pins, bump.Checkout("v7.0.1", SHA_NEW))
        assert name == "forgejo-smoke/forgejo-16.0.3-runner-13.1.0-checkout-v7.0.1"


# --- The smoke runner's Node against a default runner's -------------------

REGISTER_GO = """
var defaultLabels = []string{
\t"docker:docker://data.forgejo.org/oci/node:lts",
}
"""
LABEL = '--labels "docker:docker://node:26-trixie";'


def _node_registry(node_version: str) -> Any:
    index = {
        "manifests": [
            {
                "digest": "sha256:arm",
                "platform": {"os": "linux", "architecture": "arm64"},
            },
            {
                "digest": "sha256:amd",
                "platform": {"os": "linux", "architecture": "amd64"},
            },
        ]
    }
    bodies = {
        "/v2/oci/node/manifests/lts": index,
        "/v2/oci/node/manifests/sha256:amd": {"config": {"digest": "sha256:cfg"}},
        "/v2/oci/node/blobs/sha256:cfg": {
            "config": {"Env": ["PATH=/usr/bin", f"NODE_VERSION={node_version}"]}
        },
    }

    def fetch(
        url: str, method: str, headers: Mapping[str, str]
    ) -> tuple[int, dict[str, str], bytes]:
        path = url.split("https://data.forgejo.org", 1)[1]
        if path not in bodies:
            return 404, {}, b""
        return 200, {}, json.dumps(bodies[path]).encode()

    return lambda host: bump.Registry(host, fetch_fn=fetch)


def _register_fetch(status: int = 200, body: str = REGISTER_GO) -> Any:
    def fetch(
        url: str, method: str, headers: Mapping[str, str]
    ) -> tuple[int, dict[str, str], bytes]:
        assert url == (
            "https://code.forgejo.org/forgejo/runner/raw/tag/v13.1.0"
            "/internal/app/cmd/register.go"
        )
        return status, {}, body.encode()

    return fetch


class TestRunnerNode:
    def test_reads_the_smoke_label(self) -> None:
        assert bump.smoke_node_major(COMPOSE + LABEL) == 26

    @pytest.mark.parametrize("text", [COMPOSE, COMPOSE + LABEL + LABEL])
    def test_label_must_occur_exactly_once(self, text: str) -> None:
        with pytest.raises(bump.CannotAnswer, match="exactly one runner label"):
            bump.smoke_node_major(text)

    def test_reads_the_default_label_image(self) -> None:
        assert bump.default_label_image(REGISTER_GO) == (
            "data.forgejo.org",
            "oci/node",
            "lts",
        )

    @pytest.mark.parametrize(
        "text",
        [
            "var defaultLabels = []string{}\n",
            'var defaultLabels = []string{\n\t"docker:docker://node:lts",\n}\n',
        ],
    )
    def test_an_unreadable_default_label_cannot_answer(self, text: str) -> None:
        with pytest.raises(bump.CannotAnswer):
            bump.default_label_image(text)

    def test_node_major_comes_from_node_version(self) -> None:
        assert bump.node_major(["A=1", "NODE_VERSION=26.13.1"]) == 26
        with pytest.raises(bump.CannotAnswer, match="no NODE_VERSION"):
            bump.node_major(["A=1"])
        with pytest.raises(bump.CannotAnswer, match="not a version"):
            bump.node_major(["NODE_VERSION=lts"])

    def test_config_env_follows_index_to_the_amd64_config(self) -> None:
        reg = _node_registry("26.13.1")("data.forgejo.org")
        assert "NODE_VERSION=26.13.1" in reg.config_env("oci/node", "lts")

    def test_a_missing_manifest_cannot_answer(self) -> None:
        reg = _node_registry("26.13.1")("data.forgejo.org")
        with pytest.raises(bump.CannotAnswer, match="404"):
            reg.config_env("oci/node", "missing")

    @pytest.mark.parametrize(("version", "default"), [("26.13.1", 26), ("28.0.0", 28)])
    def test_reports_both_majors(self, version: str, default: int) -> None:
        result = bump.check_runner_node(
            COMPOSE + LABEL, _register_fetch(), _node_registry(version)
        )
        assert result == (26, default, "data.forgejo.org/oci/node:lts")

    def test_an_unreachable_runner_source_cannot_answer(self) -> None:
        with pytest.raises(bump.CannotAnswer, match="404"):
            bump.check_runner_node(
                COMPOSE + LABEL, _register_fetch(status=404), _node_registry("26.1.0")
            )


# --- The anchors this script relies on exist in the repository -------------


def test_the_live_anchors_parse() -> None:
    """Guard the guard: the real files must satisfy the same readers."""
    pins = bump.read_pins(bump.COMPOSE_FILE.read_text(encoding="utf-8"))
    claim = bump.read_claim(bump.DOCS_FILE.read_text(encoding="utf-8"))
    assert claim == (pins["forgejo"].tag, pins["runner"].tag)
    bump.read_checkout(bump.DOCS_FILE.read_text(encoding="utf-8"))
    bump.smoke_node_major(bump.COMPOSE_FILE.read_text(encoding="utf-8"))
