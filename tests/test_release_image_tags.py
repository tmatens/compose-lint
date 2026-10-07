"""scripts/release_image_tags.py — which Docker Hub tags a release moves.

The dangerous outcomes are silent ones: ``latest`` or an alias moving
backwards when an older version is published, and a truncated tag list
producing a confident answer. Both are pinned here, alongside the newest-
release case, which must keep producing exactly what every release so far
has pushed.
"""

from __future__ import annotations

import importlib.util
import io
import pathlib
import sys

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "release_image_tags",
    pathlib.Path(__file__).resolve().parent.parent
    / "scripts"
    / "release_image_tags.py",
)
assert _SPEC is not None and _SPEC.loader is not None
release_image_tags = importlib.util.module_from_spec(_SPEC)
sys.modules["release_image_tags"] = release_image_tags
_SPEC.loader.exec_module(release_image_tags)

image_tags = release_image_tags.image_tags
IMAGE = "composelint/compose-lint"

# The shape `git tag --list 'v*'` returns: lexical order, plus the
# lightweight moving major tag action-major-tag maintains from 1.0.0 on.
V0_TAGS = ["v0.10.0", "v0.3.4", "v0.33.0", "v0.33.1", "v0.34.0", "v0.9.0"]
V1_TAGS = ["v0.34.0", "v1", "v1.0.0", "v1.1.0", "v1.1.1", "v1.2.0", "v2.0.0"]


def _names(tags: list[str]) -> list[str]:
    return [t.removeprefix(f"{IMAGE}:") for t in tags]


class TestNewestRelease:
    def test_v0_matches_what_every_release_so_far_pushed(self) -> None:
        # 0.34.0 shipped as 0.34.0, 0.34 and latest; no major alias on v0.
        assert _names(image_tags("v0.34.0", V0_TAGS)) == ["0.34.0", "0.34", "latest"]

    def test_v1_and_later_also_move_the_major_alias(self) -> None:
        assert _names(image_tags("v2.0.0", V1_TAGS)) == ["2.0.0", "2.0", "2", "latest"]

    def test_tags_are_full_image_refs(self) -> None:
        assert image_tags("v0.34.0", V0_TAGS)[0] == f"{IMAGE}:0.34.0"


class TestOlderRelease:
    def test_republishing_an_old_version_moves_nothing_newer(self) -> None:
        assert _names(image_tags("v0.33.0", V0_TAGS)) == ["0.33.0"]

    def test_highest_patch_of_an_old_minor_keeps_its_minor_alias(self) -> None:
        assert _names(image_tags("v0.33.1", V0_TAGS)) == ["0.33.1", "0.33"]

    def test_backport_keeps_minor_and_major_but_not_latest(self) -> None:
        assert _names(image_tags("v1.2.0", V1_TAGS)) == ["1.2.0", "1.2", "1"]

    def test_backport_below_the_major_head_moves_only_its_minor(self) -> None:
        assert _names(image_tags("v1.1.1", V1_TAGS)) == ["1.1.1", "1.1"]

    def test_comparison_is_numeric_not_lexical(self) -> None:
        # Lexically "v0.9.0" > "v0.34.0"; numerically it is far older.
        assert _names(image_tags("v0.9.0", V0_TAGS)) == ["0.9.0", "0.9"]


class TestFailsLoudly:
    @pytest.mark.parametrize("tag", ["v1", "1.2.3", "v1.2.3-rc1", "main", ""])
    def test_rejects_a_non_release_tag(self, tag: str) -> None:
        with pytest.raises(ValueError, match="not a release tag"):
            image_tags(tag, V0_TAGS)

    def test_rejects_an_empty_tag_list(self) -> None:
        with pytest.raises(ValueError, match="empty or incomplete"):
            image_tags("v0.34.0", [])

    def test_rejects_a_list_missing_the_tag_under_release(self) -> None:
        with pytest.raises(ValueError, match="empty or incomplete"):
            image_tags("v0.35.0", V0_TAGS)

    def test_ignores_non_release_tags_in_the_list(self) -> None:
        tags = [*V0_TAGS, "v9", "v99.0.0-rc1", "not-a-tag"]
        assert _names(image_tags("v0.34.0", tags)) == ["0.34.0", "0.34", "latest"]


class TestCli:
    def _run(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        *argv: str,
        stdin: str,
    ) -> tuple[int, str, str]:
        monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
        code = release_image_tags.main(["release_image_tags.py", *argv])
        out, err = capsys.readouterr()
        return code, out, err

    def test_writes_github_output_lines(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, out, _ = self._run(
            monkeypatch, capsys, "v0.34.0", stdin="\n".join(V0_TAGS) + "\n"
        )
        assert code == 0
        assert out.splitlines() == [
            "version=0.34.0",
            f"tags={IMAGE}:0.34.0,{IMAGE}:0.34,{IMAGE}:latest",
        ]

    def test_error_goes_to_stderr_and_nothing_to_stdout(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, out, err = self._run(monkeypatch, capsys, "v0.34.0", stdin="")
        assert code == 1
        assert out == ""
        assert err.startswith("::error::")

    def test_usage_error(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, out, _ = self._run(monkeypatch, capsys, stdin="")
        assert code == 2
        assert out == ""
