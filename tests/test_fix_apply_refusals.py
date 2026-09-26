"""`fix --apply` refusals that were too loose or too tight (#886, second half).

- A deletion whose span interpolates (`driver: ${LOG_DRIVER:-none}`,
  `- ${SECCOMP_OPT:-seccomp:unconfined}`) is refused, not deleted: the line is
  a finding only under the default, and another environment may ship
  something else there.
- A full-line comment after a `security_opt` item is a comment, not the item's
  continuation, so the item is still removed.
- A coordinated `security_opt` rewrite on a merged run edits this file's own
  items; it bailed on the merged count and left the file stuck half-fixed.
- A list shared through an anchor is refused with a note saying why.
- setuid/setgid/sticky are dropped by the atomic write, and documented so.
"""

from __future__ import annotations

import os
import stat
import sys
from typing import TYPE_CHECKING, Any

import pytest

from compose_lint import cli
from tests.test_fix_apply_safety import _assert_compose_accepts

if TYPE_CHECKING:
    from pathlib import Path


def _apply(
    tmp_path: Path,
    text: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
    *,
    override: str | None = None,
    dry_run: bool = False,
) -> tuple[int, str, str]:
    path = tmp_path / "compose.yml"
    path.write_text(text, encoding="utf-8")
    if override is not None:
        (tmp_path / "compose.override.yml").write_text(override, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NO_COLOR", "1")
    capsys.readouterr()
    args = ["fix", "compose.yml"] if dry_run else ["fix", "--apply", "compose.yml"]
    with pytest.raises(SystemExit) as exc:
        cli.main(args)
    captured = capsys.readouterr()
    code = exc.value.code if isinstance(exc.value.code, int) else 1
    if not dry_run and override is None:
        # A merged run is checked by its own test; this validates the file.
        _assert_compose_accepts(path)
    return code, path.read_text(encoding="utf-8"), captured.out + captured.err


class TestInterpolatedDeletions:
    def test_an_interpolated_logging_driver_is_not_deleted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        text = (
            "services:\n  web:\n    image: nginx:1.27\n"
            "    logging:\n      driver: ${LOG_DRIVER:-none}\n"
        )
        _, written, _ = _apply(tmp_path, text, monkeypatch, capsys)
        assert "driver: ${LOG_DRIVER:-none}" in written

    def test_a_literal_none_driver_is_still_deleted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        text = (
            "services:\n  web:\n    image: nginx:1.27\n"
            "    logging:\n      driver: none\n"
        )
        _, written, _ = _apply(tmp_path, text, monkeypatch, capsys)
        assert "logging" not in written

    def test_an_interpolated_security_opt_item_is_not_deleted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        text = (
            "services:\n  web:\n    image: nginx:1.27\n    security_opt:\n"
            "      - no-new-privileges:true\n"
            "      - ${SECCOMP_OPT:-seccomp:unconfined}\n"
        )
        _, written, _ = _apply(tmp_path, text, monkeypatch, capsys)
        assert "- ${SECCOMP_OPT:-seccomp:unconfined}\n" in written

    def test_an_interpolated_item_blocks_the_coordinated_rewrite(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        text = (
            "services:\n  web:\n    image: nginx:1.27\n    security_opt:\n"
            "      - ${SECCOMP_OPT:-seccomp:unconfined}\n"
        )
        _, written, _ = _apply(tmp_path, text, monkeypatch, capsys)
        assert "- ${SECCOMP_OPT:-seccomp:unconfined}\n" in written
        assert "no-new-privileges" not in written

    def test_a_literal_security_opt_disable_is_still_deleted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        text = (
            "services:\n  web:\n    image: nginx:1.27\n    security_opt:\n"
            "      - no-new-privileges:true\n      - seccomp:unconfined\n"
        )
        _, written, _ = _apply(tmp_path, text, monkeypatch, capsys)
        assert "seccomp:unconfined" not in written


class TestCommentAfterItem:
    def test_a_comment_line_is_not_a_continuation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        text = (
            "services:\n  web:\n    image: nginx:1.27\n    security_opt:\n"
            "      - seccomp:unconfined\n"
            "        # legacy: remove when X ships\n"
            "      - label:user:foo\n"
        )
        _, written, _ = _apply(tmp_path, text, monkeypatch, capsys)
        assert "seccomp:unconfined" not in written
        assert "label:user:foo" in written

    def test_a_block_scalar_body_is_still_a_continuation(self) -> None:
        from compose_lint.rules.CL0009_security_profile import _item_is_multiline

        lines = ["      - >-\n", "        # content, not a comment\n"]
        assert _item_is_multiline(lines, 1)
        plain = ["      - seccomp:unconfined\n", "        # a comment\n"]
        assert not _item_is_multiline(plain, 1)


class TestCoordinatedRewriteOnAMergedRun:
    BASE = (
        "services:\n  web:\n    image: nginx:1.27\n    security_opt:\n"
        "      - seccomp:unconfined\n      - apparmor:unconfined\n"
    )

    def test_it_converges_in_one_pass(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        override = "services:\n  web:\n    security_opt:\n      - label:user:x\n"
        code, written, out = _apply(
            tmp_path, self.BASE, monkeypatch, capsys, override=override
        )
        assert code == 0, out
        assert "unconfined" not in written
        assert "      - no-new-privileges:true\n" in written
        _, again, out = _apply(
            tmp_path, written, monkeypatch, capsys, override=override
        )
        assert again == written
        assert "CL-0009" not in out

    def test_an_overlay_deciding_no_new_privileges_is_left_alone(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        override = (
            "services:\n  web:\n    security_opt:\n      - no-new-privileges:false\n"
        )
        _, written, _ = _apply(
            tmp_path, self.BASE, monkeypatch, capsys, override=override
        )
        assert "no-new-privileges" not in written


class TestSharedListNote:
    def test_an_anchor_shared_tmpfs_refusal_says_why(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        text = (
            "services:\n  web:\n    image: nginx:1.27\n"
            "    tmpfs: &t\n      - /run:exec\n"
            "  api:\n    image: nginx:1.27\n    tmpfs: *t\n"
        )
        _, _, out = _apply(tmp_path, text, monkeypatch, capsys, dry_run=True)
        assert "CL-0022 on 'web': 'tmpfs' is shared through a YAML anchor" in out
        assert "CL-0022 on 'api': 'tmpfs' is shared through a YAML anchor" in out

    def test_an_unshared_list_has_no_note(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        text = (
            "services:\n  web:\n    image: nginx:1.27\n    tmpfs:\n      - /run:exec\n"
        )
        _, _, out = _apply(tmp_path, text, monkeypatch, capsys, dry_run=True)
        assert "shared through a YAML anchor" not in out


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
def test_setgid_and_sticky_are_dropped_and_rw_bits_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    path = tmp_path / "compose.yml"
    path.write_text("services:\n  web:\n    image: nginx:1.27\n", encoding="utf-8")
    os.chmod(path, 0o2640 | stat.S_ISVTX)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        cli.main(["fix", "--apply", "compose.yml"])
    capsys.readouterr()
    assert "read_only: true" in path.read_text(encoding="utf-8")
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
