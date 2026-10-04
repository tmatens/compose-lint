"""An overlay or included file with no content contributes nothing.

Compose 5.5.0 accepts an empty or comment-only file as a `-f` overlay, a
COMPOSE_FILE entry, `compose.override.yml`, or an `include:` target, and
merges nothing from it. compose-lint exited 2 on each ("file is empty"), so a
project whose `compose.override.yaml` holds only commented-out examples could
not be linted at all. Any file of a merged set may be empty, the first
included, as long as another supplies the project. A lone empty file, a set
that is empty as a whole, and an empty `extends:` base, which Compose refuses,
still fail.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from compose_lint import cli

if TYPE_CHECKING:
    from pathlib import Path

BASE = "services:\n  web:\n    image: nginx:1.27\n    privileged: true\n"
ENV_NAME = "." + "env"


def _run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, dict[str, Any]]:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NO_COLOR", "1")
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        cli.main(["--format", "json", "compose.yaml"])
    code = exc.value.code if isinstance(exc.value.code, int) else 1
    return code, json.loads(capsys.readouterr().out)


@pytest.mark.parametrize("text", ["", "# only commented-out examples\n"])
class TestAcceptedEmpty:
    def test_an_override_contributes_nothing(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        text: str,
    ) -> None:
        (tmp_path / "compose.yaml").write_text(BASE)
        (tmp_path / "compose.override.yaml").write_text(text)
        code, doc = _run(tmp_path, monkeypatch, capsys)
        assert doc["errors"] == []
        assert "CL-0002" in {f["rule_id"] for f in doc["findings"]}
        assert code == 1

    def test_a_compose_file_entry_contributes_nothing(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        text: str,
    ) -> None:
        (tmp_path / "compose.yaml").write_text(BASE)
        (tmp_path / "extra.yaml").write_text(text)
        (tmp_path / ENV_NAME).write_text("COMPOSE_FILE=compose.yaml:extra.yaml\n")
        _, doc = _run(tmp_path, monkeypatch, capsys)
        assert doc["errors"] == []
        assert "CL-0002" in {f["rule_id"] for f in doc["findings"]}

    def test_an_include_target_contributes_nothing(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        text: str,
    ) -> None:
        (tmp_path / "compose.yaml").write_text("include:\n  - extra.yaml\n" + BASE)
        (tmp_path / "extra.yaml").write_text(text)
        _, doc = _run(tmp_path, monkeypatch, capsys)
        assert doc["errors"] == []
        assert "CL-0002" in {f["rule_id"] for f in doc["findings"]}


def test_an_empty_primary_with_an_override_is_linted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Compose 5.5.0 accepts it: the override supplies the project."""
    (tmp_path / "compose.yaml").write_text("# nothing\n")
    (tmp_path / "compose.override.yaml").write_text(BASE)
    _, doc = _run(tmp_path, monkeypatch, capsys)
    assert doc["errors"] == []
    assert "CL-0002" in {f["rule_id"] for f in doc["findings"]}


class TestRefusedEmpty:
    def test_an_empty_primary_file_still_fails(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        (tmp_path / "compose.yaml").write_text("# nothing\n")
        code, doc = _run(tmp_path, monkeypatch, capsys)
        assert [e["kind"] for e in doc["errors"]] == ["parse"]
        assert code == 2

    def test_an_empty_set_still_fails(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        (tmp_path / "compose.yaml").write_text("# nothing\n")
        (tmp_path / "compose.override.yaml").write_text("")
        code, doc = _run(tmp_path, monkeypatch, capsys)
        assert [e["kind"] for e in doc["errors"]] == ["parse"]
        assert code == 2

    def test_an_empty_extends_base_still_fails(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        (tmp_path / "compose.yaml").write_text(
            "services:\n  web:\n    image: nginx:1.27\n"
            "    extends: {file: extra.yaml, service: b}\n"
        )
        (tmp_path / "extra.yaml").write_text("# nothing\n")
        code, doc = _run(tmp_path, monkeypatch, capsys)
        assert [e["kind"] for e in doc["errors"]] == ["coverage_gap"]
        assert code == 2
