"""A service left without a body after the merge is refused, not crashed on.

A merge half may write `web:` with no body; Compose 5.5.0 merges that as "no
changes to web" when another file defines it. When no file does, the `None`
reached the rules and every one raised AttributeError (exit 2, `rule_crash`
per rule). Compose refuses such a project ("services.api must be a mapping"),
so it is now a parse error. Measured on Compose 5.5.0 for each case below.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from compose_lint import cli

if TYPE_CHECKING:
    from pathlib import Path

WEB = "services:\n  web:\n    image: nginx:1.27\n"


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


@pytest.mark.parametrize(
    ("base", "override"),
    [
        (WEB + "  api:\n", "services:\n  web:\n    privileged: true\n"),
        (WEB, "services:\n  api:\n"),
    ],
    ids=["bodiless-in-base", "bodiless-new-in-override"],
)
def test_a_service_nothing_defines_is_a_parse_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    base: str,
    override: str,
) -> None:
    (tmp_path / "compose.yaml").write_text(base)
    (tmp_path / "compose.override.yaml").write_text(override)
    code, doc = _run(tmp_path, monkeypatch, capsys)
    assert [e["kind"] for e in doc["errors"]] == ["parse"]
    assert "'api' has no body" in doc["errors"][0]["message"]
    assert code == 2


def test_a_bodiless_overlay_of_a_defined_service_still_lints(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Compose 5.5.0 accepts it as "no changes to web"."""
    (tmp_path / "compose.yaml").write_text(WEB)
    (tmp_path / "compose.override.yaml").write_text("services:\n  web:\n")
    _, doc = _run(tmp_path, monkeypatch, capsys)
    assert doc["errors"] == []
    assert doc["findings"]


def test_a_bodiless_service_in_an_included_file_is_a_parse_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "compose.yaml").write_text("include:\n  - part.yaml\n" + WEB)
    (tmp_path / "part.yaml").write_text("services:\n  api:\n")
    code, doc = _run(tmp_path, monkeypatch, capsys)
    assert "rule_crash" not in [e["kind"] for e in doc["errors"]]
    assert code == 2
