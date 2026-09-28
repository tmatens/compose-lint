"""A file that is not UTF-8 is an error or a gap, never a crash that exits 1.

The main Compose file already reported ``Invalid encoding`` and exited 2. Three
other reads let ``UnicodeDecodeError`` through, since it is a ``ValueError``
and their handlers caught ``OSError``: an ``include:`` target, a cross-file
``extends:`` base, and the config file. Each crashed with a traceback and exit
1 (the findings code), and JSON and SARIF on stdout were empty.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from compose_lint import cli

if TYPE_CHECKING:
    from pathlib import Path

NOT_UTF8 = b"services:\n  x:\n    image: a\xff\n"


def _run(
    args: list[str],
    cwd: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, str, str]:
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("NO_COLOR", "1")
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        cli.main(args)
    captured = capsys.readouterr()
    code = exc.value.code if isinstance(exc.value.code, int) else 1
    return code, captured.out, captured.err


def _kinds(doc: dict[str, Any]) -> list[str]:
    return [entry["kind"] for entry in doc["errors"]]


def _include(tmp_path: Path) -> None:
    (tmp_path / "compose.yml").write_text(
        "include:\n  - other.yml\nservices:\n  web:\n    image: nginx:1.27\n"
    )
    (tmp_path / "other.yml").write_bytes(NOT_UTF8)


def _extends(tmp_path: Path) -> None:
    (tmp_path / "compose.yml").write_text(
        "services:\n  web:\n    extends:\n      file: base.yml\n      service: x\n"
    )
    (tmp_path / "base.yml").write_bytes(NOT_UTF8)


@pytest.mark.parametrize("make", [_include, _extends], ids=["include", "extends"])
@pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
def test_a_reference_is_a_coverage_gap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    make: Any,
    fmt: str,
) -> None:
    make(tmp_path)
    code, out, err = _run(
        ["--format", fmt, "compose.yml"], tmp_path, monkeypatch, capsys
    )
    assert code == 2
    assert "not valid UTF-8 (byte 27)" in err
    assert "Traceback" not in err
    if fmt == "json":
        assert _kinds(json.loads(out)) == ["coverage_gap"]
    elif fmt == "sarif":
        invocation = json.loads(out)["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is False


@pytest.mark.parametrize("make", [_include, _extends], ids=["include", "extends"])
def test_allow_partial_coverage_accepts_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    make: Any,
) -> None:
    make(tmp_path)
    code, out, _ = _run(
        ["--format", "json", "--allow-partial-coverage", "compose.yml"],
        tmp_path,
        monkeypatch,
        capsys,
    )
    assert json.loads(out)["errors"] == []
    assert code in (0, 1)


@pytest.mark.parametrize("fmt", ["text", "json"])
def test_the_config_file_is_a_configuration_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fmt: str,
) -> None:
    (tmp_path / "compose.yml").write_text("services:\n  web:\n    image: nginx:1.27\n")
    (tmp_path / ".compose-lint.yml").write_bytes(b"rules: {}\n# \xff\n")
    code, out, err = _run(
        ["--format", fmt, "compose.yml"], tmp_path, monkeypatch, capsys
    )
    assert code == 2
    assert "is not valid UTF-8 (byte 12)" in err
    assert "Traceback" not in err
    if fmt == "json":
        assert _kinds(json.loads(out)) == ["run"]


@pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
def test_an_unhandled_exception_exits_2_with_an_envelope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fmt: str,
) -> None:
    """The backstop: whatever the next crash is, it is not read as findings."""
    (tmp_path / "compose.yml").write_text("services:\n  web:\n    image: nginx:1.27\n")

    def boom(*_: object, **__: object) -> None:
        raise LookupError("\x1b[2Jsimulated")

    monkeypatch.setattr(cli, "run_rules", boom)
    code, out, err = _run(
        ["--format", fmt, "compose.yml"], tmp_path, monkeypatch, capsys
    )
    assert code == 2
    assert "internal error: LookupError" in err
    assert "Traceback" in err
    assert "\x1b" not in err
    if fmt == "json":
        assert _kinds(json.loads(out)) == ["run"]
    elif fmt == "sarif":
        invocation = json.loads(out)["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is False


def test_a_crash_before_arguments_are_parsed_still_exits_2(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """No format is known yet, so there is no envelope to write."""

    def boom() -> None:
        raise LookupError("simulated")

    monkeypatch.setattr(cli, "_build_parser", boom)
    code, out, err = _run(["compose.yml"], tmp_path, monkeypatch, capsys)
    assert code == 2
    assert out == ""
    assert "internal error: LookupError: simulated" in err
