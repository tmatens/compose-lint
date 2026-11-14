"""A scalar its YAML type cannot hold is an invalid file, not an internal error.

PyYAML converts a scalar with a bare Python call. An explicit tag skips the
check that the value has the type's shape, so the call raises ``ValueError``,
``KeyError``, ``AttributeError`` or ``IndexError``: none of them a
``YAMLError``, so each reached the CLI as "internal error ... This is a bug"
with a traceback. Both loaders, an included file and the config emitter read
YAML this way.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import yaml

from compose_lint import cli
from compose_lint.config import ConfigError, load_config
from compose_lint.config_emit import _scalar
from compose_lint.parser import ComposeError, loads

if TYPE_CHECKING:
    from pathlib import Path

# Every value here made at least one loader raise something other than a
# YAMLError. The comment names what PyYAML's constructor raised.
UNCONVERTIBLE = [
    '!!int "abc"',  # ValueError
    '!!int ""',  # IndexError
    '!!int "-"',  # IndexError
    '!!int "0x"',  # ValueError
    '!!int "1:x"',  # ValueError, sexagesimal branch
    '!!float "abc"',  # ValueError
    '!!float ""',  # IndexError
    '!!float "."',  # ValueError
    '!!bool "abc"',  # KeyError
    '!!timestamp "abc"',  # AttributeError
    '!!timestamp ""',  # AttributeError
    '!!timestamp "2026-13-45"',  # ValueError, no such month
    "9" * 5000,  # ValueError, untagged: past the integer-string limit
]

MESSAGE = r"cannot be read as the type it is given \((int|float|bool|timestamp)\)"


def _compose(value: str) -> str:
    return f"x-probe: {value}\nservices:\n  app:\n    image: nginx:alpine\n"


@pytest.mark.parametrize("value", UNCONVERTIBLE)
def test_compose_loader_reports_invalid_yaml(value: str) -> None:
    with pytest.raises(ComposeError, match=f"Invalid YAML: .*{MESSAGE}") as excinfo:
        loads(_compose(value))
    assert "at line 1, column 10" in str(excinfo.value)


@pytest.mark.parametrize(
    "value",
    [*UNCONVERTIBLE, "2026-13-45", "0000-01-01"],  # untagged dates: config only
)
def test_config_loader_reports_invalid_yaml(tmp_path: Path, value: str) -> None:
    config = tmp_path / ".compose-lint.yml"
    config.write_text(f"x-probe: {value}\nrules: {{}}\n", encoding="utf-8")
    with pytest.raises(ConfigError, match=f"Invalid YAML in config file: .*{MESSAGE}"):
        load_config(config)


def test_message_does_not_repeat_the_value() -> None:
    # The value is a byte of a file the run read, and the message reaches JSON,
    # SARIF and the job log (see `describe_yaml_error`).
    with pytest.raises(ComposeError) as excinfo:
        loads(_compose('!!int "hunter2"'))
    assert "hunter2" not in str(excinfo.value)


@pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
def test_check_exits_2_without_a_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fmt: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "compose.yaml").write_text(_compose('!!int "abc"'), encoding="utf-8")
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["check", "--format", fmt, "compose.yaml"])
    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "Invalid YAML" in output
    assert "internal error" not in output
    assert "Traceback" not in output


def test_included_file_is_reported_the_same_way(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "compose.yaml").write_text(
        "include:\n  - other.yaml\nservices:\n  app:\n    image: nginx:alpine\n",
        encoding="utf-8",
    )
    (tmp_path / "other.yaml").write_text(
        'services:\n  db:\n    image: postgres:18\n    x-probe: !!bool "abc"\n',
        encoding="utf-8",
    )
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["check", "compose.yaml"])
    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "internal error" not in output
    assert "Traceback" not in output


def test_policy_file_is_reported_the_same_way(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "compose.yaml").write_text(_compose("ok"), encoding="utf-8")
    (tmp_path / ".compose-lint.yml").write_text(
        'rules:\n  CL-0001:\n    enabled: !!bool "abc"\n', encoding="utf-8"
    )
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["check", "compose.yaml"])
    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "Invalid YAML in config file" in output
    assert "Traceback" not in output


def test_convertible_tagged_values_still_load() -> None:
    data, _ = loads(
        'x-a: !!int "12"\nx-b: !!float "1.5"\nx-c: !!bool "yes"\n'
        "services:\n  app:\n    image: nginx:alpine\n"
    )
    assert (data["x-a"], data["x-b"], data["x-c"]) == (12, 1.5, True)


def test_the_stock_safe_loader_is_untouched() -> None:
    # The guard is installed on compose-lint's own loaders only.
    with pytest.raises(ValueError, match="invalid literal"):
        yaml.safe_load('!!int "abc"')


@pytest.mark.parametrize("name", ["2026-13-45", "0000-01-01", "9" * 5000])
def test_emitter_quotes_a_name_yaml_cannot_convert(name: str) -> None:
    # `init` writes service names into the policy file. These resolve to a
    # date or an int by shape and then fail the conversion, so unquoted they
    # would be a file `check` refuses; the emitter used to crash on them.
    rendered = _scalar(name)
    assert rendered == f'"{name}"'
