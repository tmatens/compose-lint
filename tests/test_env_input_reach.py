"""Values Compose deploys from env files are graded, or their absence is said (#885).

Three shapes graded a deployed credential or `privileged: true` as clean with no
machine-readable trace:

- an `env_file:` written in an included document was read from beside the
  *including* file, where it does not exist;
- a sibling `.env` that is not UTF-8 or is over the read cap was treated as
  absent, silently, though Compose reads raw bytes with no cap;
- an `env_file:` or `COMPOSE_FILE` entry refused for leaving the project was
  reported on stderr only.

The last two are warnings, not failures: kind `unread_input`, on JSON
`warnings[]` and as a SARIF `level: warning` notification that leaves
`executionSuccessful` true.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from compose_lint import cli
from compose_lint._env_file import MAX_ENV_BYTES

if TYPE_CHECKING:
    from pathlib import Path

PRIVILEGED_BY_ENV = (
    "services:\n  web:\n    image: nginx:1.27\n    privileged: ${PRIV}\n"
)


def _write(path: Path, text: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, encoding="utf-8")
    return path


def _run(
    args: list[str],
    cwd: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, Any, str]:
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("NO_COLOR", "1")
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        cli.main(args)
    captured = capsys.readouterr()
    code = exc.value.code if isinstance(exc.value.code, int) else 1
    return code, json.loads(captured.out), captured.err


def _rules(doc: dict[str, Any]) -> set[str]:
    return {finding["rule_id"] for finding in doc["findings"]}


def _unread(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return [w for w in doc["warnings"] if w["kind"] == "unread_input"]


class TestIncludedEnvFile:
    def _project(self, tmp_path: Path, *, vars_file: bool = True) -> Path:
        _write(
            tmp_path / "sub" / "compose.yml",
            "services:\n  api:\n    image: nginx:1.27\n    env_file: ./app.vars\n",
        )
        if vars_file:
            _write(
                tmp_path / "sub" / "app.vars",
                "AWS_SECRET_ACCESS_KEY=placeholder-not-a-real-key\n",
            )
        return _write(
            tmp_path / "compose.yml",
            "include:\n  - sub/compose.yml\n"
            "services:\n  front:\n    image: nginx:1.27\n",
        )

    def test_it_is_read_from_beside_the_included_document(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        self._project(tmp_path)
        code, doc, _ = _run(
            ["--format", "json", "compose.yml"], tmp_path, monkeypatch, capsys
        )
        assert "CL-0020" in _rules(doc)
        assert code == 1

    def test_a_like_named_file_beside_the_root_is_not_read(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        self._project(tmp_path, vars_file=False)
        _write(tmp_path / "app.vars", "AWS_SECRET_ACCESS_KEY=placeholder\n")
        _, doc, err = _run(
            ["--format", "json", "compose.yml"], tmp_path, monkeypatch, capsys
        )
        assert "CL-0020" not in _rules(doc)
        assert "sub/app.vars" in err

    def test_a_nested_include_is_rebased_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        _write(
            tmp_path / "a" / "b" / "compose.yml",
            "services:\n  api:\n    image: nginx:1.27\n    env_file: ./app.vars\n",
        )
        _write(tmp_path / "a" / "b" / "app.vars", "AWS_SECRET_ACCESS_KEY=x-y-z\n")
        _write(tmp_path / "a" / "compose.yml", "include:\n  - b/compose.yml\n")
        _write(tmp_path / "compose.yml", "include:\n  - a/compose.yml\n")
        _, doc, _ = _run(
            ["--format", "json", "compose.yml"], tmp_path, monkeypatch, capsys
        )
        assert "CL-0020" in _rules(doc)


class TestExtendedEnvFile:
    def test_a_two_hop_base_is_rebased_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        # Was rebased by the middle hop and again by the root, which read
        # `a/a/b/app.vars` and graded nothing.
        _write(
            tmp_path / "a" / "b" / "base.yml",
            "services:\n  base:\n    image: nginx:1.27\n    env_file: ./app.vars\n",
        )
        _write(tmp_path / "a" / "b" / "app.vars", "AWS_SECRET_ACCESS_KEY=x-y-z\n")
        _write(
            tmp_path / "a" / "mid.yml",
            "services:\n  mid:\n    extends: {file: b/base.yml, service: base}\n",
        )
        _write(
            tmp_path / "compose.yml",
            "services:\n  web:\n    extends: {file: a/mid.yml, service: mid}\n",
        )
        _, doc, _ = _run(
            ["--format", "json", "compose.yml"], tmp_path, monkeypatch, capsys
        )
        assert "CL-0020" in _rules(doc)


class TestUnreadableDotEnv:
    @pytest.mark.parametrize(
        "content",
        [
            b"# caf\xe9\nPRIV=true\n",
            b"PRIV=true\n" + b"# padding\n" * (MAX_ENV_BYTES // 10 + 1),
        ],
        ids=["not-utf8", "over-cap"],
    )
    def test_it_is_reported_not_treated_as_absent(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: Any,
        content: bytes,
    ) -> None:
        _write(tmp_path / "compose.yml", PRIVILEGED_BY_ENV)
        _write(tmp_path / ".env", content)
        code, doc, err = _run(
            ["--format", "json", "compose.yml"], tmp_path, monkeypatch, capsys
        )
        (warning,) = _unread(doc)
        assert warning["file"].endswith(".env")
        assert "was not read because" in warning["message"]
        assert "was not read because" in err
        assert doc["errors"] == []
        assert code == 0

    def test_a_readable_env_is_graded_and_not_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        _write(tmp_path / "compose.yml", PRIVILEGED_BY_ENV)
        _write(tmp_path / ".env", "PRIV=true\n")
        code, doc, _ = _run(
            ["--format", "json", "compose.yml"], tmp_path, monkeypatch, capsys
        )
        assert _unread(doc) == []
        assert "CL-0002" in _rules(doc)
        assert code == 1

    def test_no_env_is_not_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        _write(tmp_path / "compose.yml", PRIVILEGED_BY_ENV)
        _, doc, _ = _run(
            ["--format", "json", "compose.yml"], tmp_path, monkeypatch, capsys
        )
        assert _unread(doc) == []


class TestRefusedReferencesAreMachineReadable:
    def _project(self, tmp_path: Path, env_file: str) -> Path:
        _write(tmp_path / "outside" / "db.env", "DB_PASSWORD=placeholder\n")
        _write(tmp_path / "project" / "db.env", "DB_PASSWORD=placeholder\n")
        return _write(
            tmp_path / "project" / "compose.yml",
            f"services:\n  api:\n    image: nginx:1.27\n    env_file: {env_file}\n",
        )

    def test_an_out_of_project_env_file_is_a_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        self._project(tmp_path, "../outside/db.env")
        code, doc, _ = _run(
            ["--format", "json", "project/compose.yml"], tmp_path, monkeypatch, capsys
        )
        (warning,) = _unread(doc)
        assert "outside the project directory" in warning["message"]
        assert warning["file"] == "project/compose.yml"
        assert code == 0

    def test_it_is_a_sarif_warning_on_a_successful_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        self._project(tmp_path, "../outside/db.env")
        _, doc, _ = _run(
            ["--format", "sarif", "project/compose.yml"],
            tmp_path,
            monkeypatch,
            capsys,
        )
        invocation = doc["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is True
        notes = invocation["toolExecutionNotifications"]
        assert [(n["level"], n["descriptor"]["id"]) for n in notes] == [
            ("warning", "unread_input")
        ]

    def test_an_in_project_env_file_is_not_a_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        self._project(tmp_path, "./db.env")
        _, doc, _ = _run(
            ["--format", "json", "project/compose.yml"], tmp_path, monkeypatch, capsys
        )
        assert _unread(doc) == []
        assert "CL-0020" in _rules(doc)

    def test_an_out_of_project_compose_file_entry_is_a_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        _write(tmp_path / "elsewhere.yml", "services:\n  x:\n    image: nginx\n")
        _write(
            tmp_path / "project" / "compose.yml", "services:\n  web:\n    image: a\n"
        )
        _write(tmp_path / "project" / ".env", "COMPOSE_FILE=../elsewhere.yml\n")
        _, doc, _ = _run(
            ["--format", "json", "project/compose.yml"], tmp_path, monkeypatch, capsys
        )
        (warning,) = _unread(doc)
        assert "COMPOSE_FILE" in warning["message"]
        assert warning["file"].endswith(".env")

    def test_an_in_project_compose_file_list_is_not_a_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        _write(
            tmp_path / "project" / "compose.yml", "services:\n  web:\n    image: a\n"
        )
        _write(tmp_path / "project" / "extra.yml", "services:\n  web:\n    user: x\n")
        _write(tmp_path / "project" / ".env", "COMPOSE_FILE=compose.yml:extra.yml\n")
        _, doc, _ = _run(
            ["--format", "json", "project/compose.yml"], tmp_path, monkeypatch, capsys
        )
        assert _unread(doc) == []
