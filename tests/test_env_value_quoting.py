"""A finding quotes the `${NAME}` a `.env` filled in (GHSA-jf3h-8jvx-vcrg).

The sibling `.env` resolves `${VAR}` outside `environment:` so rules grade what
deploys. CL-0004 and CL-0019 then quoted the resolved image in their message and
fix, so `image: "${DB_PASSWORD}"` beside a CI-written `.env` put the password
into the job log, JSON and the SARIF uploaded to Code Scanning. Rules still
grade the value; the report quotes the reference.

Every value here is a synthetic marker.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from compose_lint import cli

if TYPE_CHECKING:
    from pathlib import Path

SECRET = "cl-env-quoting-marker-9f2"
ENV_NAME = "." + "env"


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


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


def _findings(out: str) -> list[dict[str, Any]]:
    return list(json.loads(out)["findings"])


def _by_rule(out: str, rule_id: str) -> list[dict[str, Any]]:
    return [f for f in _findings(out) if f["rule_id"] == rule_id]


class TestImageReferences:
    @pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
    @pytest.mark.parametrize(
        "image",
        ["${DB_PASSWORD}", "nginx:${DB_PASSWORD}", "app${DB_PASSWORD}:latest"],
        ids=["whole", "tag", "glued"],
    )
    def test_the_value_never_reaches_output(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        fmt: str,
        image: str,
    ) -> None:
        _write(tmp_path / "compose.yml", f'services:\n  web:\n    image: "{image}"\n')
        _write(tmp_path / ENV_NAME, f"DB_PASSWORD={SECRET}\n")
        _, out, err = _run(
            ["--format", fmt, "compose.yml"], tmp_path, monkeypatch, capsys
        )
        assert SECRET not in out
        assert SECRET not in err
        assert "${DB_PASSWORD}" in out

    def test_the_message_and_fix_quote_the_reference(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _write(
            tmp_path / "compose.yml",
            'services:\n  web:\n    image: "nginx:${DB_PASSWORD}"\n',
        )
        _write(tmp_path / ENV_NAME, f"DB_PASSWORD={SECRET}\n")
        _, out, _ = _run(
            ["--format", "json", "compose.yml"], tmp_path, monkeypatch, capsys
        )
        (finding,) = _by_rule(out, "CL-0019")
        assert "'nginx:${DB_PASSWORD}'" in finding["message"]
        assert "image: nginx:${DB_PASSWORD}@sha256:<digest>" in finding["fix"]

    def test_the_value_is_still_what_is_graded(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Classification is unchanged: the tag the `.env` supplies is mutable,
        so CL-0004 fires, and the reference is what it names."""
        _write(tmp_path / "compose.yml", "services:\n  web:\n    image: ${IMAGE_REF}\n")
        _write(tmp_path / ENV_NAME, f"IMAGE_REF=registry.example/{SECRET}:latest\n")
        _, out, _ = _run(
            ["--format", "json", "compose.yml"], tmp_path, monkeypatch, capsys
        )
        (finding,) = _by_rule(out, "CL-0004")
        assert "${IMAGE_REF}" in finding["message"]
        assert SECRET not in json.dumps(finding)


class TestWhereTheValueCameFrom:
    def test_an_included_documents_own_env(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _write(tmp_path / "compose.yml", "include:\n  - sub/compose.yml\n")
        _write(
            tmp_path / "sub" / "compose.yml",
            'services:\n  api:\n    image: "${TOKEN}"\n',
        )
        _write(tmp_path / "sub" / ENV_NAME, f"TOKEN={SECRET}\n")
        _, out, err = _run(
            ["--format", "json", "compose.yml"], tmp_path, monkeypatch, capsys
        )
        assert _by_rule(out, "CL-0004")
        assert SECRET not in out + err

    def test_a_merged_overlay(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _write(tmp_path / "compose.yml", "services:\n  web:\n    image: nginx:1.27\n")
        _write(
            tmp_path / "compose.override.yml",
            'services:\n  web:\n    image: "nginx:${TOKEN}"\n',
        )
        _write(tmp_path / ENV_NAME, f"TOKEN={SECRET}\n")
        _, out, err = _run(
            ["--format", "json", "compose.yml"], tmp_path, monkeypatch, capsys
        )
        assert _by_rule(out, "CL-0019")
        assert SECRET not in out + err

    def test_no_env_quotes_the_file_as_written(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _write(
            tmp_path / "compose.yml", 'services:\n  web:\n    image: "nginx:${TOKEN}"\n'
        )
        _write(tmp_path / ENV_NAME, f"TOKEN={SECRET}\n")
        _, out, _ = _run(
            ["--format", "json", "--no-env", "compose.yml"],
            tmp_path,
            monkeypatch,
            capsys,
        )
        assert SECRET not in out


class TestScope:
    def test_another_services_literal_is_not_rewritten(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The same text written literally in a service that uses no reference
        is that service's own, and is quoted as written."""
        literal = "registry.example/team-shared-image"
        _write(
            tmp_path / "compose.yml",
            "services:\n"
            '  web:\n    image: "${REPO}:latest"\n'
            f'  worker:\n    image: "{literal}"\n',
        )
        _write(tmp_path / ENV_NAME, f"REPO={literal}\n")
        _, out, _ = _run(
            ["--format", "json", "compose.yml"], tmp_path, monkeypatch, capsys
        )
        messages = {f["service"]: f["message"] for f in _by_rule(out, "CL-0004")}
        assert "${REPO}:latest" in messages["web"]
        assert f"'{literal}'" in messages["worker"]

    def test_short_values_leave_the_guidance_alone(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """`true` is a configuration token the rules' own fix text writes."""
        _write(
            tmp_path / "compose.yml",
            "services:\n  web:\n    image: nginx:1.27\n    privileged: ${PRIV}\n",
        )
        _write(tmp_path / ENV_NAME, "PRIV=true\n")
        _, out, _ = _run(
            ["--format", "json", "compose.yml"], tmp_path, monkeypatch, capsys
        )
        (privileged,) = _by_rule(out, "CL-0002")
        (nnp,) = _by_rule(out, "CL-0003")
        assert "${PRIV}" not in privileged["message"] + (privileged["fix"] or "")
        assert "no-new-privileges:true" in (nnp["fix"] or "")

    def test_environment_values_are_still_never_resolved(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _write(
            tmp_path / "compose.yml",
            "services:\n  web:\n    image: nginx:1.27\n"
            "    environment:\n      DB_PASSWORD: ${DB_PASSWORD}\n",
        )
        _write(tmp_path / ENV_NAME, f"DB_PASSWORD={SECRET}\n")
        _, out, err = _run(
            ["--format", "json", "compose.yml"], tmp_path, monkeypatch, capsys
        )
        assert SECRET not in out + err


class TestFix:
    def test_a_fix_beside_a_quoted_reference_still_verifies(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """`fix` compares the findings before and after by message. Quoting must
        be the same on both sides, or the reference reads as a new finding."""
        compose = _write(
            tmp_path / "compose.yml",
            'services:\n  web:\n    image: "nginx:${TOKEN}"\n',
        )
        _write(tmp_path / ENV_NAME, f"TOKEN={SECRET}\n")
        code, out, err = _run(
            ["fix", "--apply", "compose.yml"], tmp_path, monkeypatch, capsys
        )
        assert "introduces a new finding" not in err
        assert SECRET not in out + err
        assert code == 0
        assert "no-new-privileges" in compose.read_text(encoding="utf-8")
