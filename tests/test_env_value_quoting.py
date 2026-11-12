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

from compose_lint import _env_quote, cli

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


# A mount rule reads a host path from a top-level definition the service
# attaches, and quotes that path in its finding.
_SHARED_CASES = {
    "secret": (
        "CL-0013",
        "services:\n  web:\n    image: nginx:1.27\n    secrets: [s]\n"
        "secrets:\n  s:\n    file: /${DB_PASSWORD}/../../../../etc/shadow\n",
    ),
    "config": (
        "CL-0013",
        "services:\n  web:\n    image: nginx:1.27\n    configs: [c]\n"
        "configs:\n  c:\n    file: /${DB_PASSWORD}/../../../../etc/shadow\n",
    ),
    "socket": (
        "CL-0001",
        "services:\n  web:\n    image: nginx:1.27\n    secrets: [s]\n"
        "secrets:\n  s:\n"
        "    file: /${DB_PASSWORD}/../../../../var/run/docker.sock\n",
    ),
    "named-volume": (
        "CL-0025",
        "services:\n  web:\n    image: nginx:1.27\n    volumes:\n"
        "      - data:/x\n"
        "volumes:\n  data:\n    driver: local\n    driver_opts:\n"
        "      type: none\n      o: bind\n"
        "      device: /${DB_PASSWORD}/../../../../etc\n",
    ),
}


class TestSharedDefinitions:
    @pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
    @pytest.mark.parametrize("case", sorted(_SHARED_CASES))
    def test_the_value_never_reaches_output(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        fmt: str,
        case: str,
    ) -> None:
        _write(tmp_path / "compose.yml", _SHARED_CASES[case][1])
        _write(tmp_path / ENV_NAME, f"DB_PASSWORD={SECRET}\n")
        _, out, err = _run(
            ["--format", fmt, "compose.yml"], tmp_path, monkeypatch, capsys
        )
        assert SECRET not in out
        assert SECRET not in err
        assert "${DB_PASSWORD}" in out

    @pytest.mark.parametrize("case", sorted(_SHARED_CASES))
    def test_the_finding_still_fires(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        case: str,
    ) -> None:
        """Quoting changes the report, not what is graded."""
        rule_id, compose = _SHARED_CASES[case]
        _write(tmp_path / "compose.yml", compose)
        _write(tmp_path / ENV_NAME, f"DB_PASSWORD={SECRET}\n")
        _, out, _ = _run(
            ["--format", "json", "compose.yml"], tmp_path, monkeypatch, capsys
        )
        (finding,) = _by_rule(out, rule_id)
        assert "${DB_PASSWORD}" in finding["message"] + (finding["fix"] or "")


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


# Messages other than findings: coverage gaps, notes, warnings and errors. Each
# names a reference after substitution, so each quoted the value.
_DIAGNOSTIC_CASES = {
    "include": (
        'include:\n  - "${DB_PASSWORD}/missing.yml"\n'
        "services:\n  web:\n    image: nginx:1.27\n"
    ),
    "include-only": 'include:\n  - "${DB_PASSWORD}/missing.yml"\n',
    "extends-file": (
        "services:\n  web:\n    image: nginx:1.27\n    extends:\n"
        '      file: "${DB_PASSWORD}/missing.yml"\n      service: base\n'
    ),
    "extends-service": (
        "services:\n  web:\n    image: nginx:1.27\n    extends:\n"
        '      service: "${DB_PASSWORD}"\n'
    ),
    "env-file": (
        "services:\n  web:\n    image: nginx:1.27\n"
        '    env_file: "${DB_PASSWORD}/missing.env"\n'
    ),
}


class TestDiagnostics:
    @pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
    @pytest.mark.parametrize("case", sorted(_DIAGNOSTIC_CASES))
    def test_the_value_never_reaches_output(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        fmt: str,
        case: str,
    ) -> None:
        _write(tmp_path / "compose.yml", _DIAGNOSTIC_CASES[case])
        _write(tmp_path / ENV_NAME, f"DB_PASSWORD={SECRET}\n")
        _, out, err = _run(
            ["--format", fmt, "compose.yml"], tmp_path, monkeypatch, capsys
        )
        assert SECRET not in out
        assert SECRET not in err
        assert "${DB_PASSWORD}" in out + err

    @pytest.mark.parametrize("fmt", ["json", "sarif"])
    def test_an_accepted_gap_is_quoted_on_the_warnings_channel(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        fmt: str,
    ) -> None:
        _write(tmp_path / "compose.yml", _DIAGNOSTIC_CASES["include"])
        _write(tmp_path / ENV_NAME, f"DB_PASSWORD={SECRET}\n")
        code, out, err = _run(
            ["--format", fmt, "--allow-partial-coverage", "compose.yml"],
            tmp_path,
            monkeypatch,
            capsys,
        )
        assert code == 0
        assert SECRET not in out + err
        assert "${DB_PASSWORD}/missing.yml" in out

    def test_the_document_is_quoted_by_fix_too(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _write(tmp_path / "compose.yml", _DIAGNOSTIC_CASES["include"])
        _write(tmp_path / ENV_NAME, f"DB_PASSWORD={SECRET}\n")
        _, out, err = _run(["fix", "compose.yml"], tmp_path, monkeypatch, capsys)
        assert SECRET not in out + err

    def test_no_env_quotes_the_reference_as_written(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _write(tmp_path / "compose.yml", _DIAGNOSTIC_CASES["include"])
        _write(tmp_path / ENV_NAME, f"DB_PASSWORD={SECRET}\n")
        _, out, err = _run(
            ["--format", "json", "--no-env", "compose.yml"],
            tmp_path,
            monkeypatch,
            capsys,
        )
        assert SECRET not in out + err
        assert "${DB_PASSWORD}/missing.yml" in out

    def test_a_later_run_does_not_quote_an_earlier_runs_values(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        first = tmp_path / "first"
        _write(first / "compose.yml", _DIAGNOSTIC_CASES["include"])
        _write(first / ENV_NAME, f"DB_PASSWORD={SECRET}\n")
        _run(["--format", "json", "compose.yml"], first, monkeypatch, capsys)
        second = _write(
            tmp_path / "second" / "compose.yml",
            "services:\n  web:\n    image: nginx:1.27\n",
        )
        _run(["--format", "json", "compose.yml"], second.parent, monkeypatch, capsys)
        assert _env_quote.quote(SECRET) == SECRET


class TestQuoteHelper:
    def test_nothing_remembered_is_the_identity(self) -> None:
        assert _env_quote.quote("a value of some length") == "a value of some length"

    def test_a_value_and_its_long_pieces_are_quoted(self) -> None:
        _env_quote.remember({"x": {"REPO": "registry.example/team-image:2026"}})
        assert _env_quote.quote("pull registry.example/team-image:2026") == (
            "pull ${REPO}"
        )
        assert _env_quote.quote("from registry.example") == "from ${REPO}"
        # Below the floor: configuration tokens stay as written.
        assert _env_quote.quote("tag 2026") == "tag 2026"

    def test_the_longest_value_wins(self) -> None:
        _env_quote.remember(
            {"a": {"SHORTER": "abcdefgh"}, "b": {"LONGER": "abcdefghijkl"}}
        )
        assert _env_quote.quote("abcdefghijkl") == "${LONGER}"

    def test_forget_drops_everything(self) -> None:
        _env_quote.remember({"x": {"TOKEN": "abcdefghijkl"}})
        _env_quote.forget()
        assert _env_quote.quote("abcdefghijkl") == "abcdefghijkl"
