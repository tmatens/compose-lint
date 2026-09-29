"""A fixer that fails is isolated, like a rule that fails.

A fixer is part of its rule, so one that raises, or names a position the file
does not have, is a bug in compose-lint. It used to escape ``collect_edits``:
``check --format sarif`` then exited 2 through the internal-error backstop with
no results for the whole batch, while text and JSON graded the same files and
exited 1, and ``fix`` aborted every file after the one that failed. Now the
failure costs that one finding's edit. ``check`` reports it and keeps the
verdict every format gives; ``fix`` refuses the file, as it refuses one whose
rule crashed, and moves on.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from compose_lint import cli
from compose_lint.fix import collect_edits
from compose_lint.models import TextEdit
from compose_lint.parser import load_compose
from compose_lint.rules import get_registered_rules

if TYPE_CHECKING:
    from pathlib import Path

    from compose_lint.models import Finding

# CL-0007 (read_only) and CL-0003 (no-new-privileges) both have fixers, so one
# can fail while the other's edit is still offered.
DOC = "services:\n  web:\n    image: nginx:1.27\n    cap_drop: [ALL]\n"
BROKEN = "CL-0007"


def _break_fixer(monkeypatch: pytest.MonkeyPatch, fixer: Any) -> None:
    for rule_cls in get_registered_rules():
        if rule_cls().metadata.id == BROKEN:
            monkeypatch.setattr(rule_cls, "fix", fixer)
            return
    raise AssertionError(f"{BROKEN} is not registered")


def _raises(self: object, *args: object, **kwargs: object) -> None:
    raise KeyError("simulated fixer bug")


def _misplaces(
    self: object, finding: Finding, *args: object, **kwargs: object
) -> list[TextEdit]:
    # Inside the service's block, so only the offset check can catch it.
    line = finding.line or 2
    return [TextEdit(line, 0, line, 0, "    read_only: true\n")]


@pytest.mark.parametrize("fixer", [_raises, _misplaces])
def test_the_collector_keeps_the_other_fixes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fixer: Any
) -> None:
    from compose_lint.engine import run_rules

    _break_fixer(monkeypatch, fixer)
    target = tmp_path / "compose.yml"
    target.write_text(DOC, encoding="utf-8")
    data, lines = load_compose(target)
    findings = run_rules(data, lines)

    result = collect_edits(findings, data, lines, DOC)

    assert len(result.crashes) == 1
    assert BROKEN in result.crashes[0]
    assert BROKEN in {f.rule_id for f in result.manual}
    assert BROKEN not in {f.rule_id for f in result.fixed}
    assert "CL-0003" in {f.rule_id for f in result.fixed}


def _run(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    code = exc.value.code
    assert isinstance(code, int)
    return code


def test_every_format_gives_the_same_exit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _break_fixer(monkeypatch, _raises)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "compose.yml").write_text(DOC, encoding="utf-8")

    codes = {
        fmt: _run(["check", "--format", fmt, "--fail-on", "medium", "compose.yml"])
        for fmt in ("text", "json", "sarif")
    }
    capsys.readouterr()

    assert codes == {"text": 1, "json": 1, "sarif": 1}

    # SARIF still reports every finding; only the broken fixer's suggested
    # change is missing, and the failure is on the warnings channel.
    _run(["check", "--format", "sarif", "--fail-on", "medium", "compose.yml"])
    captured = capsys.readouterr()
    run = json.loads(captured.out)["runs"][0]
    by_rule = {r["ruleId"]: r for r in run["results"]}
    assert BROKEN in by_rule
    assert "fixes" not in by_rule[BROKEN]
    assert by_rule["CL-0003"].get("fixes")
    notes = run["invocations"][0]["toolExecutionNotifications"]
    assert [(n["descriptor"]["id"], n["level"]) for n in notes] == [
        ("rule_crash", "warning")
    ]
    assert run["invocations"][0]["executionSuccessful"] is True
    assert f"the {BROKEN} fixer failed on service 'web'" in captured.err


def test_fix_refuses_the_file_and_finishes_the_batch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    broken = tmp_path / "broken" / "compose.yml"
    clean = tmp_path / "clean" / "compose.yml"
    broken.parent.mkdir()
    clean.parent.mkdir()
    broken.write_text(DOC, encoding="utf-8")
    # No CL-0007 finding here, so the broken fixer is never asked.
    clean.write_text(
        "services:\n  web:\n    image: nginx:1.27\n    read_only: true\n",
        encoding="utf-8",
    )
    _break_fixer(monkeypatch, _raises)

    code = _run(["fix", "--apply", str(broken), str(clean)])

    err = capsys.readouterr().err
    assert code == 2
    assert f"the {BROKEN} fixer failed on service 'web'" in err
    assert "no fixes written" in err
    assert broken.read_text(encoding="utf-8") == DOC
    assert "no-new-privileges" in clean.read_text(encoding="utf-8")
