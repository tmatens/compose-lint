"""End-to-end regression: `fix --apply` must not splice in a desynced line space.

The unit-level invariants live in ``test_lines.py``. These drive the real CLI,
because the defect's severity came from the *combination* — a misplaced splice
that still produced valid Compose, so every downstream safety net (reparse,
structural-drift, convergence, no-new-finding) passed and the run exited 0.

The attack: a low-severity ``CL-0014`` fix is requested on a document carrying
one invisible line-break codepoint, and the splice lands one line late on the
service's network-isolation directive.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from compose_lint import cli

if TYPE_CHECKING:
    from pathlib import Path

# The four break codepoints PyYAML counts and a naive `\n`-only scan does not.
DESYNC_BREAKS = {"CR": "\r", "NEL": "\x85", "LS": "\u2028", "PS": "\u2029"}

_IMAGE = "nginx@sha256:" + "ab" * 32


def _compose(sep: str) -> str:
    """A hardened service whose `logging: driver: none` is CL-0014-fixable.

    ``sep`` sits inside a *quoted scalar*, so the document is valid Compose for
    every value of ``sep`` including the plain-space control. The line right
    after the block CL-0014 deletes is the network-isolation directive.
    """
    return (
        "services:\n"
        "  web:\n"
        f"    image: {_IMAGE}\n"
        "    labels:\n"
        f'      note: "line one{sep}line two"\n'
        "    logging:\n"
        "      driver: none\n"
        "    networks: [internal]\n"
        "    read_only: true\n"
        '    user: "1000:1000"\n'
        '    security_opt: ["no-new-privileges:true"]\n'
        "    cap_drop: [ALL]\n"
        "networks:\n"
        "  internal:\n"
        "    internal: true\n"
    )


def _write(path: Path, text: str) -> Path:
    # newline="" so a lone CR survives to disk unmangled.
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    return path


def test_fix_apply_deletes_only_the_requested_block(tmp_path: Path) -> None:
    """`fix --only CL-0014 --apply` removes the logging block and nothing else."""
    target = _write(tmp_path / "control.yml", _compose(" "))

    with pytest.raises(SystemExit) as exc:
        cli.main(["fix", "--only", "CL-0014", "--apply", str(target)])
    assert exc.value.code == 0

    after = target.read_text(encoding="utf-8")
    # The requested edit completed...
    assert "logging:" not in after
    assert "driver: none" not in after
    # ...and the security config the user never selected survives.
    assert "networks: [internal]" in after
    assert "read_only: true" in after
    assert "cap_drop: [ALL]" in after


@pytest.mark.parametrize("name,sep", sorted(DESYNC_BREAKS.items()))
def test_fix_refuses_a_document_with_an_ambiguous_break(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    name: str,
    sep: str,
) -> None:
    """`fix` writes nothing when no line number could be reported correctly."""
    target = _write(tmp_path / f"{name}.yml", _compose(sep))
    before = target.read_bytes()

    with pytest.raises(SystemExit) as exc:
        cli.main(["fix", "--only", "CL-0014", "--apply", str(target)])

    assert exc.value.code == 2, name
    assert "Ambiguous line break on line 5" in capsys.readouterr().err, name
    assert target.read_bytes() == before, f"{name}: the file was modified"


@pytest.mark.parametrize("name,sep", sorted(DESYNC_BREAKS.items()))
def test_sarif_reports_an_ambiguous_break_as_a_file_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    name: str,
    sep: str,
) -> None:
    """The refusal is machine-readable, not stderr-only.

    A coverage gap that only exists on stderr is invisible to the CI consumer
    that decides whether the gate passes, so the SARIF document has to carry it.
    """
    target = _write(tmp_path / f"sarif_{name}.yml", _compose(sep))

    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "--format", "sarif", str(target)])
    assert exc.value.code == 2, name

    doc = json.loads(capsys.readouterr().out)
    assert doc["runs"][0]["results"] == [], name
    notifications = doc["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert any("Ambiguous line break" in n["message"]["text"] for n in notifications), (
        name
    )


def test_sarif_fix_region_covers_the_logging_block(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The exported fix region names the lines the fixer actually meant."""
    from compose_lint._lines import split_lines

    target = _write(tmp_path / "sarif_control.yml", _compose(" "))

    with pytest.raises(SystemExit):
        cli.main(["check", "--format", "sarif", str(target)])
    doc = json.loads(capsys.readouterr().out)

    source = split_lines(target.read_text(encoding="utf-8"))
    regions = [
        r["fixes"][0]["artifactChanges"][0]["replacements"][0]["deletedRegion"]
        for r in doc["runs"][0]["results"]
        if r["ruleId"] == "CL-0014" and r.get("fixes")
    ]
    assert regions, "no CL-0014 fix exported"
    region = regions[0]
    end = region.get("endLine", region["startLine"])
    if region.get("endColumn", 1) == 1:
        end -= 1
    covered = [line.strip() for line in source[region["startLine"] - 1 : end]]
    assert covered == ["logging:", "driver: none"], f"covered {covered}"


def test_batch_sarif_survives_a_file_whose_fixes_cannot_be_computed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One unfixable file must not destroy the whole batch's SARIF.

    SARIF is serialized once per run, so an exception escaping the per-file fix
    computation used to take every *other* file's findings with it. The failure
    is injected here rather than spelled as a document, because the line space
    is now consistent by construction — the point under test is the CLI's
    containment of the error, not a way to still trigger it.
    """
    from compose_lint import cli as cli_module
    from compose_lint.fix import LineOutOfRangeError

    good = _write(
        tmp_path / "good.yml",
        "services:\n  api:\n    image: nginx:latest\n    privileged: true\n",
    )
    poisoned = _write(tmp_path / "poisoned.yml", _compose(" "))

    real_collect = cli_module.collect_edits

    def _explode(findings, data, lines, text, **kwargs):  # type: ignore[no-untyped-def]
        if "line one" in text:  # the poisoned document
            raise LineOutOfRangeError(
                "edit names line 99, outside the file's 15 line(s)"
            )
        return real_collect(findings, data, lines, text, **kwargs)

    monkeypatch.setattr(cli_module, "collect_edits", _explode)

    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "--format", "sarif", str(good), str(poisoned)])

    captured = capsys.readouterr()
    doc = json.loads(captured.out)
    rule_ids = {r["ruleId"] for r in doc["runs"][0]["results"]}
    # The clean file's CRITICAL finding still ships.
    assert "CL-0002" in rule_ids
    # The failure is reported, not swallowed, and takes the usage-error exit.
    assert "could not compute fixes" in captured.err
    assert exc.value.code == 2
