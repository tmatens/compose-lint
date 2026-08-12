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


@pytest.mark.parametrize("name,sep", sorted({"control": " ", **DESYNC_BREAKS}.items()))
def test_fix_apply_deletes_only_the_requested_block(
    tmp_path: Path, name: str, sep: str
) -> None:
    """`fix --only CL-0014 --apply` removes the logging block and nothing else."""
    target = _write(tmp_path / f"{name}.yml", _compose(sep))

    with pytest.raises(SystemExit) as exc:
        cli.main(["fix", "--only", "CL-0014", "--apply", str(target)])
    assert exc.value.code == 0, name

    after = target.read_text(encoding="utf-8")
    # The requested edit completed...
    assert "logging:" not in after, name
    assert "driver: none" not in after, name
    # ...and the security config the user never selected survives.
    assert "networks: [internal]" in after, name
    assert "read_only: true" in after, name
    assert "cap_drop: [ALL]" in after, name


@pytest.mark.parametrize("name,sep", sorted(DESYNC_BREAKS.items()))
def test_sarif_fix_region_covers_the_logging_block(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    name: str,
    sep: str,
) -> None:
    """The exported fix region names the lines the fixer actually meant.

    ``check --format sarif`` exports ``artifactChanges`` without going through
    the apply-time safety nets, so the region is pinned directly.
    """
    from compose_lint._lines import split_lines

    target = _write(tmp_path / f"sarif_{name}.yml", _compose(sep))

    with pytest.raises(SystemExit):
        cli.main(["check", "--format", "sarif", str(target)])
    doc = json.loads(capsys.readouterr().out)

    source = split_lines(target.read_text(encoding="utf-8"))
    regions = [
        r["fixes"][0]["artifactChanges"][0]["replacements"][0]["deletedRegion"]
        for r in doc["runs"][0]["results"]
        if r["ruleId"] == "CL-0014" and r.get("fixes")
    ]
    assert regions, f"{name}: no CL-0014 fix exported"
    region = regions[0]
    end = region.get("endLine", region["startLine"])
    if region.get("endColumn", 1) == 1:
        end -= 1
    covered = [line.strip() for line in source[region["startLine"] - 1 : end]]
    assert covered == ["logging:", "driver: none"], f"{name}: covered {covered}"


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
