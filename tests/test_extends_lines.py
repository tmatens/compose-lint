"""Inherited items point at the line that wrote them (#881, sub-finding 4).

A child that extends a service in the same file inherits the base's sequence
items, and an append merge moves every index: the child's `cap_add[0]` after
the merge is the base's first entry, not the child's. The line map kept the
child's own indices, so a finding on an inherited `SYS_ADMIN` was reported on
the child's harmless `CHOWN` line.

Correct lines are also lines a fixer can act on, and three fixers locate their
edit by the finding's line alone. So the fix engine refuses any edit that falls
outside the finding's own service block: a child's inherited finding is fixed
where it is written, by the base's own finding, never by editing the base on
the child's behalf (which stacked `127.0.0.1:` prefixes once per child).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from compose_lint import cli
from compose_lint.parser import loads
from tests._cli_env import cli_env

if TYPE_CHECKING:
    from collections.abc import Mapping

REPO_ROOT = Path(__file__).resolve().parent.parent

_DIGEST = "sha256:" + "0" * 64
ISSUE = f"""\
services:
  base:
    image: nginx:1.27@{_DIGEST}
    cap_add: [SYS_ADMIN]
  child:
    extends: base
    cap_add:
      - CHOWN
"""


def _line(lines: Mapping[str, int], key: str) -> int | None:
    value = lines.get(key)
    return None if value is None else int(value)


def test_an_inherited_sequence_item_points_at_the_base() -> None:
    data, lines = loads(ISSUE)
    assert data["services"]["child"]["cap_add"] == ["SYS_ADMIN", "CHOWN"]
    assert _line(lines, "services.child.cap_add[0]") == 4
    assert _line(lines, "services.child.cap_add[1]") == 8


def test_the_childs_own_keys_keep_the_childs_lines() -> None:
    _data, lines = loads(ISSUE)
    assert _line(lines, "services.child") == 5
    assert _line(lines, "services.child.extends") == 6
    assert _line(lines, "services.child.cap_add") == 7


def test_an_inherited_key_the_child_never_wrote_points_at_the_base() -> None:
    _data, lines = loads(
        "services:\n"
        "  base:\n    image: alpine:3.20\n    privileged: true\n"
        "  child:\n    extends: base\n"
    )
    assert _line(lines, "services.child.privileged") == 4


def test_lines_follow_a_two_level_chain() -> None:
    _data, lines = loads(
        "services:\n"
        "  a:\n    cap_add: [NET_ADMIN]\n"
        "  b:\n    extends: a\n    cap_add: [CHOWN]\n"
        "  c:\n    extends: b\n    cap_add: [KILL]\n"
    )
    assert [_line(lines, f"services.c.cap_add[{i}]") for i in range(3)] == [3, 6, 9]


def test_aliased_children_each_get_their_own_lines() -> None:
    _data, lines = loads(
        "x-child: &child\n  extends: base\n  cap_add: [CHOWN]\n"
        "services:\n"
        "  base:\n    cap_add: [SYS_ADMIN]\n"
        "  one: *child\n"
        "  two: *child\n"
    )
    for name in ("one", "two"):
        assert _line(lines, f"services.{name}.cap_add[0]") == 6, name
        # The child's own item sits inside the shared `x-child` mapping, whose
        # deeper lines the parser records under the first path only. Absent is
        # the documented answer there; a wrong line is not.
        assert _line(lines, f"services.{name}.cap_add[1]") in (3, None), name


def test_the_cli_reports_the_inherited_capability_on_its_own_line(
    tmp_path: Path,
) -> None:
    (tmp_path / "compose.yml").write_text(ISSUE, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "compose_lint", "check", "--format", "json"]
        + ["compose.yml"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env=cli_env(PYTHONPATH=str(REPO_ROOT / "src"), NO_COLOR="1"),
        timeout=120,
    )
    findings = json.loads(proc.stdout)["findings"]
    child = [
        f for f in findings if f["rule_id"] == "CL-0024" and f["service"] == "child"
    ]
    assert [f["line"] for f in child] == [4]


# --- The engine guard: a fix edits only its own service's block ------------


def _apply(tmp_path: Path, text: str, capsys: Any) -> tuple[int, str, str]:
    path = tmp_path / "compose.yml"
    path.write_text(text, encoding="utf-8")
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        cli.main(["fix", "--apply", str(path)])
    err = capsys.readouterr().err
    code = exc.value.code if isinstance(exc.value.code, int) else 1
    return code, path.read_text(encoding="utf-8"), err


def test_a_port_two_children_inherit_is_prefixed_once(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Correct lines let each child's CL-0005 fixer edit the base's line."""
    code, text, err = _apply(
        tmp_path,
        "services:\n"
        '  base:\n    image: nginx:1.27\n    ports:\n      - "8080:80"\n'
        "  one:\n    extends: base\n"
        "  two:\n    extends: base\n",
        capsys,
    )
    assert code == 0, err
    assert '"127.0.0.1:8080:80"' in text
    assert "127.0.0.1:127.0.0.1" not in text


def test_a_childs_own_security_opt_entry_is_not_deleted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """CL-0009 on the child's inherited entry deleted the child's own line.

    Its `legit_remaining` count reads the merged list, so the child looked like
    it kept a legitimate entry. The deletion introduced CL-0003 and the verify
    pass refused the whole file (exit 2). The base's entry is the only one in
    its own list, which CL-0009 refuses by design, so it stays for the user.
    """
    code, text, err = _apply(
        tmp_path,
        "services:\n"
        "  base:\n    image: nginx:1.27\n"
        "    security_opt:\n      - seccomp:unconfined\n"
        "  child:\n    extends: base\n"
        "    security_opt:\n      - no-new-privileges:true\n",
        capsys,
    )
    assert code == 0, err
    assert "      - no-new-privileges:true\n" in text
    assert "CL-0009 on 'child'" in err


def test_the_guard_refuses_an_edit_outside_the_findings_service() -> None:
    from compose_lint.engine import run_rules
    from compose_lint.fix import collect_edits

    text = (
        "services:\n"
        '  base:\n    image: nginx:1.27\n    ports:\n      - "8080:80"\n'
        "  child:\n    extends: base\n"
    )
    data, lines = loads(text)
    findings = [f for f in run_rules(data, lines) if f.rule_id == "CL-0005"]
    by_service = {f.service: f for f in findings}
    assert int(by_service["child"].line or 0) == 5
    result = collect_edits(findings, data, lines, text)
    assert by_service["base"] in result.fixed
    assert by_service["child"] in result.manual
    assert any("child" in note and "inherit" in note for note in result.notes)


def test_a_childs_own_finding_is_still_fixed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, text, err = _apply(
        tmp_path,
        "services:\n"
        "  base:\n    image: nginx:1.27\n"
        '  child:\n    extends: base\n    ports:\n      - "9090:90"\n',
        capsys,
    )
    assert code == 0, err
    assert '"127.0.0.1:9090:90"' in text
