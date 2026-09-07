"""``fix`` defers a finding whose key a ``!reset`` deletes, and fixes the rest.

A ``!reset`` removes the key from the configuration Compose runs, so an absence
rule fires on it — and its fixer writes the key straight back into a document
where the reset deletes it again. Two ways that showed, both fail-closed and
both taking every *other* fix in the file down with them
([#811](https://github.com/tmatens/compose-lint/issues/811)):

* the base does not hold the key — the patch does not converge, because a
  second pass would still be asked to add it;
* the base still holds the key — the insertion duplicates it, and Compose
  rejects a duplicate mapping key.

The mechanism needs no second document: a ``!reset`` written in the only file
there is deletes the key from that file's own parsed data, and the ``!reset``
line is still there for the insertion to collide with. The overlay shapes are
the same thing one document further out.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from compose_lint import cli
from compose_lint.rules import BaseRule, get_registered_rules

if TYPE_CHECKING:
    from pathlib import Path


def _run_fix(target: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["fix", "--apply", str(target)])
    assert exc.value.code == 0


def test_a_reset_in_the_only_file_defers_that_finding_alone(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "compose.yml"
    target.write_text(
        "services:\n  web:\n    image: nginx:1.27\n    security_opt: !reset null\n",
        encoding="utf-8",
    )

    _run_fix(target)

    written = target.read_text(encoding="utf-8")
    err = capsys.readouterr().err
    assert "does not parse as Compose" not in err
    assert "CL-0003 on 'web'" in err
    assert "deletes 'security_opt'" in err
    # The unrelated fix still lands, and the reset line is left exactly as the
    # user wrote it — the refusal is the finding's, not the file's.
    assert "read_only: true" in written
    assert written.count("security_opt") == 1


def test_a_reset_in_an_overlay_defers_a_key_the_base_lacks(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The non-convergence shape: writing the key here changes nothing."""
    target = tmp_path / "compose.yml"
    target.write_text(
        'services:\n  db:\n    image: nginx:1.27\n    volumes: ["./data:/data"]\n',
        encoding="utf-8",
    )
    (tmp_path / "compose.override.yml").write_text(
        "services:\n  db:\n    security_opt: !reset null\n", encoding="utf-8"
    )

    _run_fix(target)

    err = capsys.readouterr().err.replace("\\", "/")
    assert "does not converge" not in err
    assert "CL-0003 on 'db'" in err
    assert "compose.override.yml deletes 'security_opt'" in err
    assert "read_only: true" in target.read_text(encoding="utf-8")


def test_a_reset_in_an_overlay_defers_a_key_the_base_still_holds(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The duplicate-key shape: the insertion would collide with the base."""
    target = tmp_path / "compose.yml"
    target.write_text(
        "services:\n"
        "  web:\n"
        "    image: myapp:1.0\n"
        '    security_opt: ["seccomp:unconfined"]\n',
        encoding="utf-8",
    )
    (tmp_path / "compose.override.yml").write_text(
        "services:\n  web:\n    security_opt: !reset null\n", encoding="utf-8"
    )

    _run_fix(target)

    written = target.read_text(encoding="utf-8")
    err = capsys.readouterr().err
    assert "duplicate key" not in err
    assert "CL-0003 on 'web'" in err
    assert written.count("security_opt") == 1
    assert "read_only: true" in written


def test_a_reset_of_a_key_no_fixer_writes_changes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Only a key some fixer would write is deferred; the rest is unaffected."""
    target = tmp_path / "compose.yml"
    target.write_text(
        "services:\n  web:\n    image: nginx:1.27\n    labels: !reset null\n",
        encoding="utf-8",
    )

    _run_fix(target)

    err = capsys.readouterr().err
    assert "!reset" not in err
    assert "read_only: true" in target.read_text(encoding="utf-8")


def test_every_rule_with_a_fixer_declares_what_it_writes() -> None:
    """The deferral is only as complete as the declarations behind it.

    A rule that grows a fixer and leaves ``fix_writes_keys`` empty silently
    opts out of the check, and the failure it reopens is a whole-file refusal
    on someone else's project.
    """
    undeclared = sorted(
        rule().metadata.id
        for rule in get_registered_rules()
        if rule.fix is not BaseRule.fix and not rule().fix_writes_keys()
    )
    assert not undeclared
