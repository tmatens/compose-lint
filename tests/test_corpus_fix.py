"""ADR-014 Part 6 corpus regression gate for `compose-lint fix`.

Skipped unless ``COMPOSE_LINT_CORPUS`` points at a corpus cache root whose
``files/`` holds real Compose files (same gating style as
``test_corpus_snapshot``). For every lintable file it runs the fix engine and
asserts the three safety invariants that make shipping ``fix`` defensible
(ADR-014 Parts 5–6):

1. the patched text re-parses,
2. a second collection is a no-op (idempotent), and
3. the fix introduces no new finding.

This is the long-tail safety net the committed snapshot fixtures can't provide;
run it locally before promoting ``fix``.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from compose_lint.engine import run_rules
from compose_lint.fix import apply_edits, collect_edits
from compose_lint.parser import (
    ComposeError,
    ComposeNotApplicableError,
    load_compose,
)

CORPUS_ENV = os.environ.get("COMPOSE_LINT_CORPUS")

pytestmark = pytest.mark.skipif(not CORPUS_ENV, reason="COMPOSE_LINT_CORPUS not set")


def _corpus_files() -> list[Path]:
    root = Path(CORPUS_ENV).expanduser()  # type: ignore[arg-type]
    files_dir = root / "files"
    return sorted(files_dir.glob("*.yml")) if files_dir.is_dir() else []


def test_fix_corpus_regression(tmp_path: Path) -> None:
    files = _corpus_files()
    if not files:
        pytest.skip(f"no corpus files under {CORPUS_ENV}")

    patched_path = tmp_path / "patched.yml"
    reparse_failures: list[str] = []
    non_idempotent: list[str] = []
    introduced: list[str] = []
    fixed_files = 0

    for path in files:
        try:
            data, lines = load_compose(path)
        except (ComposeError, ComposeNotApplicableError, FileNotFoundError):
            continue
        text = path.read_text(encoding="utf-8")
        findings = run_rules(data, lines)
        result = collect_edits(findings, data, lines, text)
        if not result.edits:
            continue
        fixed_files += 1
        patched = apply_edits(text, result.edits)

        # (1) re-parses
        patched_path.write_text(patched, encoding="utf-8")
        try:
            re_data, re_lines = load_compose(patched_path)
        except (ComposeError, ComposeNotApplicableError) as exc:
            reparse_failures.append(f"{path.name}: {exc}")
            continue
        re_findings = run_rules(re_data, re_lines)

        # (2) idempotent
        if collect_edits(re_findings, re_data, re_lines, patched).edits:
            non_idempotent.append(path.name)

        # (3) no new finding introduced
        before = {(f.rule_id, f.service, f.message) for f in findings}
        after = {(f.rule_id, f.service, f.message) for f in re_findings}
        new = after - before
        if new:
            introduced.append(f"{path.name}: {sorted(new)[:2]}")

    problems = []
    if reparse_failures:
        problems.append(
            f"{len(reparse_failures)} fixed files fail to re-parse: "
            + "; ".join(reparse_failures[:5])
        )
    if non_idempotent:
        problems.append(
            f"{len(non_idempotent)} non-idempotent fixes: "
            + ", ".join(non_idempotent[:5])
        )
    if introduced:
        problems.append(
            f"{len(introduced)} fixes introduce a new finding: "
            + "; ".join(introduced[:5])
        )
    assert not problems, (
        f"fix corpus regressions across {fixed_files} fixed files:\n"
        + "\n".join(problems)
    )
