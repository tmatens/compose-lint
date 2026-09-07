"""Differential harness: generated Compose projects, graded against Compose.

The suite that drives it is ``tests/test_oracle_harness.py``. A failing seed
replays with

    python -m tests.oracle_harness --seed 731 --keep /tmp/seed731

which writes the project to disk and prints both loaders' answers side by side.
"""

from __future__ import annotations

from tests.oracle_harness._compare import (
    FindingCounts,
    LintedProject,
    describe_difference,
    findings_of,
    lint_project,
    truth_findings,
)
from tests.oracle_harness._oracle import (
    OracleResult,
    oracle_available,
    oracle_version,
    run_oracle,
)
from tests.oracle_harness._project import GeneratedProject, generate

__all__ = [
    "FindingCounts",
    "GeneratedProject",
    "LintedProject",
    "OracleResult",
    "describe_difference",
    "findings_of",
    "generate",
    "lint_project",
    "oracle_available",
    "oracle_version",
    "run_oracle",
    "truth_findings",
]
