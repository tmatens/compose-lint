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
    document_changes,
    findings_of,
    fix_in_place,
    lint_project,
    truth_findings,
)
from tests.oracle_harness._divergences import DIVERGENCES, Divergence
from tests.oracle_harness._oracle import (
    OracleResult,
    oracle_available,
    oracle_version,
    run_oracle,
)
from tests.oracle_harness._project import GeneratedProject, generate
from tests.oracle_harness._shape import (
    DUMP_NAME,
    describe_shape_difference,
    dump_document,
    shape_of,
    write_dump,
)

__all__ = [
    "DIVERGENCES",
    "DUMP_NAME",
    "Divergence",
    "FindingCounts",
    "GeneratedProject",
    "LintedProject",
    "OracleResult",
    "describe_difference",
    "describe_shape_difference",
    "document_changes",
    "dump_document",
    "findings_of",
    "fix_in_place",
    "generate",
    "lint_project",
    "oracle_available",
    "oracle_version",
    "run_oracle",
    "shape_of",
    "truth_findings",
    "write_dump",
]
