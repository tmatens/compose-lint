"""Tests for the profile ci-smoke gate (scripts/validate_profiles.py, ADR-017).

Runs the actual script as a subprocess — the same entry point CI invokes —
starting from a known-good fixture tree and mutating it to trigger each failure
mode.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from collections.abc import Callable

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "validate_profiles.py"
GOOD = Path(__file__).parent / "fixtures" / "profile_validation" / "good"


def _run(catalog_dir: Path, repo_root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--catalog-dir",
            str(catalog_dir),
            "--repo-root",
            str(repo_root),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _copy_good(tmp_path: Path) -> Path:
    tree = tmp_path / "tree"
    shutil.copytree(GOOD, tree)
    return tree


def _profile(tree: Path) -> Path:
    return tree / "catalog" / "docker.io" / "library" / "postgres.yml"


def _mutate(tree: Path, fn: Callable[[dict], None]) -> None:
    path = _profile(tree)
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    fn(doc)
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def test_good_fixture_passes(tmp_path: Path) -> None:
    tree = _copy_good(tmp_path)
    result = _run(tree / "catalog", tree)
    assert result.returncode == 0, result.stdout + result.stderr


def test_empty_catalog_passes(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog"
    catalog.mkdir()
    result = _run(catalog, tmp_path)
    assert result.returncode == 0, result.stdout


def test_default_catalog_absent_passes() -> None:
    # No bundled catalog (ADR-017 §7): a default run with no catalog present is a
    # clean no-op, not an error.
    result = subprocess.run(
        [sys.executable, str(SCRIPT)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_missing_ci_smoke_fails(tmp_path: Path) -> None:
    tree = _copy_good(tmp_path)
    _mutate(
        tree,
        lambda d: d["dimensions"]["capabilities"]["derivation"].update(
            validated_via=["bpf-observation"]
        ),
    )
    result = _run(tree / "catalog", tree)
    assert result.returncode == 1
    assert "validated_via" in result.stdout


def test_low_confidence_validated_fails(tmp_path: Path) -> None:
    tree = _copy_good(tmp_path)
    _mutate(
        tree,
        lambda d: d["dimensions"]["capabilities"]["derivation"].update(
            confidence="low"
        ),
    )
    result = _run(tree / "catalog", tree)
    assert result.returncode == 1
    assert "confidence" in result.stdout


def test_mutable_tag_validated_fails(tmp_path: Path) -> None:
    # A validated profile must declare immutable version tags: a mutable rolling
    # tag (:latest) points to a different image over time, so the derivation can't
    # be trusted to still apply (a profile derived against whatever :latest was).
    tree = _copy_good(tmp_path)
    _mutate(tree, lambda d: d.__setitem__("applies_to", {"tags": ["latest"]}))
    result = _run(tree / "catalog", tree)
    assert result.returncode == 1
    assert "mutable" in result.stdout


def test_drop_test_validated_passes(tmp_path: Path) -> None:
    # A drop-test-derived dimension (schema 1.1) is validated on
    # [drop-test, ci-smoke] and is exempt from the observation-window duration
    # floor -- drop-test covers the full lifetime and is not a timed observation.
    tree = _copy_good(tmp_path)

    def to_drop_test(d: dict) -> None:
        d["schema_version"] = "1.1"
        d["dimensions"]["capabilities"]["derivation"].update(
            observer="drop-test",
            validated_via=["drop-test", "ci-smoke"],
            duration_seconds=5,  # well under the 300s floor; waived for drop-test
            drop_test={
                "checks": [
                    {"removed": "CHOWN", "required": False, "observed": "ok"},
                    {"removed": "SETUID", "required": True, "observed": "ran as root"},
                ]
            },
        )

    _mutate(tree, to_drop_test)
    result = _run(tree / "catalog", tree)
    assert result.returncode == 0, result.stdout + result.stderr


def test_drop_test_missing_source_fails(tmp_path: Path) -> None:
    # observer=drop-test but validated_via lacks `drop-test` -> not validated.
    tree = _copy_good(tmp_path)

    def bad(d: dict) -> None:
        d["schema_version"] = "1.1"
        d["dimensions"]["capabilities"]["derivation"].update(
            observer="drop-test",
            validated_via=["bpf-observation", "ci-smoke"],
            drop_test={"checks": [{"removed": "X", "required": True, "observed": "y"}]},
        )

    _mutate(tree, bad)
    result = _run(tree / "catalog", tree)
    assert result.returncode == 1
    assert "validated_via" in result.stdout and "drop-test" in result.stdout


def test_drop_test_missing_evidence_fails(tmp_path: Path) -> None:
    # observer=drop-test but no derivation.drop_test evidence block -> not validated.
    tree = _copy_good(tmp_path)

    def bad(d: dict) -> None:
        d["schema_version"] = "1.1"
        d["dimensions"]["capabilities"]["derivation"].update(
            observer="drop-test",
            validated_via=["drop-test", "ci-smoke"],
            duration_seconds=5,
        )

    _mutate(tree, bad)
    result = _run(tree / "catalog", tree)
    assert result.returncode == 1
    assert "drop_test" in result.stdout and "evidence" in result.stdout


def test_missing_criteria_fails(tmp_path: Path) -> None:
    # A validated profile must ship a committed per-image criteria doc (#359).
    tree = _copy_good(tmp_path)
    (tree / "criteria" / "docker.io" / "library" / "postgres.md").unlink()
    result = _run(tree / "catalog", tree)
    assert result.returncode == 1
    assert "criteria" in result.stdout


def test_empty_criteria_fails(tmp_path: Path) -> None:
    tree = _copy_good(tmp_path)
    (tree / "criteria" / "docker.io" / "library" / "postgres.md").write_text(
        "\n  \n", encoding="utf-8"
    )
    result = _run(tree / "catalog", tree)
    assert result.returncode == 1
    assert "empty" in result.stdout


def test_workload_hash_mismatch_fails(tmp_path: Path) -> None:
    tree = _copy_good(tmp_path)
    workload = tree / "profiles" / "workloads" / "postgres.sh"
    workload.write_text("#!/bin/sh\n# tamper\n")
    result = _run(tree / "catalog", tree)
    assert result.returncode == 1
    assert "workload_sha256 mismatch" in result.stdout


def test_missing_workload_fails(tmp_path: Path) -> None:
    tree = _copy_good(tmp_path)
    (tree / "profiles" / "workloads" / "postgres.sh").unlink()
    result = _run(tree / "catalog", tree)
    assert result.returncode == 1
    assert "workload script not found" in result.stdout


def test_schema_invalid_fails(tmp_path: Path) -> None:
    tree = _copy_good(tmp_path)
    _mutate(tree, lambda d: d.update(image="Docker.IO/BAD"))
    result = _run(tree / "catalog", tree)
    assert result.returncode == 1
    assert "schema" in result.stdout


def test_exploratory_outside_exploratory_dir_fails(tmp_path: Path) -> None:
    tree = _copy_good(tmp_path)

    def make_exploratory(doc: dict) -> None:
        doc["status"] = "exploratory"
        doc["acceptance_contract_violations"] = ["duration_seconds 120 < 300"]

    _mutate(tree, make_exploratory)
    result = _run(tree / "catalog", tree)
    assert result.returncode == 1
    assert "exploratory" in result.stdout
