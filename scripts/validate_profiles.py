#!/usr/bin/env python3
"""Validate contributed security profiles — the compose-lint "ci-smoke" gate.

Every document under the profile catalog must be schema-valid, digest-pinned,
backed by a committed + hash-verified workload script, and satisfy the
validated/exploratory invariants the JSON Schema cannot express. A ``validated``
profile asserts ``validated_via: [bpf-observation, ci-smoke]``; this script is
the ci-smoke half, so it fails when that assertion is not backed by a
well-formed, reproducible artifact (ADR-017).

Runs in CI (the ``profile-validate`` job) and locally:

    python scripts/validate_profiles.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parent.parent
_PROFILES = REPO_ROOT / "src" / "compose_lint" / "profiles"
# No bundled catalog (ADR-017 §7): the catalog is an external, user/automation
# -owned checkout. Default to a repo-relative `profiles/catalog` for a local run;
# the catalog's own CI passes --catalog-dir explicitly. The schema stays shipped.
DEFAULT_CATALOG = REPO_ROOT / "profiles" / "catalog"
DEFAULT_SCHEMA = _PROFILES / "schema" / "profile.schema.json"

# Both sources are required for a validated profile: csd emits bpf-observation,
# and this gate backs the ci-smoke half.
VALIDATED_VIA_REQUIRED = frozenset({"bpf-observation", "ci-smoke"})
MIN_DURATION_SECONDS = 300
VALIDATED_CONFIDENCE = frozenset({"high", "moderate"})


def check_document(
    path: Path,
    doc: dict,
    validator: Draft202012Validator,
    repo_root: Path,
    exploratory_dir: Path,
) -> list[str]:
    """Return a list of human-readable violations for one profile document."""
    errors = [
        f"schema: {e.message} (at {'/'.join(str(p) for p in e.path) or '<root>'})"
        for e in validator.iter_errors(doc)
    ]
    if errors:
        # Cross-field checks below assume the schema-guaranteed shape.
        return errors

    status = doc["status"]
    under_exploratory = exploratory_dir in path.resolve().parents
    dimensions: dict = doc["dimensions"]

    if status == "validated":
        if under_exploratory:
            errors.append("validated profile must not live under catalog/exploratory/")
        for name, dim in dimensions.items():
            errors.extend(_check_validated_dimension(name, dim["derivation"]))
    elif status == "exploratory" and not under_exploratory:
        errors.append("exploratory profile must live under catalog/exploratory/")

    for name, dim in dimensions.items():
        errors.extend(_check_workload(name, dim["derivation"], repo_root))

    return errors


def _check_validated_dimension(name: str, derivation: dict) -> list[str]:
    errors: list[str] = []
    confidence = derivation.get("confidence")
    if confidence not in VALIDATED_CONFIDENCE:
        errors.append(
            f"{name}: validated requires confidence high/moderate, got {confidence!r}"
        )
    if derivation.get("duration_seconds", 0) < MIN_DURATION_SECONDS:
        errors.append(
            f"{name}: validated requires duration_seconds >= {MIN_DURATION_SECONDS}"
        )
    missing = VALIDATED_VIA_REQUIRED - set(derivation.get("validated_via", []))
    if missing:
        errors.append(
            f"{name}: validated requires validated_via to include "
            f"{sorted(VALIDATED_VIA_REQUIRED)}, missing {sorted(missing)}"
        )
    return errors


def _check_workload(name: str, derivation: dict, repo_root: Path) -> list[str]:
    workload = derivation["workload"]
    want = derivation["workload_sha256"]
    path = repo_root / workload
    if not path.is_file():
        return [f"{name}: workload script not found: {workload}"]
    got = hashlib.sha256(path.read_bytes()).hexdigest()
    if got != want:
        return [
            f"{name}: workload_sha256 mismatch for {workload} "
            f"(declared {want[:12]}…, actual {got[:12]}…)"
        ]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog-dir", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="root that workload paths resolve against",
    )
    args = parser.parse_args(argv)

    schema = json.loads(args.schema.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    exploratory_dir = (args.catalog_dir / "exploratory").resolve()
    repo_root = args.repo_root.resolve()

    files = (
        sorted(args.catalog_dir.rglob("*.y*ml")) if args.catalog_dir.is_dir() else []
    )
    total = 0
    for path in files:
        label = _label(path, repo_root)
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            print(f"FAIL {label}: invalid YAML: {exc}")
            total += 1
            continue
        if not isinstance(doc, dict):
            print(f"FAIL {label}: top level is not a mapping")
            total += 1
            continue
        errors = check_document(path, doc, validator, repo_root, exploratory_dir)
        if errors:
            total += len(errors)
            for err in errors:
                print(f"FAIL {label}: {err}")
        else:
            print(f"OK   {label}")

    print(f"\n{len(files)} profile(s) checked, {total} error(s).")
    return 1 if total else 0


def _label(path: Path, repo_root: Path) -> str:
    try:
        return str(path.resolve().relative_to(repo_root))
    except ValueError:
        return str(path)


if __name__ == "__main__":
    sys.exit(main())
