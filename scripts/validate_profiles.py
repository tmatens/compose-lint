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

# Sources required for a validated profile, by derivation. Runtime observation
# emits bpf-observation; drop-test (observer=drop-test, schema 1.1) — remove each
# candidate and verify the container breaks without it — emits drop-test. This
# gate backs the ci-smoke half in both cases.
VALIDATED_VIA_REQUIRED = frozenset({"bpf-observation", "ci-smoke"})
DROP_TEST_VIA_REQUIRED = frozenset({"drop-test", "ci-smoke"})
MIN_DURATION_SECONDS = 300
VALIDATED_CONFIDENCE = frozenset({"high", "moderate"})


def check_document(
    path: Path,
    doc: dict,
    validator: Draft202012Validator,
    repo_root: Path,
    exploratory_dir: Path,
    catalog_dir: Path,
    criteria_dir: Path,
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
        errors.extend(_check_criteria(path, catalog_dir, criteria_dir))
    elif status == "exploratory" and not under_exploratory:
        errors.append("exploratory profile must live under catalog/exploratory/")

    for name, dim in dimensions.items():
        errors.extend(_check_workload(name, dim["derivation"], repo_root))

    return errors


def _check_validated_dimension(name: str, derivation: dict) -> list[str]:
    errors: list[str] = []
    # drop-test (remove a candidate, restart, verify it breaks) is a distinct,
    # kernel-authoritative derivation: it covers the full container lifetime, so
    # it needs neither the observation-window duration floor (it is not a timed
    # observation) nor the bpf-observation source. It asserts [drop-test,
    # ci-smoke] instead. The confidence gate still applies (a drop-test dimension
    # carries `high`).
    drop_test = derivation.get("observer") == "drop-test"
    confidence = derivation.get("confidence")
    if confidence not in VALIDATED_CONFIDENCE:
        errors.append(
            f"{name}: validated requires confidence high/moderate, got {confidence!r}"
        )
    if not drop_test and derivation.get("duration_seconds", 0) < MIN_DURATION_SECONDS:
        errors.append(
            f"{name}: validated requires duration_seconds >= {MIN_DURATION_SECONDS}"
        )
    required = DROP_TEST_VIA_REQUIRED if drop_test else VALIDATED_VIA_REQUIRED
    missing = required - set(derivation.get("validated_via", []))
    if missing:
        errors.append(
            f"{name}: validated requires validated_via to include "
            f"{sorted(required)}, missing {sorted(missing)}"
        )
    # A drop-test dimension must carry its evidence: it can't just *claim* the
    # source, it has to record what was removed and what happened. The schema
    # enforces the block's shape; this makes it mandatory for observer=drop-test.
    if drop_test and not derivation.get("drop_test"):
        errors.append(
            f"{name}: observer=drop-test requires a derivation.drop_test evidence "
            f"block (the removed/required/observed checks)"
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


def _check_criteria(path: Path, catalog_dir: Path, criteria_dir: Path) -> list[str]:
    """A validated profile must ship a committed per-image criteria doc (#359,
    ADR-017 §7): the reviewable scenarios + pass criteria the derivation was
    judged against. Convention: the doc mirrors the profile's catalog path —
    ``catalog/<rel>.y*ml`` ⇒ ``criteria/<rel>.md`` — and must be non-empty."""
    try:
        rel = path.resolve().relative_to(catalog_dir)
    except ValueError:
        return []  # profile outside catalog_dir; no criteria path to derive
    criteria_path = criteria_dir / rel.with_suffix(".md")
    disp = f"criteria/{rel.with_suffix('.md')}"
    if not criteria_path.is_file():
        return [f"validated profile requires a committed criteria doc at {disp} (#359)"]
    if not criteria_path.read_text(encoding="utf-8").strip():
        return [f"criteria doc {disp} is empty (#359)"]
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
    parser.add_argument(
        "--criteria-dir",
        type=Path,
        default=None,
        help="dir holding per-image criteria docs (default: <catalog-dir>/../criteria)",
    )
    args = parser.parse_args(argv)

    schema = json.loads(args.schema.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    exploratory_dir = (args.catalog_dir / "exploratory").resolve()
    repo_root = args.repo_root.resolve()
    catalog_dir = args.catalog_dir.resolve()
    criteria_dir = (
        args.criteria_dir.resolve()
        if args.criteria_dir is not None
        else (catalog_dir.parent / "criteria")
    )

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
        errors = check_document(
            path, doc, validator, repo_root, exploratory_dir, catalog_dir, criteria_dir
        )
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
