"""Schema guard for the security profile catalog (ADR-017).

Mirrors tests/test_corpus_snapshot_schema.py: validation runs under the normal
pytest CI job, no dedicated workflow and no runtime dependency. It proves the
committed JSON Schema is itself a valid Draft 2020-12 schema, that a well-formed
example validates, and that the load-bearing constraints (digest pinning, the
status/violations coupling, additionalProperties closure) actually reject
malformed documents.

The catalog-file loader and per-file PR validation land in follow-up PRs; this
test locks the contract they build on.
"""

from __future__ import annotations

import copy
import importlib.resources
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

EXAMPLE_PATH = Path(__file__).parent / "fixtures" / "profiles" / "postgres.example.yml"


def _load_schema() -> dict[str, Any]:
    # Reach the schema the way the loader will in a later PR: as package data
    # under compose_lint.profiles, not via a source-tree-relative path.
    resource = (
        importlib.resources.files("compose_lint.profiles")
        / "schema"
        / "profile.schema.json"
    )
    return json.loads(resource.read_text(encoding="utf-8"))


def _load_example() -> dict[str, Any]:
    return yaml.safe_load(EXAMPLE_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    return _load_schema()


@pytest.fixture(scope="module")
def validator(schema: dict[str, Any]) -> Draft202012Validator:
    return Draft202012Validator(schema)


@pytest.fixture()
def example() -> dict[str, Any]:
    return _load_example()


def test_schema_is_valid_draft202012(schema: dict[str, Any]) -> None:
    # Raises SchemaError if the schema document is itself malformed.
    Draft202012Validator.check_schema(schema)


def test_schema_version_is_pinned(schema: dict[str, Any]) -> None:
    assert schema["properties"]["schema_version"]["const"] == "1.0"


def test_example_validates(
    validator: Draft202012Validator, example: dict[str, Any]
) -> None:
    assert validator.is_valid(example), list(validator.iter_errors(example))


def test_image_is_required(
    validator: Draft202012Validator, example: dict[str, Any]
) -> None:
    del example["image"]
    assert not validator.is_valid(example)


def test_validated_image_must_be_digest_pinned(
    validator: Draft202012Validator, example: dict[str, Any]
) -> None:
    example["dimensions"]["capabilities"]["derivation"]["validated_image"] = (
        "docker.io/library/postgres:16"
    )
    assert not validator.is_valid(example)


def test_validated_status_rejects_violations(
    validator: Draft202012Validator, example: dict[str, Any]
) -> None:
    # status=validated must not carry acceptance_contract_violations.
    example["acceptance_contract_violations"] = ["duration_seconds 120 < 300"]
    assert not validator.is_valid(example)


def test_exploratory_status_requires_violations(
    validator: Draft202012Validator, example: dict[str, Any]
) -> None:
    example["status"] = "exploratory"
    assert not validator.is_valid(example)

    example["acceptance_contract_violations"] = ["confidence low"]
    assert validator.is_valid(example), list(validator.iter_errors(example))


def test_unknown_observer_rejected(
    validator: Draft202012Validator, example: dict[str, Any]
) -> None:
    example["dimensions"]["capabilities"]["derivation"]["observer"] = "egress"
    assert not validator.is_valid(example)


def test_additional_properties_closed(
    validator: Draft202012Validator, example: dict[str, Any]
) -> None:
    variant = copy.deepcopy(example)
    variant["unexpected_top_level"] = True
    assert not validator.is_valid(variant)

    variant = copy.deepcopy(example)
    variant["dimensions"]["capabilities"]["oops"] = True
    assert not validator.is_valid(variant)


def test_gadget_provenance_shape(
    validator: Draft202012Validator, example: dict[str, Any]
) -> None:
    # A csd-authored gadget must record image + digest, not just a name.
    backend = example["dimensions"]["capabilities"]["derivation"]["observation_backend"]
    backend["gadgets"] = [{"name": "trace_socket"}]
    assert not validator.is_valid(example)

    backend["gadgets"] = [
        {
            "name": "trace_socket",
            "image": "ghcr.io/tmatens/csd-gadgets/trace_socket",
            "digest": "sha256:" + "b" * 64,
        }
    ]
    assert validator.is_valid(example), list(validator.iter_errors(example))
