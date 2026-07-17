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
    # 1.0 is the baseline; 1.1 adds drop-test as a derivation source; 1.2 adds
    # the optional derivation.run_config block; 1.3 adds the optional top-level
    # app_tier_verified block; 1.4 adds the optional derivation.run_config.sysctls
    # field; 1.5 adds the optional top-level reference_url field. All remain
    # valid so existing documents are not invalidated.
    assert schema["properties"]["schema_version"]["enum"] == [
        "1.0",
        "1.1",
        "1.2",
        "1.3",
        "1.4",
        "1.5",
    ]


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


def test_reference_url_accepted(
    validator: Draft202012Validator, example: dict[str, Any]
) -> None:
    # 1.5: optional top-level pointer to the profile's rendered page. Optional
    # regardless of the document's declared version (additive, like the rest).
    example["reference_url"] = (
        "https://example.com/profiles/docker.io/library/postgres.html"
    )
    assert validator.is_valid(example), list(validator.iter_errors(example))


def test_reference_url_must_be_https(
    validator: Draft202012Validator, example: dict[str, Any]
) -> None:
    example["reference_url"] = (
        "http://example.com/profiles/docker.io/library/postgres.html"
    )
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


def test_run_config_accepted(
    validator: Draft202012Validator, example: dict[str, Any]
) -> None:
    # The derivation may record the invocation the minimum was derived under.
    # It is optional (existing documents omit it) and tool-emitted.
    derivation = example["dimensions"]["capabilities"]["derivation"]
    derivation["run_config"] = {
        "user": "",
        "command": [],
        "entrypoint": "",
        "network": "",
        "pid": "",
        "devices": [],
        "security_opt": [],
        "mounts": [],
        "env": ["POSTGRES_PASSWORD"],
    }
    assert validator.is_valid(example), list(validator.iter_errors(example))


def test_run_config_rejects_unknown_key(
    validator: Draft202012Validator, example: dict[str, Any]
) -> None:
    # additionalProperties closure: run_config carries a fixed set of axes.
    example["dimensions"]["capabilities"]["derivation"]["run_config"] = {
        "user": "",
        "cap_add": ["SYS_ADMIN"],
    }
    assert not validator.is_valid(example)


def test_run_config_sysctls_accepted(
    validator: Draft202012Validator, example: dict[str, Any]
) -> None:
    # Schema 1.4: the kernel sysctl posture a posture-dependent minimum was
    # pinned under (the canonical case is ip_unprivileged_port_start for
    # NET_BIND_SERVICE). Optional array of "key=value" strings.
    example["schema_version"] = "1.4"
    example["dimensions"]["capabilities"]["derivation"]["run_config"] = {
        "sysctls": ["net.ipv4.ip_unprivileged_port_start=1024"],
    }
    assert validator.is_valid(example), list(validator.iter_errors(example))


def test_run_config_sysctls_must_be_array(
    validator: Draft202012Validator, example: dict[str, Any]
) -> None:
    example["dimensions"]["capabilities"]["derivation"]["run_config"] = {
        "sysctls": "net.ipv4.ip_unprivileged_port_start=1024",
    }
    assert not validator.is_valid(example)


def _app_tier_verified() -> dict[str, Any]:
    return {
        "service": "immich",
        "service_version": "v2.7.5",
        "method": "container-sec-derive scripts/apptier_verify.sh",
        "check": "immich REST API: sign-up, login, upload, read-back, search",
        "verified_date": "2026-07-04",
        "result": "pass",
        "over_hardening": {
            "applied": "dropped SETUID from the database",
            "result": "database unhealthy -> immich never starts",
        },
    }


def test_app_tier_verified_accepted(
    validator: Draft202012Validator, example: dict[str, Any]
) -> None:
    # A validated profile may record a whole-service verification (schema 1.3).
    # Optional and additive: existing documents omit it.
    example["schema_version"] = "1.3"
    example["app_tier_verified"] = _app_tier_verified()
    assert validator.is_valid(example), list(validator.iter_errors(example))


def test_app_tier_verified_requires_validated_status(
    validator: Draft202012Validator, example: dict[str, Any]
) -> None:
    # An exploratory profile has not cleared the bar, so it cannot claim a
    # service-level verification.
    example["status"] = "exploratory"
    example["acceptance_contract_violations"] = ["below the confidence bar"]
    example["app_tier_verified"] = _app_tier_verified()
    assert not validator.is_valid(example)


def test_app_tier_verified_requires_result(
    validator: Draft202012Validator, example: dict[str, Any]
) -> None:
    atv = _app_tier_verified()
    del atv["result"]
    example["app_tier_verified"] = atv
    assert not validator.is_valid(example)


def test_over_hardening_rejects_unknown_key(
    validator: Draft202012Validator, example: dict[str, Any]
) -> None:
    # additionalProperties closure on the over_hardening evidence.
    atv = _app_tier_verified()
    atv["over_hardening"]["cap"] = "SETUID"
    example["app_tier_verified"] = atv
    assert not validator.is_valid(example)
