"""The OpenVEX document and the smoke check that keeps it true stay in step.

A base-image statement in ``.vex/compose-lint.openvex.json`` names no package
and no version (ADR-012), so nothing in the document ties it to an image. The
tie is ``tests/smoke/assert_vex_claims.py``, which the Docker smokes run inside
the built image. A statement added without a check there would be honoured by
every scanner and verified by nothing, so the two lists are held equal here.
"""

from __future__ import annotations

import importlib.util
import json
import struct
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parent.parent
VEX_PATH = REPO_ROOT / ".vex" / "compose-lint.openvex.json"
SMOKE_PATH = REPO_ROOT / "tests" / "smoke" / "assert_vex_claims.py"

PRODUCT_IDS = [
    "pkg:oci/compose-lint?repository_url=index.docker.io/composelint/compose-lint",
    "pkg:docker/composelint/compose-lint",
]
PIP = [{"@id": "pkg:pypi/pip"}]
JUSTIFICATIONS = {
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
}


def _smoke() -> ModuleType:
    spec = importlib.util.spec_from_file_location("assert_vex_claims", SMOKE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _statements() -> list[dict[str, Any]]:
    statements = json.loads(VEX_PATH.read_text(encoding="utf-8"))["statements"]
    assert isinstance(statements, list)
    return statements


def _is_pip(statement: dict[str, Any]) -> bool:
    return any("subcomponents" in product for product in statement["products"])


def test_every_base_image_statement_is_guarded_by_the_smoke_check() -> None:
    base = {s["vulnerability"]["name"] for s in _statements() if not _is_pip(s)}
    assert base == set(_smoke().GUARDED)


def test_every_guarded_statement_is_named_by_a_check() -> None:
    smoke = _smoke()
    named: set[str] = {"CVE-2026-3479"}  # the recorded pkgutil.get_data call count
    for table in (
        smoke.FORBIDDEN_MODULES,
        smoke.FORBIDDEN_LIBRARIES,
        smoke.FORBIDDEN_IMPORTS,
        smoke.FORBIDDEN_FILES,
    ):
        for cves in table.values():
            named.update(cve.strip() for cve in cves.split(","))
    assert named == set(smoke.GUARDED)


def test_statements_keep_the_two_shapes_the_scanners_honour() -> None:
    names = []
    for statement in _statements():
        name = statement["vulnerability"]["name"]
        names.append(name)
        assert statement["status"] == "not_affected", name
        assert statement["justification"] in JUSTIFICATIONS, name
        assert statement["impact_statement"].strip(), name
        products = statement["products"]
        assert [product["@id"] for product in products] == PRODUCT_IDS, name
        # pip statements name pip; base-image statements name nothing, the
        # only form Docker Scout and Trivy both match (ADR-012).
        subcomponents = [product.get("subcomponents") for product in products]
        assert subcomponents in ([PIP, PIP], [None, None]), name
    assert len(names) == len(set(names))


def _elf(imports: list[str], defined: list[str]) -> bytes:
    """Build a minimal 64-bit little-endian ELF with a dynamic symbol table."""
    strings = b"\0"
    symbols = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
    for name, section_index in [(n, 0) for n in imports] + [(n, 1) for n in defined]:
        symbols += struct.pack("<IBBHQQ", len(strings), 0x12, 0, section_index, 0, 0)
        strings += name.encode("ascii") + b"\0"
    dynsym_offset = 64
    strings_offset = dynsym_offset + len(symbols)
    shoff = strings_offset + len(strings)
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", header, 0x28, shoff)
    struct.pack_into("<HH", header, 0x3A, 64, 3)
    section = struct.Struct("<IIQQQQIIQQ")
    sections = (
        section.pack(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        + section.pack(0, 11, 0, 0, dynsym_offset, len(symbols), 2, 1, 8, 24)
        + section.pack(0, 3, 0, 0, strings_offset, len(strings), 0, 0, 1, 0)
    )
    return bytes(header) + symbols + strings + sections


def test_the_elf_reader_returns_imports_and_not_definitions() -> None:
    data = _elf(imports=["regcomp", "malloc"], defined=["PyInit_x", "glob"])
    assert _smoke().undefined_dynamic_symbols(data) == {"regcomp", "malloc"}


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"#!/bin/bash\n", "not an ELF file"),
        (b"\x7fELF\x01\x01" + bytes(64), "not a 64-bit little-endian"),
        (b"\x7fELF\x02\x01" + bytes(64), "no readable section headers"),
    ],
)
def test_the_elf_reader_refuses_what_it_cannot_read(data: bytes, message: str) -> None:
    # A file it cannot read must be an error in the smoke, never "imports
    # nothing", or an unreadable object would pass the check.
    with pytest.raises(ValueError, match=message):
        _smoke().undefined_dynamic_symbols(data)
