"""Tests for the JSON formatter and its ADR-015 / RFC 8259 conformance.

These guard the J1 failure modes from #278: a YAML service-name key can resolve
to a non-string scalar (a bool from ``true:``, an int from a bare number, a
float from ``.nan``), which broke the JSON contract three ways — a ``TypeError``
crash, invalid ``NaN``/``Infinity`` tokens, and a wrong-typed ``service`` field.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

from compose_lint.formatters.json import build_json_log, format_findings
from compose_lint.models import Finding, Severity

if TYPE_CHECKING:
    from pathlib import Path


def _raise_constant(token: str) -> object:
    """``json.loads`` callback that rejects bare NaN/Infinity tokens.

    RFC 8259 §6 forbids them; a strict consumer would reject the document. Using
    this as ``parse_constant`` turns the issue's "valid JSON, exit 0" NaN case
    into a test failure instead of a silent pass.
    """
    raise AssertionError(f"non-JSON constant token in output: {token!r}")


def _make(service: object) -> Finding:
    # The dataclass annotates ``service`` as ``str``, but the parser feeds it
    # whatever the YAML key resolved to; reproduce that here.
    return Finding(
        rule_id="CL-0004",
        severity=Severity.MEDIUM,
        service=service,  # type: ignore[arg-type]
        message="Image 'nginx:latest' uses mutable tag.",
        line=2,
    )


class TestServiceCoercion:
    """`service` is always emitted as a string regardless of the key's type."""

    @pytest.mark.parametrize(
        ("service", "expected"),
        [
            (True, "True"),
            (False, "False"),
            (123, "123"),
            (float("nan"), "nan"),
            (float("inf"), "inf"),
            ("web", "web"),
        ],
    )
    def test_service_is_stringified(self, service: object, expected: str) -> None:
        results = format_findings([_make(service)], "x.yml")
        assert results[0]["service"] == expected
        assert isinstance(results[0]["service"], str)


class TestStrictSerialization:
    """The serialized envelope is strict, parseable JSON (no NaN/Infinity)."""

    def test_nan_service_does_not_emit_bare_nan(self) -> None:
        log = build_json_log(format_findings([_make(float("nan"))], "x.yml"))
        dumped = json.dumps(log, allow_nan=False)
        # round-trips under a parser that rejects NaN/Infinity
        parsed = json.loads(dumped, parse_constant=_raise_constant)
        assert parsed["findings"][0]["service"] == "nan"

    def test_allow_nan_false_would_catch_a_stray_float(self) -> None:
        # Belt-and-suspenders: even if a numeric field ever carried a raw NaN,
        # the CLI's allow_nan=False dump raises rather than emitting invalid JSON.
        with pytest.raises(ValueError, match="Out of range float"):
            json.dumps({"x": float("nan")}, allow_nan=False)


class TestJsonCLI:
    """End-to-end: typed service keys produce valid, contract-shaped JSON."""

    def _run(self, tmp_path: Path, body: str) -> dict:
        f = tmp_path / "compose.yml"
        f.write_text(body)
        result = subprocess.run(
            [sys.executable, "-m", "compose_lint", "--format", "json", str(f)],
            capture_output=True,
            text=True,
        )
        # The pre-fix failures were a crash (exit 1, zero bytes to stdout) and
        # invalid JSON (a bare NaN token); both are caught here. Findings on
        # these fixtures are below the HIGH default threshold, so a healthy run
        # exits 0 — never 2, and always with parseable JSON on stdout.
        assert result.returncode in (0, 1), result.stderr
        assert result.stdout, "expected JSON on stdout, got nothing (crash?)"
        return json.loads(result.stdout, parse_constant=_raise_constant)

    def test_date_service_key(self, tmp_path: Path) -> None:
        data = self._run(
            tmp_path,
            "services:\n  2024-01-01:\n    image: nginx:latest\n",
        )
        services = {f["service"] for f in data["findings"]}
        assert "2024-01-01" in services
        assert all(isinstance(s, str) for s in services)

    def test_nan_service_key(self, tmp_path: Path) -> None:
        data = self._run(
            tmp_path,
            "services:\n  .nan:\n    image: nginx:latest\n",
        )
        assert all(isinstance(f["service"], str) for f in data["findings"])

    def test_bool_service_key(self, tmp_path: Path) -> None:
        data = self._run(
            tmp_path,
            "services:\n  true:\n    image: nginx:latest\n",
        )
        assert all(isinstance(f["service"], str) for f in data["findings"])
