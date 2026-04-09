"""KICS comparison tests.

Validates that compose-lint detects the same issues as the 4 comparable
KICS Docker Compose queries, using patterns drawn from KICS examples.

KICS queries tested:
  d6355c88 — Docker Socket Mounted In Container
  ae5b6871 — Privileged Containers Enabled
  27fcc7d6 — No New Privileges Not Set
  451d79dc — Container Traffic Not Bound To Host Interface
"""

from __future__ import annotations

from pathlib import Path

from compose_lint.engine import run_rules
from compose_lint.models import Severity
from compose_lint.parser import load_compose

FIXTURE = Path(__file__).parent / "compose_files" / "kics_comparison.yml"


def _findings_for_service(
    findings: list[object], service: str, rule_id: str
) -> list[object]:
    return [f for f in findings if f.service == service and f.rule_id == rule_id]


class TestKICSDockerSocket:
    """KICS d6355c88 — Docker Socket Mounted In Container (HIGH).

    compose-lint equivalent: CL-0001 (CRITICAL).
    """

    def setup_method(self) -> None:
        data, lines = load_compose(FIXTURE)
        self.findings = run_rules(data, lines)

    def test_detects_socket_mount(self) -> None:
        hits = _findings_for_service(self.findings, "docker_socket_mounted", "CL-0001")
        assert len(hits) == 1
        assert hits[0].severity == Severity.CRITICAL
        assert "docker.sock" in hits[0].message

    def test_no_socket_clean(self) -> None:
        hits = _findings_for_service(self.findings, "no_socket_secure", "CL-0001")
        assert len(hits) == 0


class TestKICSPrivileged:
    """KICS ae5b6871 — Privileged Containers Enabled (HIGH).

    compose-lint equivalent: CL-0002 (CRITICAL).
    """

    def setup_method(self) -> None:
        data, lines = load_compose(FIXTURE)
        self.findings = run_rules(data, lines)

    def test_detects_privileged_true(self) -> None:
        hits = _findings_for_service(self.findings, "privileged_enabled", "CL-0002")
        assert len(hits) == 1
        assert hits[0].severity == Severity.CRITICAL

    def test_detects_privileged_even_with_cap_drop(self) -> None:
        """KICS also flags privileged mode even when cap_drop: all is set."""
        hits = _findings_for_service(
            self.findings, "privileged_with_cap_drop", "CL-0002"
        )
        assert len(hits) == 1

    def test_privileged_false_clean(self) -> None:
        hits = _findings_for_service(self.findings, "privileged_false", "CL-0002")
        assert len(hits) == 0


class TestKICSNoNewPrivileges:
    """KICS 27fcc7d6 — No New Privileges Not Set (HIGH).

    compose-lint equivalent: CL-0003 (WARNING).

    Severity difference: KICS rates this HIGH; compose-lint rates it WARNING
    because the absence of no-new-privileges is a defense-in-depth gap, not
    a directly exploitable misconfiguration.
    """

    def setup_method(self) -> None:
        data, lines = load_compose(FIXTURE)
        self.findings = run_rules(data, lines)

    def test_detects_missing_no_new_privs(self) -> None:
        hits = _findings_for_service(self.findings, "no_new_privs_missing", "CL-0003")
        assert len(hits) == 1
        assert hits[0].severity == Severity.MEDIUM

    def test_detects_explicit_false(self) -> None:
        """KICS flags no-new-privileges:false — compose-lint should too."""
        hits = _findings_for_service(self.findings, "no_new_privs_false", "CL-0003")
        assert len(hits) == 1

    def test_detects_other_security_opt_without_no_new_privs(self) -> None:
        """Having other security_opt but not no-new-privileges is still flagged."""
        hits = _findings_for_service(self.findings, "no_new_privs_other_opt", "CL-0003")
        assert len(hits) == 1

    def test_no_new_privs_true_clean(self) -> None:
        hits = _findings_for_service(self.findings, "new_privs_secure", "CL-0003")
        assert len(hits) == 0


class TestKICSUnboundPorts:
    """KICS 451d79dc — Container Traffic Not Bound To Host Interface (MEDIUM).

    compose-lint equivalent: CL-0005 (HIGH).
    """

    def setup_method(self) -> None:
        data, lines = load_compose(FIXTURE)
        self.findings = run_rules(data, lines)

    def test_detects_unbound_short_syntax(self) -> None:
        hits = _findings_for_service(self.findings, "unbound_port_short", "CL-0005")
        assert len(hits) == 1
        assert hits[0].severity == Severity.HIGH

    def test_detects_unbound_port_range(self) -> None:
        hits = _findings_for_service(self.findings, "unbound_port_range", "CL-0005")
        assert len(hits) == 1

    def test_detects_unbound_long_syntax(self) -> None:
        hits = _findings_for_service(self.findings, "unbound_port_long", "CL-0005")
        assert len(hits) == 1

    def test_bound_port_clean(self) -> None:
        hits = _findings_for_service(self.findings, "bound_port_secure", "CL-0005")
        assert len(hits) == 0

    def test_bound_port_range_clean(self) -> None:
        hits = _findings_for_service(
            self.findings, "bound_port_range_secure", "CL-0005"
        )
        assert len(hits) == 0
