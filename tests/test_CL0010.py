"""Tests for CL-0010: Host namespace sharing."""

from __future__ import annotations

from pathlib import Path

from compose_lint.parser import load_compose
from compose_lint.rules.CL0010_host_namespace import HostNamespaceRule

FIXTURES = Path(__file__).parent / "compose_files"


class TestHostNamespaceRule:
    """Tests for host namespace sharing detection."""

    def setup_method(self) -> None:
        self.rule = HostNamespaceRule()

    def test_detects_pid_host(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_host_namespace.yml")
        findings = list(
            self.rule.check("pid_host", data["services"]["pid_host"], data, lines)
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0010"
        assert findings[0].severity.value == "high"
        assert "process namespace" in findings[0].message

    def test_detects_ipc_host(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_host_namespace.yml")
        findings = list(
            self.rule.check("ipc_host", data["services"]["ipc_host"], data, lines)
        )
        assert len(findings) == 1
        assert "IPC namespace" in findings[0].message

    def test_detects_userns_host(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_host_namespace.yml")
        findings = list(
            self.rule.check("userns_host", data["services"]["userns_host"], data, lines)
        )
        assert len(findings) == 1
        assert "user namespace" in findings[0].message

    def test_detects_uts_host(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_host_namespace.yml")
        findings = list(
            self.rule.check("uts_host", data["services"]["uts_host"], data, lines)
        )
        assert len(findings) == 1
        assert "UTS namespace" in findings[0].message

    def test_detects_all_three(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_host_namespace.yml")
        findings = list(
            self.rule.check("all_host", data["services"]["all_host"], data, lines)
        )
        assert len(findings) == 3

    def test_no_namespace_sharing_clean(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_host_namespace.yml")
        findings = list(
            self.rule.check(
                "no_namespace_sharing",
                data["services"]["no_namespace_sharing"],
                data,
                lines,
            )
        )
        assert len(findings) == 0

    def test_ipc_shareable_clean(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_host_namespace.yml")
        findings = list(
            self.rule.check(
                "ipc_shareable", data["services"]["ipc_shareable"], data, lines
            )
        )
        assert len(findings) == 0

    def test_has_fix_guidance(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_host_namespace.yml")
        findings = list(
            self.rule.check("pid_host", data["services"]["pid_host"], data, lines)
        )
        assert findings[0].fix is not None
        assert "pid" in findings[0].fix

    def test_has_references(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_host_namespace.yml")
        findings = list(
            self.rule.check("pid_host", data["services"]["pid_host"], data, lines)
        )
        assert len(findings[0].references) > 0
        assert "owasp" in findings[0].references[0].lower()

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0010"
        assert meta.severity.value == "high"
        assert len(meta.references) > 0
