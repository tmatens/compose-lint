"""Tests for CL-0013: Sensitive host paths mounted."""

from __future__ import annotations

from pathlib import Path

from compose_lint.models import Severity
from compose_lint.parser import load_compose, loads
from compose_lint.rules.CL0013_sensitive_mount import SensitiveMountRule

FIXTURES = Path(__file__).parent / "compose_files"


class TestSensitiveMountRule:
    """Tests for sensitive host path mount detection."""

    def setup_method(self) -> None:
        self.rule = SensitiveMountRule()

    def _check(self, service_name: str) -> list:
        data, lines = load_compose(FIXTURES / "insecure_sensitive_mount.yml")
        return list(
            self.rule.check(service_name, data["services"][service_name], data, lines)
        )

    def test_detects_etc(self) -> None:
        findings = self._check("mounts_etc")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0013"
        assert "/etc" in findings[0].message
        assert findings[0].severity == Severity.HIGH

    def test_detects_proc(self) -> None:
        findings = self._check("mounts_proc")
        assert len(findings) == 1
        assert "/proc" in findings[0].message

    def test_detects_sys(self) -> None:
        findings = self._check("mounts_sys")
        assert len(findings) == 1
        assert "/sys" in findings[0].message

    def test_detects_boot(self) -> None:
        findings = self._check("mounts_boot")
        assert len(findings) == 1
        assert "/boot" in findings[0].message

    def test_detects_root(self) -> None:
        findings = self._check("mounts_root")
        assert len(findings) == 1
        assert "/root" in findings[0].message

    def test_detects_etc_subpath(self) -> None:
        findings = self._check("mounts_etc_subpath")
        assert len(findings) == 1
        assert "/etc/passwd" in findings[0].message

    def test_detects_multiple(self) -> None:
        findings = self._check("mounts_multiple")
        assert len(findings) == 2

    def test_detects_root_filesystem(self) -> None:
        findings = self._check("mounts_root_filesystem")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "root filesystem" in findings[0].message

    def test_detects_root_filesystem_ro(self) -> None:
        findings = self._check("mounts_root_filesystem_ro")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_detects_var_lib_docker(self) -> None:
        findings = self._check("mounts_var_lib_docker")
        assert len(findings) == 1
        assert "/var/lib/docker" in findings[0].message

    def test_detects_var_run(self) -> None:
        findings = self._check("mounts_var_run")
        assert len(findings) == 1
        assert "/var/run" in findings[0].message

    def test_detects_home(self) -> None:
        findings = self._check("mounts_home")
        assert len(findings) == 1
        assert "/home" in findings[0].message

    def test_detects_root_ssh(self) -> None:
        findings = self._check("mounts_root_ssh")
        assert len(findings) == 1
        assert "/root/.ssh" in findings[0].message

    def test_detects_etc_trailing_slash(self) -> None:
        findings = self._check("mounts_etc_trailing_slash")
        assert len(findings) == 1
        assert "/etc" in findings[0].message
        assert findings[0].severity == Severity.HIGH

    def test_safe_volume_no_findings(self) -> None:
        findings = self._check("safe_volume")
        assert len(findings) == 0

    def test_no_volumes_no_findings(self) -> None:
        findings = self._check("no_volumes")
        assert len(findings) == 0

    def test_long_syntax_bind(self) -> None:
        findings = self._check("long_syntax_bind")
        assert len(findings) == 1
        assert "/etc" in findings[0].message

    def test_long_syntax_bind_no_type(self) -> None:
        findings = self._check("long_syntax_bind_no_type")
        assert len(findings) == 1
        assert "/etc" in findings[0].message
        assert findings[0].severity == Severity.HIGH

    def test_long_syntax_root_no_type(self) -> None:
        findings = self._check("long_syntax_root_no_type")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_long_syntax_named_no_findings(self) -> None:
        findings = self._check("long_syntax_named")
        assert len(findings) == 0

    def test_has_fix_guidance(self) -> None:
        findings = self._check("mounts_etc")
        assert findings[0].fix is not None
        assert "/etc" in findings[0].fix

    def test_has_references(self) -> None:
        findings = self._check("mounts_etc")
        assert len(findings[0].references) > 0

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0013"
        assert meta.severity.value == "high"


class TestTimezoneExemption:
    """Read-only /etc/localtime and /etc/timezone are exempt (issue #509).

    The near-universal `- /etc/localtime:/etc/localtime:ro` pattern exposes only
    the host's UTC offset. Flagging it HIGH failed the default gate on otherwise
    fully-hardened services. /etc itself, other /etc files, and read-write
    timezone mounts still fire.
    """

    def setup_method(self) -> None:
        self.rule = SensitiveMountRule()

    def _check(self, content: str, service: str = "a") -> list:
        data, lines = loads(content)
        return list(self.rule.check(service, data["services"][service], data, lines))

    def test_readonly_localtime_and_timezone_exempt(self) -> None:
        content = (
            "services:\n  a:\n    image: nginx\n    volumes:\n"
            "      - /etc/localtime:/etc/localtime:ro\n"
            "      - /etc/timezone:/etc/timezone:ro\n"
        )
        assert self._check(content) == []

    def test_long_syntax_readonly_localtime_exempt(self) -> None:
        content = (
            "services:\n  a:\n    image: nginx\n    volumes:\n"
            "      - type: bind\n        source: /etc/localtime\n"
            "        target: /etc/localtime\n        read_only: true\n"
        )
        assert self._check(content) == []

    def test_readwrite_localtime_still_fires(self) -> None:
        content = (
            "services:\n  a:\n    image: nginx\n    volumes:\n"
            "      - /etc/localtime:/etc/localtime\n"
        )
        findings = self._check(content)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_etc_directory_still_fires_readonly(self) -> None:
        content = (
            "services:\n  a:\n    image: nginx\n    volumes:\n"
            "      - /etc:/host/etc:ro\n"
        )
        assert len(self._check(content)) == 1

    def test_other_etc_file_still_fires_readonly(self) -> None:
        content = (
            "services:\n  a:\n    image: nginx\n    volumes:\n"
            "      - /etc/shadow:/etc/shadow:ro\n"
        )
        assert len(self._check(content)) == 1

    def test_long_syntax_quoted_readonly_localtime_exempt(self) -> None:
        # A quoted `read_only: "true"` is coerced like Docker does (issue #514).
        content = (
            "services:\n  a:\n    image: nginx\n    volumes:\n"
            "      - type: bind\n        source: /etc/localtime\n"
            '        target: /etc/localtime\n        read_only: "true"\n'
        )
        assert self._check(content) == []


class TestRunMount:
    """Bare /run is sensitive: it holds both daemon sockets (issue #513)."""

    def setup_method(self) -> None:
        self.rule = SensitiveMountRule()

    def _check(self, content: str, service: str = "a") -> list:
        data, lines = loads(content)
        return list(self.rule.check(service, data["services"][service], data, lines))

    def test_bare_run_flagged(self) -> None:
        content = (
            "services:\n  a:\n    image: nginx\n    volumes:\n      - /run:/hostrun\n"
        )
        findings = self._check(content)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "/run" in findings[0].message

    def test_run_subpaths_keep_specific_message(self) -> None:
        # /run/containerd must still report as itself, not as bare /run.
        content = (
            "services:\n  a:\n    image: nginx\n    volumes:\n"
            "      - /run/containerd:/x\n"
        )
        findings = self._check(content)
        assert len(findings) == 1
        assert "/run/containerd" in findings[0].message
