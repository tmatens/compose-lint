"""Tests for CL-0013: sensitive host path exposed.

CL-0013 is the exposure tier of the host-path split. Writable mounts of
root-equivalent paths are CL-0025's; a mount of a control socket or a directory
holding one is CL-0001's. What is worth testing here is the boundary: this rule
keeps /sys, /dev and /home in either mode, and picks up read-only mounts of
CL-0025's paths, where the grant is disclosure rather than host write.
"""

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

    def test_writable_root_equivalents_are_not_this_rule(self) -> None:
        """Writable /etc, /proc, /boot, /root, /var/lib/docker are CL-0025's."""
        for service in (
            "mounts_proc",
            "mounts_boot",
            "mounts_root",
            "mounts_var_lib_docker",
            "mounts_root_filesystem",
        ):
            assert self._check(service) == [], service

    def test_control_socket_dirs_are_not_this_rule(self) -> None:
        """/var/run and friends moved to CL-0001, which owns the socket."""
        assert self._check("mounts_var_run") == []

    def test_detects_sys(self) -> None:
        findings = self._check("mounts_sys")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0013"
        assert findings[0].severity == Severity.HIGH
        assert "/sys" in findings[0].message

    def test_detects_home(self) -> None:
        findings = self._check("mounts_home")
        assert len(findings) == 1
        assert "/home" in findings[0].message

    def test_readonly_root_equivalents_are_disclosure(self) -> None:
        """Read-only /etc, /etc/passwd and /root/.ssh disclose without write."""
        for service in ("mounts_etc", "mounts_etc_subpath", "mounts_root_ssh"):
            findings = self._check(service)
            assert len(findings) == 1, service
            assert findings[0].severity == Severity.HIGH
            assert "read-only" in findings[0].message

    def test_readonly_root_filesystem_is_disclosure(self) -> None:
        """A read-only whole-root mount discloses without granting write."""
        findings = self._check("mounts_root_filesystem_ro")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "read-only" in findings[0].message

    def test_detects_multiple(self) -> None:
        # The fixture mounts /etc and /proc, both writable — both CL-0025's.
        assert self._check("mounts_multiple") == []

    def test_dev_fires_in_either_mode(self) -> None:
        for volume in ("/dev:/hostdev", "/dev:/hostdev:ro"):
            data, lines = loads(
                f"services:\n  a:\n    image: x\n    volumes:\n      - {volume}\n"
            )
            findings = list(self.rule.check("a", data["services"]["a"], data, lines))
            assert len(findings) == 1, volume
            assert findings[0].severity == Severity.HIGH

    def test_safe_volume_no_findings(self) -> None:
        findings = self._check("safe_volume")
        assert len(findings) == 0

    def test_no_volumes_no_findings(self) -> None:
        findings = self._check("no_volumes")
        assert len(findings) == 0

    def test_long_syntax_writable_binds_are_cl0025(self) -> None:
        """Both long-syntax forms parse; a writable /etc or / is CL-0025's."""
        for service in (
            "long_syntax_bind",
            "long_syntax_bind_no_type",
            "long_syntax_root_no_type",
        ):
            assert self._check(service) == [], service

    def test_long_syntax_readonly_bind_fires(self) -> None:
        data, lines = loads(
            "services:\n  a:\n    image: x\n    volumes:\n"
            "      - type: bind\n        source: /etc\n"
            "        target: /host-etc\n        read_only: true\n"
        )
        findings = list(self.rule.check("a", data["services"]["a"], data, lines))
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_long_syntax_named_no_findings(self) -> None:
        findings = self._check("long_syntax_named")
        assert len(findings) == 0

    def test_etc_trailing_slash_normalized(self) -> None:
        """`/etc/` is `/etc`; writable, so CL-0025's."""
        assert self._check("mounts_etc_trailing_slash") == []

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

    def test_readwrite_localtime_still_fires_here(self) -> None:
        """Writable, it stays this rule's HIGH — it is not a host-root write.

        The exemption is read-only-scoped, so a writable timezone bind is still
        a finding. It is deliberately *not* CL-0025's: overwriting that one file
        changes what the host reads as local time, which is not host root. The
        split escalated it to CRITICAL for a while, which would have repeated
        issue #509's mistake one tier up.
        """
        for path in ("/etc/localtime", "/etc/timezone"):
            content = (
                "services:\n  a:\n    image: nginx\n    volumes:\n"
                f"      - {path}:{path}\n"
            )
            findings = self._check(content)
            assert len(findings) == 1, path
            assert findings[0].rule_id == "CL-0013"
            assert findings[0].severity == Severity.HIGH
            assert "timezone" in findings[0].message

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
    """/run and friends moved to CL-0001 when it grew the parent-directory case.

    Issue #513 added bare /run here because it holds both daemon sockets. That
    is a control-socket exposure, so CL-0001 owns it now — including
    mode-independence, which this rule never had.
    """

    def setup_method(self) -> None:
        self.rule = SensitiveMountRule()

    def _check(self, content: str, service: str = "a") -> list:
        data, lines = loads(content)
        return list(self.rule.check(service, data["services"][service], data, lines))

    def test_bare_run_no_longer_this_rule(self) -> None:
        content = (
            "services:\n  a:\n    image: nginx\n    volumes:\n      - /run:/hostrun\n"
        )
        assert self._check(content) == []

    def test_run_subpaths_no_longer_this_rule(self) -> None:
        content = (
            "services:\n  a:\n    image: nginx\n    volumes:\n"
            "      - /run/containerd:/x\n"
        )
        assert self._check(content) == []
