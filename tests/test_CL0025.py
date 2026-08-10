"""Tests for CL-0025: root-equivalent host path mounted writable.

The CRITICAL half of the host-path split. The mode is the whole distinction —
the same path read-only is CL-0013's disclosure finding — so most of what is
worth asserting here is that ``:ro`` in either Compose syntax moves the finding
rather than silencing it.
"""

from __future__ import annotations

from pathlib import Path

from compose_lint.models import Severity
from compose_lint.parser import load_compose, loads
from compose_lint.rules.CL0025_writable_host_root import WritableHostRootMountRule

FIXTURES = Path(__file__).parent / "compose_files"


class TestWritableHostRootMountRule:
    def setup_method(self) -> None:
        self.rule = WritableHostRootMountRule()

    def _check(self, service_name: str) -> list:
        data, lines = load_compose(FIXTURES / "insecure_sensitive_mount.yml")
        return list(
            self.rule.check(service_name, data["services"][service_name], data, lines)
        )

    def _inline(self, volume: str) -> list:
        data, lines = loads(
            f"services:\n  a:\n    image: x\n    volumes:\n      - {volume}\n"
        )
        return list(self.rule.check("a", data["services"]["a"], data, lines))

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0025"
        assert meta.severity.value == "critical"
        assert len(meta.references) > 0

    def test_detects_each_member_writable(self) -> None:
        for path in ("/etc", "/root", "/boot", "/var/lib/docker", "/proc", "/"):
            findings = self._inline(f'"{path}:/host"')
            assert len(findings) == 1, path
            assert findings[0].rule_id == "CL-0025"
            assert findings[0].severity == Severity.CRITICAL

    def test_readonly_is_not_this_rule(self) -> None:
        """`:ro` moves the finding to CL-0013, it does not silence it."""
        for path in ("/etc", "/root", "/boot", "/var/lib/docker", "/proc", "/"):
            assert self._inline(f'"{path}:/host:ro"') == [], path

    def test_subpaths_are_covered(self) -> None:
        findings = self._inline("/etc/cron.d:/host-cron")
        assert len(findings) == 1
        assert "/etc/cron.d" in findings[0].message

    def test_message_names_the_mechanism(self) -> None:
        """A CRITICAL should say what makes it one, not assert the tier."""
        assert "core_pattern" in self._inline("/proc:/hostproc")[0].message
        assert "authorized_keys" in self._inline("/root:/hostroot")[0].message

    def test_fixture_services(self) -> None:
        assert len(self._check("mounts_proc")) == 1
        assert len(self._check("mounts_boot")) == 1
        assert len(self._check("mounts_root")) == 1
        assert len(self._check("mounts_var_lib_docker")) == 1
        assert len(self._check("mounts_root_filesystem")) == 1
        assert len(self._check("mounts_multiple")) == 2
        assert len(self._check("mounts_etc_trailing_slash")) == 1

    def test_long_syntax_writable(self) -> None:
        for service in (
            "long_syntax_bind",
            "long_syntax_bind_no_type",
            "long_syntax_root_no_type",
        ):
            findings = self._check(service)
            assert len(findings) == 1, service
            assert findings[0].severity == Severity.CRITICAL

    def test_long_syntax_readonly_is_not_this_rule(self) -> None:
        data, lines = loads(
            "services:\n  a:\n    image: x\n    volumes:\n"
            "      - type: bind\n        source: /etc\n"
            "        target: /host-etc\n        read_only: true\n"
        )
        assert list(self.rule.check("a", data["services"]["a"], data, lines)) == []

    def test_unrelated_paths_and_named_volumes_ignored(self) -> None:
        assert self._check("safe_volume") == []
        assert self._check("no_volumes") == []
        assert self._check("long_syntax_named") == []

    def test_control_socket_dirs_are_not_this_rule(self) -> None:
        """/run and /var/run belong to CL-0001, which owns the socket."""
        assert self._check("mounts_var_run") == []
        assert self._inline("/run:/hostrun") == []

    def test_has_fix_guidance_and_references(self) -> None:
        finding = self._inline("/etc:/host-etc")[0]
        assert finding.fix is not None
        assert ":ro" in finding.fix
        assert len(finding.references) > 0
