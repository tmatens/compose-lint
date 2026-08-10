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
        for path in ("/etc", "/root", "/boot", "/var/lib/docker", "/proc"):
            findings = self._inline(f'"{path}:/host"')
            assert len(findings) == 1, path
            assert findings[0].rule_id == "CL-0025"
            assert findings[0].severity == Severity.CRITICAL

    def test_readonly_is_not_this_rule(self) -> None:
        """`:ro` moves the finding to CL-0013, it does not silence it."""
        for path in ("/etc", "/root", "/boot", "/var/lib/docker", "/proc"):
            assert self._inline(f'"{path}:/host:ro"') == [], path

    def test_whole_root_is_cl0001_not_this_rule(self) -> None:
        """`/` holds the daemon socket, so CL-0001 owns it in both modes — it is
        not this rule's, in either mode."""
        assert self._inline('"/:/host"') == []
        assert self._inline('"/:/host:ro"') == []

    def test_timezone_files_are_not_root_equivalent(self) -> None:
        """Under /etc, but writing one changes a clock, not the host's root.

        Grading these CRITICAL would repeat issue #509 one tier up — the
        near-universal timezone bind is often written without `:ro`.
        """
        for path in ("/etc/localtime", "/etc/timezone"):
            assert self._inline(f"{path}:{path}") == [], path
            assert self._inline(f"{path}:{path}:ro") == [], path

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
        # mounts_root_filesystem ("/") is CL-0001's now — see test_CL0001.py.
        assert self._check("mounts_root_filesystem") == []
        assert len(self._check("mounts_multiple")) == 2
        assert len(self._check("mounts_etc_trailing_slash")) == 1

    def test_long_syntax_writable(self) -> None:
        # long_syntax_root_no_type ("/") is CL-0001's — see test_CL0001.py.
        for service in ("long_syntax_bind", "long_syntax_bind_no_type"):
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


class TestPathNormalisation:
    """Timezone and root exemptions must survive an unusual path spelling.

    ``/etc/./localtime`` is the timezone file; before the host path was
    normalised it slipped the exemption and a writable timezone bind came back
    as CRITICAL — issue #509 one tier up, which this rule exists not to repeat.
    """

    def setup_method(self) -> None:
        self.rule = WritableHostRootMountRule()

    def _inline(self, volume: str) -> list:
        data, lines = loads(
            f"services:\n  a:\n    image: x\n    volumes:\n      - {volume}\n"
        )
        return list(self.rule.check("a", data["services"]["a"], data, lines))

    def test_dotted_timezone_path_is_still_exempt(self) -> None:
        assert self._inline("/etc/./localtime:/etc/localtime") == []
        assert self._inline("/etc/timezone/.:/etc/timezone") == []

    def test_whole_root_is_cl0001_in_every_spelling(self) -> None:
        for spelling in ("/", "//", "/.", "/..", "/etc/.."):
            assert self._inline(f"{spelling}:/host") == [], spelling

    def test_dotted_subpath_still_matches_its_prefix(self) -> None:
        findings = self._inline("/etc/./cron.d:/x")
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL
