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
        """Writable /etc, /proc, /boot, /root, /var/lib/docker are CL-0025's;
        a whole-root mount is CL-0001's. None is this rule's."""
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

    def test_readonly_whole_root_is_cl0001_not_this_rule(self) -> None:
        """A read-only whole-root mount exposes the daemon socket, so CL-0001
        owns it at CRITICAL. It used to fall here and be under-graded to HIGH."""
        assert self._check("mounts_root_filesystem_ro") == []

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

    def test_long_syntax_writable_binds_are_not_this_rule(self) -> None:
        """Both long-syntax forms parse; a writable /etc is CL-0025's and a
        whole-root mount is CL-0001's — neither is this rule's."""
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


class TestScopedAlternatives:
    """/dev/shm and /dev/hugepages get guidance a reader can act on.

    Both still fire — a host bind of either exposes segments belonging to the
    host and to every other container, which is the same reach `ipc: host`
    carries at HIGH under CL-0010. What the generic advice got wrong is the
    remedy: "copy them into the image at build time" is not something a
    workload wanting a bigger /dev/shm or a huge-page pool can do. Compose has
    a scoped alternative for each, so the finding names it.
    """

    def setup_method(self) -> None:
        self.rule = SensitiveMountRule()

    def _check(self, host_path: str, service: str = "a") -> list:
        content = (
            f"services:\n  {service}:\n    image: nginx\n    volumes:\n"
            f"      - {host_path}:/x\n"
        )
        data, lines = loads(content)
        return list(self.rule.check(service, data["services"][service], data, lines))

    def test_dev_shm_still_fires_at_high(self) -> None:
        findings = self._check("/dev/shm")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_dev_shm_names_shm_size_and_scoped_ipc(self) -> None:
        fix = self._check("/dev/shm")[0].fix
        assert "shm_size:" in fix
        assert "ipc: shareable" in fix
        assert "copy them into the image" not in fix

    def test_dev_hugepages_names_a_hugetlbfs_volume(self) -> None:
        fix = self._check("/dev/hugepages")[0].fix
        assert "hugetlbfs" in fix
        assert "copy them into the image" not in fix

    def test_guidance_survives_docker_path_normalisation(self) -> None:
        """Docker cleans a mount source before using it, so the alternatives
        must key off the normalised path rather than the string as written."""
        for spelling in ("/dev/shm/", "/dev/./shm", "//dev/shm", "/dev/foo/../shm"):
            assert "shm_size:" in self._check(spelling)[0].fix, spelling

    def test_other_dev_paths_keep_the_generic_remedy(self) -> None:
        """Only the two paths with a scoped alternative are special-cased."""
        fix = self._check("/dev/disk")[0].fix
        assert "copy them into the image" in fix
        assert "shm_size:" not in fix

    def test_every_finding_still_points_at_the_full_guide(self) -> None:
        for path in ("/dev/shm", "/dev/hugepages", "/dev/disk", "/sys"):
            assert self._check(path)[0].fix.endswith(
                "Full guide: compose-lint --explain CL-0013"
            ), path


class TestTildeShapeClaims:
    """``~`` sources are claimed by spelling, on every platform (#602).

    Whose home ``~`` names is a deploy-host fact, so the parser leaves the
    source as written and this rule matches the shape itself — the same depth
    rule as the ``/home`` tree: the whole home or a known credential directory
    is a disclosure, a project directory under it is not.
    """

    def _check(self, volume: str) -> list:
        from compose_lint.rules.CL0013_sensitive_mount import SensitiveMountRule

        data, lines = loads(
            f'services:\n  a:\n    image: x\n    volumes:\n      - "{volume}"\n'
        )
        return list(SensitiveMountRule().check("a", data["services"]["a"], data, lines))

    def test_whole_home_is_claimed(self) -> None:
        findings = self._check("~:/probe")
        assert len(findings) == 1
        assert "'~'" in findings[0].message

    def test_credential_dir_is_claimed_with_descent(self) -> None:
        for volume in ("~/.ssh:/keys", "~/.aws/config:/cfg", "~/.ssh/:/keys"):
            findings = self._check(volume)
            assert len(findings) == 1, volume
            assert findings[0].severity == Severity.HIGH

    def test_a_project_dir_under_home_is_not_claimed(self) -> None:
        # The commonest benign idiom must stay clean, exactly as it does for
        # a resolved /home/<user>/project path.
        assert self._check("~/data:/data") == []

    def test_tilde_user_is_never_claimed(self) -> None:
        # See the parser's ~user note: Compose never resolves another
        # account's home, so no claim can be honest.
        assert self._check("~someone/.ssh:/keys") == []


class TestExecTreeReadOnly:
    """A read-only bind of the executable tree is not a disclosure.

    Every file under /usr/bin is world-readable by design, so ``:ro`` grants
    nothing to read that the image could not ship -- the grant is write-only
    and CL-0025's. Same shape as the timezone exemption, one tier up: routing
    it here would report "discloses host configuration and credentials" about
    a directory holding neither.
    """

    def setup_method(self) -> None:
        self.rule = SensitiveMountRule()

    def _findings(self, mount: str) -> list:
        data, lines = loads(
            f"services:\n  svc:\n    image: x\n    volumes:\n      - {mount}\n"
        )
        return list(self.rule.check("svc", data["services"]["svc"], data, lines))

    def test_read_only_exec_tree_is_exempt(self) -> None:
        for path in ("/usr", "/usr/bin", "/usr/local/bin", "/bin", "/sbin"):
            assert self._findings(f"{path}:/x:ro") == [], path
        assert self._findings("/usr/bin/docker:/usr/bin/docker:ro") == []

    def test_writable_exec_tree_is_cl0025s_not_this_rule(self) -> None:
        assert self._findings("/usr/bin:/x") == []

    def test_read_only_etc_still_discloses(self) -> None:
        # The exemption is the exec tree only; the other members keep their
        # read-only disclosure finding here.
        assert len(self._findings("/etc:/x:ro")) == 1
