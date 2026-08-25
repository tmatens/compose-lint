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


class TestVarLibAncestor:
    """A writable /var/lib mount reaches the container store below it.

    Measured on Docker 29.4.3: a container given only ``-v /var/lib``, at
    default capabilities and unprivileged, read a second container's private
    file and appended to it, and the victim saw the change live. /var/lib also
    covers /var/lib/containerd, which nothing else named -- on Docker 29 the
    snapshotter keeps its trees there, while each container's live rootfs stays
    reachable under /var/lib/docker as well.
    """

    def setup_method(self) -> None:
        self.rule = WritableHostRootMountRule()

    def _findings(self, mount: str) -> list:
        data, lines = loads(
            f"services:\n  svc:\n    image: nginx\n    volumes:\n      - {mount}\n"
        )
        return list(self.rule.check("svc", data["services"]["svc"], data, lines))

    def test_writable_var_lib_is_critical(self) -> None:
        findings = self._findings("/var/lib:/x")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_writable_containerd_store_is_critical(self) -> None:
        # Where the filesystems actually are on Docker 29; claimed by descent
        # from /var/lib.
        assert len(self._findings("/var/lib/containerd:/x")) == 1

    def test_the_docker_entry_still_supplies_its_own_message(self) -> None:
        # /var/lib/docker precedes /var/lib in the tuple, so the more specific
        # entry wins and the message does not degrade to the parent's.
        message = self._findings("/var/lib/docker:/x")[0].message
        assert "/var/lib/docker" in message

    def test_read_only_var_lib_is_not_this_rules(self) -> None:
        # Disclosure rather than takeover -- CL-0013 owns it, as for every
        # other root-equivalent path.
        assert self._findings("/var/lib:/x:ro") == []

    def test_a_sibling_of_the_store_is_not_claimed(self) -> None:
        # /var/log is not under /var/lib; the entry must not widen to /var.
        assert self._findings("/var/log:/x") == []


class TestExecTree:
    """A writable bind of the executable tree is host root (#737).

    Measured on two hosts (Docker 29.1.3 with AppArmor, 29.7.2 without),
    unprivileged and at default capabilities: every member accepted a write
    through an rw bind and refused it through an ro bind, and a 755 root-owned
    file planted through ``-v /usr`` was on the host afterwards. Root's PATH
    puts /usr/local/bin ahead of /usr/bin, so nothing need be overwritten.
    """

    def setup_method(self) -> None:
        self.rule = WritableHostRootMountRule()

    def _findings(self, mount: str) -> list:
        data, lines = loads(
            f"services:\n  svc:\n    image: x\n    volumes:\n      - {mount}\n"
        )
        return list(self.rule.check("svc", data["services"]["svc"], data, lines))

    def test_each_exec_dir_writable_is_critical(self) -> None:
        for path in (
            "/usr/bin",
            "/usr/sbin",
            "/usr/local/bin",
            "/usr/local/sbin",
            "/bin",
            "/sbin",
        ):
            findings = self._findings(f"{path}:/x")
            assert len(findings) == 1, path
            assert findings[0].severity is Severity.CRITICAL
            assert "PATH" in findings[0].message

    def test_a_single_binary_is_covered_by_descent(self) -> None:
        # The corpus idiom: /usr/bin/docker or /usr/bin/rclone bound rw so a
        # container can call the host's binary. Writable, it can replace it.
        assert len(self._findings("/usr/bin/docker:/usr/bin/docker")) == 1

    def test_bare_usr_is_critical_and_names_the_exec_tree(self) -> None:
        findings = self._findings("/usr:/hostusr")
        assert len(findings) == 1
        assert "/usr/local/bin" in findings[0].message

    def test_usr_application_data_is_not_claimed(self) -> None:
        # Bare /usr is an exact match, so what lies below it outside the exec
        # directories -- kernel headers, zoneinfo, an app's own share dir --
        # is not priced as host root.
        for path in ("/usr/src", "/usr/share/kubearmor", "/usr/share/zoneinfo"):
            assert self._findings(f"{path}:/x") == [], path

    def test_read_only_is_not_this_rule(self) -> None:
        for path in ("/usr", "/usr/bin", "/bin"):
            assert self._findings(f"{path}:/x:ro") == [], path

    def test_library_tree_is_deferred_not_claimed(self) -> None:
        # /usr/lib and /lib/modules carry a comparable grant but would sweep
        # site-packages and every VPN workload's modules bind; deferred to an
        # ADR rather than added by descent.
        assert self._findings("/usr/lib:/x") == []
        assert self._findings("/lib/modules:/lib/modules") == []


class TestFileBackedSecretsAndConfigs:
    """A host file handed over through ``secrets:``/``configs:`` ``file:``.

    Measured on Docker 29.7.2 / Compose 5.4.0: a non-swarm ``file:`` secret is
    a read-only bind of the host inode at ``/run/secrets/<name>``, a socket
    handed over that way is live (the daemon answered through it), and the
    write stays refused even with ``mode: 0666``. Neither channel was read by
    any mount rule (#736).
    """

    def setup_method(self) -> None:
        self.rule = WritableHostRootMountRule()

    def _findings(self, doc: str) -> list:
        data, lines = loads(doc)
        return list(self.rule.check("a", data["services"]["a"], data, lines))

    def test_channel_is_always_read_only_so_never_this_rule(self) -> None:
        # Even `mode: 0666` only sets permission bits; the bind stays ro
        # (measured). Disclosure is CL-0013's; takeover never arises here.
        for doc in (
            "services:\n  a:\n    image: x\n    secrets: [etc]\n"
            "secrets:\n  etc:\n    file: /etc\n",
            "services:\n  a:\n    image: x\n    configs:\n"
            "      - source: etc\n        target: /x\n        mode: 0666\n"
            "configs:\n  etc:\n    file: /etc\n",
        ):
            assert self._findings(doc) == []
