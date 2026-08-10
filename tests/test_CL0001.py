"""Tests for CL-0001: Docker socket mounted."""

from __future__ import annotations

from pathlib import Path

from compose_lint.models import Severity
from compose_lint.parser import load_compose, loads
from compose_lint.rules.CL0001_docker_socket import DockerSocketRule

FIXTURES = Path(__file__).parent / "compose_files"


class TestDockerSocketRule:
    """Tests for Docker socket detection."""

    def setup_method(self) -> None:
        self.rule = DockerSocketRule()

    def test_detects_socket_mount(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_socket.yml")
        findings = list(
            self.rule.check("traefik", data["services"]["traefik"], data, lines)
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0001"
        assert findings[0].severity.value == "critical"
        assert "docker.sock" in findings[0].message

    def test_detects_readonly_socket_mount(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_socket.yml")
        findings = list(
            self.rule.check("portainer", data["services"]["portainer"], data, lines)
        )
        assert len(findings) == 1
        assert "docker.sock" in findings[0].message

    def _check_socket(self, mount: str) -> list:
        data, lines = loads(
            f"services:\n  svc:\n    image: nginx\n    volumes:\n      - {mount}\n"
        )
        return list(self.rule.check("svc", data["services"]["svc"], data, lines))

    def test_detects_podman_socket(self) -> None:
        # podman.sock was caught by neither CL-0001 nor CL-0013 (issue #279 R4).
        findings = self._check_socket("/run/podman/podman.sock:/run/podman/podman.sock")
        assert len(findings) == 1
        assert "Podman" in findings[0].message

    def test_detects_containerd_socket(self) -> None:
        findings = self._check_socket(
            "/run/containerd/containerd.sock:/run/containerd/containerd.sock"
        )
        assert len(findings) == 1
        assert "containerd" in findings[0].message

    def test_detects_crio_socket(self) -> None:
        findings = self._check_socket("/var/run/crio/crio.sock:/var/run/crio/crio.sock")
        assert len(findings) == 1
        assert "CRI-O" in findings[0].message

    def test_clean_service_no_findings(self) -> None:
        data, lines = load_compose(FIXTURES / "valid_basic.yml")
        findings = list(self.rule.check("web", data["services"]["web"], data, lines))
        assert len(findings) == 0

    def test_no_volumes_no_findings(self) -> None:
        findings = list(self.rule.check("app", {"image": "nginx"}, {}, {}))
        assert len(findings) == 0

    def test_has_fix_guidance(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_socket.yml")
        findings = list(
            self.rule.check("traefik", data["services"]["traefik"], data, lines)
        )
        assert findings[0].fix is not None
        assert "socket proxy" in findings[0].fix.lower()

    def test_has_references(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_socket.yml")
        findings = list(
            self.rule.check("traefik", data["services"]["traefik"], data, lines)
        )
        assert len(findings[0].references) > 0
        assert "owasp" in findings[0].references[0].lower()

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0001"
        assert meta.severity.value == "critical"
        assert len(meta.references) > 0


class TestSocketDirectories:
    """Mounting a directory that *holds* a socket exposes it too.

    The matcher's blind spot before the broadening: `/run` hands over both
    daemon sockets without naming either. The direction of the match is the
    thing worth pinning — a mount counts when it is, or is an ancestor of, a
    socket-holding directory. Matching descendants instead reported `/run/myapp`
    as exposing the daemon and missed `/var`, which really does contain
    `/var/run/docker.sock`.
    """

    def setup_method(self) -> None:
        self.rule = DockerSocketRule()

    def _check(self, volume: str) -> list:
        data, lines = loads(
            f"services:\n  a:\n    image: x\n    volumes:\n      - {volume}\n"
        )
        return list(self.rule.check("a", data["services"]["a"], data, lines))

    def test_socket_holding_directories_fire(self) -> None:
        for path in ("/run", "/var/run", "/run/containerd", "/run/systemd"):
            findings = self._check(f"{path}:/x")
            assert len(findings) == 1, path
            assert findings[0].severity == Severity.CRITICAL

    def test_ancestor_of_a_socket_directory_fires(self) -> None:
        """/var holds /var/run/docker.sock — previously missed entirely."""
        findings = self._check("/var:/x")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_sibling_runtime_dirs_do_not_fire(self) -> None:
        """Under /run, but holding no socket — a false CRITICAL if matched."""
        for path in ("/run/myapp", "/run/user/1000", "/run/dbus"):
            assert self._check(f"{path}:/x") == [], path

    def test_systemd_private_socket_named_directly(self) -> None:
        """It is not a *.sock, so the name match needs its own marker."""
        findings = self._check("/run/systemd/private:/x")
        assert len(findings) == 1
        assert "systemd" in findings[0].message

    def test_mode_independent(self) -> None:
        """`:ro` applies to the socket file, not to the API behind it."""
        for volume in ("/run:/x", "/run:/x:ro", "/var/run/docker.sock:/x:ro"):
            findings = self._check(volume)
            assert len(findings) == 1, volume
            assert findings[0].severity == Severity.CRITICAL

    def test_whole_root_mount_fires_in_either_mode(self) -> None:
        """`/` holds the control sockets, so it is CRITICAL read-only too.

        Read-only `/` used to fall to CL-0013 HIGH: CL-0025 declines a read-only
        mount and CL-0001 deferred the whole-root case to it, so the socket the
        mount exposes went a tier under-graded. CL-0001 now owns `/` in both
        modes.
        """
        for volume in ("/:/host", "/:/host:ro"):
            findings = self._check(volume)
            assert len(findings) == 1, volume
            assert findings[0].severity == Severity.CRITICAL
            assert "control sockets" in findings[0].message


class TestRootSpellingNormalisation:
    """A whole-root mount is root however the path is spelled.

    ``/.``, ``/..``, ``//`` and ``/./`` all name the host root, and Docker
    cleans the mount source before using it — verified: ``- /.:/host:ro``
    mounts the real filesystem, live ``docker.sock`` included. Matching the
    string as written missed every spelling but the bare ``/``, so a whole-root
    bind was reported as a clean pass. ``/run/.`` is the same defect one level
    down, and ``/etc/..`` under-graded to CL-0013's HIGH.
    """

    def setup_method(self) -> None:
        self.rule = DockerSocketRule()

    def _check(self, mount: str) -> list:
        data, lines = loads(
            f"services:\n  svc:\n    image: nginx\n    volumes:\n      - {mount}\n"
        )
        return list(self.rule.check("svc", data["services"]["svc"], data, lines))

    def test_every_root_spelling_is_critical(self) -> None:
        for spelling in ("/", "//", "/.", "/..", "/./", "/etc/.."):
            findings = self._check(f"{spelling}:/host:ro")
            assert len(findings) == 1, f"{spelling!r} produced {findings}"
            assert findings[0].severity is Severity.CRITICAL, spelling

    def test_dotted_socket_directory_is_still_matched(self) -> None:
        findings = self._check("/run/.:/hostrun")
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL

    def test_normalisation_does_not_resurrect_the_named_volume_bug(self) -> None:
        # An empty host path must not normalise to root: that turned every
        # named volume into a CRITICAL finding once already.
        assert self._check("myvol:/data") == []

    def test_descendants_of_a_socket_dir_stay_unflagged(self) -> None:
        # Ancestry, not descent — /run/myapp holds no socket.
        assert self._check("/run/myapp:/x") == []
        assert self._check("/run/./myapp:/x") == []


class TestHostSideMatching:
    """The socket name is matched on the host side of the mount only.

    Matching the whole entry reported `- /tmp/fake:/var/run/docker.sock` as a
    socket mount. That is false — the container path is where a socket would
    land, not where it comes from — and it landed at CRITICAL, the tier meant
    for "fix this first". The catch it cost was a named volume mounted *at* a
    socket path, which shadows that path with an empty volume and grants
    nothing.
    """

    def setup_method(self) -> None:
        self.rule = DockerSocketRule()

    def _check(self, mount: str) -> list:
        data, lines = loads(
            f"services:\n  svc:\n    image: nginx\n    volumes:\n      - {mount}\n"
        )
        return list(self.rule.check("svc", data["services"]["svc"], data, lines))

    def test_container_side_socket_path_is_not_a_finding(self) -> None:
        assert self._check("/tmp/fake:/var/run/docker.sock") == []
        assert self._check("myvol:/var/run/docker.sock") == []

    def test_host_side_socket_still_fires_anywhere_on_disk(self) -> None:
        for host in (
            "/var/run/docker.sock",
            "/opt/custom/docker.sock",
            "/run/containerd/containerd.sock",
        ):
            findings = self._check(f"{host}:/x")
            assert len(findings) == 1, host
            assert findings[0].severity is Severity.CRITICAL

    def test_long_syntax_uses_source_not_target(self) -> None:
        data, lines = loads(
            "services:\n  svc:\n    image: nginx\n    volumes:\n"
            "      - type: bind\n        source: /tmp/f\n"
            "        target: /var/run/docker.sock\n"
        )
        assert list(self.rule.check("svc", data["services"]["svc"], data, lines)) == []
