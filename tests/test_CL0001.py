"""Tests for CL-0001: Docker socket mounted."""

from __future__ import annotations

from pathlib import Path

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
