"""CL-0001: Docker socket mounted."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-1---do-not-expose-the-docker-daemon-socket-"
    "even-to-the-containers"
)

CIS_REF = (
    "CIS Docker Benchmark 5.32 — Ensure that the Docker socket is not "
    "mounted inside any containers"
)

# Control sockets for container runtimes. Mounting any of them grants the
# container root-equivalent control of the host's runtime; podman.sock and
# crio.sock are caught by neither CL-0001 (until now) nor CL-0013, and
# containerd.sock was only salvaged incidentally by CL-0013 (issue #279 R4).
# Matched as a substring so both short- and long-syntax mounts are covered.
_RUNTIME_SOCKETS: dict[str, str] = {
    "docker.sock": "Docker",
    "containerd.sock": "containerd",
    "crio.sock": "CRI-O",
    "podman.sock": "Podman",
}


@register_rule
class DockerSocketRule(BaseRule):
    """Detects container-runtime control-socket mounts in service volumes."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0001",
            name="Container runtime socket mounted",
            description=(
                "Mounting a container runtime's control socket (Docker, "
                "containerd, CRI-O, or Podman) gives a container full root-level "
                "access to the host's runtime. A compromised container can create "
                "privileged containers, access all other containers, and escape "
                "to the host. The OWASP/CIS grounding is written for the Docker "
                "socket; the exposure is identical for any runtime that exposes "
                "an unauthenticated control socket."
            ),
            severity=Severity.CRITICAL,
            references=[OWASP_REF, CIS_REF],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        volumes = service_config.get("volumes", [])
        if not isinstance(volumes, list):
            return

        for i, volume in enumerate(volumes):
            volume_str = str(volume)
            runtime = next(
                (
                    name
                    for marker, name in _RUNTIME_SOCKETS.items()
                    if marker in volume_str
                ),
                None,
            )
            if runtime is None:
                continue
            yield Finding(
                rule_id="CL-0001",
                severity=Severity.CRITICAL,
                service=service_name,
                message=(
                    f"{runtime} runtime socket mounted via '{volume_str}'. "
                    f"This gives the container full control over the {runtime} "
                    "runtime — equivalent to root on the host."
                ),
                line=lines.get(f"services.{service_name}.volumes[{i}]")
                or lines.get(f"services.{service_name}.volumes"),
                fix=(
                    "Don't mount the runtime socket. If a service genuinely "
                    "needs Docker API access, put a socket proxy (e.g. "
                    "tecnativa/docker-socket-proxy) in front of it, restricted "
                    "to the minimum endpoints; other runtimes have equivalent "
                    "rootless or proxied integrations."
                ),
                references=[OWASP_REF, CIS_REF],
            )
