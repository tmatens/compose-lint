"""CL-0001: Docker socket mounted."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule
from compose_lint.rules._mounts import iter_bind_mounts

if TYPE_CHECKING:
    from collections.abc import Iterator

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-1-do-not-expose-the-docker-daemon-socket-"
    "even-to-the-containers"
)

CIS_REF = (
    "CIS Docker Benchmark 5.32 — Ensure that the Docker socket is not "
    "mounted inside any containers"
)

# Control sockets a mount can name directly. Matched as a substring so both
# short- and long-syntax mounts are covered.
#
# containerd.sock is core Docker coverage, not multi-engine support: Docker
# Engine *is* containerd since 18.09, so a plain Docker host always runs it —
# and it is a lower-level API with no authorization-plugin layer above it.
# podman.sock and crio.sock belong to other ecosystems but stay flagged, because
# the rule is about what a compose file exposes into a container, not about
# which engine started it (ADR-020).
_RUNTIME_SOCKETS: dict[str, str] = {
    "docker.sock": "Docker",
    "containerd.sock": "containerd",
    "crio.sock": "CRI-O",
    "podman.sock": "Podman",
}

# Directories that *contain* a control socket on a stock Docker host. Mounting
# one hands over the socket inside it just as surely as naming the socket, and
# the parent-directory case was CL-0001's blind spot: /run holds both
# docker.sock and containerd.sock (with /var/run a symlink to it), and
# /run/systemd/private authenticates a container straight into
# StartTransientUnit — host command execution.
#
# Ordered specific-first so the more precise entry supplies the message.
_SOCKET_DIRS: dict[str, str] = {
    "/run/containerd": "the containerd control API, which sits below the "
    "Docker daemon's authorization layer",
    "/run/systemd": "systemd's private socket — a container can authenticate to "
    "it and drive StartTransientUnit, executing commands on the host",
    "/var/run": "the Docker and containerd control sockets",
    "/run": "the Docker and containerd control sockets",
}


def _matched_socket_dir(host_path: str) -> str | None:
    """Return the socket-holding directory ``host_path`` is at or under."""
    normalized = host_path.rstrip("/")
    if not normalized:
        return None  # a whole-root mount is CL-0025's finding
    for candidate in _SOCKET_DIRS:
        if normalized == candidate or normalized.startswith(candidate + "/"):
            return candidate
    return None


@register_rule
class DockerSocketRule(BaseRule):
    """Detects container-runtime control-socket mounts in service volumes."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0001",
            name="Host control socket exposed",
            description=(
                "Mounting a host control socket — a container runtime's, or "
                "systemd's — gives a container root-equivalent control of the "
                "host, as does mounting a directory that contains one. A "
                "read-only mount grants the same access: the flag applies to "
                "the socket file, not to the API behind it."
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

        # Host path per index, so the socket-name match (a substring over the
        # whole entry, which also catches a named volume mounted *at* a socket
        # path) and the parent-directory match can share one pass.
        host_paths = {
            mount.position: mount.host_path
            for mount in iter_bind_mounts(service_name, service_config, lines)
        }

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
            if runtime is not None:
                message = (
                    f"{runtime} runtime socket mounted via '{volume_str}'. "
                    f"This gives the container full control over the {runtime} "
                    "runtime — equivalent to root on the host."
                )
            else:
                # The parent-directory case: no socket named, but one is inside.
                # Mode-independent — ':ro' applies to the socket file, not to
                # the API behind it.
                directory = _matched_socket_dir(host_paths.get(i, ""))
                if directory is None:
                    continue
                message = (
                    f"Service mounts '{volume_str}', which contains "
                    f"{_SOCKET_DIRS[directory]}. Exposing the directory "
                    "exposes the socket inside it."
                )
            yield Finding(
                rule_id="CL-0001",
                severity=Severity.CRITICAL,
                service=service_name,
                message=message,
                line=lines.get(f"services.{service_name}.volumes[{i}]")
                or lines.get(f"services.{service_name}.volumes"),
                fix=(
                    "Don't mount the runtime socket or a directory holding "
                    "one. If a service genuinely needs Docker API access, put "
                    "a socket proxy (e.g. tecnativa/docker-socket-proxy) in "
                    "front of it, restricted to the minimum endpoints; other "
                    "runtimes have equivalent rootless or proxied "
                    "integrations. Mounting read-only does not help.\n"
                    "Full guide: compose-lint --explain CL-0001"
                ),
                references=[OWASP_REF, CIS_REF],
            )
