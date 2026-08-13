"""CL-0001: Docker socket mounted."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint._scalar import as_scalar_text
from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule
from compose_lint.rules._mounts import iter_bind_mounts, normalize_host_path

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
    # systemd's private socket is not named "*.sock"; a container that mounts it
    # can authenticate and drive StartTransientUnit — host command execution.
    "systemd/private": "systemd",
}

# Directories that *contain* a control socket on a stock Docker host. Mounting
# one hands over the socket inside it just as surely as naming the socket, and
# the parent-directory case was CL-0001's blind spot: /run holds both
# docker.sock and containerd.sock (with /var/run a symlink to it), and
# /run/systemd/private authenticates a container straight into
# StartTransientUnit — host command execution.
#
# Ordered specific-first so the more precise entry supplies the message. "/" is
# last: a whole-root mount contains every socket below, and is owned here rather
# than by CL-0025 because it exposes the daemon socket in *either* mode, not
# only when writable (CL-0025 covers writable mounts only).
_SOCKET_DIRS: dict[str, str] = {
    "/run/containerd": "the containerd control API, which sits below the "
    "Docker daemon's authorization layer",
    "/run/systemd": "systemd's private socket — a container can authenticate to "
    "it and drive StartTransientUnit, executing commands on the host",
    "/var/run": "the Docker and containerd control sockets",
    "/run": "the Docker and containerd control sockets",
    "/": "the Docker and containerd control sockets",
}


def _matched_socket_dir(host_path: str) -> str | None:
    """Return the socket-holding directory this mount exposes, if any.

    A mount exposes a socket when it **is** a socket-holding directory or an
    **ancestor** of one. The direction matters and the first draft had it
    backwards, matching descendants instead: that reported `/run/myapp` and
    `/run/user/1000` as exposing the daemon socket, which is false — they are
    under /run but hold no socket — while missing `/var`, which genuinely
    contains /var/run/docker.sock.

    A whole-root mount is the widest ancestor of all: it contains the sockets in
    either mode, so it matches here rather than falling to CL-0025 (writable
    only) or CL-0013 (HIGH disclosure), both of which would under-grade it.

    A descendant that *is* a socket is still caught, by the socket-name
    substring match in the caller.
    """
    normalized = normalize_host_path(host_path)
    if not normalized:
        return None  # not a bind mount (e.g. a named volume) — no host path
    if normalized == "/":
        return "/" if "/" in _SOCKET_DIRS else None  # a whole-root mount
    for candidate in _SOCKET_DIRS:
        if candidate == "/":
            continue
        if normalized == candidate or candidate.startswith(normalized + "/"):
            return candidate
    return None


def claims_host_path(host_path: str) -> bool:
    """Whether CL-0001 owns this mount — by socket directory or socket name.

    Exported so CL-0013 can claim what is left under ``/run`` and ``/var/run``
    without guessing at the boundary. CL-0001 matches a socket directory or an
    **ancestor** of one, so a strict descendant like ``/run/dbus`` is not its:
    that path holds no control socket. Before the runtime directories moved
    here, CL-0013 matched them by descent and covered those descendants; the
    move left them claimed by neither rule, which is the gap this predicate
    closes rather than papers over.
    """
    if _matched_socket_dir(host_path) is not None:
        return True
    return any(marker in host_path for marker in _RUNTIME_SOCKETS)


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

        # Host path per index, so the socket-name match and the
        # parent-directory match can share one pass. Keyed on the entry's real
        # position in volumes:, because the iterator skips named volumes and
        # enumerating it instead would be off-by-N.
        host_paths = {
            mount.position: mount.host_path
            for mount in iter_bind_mounts(
                service_name, service_config, lines, global_config
            )
        }

        for i, volume in enumerate(volumes):
            # Only for the message; the match below uses the resolved host path.
            # Long syntax is a mapping, and `str()` on it serialized whatever it
            # contained — which YAML aliases make exponential. The host path is
            # what the message is about, so it is the better fallback anyway.
            volume_str = as_scalar_text(volume) or host_paths.get(i, "")
            # Match the *host* side only. Matching the whole entry reported
            # `- /tmp/fake:/var/run/docker.sock` as a socket mount, which is
            # false: the container path is where the socket lands, not where it
            # comes from. The catch that cost was a named volume mounted *at* a
            # socket path — which shadows the path with an empty volume and
            # grants nothing, so it was never a risk. A host socket is always
            # the host side in short syntax and `source:` in long syntax, so
            # nothing real is missed.
            host_path = host_paths.get(i, "")
            runtime = next(
                (
                    name
                    for marker, name in _RUNTIME_SOCKETS.items()
                    if marker in host_path
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
                directory = _matched_socket_dir(host_path)
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
