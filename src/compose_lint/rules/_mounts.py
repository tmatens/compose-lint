"""Shared bind-mount extraction for the host-path rules.

Three rules read the same ``volumes:`` list and differ only in which host paths
they claim and how the mount mode changes the answer: CL-0001 (host control
sockets, mode-independent), CL-0025 (root-equivalent paths, writable only), and
CL-0013 (everything else, plus read-only mounts of CL-0025's paths). Parsing
both Compose syntaxes once keeps them from drifting — the long-syntax handling
in particular has already been a source of missed mounts.
"""

from __future__ import annotations

import posixpath
import re
from typing import TYPE_CHECKING, Any, NamedTuple

from compose_lint.rules._bool import as_bool

if TYPE_CHECKING:
    from collections.abc import Iterator

# Matches host:container or host:container:mode in short syntax. The host group
# allows a bare "/" (root mount) by using `*` instead of `+`.
_SHORT_VOLUME_RE = re.compile(
    r"^(?P<host>/[^:]*):(?P<container>[^:]+)(?::(?P<mode>[^:]+))?"
)


# `- /etc/localtime:/etc/localtime:ro` (and /etc/timezone) is a near-universal
# timezone-config pattern. Read-only it exposes only the host's UTC offset;
# *writable* it lets a container change the host's clock display — annoying, but
# not host root, so these two paths are not root-equivalent in either mode even
# though they sit under /etc. Flagging the read-only form HIGH failed the default
# gate on otherwise-hardened files (issue #509); grading the writable form
# CRITICAL would repeat that mistake one tier up.
TIMEZONE_FILES = frozenset({"/etc/localtime", "/etc/timezone"})


class BindMount(NamedTuple):
    """One bind mount as written, with its position in ``volumes:``.

    ``position`` is the entry's index in the original list, not a count of the
    binds yielded — non-bind entries (named volumes) are skipped, so the two
    diverge and a caller correlating back to ``volumes[i]`` needs the real one.
    """

    position: int
    host_path: str
    read_only: bool
    line: int | None


def _extract_short(volume: str) -> tuple[str, bool] | None:
    m = _SHORT_VOLUME_RE.match(volume)
    if not m:
        return None
    mode = m.group("mode")
    read_only = bool(mode) and "ro" in (part.strip() for part in mode.split(","))
    return m.group("host"), read_only


def iter_bind_mounts(
    service_name: str,
    service_config: dict[str, Any],
    lines: dict[str, int],
) -> Iterator[BindMount]:
    """Yield every host bind mount a service declares, in either syntax."""
    volumes = service_config.get("volumes", [])
    if not isinstance(volumes, list):
        return

    for i, volume in enumerate(volumes):
        if isinstance(volume, str):
            short = _extract_short(volume)
            if short is None:
                continue
            host_path, read_only = short
        elif isinstance(volume, dict):
            # Long syntax. Treat as a bind when type == "bind" OR when source
            # is an absolute path — Compose infers bind from an absolute source
            # even with type omitted.
            source = volume.get("source")
            vtype = volume.get("type")
            if not (
                isinstance(source, str) and (vtype == "bind" or source.startswith("/"))
            ):
                continue
            host_path = source
            read_only = as_bool(volume.get("read_only")) is True
        else:
            continue

        line = lines.get(f"services.{service_name}.volumes[{i}]") or lines.get(
            f"services.{service_name}.volumes"
        )
        yield BindMount(i, host_path, read_only, line)


def normalize_host_path(host_path: str) -> str:
    """Resolve ``.`` and ``..`` segments; drop any trailing slash.

    Docker cleans a mount source this way before using it, so ``/.``, ``/..``,
    ``//`` and ``/etc/..`` all name the host **root**, and ``/run/.`` names
    ``/run``. Matching the string as written missed every one of them: a
    whole-root bind spelled ``/.`` mounted the host filesystem — the live
    ``docker.sock`` included — and was reported as a clean pass.

    Returns ``"/"`` for any spelling of the root and ``""`` for an empty path.
    The two must not collapse together: an empty host path means a named
    volume, which is not a bind mount at all, and normalising it to root is
    how every named volume once became a CRITICAL finding.
    """
    if not host_path:
        return ""
    normalized = posixpath.normpath(host_path)
    # normpath keeps exactly two leading slashes (POSIX leaves them
    # implementation-defined); Docker collapses them.
    if normalized.startswith("//"):
        normalized = "/" + normalized.lstrip("/")
    return normalized


def match_prefix(host_path: str, paths: tuple[str, ...]) -> str | None:
    """Return the entry in ``paths`` that ``host_path`` is at or under.

    Returns ``"/"`` for a root mount in any spelling. ``paths`` is matched in
    order, so callers list more specific entries before the prefixes that
    contain them.
    """
    normalized = normalize_host_path(host_path)
    if not normalized:
        return None
    if normalized == "/":
        return "/" if "/" in paths else None
    for candidate in paths:
        if candidate == "/":
            continue
        if normalized == candidate or normalized.startswith(candidate + "/"):
            return candidate
    return None
