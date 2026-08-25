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

from compose_lint._scalar import as_scalar_text
from compose_lint.rules._bool import as_bool

if TYPE_CHECKING:
    from collections.abc import Iterator

# Matches host:container or host:container:mode in short syntax. The host group
# allows a bare "/" (root mount) by using `*` instead of `+`. A leading ``~``
# is a host path too — Compose expands it at deploy time — and became visible
# here when the parser stopped expanding it against the linting user (#602);
# a named volume cannot begin with ``~``, so the shapes stay disjoint.
_SHORT_VOLUME_RE = re.compile(
    r"^(?P<host>(?:/|~)[^:]*):(?P<container>[^:]+)(?::(?P<mode>[^:]+))?"
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
    """One bind mount as written, with its position in the list it came from.

    ``position`` is the entry's index in the original list, not a count of the
    binds yielded — non-bind entries (named volumes) are skipped, so the two
    diverge and a caller correlating back to ``volumes[i]`` needs the real one.

    ``origin`` names that list: ``volumes`` (the default), or ``secrets`` /
    ``configs`` for a host file handed over through those channels (see
    :func:`file_backed_entries`). A caller that reads the entry back for a
    message must index the list ``origin`` names, not ``volumes:``.
    """

    position: int
    host_path: str
    read_only: bool
    line: int | None
    origin: str = "volumes"


# The two Compose channels that bind a host *file* into a container without
# going through ``volumes:``.
FILE_CHANNELS: tuple[str, ...] = ("secrets", "configs")


def _extract_short(volume: str) -> tuple[str, bool] | None:
    m = _SHORT_VOLUME_RE.match(volume)
    if not m:
        return None
    mode = m.group("mode")
    read_only = bool(mode) and "ro" in (part.strip() for part in mode.split(","))
    return m.group("host"), read_only


def _opt_flags(driver_opts: dict[str, Any]) -> set[str]:
    """The comma-separated flags in a volume's ``o:`` driver option."""
    text = as_scalar_text(driver_opts.get("o", "")) or ""
    return {part.strip().lower() for part in text.split(",")}


def _is_local_bind(driver_opts: dict[str, Any]) -> bool:
    """Whether these ``driver_opts`` describe a host bind mount.

    Keyed off the kernel-observable shape — ``type: none`` with an absolute
    ``device`` path under the local driver — rather than the ``o:`` string
    spelling ``bind`` exactly. ``o: rbind`` is a *recursive* bind: the kernel
    mounts the host path just the same, and `docker compose config` passes it
    through unchanged, but ``"bind" in flags`` was False so no host path was
    visible to any rule and a ``device: /var/run`` volume linted clean.

    ``type: none`` + a device path is what makes it a bind; the ``o:`` flags
    then only modify *how*. The whole ``r``-prefixed family is accepted for the
    same reason, and the flags are still read for ``ro``.
    """
    device = driver_opts.get("device")
    if not isinstance(device, str) or not device.startswith("/"):
        return False
    fs_type = driver_opts.get("type")
    if isinstance(fs_type, str) and fs_type.strip().lower() == "none":
        return True
    # `type:` omitted: fall back to the flag family, which is the only other
    # signal that the local driver should treat `device` as a path to bind.
    return any(flag in {"bind", "rbind"} for flag in _opt_flags(driver_opts))


def bind_backed_volumes(global_config: dict[str, Any]) -> dict[str, tuple[str, bool]]:
    """Named volumes that are host bind mounts under another name.

    ``driver_opts: {type: none, device: <host path>, o: bind}`` is the standard
    idiom for pinning a bind mount's options, and Compose honours it — verified
    on Docker 29.4.3, where a container read host-side content through such a
    volume. The host path lives in the **top-level** ``volumes:`` block, not in
    the service entry, so a rule reading only ``services.*.volumes`` sees a
    plain named volume and finds no host path at all. That is how
    ``device: /var/run/docker.sock`` reached a container at a clean pass.

    Returns ``{volume name: (host path, read_only)}``. A volume declared
    ``external: true`` is skipped: its host path is not in this file, and
    guessing one would invent a finding.
    """
    found: dict[str, tuple[str, bool]] = {}
    volumes = global_config.get("volumes")
    if not isinstance(volumes, dict):
        return found
    for name, spec in volumes.items():
        if not isinstance(spec, dict) or as_bool(spec.get("external")) is True:
            continue
        driver = spec.get("driver")
        if driver is not None and driver != "local":
            # Only the local driver reads `device` as a host path. Under a
            # third-party driver the same key names something else entirely --
            # an EBS volume, a Ceph image -- so treating it as a bind would
            # invent a host path the way an `external: true` volume would.
            continue
        driver_opts = spec.get("driver_opts")
        if not isinstance(driver_opts, dict):
            continue
        device = driver_opts.get("device")
        if isinstance(device, str) and device and _is_local_bind(driver_opts):
            found[str(name)] = (device, "ro" in _opt_flags(driver_opts))
    return found


def file_backed_entries(global_config: dict[str, Any], channel: str) -> dict[str, str]:
    """Top-level ``secrets:`` or ``configs:`` entries that bind a host file.

    A non-swarm ``secrets: name: file: <path>`` (and the same for ``configs:``)
    is a **bind mount** of that host file, read-only, at ``/run/secrets/<name>``
    (or ``/<name>`` for a config). Measured on Docker 29.7.2 / Compose 5.4.0:
    the container saw the host inode, `mountinfo` showed the host path with
    ``ro``, a write was refused even with ``mode: 0666``, and a socket handed
    over this way was live — ``docker -H unix:///run/secrets/<name> version``
    answered. So ``file: /var/run/docker.sock`` is the socket mount CL-0001
    exists to catch, and ``file: /etc/shadow`` is CL-0013's read-only
    disclosure — yet neither channel was read by any mount rule (#736).

    Only an absolute or ``~`` path is returned. A project-relative ``file:``
    (``./secrets/db_password``) is the pattern CL-0020 recommends, and it is
    not a host path any rule grades — the same line ``volumes:`` draws for a
    relative short-syntax bind. ``external: true`` entries have no path in this
    file, and ``environment:``-sourced ones are not files at all.

    Returns ``{entry name: host path}``.
    """
    found: dict[str, str] = {}
    block = global_config.get(channel)
    if not isinstance(block, dict):
        return found
    for name, spec in block.items():
        if not isinstance(spec, dict) or as_bool(spec.get("external")) is True:
            continue
        path = spec.get("file")
        if isinstance(path, str) and path.startswith(("/", "~")):
            found[str(name)] = path
    return found


def iter_bind_mounts(
    service_name: str,
    service_config: dict[str, Any],
    lines: dict[str, int],
    global_config: dict[str, Any] | None = None,
) -> Iterator[BindMount]:
    """Yield every host bind mount a service declares, in either syntax.

    ``global_config`` supplies the top-level ``volumes:`` block, without which
    a bind-backed named volume (see :func:`bind_backed_volumes`) is invisible.
    """
    volumes = service_config.get("volumes", [])
    if not isinstance(volumes, list):
        return
    named_binds = bind_backed_volumes(global_config or {})

    for i, volume in enumerate(volumes):
        if isinstance(volume, str):
            short = _extract_short(volume)
            if short is None:
                # Not a host path — but it may name a bind-backed volume,
                # which is a host path one level of indirection away.
                name, sep, rest = volume.partition(":")
                if not sep or name not in named_binds:
                    continue
                host_path, volume_read_only = named_binds[name]
                _, _, mode = rest.partition(":")
                read_only = volume_read_only or "ro" in (
                    part.strip() for part in mode.split(",")
                )
            else:
                host_path, read_only = short
        elif isinstance(volume, dict):
            # Long syntax. Treat as a bind when type == "bind" OR when source
            # is an absolute path — Compose infers bind from an absolute source
            # even with type omitted.
            source = volume.get("source")
            vtype = volume.get("type")
            if not isinstance(source, str):
                continue
            if vtype == "bind" or source.startswith(("/", "~")):
                host_path = source
                read_only = as_bool(volume.get("read_only")) is True
            elif source in named_binds:
                host_path, volume_read_only = named_binds[source]
                read_only = volume_read_only or as_bool(volume.get("read_only")) is True
            else:
                continue
        else:
            continue

        line = lines.get(f"services.{service_name}.volumes[{i}]") or lines.get(
            f"services.{service_name}.volumes"
        )
        yield BindMount(i, host_path, read_only, line)

    # A host file handed over through secrets:/configs: is a read-only bind of
    # that file, whatever mode: says -- see file_backed_entries.
    for channel in FILE_CHANNELS:
        refs = service_config.get(channel)
        if not isinstance(refs, list):
            continue
        entries = file_backed_entries(global_config or {}, channel)
        if not entries:
            continue
        for i, ref in enumerate(refs):
            if isinstance(ref, str):
                name = ref
            elif isinstance(ref, dict) and isinstance(ref.get("source"), str):
                name = ref["source"]
            else:
                continue
            if name not in entries:
                continue
            line = lines.get(f"services.{service_name}.{channel}[{i}]") or lines.get(
                f"services.{service_name}.{channel}"
            )
            yield BindMount(i, entries[name], True, line, channel)


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


def match_exact(host_path: str, paths: tuple[str, ...]) -> str | None:
    """Return the entry in ``paths`` that ``host_path`` names exactly.

    For a member whose grant comes from what it *contains* rather than from
    what lies below it, where :func:`match_prefix` would draw in the wrong
    set. ``/var/lib`` is root-equivalent because ``/var/lib/docker`` and
    ``/var/lib/containerd`` sit inside it — but ``/var/lib/mysql`` contains
    neither, so matching it by descent priced a database's own state
    directory as host root (measured: 24 of 25 corpus hits were that shape).

    An ancestor-aware :func:`match_prefix` would cover this case generally,
    but it also has to re-settle the CL-0001 boundary — ``/`` and ``/var``
    contain root-equivalent paths *and* the control socket — so it is a
    larger change than the member it fixes.
    """
    normalized = normalize_host_path(host_path)
    if not normalized:
        return None
    return normalized if normalized in paths else None
