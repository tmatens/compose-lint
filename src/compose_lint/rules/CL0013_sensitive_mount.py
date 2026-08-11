"""CL-0013: Sensitive host path exposed."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule
from compose_lint.rules._mounts import (
    TIMEZONE_FILES,
    iter_bind_mounts,
    match_prefix,
    normalize_host_path,
)
from compose_lint.rules.CL0001_docker_socket import claims_host_path
from compose_lint.rules.CL0025_writable_host_root import match_root_equivalent

if TYPE_CHECKING:
    from collections.abc import Iterator

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-8-set-filesystem-and-volumes-to-read-only"
)

CIS_REF = (
    "CIS Docker Benchmark 5.6 — Ensure sensitive host system directories "
    "are not mounted on containers"
)

REFERENCES = [OWASP_REF, CIS_REF]

# Paths that are a disclosure or a weakened boundary in *either* mode, because
# writing to them does not add a host-root path the way CL-0025's members do.
#
# /var/lib/kubelet was removed: its danger is entirely conditional on Kubernetes
# being present, so it cannot be premise-checked on the grounded target and it
# fails the same bar that removed CL-0023 (ADR-020).
_EXPOSED_PATHS: tuple[str, ...] = (
    # uevent_helper is not writable at default capabilities and release_agent is
    # cgroup-v1 only, so /sys is disclosure and a weakened boundary, not escape.
    "/sys",
    # A /dev bind conveys the device *nodes* without device-cgroup permission —
    # verified: the same raw read fails through a bind and succeeds through
    # --device, which is why CL-0016 owns raw device access, not this rule.
    "/dev",
)

# Character devices that convey nothing. Mounting /dev/null into a container
# discloses no host state and grants no access -- it is a bit bucket, and a
# near-universal way to blank out a config file the image expects. They are
# excluded rather than left to the /dev descent match, which priced them as
# "exposes host kernel interfaces, devices or user data".
_INERT_DEVICES: frozenset[str] = frozenset(
    {"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom"}
)

# Paths where "remove the bind mount" is not a followable instruction, because
# the workload needs the facility the mount provides. Compose has a scoped
# alternative for each that keeps the facility and drops the host exposure, so
# the finding stays and the guidance names the alternative instead.
#
# Verified against Docker 29.4.3, and each is clean under this rule set:
#   /dev/shm       `shm_size:` resizes the container's own /dev/shm (64 MiB by
#                  default) without exposing the host's; `ipc: shareable` plus
#                  `ipc: service:<owner>` shares one segment between named
#                  services with the host and every other container excluded.
#   /dev/hugepages a local volume with `type: hugetlbfs` mounts a *fresh*
#                  hugetlbfs instance — a file created in it is invisible both
#                  on the host's /dev/hugepages and through a bind of it.
#
# Neither alternative bounds the underlying host-wide resource (the huge-page
# pool is global), which is what `deploy.resources.limits` is for.
_SCOPED_ALTERNATIVES: dict[str, str] = {
    # nosec B108 - naming the path is the rule's job, not a temp-file use
    "/dev/shm": (
        "Don't bind the host's /dev/shm. If the container only needs a larger "
        "shared-memory segment than the 64 MiB default, set `shm_size:` on the "
        "service. If two services genuinely need to share one, set "
        "`ipc: shareable` on the owner and `ipc: service:<owner>` on the "
        "other — that scopes the segment to those services instead of exposing "
        "every segment on the host."
    ),
    "/dev/hugepages": (
        "Don't bind the host's /dev/hugepages. Declare a volume with "
        "`driver_opts: {type: hugetlbfs, device: hugetlbfs}` and mount that "
        "instead: the container gets its own hugetlbfs instance, so it can "
        "still use huge pages but cannot read or corrupt the pages another "
        "workload mapped. The page pool stays host-wide, so also bound the "
        "service with `deploy.resources.limits`."
    ),
}

# The runtime directories. CL-0001 owns these and their ancestors, because they
# hold the control sockets; it does not own what sits *below* them, which holds
# host service state instead -- the system D-Bus, the libvirt control socket,
# udev's device database, utmp. CL-0013 matched all of it by descent until the
# directories moved to CL-0001, and the move left the descendants claimed by
# neither rule: measured over the corpus, 35 HIGH findings disappeared,
# /var/run/dbus and /var/run/libvirt/libvirt-sock among them.
_RUNTIME_DIRS: tuple[str, ...] = ("/run", "/var/run")


def _match_runtime_descendant(normalized: str) -> str | None:
    """The runtime directory this mount sits strictly below, or ``None``.

    Callers must first confirm CL-0001 does not claim the path
    (:func:`claims_host_path`) — a descendant that *is* a control socket, or a
    socket directory in its own right like ``/run/containerd``, is CL-0001's at
    CRITICAL and must not be double-reported here at HIGH.
    """
    for directory in _RUNTIME_DIRS:
        if normalized.startswith(directory + "/"):
            return directory
    return None


_HOME_ROOT = "/home"

# Credential material kept at a fixed path inside a home directory. These keep a
# descent match: exposing ~/.ssh is a disclosure whatever sits below it, and the
# grant does not weaken with depth the way a project directory's does.
_HOME_CREDENTIAL_DIRS: frozenset[str] = frozenset(
    {".ssh", ".docker", ".aws", ".kube", ".gnupg"}
)


def _match_home_tree(normalized: str) -> str | None:
    """The home path this mount exposes, or ``None``.

    ``/home`` is a disclosure when the *tree* is exposed — /home itself, or one
    user's home directory — or when a known credential directory inside one is.
    It is **not** a disclosure merely because a path happens to sit inside it.

    That distinction did not matter while only a deliberately absolute source
    could reach here. Resolving relative sources changed it: ``./data`` becomes
    an absolute path under the compose file's directory, and for the
    overwhelming majority of real files that lands under /home. Matched by
    descent, the single most common bind idiom in Compose became a HIGH
    finding — measured over the corpus, 4,598 findings across 1,712 of 5,417
    files, none of them real. Depth is what separates the two cases:
    /home/alice is host user data, /home/alice/projects/app/data is the
    application's own directory.
    """
    if normalized == _HOME_ROOT:
        return _HOME_ROOT
    if not normalized.startswith(_HOME_ROOT + "/"):
        return None
    parts = normalized.split("/")  # ["", "home", <user>, ...]
    if len(parts) == 3:
        return normalized  # a whole user's home directory
    if parts[3] in _HOME_CREDENTIAL_DIRS:
        return "/".join(parts[:4])
    return None


@register_rule
class SensitiveMountRule(BaseRule):
    """Detects host paths exposed into a container without host-root write."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0013",
            name="Sensitive host path exposed",
            description=(
                "Mounting /sys, /dev or /home into a container, or mounting a "
                "root-equivalent host path read-only, exposes host "
                "configuration, kernel interfaces and credentials to it."
            ),
            severity=Severity.HIGH,
            references=REFERENCES,
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        for mount in iter_bind_mounts(
            service_name, service_config, lines, global_config
        ):
            normalized = normalize_host_path(mount.host_path)

            if normalized in _INERT_DEVICES:
                continue  # a bit bucket discloses nothing

            matched = match_prefix(mount.host_path, _EXPOSED_PATHS) or _match_home_tree(
                normalized
            )
            reason = "exposes host kernel interfaces, devices or user data"
            if matched is None and not claims_host_path(mount.host_path):
                matched = _match_runtime_descendant(normalized)
                if matched is not None:
                    reason = (
                        "exposes host runtime state — service sockets, the "
                        "system bus and device state live here"
                    )
            if matched is None:
                matched = match_root_equivalent(mount.host_path)
                if matched is None:
                    continue
                if normalized in TIMEZONE_FILES:
                    # Read-only, this is the exempt timezone pattern (#509).
                    # Writable, the container can change what the host reads as
                    # local time — worth a finding, but not CL-0025's tier,
                    # because writing this file is not host root.
                    if mount.read_only:
                        continue
                    reason = (
                        "is writable, letting the container change the host's "
                        "timezone configuration"
                    )
                elif mount.read_only:
                    # A read-only mount of a root-equivalent path is disclosure
                    # rather than takeover, so it lands here instead of CL-0025.
                    reason = (
                        "is read-only, so it discloses host configuration and "
                        "credentials without granting host write"
                    )
                else:
                    continue  # writable root-equivalent — CL-0025's

            remedy = _SCOPED_ALTERNATIVES.get(normalized) or (
                f"Remove the bind mount for {mount.host_path}. If the "
                "container needs specific files, copy them into the image at "
                "build time or use a named volume with only the required data."
            )

            yield Finding(
                rule_id="CL-0013",
                severity=Severity.HIGH,
                service=service_name,
                message=(
                    f"Service mounts sensitive host path '{mount.host_path}' "
                    f"(under {matched}). The mount {reason}."
                ),
                line=mount.line,
                fix=f"{remedy}\nFull guide: compose-lint --explain CL-0013",
                references=REFERENCES,
            )
