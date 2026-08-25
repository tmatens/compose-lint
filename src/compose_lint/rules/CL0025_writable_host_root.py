"""CL-0025: Root-equivalent host path mounted writable."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule
from compose_lint.rules._mounts import (
    TIMEZONE_FILES,
    iter_bind_mounts,
    match_exact,
    match_prefix,
    normalize_host_path,
)

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

# Host paths where *write* access is host root, with no further technique. A
# read-only mount of any of these is disclosure rather than takeover and falls
# through to CL-0013.
#
# A whole-root mount ("/") is deliberately absent: it contains the daemon
# control socket, so it is host root in *either* mode, not only when writable.
# CL-0001 owns it, mode-independent — grading a read-only "/" here (or as
# CL-0013's HIGH disclosure) would under-price the socket it exposes.
#
# Matching here is by descent (a mount at or under a listed path), so an
# *ancestor* of a listed path is not claimed even though it grants everything
# below it. "/var/lib" was the uncovered case: it contains /var/lib/docker, so a
# writable mount of it grants what that entry describes, and it produced no
# finding. It is covered by ROOT_EQUIVALENT_EXACT_PATHS below rather than added
# here — see that block for why descent is the wrong match for it.
#
# Verified on Docker 29.4.3, both legs, against a second container started for
# the purpose: a container given only `-v /var/lib`, unprivileged and at
# default capabilities, read that container's private file and appended to it,
# and the victim saw the change live.
#
# /var/lib/containerd is listed here, which nothing named before. Where the data
# sits is version-dependent, and both layouts keep it inside /var/lib:
#   * Docker 29 + containerd snapshotter (measured on both grounding hosts):
#     snapshot trees are in /var/lib/containerd/io.containerd.snapshotter.*/,
#     while each running container's live rootfs is still reachable under
#     /var/lib/docker/rootfs/overlayfs/<id>/ — verified, the same read and
#     write succeeded through a /var/lib/docker mount alone.
#   * classic overlay2 graph driver (pre-29 default): layers and the merged
#     rootfs are under /var/lib/docker/overlay2/<id>/. Not measured here — no
#     host on hand runs it — so it is cited as the documented layout, not as a
#     capture.
# Either way /var/lib/docker keeps its grant; /var/lib/containerd is the part
# that had no owner.
#
# The executable tree (#737). Root's PATH on every mainstream distro is some
# ordering of /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin, so a
# file planted in any of these runs as root the next time root -- cron, a login
# shell, a systemd unit -- calls that name. No existing binary need be
# overwritten: a name planted in /usr/local/bin shadows the same name in
# /usr/bin. Measured on two hosts (Docker 29.1.3 with AppArmor; 29.7.2 without),
# unprivileged, default capabilities: a writable bind of each member accepted a
# write and a read-only bind refused it, and a 755 root-owned file planted
# through `-v /usr` was visible to a second container and on the host.
#
# Both the /usr/... and the bare /bin, /sbin spellings are listed. On a
# merged-usr host they are the same directories, but Docker resolves the symlink
# at mount time while this rule matches what the *document* wrote, so a prefix
# on one spelling cannot cover the other.
#
# The library tree is deliberately *not* here. /usr/lib and /lib/modules carry a
# comparable grant (systemd units, ld.so libraries, loadable modules), but by
# descent they would also sweep /usr/lib/python3, /usr/lib/node_modules and
# every VPN workload's standard /lib/modules bind -- the /var/lib containment
# failure again -- and the corpus holds no bind of /usr/lib other than modules
# to shape a narrower match on. Recorded here as deferred, pending an ADR, so
# it is a disposition rather than an omission.
#
ROOT_EQUIVALENT_PATHS: tuple[str, ...] = (
    "/etc",
    "/root",
    "/boot",
    "/var/lib/docker",
    "/var/lib/containerd",
    "/proc",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/bin",
    "/sbin",
)

# The executable tree is root-equivalent *only* writable. Read-only it discloses
# nothing -- every file in it is world-readable by design -- so unlike the
# other members a `:ro` mount of one of these is not CL-0013's disclosure
# finding either. Same shape as the timezone exemption, one tier up.
EXEC_TREE_PATHS: frozenset[str] = frozenset(
    {
        "/usr",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/bin",
        "/sbin",
    }
)

# "/var/lib" is root-equivalent because of what it *contains* — /var/lib/docker
# and /var/lib/containerd — not because of what lies below it. Those are two
# different sets, and matching it by descent takes the wrong one: /var/lib/mysql
# contains neither, yet a writable bind of it was priced CRITICAL with a message
# naming a container store it does not hold. Measured over the corpus, 24 of the
# 25 hits the member produced were an application's own state directory
# (/var/lib/mysql, /var/lib/postgresql/data, /var/lib/grafana …) and exactly one
# was a real bare /var/lib mount.
#
# So it is matched *exactly*: -v /var/lib is CRITICAL, -v /var/lib/mysql is not.
# The general fix is an ancestor-aware matcher, which also has to re-settle the
# CL-0001 boundary ("/" and "/var" contain the control socket) and is therefore
# a larger change than this member warrants.
#
# "/usr" is the same shape: root-equivalent because it *contains* the exec
# directories above, while by descent it would also claim /usr/src, /usr/share
# and the Python site-packages -- measured over the corpus, 6 of the 27 writable
# /usr-family binds (22%) were that kind of application data.
ROOT_EQUIVALENT_EXACT_PATHS: tuple[str, ...] = ("/var/lib", "/usr")


def match_root_equivalent(host_path: str) -> str | None:
    """The root-equivalent member this mount lands on, by descent or exactly."""
    return match_prefix(host_path, ROOT_EQUIVALENT_PATHS) or match_exact(
        host_path, ROOT_EQUIVALENT_EXACT_PATHS
    )


_GRANTS: dict[str, str] = {
    "/etc": "cron.d, ld.so.preload, sudoers and shadow — host root on the next "
    "scheduled job or login",
    "/root": "authorized_keys — host root over SSH",
    "/boot": "the kernel and initramfs — a persistent rootkit surviving reboot",
    "/var/lib/docker": "every other container's filesystem and image layers — "
    "tamper with one and it escapes on next start",
    "/var/lib/containerd": "the containerd snapshot trees holding every "
    "container's filesystem — on Docker 29 with the containerd snapshotter "
    "that is where the layers live",
    "/var/lib": "/var/lib/docker and /var/lib/containerd inside it, and with "
    "them every other container's filesystem — verified, a container holding "
    "only this mount read and modified a neighbour's files",
    "/proc": "core_pattern — the host's core-dump handler runs a program of the "
    "attacker's choosing, as root, on the next crash",
    **dict.fromkeys(
        ("/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/bin", "/sbin"),
        "root's PATH — a planted or replaced binary runs as root on the next "
        "cron job, login or unit start",
    ),
    "/usr": "the executable tree inside it (/usr/bin, /usr/sbin, /usr/local/bin) "
    "— a planted binary runs as root on the next cron job, login or unit start",
}


@register_rule
class WritableHostRootMountRule(BaseRule):
    """Detects writable bind mounts of root-equivalent host paths."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0025",
            name="Root-equivalent host path mounted writable",
            description=(
                "A writable bind mount of /etc, /root, /boot, /proc, the "
                "container store (/var/lib/docker, /var/lib/containerd), "
                "/var/lib itself, or the executable tree (/usr, /usr/bin, "
                "/usr/local/bin, /bin, /sbin) gives a container host root "
                "through ordinary file writes — no exploit and no technique "
                "required. (A whole-root mount is CL-0001's, which owns it in "
                "either mode.)"
            ),
            severity=Severity.CRITICAL,
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
            if mount.read_only:
                continue  # disclosure only — CL-0013 owns it
            if normalize_host_path(mount.host_path) in TIMEZONE_FILES:
                continue  # under /etc, but writing it is not host root
            matched = match_root_equivalent(mount.host_path)
            if matched is None:
                continue
            yield Finding(
                rule_id="CL-0025",
                severity=Severity.CRITICAL,
                service=service_name,
                evidence=mount.host_path,
                message=(
                    f"Service mounts host path '{mount.host_path}' writable "
                    f"(under {matched}). Writing there is host root: "
                    f"{_GRANTS[matched]}."
                ),
                line=mount.line,
                fix=(
                    f"Remove the bind mount for {mount.host_path}, or make it "
                    "read-only (:ro) if the container only needs to read — that "
                    "is still a disclosure finding but not a host takeover.\n"
                    "Where specific files are needed, copy them into the image "
                    "at build time or use a named volume holding only those.\n"
                    "Full guide: compose-lint --explain CL-0025"
                ),
                references=REFERENCES,
            )
