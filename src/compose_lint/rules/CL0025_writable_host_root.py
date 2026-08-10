"""CL-0025: Root-equivalent host path mounted writable."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule
from compose_lint.rules._mounts import (
    TIMEZONE_FILES,
    iter_bind_mounts,
    match_prefix,
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
ROOT_EQUIVALENT_PATHS: tuple[str, ...] = (
    "/etc",
    "/root",
    "/boot",
    "/var/lib/docker",
    "/proc",
    "/",
)

_GRANTS: dict[str, str] = {
    "/": "the whole host filesystem — every path below is writable at once",
    "/etc": "cron.d, ld.so.preload, sudoers and shadow — host root on the next "
    "scheduled job or login",
    "/root": "authorized_keys — host root over SSH",
    "/boot": "the kernel and initramfs — a persistent rootkit surviving reboot",
    "/var/lib/docker": "every other container's filesystem and image layers — "
    "tamper with one and it escapes on next start",
    "/proc": "core_pattern — the host's core-dump handler runs a program of the "
    "attacker's choosing, as root, on the next crash",
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
                "A writable bind mount of /, /etc, /root, /boot, /var/lib/docker "
                "or /proc gives a container host root through ordinary file "
                "writes — no exploit and no technique required."
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
        for mount in iter_bind_mounts(service_name, service_config, lines):
            if mount.read_only:
                continue  # disclosure only — CL-0013 owns it
            if mount.host_path.rstrip("/") in TIMEZONE_FILES:
                continue  # under /etc, but writing it is not host root
            matched = match_prefix(mount.host_path, ROOT_EQUIVALENT_PATHS)
            if matched is None:
                continue
            yield Finding(
                rule_id="CL-0025",
                severity=Severity.CRITICAL,
                service=service_name,
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
