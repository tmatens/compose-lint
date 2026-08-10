"""CL-0013: Sensitive host path exposed."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule
from compose_lint.rules._mounts import iter_bind_mounts, match_prefix
from compose_lint.rules.CL0025_writable_host_root import ROOT_EQUIVALENT_PATHS

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
    "/home",
)

# The timezone-config pattern `- /etc/localtime:/etc/localtime:ro` (and
# /etc/timezone) is near-universal and, read-only, exposes only the host's UTC
# offset — not host configuration. A read-only mount of exactly these files is
# exempt; /etc itself, /etc/shadow, or a read-write timezone mount still fire.
_BENIGN_READONLY_FILES = frozenset({"/etc/localtime", "/etc/timezone"})


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
        for mount in iter_bind_mounts(service_name, service_config, lines):
            normalized = mount.host_path.rstrip("/")

            # Exempt the read-only timezone-config pattern (issue #509).
            if mount.read_only and normalized in _BENIGN_READONLY_FILES:
                continue

            matched = match_prefix(mount.host_path, _EXPOSED_PATHS)
            reason = "exposes host kernel interfaces, devices or user data"
            if matched is None:
                # A read-only mount of a root-equivalent path is disclosure
                # rather than takeover, so it lands here instead of CL-0025.
                if not mount.read_only:
                    continue
                matched = match_prefix(mount.host_path, ROOT_EQUIVALENT_PATHS)
                if matched is None:
                    continue
                reason = (
                    "is read-only, so it discloses host configuration and "
                    "credentials without granting host write"
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
                fix=(
                    f"Remove the bind mount for {mount.host_path}. If the "
                    "container needs specific files, copy them into the image "
                    "at build time or use a named volume with only the "
                    "required data.\n"
                    "Full guide: compose-lint --explain CL-0013"
                ),
                references=REFERENCES,
            )
