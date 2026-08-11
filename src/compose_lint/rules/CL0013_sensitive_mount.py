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

            matched = match_prefix(mount.host_path, _EXPOSED_PATHS) or _match_home_tree(
                normalized
            )
            reason = "exposes host kernel interfaces, devices or user data"
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
