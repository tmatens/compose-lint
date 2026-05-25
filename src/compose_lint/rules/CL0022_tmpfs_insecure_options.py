"""CL-0022: tmpfs mount re-enables exec/suid/dev."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

# Docker mounts every tmpfs with noexec,nosuid,nodev by default — verified across
# the short, list, and long (`--mount type=tmpfs`) forms, and the defaults are
# kept even when other options (e.g. size=) are set. The only way to weaken that
# is to explicitly pass one of these options, which removes the matching default.
# Token -> the protection it turns back off.
_INSECURE_OPTIONS: dict[str, str] = {
    "exec": "execution of binaries from the mount (default noexec)",
    "suid": "setuid/setgid bits on the mount (default nosuid)",
    "dev": "device nodes on the mount (default nodev)",
}

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-8-set-filesystem-and-volumes-to-read-only"
)

DOCKER_REF = "https://docs.docker.com/engine/storage/tmpfs/"


def _insecure_options(entry: str) -> list[str]:
    """Return the secure-default-removing options present in a tmpfs entry.

    Matches whole comma-separated tokens, so the secure ``noexec`` is never
    mistaken for the insecure ``exec``.
    """
    opts = entry.partition(":")[2].split(",")
    return [token for token in _INSECURE_OPTIONS if token in opts]


@register_rule
class TmpfsInsecureOptionsRule(BaseRule):
    """Detects tmpfs mounts that re-enable exec/suid/dev."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0022",
            name="tmpfs mount re-enables exec/suid/dev",
            description=(
                "Docker mounts tmpfs with noexec, nosuid, and nodev by default. "
                "Passing exec, suid, or dev removes that protection, making a "
                "writable in-memory mount executable or able to carry setuid "
                "binaries — a deliberate weakening of a secure default."
            ),
            severity=Severity.LOW,
            references=[OWASP_REF, DOCKER_REF],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        tmpfs = service_config.get("tmpfs")
        # Only the short `tmpfs:` form (string or list) carries per-entry options;
        # the long `volumes: [{type: tmpfs}]` form keeps the secure defaults and
        # cannot express these tokens, so it is out of scope.
        if isinstance(tmpfs, str):
            entries = [(tmpfs, f"services.{service_name}.tmpfs")]
        elif isinstance(tmpfs, list):
            entries = [
                (item, f"services.{service_name}.tmpfs[{i}]")
                for i, item in enumerate(tmpfs)
                if isinstance(item, str)
            ]
        else:
            return

        for entry, line_key in entries:
            insecure = _insecure_options(entry)
            if not insecure:
                continue
            path = entry.partition(":")[0]
            opts = ", ".join(insecure)
            yield Finding(
                rule_id="CL-0022",
                severity=Severity.LOW,
                service=service_name,
                message=(
                    f"tmpfs mount '{path}' re-enables {opts}. Docker mounts tmpfs "
                    "noexec,nosuid,nodev by default; this turns that off, making "
                    "a writable in-memory mount a place to stage and run dropped "
                    "payloads — especially under read_only: true."
                ),
                line=lines.get(line_key) or lines.get(f"services.{service_name}.tmpfs"),
                fix=(
                    f"Remove the {opts} option to restore Docker's secure default "
                    "(noexec,nosuid,nodev). Keep it only if the workload must "
                    "execute or setuid from this mount. No auto-fix: the option "
                    "is set deliberately, so reverting is left to manual review."
                ),
                references=[OWASP_REF, DOCKER_REF],
            )
