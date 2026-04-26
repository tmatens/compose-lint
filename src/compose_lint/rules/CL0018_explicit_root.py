"""CL-0018: Explicit root user."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-7---do-not-use-root-user"
)

CIS_REF = "CIS Docker Benchmark 5.x — Do not run containers as root"

_ROOT_USER_PARTS = {"root", "0"}


def _is_root_user(user_str: str) -> bool:
    """Return True if user_str names UID 0 / root, regardless of group.

    A non-root group does not change the effective user — running as root with
    GID 1000 is still root. Cross-spec forms (root:0, 0:root) and the bare
    forms (root, 0, root:root, 0:0) all collapse to "is the user portion
    root?".
    """
    user_part = user_str.partition(":")[0]
    return user_part in _ROOT_USER_PARTS


@register_rule
class ExplicitRootRule(BaseRule):
    """Detects services explicitly running as root."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0018",
            name="Explicit root user",
            description=(
                "Explicitly setting user to root overrides any non-root USER "
                "instruction in the image, running the container's process as "
                "UID 0."
            ),
            severity=Severity.MEDIUM,
            references=[OWASP_REF, CIS_REF],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        user = service_config.get("user")
        if user is None:
            return

        user_str = str(user).strip().lower()
        if _is_root_user(user_str):
            yield Finding(
                rule_id="CL-0018",
                severity=Severity.MEDIUM,
                service=service_name,
                message=(
                    f"Service explicitly runs as root "
                    f"(user: {service_config['user']}). This overrides any "
                    "non-root USER instruction in the image."
                ),
                line=lines.get(f"services.{service_name}.user"),
                fix=(
                    "Remove the 'user:' directive to respect the image's USER "
                    "instruction, or set a non-root user:\n"
                    "  user: 1000:1000"
                ),
                references=[OWASP_REF, CIS_REF],
            )
