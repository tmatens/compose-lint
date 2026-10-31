"""CL-0031: Engine API delegated with registry credentials."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

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

COMPOSE_REF = "https://docs.docker.com/reference/compose-file/services/#use_api_socket"

# The one spelling the rule grades. Compose's own loader accepts only a YAML
# boolean here: the quoted string `"true"` and an interpolated `${X:-true}`
# are both refused with `use_api_socket must be a boolean` (measured on
# Compose v5.0.0), so a file written that way never deploys and grading it
# would describe nothing. That is why this rule does not go through
# `_bool.as_bool`, which exists for keys Compose coerces, `privileged` among
# them. The parser's YAML 1.1 resolvers still read the bare `yes`/`on`
# spellings as booleans, so those reach this test as `True` and are graded.
EVIDENCE = "use_api_socket"


def delegates_api_socket(service_config: dict[str, Any]) -> bool:
    """Whether the service sets ``use_api_socket`` to the YAML boolean true.

    Exported so the CL-0007 fixer can refuse to insert ``read_only: true``
    beside it: Compose copies the credentials file into the root filesystem
    rather than mounting it, so a read-only service cannot receive it and
    ``up`` fails. One predicate, one reader.
    """
    return service_config.get("use_api_socket") is True


@register_rule
class ApiSocketRule(BaseRule):
    """Detects ``use_api_socket: true``: the socket plus the user's logins."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0031",
            name="Engine API delegated with registry credentials",
            description=(
                "use_api_socket: true makes Compose bind-mount the host's "
                "Docker socket read-write into the container and copy the "
                "registry logins of the user running the stack in beside it. "
                "The container controls the host daemon, as a socket mount "
                "does, and can also push and pull as that user."
            ),
            severity=Severity.CRITICAL,
            references=[OWASP_REF, CIS_REF, COMPOSE_REF],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        if not delegates_api_socket(service_config):
            return
        yield Finding(
            rule_id="CL-0031",
            severity=Severity.CRITICAL,
            service=service_name,
            evidence=EVIDENCE,
            message=(
                "Service sets 'use_api_socket: true'. Compose mounts the "
                "host's Docker socket read-write and copies the registry "
                "logins of the user who runs the stack into the container, "
                "which can then control the host daemon and push or pull as "
                "that user."
            ),
            line=lines.get(f"services.{service_name}.use_api_socket"),
            fix=(
                "Remove 'use_api_socket: true' if the service does not need "
                "the engine API. If it needs the API but not your registry "
                "identity, mount a filtered socket instead (compose-lint "
                "--explain CL-0001); no credentials are copied in. A tool that "
                "needs both, such as an engine-management gateway, has no "
                "in-file fix: exclude it with a written reason and run the "
                "stack from a deploy identity whose Docker config holds no "
                "logins it does not need.\n"
                "Full guide: compose-lint --explain CL-0031"
            ),
            references=[OWASP_REF, CIS_REF, COMPOSE_REF],
        )
