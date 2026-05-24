"""CL-0003: Privilege escalation not blocked."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.fix import (
    DISABLED_SECURITY_PROFILES,
    block_span,
    first_child_indent,
    is_anchored_or_merged,
    line_indent,
    opens_block_body,
)
from compose_lint.models import Finding, RuleMetadata, Severity, TextEdit
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-4---add-no-new-privileges-flag"
)

CIS_REF = (
    "CIS Docker Benchmark 5.26 — Ensure that the container is restricted "
    "from acquiring additional privileges"
)


@register_rule
class NoNewPrivilegesRule(BaseRule):
    """Detects services missing no-new-privileges security option."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0003",
            name="Privilege escalation not blocked",
            description=(
                "Without no-new-privileges, processes inside the container can "
                "gain additional privileges via setuid/setgid binaries. An "
                "attacker who gains shell access could escalate to root."
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
        security_opt = service_config.get("security_opt", [])
        if not isinstance(security_opt, list):
            security_opt = []

        has_no_new_privs = any(
            str(opt).strip() in ("no-new-privileges:true", "no-new-privileges")
            for opt in security_opt
        )

        if not has_no_new_privs:
            yield Finding(
                rule_id="CL-0003",
                severity=Severity.MEDIUM,
                service=service_name,
                message=(
                    "Service does not set no-new-privileges. Processes inside "
                    "the container can escalate privileges via setuid/setgid binaries."
                ),
                line=lines.get(f"services.{service_name}"),
                fix=(
                    "Add to your service:\n"
                    "  security_opt:\n"
                    "    - no-new-privileges:true\n"
                    "Note: breaks images that switch users via "
                    "gosu/su-exec — test first."
                ),
                references=[OWASP_REF, CIS_REF],
            )

    def fix(
        self,
        finding: Finding,
        data: dict[str, Any],
        lines: dict[str, int],
        text: str,
    ) -> list[TextEdit] | None:
        """Add ``no-new-privileges:true`` to the service's ``security_opt``.

        Appends the entry to an existing block-style ``security_opt:`` list, or
        creates the list as the service's first child when it is absent. This is
        the only hardening-only fixer (ADR-014) — blocking setuid/setgid
        escalation has near-zero breakage — so the edit carries no caveat.

        Refuses (returns ``None``) for anchored/merged services, a flow-style or
        non-list ``security_opt``, a service whose child indentation cannot be
        determined, or a ``security_opt`` that already names ``no-new-privileges``
        with a different value (appending the true form would duplicate the key).
        """
        service = finding.service
        services = data.get("services")
        if not isinstance(services, dict):
            return None
        service_config = services.get(service)
        if not isinstance(service_config, dict):
            return None

        key_line = lines.get(f"services.{service}")
        if key_line is None:
            return None
        source_lines = text.splitlines(keepends=True)
        n = len(source_lines)
        if not 1 <= key_line <= n:
            return None
        if is_anchored_or_merged(source_lines, key_line):
            return None

        if "security_opt" in service_config:
            return self._append_to_existing(
                service, service_config, lines, source_lines, n
            )
        return self._create_list(source_lines, key_line)

    def _append_to_existing(
        self,
        service: str,
        service_config: dict[str, Any],
        lines: dict[str, int],
        source_lines: list[str],
        n: int,
    ) -> list[TextEdit] | None:
        """Append the entry to an existing block-style ``security_opt:`` list."""
        security_opt = service_config.get("security_opt")
        if not isinstance(security_opt, list):
            return None
        if any(
            str(opt).strip().startswith("no-new-privileges") for opt in security_opt
        ):
            # Already named (e.g. `no-new-privileges:false`): appending the true
            # form would duplicate the key. Leave it for the human.
            return None
        if security_opt and all(
            str(opt).strip().lower() in DISABLED_SECURITY_PROFILES
            for opt in security_opt
        ):
            # Every entry is a profile-disable CL-0009 will remove. If we append
            # a survivor now, a second `fix` pass would let CL-0009 delete those
            # entries one by one — non-idempotent (ADR-014). Refuse; the user (or
            # CL-0009) clears the block first, then CL-0003 creates a fresh list.
            return None

        so_line = lines.get(f"services.{service}.security_opt")
        if so_line is None or not 1 <= so_line <= n:
            return None
        if not opens_block_body(source_lines[so_line - 1]):
            return None  # flow style or inline value: no block list to append to
        item_indent = first_child_indent(source_lines, so_line)
        if item_indent is None:
            return None  # `security_opt:` with no items: nothing to append after

        new_item = f"{' ' * item_indent}- no-new-privileges:true\n"
        _first, last = block_span(source_lines, so_line)
        last_line = source_lines[last - 1]
        if last_line.endswith("\n"):
            # The trailing newline makes the start of the next line addressable
            # even when ``last`` is the final line of the file.
            return [TextEdit(last + 1, 1, last + 1, 1, new_item)]
        # Final list item has no trailing newline: append after it on a new line.
        end_col = len(last_line) + 1
        return [TextEdit(last, end_col, last, end_col, f"\n{new_item}")]

    def _create_list(
        self, source_lines: list[str], key_line: int
    ) -> list[TextEdit] | None:
        """Create ``security_opt:`` as the service's first child."""
        child_indent = first_child_indent(source_lines, key_line)
        if child_indent is None:
            return None
        service_indent = line_indent(source_lines[key_line - 1])
        step = child_indent - service_indent
        block = (
            f"{' ' * child_indent}security_opt:\n"
            f"{' ' * (child_indent + step)}- no-new-privileges:true\n"
        )
        return [TextEdit(key_line + 1, 1, key_line + 1, 1, block)]
