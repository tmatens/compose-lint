"""Shared ``cap_add`` scanning for the three capability rules.

``cap_add`` is graded by what the capability grants, across three rules that
differ only in membership and severity: CL-0024 (host code execution),
CL-0011 (strong host-adjacent), CL-0027 (lesser). One rule per tier because
SARIF advertises ``security-severity`` on the *rule descriptor*, so a rule
carrying two severities misreports one of them in GitHub regardless of what the
individual finding says (see ``docs/severity.md``, "One rule, one severity").

The scan itself is identical for all three, so it lives here rather than being
copied three times and drifting.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-3-limit-capabilities-grant-only-"
    "specific-capabilities-needed-by-a-container"
)

CIS_REF = (
    "CIS Docker Benchmark 5.4 — Ensure that Linux kernel capabilities "
    "are restricted within containers"
)

REFERENCES = [OWASP_REF, CIS_REF]


def iter_cap_add(
    service_name: str,
    service_config: dict[str, Any],
    lines: dict[str, int],
    members: dict[str, str],
) -> Iterator[tuple[str, str, int | None]]:
    """Yield ``(as_written, bare_name, line)`` for each matching ``cap_add``.

    ``as_written`` preserves the spelling in the file so the message quotes
    what the author typed; ``bare_name`` is the key into ``members``. Docker
    treats a ``CAP_`` prefix as optional — ``CAP_SYS_ADMIN`` and ``SYS_ADMIN``
    name the same capability, and so does ``CAP_ALL`` — so the prefix is
    stripped before lookup (issue #277 F2).
    """
    cap_add = service_config.get("cap_add", [])
    if not isinstance(cap_add, list):
        return

    for i, cap in enumerate(cap_add):
        as_written = str(cap).strip().upper()
        bare = as_written.removeprefix("CAP_")
        if bare not in members:
            continue
        line = lines.get(f"services.{service_name}.cap_add[{i}]") or lines.get(
            f"services.{service_name}.cap_add"
        )
        yield as_written, bare, line
