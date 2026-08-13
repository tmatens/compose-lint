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

from compose_lint._scalar import as_scalar_text

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


def normalize_cap(cap: object) -> str:
    """Canonical capability name: upper-cased, trimmed, ``CAP_`` prefix removed.

    Shared so ``cap_add`` and ``cap_drop`` cannot disagree about the same
    spelling. They did: this helper trimmed and stripped the prefix while
    CL-0006 upper-cased only, so ``cap_drop: [CAP_ALL]`` read as "did not drop
    all" while ``cap_add: [CAP_ALL]`` was normalised. Docker refuses both odd
    spellings, so neither reading shipped a wrong finding about a file that
    runs -- but one answer is better than two.

    ``ALL`` keeps its exception (see :func:`iter_cap_add`) at the call site,
    because it is only ``cap_add`` that must reject the prefixed form.
    """
    text = as_scalar_text(cap)
    if text is None:
        return ""  # a container is not a capability name; matches nothing
    return text.strip().upper().removeprefix("CAP_")


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
    name the same capability — so the prefix is stripped before lookup
    (issue #277 F2).

    ``ALL`` is the exception, and it does not generalise: Docker special-cases
    it *before* applying the prefix, so ``CAP_ALL`` falls through to the
    capability table and is rejected outright — ``docker run --cap-add CAP_ALL``
    fails with ``invalid CapAdd: unknown capability: "CAP_ALL"`` (verified,
    Docker 29.1.3). Flagging it would be a CRITICAL finding on a file that
    cannot start, so the prefixed spelling is not accepted for ``ALL``.
    """
    cap_add = service_config.get("cap_add", [])
    if not isinstance(cap_add, list):
        return

    for i, cap in enumerate(cap_add):
        raw = as_scalar_text(cap)
        if raw is None:
            # An alias-expanded nested list here is what made `str()` allocate
            # 2^depth characters; it is also not a capability, so skip it.
            continue
        as_written = raw.strip().upper()
        bare = normalize_cap(cap)
        if bare == "ALL" and as_written != "ALL":
            continue  # CAP_ALL is not a capability Docker accepts — see above
        if bare not in members:
            continue
        line = lines.get(f"services.{service_name}.cap_add[{i}]") or lines.get(
            f"services.{service_name}.cap_add"
        )
        yield as_written, bare, line
