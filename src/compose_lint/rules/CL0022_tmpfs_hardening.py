"""CL-0022: tmpfs mount missing hardening flags."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.fix import is_anchored_or_merged
from compose_lint.models import Finding, RuleMetadata, Severity, TextEdit
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

# Order is canonical: a fixer appends missing flags in this sequence.
_HARDENING_FLAGS = ("noexec", "nosuid", "nodev")

_CAVEAT = (
    "noexec blocks executing files from the tmpfs; if the workload legitimately "
    "runs binaries or scripts from this mount it will break — drop noexec there."
)

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-8-set-filesystem-and-volumes-to-read-only"
)

DOCKER_REF = "https://docs.docker.com/engine/storage/tmpfs/"


def _missing_flags(entry: str) -> list[str]:
    """Return the hardening flags absent from a ``path[:opt,opt]`` tmpfs entry."""
    _, _, optstr = entry.partition(":")
    opts = {o for o in optstr.split(",") if o}
    return [flag for flag in _HARDENING_FLAGS if flag not in opts]


@register_rule
class TmpfsHardeningRule(BaseRule):
    """Detects ``tmpfs`` mounts that omit ``noexec``/``nosuid``/``nodev``."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0022",
            name="tmpfs mount not hardened",
            description=(
                "A tmpfs mount without noexec, nosuid, and nodev leaves a "
                "writable, executable in-memory filesystem — a staging ground "
                "for dropped payloads, especially under a read-only root."
            ),
            severity=Severity.MEDIUM,
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
        # Only the short `tmpfs:` form (string or list of strings) exposes mount
        # flags through Compose; the long `volumes: [{type: tmpfs}]` form does
        # not, so it is out of scope.
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
            missing = _missing_flags(entry)
            if not missing:
                continue
            path = entry.partition(":")[0]
            yield Finding(
                rule_id="CL-0022",
                severity=Severity.MEDIUM,
                service=service_name,
                message=(
                    f"tmpfs mount '{path}' is missing hardening option(s) "
                    f"{', '.join(missing)}. A writable, executable in-memory "
                    "mount is a staging ground for dropped payloads — especially "
                    "under read_only: true where it may be the only writable path."
                ),
                line=lines.get(line_key) or lines.get(f"services.{service_name}.tmpfs"),
                fix=(
                    "Add mount flags to the tmpfs entry:\n"
                    "  tmpfs:\n"
                    f"    - {path}:{','.join(_HARDENING_FLAGS)}\n"
                    "Keep noexec unless the workload must execute from the mount."
                ),
                references=[OWASP_REF, DOCKER_REF],
            )

    def fix(
        self,
        finding: Finding,
        data: dict[str, Any],
        lines: dict[str, int],
        text: str,
    ) -> list[TextEdit] | None:
        """Append the missing ``noexec``/``nosuid``/``nodev`` flags in place.

        Edits the tmpfs entry's scalar — ``- /tmp`` becomes
        ``- /tmp:noexec,nosuid,nodev`` and ``- /run:size=64m`` keeps its existing
        options. Handles both the list-item form and the single-string
        ``tmpfs: /tmp`` form, inside surrounding quotes when present. The edit
        carries a caveat because ``noexec`` changes runtime behavior (ADR-014).

        Refuses (returns ``None``) for anchored/merged services, flow-style
        (``tmpfs: [/tmp]``) or ``${VAR}`` entries, or a line that is not a plain
        scalar tmpfs entry.
        """
        service = finding.service
        services = data.get("services")
        if not isinstance(services, dict):
            return None
        service_config = services.get(service)
        if not isinstance(service_config, dict):
            return None
        if not isinstance(service_config.get("tmpfs"), (str, list)):
            return None

        item_line = finding.line
        service_line = lines.get(f"services.{service}")
        if item_line is None or service_line is None:
            return None
        source_lines = text.splitlines(keepends=True)
        n = len(source_lines)
        if not (1 <= item_line <= n and 1 <= service_line <= n):
            return None
        if is_anchored_or_merged(source_lines, service_line):
            return None

        span = _value_span(source_lines[item_line - 1])
        if span is None:
            return None
        value, start_col, end_col = span
        # Flow collection or interpolation: ambiguous to edit, leave manual.
        if value[:1] in ("[", "{") or "$" in value:
            return None

        missing = _missing_flags(value)
        if not missing:
            return None
        path, _, optstr = value.partition(":")
        opts = [o for o in optstr.split(",") if o]
        new_value = f"{path}:{','.join(opts + missing)}"

        return [
            TextEdit(
                item_line, start_col, item_line, end_col, new_value, caveat=_CAVEAT
            )
        ]


def _value_span(raw_line: str) -> tuple[str, int, int] | None:
    """Return ``(value, start_col, end_col)`` for a tmpfs entry's scalar.

    Handles a block-sequence item (``- /tmp``) and the single-string mapping
    form (``tmpfs: /tmp``). Columns are 1-indexed and the span is half-open,
    pointing inside a surrounding quote when the value is quoted. A trailing
    ``# comment`` is excluded. Returns ``None`` when the line is neither shape.
    """
    line = raw_line.rstrip("\n")
    idx = len(line) - len(line.lstrip(" "))
    if idx < len(line) and line[idx] == "-":
        idx += 1
        if idx >= len(line) or line[idx] != " ":
            return None
    elif line[idx:].startswith("tmpfs:"):
        idx += len("tmpfs:")
    else:
        return None
    while idx < len(line) and line[idx] == " ":
        idx += 1
    if idx >= len(line):
        return None

    if line[idx] in ("'", '"'):
        quote = line[idx]
        close = line.find(quote, idx + 1)
        if close == -1:
            return None
        return line[idx + 1 : close], idx + 2, close + 1

    rest = line[idx:]
    comment = rest.find(" #")
    if comment != -1:
        rest = rest[:comment]
    value = rest.rstrip()
    if not value:
        return None
    return value, idx + 1, idx + 1 + len(value)
