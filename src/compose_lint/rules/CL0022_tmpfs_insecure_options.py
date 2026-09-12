"""CL-0022: tmpfs mount re-enables exec/suid."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint._lines import split_lines
from compose_lint._yaml_edit import (
    is_anchored_or_merged,
    mapping_scalar_span,
    sequence_scalar_span,
)
from compose_lint.models import Finding, RuleMetadata, Severity, TextEdit
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

_CAVEAT = (
    "Removing exec/suid restores Docker's noexec,nosuid tmpfs default; a "
    "workload that executes a binary or relies on a setuid bit from this mount "
    "will fail."
)

# Docker mounts every tmpfs with noexec,nosuid,nodev by default — verified across
# the short, list, and long (`--mount type=tmpfs`) forms, and the defaults are
# kept even when other options (e.g. size=) are set. The only way to weaken that
# is to explicitly pass one of these options, which removes the matching default.
# Token -> the protection it turns back off.
#
# `dev` is deliberately absent (ADR-028). Removing `nodev` changes nothing a
# container can do: the device cgroup refuses every non-allow-listed node
# wherever it sits, and the rootfs and /dev — mounts every container already
# has — carry no `nodev` either. Where the cgroup is off (`privileged`), /dev is
# already a writable, device-capable tmpfs. Flagging `dev` would be a finding on
# a config that changes nothing — the CL-0023 failure mode. Proven live by
# `_cl0022_dev_inert` in scripts/validate_rule_premises.py.
_INSECURE_OPTIONS: dict[str, str] = {
    "exec": "execution of binaries from the mount (default noexec)",
    "suid": "setuid/setgid bits on the mount (default nosuid)",
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


def _without_insecure_options(entry: str) -> str:
    """The tmpfs entry with its ``exec``/``suid`` tokens removed.

    The inverse of :func:`_insecure_options` on the same token grammar: the
    path is kept as written, the surviving options keep their order, and when
    none survive the separating colon goes too (``/tmp:exec`` -> ``/tmp``), so
    the result is the bare form Docker mounts with every default. Empty tokens
    (a doubled or trailing comma) are dropped with the rest rather than left as
    ``/tmp:`` -- they name nothing, and a bare colon is not a shape the rule's
    own examples ever write.
    """
    path, _, options = entry.partition(":")
    kept = [
        token
        for token in options.split(",")
        if token and token not in _INSECURE_OPTIONS
    ]
    return f"{path}:{','.join(kept)}" if kept else path


@register_rule
class TmpfsInsecureOptionsRule(BaseRule):
    """Detects tmpfs mounts that re-enable exec or suid."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0022",
            name="tmpfs mount re-enables exec/suid",
            description=(
                "Docker mounts tmpfs with noexec and nosuid by default. Passing "
                "exec or suid removes that protection, making a writable "
                "in-memory mount executable or able to carry setuid binaries — "
                "a deliberate weakening of a secure default."
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
                evidence=path,
                message=(
                    f"tmpfs mount '{path}' re-enables {opts}. Docker mounts tmpfs "
                    "noexec,nosuid by default; this turns that off, making a "
                    "writable in-memory mount a place to stage and run dropped "
                    "payloads — especially under read_only: true."
                ),
                line=lines.get(line_key) or lines.get(f"services.{service_name}.tmpfs"),
                fix=(
                    f"Remove the {opts} option to restore Docker's secure default "
                    "(noexec,nosuid). Keep it only if the workload must "
                    "execute or setuid from this mount."
                ),
                references=[OWASP_REF, DOCKER_REF],
            )

    def fix_writes_keys(self) -> frozenset[str]:
        """It rewrites an entry inside `tmpfs`."""
        return frozenset({"tmpfs"})

    def fix(
        self,
        finding: Finding,
        data: dict[str, Any],
        lines: dict[str, int],
        text: str,
    ) -> list[TextEdit] | None:
        """Delete the ``exec``/``suid`` tokens from the flagged tmpfs entry.

        The tokens are an explicit opt-out of the ``noexec,nosuid`` default
        Docker applies to every tmpfs, so removing them restores the default
        with nothing else to compensate -- the same "revert a guardrail" class
        as CL-0009 and CL-0014 (ADR-014, Part 4). The edit is made inside the
        entry's scalar, on its own line, in either spelling the rule checks:
        a list item (``- /run:exec,size=64m`` -> ``- /run:size=64m``) or the
        scalar form (``tmpfs: /tmp:exec`` -> ``tmpfs: /tmp``). Quoting and any
        trailing comment are left as written.

        Refuses (returns ``None``) for anchored/merged services; a flow-style
        list (``tmpfs: [/tmp:exec]``), where the item has no line of its own;
        ``$`` interpolation in the entry, since the deployed value is unknown;
        and any line whose visible scalar is not the whole parsed entry -- a
        wrapped plain scalar, a block scalar, an escaped quote -- so an edit
        never lands on part of a value (the shape behind issue #508). The edit
        carries a caveat: a workload that really executes from the mount
        breaks when the default comes back.
        """
        service = finding.service
        services = data.get("services")
        if not isinstance(services, dict):
            return None
        service_config = services.get(service)
        if not isinstance(service_config, dict):
            return None
        tmpfs = service_config.get("tmpfs")

        item_line = finding.line
        service_line = lines.get(f"services.{service}")
        if item_line is None or service_line is None:
            return None
        source_lines = split_lines(text)
        n = len(source_lines)
        if not (1 <= item_line <= n and 1 <= service_line <= n):
            return None
        if is_anchored_or_merged(source_lines, service_line):
            return None

        raw_line = source_lines[item_line - 1]
        if isinstance(tmpfs, str):
            entry: Any = tmpfs
            parsed = mapping_scalar_span(raw_line, "tmpfs")
        elif isinstance(tmpfs, list):
            entry = _entry_at_line(tmpfs, lines, service, item_line)
            parsed = sequence_scalar_span(raw_line)
        else:
            return None
        if parsed is None or not isinstance(entry, str):
            return None  # flow-style list, block body, or no entry on this line
        scalar, col = parsed
        if scalar != entry:
            return None  # the line does not show the whole value: refuse (#508)
        if "$" in scalar:
            return None  # interpolation: the deployed entry is unknown
        replacement = _without_insecure_options(scalar)
        if replacement == scalar:
            return None  # nothing to remove on this spelling; leave it
        return [
            TextEdit(
                item_line,
                col,
                item_line,
                col + len(scalar),
                replacement,
                caveat=_CAVEAT,
            )
        ]


def _entry_at_line(
    tmpfs: list[Any], lines: dict[str, int], service: str, item_line: int
) -> Any:
    """Return the parsed ``tmpfs`` list entry whose sequence line is ``item_line``.

    Matches the finding's line against the recorded ``tmpfs[i]`` lines so the
    fixer edits the entry the finding is about and no other. ``None`` when no
    entry maps to that line -- the finding fell back to the ``tmpfs:`` key line,
    which happens for a flow-style list.
    """
    for index in range(len(tmpfs)):
        if lines.get(f"services.{service}.tmpfs[{index}]") == item_line:
            return tmpfs[index]
    return None
