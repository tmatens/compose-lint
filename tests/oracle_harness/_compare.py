"""Put compose-lint's view of a project beside Compose's own.

The comparison is a ``(rule_id, service)`` multiset, for the reason
``test_merge_fuzz`` gives at length: Compose's resolved output is *normalised*,
rules derive evidence from the spelling the user wrote, and comparing evidence
would report a disagreement that exists only between two renderings of one
configuration. Counting rather than set-ing keeps the discrimination that
matters — a merge that drops one of two mounts, or duplicates one, changes the
count even when the rule and service do not.

What this cannot see is the whole argument for the shape comparator: a field no
rule reads can merge to the wrong value with the finding multisets in perfect
agreement, which is how #797 shipped.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from compose_lint._selection import plan_documents
from compose_lint._service_env import resolve_env_files
from compose_lint.engine import run_rules
from compose_lint.parser import ComposeError, load_compose, load_merged

if TYPE_CHECKING:
    from pathlib import Path

FindingCounts = Counter[tuple[str, str]]


@dataclass(frozen=True)
class LintedProject:
    """What a compose-lint run made of a project directory."""

    findings: FindingCounts
    # References the run could not follow, one message each. A non-empty tuple
    # is exit 2: part of the stack was never linted, so its findings are not
    # comparable to a resolved document's.
    gaps: tuple[str, ...] = ()
    # The run refused the project outright (a parse error, an unlintable
    # document in the merge set).
    error: str | None = None

    @property
    def refused(self) -> bool:
        return bool(self.gaps) or self.error is not None


def findings_of(
    data: dict[str, Any], lines: dict[str, int], base_dir: Path
) -> FindingCounts:
    """Findings as a ``(rule, service)`` multiset, suppressions excluded.

    ``env_file:`` targets are resolved the way the CLI resolves them, because
    the comparison would otherwise be rigged: Compose folds an ``env_file:``
    into the ``environment:`` it emits, so the credential rules see those keys
    on the truth side no matter what. Without the same input on our side every
    generated project with an ``env_file:`` reports a disagreement that says
    nothing about the loader.
    """
    return Counter(
        (f.rule_id, str(f.service))
        for f in run_rules(data, lines, env_files=resolve_env_files(data, base_dir))
        if not f.suppressed
    )


def lint_project(primary: Path) -> LintedProject:
    """Grade ``primary`` the way the CLI would, overlay discovery included.

    Going through ``plan_documents`` rather than handing ``load_merged`` a file
    list is deliberate: which documents Compose pairs together is part of what
    the harness is checking, so the selection layer has to be inside the
    comparison rather than assumed by it.
    """
    selection = plan_documents([str(primary)])
    if not selection.groups:
        return LintedProject(findings=Counter(), error="no document selected")
    group = selection.groups[0]
    try:
        merged = load_merged(list(group.paths))
    except ComposeError as exc:
        return LintedProject(findings=Counter(), error=str(exc))
    if merged.gaps:
        return LintedProject(findings=Counter(), gaps=merged.gaps)
    return LintedProject(
        findings=findings_of(merged.data, merged.lines, primary.absolute().parent)
    )


def truth_findings(resolved: str, scratch: Path) -> FindingCounts:
    """The same rules, run over the configuration Compose resolved.

    ``scratch`` is deliberately outside the generated project: the truth
    document is not part of the stack under test, and a stray file inside it
    could be picked up by a discovery step the harness is trying to observe.
    """
    scratch.mkdir(parents=True, exist_ok=True)
    truth_file = scratch / "truth.yaml"
    truth_file.write_text(resolved)
    data, lines = load_compose(truth_file)
    return findings_of(data, lines, scratch)


def describe_difference(ours: FindingCounts, theirs: FindingCounts) -> str:
    """The two directions of a disagreement, for an assertion message."""
    return (
        f"  only ours:   {sorted((ours - theirs).elements())}\n"
        f"  only theirs: {sorted((theirs - ours).elements())}"
    )
