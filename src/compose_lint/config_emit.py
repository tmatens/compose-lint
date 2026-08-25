"""Render a starter ``.compose-lint.yml`` from lint findings (ADR-011).

``compose-lint init`` runs the rules with no existing config, then hands the raw
findings here to produce a config the user edits to triage suppressions. Every
finding becomes a per-service ``exclude_services`` entry with a placeholder
reason. The encoding is deliberately service-level — never a global
``enabled: false``: naming each service fails safe, so a rule still fires on a
service added to the Compose file later instead of being silently uncovered.

This module is intentionally outside ``formatters/``. It does not satisfy the
``format(findings) -> str`` contract: it needs rule metadata (names) and emits a
different artifact, not rendered findings.
"""

from __future__ import annotations

import re

import yaml

from compose_lint.models import Finding, Severity

_PLACEHOLDER_REASON = "TODO: justify or fix"
_DOCS_URL = "https://github.com/tmatens/compose-lint/blob/main/docs/configuration.md"

# Sort key for severity, most severe first. Kept local (rather than reaching into
# Severity._rank) so the emitter owns its own public ordering.
_SEVERITY_RANK = {
    Severity.CRITICAL: 3,
    Severity.HIGH: 2,
    Severity.MEDIUM: 1,
    Severity.LOW: 0,
}

# A YAML plain scalar safe to emit unquoted: an identifier-ish token with no
# characters that would change the parse. Anything else is double-quoted.
#
# `\A`/`\Z`, not `^`/`$`: in Python `$` also matches *before* a trailing
# newline, so a service named "web\n" passed this check and was emitted
# unquoted — a bare newline in the middle of a mapping key.
_PLAIN_SCALAR = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]*\Z")


def _round_trips_as_itself(value: str) -> bool:
    """Whether ``value`` unquoted reloads as the same *string*.

    The pattern above says the characters are safe; it does not say the
    *token* is. YAML 1.1 resolves a set of bare words and numerals to
    non-strings, and every one of them matches an identifier-ish pattern:
    ``no``/``yes``/``on``/``off``/``true``/``false`` become booleans,
    ``123`` an int, ``1.5`` a float, ``null`` None. Compose service names
    are unrestricted, so all of these are legal names.

    Emitted unquoted, such a name reloads as a bool or an int, and
    ``config.py`` requires ``exclude_services`` keys to be strings — so
    ``init`` wrote a config that ``check`` then refused, exit 2, breaking
    that directory until someone edited the file by hand. That is the exact
    failure this module's docstring says it exists to prevent, arriving
    through the token rather than through the characters.

    Asking PyYAML to reload it is the check that cannot drift: the resolver
    that decides the type is the same one that will read the file back.
    """
    try:
        return bool(yaml.safe_load(value) == value)
    except yaml.YAMLError:  # pragma: no cover - the pattern excludes these
        return False


def _scalar(value: str) -> str:
    """Render a string as a YAML scalar, quoting only when necessary.

    Quoting is delegated to PyYAML rather than hand-rolled. The previous
    version escaped `\\` and `"` and nothing else, so a service name carrying a
    newline produced a config that does not parse — and `init` reported success
    while writing it, which broke every later run in that directory with
    `Invalid YAML in config file`, exit 2. Durable corruption from one lint of
    one hostile file.

    Escaping is the kind of thing that is nearly right until it meets the next
    character class; the emitter that owns the format should decide.
    """
    if _PLAIN_SCALAR.match(value) and _round_trips_as_itself(value):
        return value
    # `default_style='"'` forces the double-quoted form, which is what this
    # emitter wants and which yields a single line with no document markers.
    return yaml.safe_dump(
        value, default_style='"', width=10**9, allow_unicode=True
    ).rstrip("\n")


def _rule_names() -> dict[str, str]:
    """Map rule id to human name for the per-rule annotation comment."""
    from compose_lint.rules import get_registered_rules

    return {cls().metadata.id: cls().metadata.name for cls in get_registered_rules()}


def render_config(findings: list[Finding]) -> str:
    """Render a starter ``.compose-lint.yml`` from ``findings``.

    ``findings`` must be non-empty; the caller handles the no-findings case.
    Rules are ordered by severity (most severe first), then by id. Services
    within a rule are sorted, and each ``(rule, service)`` pair appears once even
    if a rule fired more than once on the same service.
    """
    by_rule: dict[str, set[str]] = {}
    severities: dict[str, Severity] = {}
    for f in findings:
        by_rule.setdefault(f.rule_id, set()).add(f.service)
        # Last writer per rule wins, which is only sound because severity is
        # rule-stable here: init runs with an empty config, so no per-rule
        # override applies, and every rule emits exactly one severity — an
        # invariant tests/test_rule_consistency.py enforces through its
        # deliberately empty VARIABLE_SEVERITY_RULES allow-list.
        #
        # This was false when #503 was filed: CL-0011 and CL-0013 branched, and
        # this line labelled them by whichever finding the rule emitted last.
        # Both stopped branching when the capability and host-path splits gave
        # each tier its own id. Putting an entry back on that allow-list
        # silently reinstates the mislabelling here, so a branching rule needs
        # this to take the highest severity per rule rather than the last.
        severities[f.rule_id] = f.severity

    names = _rule_names()

    lines = [
        "# .compose-lint.yml — generated by `compose-lint init`",
        "#",
        "# Each entry suppresses a finding compose-lint reported. Replace the",
        "# placeholder reason with a real justification, or delete the entry and",
        "# fix the underlying issue. Suppressed findings still appear in output",
        "# (marked SUPPRESSED) and no longer count toward --fail-on.",
        "#",
        "# Review CRITICAL and HIGH entries first — prefer fixing over suppressing.",
        f"# Docs: {_DOCS_URL}",
        "",
        "rules:",
    ]
    for rule_id in sorted(by_rule, key=lambda r: (-_SEVERITY_RANK[severities[r]], r)):
        label = severities[rule_id].value.upper()
        name = names.get(rule_id)
        if name:
            label = f"{label} — {name}"
        lines.append(f"  {_scalar(rule_id)}:  # {label}")
        lines.append("    exclude_services:")
        for service in sorted(by_rule[rule_id]):
            lines.append(f"      {_scalar(service)}: {_scalar(_PLACEHOLDER_REASON)}")

    return "\n".join(lines) + "\n"
