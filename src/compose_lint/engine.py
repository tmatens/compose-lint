"""Rule engine that runs registered rules against parsed Compose data."""

from __future__ import annotations

import re
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from compose_lint._limits import MAX_FINDINGS
from compose_lint._output import emit
from compose_lint.models import Finding, Severity
from compose_lint.rules import get_registered_rules

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from compose_lint._service_env import ServiceEnvFiles


class FindingLimitError(Exception):
    """A document produced more findings than one run grades.

    ``findings`` are the ones graded before grading stopped, sorted and
    quoted as :func:`run_rules` sorts and quotes its result, so a caller that
    accepts the gap can still report them.
    """

    def __init__(self, findings: list[Finding]) -> None:
        super().__init__(
            f"grading stopped after {len(findings)} findings (the limit is "
            f"{MAX_FINDINGS}), so the rest of this "
            "document was not graded. That many findings means a shared list "
            "multiplied by the services that use it; lint the document with "
            "fewer aliases of it, or split the stack."
        )
        self.findings = findings


def _default_rule_error(rule_id: str, service_name: str, exc: Exception) -> None:
    """Report a crashed rule to stderr without aborting the run."""
    emit(
        f"Error: rule {rule_id} failed on service '{service_name}': "
        f"{type(exc).__name__}: {exc}"
    )


def run_rules(
    data: dict[str, Any],
    lines: dict[str, int],
    disabled_rules: dict[str, str | None] | None = None,
    severity_overrides: dict[str, Severity] | None = None,
    excluded_services: dict[str, dict[str, str | None]] | None = None,
    on_error: Callable[[str, str, Exception], None] | None = None,
    env_files: Mapping[str, ServiceEnvFiles] | None = None,
    config_path: str | None = None,
    env_values: Mapping[str, Mapping[str, str]] | None = None,
) -> list[Finding]:
    """Run all registered rules against the parsed Compose data.

    Disabled rules and per-service exclusions still produce findings, but
    those findings are marked suppressed with an appropriate reason. A
    global disable takes precedence over per-service exclusions (see
    ADR-010). Returns findings sorted by line number (None-line last).

    ``env_files`` carries what each service's ``env_file:`` targets contribute
    (ADR-027). It reaches rules through :meth:`BaseRule.check_env_file_keys`
    rather than through ``service_config``, because those keys are not in the
    document: merging them into the ``environment:`` a rule sees would put
    values in the parsed document that nobody wrote there, and would expose
    them to every rule rather than the two that grade them.

    ``config_path`` is the config file the suppressions were read from, as the
    user named it. It goes into ``suppressed_by`` so the text report points a
    reader at the file that was actually read rather than at the conventional
    ``.compose-lint.yml``, which is what it defaults to. ``suppression_reason``
    carries only a reason the config wrote (ADR-015).

    A rule that raises is isolated rather than allowed to abort the whole
    run: the failure is reported via ``on_error`` (defaulting to a stderr
    diagnostic) and the engine continues with the next service and rule. The
    CLI maps such a failure to exit 2 ("compose-lint itself couldn't run",
    ADR-006) so a directory sweep is never silently truncated and a crash is
    never mistaken for a clean lint failure.

    More than :data:`~compose_lint._limits.MAX_FINDINGS` findings raises
    :class:`FindingLimitError` carrying the ones graded so far.

    ``env_values`` is what a ``.env`` substituted into the document: for each
    substituted value, the names and values it used (``Loaded.env_values``).
    Rules grade the substituted value, which is what deploys, but a finding
    quotes ``${NAME}`` in its place. Some CI jobs write secrets into that
    ``.env``, and a message is copied into the job log, JSON and the SARIF
    uploaded to Code Scanning; ``image: "${DB_PASSWORD}"`` quoted the password
    in CL-0004's message and fix. The reference says as much as the value
    would, and it is what the file shows.
    """
    disabled = disabled_rules or {}
    overrides = severity_overrides or {}
    excluded = excluded_services or {}
    report_error = on_error if on_error is not None else _default_rule_error
    config_name = config_path or ".compose-lint.yml"
    findings: list[Finding] = []

    rule_classes = get_registered_rules()
    rules = [cls() for cls in rule_classes]

    services = data.get("services", {})

    for rule in rules:
        rule_id = rule.metadata.id
        # One rule's findings on each shared `env_file:` key set, graded once.
        graded: dict[int, tuple[tuple[Any, ...], list[Finding]]] = {}
        is_suppressed = rule_id in disabled
        rule_excluded = excluded.get(rule_id, {})

        for service_name, service_config in services.items():
            try:
                rule_findings = list(
                    rule.check(service_name, service_config, data, lines)
                )
                contributed = (env_files or {}).get(service_name)
                if contributed is not None and contributed.keys:
                    rule_findings += _env_file_findings(
                        rule, service_name, contributed, service_config, graded
                    )
            except Exception as exc:  # noqa: BLE001 - isolate a crashing rule
                report_error(rule_id, service_name, exc)
                continue
            for finding in rule_findings:
                # A severity override only makes sense on a finding that will be
                # reported: if the rule is globally suppressed the finding is
                # already suppressed below, so re-grading its severity is moot.
                if rule_id in overrides and not is_suppressed:
                    if overrides[rule_id] != finding.severity:
                        finding = replace(
                            finding,
                            severity=overrides[rule_id],
                            severity_overridden_from=finding.severity,
                        )
                    else:
                        finding = replace(finding, severity=overrides[rule_id])
                # Suppression precedence: a global disable (whole rule off) wins
                # over a per-service exclusion. Both set suppressed=True, but the
                # reason differs, so this must be if/elif, not two independent
                # ifs — the broader, rule-level intent owns the reason string.
                # A rule that is globally disabled is never also labeled with a
                # narrower "excluded for service X" reason.
                if is_suppressed:
                    finding = replace(
                        finding,
                        suppressed=True,
                        suppression_reason=disabled[rule_id] or None,
                        suppressed_by=f"disabled in {config_name}",
                    )
                elif service_name in rule_excluded:
                    finding = replace(
                        finding,
                        suppressed=True,
                        suppression_reason=rule_excluded[service_name] or None,
                        suppressed_by=(
                            f"excluded for service '{service_name}' in {config_name}"
                        ),
                    )
                findings.append(finding)
            if len(findings) > MAX_FINDINGS:
                # Quote before raising: the caller reports these findings, so
                # they must not carry a value a reference resolved to either.
                if env_values:
                    findings = _quote_references(findings, services, env_values)
                findings.sort(key=lambda f: (f.line is None, f.line or 0))
                raise FindingLimitError(findings)

    if env_values:
        findings = _quote_references(findings, services, env_values)
    findings.sort(key=lambda f: (f.line is None, f.line or 0))
    return findings


# Nodes one service's walk may visit before its references are taken from the
# whole document instead. Aliases make a service a DAG that can be far larger
# than the file; the fallback only ever quotes more references, never fewer.
_MAX_WALK = 100_000


def _quote_references(
    findings: list[Finding],
    services: Mapping[Any, Any],
    env_values: Mapping[str, Mapping[str, str]],
) -> list[Finding]:
    """Replace each ``.env`` value a service used with its ``${NAME}``.

    Scoped to the values that reached *that* service's own substituted fields,
    so a literal ``redis:latest`` in one service is not rewritten because
    another service's ``${TAG}`` supplied ``latest``. Within a service a value
    is replaced wherever it appears, from :data:`_QUOTED_FROM` characters up.
    """
    patterns: dict[str, tuple[re.Pattern[str], dict[str, str]] | None] = {}
    quoted: list[Finding] = []
    for finding in findings:
        if finding.service not in patterns:
            patterns[finding.service] = _service_pattern(
                services.get(finding.service), env_values
            )
        compiled = patterns[finding.service]
        if compiled is None:
            quoted.append(finding)
            continue
        pattern, names = compiled

        def sub(
            text: str, _p: re.Pattern[str] = pattern, _n: dict[str, str] = names
        ) -> str:
            return _p.sub(lambda m: "${" + _n[m.group(0)] + "}", text)

        quoted.append(
            replace(
                finding,
                message=sub(finding.message),
                fix=sub(finding.fix) if finding.fix else finding.fix,
            )
        )
    return quoted


def _service_pattern(
    config: Any, env_values: Mapping[str, Mapping[str, str]]
) -> tuple[re.Pattern[str], dict[str, str]] | None:
    """A regex matching every ``.env`` value ``config`` used, and its names."""
    used: dict[str, str] = {}
    seen: set[int] = set()
    stack = [config]
    visited = 0
    while stack:
        node = stack.pop()
        visited += 1
        if visited > _MAX_WALK:
            used = {}
            for leaf_names in env_values.values():
                used.update(leaf_names)
            break
        if isinstance(node, str):
            used.update(env_values.get(node, {}))
        elif isinstance(node, (dict, list)):
            if id(node) in seen:
                continue
            seen.add(id(node))
            stack.extend(node.values() if isinstance(node, dict) else node)
    if not used:
        return None
    names: dict[str, str] = {}
    for name, value in used.items():
        # The whole value, and each separated part of it: a rule quotes pieces
        # of what it parsed (CL-0004's fix names the image without its tag), so
        # a secret inside the value would otherwise leave in a fragment.
        for piece in (value, *_SEPARATORS.split(value)):
            if len(piece) >= _QUOTED_FROM:
                names.setdefault(piece, name)
    if not names:
        return None
    alternatives = "|".join(
        re.escape(value) for value in sorted(names, key=len, reverse=True)
    )
    return re.compile(alternatives), names


# The shortest value replaced by its reference. A secret is often glued to the
# text around it (`image: "app${TOKEN}"`), so a value is matched anywhere, not
# as a whole word, and that is what makes a floor necessary: short values are
# configuration tokens (`true`, `host`, `latest`, `1000`) that the rules' own
# guidance also writes, and replacing them there turned `no-new-privileges:true`
# into `no-new-privileges:${PRIV}`. A value a CI job writes as a secret is
# longer than this.
_QUOTED_FROM = 8

# What rules split a value on before quoting part of it: image references,
# ports, mounts, `key=value` options, lists.
_SEPARATORS = re.compile(r"[:/@=,;\s]+")


def filter_findings(
    findings: list[Finding],
    severity_threshold: Severity = Severity.HIGH,
) -> list[Finding]:
    """Filter findings to only those at or above the severity threshold.

    Suppressed findings are excluded regardless of severity.
    """
    return [
        f for f in findings if f.severity >= severity_threshold and not f.suppressed
    ]


def _env_file_findings(
    rule: Any,
    service_name: str,
    contributed: ServiceEnvFiles,
    service_config: dict[str, Any],
    graded: dict[int, tuple[tuple[Any, ...], list[Finding]]],
) -> list[Finding]:
    """``rule``'s findings on one service's ``env_file:`` keys.

    Services naming the same files share one ``available`` tuple, and the
    rules that grade it read only the keys (the contract on
    :meth:`BaseRule.check_env_file_keys`). So the tuple is graded once and each
    service gets those findings under its own name, less the keys its own
    ``environment:`` shadows. Grading it per service cost the file's keys times
    the services: 20,000 keys named by 2,000 services ran for over a minute.
    """
    available = contributed.available
    cached = graded.get(id(available))
    if cached is None or cached[0] is not available:
        template = list(rule.check_env_file_keys("", available, service_config))
        cached = (available, template)
        graded[id(available)] = cached
    shadowed = contributed.shadowed
    return [
        replace(finding, service=service_name)
        for finding in cached[1]
        if finding.evidence not in shadowed
    ]
