"""Configuration file loading for compose-lint."""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from compose_lint._output import emit
from compose_lint._safe_read import containment_root, read_text_bounded, resolved
from compose_lint._scalar import as_scalar_text
from compose_lint._yaml_error import describe_yaml_error
from compose_lint.models import Severity

if TYPE_CHECKING:
    from collections.abc import Collection

# Top-level keys the config schema defines today (docs/configuration.md).
# Anything else is almost certainly a typo or a misplaced CLI flag (e.g. a
# top-level `fail_on:`), so we warn rather than silently drop it (issue #279 G1).
# Public because the parser reads it to recognise a compose-lint config that
# was handed to the linter as if it were a Compose file (ADR-013, issue #499);
# keeping one definition means a new config key can never drift out of that
# check.
KNOWN_TOP_LEVEL_KEYS = frozenset({"rules"})

# Recognized keys inside a per-rule block. A key outside this set (a typo'd
# `severty:`) is silently inert; warn so the user learns their override never
# took effect (issue #279 G1). A `reason:` without `enabled: false` is a
# separate diagnostic in `_parse_rules` (issue #723).
_KNOWN_RULE_KEYS = frozenset(
    {"enabled", "reason", "severity", "exclude_services", "expires"}
)

# Recognized keys inside a mapping-form `exclude_services` entry (ADR-041).
# The entry is a mapping so that a later key has somewhere to go; until one
# is defined, anything else is a typo and warns like an unknown rule key.
_KNOWN_ENTRY_KEYS = frozenset({"reason", "expires"})

# `expires:` is a calendar date and nothing else (ADR-041 §3). PyYAML resolves
# an unquoted `2027-03-31` to a `date` and a quoted one stays a string; the
# pattern is applied to the string form because `date.fromisoformat` also
# accepts `20270331` and week dates, which a reader of the policy file would
# not recognise as the same day.
_ISO_DATE = re.compile(r"\A\d{4}-\d{2}-\d{2}\Z")

# The file names an implicit run (no `--config`) looks for, in precedence
# order, in the directories `config_search_dirs` names. `.yml` has been the
# documented name from the start; `.yaml` is accepted because the pre-commit
# hook already excluded both spellings as config files, so a repository using
# the second one had its policy skipped by the hook and ignored by the linter
# at once — every suppression silently absent, with nothing naming why. When
# both exist the first wins and `_read_raw_config` says so.
CONFIG_FILENAMES: tuple[str, ...] = (".compose-lint.yml", ".compose-lint.yaml")


class ConfigError(Exception):
    """Raised when a config file is invalid."""


def _warn(message: str, strict: bool = False) -> None:
    """Emit a config diagnostic — a stderr warning, or a hard error under strict.

    A misconfiguration that silently weakens a security control should be
    visible, but config and Compose files evolve independently, so by default
    it must not hard-fail the run (ADR-010). Under strict-config
    (``--strict-config``, #380) the same diagnostics are raised as
    ``ConfigError`` instead, so a typo'd rule id or key fails loudly rather
    than silently no-op'ing where stderr may be suppressed.

    Every call site carries a ``# diag: <slug>`` comment naming the bullet that
    documents it in ``docs/configuration.md``; ``tests/test_config_surfaces.py``
    holds the two sides together. See that module for why.
    """
    if strict:
        raise ConfigError(message)
    emit(f"Warning: {message}")


def config_search_dirs(start: Path | None = None) -> list[Path]:
    """Return the directories an implicit run looks in, nearest first.

    ``start`` is the directory of the first compose file the run lints — the
    directory Compose itself treats as the project directory — so
    ``compose-lint app/docker-compose.yml`` reads ``app/.compose-lint.yml``
    from wherever it was run. The working directory follows as the fallback,
    which keeps a config at the root of a checkout applying to compose files
    in subdirectories that have none of their own (ADR-039). Parents are not
    searched: which file is in force should be answerable by looking in two
    places, and the banner names the one that was read.
    """
    dirs = [Path(".")]
    if start is not None and resolved(start) != resolved(Path.cwd()):
        dirs.insert(0, start)
    return dirs


def _present_in(directory: Path) -> list[Path]:
    """The config file names that exist in ``directory``, in precedence order."""
    return [
        directory / name for name in CONFIG_FILENAMES if (directory / name).exists()
    ]


def discover_config_path(start: Path | None = None) -> Path | None:
    """Return the config file an implicit run would read, or None.

    Pure: the both-spellings warning belongs to ``load_config``, which knows
    whether the run is strict, so the CLI can ask this a second time — to name
    the file in the banner — without the warning printing twice.
    """
    for directory in config_search_dirs(start):
        present = _present_in(directory)
        if present:
            return present[0]
    return None


def _known_rule_ids() -> set[str]:
    """Return the set of registered rule IDs for config validation."""
    from compose_lint.rules import get_registered_rules

    return {cls().metadata.id for cls in get_registered_rules()}


def _parse_severity(value: str) -> Severity:
    """Parse a severity string from config."""
    try:
        return Severity(value.lower())
    except ValueError:
        choices = ", ".join(s.value for s in Severity)
        raise ConfigError(
            f"Invalid severity '{value}' in config (choose from {choices})"
        ) from None


ExcludedServices = dict[str, dict[str, str | None]]


@dataclass(frozen=True)
class Expiries:
    """The expiry dates a config gave its suppressions (ADR-041).

    Kept beside the reason maps rather than inside them, so a config with no
    ``expires:`` loads to exactly the structures it always did. ``rules``
    holds the date beside a rule-level ``enabled: false``; ``services`` holds
    the date on each ``exclude_services`` entry, by rule id then service.
    """

    rules: dict[str, datetime.date] = field(default_factory=dict)
    services: dict[str, dict[str, datetime.date]] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.rules or self.services)


@dataclass(frozen=True)
class Policy:
    """Everything a ``.compose-lint.yml`` tells the engine."""

    disabled: dict[str, str | None] = field(default_factory=dict)
    overrides: dict[str, Severity] = field(default_factory=dict)
    excluded: ExcludedServices = field(default_factory=dict)
    expiries: Expiries = field(default_factory=Expiries)


class _StrictLoader(yaml.SafeLoader):
    """A SafeLoader that refuses duplicate mapping keys.

    Plain YAML resolves a duplicate key last-wins and says nothing, so a policy
    file listing a rule twice silently kept only the second entry. That is the
    worst failure mode a policy file has: the reviewer reads a config that
    disables a rule "with a reason", ships it, and the rule is on — or off —
    depending on which duplicate happened to be last. The parser already
    refuses duplicates in Compose documents for the same reason; the config
    loader was the one door left open.
    """


def _reject_duplicate_config_keys(
    loader: _StrictLoader, node: yaml.MappingNode
) -> dict[Any, Any]:
    seen: set[Any] = set()
    for key_node, _value_node in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            # The `<<` merge directive, not a data key. `construct_object` has
            # no constructor for the merge tag, so calling it aborted the whole
            # run with PyYAML internals — `could not determine a constructor
            # for the tag 'tag:yaml.org,2002:merge'`, exit 2, naming no fix.
            # `parser.py` already skips it the same way for Compose documents,
            # so a `<<:` was legal in the file being linted and fatal in the
            # config beside it.
            continue
        key = _config_key(loader, key_node)
        try:
            duplicate = key in seen
        except TypeError:
            continue  # unhashable key — the construction below reports it
        if duplicate:
            raise yaml.constructor.ConstructorError(
                None,
                None,
                f"found duplicate key {key!r}; the later entry would silently "
                "replace the earlier one",
                key_node.start_mark,
            )
        seen.add(key)
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = _config_key(loader, key_node)
        try:
            hash(key)
        except TypeError as e:
            raise yaml.constructor.ConstructorError(
                None, None, "found unhashable key", key_node.start_mark
            ) from e
        mapping[key] = loader.construct_object(value_node, deep=True)
    return mapping


def _source_text(loader: _StrictLoader, node: yaml.Node) -> Any:
    """Construct ``node``, keeping a plain non-string scalar as its source text.

    The Compose parser keeps a service key like ``2048``, ``yes`` or ``0x10``
    exactly as written (``parser._mapping_key``), because Compose does. A config
    naming that service went through plain YAML instead, which turned it into
    an int or a bool and was refused as "not a service name string", so the
    service could not be excluded at all. Converting after the fact with
    ``str()`` would name a different service (``True`` for ``yes``, ``16`` for
    ``0x10``), so the text is kept at the one point it still exists.

    Applied to mapping keys and to sequence items. Every config key is a name,
    and ``exclude_services`` is the only sequence in the schema, so no value a
    config means as a boolean or a number passes through here.
    """
    value = loader.construct_object(node, deep=True)
    if (
        isinstance(node, yaml.ScalarNode)
        and node.style is None
        and not isinstance(value, str)
    ):
        return node.value
    return value


_config_key = _source_text


def _construct_config_sequence(
    loader: _StrictLoader, node: yaml.SequenceNode
) -> list[Any]:
    return [_source_text(loader, item) for item in node.value]


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _reject_duplicate_config_keys,
)
_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_SEQUENCE_TAG,
    _construct_config_sequence,
)


def load_config(
    path: str | Path | None = None,
    strict: bool = False,
    start: Path | None = None,
) -> tuple[dict[str, str | None], dict[str, Severity], ExcludedServices]:
    """Load a config file as the three maps the engine has always taken.

    The ``expires:`` dates are dropped here; :func:`load_policy` returns them.
    Kept for the callers that grade without a clock.
    """
    policy = load_policy(path, strict, start)
    return policy.disabled, policy.overrides, policy.excluded


def load_policy(
    path: str | Path | None = None,
    strict: bool = False,
    start: Path | None = None,
) -> Policy:
    """Load a .compose-lint.yml (or .compose-lint.yaml) config file.

    Returns a tuple of (disabled_rules, severity_overrides, excluded_services).
    disabled_rules maps rule ID to an optional reason string.
    excluded_services maps rule ID to a mapping of service name to optional
    per-service reason (see ADR-010).
    If path is None, looks for the names in CONFIG_FILENAMES in ``start`` (the
    first compose file's directory) and then the current directory — see
    ``config_search_dirs``; the first directory holding either name wins, and
    when it holds both the first name is used and a diagnostic says so. If no
    config file is found, returns empty defaults.
    When strict is True, config diagnostics that are normally warnings (unknown
    top-level key, unknown/typo'd rule id, unknown rule key, an inert reason or
    severity, both config spellings present) are raised as ConfigError instead
    (#380).
    """
    data = _read_raw_config(path, strict, start)
    if data is None:
        return Policy()

    for key in data:
        name = str(key)
        if name.startswith("x-"):
            # Compose's extension-field convention, which this project already
            # honours in the documents it lints (`parser.py`). Tolerated here
            # because it is the other half of `<<:` support: a merge key needs
            # an anchor to merge *from*, and the idiomatic place to hold one is
            # a top-level `x-` block. Warning on that — and erroring under
            # `--strict-config`, which the docs recommend for CI — would make
            # the anchor idiom unusable in exactly the pipelines that opted
            # into rigor.
            #
            # It costs no typo detection: `x-` is a deliberate marker, so a
            # mistyped `rulez:` is still caught. A bare unknown key still warns.
            continue
        if name not in KNOWN_TOP_LEVEL_KEYS:
            # diag: unknown-top-level-key
            _warn(
                f"config: unknown top-level key '{key}' (recognized: "
                f"{', '.join(sorted(KNOWN_TOP_LEVEL_KEYS))}); it has no effect",
                strict,
            )

    return _parse_rules(data.get("rules", {}), strict)


def _containment_root(config_path: Path) -> Path:
    """The directory a discovered config may not resolve outside of.

    The working directory's own config keeps the boundary it always had. One
    found beside the Compose file is contained the way every other file that
    Compose file leads to is (ADR-038): to the repository holding it, else the
    run directory when that holds it, else its own directory. Deciding that
    by hand from lexical paths refused ``../other/.compose-lint.yml`` and any
    config under a linked directory as an escape it was not.
    """
    if config_path.parent == Path("."):
        return Path.cwd()
    return containment_root(config_path.parent)


def _read_raw_config(
    path: str | Path | None, strict: bool = False, start: Path | None = None
) -> dict[str, Any] | None:
    """Read and parse a config file to a mapping, or None when there is none.

    Returns None when no config file is found (implicit path) or the file is
    empty. Raises ConfigError for an explicitly-named missing file, a read
    error, invalid YAML, or a non-mapping top level.
    """
    if path is not None:
        config_path = Path(path)
        if not config_path.exists():
            raise ConfigError(f"Config file not found: {path}")
    else:
        present = []
        for directory in config_search_dirs(start):
            present = _present_in(directory)
            if present:
                break
        if not present:
            return None
        if len(present) > 1:
            # Two policy files side by side is almost always one being edited
            # while the other is the one in force; a reader has no way to
            # tell which the linter honoured unless it says.
            # diag: both-config-spellings
            _warn(
                f"config: both {' and '.join(CONFIG_FILENAMES)} exist; "
                f"using {present[0]}",
                strict,
            )
        config_path = present[0]

    try:
        # A committed symlink to a FIFO or /dev/zero passes `.exists()` and
        # every permission check; reading one hangs the job or allocates until
        # the runner dies. Same bounded read the Compose loader uses.
        #
        # A discovered config is part of the checkout, not something the user
        # pointed at, so it gets the containment every other file the project
        # names gets: a `.compose-lint.yml` committed as a symlink to a file
        # elsewhere on the runner is refused rather than read. The boundary is
        # the working directory when the config sits inside it, and otherwise
        # the config's own directory — the compose file's, which the user
        # named. `--config` is a path the user typed and is read as given.
        content = read_text_bounded(
            config_path,
            within=None if path is not None else _containment_root(config_path),
        )
    except OSError as e:
        # UnsafeFileError is an OSError, so one clause covers both the refusal
        # and an ordinary read failure.
        raise ConfigError(f"Cannot read config file: {e}") from e
    except UnicodeDecodeError as e:
        # A ValueError, so the clause above missed it and a policy file that is
        # not UTF-8 crashed the run with a traceback and exit 1.
        raise ConfigError(
            f"Cannot read config file: {config_path} is not valid UTF-8 "
            f"(byte {e.start})"
        ) from e

    try:
        data = yaml.load(content, Loader=_StrictLoader)  # noqa: S506  # nosec B506
    except yaml.YAMLError as e:
        # Without the source line PyYAML quotes under its caret: the file may
        # not be the one it appears to be, and the message reaches JSON, SARIF
        # and the job log.
        raise ConfigError(
            f"Invalid YAML in config file: {describe_yaml_error(e)}"
        ) from e
    except RecursionError as e:
        # PyYAML's composer recurses with no depth limit, and RecursionError is
        # a RuntimeError rather than a YAMLError, so it walks straight past the
        # clause above. The Compose loader already translates this; the config
        # loader raised a traceback and exit 1 on the same class of input.
        raise ConfigError(
            "Invalid YAML in config file: input is too deeply nested"
        ) from e

    if data is None:
        return None

    if not isinstance(data, dict):
        raise ConfigError("Config file must be a YAML mapping")

    return data


def _scalar_field(value: Any, rule_id: str, field: str) -> str | None:
    """Coerce a config value to text, refusing a container.

    ``str()`` on a YAML node is only safe if the node is a scalar. PyYAML shares
    aliased nodes by reference, so `reason: *l22` loads in about a millisecond
    and serializes as a *tree* — a 579-byte config produced 151 MB. The sibling
    ``enabled`` field already type-checks strictly for a related reason (a
    quoted ``'false'`` would silently leave the rule on); ``reason``,
    ``severity`` and the exclusion reasons simply missed that treatment.

    Refusing is right rather than merely safe: a list is not a reason, and a
    policy file that contains one is malformed in a way the author wants to know
    about.
    """
    if value is None:
        return None
    text = as_scalar_text(value)
    if text is None:
        raise ConfigError(
            f"Config for rule '{rule_id}': '{field}' must be a scalar, "
            f"not a {type(value).__name__}"
        )
    return text


def _parse_expires(value: Any, where: str) -> datetime.date:
    """Read an ``expires:`` value as a calendar date (ADR-041 §3).

    An unquoted ``2027-03-31`` arrives as a ``date``; a quoted one as a
    string. A time of day is refused rather than truncated: the comparison is
    by UTC date, and a value that names an hour promises a precision the
    check does not keep.
    """
    if isinstance(value, datetime.datetime):
        raise ConfigError(
            f"Config {where}: 'expires' must be a date (YYYY-MM-DD) with no "
            f"time of day, not {value.isoformat()!r}"
        )
    if isinstance(value, datetime.date):
        return value
    if isinstance(value, str) and _ISO_DATE.match(value):
        try:
            return datetime.date.fromisoformat(value)
        except ValueError:
            pass
    raise ConfigError(
        f"Config {where}: 'expires' must be a date written YYYY-MM-DD, not {value!r}"
    )


def _parse_rules(
    rules: Any,
    strict: bool = False,
) -> Policy:
    """Parse the rules section of a config file."""
    if rules is None:
        rules = {}
    if not isinstance(rules, dict):
        raise ConfigError("'rules' must be a mapping")

    disabled: dict[str, str | None] = {}
    overrides: dict[str, Severity] = {}
    excluded: ExcludedServices = {}
    expiries = Expiries()
    known_ids = _known_rule_ids()

    for rule_id, rule_config in rules.items():
        rule_id = str(rule_id)

        if rule_config is None:
            rule_config = {}
        if not isinstance(rule_config, dict):
            raise ConfigError(f"Config for rule '{rule_id}' must be a mapping")

        if rule_id not in known_ids:
            # diag: unknown-rule-id
            _warn(
                f"config: unknown rule id '{rule_id}'; the override has no effect "
                "(check for a typo or a retired rule)",
                strict,
            )

        for key in rule_config:
            if str(key) not in _KNOWN_RULE_KEYS:
                # diag: unknown-per-rule-key
                _warn(
                    f"config: rule '{rule_id}' has unknown key '{key}' (recognized: "
                    f"{', '.join(sorted(_KNOWN_RULE_KEYS))}); it has no effect",
                    strict,
                )

        if "enabled" in rule_config:
            enabled = rule_config["enabled"]
            if not isinstance(enabled, bool):
                raise ConfigError(
                    f"Config for rule '{rule_id}': 'enabled' must be true or false, "
                    f"not {enabled!r} — a quoted 'false', 0, or no would otherwise "
                    "silently leave the rule on"
                )
            if enabled is False:
                disabled[rule_id] = _scalar_field(
                    rule_config.get("reason"), rule_id, "reason"
                )

        if "reason" in rule_config and rule_id not in disabled:
            # diag: reason-without-enabled-false
            _warn(
                f"config: rule '{rule_id}' has a 'reason' without "
                f"'enabled: false'; it has no effect",
                strict,
            )

        if "expires" in rule_config:
            # Validated whether or not it is in force, so a malformed date is
            # reported where it is written rather than when the rule is
            # later disabled.
            expires = _parse_expires(rule_config["expires"], f"for rule '{rule_id}'")
            if rule_id in disabled:
                if not disabled[rule_id]:
                    raise ConfigError(
                        f"Config for rule '{rule_id}': an 'expires' date needs a "
                        "'reason' beside it (ADR-041)"
                    )
                expiries.rules[rule_id] = expires
            else:
                # diag: expires-without-enabled-false
                _warn(
                    f"config: rule '{rule_id}' has an 'expires' without "
                    f"'enabled: false'; it has no effect",
                    strict,
                )

        if "severity" in rule_config:
            severity_text = _scalar_field(rule_config["severity"], rule_id, "severity")
            if severity_text is None:
                raise ConfigError(f"Config for rule '{rule_id}': 'severity' is empty")
            overrides[rule_id] = _parse_severity(severity_text)
            if rule_id in disabled:
                # The engine never re-grades a suppressed finding (a disabled
                # rule's findings are all suppressed), so the key is inert —
                # the same shape as a lone `reason:` above, and the same
                # silence: a reader sees a rule re-tuned to LOW and does not
                # see that it is off. The value is still validated, and kept,
                # so re-enabling the rule later takes effect without a second
                # edit.
                # diag: severity-on-disabled-rule
                _warn(
                    f"config: rule '{rule_id}' has a 'severity' but is disabled; "
                    "the override has no effect",
                    strict,
                )

        if "exclude_services" in rule_config:
            reasons, dates = _parse_exclude_services(
                rule_id, rule_config["exclude_services"], strict
            )
            excluded[rule_id] = reasons
            if dates:
                expiries.services[rule_id] = dates

    return Policy(disabled, overrides, excluded, expiries)


def warn_unknown_excluded_services(
    excluded: ExcludedServices,
    seen_services: Collection[str],
    strict: bool = False,
) -> None:
    """Flag an ``exclude_services`` name no linted file defines (ADR-010).

    The one config diagnostic that cannot be raised on load: whether a name is
    stale is known only once every file has been read, so the CLI calls this
    after the scan. A stale name is the same class of fault as a typo'd rule
    id — an exclusion the author believes is in effect and is not, because
    the service was renamed or never existed under that spelling. By default
    it warns, because config and Compose files evolve independently and a
    rename must not break the linter; under strict it raises like the rest,
    and the CLI carries that onto the machine channel and exits 2.
    """
    for rule_id, services_map in excluded.items():
        for service_name in services_map:
            if service_name not in seen_services:
                # diag: unknown-excluded-service
                _warn(
                    f"config: exclude_services for {rule_id} references "
                    f"unknown service '{service_name}'",
                    strict,
                )


def _parse_exclusion_entry(
    rule_id: str, service_name: str, entry: dict[Any, Any], strict: bool
) -> tuple[str | None, datetime.date | None]:
    """Read a mapping-form entry, ``{reason, expires}`` (ADR-041 §1)."""
    for key in entry:
        if str(key) not in _KNOWN_ENTRY_KEYS:
            # diag: unknown-exclusion-entry-key
            _warn(
                f"config: exclude_services for {rule_id} entry '{service_name}' "
                f"has unknown key '{key}' (recognized: "
                f"{', '.join(sorted(_KNOWN_ENTRY_KEYS))}); it has no effect",
                strict,
            )
    field_name = f"exclude_services[{service_name}].reason"
    reason = _scalar_field(entry.get("reason"), rule_id, field_name)
    if "expires" not in entry:
        return reason, None
    expires = _parse_expires(
        entry["expires"],
        f"for rule '{rule_id}', exclude_services entry '{service_name}'",
    )
    if not reason:
        raise ConfigError(
            f"Config for rule '{rule_id}': exclude_services entry "
            f"'{service_name}' has an 'expires' date and needs a 'reason' "
            "beside it (ADR-041)"
        )
    return reason, expires


def _parse_exclude_services(
    rule_id: str, value: Any, strict: bool = False
) -> tuple[dict[str, str | None], dict[str, datetime.date]]:
    """Parse an exclude_services value into reasons and expiry dates.

    Accepts None (empty mapping), a list of service names (no reasons), or a
    mapping of service name to an entry. An entry is a reason string, null,
    or a mapping ``{reason, expires}`` (ADR-041). Returns the service-name to
    reason mapping the engine has always taken, and the dates of the entries
    that gave one.
    """
    dates: dict[str, datetime.date] = {}
    if value is None:
        return {}, dates
    if isinstance(value, list):
        result: dict[str, str | None] = {}
        for item in value:
            if not isinstance(item, str):
                raise ConfigError(
                    f"exclude_services for '{rule_id}' list entries must be "
                    "service name strings"
                )
            result[item] = None
        return result, dates

    if isinstance(value, dict):
        result = {}
        for service_name, reason in value.items():
            if not isinstance(service_name, str):
                raise ConfigError(
                    f"exclude_services for '{rule_id}' keys must be "
                    "service name strings"
                )
            if isinstance(reason, dict):
                result[service_name], expires = _parse_exclusion_entry(
                    rule_id, service_name, reason, strict
                )
                if expires is not None:
                    dates[service_name] = expires
                continue
            result[service_name] = _scalar_field(
                reason, rule_id, f"exclude_services[{service_name}]"
            )
        return result, dates

    raise ConfigError(f"exclude_services for '{rule_id}' must be a list or mapping")
