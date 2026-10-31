"""The units a Compose file deploys: what the engine hands each rule (ADR-040).

A unit is a container the file deploys, or a command it runs inside one:

- every ``services.<name>`` whose ``provider`` is not a mapping (issue #1186);
- every ``services.<name>.pre_start[i]``, an init container run to completion
  before the service starts (Compose 5.3.0);
- every ``services.<name>.post_start[i]`` and ``pre_stop[i]``, a command
  executed inside the running container (Compose 2.30.0);
- every ``jobs.<name>``, a run-to-completion container started by
  ``docker compose run`` (Compose 5.6.0).

A unit's name is its document path below ``services.`` (``app.pre_start[0]``,
``jobs.migrate``), and it is what a finding's ``service`` field carries. Every
rule builds its line paths as ``services.<name>.<key>``, so a hook's paths
resolve in the parser's line map unchanged, and a job's resolve through an
alias (:class:`UnitLines`).

The parser imports :func:`container_specs` to resolve bind sources and
``env_file:`` paths on every container, not only on services, so this module
must not import the parser or the rules.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

PRE_START = "pre_start"
EXEC_HOOKS = ("post_start", "pre_stop")

# The keys an exec hook is graded on (ADR-040 §4). `environment` is the hook's
# own; `user` and `working_dir` overlay the parent's scalars.
_EXEC_SCALARS = ("user", "working_dir")
# Keys an exec hook writes that are not graded: `command` is the exec itself,
# and `privileged` on an exec is not the grant CL-0002 describes (measured on
# Compose 5.6.1: seccomp stays in filter mode and the device cgroup enforced).
# The parent's value for either is still in the mapping, so its path on the
# hook is hidden from the rules; otherwise a parent's `privileged: true` would
# be reported at the line of a hook's `privileged: false`.
_EXEC_UNGRADED = ("command", "privileged")

_INDEX = re.compile(r"\[\d+\]$")


@dataclass(frozen=True)
class Unit:
    """One graded unit: its name, the mapping rules see, and its line view.

    ``hook`` marks a unit whose findings are attributed to what it wrote: a
    finding with no line is about a key the hook did not write (an inherited
    scalar, or an absence) and belongs to the parent, which reports it.
    ``env_key`` is the key :func:`~compose_lint._service_env.resolve_env_files`
    files this unit's ``env_file:`` targets under, or ``None`` for a hook,
    whose ``env_file:`` Compose does not apply.
    """

    name: str
    config: Any
    lines: Mapping[str, int]
    hook: bool = False
    env_key: str | None = None

    @property
    def kind_name(self) -> str | None:
        """The hook's name without its index (``app.pre_start``), or ``None``."""
        return _INDEX.sub("", self.name) if self.hook else None


class UnitLines(Mapping[str, int]):
    """The document's line map as one unit's rules should see it.

    Read-only and lazy: rules only ever call ``get``, and copying a line map
    per unit would cost its size times the units.

    ``hidden`` paths answer as absent, and so does everything below a path in
    ``hidden_trees``. ``alias`` answers every key under ``alias_prefix`` on its
    own, so a job's view never falls through to a service that happens to be
    named ``jobs.<x>``.
    """

    __slots__ = ("_alias", "_alias_prefix", "_base", "_hidden", "_hidden_trees")

    def __init__(
        self,
        base: Mapping[str, int],
        *,
        hidden: frozenset[str] = frozenset(),
        hidden_trees: tuple[str, ...] = (),
        alias: Mapping[str, int] | None = None,
        alias_prefix: str | None = None,
    ) -> None:
        self._base = base
        self._hidden = hidden
        self._hidden_trees = hidden_trees
        self._alias = alias or {}
        self._alias_prefix = alias_prefix

    def _is_hidden(self, key: str) -> bool:
        if key in self._hidden:
            return True
        return any(
            key == tree or key.startswith((f"{tree}.", f"{tree}["))
            for tree in self._hidden_trees
        )

    def __getitem__(self, key: str) -> int:
        if self._is_hidden(key):
            raise KeyError(key)
        if self._alias_prefix is not None and _under(key, self._alias_prefix):
            return self._alias[key]
        return self._base[key]

    def __iter__(self) -> Iterator[str]:
        for key in (*self._alias, *self._base):
            if key in self:
                yield key

    def __len__(self) -> int:
        return sum(1 for _ in self)

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        try:
            self[key]
        except KeyError:
            return False
        return True


def _under(key: str, prefix: str) -> bool:
    return key == prefix or key.startswith((f"{prefix}.", f"{prefix}["))


def _is_provider_service(config: Any) -> bool:
    """True for a service Compose hands to a provider plugin, not to the daemon.

    ``provider:`` (Compose 2.36 and later) declares a service that an external
    binary sets up and tears down. Compose creates no container for it: on
    ``up`` it runs the plugin and injects what the plugin publishes into the
    services that depend on it, and every container-only key written on the
    service (``privileged``, ``cap_add``, ``volumes``, ``environment``, even
    ``image``) is accepted and ignored. There is no container whose
    configuration a rule could describe, so no rule runs on it (issue #1186).
    Only the shape the spec defines, a mapping, counts; any other value is
    not a file Compose accepts, and is graded as written.
    """
    return isinstance(config, dict) and isinstance(config.get("provider"), dict)


def _scalars(config: Mapping[Any, Any]) -> dict[Any, Any]:
    """``config``'s scalar keys: the ones a hook inherits (ADR-040 §3)."""
    return {k: v for k, v in config.items() if not isinstance(v, (dict, list))}


def _hooks(config: Mapping[Any, Any], kind: str) -> list[tuple[int, dict[Any, Any]]]:
    entries = config.get(kind)
    if not isinstance(entries, list):
        return []
    return [(i, hook) for i, hook in enumerate(entries) if isinstance(hook, dict)]


def container_specs(
    data: Mapping[Any, Any], *, hooks: bool = True
) -> Iterator[tuple[str, dict[Any, Any]]]:
    """Every container spec the document writes, as written, with its unit name.

    The services, their ``pre_start`` entries and the jobs: the mappings that
    carry container keys such as ``volumes`` and ``env_file``. Exec hooks have
    none and are not yielded. For the parser, which rewrites paths in place
    before any rule runs, so a mapping is yielded as the document holds it.
    ``hooks=False`` leaves the ``pre_start`` entries out.
    """
    services = data.get("services")
    if isinstance(services, dict):
        for name, config in services.items():
            if not isinstance(config, dict):
                continue
            yield str(name), config
            if not hooks:
                continue
            for i, hook in _hooks(config, PRE_START):
                yield f"{name}.{PRE_START}[{i}]", hook
    jobs = data.get("jobs")
    if isinstance(jobs, dict):
        for name, config in jobs.items():
            if isinstance(config, dict):
                yield f"jobs.{name}", config


def job_lines(lines: Mapping[str, int]) -> dict[str, int]:
    """``jobs.<name>.*`` re-keyed as ``services.jobs.<name>.*``, in one pass.

    Built once per document rather than once per job, so many jobs over a large
    line map stay linear.
    """
    return {
        f"services.{key}": line for key, line in lines.items() if key[:5] == "jobs."
    }


def units(data: Mapping[Any, Any], lines: Mapping[str, int]) -> list[Unit]:
    """The document's units, services first, each hook after its service."""
    found: list[Unit] = []
    services = data.get("services")
    if isinstance(services, dict):
        for name, config in services.items():
            if _is_provider_service(config):
                continue
            found.append(Unit(name, config, lines, env_key=name))
            if isinstance(config, dict):
                found.extend(_service_hooks(str(name), config, lines))
    jobs = data.get("jobs")
    if isinstance(jobs, dict) and jobs:
        aliased = job_lines(lines)
        for name, config in jobs.items():
            if not isinstance(config, dict) or "extends" in config:
                # An extended job is not resolved yet: graded as written it
                # would report every key its base supplies as absent. The
                # parser reports it as a coverage gap instead.
                continue
            unit_name = f"jobs.{name}"
            view = UnitLines(lines, alias=aliased, alias_prefix=f"services.{unit_name}")
            found.append(Unit(unit_name, config, view, env_key=unit_name))
    return found


def _service_hooks(
    name: str, config: dict[Any, Any], lines: Mapping[str, int]
) -> Iterator[Unit]:
    inherited = _scalars(config)
    for i, hook in _hooks(config, PRE_START):
        unit_name = f"{name}.{PRE_START}[{i}]"
        # The unit's own path is where an absence finding lands, and it shares
        # its line with the hook's first key (`- image: alpine`), so the drop
        # rule cannot compare lines: hiding the path makes an absence finding
        # line-less instead, and a finding on the first key keeps its line.
        view = UnitLines(lines, hidden=frozenset({f"services.{unit_name}"}))
        yield Unit(unit_name, {**inherited, **hook}, view, hook=True)
    for kind in EXEC_HOOKS:
        for i, hook in _hooks(config, kind):
            unit_name = f"{name}.{kind}[{i}]"
            mapping = {k: v for k, v in inherited.items() if k != "privileged"}
            mapping.update({k: hook[k] for k in _EXEC_SCALARS if k in hook})
            if "environment" in hook:
                mapping["environment"] = hook["environment"]
            view = UnitLines(
                lines,
                hidden=frozenset({f"services.{unit_name}"}),
                hidden_trees=tuple(
                    f"services.{unit_name}.{key}" for key in _EXEC_UNGRADED
                ),
            )
            yield Unit(unit_name, mapping, view, hook=True)


def count_units(document: Mapping[Any, Any]) -> int:
    """How many units ``document`` declares, without building any.

    Each hook list counts its length, so a list aliased into every service is
    counted once per service that uses it, which is what grading it costs.
    """
    count = 0
    services = document.get("services")
    if isinstance(services, dict):
        for name, config in services.items():
            if not isinstance(name, str):
                continue
            count += 1
            if isinstance(config, dict):
                for kind in (PRE_START, *EXEC_HOOKS):
                    entries = config.get(kind)
                    if isinstance(entries, list):
                        count += len(entries)
    jobs = document.get("jobs")
    if isinstance(jobs, dict):
        count += sum(1 for name in jobs if isinstance(name, str))
    return count


def extended_jobs(data: Mapping[Any, Any]) -> list[str]:
    """Names of the jobs that use ``extends:``, which are not graded yet."""
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return []
    return [
        str(name)
        for name, config in jobs.items()
        if isinstance(config, dict) and "extends" in config
    ]


def unit_names(data: Mapping[Any, Any]) -> set[str]:
    """Names an ``exclude_services`` entry may use for this document.

    Every unit name, plus each hook kind name (``app.pre_start``) the service
    has at least one hook of (ADR-040 §9).
    """
    names: set[str] = set()
    for unit in units(data, {}):
        names.add(str(unit.name))
        kind = unit.kind_name
        if kind is not None:
            names.add(kind)
    return names
