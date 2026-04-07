"""Rule registry and base class for compose-lint rules."""

from __future__ import annotations

import abc
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

    from compose_lint.models import Finding, RuleMetadata

_registry: list[type[BaseRule]] = []


class BaseRule(abc.ABC):
    """Base class for all compose-lint rules.

    Subclasses must define metadata and implement the check method.
    """

    @property
    @abc.abstractmethod
    def metadata(self) -> RuleMetadata:
        """Return the rule's metadata."""
        ...

    @abc.abstractmethod
    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        """Check a single service for issues.

        Yields Finding objects for each issue detected.
        """
        ...


def register_rule(cls: type[BaseRule]) -> type[BaseRule]:
    """Decorator to register a rule class in the global registry."""
    _registry.append(cls)
    return cls


def get_registered_rules() -> list[type[BaseRule]]:
    """Return all registered rule classes."""
    return list(_registry)


def _load_rules() -> None:
    """Import all rule modules to trigger registration."""
    import importlib
    import pkgutil

    package_path = __path__
    for _importer, modname, _ispkg in pkgutil.iter_modules(package_path):
        if modname.startswith("CL"):
            importlib.import_module(f"{__name__}.{modname}")


_load_rules()

__all__ = [
    "BaseRule",
    "register_rule",
    "get_registered_rules",
]
