"""Which lines of a step's log a CI runner would act on as workflow commands.

A model of the GitHub Actions runner's grammar, for GHSA-6f4g-xm8v-pgv6, from
GitHub's workflow-commands documentation and the runner's command parser:

- ``::name key=value::data`` at the start of a line, after any whitespace;
- the legacy ``##[name]data`` anywhere in a line (Azure Pipelines shares it);
- ``::stop-commands::TOKEN`` turns processing off until a line ``::TOKEN::``.

It is a model, not the runner. The forks the fixes were written in cannot run
Actions, so what these tests prove is that no forged command reaches a line the
documented grammar would act on; the Action's own smoke job on ``main`` is the
first check against a real runner.
"""

from __future__ import annotations

import re

_COMMAND = re.compile(r"::([A-Za-z][\w-]*)(?: [^:]*)?::(.*)")


def processed(log: str) -> list[str]:
    """Every command the runner would act on, in order, including the
    ``stop-commands`` bracket itself."""
    commands: list[str] = []
    stop_token: str | None = None
    for line in log.splitlines():
        stripped = line.strip()
        if stop_token is not None:
            if stripped == f"::{stop_token}::":
                stop_token = None
                commands.append(stripped)
            continue
        match = _COMMAND.fullmatch(stripped)
        if match:
            commands.append(stripped)
            if match.group(1) == "stop-commands":
                stop_token = match.group(2)
            continue
        legacy = line.find("##[")
        if legacy >= 0:
            commands.append(line[legacy:])
    return commands


def forged(log: str, marker: str) -> list[str]:
    """The processed commands that carry ``marker``, i.e. came from the file."""
    return [command for command in processed(log) if marker in command]
