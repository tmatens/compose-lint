"""Every known amplification shape runs within a fixed memory and time budget.

Each shape below once made a file of a few hundred kilobytes, or less, cost
gigabytes or minutes. Each was fixed where it was found, and each fix closed
one route while the next audit found another. This test is the net under all
of them: it builds every shape at the same size, runs compose-lint on it in a
child process, and fails if any exceeds the budget, so a regression fails the
pull request that causes it instead of a later audit.

The size is 512 KB rather than the 8 MB read cap because the parser alone costs
about a hundred bytes of memory per input byte on a flat file (the ``flat``
control); what is under test is that no shape costs much more than that. At
this size every shape measured at or under 150 MiB and 3.2 s; the budget leaves
room for a slower runner, and none for a multiplication.

The exit code is not asserted beyond "not a crash": several shapes end at a
documented limit (the service count, the findings cap), which is exit 2.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET_BYTES = 512 * 1024
MEMORY_BUDGET_MIB = 256
TIME_BUDGET_S = 15.0

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="peak RSS is read from getrusage, whose units differ off Linux",
)

Files = dict[str, list[str]]


def _chain(name: str, depth: int) -> list[str]:
    out = [f"  {name}0: &{name}0 [x, x]"]
    out += [
        f"  {name}{k}: &{name}{k} [*{name}{k - 1}, *{name}{k - 1}]"
        for k in range(1, depth + 1)
    ]
    return out


def flat(n: int) -> Files:
    """The control: no sharing at all, so the parser's own cost."""
    labels = "".join(f"\n      k{i}: v" for i in range(n // 4000 + 1))
    services = [
        f"  s{j}:\n    image: nginx:1.27\n    labels:{labels}" for j in range(4000)
    ]
    return {"compose.yml": ["services:", *services]}


def port_chain_override(n: int) -> Files:
    """A long-form port's host_ip is a doubling alias chain; an override merges."""
    out = ["x-c:", *_chain("a", 40), "services:", "  base:", "    image: nginx:1.27"]
    out += ["    ports:", "      - target: 80", "        host_ip: *a40", "    labels:"]
    out += [f"      L{i}: v" for i in range(n)]
    override = ["services:", "  base:", "    ports:", "      - target: 81"]
    return {"compose.yml": out, "compose.override.yml": override}


def equal_chains_extends(n: int) -> Files:
    """Two distinct alias chains of one shape, deduplicated by an extends: merge."""
    out = ["x-c:", *_chain("a", 60), *_chain("b", 60), "services:"]
    out += ["  base:", "    image: nginx:1.27", "    dns: [*a60]"]
    out += [f"  c{i}:\n    extends: base\n    dns: [*b60]" for i in range(64)]
    out += ["  pad:", "    image: nginx:1.27", "    labels:"]
    out += [f"      L{i}: v" for i in range(n)]
    return {"compose.yml": out}


def long_list_override(n: int) -> Files:
    """A long append-merged list under a one-line override."""
    out = ["services:", "  base:", "    image: nginx:1.27", "    dns:"]
    out += [f"      - d{i}" for i in range(n)]
    return {
        "compose.yml": out,
        "compose.override.yml": ["services:", "  base:", "    dns: [z]"],
    }


def long_list_children(n: int) -> Files:
    """The same list merged into 64 extends: children."""
    out = ["services:", "  base:", "    image: nginx:1.27", "    dns:"]
    out += [f"      - d{i}" for i in range(n)]
    out += [f"  c{j}:\n    extends: base\n    dns: [z]" for j in range(64)]
    return {"compose.yml": out}


def extends_children(n: int) -> Files:
    """2,000 children inheriting one base's labels."""
    out = ["services:", "  base:", "    image: nginx:1.27", "    labels:"]
    out += [f"      K{i}: v" for i in range(n)]
    out += [f"  s{j}:\n    extends: base" for j in range(2000)]
    return {"compose.yml": out}


def aliased_mapping(n: int) -> Files:
    """One labels: anchor aliased into 4,000 services."""
    out = ["x-l: &lab", *(f"  K{i}: v" for i in range(n)), "services:"]
    out += [f"  s{j}:\n    image: nginx:1.27\n    labels: *lab" for j in range(4000)]
    return {"compose.yml": out}


def merge_key(n: int) -> Files:
    """The same through a merge key."""
    out = ["x-m: &m", "  labels:", *(f"    K{i}: v" for i in range(n)), "services:"]
    out += [f"  s{j}:\n    <<: *m\n    image: nginx:1.27" for j in range(4000)]
    return {"compose.yml": out}


def aliased_resets(n: int) -> Files:
    """A mapping of !reset keys aliased into 4,000 services."""
    out = ["x-r: &r", *(f"  K{i}: !reset v" for i in range(n)), "services:"]
    out += [f"  s{j}:\n    image: nginx:1.27\n    labels: *r" for j in range(4000)]
    return {"compose.yml": out}


def long_service_name(n: int) -> Files:
    """An 8,000-character service name over many labels."""
    name = ".".join(["a"] * 4000)
    out = ["services:", f"  ? '{name}'", "  :", "    image: nginx:1.27", "    labels:"]
    out += [f"      K{i}: v" for i in range(n)]
    return {"compose.yml": out}


def large_env_value(n: int) -> Files:
    """Distinct references to one 130 KB .env value."""
    out = ["services:", "  s:", "    image: nginx:1.27", "    labels:"]
    out += [f"      K{i}: ${{X}}{i}" for i in range(n)]
    return {".env": ["X=" + "a" * 130_000], "compose.yml": out}


def shared_env_file(n: int) -> Files:
    """One 20,000-key env_file: named by up to 4,000 services."""
    out = ["services:"]
    out += [
        f"  s{j}:\n    image: nginx:1.27\n    env_file: app.env"
        for j in range(min(n, 4000))
    ]
    out += ["  pad:", "    image: nginx:1.27", "    labels:"]
    out += [f"      L{i}: v" for i in range(max(0, n - 4000))]
    return {"app.env": [f"K{i}=v" for i in range(20_000)], "compose.yml": out}


def aliased_ports(n: int) -> Files:
    """A ports: anchor in 2,000 services: one finding per service per port."""
    out = ["x-p: &p", *(f"  - '{8000 + i}:80'" for i in range(n)), "services:"]
    out += [f"  s{j}:\n    image: nginx:1.27\n    ports: *p" for j in range(2000)]
    return {"compose.yml": out}


def aliased_environment(n: int) -> Files:
    """Long environment: values aliased into 4,000 services and scanned by rules."""
    value = ("scheme://host/path?" * 500)[:8000]
    out = ["x-env: &env", *(f"  K{i}: '{value}'" for i in range(n)), "services:"]
    out += [
        f"  s{j}:\n    image: nginx:1.27\n    environment: *env" for j in range(4000)
    ]
    return {"compose.yml": out}


SHAPES: dict[str, Callable[[int], Files]] = {
    shape.__name__: shape
    for shape in (
        flat,
        port_chain_override,
        equal_chains_extends,
        long_list_override,
        long_list_children,
        extends_children,
        aliased_mapping,
        merge_key,
        aliased_resets,
        long_service_name,
        large_env_value,
        shared_env_file,
        aliased_ports,
        aliased_environment,
    )
}


def _compose_size(shape: Callable[[int], Files], n: int) -> int:
    return len("\n".join(shape(n)["compose.yml"])) + 1


def _build(shape: Callable[[int], Files], directory: Path) -> None:
    """Write ``shape`` with its size parameter grown to TARGET_BYTES."""
    low, high = 1, 1
    while _compose_size(shape, high) < TARGET_BYTES:
        low, high = high, high * 2
    while low < high:
        mid = (low + high) // 2
        if _compose_size(shape, mid) < TARGET_BYTES:
            low = mid + 1
        else:
            high = mid
    for name, lines in shape(low).items():
        (directory / name).write_text("\n".join(lines) + "\n", encoding="utf-8")


# Runs compose-lint as a grandchild so the peak RSS it reports is that run's
# alone: RUSAGE_CHILDREN in the test process would carry the maximum over every
# child it has ever waited for.
_MEASURE = """
import resource, subprocess, sys, time
start = time.monotonic()
run = subprocess.run(sys.argv[1:], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
code = run.returncode
elapsed = time.monotonic() - start
print(code, elapsed, resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss // 1024)
"""


@pytest.mark.parametrize("name", sorted(SHAPES))
def test_the_shape_stays_within_budget(tmp_path: Path, name: str) -> None:
    _build(SHAPES[name], tmp_path)
    result = subprocess.run(  # noqa: S603 - fixed argv
        [
            sys.executable,
            "-c",
            _MEASURE,
            sys.executable,
            "-m",
            "compose_lint",
            "--format",
            "json",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(REPO_ROOT / "src")},
        timeout=TIME_BUDGET_S * 4,
        check=True,
    )
    code, elapsed, peak_mib = result.stdout.split()
    assert int(code) in (0, 1, 2), f"{name} crashed (exit {code})"
    assert float(elapsed) <= TIME_BUDGET_S, f"{name} took {float(elapsed):.1f} s"
    assert int(peak_mib) <= MEMORY_BUDGET_MIB, f"{name} peaked at {peak_mib} MiB"
