#!/usr/bin/env python3
"""Validate each rule's premise against a live container (see AGENTS.md).

compose-lint flags *runtime* misconfigurations, so a rule is only sound if the
behavior it warns about is real in an actual container — and, for an
"absence" rule (one that fires when a hardening directive is missing), if the
insecure state is genuinely Docker's *default*. CL-0022 and CL-0023 shipped
without that check and both flagged Docker defaults (tmpfs is mounted
``noexec,nosuid,nodev`` by default; ``net.ipv4.ip_forward`` is ``1`` by
default), so they were corrected/removed.

This gate runs a short ``docker run`` per runtime-testable rule and asserts the
premise holds. It is the runtime arm of the rule-grounding bar: a new rule must
either cite a container-context source or pass a check here.

Usage: ``python scripts/validate_rule_premises.py`` (needs a working Docker).
Exits 0 if every premise holds (or Docker is unavailable → skipped), 1 on any
failure. Rules that describe image/supply-chain or config-only concerns
(CL-0004, CL-0014, CL-0015, CL-0019, CL-0020, CL-0021) have no runtime state to
observe and are listed as intentionally out of scope.
"""

from __future__ import annotations

import subprocess
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

# Pinned by manifest-list (OCI index) digest so CI uses no mutable ref.
IMAGE = (
    "busybox@sha256:fd8d9aa63ba2f0982b5304e1ee8d3b90a210bc1ffb5314d980eb6962f1a9715d"
)
# Rules with nothing to observe in a live container — grounded by source only.
_NON_RUNTIME = ["CL-0004", "CL-0014", "CL-0015", "CL-0019", "CL-0020", "CL-0021"]


def _run(args: list[str], cmd: list[str]) -> tuple[int, str]:
    """``docker run --rm <args> IMAGE <cmd>`` → (returncode, stdout).

    Returns *stdout only*: the container echoes the value each check inspects,
    and ``docker`` itself writes warnings to stderr — folding stderr in here
    corrupted exact/suffix matches (e.g. a stderr warning after ``SOCKET``).
    """
    proc = subprocess.run(
        ["docker", "run", "--rm", *args, IMAGE, *cmd],
        capture_output=True,
        text=True,
        timeout=90,
    )
    return proc.returncode, proc.stdout.strip()


# --- per-rule premise checks: each returns (ok, detail) ---------------------


def _cl0001() -> tuple[bool, str]:
    """Mounting the docker socket exposes a root-equivalent control channel."""
    rc, out = _run(
        ["-v", "/var/run/docker.sock:/var/run/docker.sock"],
        ["sh", "-c", "test -S /var/run/docker.sock && echo SOCKET || echo NONE"],
    )
    return ("SOCKET" in out), f"socket in container: {out!r}"


def _cl0002() -> tuple[bool, str]:
    """--privileged grants the full capability set."""
    _, base = _run([], ["grep", "CapEff", "/proc/self/status"])
    _, priv = _run(["--privileged"], ["grep", "CapEff", "/proc/self/status"])
    return ("ffffffffff" in priv and priv != base), f"default={base} priv={priv}"


def _cl0003() -> tuple[bool, str]:
    """no-new-privileges is OFF by default (the insecure state is the default)."""
    _, base = _run([], ["grep", "NoNewPrivs", "/proc/self/status"])
    _, miti = _run(
        ["--security-opt", "no-new-privileges"],
        ["grep", "NoNewPrivs", "/proc/self/status"],
    )
    return ("0" in base and "1" in miti), f"default={base!r} mitigated={miti!r}"


def _cl0005() -> tuple[bool, str]:
    """A bare published port binds all interfaces (empty/0.0.0.0 host IP)."""
    cid = subprocess.run(
        ["docker", "create", "-p", "18080:80", IMAGE, "true"],
        capture_output=True,
        text=True,
    ).stdout.strip()
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f", "{{json .HostConfig.PortBindings}}", cid],
            capture_output=True,
            text=True,
        ).stdout.strip()
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True)
    # Unspecified host IP serializes as "" — Docker then binds 0.0.0.0/::.
    return ('"HostIp":""' in out), f"port bindings: {out}"


def _cl0006() -> tuple[bool, str]:
    """A container keeps ~14 default capabilities unless they are dropped."""
    _, base = _run([], ["grep", "CapEff", "/proc/self/status"])
    _, miti = _run(["--cap-drop", "ALL"], ["grep", "CapEff", "/proc/self/status"])
    base_zero = base.split()[-1].strip("0") == ""
    miti_zero = miti.split()[-1].strip("0") == ""
    return (not base_zero and miti_zero), f"default={base} dropped={miti}"


def _cl0007() -> tuple[bool, str]:
    """The root filesystem is writable by default."""
    _, base = _run([], ["sh", "-c", "touch /x 2>/dev/null && echo RW || echo RO"])
    _, miti = _run(
        ["--read-only"], ["sh", "-c", "touch /x 2>/dev/null && echo RW || echo RO"]
    )
    return (base.endswith("RW") and miti.endswith("RO")), f"default={base} ro={miti}"


def _cl0008() -> tuple[bool, str]:
    """--network host exposes the host's network interfaces."""
    _, base = _run([], ["sh", "-c", "ls /sys/class/net | tr '\\n' ' '"])
    _, host = _run(
        ["--network", "host"], ["sh", "-c", "ls /sys/class/net | tr '\\n' ' '"]
    )
    return ("docker0" in host and host != base), f"default=[{base}] host=[{host}]"


def _cl0009() -> tuple[bool, str]:
    """A seccomp filter is active by default; unconfined removes it."""
    _, base = _run([], ["grep", "Seccomp:", "/proc/self/status"])
    _, unconf = _run(
        ["--security-opt", "seccomp=unconfined"],
        ["grep", "Seccomp:", "/proc/self/status"],
    )
    return ("2" in base and "0" in unconf), f"default={base!r} unconfined={unconf!r}"


def _cl0010() -> tuple[bool, str]:
    """--pid host makes every host process visible."""
    _, base = _run([], ["sh", "-c", "ls -d /proc/[0-9]* | wc -l"])
    _, host = _run(["--pid", "host"], ["sh", "-c", "ls -d /proc/[0-9]* | wc -l"])
    return (int(host) > int(base) + 10), f"default={base} host={host}"


def _cl0011() -> tuple[bool, str]:
    """--cap-add adds the named capability to the effective set."""
    _, base = _run([], ["grep", "CapEff", "/proc/self/status"])
    _, added = _run(["--cap-add", "SYS_ADMIN"], ["grep", "CapEff", "/proc/self/status"])
    return (added != base), f"default={base} +SYS_ADMIN={added}"


def _cl0012() -> tuple[bool, str]:
    """pids_limit: -1 (the rule's trigger) leaves a high/unbounded cap.

    A positive limit is enforced; ``-1`` leaves whatever the cgroup hierarchy
    allows (``max`` on an unconstrained host, or a high parent cap), which is far
    looser than a sane explicit limit — the insecure choice the rule flags.
    """
    _, unlim = _run(["--pids-limit", "-1"], ["cat", "/sys/fs/cgroup/pids.max"])
    _, limited = _run(["--pids-limit", "100"], ["cat", "/sys/fs/cgroup/pids.max"])
    u = unlim.strip()
    high = u == "max" or (u.isdigit() and int(u) > 1000)
    return (high and limited.strip() == "100"), f"-1={u} 100={limited.strip()}"


def _cl0013() -> tuple[bool, str]:
    """A host bind mount exposes the host path inside the container."""
    rc, out = _run(
        ["-v", "/etc/os-release:/hostfile:ro"],
        ["sh", "-c", "test -r /hostfile && echo READABLE || echo NONE"],
    )
    return out.endswith("READABLE"), f"host file in container: {out}"


def _cl0016() -> tuple[bool, str]:
    """--device exposes a host device that is absent by default."""
    _, base = _run([], ["sh", "-c", "test -e /dev/kmsg && echo YES || echo NO"])
    _, dev = _run(
        ["--device", "/dev/kmsg"],
        ["sh", "-c", "test -e /dev/kmsg && echo YES || echo NO"],
    )
    return (base.endswith("NO") and dev.endswith("YES")), f"default={base} device={dev}"


def _cl0017() -> tuple[bool, str]:
    """A shared bind propagation is observable as 'shared' in mountinfo."""
    _, out = _run(
        ["--mount", "type=bind,source=/tmp,target=/x,bind-propagation=shared"],
        ["sh", "-c", "grep ' /x ' /proc/self/mountinfo"],
    )
    return ("shared:" in out), f"/x mountinfo: {out}"


def _cl0018() -> tuple[bool, str]:
    """An explicit user maps to that uid (root => 0)."""
    _, root = _run(["--user", "root"], ["id", "-u"])
    _, nonroot = _run(["--user", "1000"], ["id", "-u"])
    return (
        root.strip() == "0" and nonroot.strip() == "1000"
    ), f"root={root} 1000={nonroot}"


def _cl0022() -> tuple[bool, str]:
    """tmpfs is noexec by default; :exec removes it (the inverted rule's premise)."""
    _, base = _run(["--tmpfs", "/d"], ["sh", "-c", "grep ' /d ' /proc/self/mountinfo"])
    _, ex = _run(
        ["--tmpfs", "/d:exec"], ["sh", "-c", "grep ' /d ' /proc/self/mountinfo"]
    )
    return (
        "noexec" in base and "noexec" not in ex
    ), f"default has noexec={'noexec' in base}, :exec has noexec={'noexec' in ex}"


CHECKS: list[tuple[str, str, Callable[[], tuple[bool, str]]]] = [
    ("CL-0001", "docker socket mount is root-equivalent", _cl0001),
    ("CL-0002", "privileged grants full caps", _cl0002),
    ("CL-0003", "no-new-privileges off by default", _cl0003),
    ("CL-0005", "bare published port binds all interfaces", _cl0005),
    ("CL-0006", "default caps present unless dropped", _cl0006),
    ("CL-0007", "rootfs writable by default", _cl0007),
    ("CL-0008", "host network exposes host interfaces", _cl0008),
    ("CL-0009", "seccomp filter active by default", _cl0009),
    ("CL-0010", "pid host exposes host processes", _cl0010),
    ("CL-0011", "cap_add adds the capability", _cl0011),
    ("CL-0012", "explicit pids limit takes effect", _cl0012),
    ("CL-0013", "host bind mount exposes host path", _cl0013),
    ("CL-0016", "device exposes a host device", _cl0016),
    ("CL-0017", "shared propagation is observable", _cl0017),
    ("CL-0018", "explicit user maps to that uid", _cl0018),
    ("CL-0022", "tmpfs noexec by default; :exec removes it", _cl0022),
]


def main() -> int:
    if subprocess.run(["docker", "version"], capture_output=True).returncode != 0:
        print("SKIP: Docker not available", file=sys.stderr)
        return 0

    failures = []
    for rule_id, label, check in CHECKS:
        try:
            ok, detail = check()
        except Exception as exc:  # noqa: BLE001 - a crashed check is a failure
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {rule_id}  {label}\n          {detail}")
        if not ok:
            failures.append(rule_id)

    print()
    print(f"not runtime-testable (grounded by source): {', '.join(_NON_RUNTIME)}")
    if failures:
        print(f"RESULT: FAIL ({len(failures)}): {', '.join(failures)}")
        return 1
    print(f"RESULT: PASS ({len(CHECKS)} premises validated)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
