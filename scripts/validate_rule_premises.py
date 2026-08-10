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

**This is a maintainer and CI tool, not part of the product.** Nothing in the
installed package opens a socket: ``check``, ``fix`` and ``--explain`` are pure
YAML analysis, the wheel does not ship this file, and the corpus pipeline never
touches a daemon either. It runs in CI's ``rule-premises`` job and by hand — a
user of compose-lint will never see its output, including the posture note.
What it validates is a rule's *premise*, on a daemon at Docker's documented
defaults, so that the word "verified" on a rule page means something specific.
It says nothing about the daemon a compose file will eventually be deployed to
(ADR-020) — compose-lint never sees that host.

Usage: ``python scripts/validate_rule_premises.py`` (needs a working **rootful**
Docker). Under rootless Docker several checks fail spuriously: the kernel
authorizes SYS_NICE/SYS_TIME/IPC_LOCK in the *init* user namespace, so their
allow legs fail even with the capability granted, and the socket-mount and
/dev/kmsg checks assume rootful paths. CI runs rootful; treat rootless-local
failures as environmental.
Exits 0 if every premise holds (or Docker is unavailable → skipped), 1 on any
failure. Rules that describe image/supply-chain or config-only concerns
(CL-0004, CL-0014, CL-0019, CL-0020, CL-0021) have no runtime state to
observe and are listed as intentionally out of scope.
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

# Pinned by manifest-list (OCI index) digest so CI uses no mutable ref.
IMAGE = (
    "busybox@sha256:fd8d9aa63ba2f0982b5304e1ee8d3b90a210bc1ffb5314d980eb6962f1a9715d"
)
# python:3.13-alpine — for checks busybox can't express: syscalls needing a
# libc caller (mlockall, clock_settime) and the CL-0003 setuid-interpreter
# staging (python keeps its effective uid; busybox re-drops it).
PY_IMAGE = (
    "python@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0"
)
# Rules with nothing to observe in a live container — grounded by source only.
_NON_RUNTIME = ["CL-0004", "CL-0014", "CL-0019", "CL-0020", "CL-0021"]

# Docker's default capability set, which is compiled into the daemon and has no
# flag or daemon.json key. Every capability premise is measured against it.
DEFAULT_CAPEFF = "00000000a80425fb"


def _info(field: str) -> str:
    """One projected field from ``docker info``.

    Projected rather than dumped: the full ``docker info`` output carries
    registry and proxy configuration, and nothing here needs it.
    """
    proc = subprocess.run(
        ["docker", "info", "--format", field],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return proc.stdout.strip()


def _posture() -> tuple[list[tuple[str, str, str]], str]:
    """Report how the daemon under test departs from Docker's defaults.

    ADR-020 grounds every rule against rootful Docker Engine at its default
    configuration, so a premise measured elsewhere cannot be cited as evidence
    for one. A departure does not stop the run: measured on a no-AppArmor
    desktop, all 41 checks returned verdicts identical to the grounded host, so
    refusing outright threw away a run that was almost entirely valid. What a
    departure does is cost the run its authority — the caller marks it
    non-authoritative and exits non-zero.

    Note what this is *not*. It says nothing about the daemon a compose file
    will eventually run on: compose-lint never sees that host (ADR-020). This
    is about where the measurement was taken.

    **A clause exists here only when a check depends on it.** The first draft
    asserted five facts; two of them — an active LSM, and ``icc`` left on —
    were not measured by any check in the suite, and the LSM clause was the one
    that fired on the desktop run described above. Asserting a condition
    speculatively, in case something later needs it, buys nothing and costs
    false alarms. When the deferred CL-0006 ARP check lands it will depend on
    ``icc``, and the ``icc`` clause lands with it.

    Currently asserted, with what depends on each:

    * **default capability set** — every "denied without the capability,
      allowed with it" mapping.
    * **builtin seccomp** — ``_cl0009``, which asserts a filter is active by
      default.
    * **no uid remapping** — ``_cl0018``, which asserts an explicit ``user:``
      maps to that uid.

    Returns ``(departures, security_options)``, where each departure is
    ``(what departed, what was expected, what was observed)`` — a bare
    "posture is wrong" leaves the reader to guess which setting and what to
    change.
    """
    problems: list[tuple[str, str, str]] = []

    opts = _info("{{.SecurityOptions}}")
    if "seccomp,profile=builtin" not in opts:
        problems.append(
            ("seccomp is not the builtin profile", "name=seccomp,profile=builtin", opts)
        )
    if "name=userns" in opts:
        problems.append(("userns-remap is enabled", "no name=userns", opts))

    _, caps = _run([], ["sh", "-c", "grep ^CapEff /proc/self/status | tr -d '\t'"])
    if not caps.endswith(DEFAULT_CAPEFF):
        problems.append(
            ("capability set is not Docker's default 14", DEFAULT_CAPEFF, caps)
        )

    _, uid_map = _run([], ["cat", "/proc/self/uid_map"])
    if uid_map.split()[:2] != ["0", "0"]:
        problems.append(
            ("uid namespace is remapped", "uid_map starting '0 0'", uid_map)
        )

    return problems, opts


def _run(args: list[str], cmd: list[str], image: str = IMAGE) -> tuple[int, str]:
    """``docker run --rm <args> <image> <cmd>`` → (returncode, stdout).

    Returns *stdout only*: the container echoes the value each check inspects,
    and ``docker`` itself writes warnings to stderr — folding stderr in here
    corrupted exact/suffix matches (e.g. a stderr warning after ``SOCKET``).
    """
    proc = subprocess.run(
        ["docker", "run", "--rm", *args, image, *cmd],
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


# --- CL-0006 symptom-table mappings (docs/rules/CL-0006.md) -----------------
#
# The rule doc's "Determining required capabilities" table quotes verbatim
# error messages and maps each to a capability. Each check here re-proves one
# row against a live container: the operation must FAIL under ``cap_drop: ALL``
# emitting the quoted message, and SUCCEED with only the mapped capability
# added. This catches engine drift — e.g. Docker 20.10 setting
# ``ip_unprivileged_port_start=0`` silently invalidated the old "low ports need
# NET_BIND_SERVICE" folklore, which is exactly the kind of change these checks
# turn into a CI failure instead of stale documentation (#468).


def _run_err(args: list[str], cmd: list[str], image: str = IMAGE) -> tuple[int, str]:
    """``docker run --rm <args> <image> <cmd>`` → (returncode, stderr).

    The capability-failure messages the CL-0006 table quotes are emitted on
    stderr, so this helper returns stderr where ``_run`` returns stdout.
    """
    proc = subprocess.run(
        ["docker", "run", "--rm", *args, image, *cmd],
        capture_output=True,
        text=True,
        timeout=90,
    )
    return proc.returncode, proc.stderr.strip()


def _mapping(
    caps: list[str],
    cmd: list[str],
    msg: str,
    args: list[str] | None = None,
    image: str = IMAGE,
) -> tuple[bool, str]:
    """Prove one symptom→capability row (fails capless with ``msg``; works
    with only ``caps`` added)."""
    extra = args or []
    rc_deny, err = _run_err(["--cap-drop", "ALL", *extra], cmd, image)
    add = [flag for cap in caps for flag in ("--cap-add", cap)]
    rc_allow, _ = _run_err(["--cap-drop", "ALL", *add, *extra], cmd, image)
    ok = rc_deny != 0 and msg in err and rc_allow == 0
    return ok, f"denied rc={rc_deny} msg={err!r}; with {'+'.join(caps)} rc={rc_allow}"


def _t_chown() -> tuple[bool, str]:
    return _mapping(
        ["CHOWN"],
        ["sh", "-c", "touch /tmp/f && chown 1000:1000 /tmp/f"],
        "chown: /tmp/f: Operation not permitted",
    )


def _t_fowner() -> tuple[bool, str]:
    # A chmod probe is a no-op on a root-owned file — FOWNER only gates files
    # owned by *another* uid, so stage a foreign-owned dir via tmpfs uid=.
    return _mapping(
        ["FOWNER"],
        ["chmod", "0755", "/work"],
        "chmod: /work: Operation not permitted",
        args=["--tmpfs", "/work:uid=1000,mode=0700"],
    )


def _t_setuid_setgid() -> tuple[bool, str]:
    return _mapping(
        ["SETUID", "SETGID"],
        ["su", "nobody", "-s", "/bin/sh", "-c", "true"],
        "su: can't set groups: Operation not permitted",
    )


def _t_net_bind_service() -> tuple[bool, str]:
    # Only meaningful under a hardened ip_unprivileged_port_start: Docker
    # 20.10+ defaults the sysctl to 0 in each container's own network
    # namespace, so the loose leg must bind :80 with NO capability at all —
    # that default going away (or the hardened leg passing capless) is drift.
    # Poll for the listening socket instead of a fixed sleep — on a loaded
    # runner the fork-to-bind can exceed any single guess, and nc's own exit
    # status is swallowed by the backgrounding.
    bind_script = (
        "nc -l -p 80 -w 3 & i=0; while [ $i -lt 20 ]; do "
        "netstat -tln | grep -q ':80 ' && exit 0; "
        "i=$((i+1)); sleep 0.1; done; exit 1"
    )
    bind = ["sh", "-c", bind_script]
    hard = ["--sysctl", "net.ipv4.ip_unprivileged_port_start=1024"]
    rc_loose, _ = _run_err(["--cap-drop", "ALL"], bind)
    rc_deny, err = _run_err(["--cap-drop", "ALL", *hard], bind)
    rc_allow, _ = _run_err(
        ["--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", *hard], bind
    )
    ok = (
        rc_loose == 0
        and rc_deny != 0
        and "nc: bind: Permission denied" in err
        and rc_allow == 0
    )
    return ok, (
        f"loose capless rc={rc_loose}; hardened rc={rc_deny} msg={err!r}; "
        f"hardened with cap rc={rc_allow}"
    )


def _t_net_raw() -> tuple[bool, str]:
    # busybox ping uses a raw socket; other ping builds work capless via ICMP
    # datagram sockets (the doc notes the tool-dependence).
    return _mapping(
        ["NET_RAW"],
        ["ping", "-c1", "-W1", "127.0.0.1"],
        "ping: permission denied (are you root?)",
    )


def _t_mknod() -> tuple[bool, str]:
    return _mapping(
        ["MKNOD"],
        ["mknod", "/tmp/null0", "c", "1", "3"],
        "mknod: /tmp/null0: Operation not permitted",
    )


def _t_net_admin() -> tuple[bool, str]:
    # Route change in the container's own netns — NET_ADMIN is netns-scoped,
    # so granting it here touches nothing outside the container.
    return _mapping(
        ["NET_ADMIN"],
        ["ip", "route", "add", "192.0.2.0/24", "dev", "lo"],
        "ip: RTNETLINK answers: Operation not permitted",
    )


def _t_sys_nice() -> tuple[bool, str]:
    # Note EACCES ("Permission denied"), not EPERM — setpriority(2)'s
    # documented errno for lowering nice without privilege.
    return _mapping(
        ["SYS_NICE"],
        ["renice", "-n", "-5", "-p", "1"],
        "renice: setpriority: Permission denied",
    )


_SETTIME_PROBE = (
    "import ctypes,os,sys\n"
    "libc=ctypes.CDLL(None,use_errno=True)\n"
    "class TS(ctypes.Structure):\n"
    "    _fields_=[('tv_sec',ctypes.c_long),('tv_nsec',ctypes.c_long)]\n"
    "ts=TS()\n"
    "libc.clock_gettime(0,ctypes.byref(ts))\n"
    "if libc.clock_settime(0,ctypes.byref(ts))!=0:\n"
    "    print('clock_settime: '+os.strerror(ctypes.get_errno()),file=sys.stderr)\n"
    "    sys.exit(1)\n"
)


def _t_sys_time() -> tuple[bool, str]:
    # Deny leg: busybox `date -s`, keyed on the quoted message rather than the
    # exit code — busybox builds differ on whether a settime failure is fatal
    # (ours exits 1; upstream has shipped variants that print and exit 0).
    # Allow leg: a clock_gettime→clock_settime round-trip of the same timespec.
    # CLOCK_REALTIME is not namespaced, so proving the grant touches the HOST
    # clock — the round-trip bounds that to microseconds of drift instead of
    # `date -s`'s up-to-a-second backward step.
    # Set-to-now even on the deny leg: if a broken engine ever let it through,
    # the "failure" must still be a harmless no-op, never a step to epoch 0.
    rc_deny, err = _run_err(["--cap-drop", "ALL"], ["sh", "-c", "date -s @$(date +%s)"])
    rc_allow, allow_err = _run_err(
        ["--cap-drop", "ALL", "--cap-add", "SYS_TIME"],
        ["python", "-c", _SETTIME_PROBE],
        image=PY_IMAGE,
    )
    msg = "date: can't set date: Operation not permitted"
    ok = msg in err and rc_allow == 0
    return ok, (
        f"denied msg={err!r}; settime round-trip with SYS_TIME "
        f"rc={rc_allow} {allow_err!r}"
    )


def _t_kill() -> tuple[bool, str]:
    # kill(2) across uids: PID 1 runs as uid 1000, the exec'd root shell
    # (inheriting the container's dropped caps) signals it — EPERM without
    # CAP_KILL even for root.
    def attempt(extra: list[str]) -> tuple[int, str]:
        create = subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--cap-drop",
                "ALL",
                *extra,
                "--user",
                "1000",
                IMAGE,
                "sleep",
                "60",
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )
        cid = create.stdout.strip()
        if create.returncode != 0 or not cid:
            # Surface as an environment error, not a premise verdict.
            raise RuntimeError(f"container create failed: {create.stderr.strip()!r}")
        try:
            proc = subprocess.run(
                ["docker", "exec", "-u", "0", cid, "kill", "-TERM", "1"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return proc.returncode, proc.stderr.strip()
        finally:
            subprocess.run(["docker", "rm", "-f", cid], capture_output=True)

    rc_deny, err = attempt([])
    rc_allow, _ = attempt(["--cap-add", "KILL"])
    ok = (
        rc_deny != 0
        and "kill: can't kill pid 1: Operation not permitted" in err
        and rc_allow == 0
    )
    return ok, f"denied rc={rc_deny} msg={err!r}; with KILL rc={rc_allow}"


_MLOCK_PROBE = (
    "import ctypes,os,sys\n"
    "libc=ctypes.CDLL(None,use_errno=True)\n"
    "if libc.mlockall(1)!=0:\n"
    "    print('mlockall: '+os.strerror(ctypes.get_errno()),file=sys.stderr)\n"
    "    sys.exit(1)\n"
)


def _t_ipc_lock() -> tuple[bool, str]:
    # mlockall(2) with RLIMIT_MEMLOCK=0: EPERM without CAP_IPC_LOCK, allowed
    # with it (the cap bypasses the rlimit) — the vault/elasticsearch
    # memory-lock pattern. Docker's default memlock limit permits small locks
    # capless, so the rlimit must be pinned to 0 to expose the mapping.
    return _mapping(
        ["IPC_LOCK"],
        ["python", "-c", _MLOCK_PROBE],
        "mlockall: Operation not permitted",
        args=["--ulimit", "memlock=0:0"],
        image=PY_IMAGE,
    )


# --- CL-0007 symptom-table mappings (docs/rules/CL-0007.md) -----------------
#
# Same contract as the CL-0006 mapping checks (ADR-016 amendment): each row of
# the rule doc's "Reading the failure" table is proven live — the write fails
# under ``--read-only`` emitting the quoted busybox message, and succeeds with
# the mapped remedy applied.


def _remedy(
    deny_args: list[str],
    allow_args: list[str],
    cmd: list[str],
    msg: str,
) -> tuple[bool, str]:
    """Prove one symptom→remedy row (fails under ``deny_args`` with ``msg``;
    works under ``allow_args``)."""
    rc_deny, err = _run_err(deny_args, cmd)
    rc_allow, _ = _run_err(allow_args, cmd)
    ok = rc_deny != 0 and msg in err and rc_allow == 0
    return ok, f"denied rc={rc_deny} msg={err!r}; remedied rc={rc_allow}"


def _t7_touch_tmpfs() -> tuple[bool, str]:
    return _remedy(
        ["--read-only"],
        ["--read-only", "--tmpfs", "/tmp"],
        ["touch", "/tmp/scratch"],
        "touch: /tmp/scratch: Read-only file system",
    )


def _t7_mkdir_tmpfs() -> tuple[bool, str]:
    # busybox mkdir -p reports the first missing parent it fails to create.
    return _remedy(
        ["--read-only"],
        ["--read-only", "--tmpfs", "/var/cache"],
        ["mkdir", "-p", "/var/cache/app"],
        "mkdir: can't create directory '/var/cache/': Read-only file system",
    )


def _t7_tmpfs_creates_mountpoint() -> tuple[bool, str]:
    # The doc's masked-symptom row: /run is absent from the busybox image, so
    # under read_only the write fails ENOENT (not EROFS) — and a tmpfs entry
    # both creates the mount point and makes it writable.
    return _remedy(
        ["--read-only"],
        ["--read-only", "--tmpfs", "/run"],
        ["touch", "/run/app.pid"],
        "touch: /run/app.pid: No such file or directory",
    )


def _t7_volume_writable() -> tuple[bool, str]:
    # The doc's persistent-data row: a named volume stays writable under
    # read_only while the rootfs is locked — the load-bearing fact behind
    # "persistent data -> named volume, never tmpfs".
    vol = "clpremise-cl0007-vol"
    subprocess.run(["docker", "volume", "create", vol], capture_output=True, timeout=90)
    try:
        rc_vol, _ = _run_err(
            ["--read-only", "-v", f"{vol}:/data"],
            [
                "touch",
                "/data/persist",
            ],
        )
        rc_root, err = _run_err(
            ["--read-only", "-v", f"{vol}:/data"],
            [
                "touch",
                "/tmp/x",
            ],
        )
    finally:
        subprocess.run(["docker", "volume", "rm", vol], capture_output=True, timeout=90)
    ok = rc_vol == 0 and rc_root != 0 and "Read-only file system" in err
    return ok, f"volume write rc={rc_vol}; rootfs write rc={rc_root} msg={err!r}"


# --- CL-0018 / CL-0022 symptom-table mappings (#479) -----------------------
#
# Same contract as the CL-0006/CL-0007 mapping checks (ADR-016 amendment).


def _t22_exec_tmpfs() -> tuple[bool, str]:
    # Exec from a default (noexec) tmpfs fails even though the file has the x
    # bit; :exec permits it — which is exactly the option CL-0022 flags, so
    # the doc frames the remedy as relocate-first, :exec-with-reason last.
    exec_script = "cp /bin/busybox /scratch/busybox && /scratch/busybox true"
    return _remedy(
        ["--tmpfs", "/scratch"],
        ["--tmpfs", "/scratch:exec"],
        ["sh", "-c", exec_script],
        "/scratch/busybox: Permission denied",
    )


def _t18_rootfs_write() -> tuple[bool, str]:
    # Non-root write to a root-owned image path fails EACCES; the remedy row
    # is a tmpfs with uid= — see _t18_tmpfs_inherits for why bare tmpfs isn't
    # enough here.
    return _remedy(
        ["--user", "1000"],
        ["--user", "1000", "--tmpfs", "/etc:uid=1000"],
        ["touch", "/etc/app.lock"],
        "touch: /etc/app.lock: Permission denied",
    )


def _t18_tmpfs_inherits() -> tuple[bool, str]:
    # The doc's tmpfs gotcha, both halves: a tmpfs over an EXISTING image dir
    # inherits that dir's root ownership (still unwritable for uid 1000),
    # while a tmpfs at a path ABSENT from the image defaults to mode 1777.
    rc_inherit, err = _run_err(
        ["--user", "1000", "--tmpfs", "/etc"], ["touch", "/etc/app.lock"]
    )
    rc_fresh, _ = _run_err(
        ["--user", "1000", "--tmpfs", "/newpath"], ["touch", "/newpath/x"]
    )
    ok = rc_inherit != 0 and "Permission denied" in err and rc_fresh == 0
    return ok, (
        f"tmpfs over /etc rc={rc_inherit} msg={err!r}; tmpfs at absent path "
        f"rc={rc_fresh}"
    )


def _t18_volume_ownership() -> tuple[bool, str]:
    # The doc's named-volume rows: a fresh volume at a path absent from the
    # image is root-owned (non-root write fails), while a volume mounted over
    # an existing image dir copies that dir's contents AND ownership on first
    # use (busybox's /tmp is 1777, so the copy-up makes it writable).
    def attempt(vol: str, mountpoint: str, path: str) -> tuple[int, str]:
        subprocess.run(
            ["docker", "volume", "create", vol], capture_output=True, timeout=90
        )
        try:
            return _run_err(
                ["--user", "1000", "-v", f"{vol}:{mountpoint}"], ["touch", path]
            )
        finally:
            subprocess.run(
                ["docker", "volume", "rm", vol], capture_output=True, timeout=90
            )

    rc_fresh, err = attempt("clpremise-cl0018-fresh", "/data", "/data/x")
    rc_copyup, _ = attempt("clpremise-cl0018-copyup", "/tmp", "/tmp/x")
    ok = rc_fresh != 0 and "Permission denied" in err and rc_copyup == 0
    return ok, (
        f"fresh volume rc={rc_fresh} msg={err!r}; copy-up volume rc={rc_copyup}"
    )


# --- CL-0003 symptom mappings (#471 follow-on) ------------------------------
#
# Both checks use PY_IMAGE: staging a setuid interpreter needs a real ELF that
# keeps its effective uid (python does; busybox re-drops for non-suid applets),
# and alpine's su provides the root->nobody drop.

_SUID_GAIN_SCRIPT = (
    "PY=$(readlink -f $(command -v python3)); cp $PY /tmp/suidpy && "
    "chmod u+s /tmp/suidpy && "
    "su nobody -s /bin/sh -c '/tmp/suidpy -c \"import os;print(os.geteuid())\"'"
)


def _t3_setuid_inert() -> tuple[bool, str]:
    # The doc's silent-failure claim: without nnp the staged setuid python
    # gives nobody euid 0; WITH nnp the same execve SUCCEEDS (rc 0) but the
    # setuid bit is ignored — euid stays 65534, and nothing errors.
    rc_gain, out_gain = _run([], ["sh", "-c", _SUID_GAIN_SCRIPT], image=PY_IMAGE)
    rc_nnp, out_nnp = _run(
        ["--security-opt", "no-new-privileges"],
        ["sh", "-c", _SUID_GAIN_SCRIPT],
        image=PY_IMAGE,
    )
    ok = (
        rc_gain == 0
        and out_gain.strip() == "0"
        and rc_nnp == 0
        and out_nnp.strip() == "65534"
    )
    return ok, (
        f"without nnp euid={out_gain!r} rc={rc_gain}; "
        f"with nnp euid={out_nnp!r} rc={rc_nnp} (exec still succeeds)"
    )


def _t3_drop_unaffected() -> tuple[bool, str]:
    # The compatibility claim this page once got wrong: a root entrypoint
    # dropping to an unprivileged user (the gosu/su-exec pattern) works fine
    # under no-new-privileges — nnp blocks execve-time GAIN, not setuid()
    # drops. This check exists so that claim can never silently regress.
    rc, out = _run(
        ["--security-opt", "no-new-privileges"],
        ["su", "nobody", "-s", "/bin/sh", "-c", "id -u"],
        image=PY_IMAGE,
    )
    ok = rc == 0 and out.strip() == "65534"
    return ok, f"root->nobody drop under nnp rc={rc} uid={out!r}"


def _cl0001_ro_socket() -> tuple[bool, str]:
    """``:ro`` does not neuter the socket — the API answers through it.

    ``:ro`` sets the inode permissions on the socket *file*; the Docker API is
    read-write over any connection that gets opened, so a read-only mount grants
    the same control as a read-write one. Uses ``/_ping`` — the smallest
    read-only endpoint — so the check makes no state-changing API call.
    """
    probe = (
        "import socket;"
        "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);"
        "s.connect('/var/run/docker.sock');"
        "s.sendall(b'GET /_ping HTTP/1.1\\r\\nHost: docker\\r\\n\\r\\n');"
        "print(s.recv(64).split(b'\\r\\n')[0].decode())"
    )
    _, out = _run(
        ["-v", "/var/run/docker.sock:/var/run/docker.sock:ro"],
        ["python", "-c", probe],
        image=PY_IMAGE,
    )
    return ("200 OK" in out), f"ro-mounted socket answered: {out!r}"


def _host_block_device() -> str:
    """Name of a whole-disk block device on the *daemon's* host, or ""."""
    _, dev = _run(
        ["-v", "/dev:/hostdev:ro"],
        [
            "sh",
            "-c",
            "ls /hostdev | grep -E '^(nvme[0-9]+n[0-9]+|sd[a-z]|vd[a-z])$' | head -1",
        ],
    )
    return dev


def _cl0016_raw_disk() -> tuple[bool, str]:
    """A block device mapped via ``devices:`` is readable at default caps.

    This is what puts CL-0016 in the CRITICAL tier: no capability is added, no
    technique is needed, and the read lands on the disk backing the host
    filesystem. Reads one sector to /dev/null — nothing is written, and no disk
    content reaches the output.
    """
    dev = _host_block_device()
    if not dev:
        return False, "no whole-disk block device found under the daemon host's /dev"
    _, out = _run(
        ["--device", f"/dev/{dev}:/dev/{dev}:r"],
        ["sh", "-c", f"dd if=/dev/{dev} of=/dev/null bs=512 count=1 2>&1 | tail -1"],
    )
    return ("512 bytes" in out), f"/dev/{dev} via --device at default caps: {out!r}"


def _cl0013_dev_bind_is_gated() -> tuple[bool, str]:
    """A ``/dev`` bind conveys the nodes but not device-cgroup permission.

    The negative control for ``_cl0016``: same host, same device, same default
    capabilities — refused through a bind mount, allowed through ``--device``.
    It is why CL-0013's ``/dev`` member is not equivalent to CL-0016.
    """
    dev = _host_block_device()
    if not dev:
        return False, "no whole-disk block device found under the daemon host's /dev"
    _, out = _run(
        ["-v", "/dev:/hostdev"],
        [
            "sh",
            "-c",
            f"dd if=/hostdev/{dev} of=/dev/null bs=512 count=1 2>&1 | tail -1",
        ],
    )
    return ("not permitted" in out), f"/dev/{dev} via bind mount: {out!r}"


def _cl0025_core_pattern() -> tuple[bool, str]:
    """An rw ``/proc`` bind makes ``core_pattern`` writable at default caps.

    Docker mounts the container's own ``/proc/sys`` read-only, but a bind mount
    of the host's ``/proc`` arrives writable — which hands a container the
    ability to point the host's core-dump handler at a program of its choosing.

    The check writes back the value it just read, so the host's setting is
    unchanged whether the write is permitted or refused.
    """
    script = (
        "v=$(cat {root}/sys/kernel/core_pattern); "
        'printf "%s\\n" "$v" > {root}/sys/kernel/core_pattern 2>/dev/null '
        "&& echo WROTE || echo REFUSED"
    )
    _, bound = _run(
        ["-v", "/proc:/hostproc"], ["sh", "-c", script.format(root="/hostproc")]
    )
    _, default = _run([], ["sh", "-c", script.format(root="/proc")])
    ok = bound == "WROTE" and default == "REFUSED"
    return ok, f"rw /proc bind={bound!r}, container's own /proc={default!r}"


def _cl0026() -> tuple[bool, str]:
    """Memory and CPU are both unbounded by default; a limit bounds them.

    Docker imposes no default memory or CPU cap, so the absence CL-0026 flags is
    genuinely the insecure default rather than a hardening preference.
    """
    read = "echo $(cat /sys/fs/cgroup/memory.max)/$(cat /sys/fs/cgroup/cpu.max)"
    _, base = _run([], ["sh", "-c", read])
    _, limited = _run(["--memory", "64m", "--cpus", "0.5"], ["sh", "-c", read])
    ok = base.startswith("max/max ") and not limited.startswith("max/")
    return ok, f"default={base!r} limited={limited!r}"


# NOTE: CL-0006's ARP-overwrite leg (ADR-020 Appendix A, row 5) is not yet
# automated. It needs two containers on a shared user-defined bridge, a
# raw-socket ARP sender, and a victim whose cache is actively cycling — an
# orchestration this single-container harness has no shape for. The capability
# gate underneath it (`_t_net_raw`) *is* checked on every run; the overwrite
# itself is captured evidence in the ADR until a multi-container harness exists.
CHECKS: list[tuple[str, str, Callable[[], tuple[bool, str]]]] = [
    ("CL-0001", "docker socket mount is root-equivalent", _cl0001),
    (
        "CL-0001",
        "premise: :ro socket is still a working API endpoint",
        _cl0001_ro_socket,
    ),
    ("CL-0002", "privileged grants full caps", _cl0002),
    ("CL-0003", "no-new-privileges off by default", _cl0003),
    ("CL-0005", "bare published port binds all interfaces", _cl0005),
    ("CL-0006", "default caps present unless dropped", _cl0006),
    ("CL-0007", "rootfs writable by default", _cl0007),
    ("CL-0008", "host network exposes host interfaces", _cl0008),
    ("CL-0009", "seccomp filter active by default", _cl0009),
    ("CL-0010", "pid host exposes host processes", _cl0010),
    ("CL-0011", "cap_add adds the capability", _cl0011),
    ("CL-0013", "host bind mount exposes host path", _cl0013),
    (
        "CL-0013",
        "premise: /dev bind is device-cgroup gated, unlike --device",
        _cl0013_dev_bind_is_gated,
    ),
    ("CL-0016", "device exposes a host device", _cl0016),
    ("CL-0016", "premise: raw host-disk read at default caps", _cl0016_raw_disk),
    ("CL-0017", "shared propagation is observable", _cl0017),
    ("CL-0018", "explicit user maps to that uid", _cl0018),
    ("CL-0022", "tmpfs noexec by default; :exec removes it", _cl0022),
    # CL-0006 symptom-table mappings — one per row of the rule doc's table.
    ("CL-0006", "map: chown -> CHOWN", _t_chown),
    ("CL-0006", "map: chmod on foreign-owned -> FOWNER", _t_fowner),
    ("CL-0006", "map: user switch -> SETUID+SETGID", _t_setuid_setgid),
    ("CL-0006", "map: hardened low-port bind -> NET_BIND_SERVICE", _t_net_bind_service),
    ("CL-0006", "map: raw-socket ping -> NET_RAW", _t_net_raw),
    ("CL-0006", "map: mknod -> MKNOD", _t_mknod),
    ("CL-0006", "map: route change -> NET_ADMIN", _t_net_admin),
    ("CL-0006", "map: renice -> SYS_NICE", _t_sys_nice),
    ("CL-0006", "map: set clock -> SYS_TIME", _t_sys_time),
    ("CL-0006", "map: cross-uid signal -> KILL", _t_kill),
    ("CL-0006", "map: mlockall -> IPC_LOCK", _t_ipc_lock),
    # CL-0007 symptom-table mappings — one per row of the rule doc's table.
    ("CL-0007", "map: touch EROFS -> tmpfs", _t7_touch_tmpfs),
    ("CL-0007", "map: mkdir EROFS -> tmpfs", _t7_mkdir_tmpfs),
    ("CL-0007", "map: masked ENOENT -> tmpfs mountpoint", _t7_tmpfs_creates_mountpoint),
    ("CL-0007", "premise: named volume writable under read_only", _t7_volume_writable),
    # CL-0018 / CL-0022 symptom-table mappings (#479).
    ("CL-0022", "map: exec from noexec tmpfs", _t22_exec_tmpfs),
    ("CL-0018", "map: non-root write to root-owned path", _t18_rootfs_write),
    ("CL-0018", "premise: tmpfs inherits image-dir ownership", _t18_tmpfs_inherits),
    ("CL-0018", "premise: named-volume initial ownership", _t18_volume_ownership),
    # Premises for rules that land later in this release train.
    (
        "CL-0025",
        "premise: rw /proc bind makes core_pattern writable",
        _cl0025_core_pattern,
    ),
    ("CL-0026", "premise: memory and cpu are unbounded by default", _cl0026),
    # CL-0003 symptom mappings.
    ("CL-0003", "map: setuid bit inert (and silent) under nnp", _t3_setuid_inert),
    ("CL-0003", "premise: root privilege-drop unaffected by nnp", _t3_drop_unaffected),
]


def _docker_available() -> bool:
    """Report whether a working Docker is reachable. Handles both the
    daemon-down case (non-zero exit) and the not-installed case (the bare
    ``subprocess.run`` would otherwise raise FileNotFoundError and crash)."""
    try:
        proc = subprocess.run(["docker", "version"], capture_output=True)
    except FileNotFoundError:
        return False
    return proc.returncode == 0


def main() -> int:
    if not _docker_available():
        # A silent skip (the old one-line message) let a contributor without
        # Docker believe the premises were validated when they weren't — the gap
        # would surface only in CI. Make the skip unmissable, and let a caller
        # who *requires* the check demand it via CL_REQUIRE_DOCKER=1 (#378).
        bar = "!" * 70
        for line in (
            "",
            bar,
            "!! rule-premise validation SKIPPED — Docker is not available.",
            "!! The rules' runtime premises were NOT checked against a live",
            "!! container, so a drifted premise passes here and surfaces only in",
            "!! CI (the rule-premises job, which has Docker).",
            "!! Set CL_REQUIRE_DOCKER=1 to treat this skip as a hard failure.",
            bar,
            "",
        ):
            print(line, file=sys.stderr)
        return 1 if os.environ.get("CL_REQUIRE_DOCKER") == "1" else 0

    # Pre-pull the pinned images so a registry failure (network outage, Docker
    # Hub rate limit) fails loudly HERE as infrastructure, instead of surfacing
    # inside a check's 90s timeout and being misread as premise drift.
    for image in (IMAGE, PY_IMAGE):
        pull = subprocess.run(
            ["docker", "pull", "-q", image],
            capture_output=True,
            text=True,
            timeout=600,
        )
        if pull.returncode != 0:
            print(
                f"IMAGE PULL FAILED (infrastructure, not premise drift): {image}\n"
                f"{pull.stderr.strip()}",
                file=sys.stderr,
            )
            return 1

    departures, opts = _posture()
    if departures:
        print(f"  [WARN] posture  NOT at Docker defaults — {opts}")
        for what, expected, observed in departures:
            print(f"          · {what}")
            print(f"              expected: {expected}")
            print(f"              observed: {observed}")
        print(
            "\n"
            "POSTURE DEPARTS FROM DOCKER'S DEFAULTS — this run is NOT\n"
            "authoritative, and exits non-zero for that reason alone.\n"
            "\n"
            "The checks below still run, and most do not depend on the setting\n"
            "that departed. But rules are grounded against rootful Docker Engine\n"
            "at default configuration (ADR-020), so a premise measured here\n"
            "cannot be cited as evidence for one — and a check that *does*\n"
            "depend on the departed setting will report a confident, wrong\n"
            "answer rather than an error. Read the results; do not ground on\n"
            "them.\n"
            "\n"
            "For an authoritative run, use a host at Docker's defaults, or\n"
            "push the branch and read the `rule-premises` job, which does.\n"
            "\n"
            "This says nothing about the security of any deployment. It is about\n"
            "where the *measurement* was taken. compose-lint never sees the\n"
            "daemon a compose file will eventually run on (ADR-020), and this\n"
            "check does not pretend otherwise.",
            file=sys.stderr,
        )
    else:
        print(f"  [PASS] posture  daemon is at Docker defaults — {opts}")

    failures = []
    for rule_id, label, check in CHECKS:
        try:
            ok, detail = check()
        except Exception as exc:  # noqa: BLE001 - a crashed check is a failure
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {rule_id}  {label}\n          {detail}")
        if not ok:
            # Include the label: 12 rows share rule_id CL-0006, and a bare
            # "CL-0006, CL-0006" summary hides which mapping broke.
            failures.append(f"{rule_id} ({label})")

    print()
    print(f"not runtime-testable (grounded by source): {', '.join(_NON_RUNTIME)}")
    if failures:
        print(f"RESULT: FAIL ({len(failures)}): {', '.join(failures)}")
        return 1
    if departures:
        print(
            f"RESULT: NOT AUTHORITATIVE — {len(CHECKS)} premises ran and none "
            "failed, but the daemon is not at Docker's defaults, so this run "
            "cannot ground a rule. See the posture note above."
        )
        return 1
    print(f"RESULT: PASS ({len(CHECKS)} premises validated)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
