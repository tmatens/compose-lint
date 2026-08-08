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

Usage: ``python scripts/validate_rule_premises.py`` (needs a working **rootful**
Docker). Under rootless Docker several checks fail spuriously: the kernel
authorizes SYS_NICE/SYS_TIME/IPC_LOCK in the *init* user namespace, so their
allow legs fail even with the capability granted, and the socket-mount and
/dev/kmsg checks assume rootful paths. CI runs rootful; treat rootless-local
failures as environmental.
Exits 0 if every premise holds (or Docker is unavailable → skipped), 1 on any
failure. Rules that describe image/supply-chain or config-only concerns
(CL-0004, CL-0014, CL-0015, CL-0019, CL-0020, CL-0021) have no runtime state to
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
# python:3.13-alpine — used only by the IPC_LOCK mapping check: proving the
# mlockall(2) -> CAP_IPC_LOCK mapping needs a libc caller busybox doesn't ship.
PY_IMAGE = (
    "python@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0"
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
    print(f"RESULT: PASS ({len(CHECKS)} premises validated)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
