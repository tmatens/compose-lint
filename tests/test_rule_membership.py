"""Every rule's member list, pinned against the decision that chose it.

This is the one consistency check the rest of the suite cannot make. The other
enforcement tests compare the code against the docs -- the severity table, the
derivation blocks, the ATT&CK mapping -- which catches drift between two
surfaces that disagree. It cannot catch the case where both surfaces agree with
each other and neither matches what was decided.

That case shipped. CL-0016 was specified to gain ``/dev/vd*``, ``/dev/xvd*``,
``/dev/mmcblk*`` and ``/dev/md*`` -- the host root disks of KVM and Proxmox
guests, EC2 instances, Raspberry Pis and mdraid arrays -- and to drop
``/dev/kmem`` and ``/dev/raw``. Neither half landed. Nothing in the repository
contradicted anything: the code and the page agreed the patterns did not exist,
so there was no inconsistency for a reviewer or a test to trip over, and a
``devices: ["/dev/vda:/dev/vda"]`` on a Proxmox guest handed over the host root
disk at a clean pass.

So these lists are transcribed from the decisions rather than from the code.
Editing a rule's membership is meant to fail here first, which forces the
question "was that decided?" before the change is reviewable. Each entry names
the reason its members were chosen, so a future edit can tell an intentional
membership change from an accident.
"""

from __future__ import annotations

import itertools
from pathlib import Path

from compose_lint.engine import run_rules
from compose_lint.parser import loads
from compose_lint.rules._mounts import TIMEZONE_FILES, match_prefix
from compose_lint.rules.CL0001_docker_socket import _RUNTIME_SOCKETS, _SOCKET_DIRS
from compose_lint.rules.CL0011_dangerous_cap_add import STRONG_CAPS
from compose_lint.rules.CL0013_sensitive_mount import (
    _EXPOSED_PATHS,
    _HOME_CREDENTIAL_DIRS,
    _match_home_tree,
)
from compose_lint.rules.CL0016_dangerous_devices import _DANGEROUS_DEVICE_PATTERNS
from compose_lint.rules.CL0024_host_exec_cap_add import HOST_EXEC_CAPS
from compose_lint.rules.CL0025_writable_host_root import (
    ROOT_EQUIVALENT_EXACT_PATHS,
    ROOT_EQUIVALENT_PATHS,
    match_root_equivalent,
)
from compose_lint.rules.CL0027_lesser_cap_add import LESSER_CAPS
from compose_lint.rules.CL0028_host_reach_cap_add import HOST_REACH_CAPS
from compose_lint.rules.CL0029_host_availability_cap_add import (
    HOST_AVAILABILITY_CAPS,
)
from compose_lint.rules.CL0030_host_disclosure_cap_add import (
    HOST_DISCLOSURE_CAPS,
)


class TestCapabilityTiers:
    """``cap_add`` is graded by what the capability grants, across four rules.

    The tiers are the split's whole point, so a capability moving between them
    is a severity change for that capability and has to be deliberate.
    """

    def test_host_code_execution_tier(self) -> None:
        # CRITICAL: reaches host code execution. SYS_ADMIN sits here as a
        # documented judgment call -- its escape needs a technique -- but both
        # readings land at CRITICAL, so the tier is unaffected.
        assert set(HOST_EXEC_CAPS) == {"ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO"}

    def test_strong_host_adjacent_tier(self) -> None:
        # HIGH: reaches past this container without handing over host code
        # execution outright.
        assert set(STRONG_CAPS) == {"NET_ADMIN", "BPF", "SYS_BOOT"}

    def test_bounded_grant_tier(self) -> None:
        # MEDIUM: bounded twice over -- confined to this container, and live
        # only where the image supplies a different-uid process or a file the
        # workload uid cannot already read. Moving a debugger sidecar's
        # capability out of HIGH was the precision win that justified the tier.
        assert set(LESSER_CAPS) == {"SYS_PTRACE", "DAC_READ_SEARCH"}

    def test_host_reaching_tier(self) -> None:
        # HIGH: reaches the host with no sibling key and nothing from the
        # image, but stops short of host code execution. These two were
        # CL-0027's until the split; priced there, the rule had to set them
        # aside as scoping assumptions, a clause reserved for reach that
        # *depends* on a sibling key -- which neither of these does.
        assert set(HOST_REACH_CAPS) == {"PERFMON", "SYS_TIME"}

    def test_the_four_tiers_are_disjoint(self) -> None:
        tiers = [
            set(HOST_EXEC_CAPS),
            set(STRONG_CAPS),
            set(LESSER_CAPS),
            set(HOST_REACH_CAPS),
        ]
        assert sum(len(t) for t in tiers) == len(set().union(*tiers)), (
            "a capability appears in more than one tier, so it double-reports"
        )

    def test_deliberately_excluded_capabilities_stay_out(self) -> None:
        """Each of these was examined and rejected with a recorded reason.

        Re-adding one silently would repeat the mistake that removed
        DAC_OVERRIDE (a Docker default, issue #492) and CL-0023.
        """
        graded = (
            set(HOST_EXEC_CAPS)
            | set(STRONG_CAPS)
            | set(LESSER_CAPS)
            | set(HOST_REACH_CAPS)
        )
        excluded = {
            "DAC_OVERRIDE": "a Docker default, so cap_drop: [ALL] already covers it",
            "MKNOD": "a Docker default",
            "SYS_CHROOT": "a Docker default",
            "NET_RAW": "a Docker default -- CL-0006 owns the absence of cap_drop",
            "SETPCAP": "verified inert: cannot raise a capability not held",
            "MAC_ADMIN": "verified inert under Docker's masked /sys/kernel/security",
            "MAC_OVERRIDE": "verified inert, same reason",
        }
        for cap, why in excluded.items():
            assert cap not in graded, f"{cap} was excluded because {why}"


class TestMountOwnership:
    """Which rule owns which host path.

    The three mount rules partition the input: every mount is claimed by
    exactly one. A path moving between them is a severity change and a
    suppression migration, never a tidy-up.
    """

    def test_root_equivalent_paths_are_cl0025s(self) -> None:
        # Writable, these are host root through ordinary file writes, and they
        # stay root-equivalent all the way down -- everything under /etc or
        # /var/lib/docker carries the same grant, so descent is the right match.
        assert set(ROOT_EQUIVALENT_PATHS) == {
            "/etc",
            "/root",
            "/boot",
            "/var/lib/docker",
            "/var/lib/containerd",
            "/proc",
        }

    def test_var_lib_is_matched_exactly_not_by_descent(self) -> None:
        # /var/lib is root-equivalent because of what it *contains* -- the
        # container store -- not because of what lies below it. Those are
        # different sets: /var/lib/mysql contains neither /var/lib/docker nor
        # /var/lib/containerd. Matching it by descent priced every stateful
        # service's own data directory as host root (24 of 25 corpus hits).
        assert set(ROOT_EQUIVALENT_EXACT_PATHS) == {"/var/lib"}
        assert "/var/lib" not in ROOT_EQUIVALENT_PATHS

        # The behaviour the split exists to produce.
        assert match_root_equivalent("/var/lib") == "/var/lib"
        assert match_root_equivalent("/var/lib/docker") == "/var/lib/docker"
        assert match_root_equivalent("/var/lib/docker/volumes") == "/var/lib/docker"
        assert match_root_equivalent("/var/lib/containerd") == "/var/lib/containerd"
        for benign in (
            "/var/lib/mysql",
            "/var/lib/postgresql/data",
            "/var/lib/grafana",
            "/var/lib/redis",
        ):
            assert match_root_equivalent(benign) is None, benign

    def test_no_root_equivalent_entry_shadows_another(self) -> None:
        # match_prefix returns the *first* matching entry, so a member that is a
        # prefix of another makes the message depend on list order. Keeping the
        # descent members mutually disjoint removes that coupling entirely --
        # which is what the /var/lib split bought. If a future member does nest,
        # this fails and the ordering has to be made explicit again.
        paths = list(ROOT_EQUIVALENT_PATHS)
        for outer in paths:
            for inner in paths:
                if outer is not inner:
                    assert not inner.startswith(outer + "/"), (
                        f"{inner} sits under {outer}; ordering now decides the "
                        "message, so assert it explicitly"
                    )
        # An exact-only member must not also be reachable by descent, or the two
        # lists would disagree about which grant text applies.
        for exact in ROOT_EQUIVALENT_EXACT_PATHS:
            assert match_prefix(exact, ROOT_EQUIVALENT_PATHS) is None

    def test_every_member_path_appears_in_its_rule_doc(self) -> None:
        """A member a user cannot read about is a member they cannot waive.

        The lists above pin the *code*, and nothing tied them to the page the
        finding's `--explain` sends people to. `/var/lib` shipped as a CRITICAL
        member of CL-0025 with no mention on `docs/rules/CL-0025.md` at all --
        the membership guard passed, because it only ever compared the list to
        itself.
        """
        repo = Path(__file__).parent.parent
        expected = {
            "CL-0025": (
                *ROOT_EQUIVALENT_PATHS,
                *ROOT_EQUIVALENT_EXACT_PATHS,
            ),
            "CL-0013": (
                *_EXPOSED_PATHS,
                "/home",
                *(f".{d.lstrip('.')}" for d in _HOME_CREDENTIAL_DIRS),
            ),
        }
        for rule_id, members in expected.items():
            doc = (repo / "docs" / "rules" / f"{rule_id}.md").read_text(
                encoding="utf-8"
            )
            for member in members:
                assert member in doc, (
                    f"{member} is a {rule_id} member but appears nowhere in "
                    f"docs/rules/{rule_id}.md"
                )

    def test_whole_root_is_not_cl0025s(self) -> None:
        # "/" contains the daemon control socket, so it is host root in *either*
        # mode. CL-0001 owns it; grading it here would miss the read-only case.
        assert "/" not in ROOT_EQUIVALENT_PATHS

    def test_exposed_paths_are_cl0013s(self) -> None:
        # Disclosure or a weakened boundary in either mode. /var/lib/kubelet was
        # dropped: its danger is conditional on Kubernetes, so it cannot be
        # premise-checked on the grounded target. /home is not here because it
        # is not a descent match -- see the home-tree tests below.
        assert set(_EXPOSED_PATHS) == {"/sys", "/dev"}
        assert "/var/lib/kubelet" not in _EXPOSED_PATHS
        assert "/home" not in _EXPOSED_PATHS

    def test_the_home_tree_is_matched_by_depth_not_descent(self) -> None:
        # Exposing the home tree is a disclosure; sitting inside it is not.
        # Resolving relative sources made "./data" absolute under the compose
        # file's directory, which for almost every real file is under /home --
        # so a descent match turned the commonest bind idiom in Compose into a
        # HIGH finding (4,598 findings over 1,712 of 5,417 corpus files).
        assert _match_home_tree("/home") == "/home"
        assert _match_home_tree("/home/alice") == "/home/alice"

        # Credential directories keep a descent match: the grant does not
        # weaken with depth the way a project directory's does.
        assert _match_home_tree("/home/alice/.ssh") == "/home/alice/.ssh"
        assert _match_home_tree("/home/alice/.ssh/id_ed25519") == "/home/alice/.ssh"
        assert _match_home_tree("/home/alice/.docker") == "/home/alice/.docker"

        # A project directory is the application's own, not host user data.
        for benign in (
            "/home/alice/projects/app/data",
            "/home/alice/stacks/blog/config/nginx.conf",
            "/home/alice/compose-data",
        ):
            assert _match_home_tree(benign) is None, benign

    def test_socket_directories_are_cl0001s(self) -> None:
        # Mounting one hands over the socket inside it, mode-independently.
        assert set(_SOCKET_DIRS) == {
            "/run/containerd",
            "/run/systemd",
            "/var/run",
            "/run",
            "/",
        }

    def test_control_socket_names(self) -> None:
        # systemd/private is not named "*.sock" but drives StartTransientUnit.
        assert set(_RUNTIME_SOCKETS) == {
            "docker.sock",
            "containerd.sock",
            "crio.sock",
            "podman.sock",
            "systemd/private",
        }

    def test_timezone_files_are_exempt_from_the_critical_tier(self) -> None:
        # Writing these changes the host's timezone, not host root (issue #509).
        assert set(TIMEZONE_FILES) == {"/etc/localtime", "/etc/timezone"}


class TestDeviceMembership:
    """CL-0016 covers devices that grant reach with the capabilities a
    container already has. This is the list that drifted."""

    def _patterns(self) -> set[str]:
        return {p.pattern for p, _ in _DANGEROUS_DEVICE_PATTERNS}

    def test_the_device_list_is_exactly_this(self) -> None:
        """The whole set, pinned by equality like every other list here.

        The tests below assert that four patterns are *present* and that six
        are *absent*, which leaves the rest of the list unguarded: with only
        those, ``/dev/mapper/``, ``/dev/zfs`` and ``/dev/rbd`` could each be
        deleted, and an undecided pattern added, with the full suite green.
        Measured -- each of those four mutations passed 1355 tests. That is the
        same escape this file was written to close, in the same rule, so the
        set is pinned exactly.
        """
        assert self._patterns() == {
            # Raw block devices: a capability-independent read of the host's
            # disk, which is what puts this rule in the CRITICAL tier.
            r"^/dev/sd[a-z]",
            r"^/dev/nvme",
            r"^/dev/vd[a-z]",
            r"^/dev/xvd[a-z]",
            r"^/dev/mmcblk",
            r"^/dev/md\d",
            r"^/dev/md/",
            r"^/dev/dm-",
            r"^/dev/rbd",
            # Symlinks and control nodes that reach the same devices.
            r"^/dev/disk/",
            r"^/dev/mapper/",
            r"^/dev/zfs$",
            r"^/dev/loop",
            # Not a block device, kept for the reason in the test below.
            r"^/dev/kmsg$",
        }

    def test_block_devices_cover_the_mainstream_hypervisors(self) -> None:
        """The four that were specified and never landed.

        /dev/vda is the host root disk on KVM and Proxmox, /dev/xvda on EC2,
        /dev/mmcblk0 on a Raspberry Pi, /dev/md0 on an mdraid array. Each is a
        capability-independent raw disk read, which is what puts this rule in
        the CRITICAL tier at all.
        """
        assert {
            r"^/dev/vd[a-z]",
            r"^/dev/xvd[a-z]",
            r"^/dev/mmcblk",
            r"^/dev/md\d",
            r"^/dev/md/",
        } <= self._patterns()

    def test_capability_gated_devices_are_not_claimed(self) -> None:
        """Live only alongside a capability another rule already flags.

        Verified at default capabilities on both grounding hosts: /dev/mem and
        /dev/port are refused without CAP_SYS_RAWIO, and readable with it;
        /dev/fuse's mount(2) needs CAP_SYS_ADMIN. Both capabilities are
        CL-0024's, at CRITICAL, which is what puts these devices outside this
        rule. On an AppArmor host fuse needs an unconfined profile as well
        (CL-0009), but that leg is posture-specific -- SYS_ADMIN alone mounts
        where no AppArmor policy is loaded -- so the drop rests on the
        capability gate, which holds everywhere.
        """
        for pattern in (r"^/dev/mem$", r"^/dev/port$", r"^/dev/fuse$"):
            assert pattern not in self._patterns(), pattern

    def test_unreachable_devices_are_not_claimed(self) -> None:
        """Docker refuses to create the container for either of these, so a
        finding could never describe a running service."""
        for pattern in (r"^/dev/kmem$", r"^/dev/raw"):
            assert pattern not in self._patterns(), pattern

    def test_loop_and_kmsg_are_kept_deliberately(self) -> None:
        """Both look capability-gated and are not, at the grounded default.

        /dev/loop*: a container with only --device /dev/loop-control, at
        --cap-drop ALL, allocated a host loop device via LOOP_CTL_GET_FREE.
        /dev/kmsg: needs CAP_SYSLOG only where dmesg_restrict is 1, and the
        upstream default is 0 -- and no rule flags SYSLOG.
        """
        assert r"^/dev/loop" in self._patterns()
        assert r"^/dev/kmsg$" in self._patterns()


class TestRuntimeDirectoryPartition:
    """`/run` and `/var/run` split between CL-0001 and CL-0013 by direction.

    CL-0001 owns a socket directory and its *ancestors*, because those hold the
    control socket. What sits strictly *below* holds host service state instead
    -- the system bus, the libvirt socket, udev's database -- and that is
    CL-0013's. CL-0013 matched all of it by descent until the directories moved
    to CL-0001; the move left the descendants owned by neither, and 35 HIGH
    findings vanished from the corpus without anything recording the decision.
    """

    def _owners(self, host_path: str) -> set[str]:
        data, lines = loads(
            f"services:\n  a:\n    image: x\n    volumes:\n      - {host_path}:/mnt\n"
        )
        return {
            f.rule_id
            for f in run_rules(data, lines)
            if f.rule_id in {"CL-0001", "CL-0013", "CL-0025"}
        }

    def test_socket_directories_and_ancestors_are_cl0001s(self) -> None:
        for path in ("/", "/var", "/run", "/var/run", "/run/containerd"):
            assert self._owners(path) == {"CL-0001"}, path

    def test_strict_descendants_are_cl0013s(self) -> None:
        # None of these holds a control socket, so CRITICAL would be false --
        # but they are not nothing either.
        for path in (
            "/run/dbus",
            "/var/run/dbus",
            "/var/run/libvirt/libvirt-sock",
            "/run/udev",
            "/run/user/1000",
            "/run/myapp",
        ):
            assert self._owners(path) == {"CL-0013"}, path

    def test_a_descendant_that_is_a_socket_stays_cl0001s(self) -> None:
        # The socket-name match still wins, so these must not double-report.
        for path in (
            "/run/docker.sock",
            "/var/run/docker.sock",
            "/run/systemd/private",
        ):
            assert self._owners(path) == {"CL-0001"}, path

    def test_inert_devices_are_claimed_by_nobody(self) -> None:
        # A bit bucket discloses nothing. /dev/null:/some/config is a common way
        # to blank a file the image expects, and it was priced HIGH.
        for path in ("/dev/null", "/dev/zero", "/dev/urandom", "/dev/random"):
            assert self._owners(path) == set(), path

    def test_the_rest_of_dev_is_untouched(self) -> None:
        for path in ("/dev", "/dev/shm", "/dev/sda"):
            assert "CL-0013" in self._owners(path), path


# Every capability the kernel defines, CAP_CHOWN (0) through CAP_LAST_CAP.
# Linux 6.x defines 41. Listed in full so a capability cannot be omitted by
# never being thought about -- the disjointness tests above prove the four
# tiers do not overlap, which is a different claim from proving nothing was
# forgotten, and only the first was checked.
_ALL_LINUX_CAPABILITIES: frozenset[str] = frozenset(
    {
        "AUDIT_CONTROL",
        "AUDIT_READ",
        "AUDIT_WRITE",
        "BLOCK_SUSPEND",
        "BPF",
        "CHECKPOINT_RESTORE",
        "CHOWN",
        "DAC_OVERRIDE",
        "DAC_READ_SEARCH",
        "FOWNER",
        "FSETID",
        "IPC_LOCK",
        "IPC_OWNER",
        "KILL",
        "LEASE",
        "LINUX_IMMUTABLE",
        "MAC_ADMIN",
        "MAC_OVERRIDE",
        "MKNOD",
        "NET_ADMIN",
        "NET_BIND_SERVICE",
        "NET_BROADCAST",
        "NET_RAW",
        "PERFMON",
        "SETFCAP",
        "SETGID",
        "SETPCAP",
        "SETUID",
        "SYSLOG",
        "SYS_ADMIN",
        "SYS_BOOT",
        "SYS_CHROOT",
        "SYS_MODULE",
        "SYS_NICE",
        "SYS_PACCT",
        "SYS_PTRACE",
        "SYS_RAWIO",
        "SYS_RESOURCE",
        "SYS_TIME",
        "SYS_TTY_CONFIG",
        "WAKE_ALARM",
    }
)

# Docker grants these to every container by default, so naming one in cap_add
# is a no-op and there is nothing to grade. Dropping them is CL-0006's.
_DOCKER_DEFAULT_CAPABILITIES: frozenset[str] = frozenset(
    {
        "AUDIT_WRITE",
        "CHOWN",
        "DAC_OVERRIDE",
        "FOWNER",
        "FSETID",
        "KILL",
        "MKNOD",
        "NET_BIND_SERVICE",
        "NET_RAW",
        "SETFCAP",
        "SETGID",
        "SETPCAP",
        "SETUID",
        "SYS_CHROOT",
    }
)

# Considered and deliberately not graded, with the reason on record.
#
# The entries below MAC_OVERRIDE were measured against Docker 29.4.3 on
# 2026-08-11, each by holding the single capability under `--cap-drop ALL` and
# comparing against the same run without it. They fall into two families.
#
# **Reach needs a sibling key another rule already scores.** The capability is
# real and confers what its man page says, but only once the file also sets a
# key that is itself a HIGH finding. Grading the capability would double-report
# the same configuration. This is the ADR-020 scoping clause, and the same
# treatment SYS_PTRACE's host-PID reach and DAC_READ_SEARCH's host leg already
# get. Measured: with the capability alone every one of these is denied.
#
# **Inert or negligible at Docker's default posture.** Either the default
# seccomp profile, the read-only /sys, or the device cgroup neutralises the
# grant, or the grant lands somewhere that is not a security boundary. Grading
# one would be the CL-0022/CL-0023 failure mode -- a rule that fires on a
# configuration the runtime already defends.
_EXCLUDED_WITH_REASON: dict[str, str] = {
    "MAC_ADMIN": "verified inert under Docker's masked /sys/kernel/security",
    "MAC_OVERRIDE": "verified inert, same reason",
    # --- reach gated behind a sibling key that another rule scores ---
    "AUDIT_CONTROL": (
        "audit netlink requires the initial PID namespace: AUDIT_GET is EPERM "
        "with the capability alone and with --privileged, and succeeds only "
        "with `pid: host`, which CL-0010 scores"
    ),
    "AUDIT_READ": (
        "the capability opens the audit multicast socket but records are "
        "delivered per network namespace: 0 records with the capability "
        "alone, 40 host records with `network_mode: host`, which CL-0008 "
        "scores"
    ),
    "IPC_OWNER": (
        "SysV IPC objects are namespaced -- a container gets its own IPC "
        "namespace, so the permission bypass reaches nothing until "
        "`ipc: host`, which CL-0010 scores"
    ),
    "SYS_PACCT": (
        "BSD process accounting is per-PID-namespace: a container enabling it "
        "captured 1 of its own process exits and none of 25 host exits, "
        "against 122 host records under `pid: host`, which CL-0010 scores"
    ),
    "LINUX_IMMUTABLE": (
        "sets the immutable flag on host files, but only through a *writable* "
        "bind mount -- EROFS through a read-only one -- and the paths worth "
        "protecting are CL-0013's and CL-0025's"
    ),
    # --- inert or negligible at Docker's default posture ---
    "CHECKPOINT_RESTORE": (
        "grants clone3(set_tid), but Docker's default seccomp profile admits "
        "clone3 only for CAP_SYS_ADMIN: ENOSYS with the capability, and it "
        "succeeds only under `seccomp:unconfined`, which CL-0009 scores"
    ),
    "SYS_TTY_CONFIG": (
        "vhangup() succeeds but reaches only the container's own pty; "
        "/dev/console and the host VTs are absent under the device cgroup, "
        "and exposing one is CL-0016's"
    ),
    "BLOCK_SUSPEND": (
        "the wake_lock interface lives under /sys, which Docker mounts "
        "read-only: EROFS with the capability held. Not proven from the "
        "other side -- the measuring kernel had CONFIG_PM_WAKELOCKS unset"
    ),
    "WAKE_ALARM": (
        "grant confirmed (timerfd_create(CLOCK_REALTIME_ALARM) is EPERM "
        "without it), but the reach is waking a suspended host, which is not "
        "a boundary a Compose file defends"
    ),
    "NET_BROADCAST": (
        "confers nothing observable -- the kernel does not check it; a UDP "
        "broadcast sends identically with and without the capability"
    ),
    "SYS_RESOURCE": (
        "raises the process's own hard rlimits, which stays inside the "
        "container's cgroup; the host-sysctl leg is EROFS on /proc/sys until "
        "`privileged`, which CL-0002 scores"
    ),
}

# Not granted by default, not graded, and no reason recorded anywhere.
#
# **It is empty, and that is the point.** This set was the hole §47.4 of the
# severity review named: fifteen capabilities that passed every disjointness
# test by being in none of the tiers. Eleven now carry a measured reason in
# _EXCLUDED_WITH_REASON; the other four were measured reaching the host with no
# other key in the file and were owed rules rather than exclusions, which is
# what CL-0029 (SYS_NICE, IPC_LOCK, LEASE) and CL-0030 (SYSLOG) are.
#
# Keep it empty. A capability landing here is not a neutral "to be decided" --
# it is a capability the tool has no opinion about, which is the state this set
# exists to make visible. Grading it, or excluding it with a reason someone can
# check, is a one-line edit either way.
_UNGRADED_NO_RECORDED_REASON: frozenset[str] = frozenset()


class TestCapabilityCompleteness:
    """Every Linux capability has a recorded disposition.

    The tier tests prove the four graded sets are disjoint. Disjointness says
    nothing about coverage: a capability omitted from all four passes every one
    of them. This closes that by requiring each of the kernel's 41 to land in
    exactly one bucket -- graded, Docker default, excluded with a reason, or
    explicitly ungraded.
    """

    def _graded(self) -> set[str]:
        return (
            (
                set(HOST_EXEC_CAPS)
                | set(STRONG_CAPS)
                | set(HOST_REACH_CAPS)
                | set(HOST_AVAILABILITY_CAPS)
                | set(HOST_DISCLOSURE_CAPS)
                | set(LESSER_CAPS)
            )
            - {"ALL"}  # a keyword, not a capability
        )

    def test_every_capability_has_exactly_one_disposition(self) -> None:
        buckets = {
            "graded": self._graded(),
            "docker default": set(_DOCKER_DEFAULT_CAPABILITIES),
            "excluded with reason": set(_EXCLUDED_WITH_REASON),
            "ungraded, no reason": set(_UNGRADED_NO_RECORDED_REASON),
        }
        for a, b in itertools.combinations(sorted(buckets), 2):
            overlap = buckets[a] & buckets[b]
            assert not overlap, f"{sorted(overlap)} is both '{a}' and '{b}'"

        covered = set().union(*buckets.values())
        missing = _ALL_LINUX_CAPABILITIES - covered
        assert not missing, (
            f"{sorted(missing)} has no recorded disposition -- grade it, or add "
            "it to the excluded or explicitly-ungraded list with a reason"
        )
        invented = covered - _ALL_LINUX_CAPABILITIES
        assert not invented, f"{sorted(invented)} is not a Linux capability"

    def test_no_graded_capability_is_a_docker_default(self) -> None:
        # Grading one would flag a cap_add that changes nothing, which is the
        # CL-0022/CL-0023 failure mode: a rule firing on a Docker default.
        overlap = self._graded() & _DOCKER_DEFAULT_CAPABILITIES
        assert not overlap, f"{sorted(overlap)} is granted by default"
