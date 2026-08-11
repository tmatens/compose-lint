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

from pathlib import Path

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
