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

from compose_lint.rules._mounts import TIMEZONE_FILES
from compose_lint.rules.CL0001_docker_socket import _RUNTIME_SOCKETS, _SOCKET_DIRS
from compose_lint.rules.CL0011_dangerous_cap_add import STRONG_CAPS
from compose_lint.rules.CL0013_sensitive_mount import _EXPOSED_PATHS
from compose_lint.rules.CL0016_dangerous_devices import _DANGEROUS_DEVICE_PATTERNS
from compose_lint.rules.CL0024_host_exec_cap_add import HOST_EXEC_CAPS
from compose_lint.rules.CL0025_writable_host_root import ROOT_EQUIVALENT_PATHS
from compose_lint.rules.CL0027_lesser_cap_add import LESSER_CAPS


class TestCapabilityTiers:
    """``cap_add`` is graded by what the capability grants, across three rules.

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
        # MEDIUM: a real but bounded grant. Moving a debugger or NTP sidecar's
        # capability out of HIGH was the precision win that justified the tier.
        assert set(LESSER_CAPS) == {
            "SYS_PTRACE",
            "PERFMON",
            "SYS_TIME",
            "DAC_READ_SEARCH",
        }

    def test_the_three_tiers_are_disjoint(self) -> None:
        tiers = [set(HOST_EXEC_CAPS), set(STRONG_CAPS), set(LESSER_CAPS)]
        assert sum(len(t) for t in tiers) == len(set().union(*tiers)), (
            "a capability appears in more than one tier, so it double-reports"
        )

    def test_deliberately_excluded_capabilities_stay_out(self) -> None:
        """Each of these was examined and rejected with a recorded reason.

        Re-adding one silently would repeat the mistake that removed
        DAC_OVERRIDE (a Docker default, issue #492) and CL-0023.
        """
        graded = set(HOST_EXEC_CAPS) | set(STRONG_CAPS) | set(LESSER_CAPS)
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
        # Writable, these are host root through ordinary file writes.
        assert set(ROOT_EQUIVALENT_PATHS) == {
            "/etc",
            "/root",
            "/boot",
            "/var/lib/docker",
            "/proc",
        }

    def test_whole_root_is_not_cl0025s(self) -> None:
        # "/" contains the daemon control socket, so it is host root in *either*
        # mode. CL-0001 owns it; grading it here would miss the read-only case.
        assert "/" not in ROOT_EQUIVALENT_PATHS

    def test_exposed_paths_are_cl0013s(self) -> None:
        # Disclosure or a weakened boundary in either mode. /var/lib/kubelet was
        # dropped: its danger is conditional on Kubernetes, so it cannot be
        # premise-checked on the grounded target.
        assert set(_EXPOSED_PATHS) == {"/sys", "/dev", "/home"}
        assert "/var/lib/kubelet" not in _EXPOSED_PATHS

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
        } <= self._patterns()

    def test_capability_gated_devices_are_not_claimed(self) -> None:
        """Live only alongside a capability another rule already flags.

        Verified at default capabilities: /dev/mem and /dev/port are refused
        without CAP_SYS_RAWIO (CL-0024), and /dev/fuse's mount(2) needs
        CAP_SYS_ADMIN (CL-0024) plus an unconfined AppArmor profile (CL-0009).
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
