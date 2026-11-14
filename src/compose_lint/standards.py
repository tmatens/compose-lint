"""CIS and OWASP mapping for the rule set, and the SARIF tags built from it.

Each rule cites its sources as prose in ``references``. A person can read
that; a dashboard cannot filter on it. This module holds the same mapping as
data, so SARIF can carry it in ``properties.tags`` next to the MITRE ATT&CK
mapping in :mod:`compose_lint.attack`, which is tagged from here too.

**What a tag claims.** A tag says the rule *relates to* the named control or
technique. It does not say that a file with no findings complies with the
benchmark. compose-lint reads a Compose file, not a running daemon, so most
of any benchmark is outside what it can see.

**The version pin is load-bearing.** CIS renumbers controls between benchmark
versions: memory limits are 5.11 in v1.9.0 and were 5.10 two versions
earlier. A number is only meaningful beside the version it was read from, so
moving ``CIS_DOCKER_VERSION`` means re-reading every control cited here
against the new text.

The OWASP Docker Security Cheat Sheet is unversioned. Its rules are cited by
the rule number in their heading, and the anchor is that heading's slug.

The rules keep their own ``references`` strings. ``tests/test_standards_mapping.py``
holds the two together: a rule that cites a control this module does not
list, or the reverse, fails there.
"""

from __future__ import annotations

from typing import NamedTuple

from compose_lint.attack import RULE_TECHNIQUES

#: CIS Docker Benchmark release every control number here was read from.
CIS_DOCKER_VERSION = "1.9.0"

OWASP_DOCKER_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"
)

#: Both GitHub Code Scanning and GitLab keep at most this many tags per rule.
#: GitHub accepts up to 20 and includes 10; it does not say which.
MAX_TAGS_PER_RULE = 10

#: Tag prefixes, in the order tags are emitted. The ``external/<source>/<id>``
#: shape is the one CodeQL uses for its own CWE tags, so it is the shape a
#: Code Scanning user has already met.
CIS_TAG_PREFIX = "external/cis-docker/"
OWASP_TAG_PREFIX = "external/owasp-docker/"
ATTACK_TAG_PREFIX = "external/mitre-attack/"


class CisControl(NamedTuple):
    """One CIS Docker Benchmark recommendation, as this project cites it."""

    id: str
    title: str

    @property
    def reference(self) -> str:
        """The string a rule carries in ``references``."""
        return f"CIS Docker Benchmark {self.id} — {self.title}"

    @property
    def tag(self) -> str:
        return f"{CIS_TAG_PREFIX}{self.id}"


class OwaspRule(NamedTuple):
    """One rule of the OWASP Docker Security Cheat Sheet."""

    #: The number in the rule's heading: ``"3"``, or ``"5a"``.
    id: str
    title: str
    #: The heading's slug on the published page.
    anchor: str

    @property
    def reference(self) -> str:
        """The URL a rule carries in ``references``."""
        return f"{OWASP_DOCKER_URL}#{self.anchor}"

    @property
    def tag(self) -> str:
        return f"{OWASP_TAG_PREFIX}rule-{self.id}"


CIS_2_14 = CisControl("2.14", "Ensure centralized and remote logging is configured")
CIS_5_2 = CisControl(
    "5.2", "Ensure that, if applicable, an AppArmor Profile is enabled"
)
CIS_5_3 = CisControl(
    "5.3", "Ensure that, if applicable, SELinux security options are set"
)
CIS_5_4 = CisControl(
    "5.4", "Ensure that Linux kernel capabilities are restricted within containers"
)
CIS_5_5 = CisControl("5.5", "Ensure that privileged containers are not used")
CIS_5_6 = CisControl(
    "5.6", "Ensure sensitive host system directories are not mounted on containers"
)
CIS_5_10 = CisControl("5.10", "Ensure that the host's network namespace is not shared")
CIS_5_11 = CisControl("5.11", "Ensure that the memory usage for containers is limited")
CIS_5_12 = CisControl(
    "5.12", "Ensure that CPU priority is set appropriately on containers"
)
CIS_5_13 = CisControl(
    "5.13", "Ensure that the container's root filesystem is mounted as read only"
)
CIS_5_14 = CisControl(
    "5.14",
    "Ensure that incoming container traffic is bound to a specific host interface",
)
CIS_5_16 = CisControl("5.16", "Ensure that the host's process namespace is not shared")
CIS_5_17 = CisControl("5.17", "Ensure that the host's IPC namespace is not shared")
CIS_5_18 = CisControl(
    "5.18", "Ensure that host devices are not directly exposed to containers"
)
CIS_5_20 = CisControl("5.20", "Ensure mount propagation mode is not set to shared")
CIS_5_22 = CisControl("5.22", "Ensure the default seccomp profile is not Disabled")
CIS_5_26 = CisControl(
    "5.26",
    "Ensure that the container is restricted from acquiring additional privileges",
)
CIS_5_28 = CisControl(
    "5.28",
    "Ensure that Docker commands always make use of the latest version of their image",
)
CIS_5_32 = CisControl(
    "5.32", "Ensure that the Docker socket is not mounted inside any containers"
)

OWASP_1 = OwaspRule(
    "1",
    "Do not expose the Docker daemon socket (even to the containers)",
    "rule-1-do-not-expose-the-docker-daemon-socket-even-to-the-containers",
)
OWASP_2 = OwaspRule("2", "Set a user", "rule-2-set-a-user")
OWASP_3 = OwaspRule(
    "3",
    "Limit capabilities (Grant only specific capabilities, needed by a container)",
    "rule-3-limit-capabilities-grant-only-specific-capabilities-needed-by-a-container",
)
OWASP_4 = OwaspRule(
    "4",
    "Prevent in-container privilege escalation",
    "rule-4-prevent-in-container-privilege-escalation",
)
OWASP_5A = OwaspRule(
    "5a",
    "Be careful when mapping container ports to the host with firewalls like UFW",
    "rule-5a-be-careful-when-mapping-container-ports-to-the-host-with-firewalls-like-ufw",
)
OWASP_6 = OwaspRule(
    "6",
    "Use Linux Security Module (seccomp, AppArmor, or SELinux) for runtime security",
    "rule-6-use-linux-security-module-seccomp-apparmor-or-selinux-for-runtime-security",
)
OWASP_7 = OwaspRule(
    "7",
    "Limit resources (memory, CPU, file descriptors, processes, restarts)",
    "rule-7-limit-resources-memory-cpu-file-descriptors-processes-restarts",
)
OWASP_8 = OwaspRule(
    "8",
    "Set filesystem and volumes to read-only",
    "rule-8-set-filesystem-and-volumes-to-read-only",
)
OWASP_12 = OwaspRule(
    "12",
    "Utilize Docker Secrets for Sensitive Data Management",
    "rule-12-utilize-docker-secrets-for-sensitive-data-management",
)
OWASP_13 = OwaspRule(
    "13", "Enhance Supply Chain Security", "rule-13-enhance-supply-chain-security"
)

#: rule id -> the CIS Docker Benchmark controls it relates to.
#:
#: Every control is in section 5 (container runtime) except CL-0014's 2.14,
#: which is a daemon-level control: the rule reads one service's ``logging:``
#: key, so it relates to 2.14 and cannot satisfy it.
RULE_CIS: dict[str, tuple[CisControl, ...]] = {
    "CL-0001": (CIS_5_32,),
    "CL-0002": (CIS_5_5,),
    "CL-0003": (CIS_5_26,),
    "CL-0004": (CIS_5_28,),
    "CL-0005": (CIS_5_14,),
    "CL-0006": (CIS_5_4,),
    "CL-0007": (CIS_5_13,),
    "CL-0008": (CIS_5_10,),
    "CL-0009": (CIS_5_22, CIS_5_2, CIS_5_3),
    "CL-0010": (CIS_5_16, CIS_5_17),
    "CL-0011": (CIS_5_4,),
    "CL-0013": (CIS_5_6,),
    "CL-0014": (CIS_2_14,),
    "CL-0016": (CIS_5_18,),
    "CL-0017": (CIS_5_20,),
    "CL-0024": (CIS_5_4,),
    "CL-0025": (CIS_5_6,),
    "CL-0026": (CIS_5_11, CIS_5_12),
    "CL-0027": (CIS_5_4,),
    "CL-0028": (CIS_5_4,),
    "CL-0029": (CIS_5_4,),
    "CL-0030": (CIS_5_4,),
    "CL-0031": (CIS_5_32,),
}

#: Rules with no CIS control, each for a stated reason. An allow-list rather
#: than a silent gap, as for ATT&CK: a rule added without a mapping has to
#: land in one place or the other.
CIS_UNMAPPED_BY_DESIGN: dict[str, str] = {
    "CL-0018": (
        "the nearest control, 4.1, asks that the image defines a user; it is "
        "an image-build control and does not cover a Compose `user:` key"
    ),
    "CL-0019": (
        "no control asks for a digest; 5.28 is about stale cached images and "
        "is CL-0004's"
    ),
    "CL-0020": (
        "the secrets controls cover Dockerfiles (4.9) and swarm (7.4), not a "
        "Compose `environment:` value"
    ),
    "CL-0021": "same as CL-0020",
    "CL-0022": "no control covers tmpfs mount options",
}

#: rule id -> the OWASP Docker Security Cheat Sheet rules it relates to.
RULE_OWASP: dict[str, tuple[OwaspRule, ...]] = {
    "CL-0001": (OWASP_1,),
    "CL-0002": (OWASP_3,),
    "CL-0003": (OWASP_4,),
    "CL-0004": (OWASP_13,),
    "CL-0005": (OWASP_5A,),
    "CL-0006": (OWASP_3,),
    "CL-0007": (OWASP_8,),
    "CL-0009": (OWASP_6,),
    "CL-0011": (OWASP_3,),
    "CL-0013": (OWASP_8,),
    "CL-0018": (OWASP_2,),
    "CL-0019": (OWASP_13,),
    "CL-0020": (OWASP_12,),
    "CL-0021": (OWASP_12,),
    "CL-0022": (OWASP_8,),
    "CL-0024": (OWASP_3,),
    "CL-0025": (OWASP_8,),
    "CL-0026": (OWASP_7,),
    "CL-0027": (OWASP_3,),
    "CL-0028": (OWASP_3,),
    "CL-0029": (OWASP_3,),
    "CL-0030": (OWASP_3,),
    "CL-0031": (OWASP_1,),
}

#: Rules with no rule on the cheat sheet, each for a stated reason.
OWASP_UNMAPPED_BY_DESIGN: dict[str, str] = {
    "CL-0008": (
        "Rule 5 is about traffic between containers and does not mention "
        "host networking; no rule on the sheet does"
    ),
    "CL-0010": "no rule on the sheet covers host PID or IPC namespaces",
    "CL-0014": (
        "Rule 10 is about the daemon's log level; the rule cites the OWASP "
        "Logging Cheat Sheet, a different document"
    ),
    "CL-0016": "no rule on the sheet covers host devices",
    "CL-0017": "no rule on the sheet covers mount propagation",
}


def rule_tags(rule_id: str) -> list[str]:
    """The SARIF ``properties.tags`` for one rule: CIS, OWASP, then ATT&CK.

    No ``security`` tag. GitHub treats a result as a security result because
    its rule has ``security-severity``, which every rule here does; the tag
    would only add a filter value that matches the whole rule set, and cost
    one of ten slots on every rule to do it.

    The order is the order tags would be given up in if a rule ever outgrew
    ``MAX_TAGS_PER_RULE``, last first. A test keeps that from happening
    unnoticed; nothing is truncated here.
    """
    tags = [control.tag for control in RULE_CIS.get(rule_id, ())]
    tags.extend(rule.tag for rule in RULE_OWASP.get(rule_id, ()))
    tags.extend(
        f"{ATTACK_TAG_PREFIX}{technique.id}"
        for technique in RULE_TECHNIQUES.get(rule_id, ())
    )
    return tags
