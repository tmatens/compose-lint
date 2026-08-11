"""MITRE ATT&CK mapping for the rule set, pinned to ATT&CK v18.

Every rule describes a *misconfiguration*. The mapping says which adversary
techniques remediating it would mitigate — **mitigation coverage, never
detection**. compose-lint reads a file; it observes no adversary behaviour and
emits no telemetry, so presenting these as detections would misrepresent the
tool to exactly the audience the mapping is for.

**The version pin is load-bearing.** ATT&CK v18 restructured the Containers
matrix: Defense Evasion was renamed **Stealth**, a **Defense Impairment** tactic
was added, and ``T1562.001`` was promoted to top-level ``T1685``. An unpinned
mapping rots into wrong tactic names without appearing to change. See
``docs/adr/022-threat-model-grounding.md``.

Four intuitive mappings are wrong and are corrected here, because a security
audience will check them:

* CL-0002 / CL-0009 map to **T1685**, not ``T1562.001`` (promoted in v18).
* CL-0014 maps to **T1070**, not ``T1562.008`` — Containers is not a platform
  for ``.008``.
* CL-0004 / CL-0019 map to **T1204.003** and **T1525**, not ``T1195`` —
  Containers is not a platform for the supply-chain technique.
* T1040, T1557, T1057 and T1548 are **Enterprise/Linux** techniques, not
  Containers-matrix ones. Rules relying on them say so via ``enterprise=True``
  rather than passing them off as Containers coverage.
"""

from __future__ import annotations

from typing import NamedTuple

#: ATT&CK release this mapping was authored against. Bumping it is a deliberate
#: review, not a version bump: tactic names and technique IDs both move.
ATTACK_VERSION = "18"

ATTACK_URL = "https://attack.mitre.org"

#: Stable identity for the taxonomy component in SARIF output. Generated once;
#: consumers key on it, so it must not change.
ATTACK_TAXONOMY_GUID = "6c2d9b1e-3f2a-4d17-9a53-7e1c0b8f4a20"


class Technique(NamedTuple):
    """One ATT&CK technique, as this project cites it."""

    id: str
    name: str
    tactic: str
    #: True when the technique is Enterprise/Linux rather than Containers —
    #: the Containers matrix has real blind spots and pretending otherwise is
    #: the kind of inaccuracy a SOC reader notices immediately.
    enterprise: bool = False

    @property
    def url(self) -> str:
        base, _, sub = self.id.partition(".")
        suffix = f"/{sub}" if sub else ""
        return f"{ATTACK_URL}/techniques/{base}{suffix}/"

    @property
    def label(self) -> str:
        scope = " (Enterprise)" if self.enterprise else ""
        return f"{self.id} {self.name}{scope}"


T1003 = Technique("T1003", "OS Credential Dumping", "Credential Access")
T1040 = Technique("T1040", "Network Sniffing", "Credential Access", enterprise=True)
T1046 = Technique("T1046", "Network Service Discovery", "Discovery")
T1055 = Technique("T1055", "Process Injection", "Privilege Escalation")
T1070 = Technique("T1070", "Indicator Removal", "Stealth")
T1078 = Technique("T1078", "Valid Accounts", "Privilege Escalation")
T1190 = Technique("T1190", "Exploit Public-Facing Application", "Initial Access")
T1204_003 = Technique("T1204.003", "User Execution: Malicious Image", "Execution")
T1496 = Technique("T1496", "Resource Hijacking", "Impact")
T1499 = Technique("T1499", "Endpoint Denial of Service", "Impact")
T1525 = Technique("T1525", "Implant Internal Image", "Persistence")
T1529 = Technique("T1529", "System Shutdown/Reboot", "Impact")
T1548_001 = Technique(
    "T1548.001",
    "Abuse Elevation Control Mechanism: Setuid and Setgid",
    "Privilege Escalation",
    enterprise=True,
)
T1552_001 = Technique(
    "T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access"
)
T1552_007 = Technique(
    "T1552.007", "Unsecured Credentials: Container API", "Credential Access"
)
T1557 = Technique(
    "T1557", "Adversary-in-the-Middle", "Credential Access", enterprise=True
)
T1609 = Technique("T1609", "Container Administration Command", "Execution")
T1610 = Technique("T1610", "Deploy Container", "Execution")
T1611 = Technique("T1611", "Escape to Host", "Privilege Escalation")
T1612 = Technique("T1612", "Build Image on Host", "Stealth")
T1613 = Technique("T1613", "Container and Resource Discovery", "Discovery")
T1685 = Technique("T1685", "Disable or Modify Tools", "Defense Impairment")

#: rule id -> the techniques its remediation mitigates.
#:
#: CL-0005 is deliberately absent: it has no adversary-technique home. It is
#: attack surface that *enables* T1190, and Microsoft's Kubernetes matrix lists
#: only the defender-side "Exposed sensitive interfaces". That absence is part
#: of the basis for shipping it under a detection-precision override, so
#: inventing a technique for it would erase the evidence.
#:
#: CL-0007 and CL-0022 are absent for a different reason: they are
#: defence-in-depth that denies an attacker somewhere to stage tools, which is
#: indirect enough that naming a technique would overstate the link.
RULE_TECHNIQUES: dict[str, tuple[Technique, ...]] = {
    "CL-0001": (T1610, T1609, T1611, T1612, T1552_007, T1613),
    "CL-0002": (T1611, T1685),
    "CL-0003": (T1548_001,),
    "CL-0004": (T1204_003,),
    "CL-0006": (T1040, T1557, T1548_001),
    "CL-0008": (T1046,),
    "CL-0009": (T1685,),
    "CL-0010": (T1611,),
    "CL-0011": (T1611, T1557, T1040, T1529),
    "CL-0013": (T1552_001,),
    "CL-0014": (T1070,),
    "CL-0016": (T1611, T1552_001),
    "CL-0017": (T1611,),
    "CL-0018": (T1611, T1078),
    "CL-0019": (T1204_003, T1525),
    "CL-0020": (T1552_001,),
    "CL-0021": (T1552_001,),
    "CL-0024": (T1611,),
    "CL-0025": (T1611,),
    "CL-0026": (T1496, T1499),
    "CL-0027": (T1055, T1003, T1552_001, T1611),
    # SYS_TIME moves the host clock: T1070 for the detection/correlation
    # consequence, T1499 because cert validation and Kerberos fail machine-wide.
    # PERFMON samples every process on the host, hence T1003.
    "CL-0028": (T1070, T1499, T1003),
}

#: Techniques a rule *enables* rather than mitigates, kept out of the mapping
#: proper so the coverage claim stays honest. Documented, not exported to SARIF.
ENABLED_ONLY: dict[str, tuple[Technique, ...]] = {
    "CL-0005": (T1190,),
}


def all_techniques() -> list[Technique]:
    """Every mapped technique, ordered by id — the taxonomy's ``taxa``."""
    seen: dict[str, Technique] = {}
    for techniques in RULE_TECHNIQUES.values():
        for technique in techniques:
            seen.setdefault(technique.id, technique)
    return [seen[key] for key in sorted(seen)]
