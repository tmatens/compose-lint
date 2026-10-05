"""CL-0016: every equivalent spelling of a device, generated from one table.

Threat-model row #3 (``docs/ASSURANCE.md``) puts "alternate-form constructs" in
scope, and CL-0016 has more of them than any other rule: a device can be named
by path, by a path with ``.``/``..``/``//`` noise, by its ``/dev/block`` or
``/dev/char`` ``<major>:<minor>`` link, or not named at all and opened through a
``device_cgroup_rules:`` entry. Each gap found in that space used to cost its
own issue, measurement and PR (#913, #994/#996, #999/#1001). Here each device
is one row in ``DEVICES``, and the generators below derive every spelling from
it, so a new row is covered by every generator and a new generator covers every
row (#1002).

This file checks that the linter treats equivalent inputs equivalently. Whether
two spellings *are* equivalent to Docker is the premise checks' job, and a
generator is added only once a premise check or a recorded measurement shows the
spelling reaches the same node. One spelling was measured and left out: a
trailing slash on a device node (``/dev/zero/``) is refused by Docker 29.1.3 in
both syntaxes ("error gathering device information while adding custom device
... not a directory"), so it names no running service. A trailing slash on a
*directory* is a real spelling and is generated for the directory rows.

The table is also the single source the rule is checked against: the pattern
list, the ``c`` cgroup table and the rule page's rows must each agree with it,
so none of them can drift without a test naming the row.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

import pytest

from compose_lint.parser import loads
from compose_lint.rules.CL0016_dangerous_devices import (
    _DANGEROUS_DEVICE_PATTERNS,
    _FLAGGED_CHAR_DEVICES,
    DangerousDevicesRule,
)

if TYPE_CHECKING:
    from _pytest.mark import ParameterSet

RULE_PAGE = Path(__file__).parent.parent / "docs" / "rules" / "CL-0016.md"

# Major and minor numbers are from the kernel's
# Documentation/admin-guide/devices.txt. A row whose numbers are allocated at
# runtime carries ``dynamic_because`` instead, because the rule can only name a
# number that is the same on every host.


@dataclass(frozen=True)
class Device:
    path: str
    kind: Literal["b", "c", "link", "dir"]
    numbers: tuple[int, int] | None = None
    dynamic_because: str | None = None
    # Exactly one of these two. ``flagged_by`` is the pattern in
    # ``_DANGEROUS_DEVICE_PATTERNS`` that claims the canonical path.
    flagged_by: str | None = None
    unclaimed_because: str | None = None
    # The table and the rule disagree, and changing the rule is a decision not
    # yet taken. The disagreeing cases are strict xfails, so the row cannot be
    # forgotten: the day the rule changes, they pass and fail the run.
    rule_disagrees: str | None = None

    @property
    def flagged(self) -> bool:
        return self.flagged_by is not None


DEVICES: tuple[Device, ...] = (
    # --- Raw block devices on static majors --------------------------------
    Device("/dev/sda", "b", (8, 0), flagged_by=r"^/dev/sd[a-z]"),
    Device("/dev/sdb1", "b", (8, 17), flagged_by=r"^/dev/sd[a-z]"),
    Device("/dev/hda", "b", (3, 0), flagged_by=r"^/dev/hd[a-z]\d*$"),
    Device("/dev/hdb1", "b", (3, 65), flagged_by=r"^/dev/hd[a-z]\d*$"),
    Device("/dev/loop0", "b", (7, 0), flagged_by=r"^/dev/loop"),
    Device("/dev/md0", "b", (9, 0), flagged_by=r"^/dev/md\d"),
    Device("/dev/nbd0", "b", (43, 0), flagged_by=r"^/dev/nbd\d"),
    Device("/dev/mtdblock0", "b", (31, 0), flagged_by=r"^/dev/mtdblock"),
    Device("/dev/mmcblk0", "b", (179, 0), flagged_by=r"^/dev/mmcblk"),
    Device("/dev/xvda", "b", (202, 0), flagged_by=r"^/dev/xvd[a-z]"),
    # --- Raw block devices on dynamic numbers --------------------------------
    Device(
        "/dev/nvme0n1",
        "b",
        dynamic_because="namespaces take minors on the extended major 259 in "
        "probe order, so no minor names the same disk on every host",
        flagged_by=r"^/dev/nvme",
    ),
    Device(
        "/dev/vda",
        "b",
        dynamic_because="virtio_blk registers with major 0 (allocated at load)",
        flagged_by=r"^/dev/vd[a-z]",
    ),
    Device(
        "/dev/dm-0",
        "b",
        dynamic_because="device-mapper registers with major 0",
        flagged_by=r"^/dev/dm-",
    ),
    Device(
        "/dev/rbd0",
        "b",
        dynamic_because="rbd allocates a major per image (or one shared, "
        "allocated, major with single_major)",
        flagged_by=r"^/dev/rbd",
    ),
    Device(
        "/dev/zd0",
        "b",
        dynamic_because="ZFS registers the zvol major with major 0",
        flagged_by=r"^/dev/zd\d",
    ),
    # --- Character devices ---------------------------------------------------
    Device("/dev/kmsg", "c", (1, 11), flagged_by=r"^/dev/kmsg$"),
    Device("/dev/loop-control", "c", (10, 237), flagged_by=r"^/dev/loop"),
    Device(
        "/dev/zfs",
        "c",
        dynamic_because="registered as a misc device with MISC_DYNAMIC_MINOR",
        flagged_by=r"^/dev/zfs$",
    ),
    Device(
        "/dev/nvme0",
        "c",
        dynamic_because="the NVMe controller node's major comes from "
        "alloc_chrdev_region",
        flagged_by=r"^/dev/nvme",
    ),
    # --- udev symlinks, resolved by Docker to a node above -------------------
    Device(
        "/dev/disk/by-id/nvme-x",
        "link",
        dynamic_because="a symlink; its numbers are the target's",
        flagged_by=r"^/dev/disk/",
    ),
    Device(
        "/dev/mapper/vg-root",
        "link",
        dynamic_because="a symlink; its numbers are the target's",
        flagged_by=r"^/dev/mapper/",
    ),
    Device(
        "/dev/md/data",
        "link",
        dynamic_because="a symlink; its numbers are the target's",
        flagged_by=r"^/dev/md/",
    ),
    Device(
        "/dev/zvol/tank/vm-100-disk-0",
        "link",
        dynamic_because="a symlink; its numbers are the target's",
        flagged_by=r"^/dev/zvol/",
    ),
    # --- Directories (#913): Docker maps every real node beneath one ---------
    Device("/dev", "dir", flagged_by=r"^/dev$"),
    Device(
        "/dev/disk",
        "dir",
        unclaimed_because="holds only symlinks, which the walk skips (#913)",
    ),
    Device(
        "/dev/mapper",
        "dir",
        unclaimed_because="the walk maps only control, whose ioctls need "
        "CAP_SYS_ADMIN (#913)",
    ),
    Device("/dev/md", "dir", unclaimed_because="holds only symlinks (#913)"),
    Device(
        "/dev/block",
        "dir",
        unclaimed_because="holds only symlinks; Docker refuses it (#913)",
    ),
    # --- Devices the rule deliberately does not claim ------------------------
    Device("/dev/mem", "c", (1, 1), unclaimed_because="needs CAP_SYS_RAWIO (CL-0024)"),
    Device("/dev/port", "c", (1, 4), unclaimed_because="needs CAP_SYS_RAWIO (CL-0024)"),
    Device(
        "/dev/kmem",
        "c",
        (1, 2),
        unclaimed_because="Docker refuses to create the container",
    ),
    Device(
        "/dev/raw/rawctl",
        "c",
        (162, 0),
        unclaimed_because="Docker refuses to create the container",
    ),
    Device(
        "/dev/fuse",
        "c",
        (10, 229),
        unclaimed_because="mount(2) needs CAP_SYS_ADMIN (CL-0024)",
    ),
    Device(
        "/dev/net/tun",
        "c",
        (10, 200),
        unclaimed_because="safe: an interface in the container's own netns",
    ),
    Device(
        "/dev/mapper/control",
        "c",
        (10, 236),
        unclaimed_because="its ioctls need CAP_SYS_ADMIN (CL-0024)",
        rule_disagrees="named directly, ^/dev/mapper/ claims it, while the page "
        "leaves the same node unclaimed when the /dev/mapper walk maps it",
    ),
)

# Spellings next to a flagged one that name something else. They keep a pattern
# from being loosened past its device without a test noticing.
NEAR_MISS_PATHS = (
    "/dev/zero",
    "/dev/null",
    "/dev/hdmi0",
    "/dev/hidraw0",
    "/dev/mtd0",
    "/dev/mdadm",
    "/dev/char/1:110",
    "/dev/char/10:2370",
    "/dev/net",
    "/dev/snd",
    "/dev/dri",
    "/dev/bus/usb",
)
NEAR_MISS_CGROUP_RULES = ("c 1:110 r", "c 10:2370 rw", "c 11:1 rw")


# --- Generators ---------------------------------------------------------------
#
# Each turns a row into ``Spelling``s: a ``devices:`` body or one cgroup rule,
# any extra service keys, and the evidence the finding must carry. Evidence is
# None for a spelling that must not be flagged.


@dataclass(frozen=True)
class Spelling:
    case: str
    devices: str | None = None
    cgroup_rule: str | None = None
    extra: str = ""
    evidence: str | None = None


def _short(path: str) -> str:
    return f'      - "{path}:/dev/x"\n'


def _long(path: str) -> str:
    return (
        f'      - source: "{path}"\n        target: /dev/x\n        permissions: rwm\n'
    )


def _path_noise(path: str, kind: str) -> list[str]:
    """Spellings Compose passes through verbatim and the kernel resolves alike."""
    rest = path.removeprefix("/dev")
    variants = [f"/{path}", f"/dev/.{rest}", f"/dev/../dev{rest}"]
    if kind == "dir":
        variants.append(f"{path}/")
    return variants


def _path_spellings(device: Device) -> list[Spelling]:
    evidence = device.path if device.flagged else None
    spellings = [
        Spelling("short", _short(device.path), evidence=evidence),
        Spelling("long", _long(device.path), evidence=evidence),
    ]
    for variant in _path_noise(device.path, device.kind):
        spellings.append(
            Spelling(f"short {variant}", _short(variant), evidence=evidence)
        )
        spellings.append(Spelling(f"long {variant}", _long(variant), evidence=evidence))
    return spellings


def _number_link_spellings(device: Device) -> list[Spelling]:
    """``/dev/block/M:m`` and ``/dev/char/M:m``: long syntax only.

    Short syntax cannot carry the colon, which is its field delimiter. The rule
    keeps the link as evidence rather than resolving it to a name.
    """
    if device.numbers is None or device.kind not in ("b", "c"):
        return []
    major, minor = device.numbers
    farm = "block" if device.kind == "b" else "char"
    link = f"/dev/{farm}/{major}:{minor}"
    return [
        Spelling(f"long {link}", _long(link), evidence=link if device.flagged else None)
    ]


_NO_MKNOD = "    cap_drop: [MKNOD]\n"
_DEV_BIND_WITHOUT_CAPS = "    cap_drop: [ALL]\n    volumes:\n      - /dev:/dev\n"


def _cgroup_spellings(device: Device) -> list[Spelling]:
    """``device_cgroup_rules:`` entries that cover the device's number.

    A flagged device is reachable through every rule that covers it with ``r``
    or ``w``, provided the container can obtain the node: Docker's default
    ``MKNOD`` or a ``/dev`` bind mount (#882, measured). ``m`` alone, or no way
    to the node, reaches nothing. A dynamic number is covered only by the
    wildcards, which are therefore all a dynamic row generates.
    """
    if device.kind not in ("b", "c"):
        return []
    kind = device.kind
    if not device.flagged:
        if device.numbers is None:
            return []
        major, minor = device.numbers
        # Exact numbers only: a wildcard over a dropped device's major also
        # covers a flagged neighbour (c 1:* covers /dev/kmsg).
        return [
            Spelling(f"cgroup {kind} {major}:{minor} {acc}", cgroup_rule=rule)
            for acc in ("r", "w", "rwm")
            for rule in [f"{kind} {major}:{minor} {acc}"]
        ]

    covering = [f"{kind} *:* r", "a *:* r"]
    if device.numbers is not None:
        major, minor = device.numbers
        covering = [
            f"{kind} {major}:{minor} r",
            f"{kind} {major}:{minor} w",
            f"{kind} {major}:{minor} rwm",
            f"{kind} {major}:* r",
            *covering,
        ]
    spellings = []
    for rule in covering:
        evidence = " ".join(rule.split()[:2])
        spellings.append(
            Spelling(f"cgroup {rule}", cgroup_rule=rule, evidence=evidence)
        )
        spellings.append(
            Spelling(f"cgroup {rule} without MKNOD", cgroup_rule=rule, extra=_NO_MKNOD)
        )
        spellings.append(
            Spelling(
                f"cgroup {rule} via a /dev bind",
                cgroup_rule=rule,
                extra=_DEV_BIND_WITHOUT_CAPS,
                evidence=evidence,
            )
        )
        mknod_only = rule[: -len(rule.split()[2])] + "m"
        spellings.append(Spelling(f"cgroup {mknod_only}", cgroup_rule=mknod_only))
    return spellings


GENERATORS = (_path_spellings, _number_link_spellings, _cgroup_spellings)


def _cases() -> list[ParameterSet]:
    cases = []
    for device in DEVICES:
        for generate in GENERATORS:
            for spelling in generate(device):
                marks = []
                if device.rule_disagrees and generate is _path_spellings:
                    marks.append(
                        pytest.mark.xfail(strict=True, reason=device.rule_disagrees)
                    )
                cases.append(
                    pytest.param(
                        device,
                        spelling,
                        id=f"{device.path} | {spelling.case}",
                        marks=marks,
                    )
                )
    return cases


def _findings(spelling: Spelling) -> list:
    body = "services:\n  app:\n    image: busybox:1.37\n"
    if spelling.devices is not None:
        body += "    devices:\n" + spelling.devices
    if spelling.cgroup_rule is not None:
        body += f'    device_cgroup_rules: ["{spelling.cgroup_rule}"]\n'
    body += spelling.extra
    data, lines = loads(body)
    rule = DangerousDevicesRule()
    return list(rule.check("app", data["services"]["app"], data, lines))


# --- The equivalence assertions -------------------------------------------------


@pytest.mark.parametrize(("device", "spelling"), _cases())
def test_every_spelling_is_graded_like_its_device(
    device: Device, spelling: Spelling
) -> None:
    findings = _findings(spelling)
    if spelling.evidence is None:
        assert findings == []
    else:
        assert [f.evidence for f in findings] == [spelling.evidence]
        assert findings[0].rule_id == "CL-0016"


@pytest.mark.parametrize("path", NEAR_MISS_PATHS)
def test_near_miss_paths_are_not_flagged(path: str) -> None:
    for body in (_short(path), _long(path)):
        assert _findings(Spelling(path, devices=body)) == []


@pytest.mark.parametrize("rule", NEAR_MISS_CGROUP_RULES)
def test_near_miss_cgroup_rules_are_not_flagged(rule: str) -> None:
    assert _findings(Spelling(rule, cgroup_rule=rule)) == []


def test_any_block_link_is_flagged_whatever_its_number() -> None:
    """The dynamic rows get no ``/dev/block`` spelling of their own.

    The pattern claims the whole farm, so a number from any host reaches it.
    """
    for link in ("/dev/block/259:0", "/dev/block/253:3", "/dev/block/230:16"):
        [finding] = _findings(Spelling(link, devices=_long(link)))
        assert finding.evidence == link


# --- The table is the single source ----------------------------------------------


def test_every_row_is_well_formed() -> None:
    for device in DEVICES:
        assert device.flagged != (device.unclaimed_because is not None), device.path
        if device.kind in ("b", "c"):
            assert (device.numbers is None) != (device.dynamic_because is None), (
                device.path
            )
        if device.kind == "link":
            assert device.numbers is None and device.dynamic_because, device.path


def test_each_row_is_claimed_by_the_pattern_it_names() -> None:
    patterns = [pattern for pattern, _ in _DANGEROUS_DEVICE_PATTERNS]
    for device in DEVICES:
        first = next((p.pattern for p in patterns if p.match(device.path)), None)
        if device.rule_disagrees:
            assert first is not None, f"{device.path}: resolved, drop rule_disagrees"
            continue
        assert first == device.flagged_by, device.path


def test_every_pattern_is_exercised_by_a_row() -> None:
    """No pattern outlives the device it was written for.

    A pattern is exercised when some generated path spelling of a flagged row
    is what it matches. The ``/dev/block`` and ``/dev/char`` patterns are
    reached through the number-link generator, so they count too.
    """
    exercised = set()
    for device in DEVICES:
        if not device.flagged:
            continue
        for spelling in _path_spellings(device) + _number_link_spellings(device):
            for pattern, _ in _DANGEROUS_DEVICE_PATTERNS:
                if spelling.evidence and pattern.match(spelling.evidence):
                    exercised.add(pattern.pattern)
                    break
    assert exercised == {p.pattern for p, _ in _DANGEROUS_DEVICE_PATTERNS}


def test_the_char_cgroup_table_is_the_static_flagged_char_rows() -> None:
    assert {
        (str(d.numbers[0]), str(d.numbers[1])): d.path
        for d in DEVICES
        if d.flagged and d.kind == "c" and d.numbers is not None
    } == _FLAGGED_CHAR_DEVICES


def _page_table(heading: str) -> list[list[str]]:
    """Backticked tokens from the first column of the table under ``heading``."""
    text = RULE_PAGE.read_text(encoding="utf-8")
    start = text.index(heading)
    rows: list[list[str]] = []
    in_table = False
    for line in text[start:].splitlines()[1:]:
        if line.startswith("|"):
            in_table = True
            first = line.split("|")[1]
            tokens = re.findall(r"`([^`]+)`", first)
            if tokens:
                rows.append(tokens)
        elif in_table:
            break
    return rows


def _page_covers(token: str, path: str) -> bool:
    return fnmatch.fnmatchcase(path, token) or path == token


def test_the_page_lists_every_flagged_row_and_nothing_else() -> None:
    tokens = sorted({t for row in _page_table("| Pattern | Risk |") for t in row})
    assert len(tokens) > 20
    spelled = [
        s.evidence
        for d in DEVICES
        if d.flagged
        for s in [*_path_spellings(d)[:1], *_number_link_spellings(d)]
        if s.evidence
    ]
    for path in spelled:
        assert any(_page_covers(t, path) for t in tokens), path
    for token in tokens:
        assert any(_page_covers(token, path) for path in spelled), token


def test_the_page_explains_every_unclaimed_device() -> None:
    tokens = [
        t
        for row in _page_table("### Devices this rule deliberately does not claim")
        for t in row
    ]
    assert tokens
    text = RULE_PAGE.read_text(encoding="utf-8")
    for device in DEVICES:
        if device.flagged:
            continue
        explained = any(
            device.path == t or device.path.startswith(t + "/") for t in tokens
        )
        # A safe device is not a deliberate drop; the page need only name it.
        assert explained or f"`{device.path}`" in text, device.path


def test_the_page_lists_the_flagged_char_cgroup_numbers() -> None:
    text = RULE_PAGE.read_text(encoding="utf-8")
    for device in DEVICES:
        if device.flagged and device.kind == "c" and device.numbers is not None:
            major, minor = device.numbers
            assert f"`c {major}:{minor}" in text, device.path
