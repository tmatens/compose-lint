"""Classify the normalized form, not the spelling the author happened to use.

Five rules decided what a value *was* by matching the raw token: a literal set
of wildcard addresses, an exact ``o: bind`` string, ``^/dev/``-anchored patterns
over an unnormalized path, a boolean table missing YAML 1.1's single letters,
and an override tag constructed as if it were not there. Each let an equivalent
spelling through, and four of the five silenced a CRITICAL or HIGH rule.

Every expectation here was captured from ``docker compose config`` on Docker
Compose 29.7.2 and is named in the test that relies on it. The evasions are
covered as tables rather than one representative each, because a per-spelling
fix is exactly the shape of fix that leaves the next spelling working.
"""

from __future__ import annotations

import pytest

from compose_lint.engine import run_rules
from compose_lint.parser import loads
from compose_lint.rules._bool import as_bool
from compose_lint.rules._mounts import normalize_host_path
from compose_lint.rules.CL0005_unbound_ports import _is_wildcard_ip
from compose_lint.rules.CL0016_dangerous_devices import _extract_host_device


def _rule_ids(source: str) -> set[str]:
    data, lines = loads(source)
    return {f.rule_id for f in run_rules(data, lines) if not f.suppressed}


# --- VULN-015: YAML 1.1 booleans ------------------------------------------

# `docker compose config` emits `privileged: true` for every one of these.
TRUE_SPELLINGS = ["true", "yes", "on", "y", "Y", "TRUE", "True", '"y"', "'y'"]
# ...and drops the key (i.e. false) for every one of these.
FALSE_SPELLINGS = ["false", "no", "off", "n", "N", '"n"']


@pytest.mark.parametrize("spelling", TRUE_SPELLINGS)
def test_every_true_spelling_fires_cl0002(spelling: str) -> None:
    source = f"services:\n  web:\n    image: nginx:1.25\n    privileged: {spelling}\n"
    assert "CL-0002" in _rule_ids(source), spelling


@pytest.mark.parametrize("spelling", FALSE_SPELLINGS)
def test_no_false_spelling_fires_cl0002(spelling: str) -> None:
    source = f"services:\n  web:\n    image: nginx:1.25\n    privileged: {spelling}\n"
    assert "CL-0002" not in _rule_ids(source), spelling


def test_as_bool_covers_the_single_letter_forms() -> None:
    assert as_bool("y") is True
    assert as_bool("Y") is True
    assert as_bool("n") is False
    assert as_bool("N") is False
    assert as_bool("maybe") is None


# --- VULN-010: wildcard addresses -----------------------------------------

# Every spelling of the unspecified address, in both families.
WILDCARD_SPELLINGS = [
    "0.0.0.0",
    "::",
    "[::]",
    "[::0]",
    "[0:0:0:0:0:0:0:0]",
    "[::ffff:0.0.0.0]",
    "0000:0000:0000:0000:0000:0000:0000:0000",
]
BOUND_SPELLINGS = [
    "127.0.0.1",
    "[::1]",
    "192.168.1.10",
    "10.0.0.1",
    # An IPv4-mapped *bind* address. The wildcard check unwraps the mapping,
    # so this is the case that proves the unwrap is not blanket "any mapped
    # address is a wildcard".
    "[::ffff:127.0.0.1]",
    "[::ffff:192.168.1.10]",
]


@pytest.mark.parametrize("host_ip", WILDCARD_SPELLINGS)
def test_every_unspecified_address_is_a_wildcard(host_ip: str) -> None:
    assert _is_wildcard_ip(host_ip) is True, host_ip


@pytest.mark.parametrize("host_ip", BOUND_SPELLINGS)
def test_a_real_bind_address_is_not_a_wildcard(host_ip: str) -> None:
    assert _is_wildcard_ip(host_ip) is False, host_ip


def test_an_unparseable_host_is_not_treated_as_a_wildcard() -> None:
    """A hostname is not the unspecified address; guessing invents findings."""
    assert _is_wildcard_ip("localhost") is False
    assert _is_wildcard_ip("db.internal") is False


@pytest.mark.parametrize(
    "host_ip", ["[::ffff:0.0.0.0]", "[::ffff:0:0]", "::ffff:0.0.0.0"]
)
def test_the_ipv4_mapped_wildcard_does_not_depend_on_the_interpreter(
    host_ip: str,
) -> None:
    """``::ffff:0.0.0.0`` is the unspecified address in an IPv6 spelling.

    ``_is_wildcard_ip`` used to hand this to ``ipaddress.is_unspecified``,
    whose treatment of IPv4-mapped addresses depends on the CPython build:
    the macOS and Windows 3.10 legs reported False while 3.13 reported
    True, so the same compose file was graded differently by interpreter
    patch level and CL-0005 silently missed a port published on all
    interfaces. Assert the classification directly — it is ours now.
    """
    assert _is_wildcard_ip(host_ip) is True, host_ip


@pytest.mark.parametrize("host_ip", ["[::ffff:127.0.0.1]", "[::ffff:10.0.0.1]"])
def test_an_ipv4_mapped_bind_address_is_still_not_a_wildcard(host_ip: str) -> None:
    """The unwrap must not turn every mapped address into a finding."""
    assert _is_wildcard_ip(host_ip) is False, host_ip


@pytest.mark.parametrize(
    "host_ip", ["[::0]", "[0:0:0:0:0:0:0:0]", "[::ffff:0.0.0.0]", "[::ffff:0:0]"]
)
def test_ipv6_wildcard_spellings_fire_cl0005(host_ip: str) -> None:
    source = (
        "services:\n  web:\n    image: nginx:1.25\n"
        f'    ports:\n      - "{host_ip}:8080:80"\n'
    )
    assert "CL-0005" in _rule_ids(source), host_ip


# --- VULN-009: device path normalization ----------------------------------

# Compose passes each of these through verbatim; the kernel resolves them to
# the same device node.
DEVICE_SPELLINGS = ["/dev/sda", "//dev/sda", "/dev/./sda", "/dev/../dev/sda"]


@pytest.mark.parametrize("spelling", DEVICE_SPELLINGS)
def test_every_device_spelling_normalizes_to_the_same_node(spelling: str) -> None:
    assert _extract_host_device(f"{spelling}:/dev/sda") == "/dev/sda", spelling


@pytest.mark.parametrize("spelling", DEVICE_SPELLINGS)
def test_every_device_spelling_fires_cl0016(spelling: str) -> None:
    source = (
        "services:\n  web:\n    image: nginx:1.25\n"
        f'    devices:\n      - "{spelling}:/dev/sda"\n'
    )
    assert "CL-0016" in _rule_ids(source), spelling


def test_a_harmless_device_still_does_not_fire() -> None:
    source = (
        "services:\n  web:\n    image: nginx:1.25\n"
        '    devices:\n      - "/dev/null:/dev/null"\n'
    )
    assert "CL-0016" not in _rule_ids(source)


# --- VULN-007: the bind family --------------------------------------------

# `o:` values the kernel treats as a bind of `device`. compose-lint used to
# require the token to be exactly `bind`.
BIND_OPTS = ["bind", "rbind", "rw,rbind", "rbind,rw", "ro,rbind"]


@pytest.mark.parametrize("opt", BIND_OPTS)
def test_every_bind_flavour_exposes_the_host_path(opt: str) -> None:
    source = (
        "services:\n  web:\n    image: nginx:1.25\n"
        "    volumes:\n      - sock:/mnt\n"
        "volumes:\n  sock:\n    driver: local\n    driver_opts:\n"
        "      type: none\n      device: /var/run/docker.sock\n"
        f"      o: {opt}\n"
    )
    assert "CL-0001" in _rule_ids(source), opt


def test_bind_is_detected_without_an_o_flag_at_all() -> None:
    """``type: none`` plus an absolute device is already a bind."""
    source = (
        "services:\n  web:\n    image: nginx:1.25\n"
        "    volumes:\n      - sock:/mnt\n"
        "volumes:\n  sock:\n    driver: local\n    driver_opts:\n"
        "      type: none\n      device: /var/run/docker.sock\n"
    )
    assert "CL-0001" in _rule_ids(source)


def test_a_non_bind_driver_opt_is_not_claimed_as_a_host_path() -> None:
    """NFS and tmpfs name something other than a host path — no invented finding."""
    for fs_type, device, opts in (
        ("nfs", ":/export", "addr=10.0.0.1,rw"),
        ("tmpfs", "tmpfs", "size=100m"),
    ):
        source = (
            "services:\n  web:\n    image: nginx:1.25\n"
            "    volumes:\n      - vol:/mnt\n"
            "volumes:\n  vol:\n    driver: local\n    driver_opts:\n"
            f"      type: {fs_type}\n      device: {device}\n      o: {opts}\n"
        )
        assert "CL-0001" not in _rule_ids(source), fs_type


def test_read_only_flag_is_still_read_from_the_opt_list() -> None:
    assert normalize_host_path("//var/run/") == "/var/run"


# --- VULN-001: `!reset` is a deletion -------------------------------------


def test_reset_hardening_makes_the_absence_rules_fire() -> None:
    """The linted view must be the deployed view.

    `docker compose config` on this document deploys a service with no
    ``read_only``, no ``cap_drop`` and no ``security_opt`` — so the rules that
    check for their absence have to see the absence.
    """
    source = (
        "services:\n"
        "  web:\n"
        "    image: nginx@sha256:" + "ab" * 32 + "\n"
        "    read_only: !reset true\n"
        "    cap_drop: !reset [ALL]\n"
        '    security_opt: !reset ["no-new-privileges:true"]\n'
        '    user: "1000:1000"\n'
    )
    ids = _rule_ids(source)
    assert {"CL-0003", "CL-0006", "CL-0007"} <= ids, ids


def test_override_keeps_its_value() -> None:
    """``!override`` changes how a value merges, not what it is."""
    source = (
        "services:\n  web:\n    image: nginx:1.25\n    privileged: !override true\n"
    )
    assert "CL-0002" in _rule_ids(source)


def test_reset_does_not_break_line_tracking_for_surviving_keys() -> None:
    _data, lines = loads(
        "services:\n"
        "  web:\n"
        "    image: nginx:1.25\n"
        "    read_only: !reset true\n"
        "    privileged: true\n"
    )
    assert lines["services.web.privileged"] == 5
