"""Generative differential test: random overlay pairs against Compose itself.

`test_merge_semantics.py` covers a hand-written case list and a systematic
field x directive matrix. Both are finite, and both encode what their author
thought to enumerate — the `!override` bug shipped because it was probed while
deriving the merge table and never became a case.

This suite removes the author from the loop for coverage. It builds base and
overlay documents from a pool of field values, asks `docker compose config`
what the merged configuration is, and requires compose-lint's merge to yield
the same findings. Combinations neither the case list nor the matrix contains
are reached by construction.

Seeded and enumerated rather than randomly sampled per run: a fuzzer that
generates different inputs on every invocation reports failures nobody can
reproduce, and turns an unrelated commit red for reasons that vanish on
re-run. The seeds are fixed, so a failure names a case that can be replayed.
"""

from __future__ import annotations

import random
import shutil
import subprocess
from collections import Counter
from typing import TYPE_CHECKING

import pytest

from compose_lint.engine import run_rules
from compose_lint.parser import load_compose, load_merged

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None,
    reason="differential fuzz needs the docker compose CLI",
)

# Field -> values worth generating. Each pool mixes a dangerous value, a
# hardening value and a neutral one, so a generated pair can move a finding in
# either direction rather than only adding them.
FIELD_POOL: dict[str, list[str]] = {
    "volumes": [
        '["/var/run/docker.sock:/var/run/docker.sock"]',
        '["/tmp/safe:/var/run/docker.sock"]',
        '["/app:/app"]',
        '["/:/host"]',
        '["/etc:/etc:ro"]',
    ],
    "devices": ['["/dev/mem:/dev/probe"]', '["/dev/null:/dev/probe"]'],
    "ports": ['["8080:80"]', '["127.0.0.1:8080:80"]', '["9999:80"]', '["53:53/udp"]'],
    "cap_add": ["[SYS_ADMIN]", "[NET_ADMIN]", "[SYS_PTRACE]"],
    "cap_drop": ["[ALL]", "[NET_RAW]"],
    "security_opt": [
        '["no-new-privileges:true"]',
        '["seccomp:unconfined"]',
        '["apparmor:unconfined"]',
    ],
    "read_only": ["true", "false"],
    "privileged": ["true", "false"],
    "user": ['"1000:1000"', '"root"', '"0"'],
    "tmpfs": ['["/tmp"]', '["/run:exec"]'],
    "logging": ['{driver: "json-file"}', '{driver: "none"}'],
    "mem_limit": ['"512m"', '"1g"'],
    "restart": ['"on-failure"', '"always"'],
    "network_mode": ['"bridge"', '"host"'],
    "environment": [
        '{AWS_SECRET_ACCESS_KEY: "AKIAIOSFODNN7EXAMPLE"}',
        '{HARMLESS: "1"}',
    ],
}

# `network_mode` conflicts with `ports`, and Compose rejects the project rather
# than merging it. Generating the pair wastes a subprocess on a skip.
_EXCLUSIVE = [{"network_mode", "ports"}]

DIRECTIVES = ["", "", "", "", "!override ", "!reset "]

FIELDS = sorted(FIELD_POOL)
SEEDS = list(range(150))


def _render(fields: dict[str, str], *, with_image: bool) -> str:
    body = "services:\n  web:\n"
    if with_image:
        body += "    image: myapp:1.0\n"
    for key, value in fields.items():
        body += f"    {key}: {value}\n"
    return body


def _pick(rng: random.Random) -> tuple[dict[str, str], dict[str, str]]:
    """One base/overlay pair: overlapping field sets, independent values."""
    chosen = rng.sample(FIELDS, rng.randint(1, 5))
    base: dict[str, str] = {}
    over: dict[str, str] = {}
    for field in chosen:
        in_base = rng.random() < 0.75
        in_over = rng.random() < 0.75 or not in_base
        if in_base:
            base[field] = rng.choice(FIELD_POOL[field])
        if in_over:
            directive = rng.choice(DIRECTIVES)
            if directive.startswith("!reset"):
                # `!reset` deletes the key; a typed value is schema-invalid.
                over[field] = "!reset null"
            else:
                over[field] = f"{directive}{rng.choice(FIELD_POOL[field])}"
    for group in _EXCLUSIVE:
        if len(group & (set(base) | set(over))) > 1:
            for field in sorted(group)[1:]:
                base.pop(field, None)
                over.pop(field, None)
    return base, over


def _findings_of(data: dict, lines: dict[str, int]) -> Counter[tuple[str, str]]:
    """Findings as a (rule, service) multiset.

    Evidence is deliberately excluded here, unlike in `test_merge_semantics`,
    because this suite's oracle is a *normalised* document. Rules derive
    evidence from the spelling the user wrote, and `docker compose config`
    rewrites short port and volume syntax into long form — so `53:53/udp`
    becomes `53:53` on the truth side for the same finding about the same
    port. Comparing it would report a disagreement that only exists between
    two renderings of one configuration.

    Counting rather than set-ing keeps the discrimination that matters: a merge
    that drops one of two mounts, or duplicates one, changes the count even
    when the rule and service are unchanged.
    """
    return Counter(
        (f.rule_id, str(f.service)) for f in run_rules(data, lines) if not f.suppressed
    )


@pytest.mark.parametrize("seed", SEEDS)
def test_generated_pair_matches_docker_compose(seed: int, tmp_path: Path) -> None:
    """A generated base/overlay pair yields the findings Compose's merge would."""
    rng = random.Random(seed)  # noqa: S311 - fixture generation, not security
    base_fields, over_fields = _pick(rng)

    base_text = _render(base_fields, with_image=True)
    over_text = _render(over_fields, with_image=False)
    (tmp_path / "compose.yml").write_text(base_text)
    (tmp_path / "compose.override.yml").write_text(over_text)

    result = subprocess.run(
        ["docker", "compose", "config"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        # An invalid combination is not a merge disagreement. Compose refuses to
        # run it, so compose-lint's answer for it cannot mis-grade anything.
        pytest.skip(f"compose rejected seed {seed}: {result.stderr.strip()[:120]}")

    truth_file = tmp_path / "truth.yml"
    truth_file.write_text(result.stdout)
    truth_data, truth_lines = load_compose(truth_file)
    expected = _findings_of(truth_data, truth_lines)

    merged = load_merged([tmp_path / "compose.yml", tmp_path / "compose.override.yml"])
    actual = _findings_of(merged.data, merged.lines)

    assert actual == expected, (
        f"seed {seed}: merge disagrees with docker compose\n"
        f"--- compose.yml ---\n{base_text}"
        f"--- compose.override.yml ---\n{over_text}"
        f"  only ours:   {sorted((actual - expected).elements())}\n"
        f"  only theirs: {sorted((expected - actual).elements())}"
    )
