"""CL-0020 on `command:`, `entrypoint:` and `healthcheck.test` (issue #1077).

The same key-shaped test the rule applies to an env key, applied to the
tokens of an argument list. The positive fixture is
`compose_files/insecure_credential_argv.yml`; the hardened-but-unusual
negatives are inline, because each one is a single value shape.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from compose_lint.models import Finding, Severity
from compose_lint.parser import load_compose, loads
from compose_lint.rules.CL0020_credential_env_keys import (
    CredentialEnvKeysRule,
    _argv_tokens,
)

FIXTURES = Path(__file__).parent / "compose_files"
FIXTURE = FIXTURES / "insecure_credential_argv.yml"


def _fixture(service: str) -> list[Finding]:
    data, lines = load_compose(FIXTURE)
    return list(
        CredentialEnvKeysRule().check(service, data["services"][service], data, lines)
    )


def _service(body: str) -> list[Finding]:
    data, lines = loads("services:\n  a:\n    image: app:1.0\n" + body)
    return list(CredentialEnvKeysRule().check("a", data["services"]["a"], data, lines))


# ---- Positive: every shape the corpus count was built from -------------------


@pytest.mark.parametrize(
    ("service", "evidence"),
    [
        ("requirepass_list", "command:--requirepass"),
        ("requirepass_string", "command:--requirepass"),
        ("masterauth_inline", "command:--masterauth"),
        ("password_flag_entrypoint", "entrypoint:--admin-password"),
        ("assignment_in_shell_list", "command:PGPASSWORD"),
        ("assignment_in_shell_string", "entrypoint:PGPASSWORD"),
        ("mysql_glued_healthcheck", "healthcheck.test:-p"),
        ("mysql_glued_cmd_shell", "healthcheck.test:-p"),
        ("healthcheck_string_form", "healthcheck.test:--password"),
        ("defaulted_reference", "command:--requirepass"),
        ("numeric_value", "command:--requirepass"),
        ("single_dash_long_flag", "command:-rpcpassword"),
    ],
)
def test_detects_literal_argument(service: str, evidence: str) -> None:
    findings = _fixture(service)
    assert [f.evidence for f in findings] == [evidence]
    (finding,) = findings
    assert finding.rule_id == "CL-0020"
    assert finding.severity == Severity.HIGH
    assert finding.line is not None and finding.line > 0
    location, name = evidence.split(":", 1)
    assert f"'{name}'" in finding.message
    assert f"`{location}`" in finding.message


def test_value_is_never_printed() -> None:
    for service in (
        "requirepass_list",
        "assignment_in_shell_list",
        "mysql_glued_healthcheck",
    ):
        for finding in _fixture(service):
            assert "hunter2" not in finding.message
            assert "hunter2" not in (finding.fix or "")
            assert "hunter2" not in (finding.evidence or "")


def test_repeated_flag_is_one_finding() -> None:
    # Two `--password` literals on one line are one thing to move.
    assert [f.evidence for f in _fixture("repeated_flag_once")] == [
        "command:--password"
    ]


def test_env_and_argv_are_separate_findings() -> None:
    # Different objects: the env key and the flag each need moving.
    evidence = sorted(f.evidence or "" for f in _fixture("both_surfaces"))
    assert evidence == ["REDIS_PASSWORD", "command:--requirepass"]


def test_fix_names_the_secrets_primitive_and_the_escaped_dollar() -> None:
    (finding,) = _fixture("requirepass_list")
    assert finding.fix is not None
    assert "secrets:" in finding.fix
    assert "$$(cat /run/secrets/" in finding.fix


# ---- Negative: the two shapes that are literal in env but not here -----------


def test_shell_reference_is_not_a_literal() -> None:
    # Compose hands `$$VAR` over as `$VAR`; the container's shell expands it.
    assert (
        _service('    command: redis-server --requirepass "$$REDIS_PASSWORD"\n') == []
    )
    assert _service("    command: redis-server --requirepass $$REDIS_PASSWORD\n") == []
    assert (
        _service(
            "    healthcheck:\n"
            '      test: ["CMD-SHELL", "mysqladmin ping -p$$MYSQL_ROOT_PASSWORD"]\n'
        )
        == []
    )
    assert _service('    command: ["sh", "-c", "PGPASSWORD=$$PW psql"]\n') == []


def test_command_substitution_is_a_shell_reference() -> None:
    # The fix the rule recommends must not trip the rule.
    assert (
        _service(
            "    command:\n"
            "      - sh\n"
            "      - -c\n"
            '      - redis-server --requirepass "$$(cat /run/secrets/redis_pw)"\n'
        )
        == []
    )


@pytest.mark.parametrize(
    "value",
    ["/run/secrets/redis_pw", "./secrets/pw", "../pw", "~/.pw"],
)
def test_path_value_is_the_fix_pattern(value: str) -> None:
    assert _service(f"    command: app --password {value}\n") == []
    assert _service(f"    command: app --password={value}\n") == []


def test_compose_reference_without_default_ships_nothing() -> None:
    assert _service("    command: redis-server --requirepass ${REDIS_PASSWORD}\n") == []
    assert (
        _service('    command: ["redis-server", "--requirepass", "${PW:?set it}"]\n')
        == []
    )


# ---- Negative: the key-shaped exemptions carry over -------------------------


def test_file_suffix_flag_is_exempt() -> None:
    assert _service("    command: app --password-file secret.txt\n") == []


def test_quantity_knob_flag_is_exempt() -> None:
    assert _service("    command: app --token-ttl 900 --password-min-length=12\n") == []


def test_boolean_toggle_value_is_exempt() -> None:
    assert _service("    command: app --require-password true\n") == []


def test_flag_without_a_value_is_not_a_literal() -> None:
    assert _service("    command: app --password --verbose\n") == []
    assert _service("    command: app --password\n") == []


def test_unrelated_flags_are_not_flagged() -> None:
    assert _service("    command: nginx -g 'daemon off;' --port 8080 -p 80\n") == []
    assert _service("    command: app --license-key ABC-123 --public-key k.pub\n") == []


# ---- Negative: the mysql `-p` guard --------------------------------------------


def test_glued_p_without_a_mysql_binary_is_not_read() -> None:
    # `-p` is a port, a prefix, a project to everything else.
    assert _service("    command: app -phunter2\n") == []
    assert (
        _service('    healthcheck:\n      test: ["CMD", "pg_isready", "-phunter2"]\n')
        == []
    )


def test_mysql_port_flag_is_not_a_password() -> None:
    assert (
        _service(
            "    healthcheck:\n"
            '      test: ["CMD", "mysqladmin", "ping", "-P", "3306"]\n'
        )
        == []
    )


def test_mysql_binary_by_path_is_recognised() -> None:
    findings = _service(
        "    healthcheck:\n"
        '      test: ["CMD", "/usr/bin/mysqladmin", "ping", "-phunter2"]\n'
    )
    assert [f.evidence for f in findings] == ["healthcheck.test:-p"]


# ---- Shapes of the surfaces themselves -----------------------------------------


def test_disabled_healthcheck_is_not_read() -> None:
    # `disable: true` makes Compose ship `test: ["NONE"]` whatever is written.
    assert (
        _service(
            "    healthcheck:\n"
            "      disable: true\n"
            '      test: ["CMD", "mysqladmin", "ping", "-phunter2"]\n'
        )
        == []
    )


def test_healthcheck_none_and_non_list_shapes() -> None:
    assert _service('    healthcheck:\n      test: ["NONE"]\n') == []
    assert _service("    healthcheck: {test: 42}\n") == []
    assert _service("    healthcheck: not-a-mapping\n") == []
    assert _service("    command: 42\n") == []
    assert _service("    command: {not: a-list}\n") == []


def test_unbalanced_quotes_fall_back_to_whitespace() -> None:
    # A shell line shlex refuses is still scanned token by token.
    findings = _service(
        '    command: redis-server --requirepass hunter2 --save "60 1\n'
    )
    assert [f.evidence for f in findings] == ["command:--requirepass"]


def test_non_string_list_items_are_skipped() -> None:
    assert _argv_tokens(["app", True, None, 8080, {"k": "v"}]) == ["app", "8080"]


def test_cmd_shell_payload_is_split_only_in_position_one() -> None:
    # `CMD-SHELL` is the marker only as the first element; later it is a word.
    tokens = _argv_tokens(["CMD-SHELL", "a --password x"], healthcheck=True)
    assert tokens == ["CMD-SHELL", "a", "--password", "x"]
    tokens = _argv_tokens(["CMD", "CMD-SHELL", "a --password x"], healthcheck=True)
    assert tokens == ["CMD", "CMD-SHELL", "a --password x"]
