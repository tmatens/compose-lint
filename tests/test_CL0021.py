"""Tests for CL-0021: Credentials in connection-string env values."""

from __future__ import annotations

import time
from pathlib import Path

from compose_lint.models import Finding, Severity
from compose_lint.parser import load_compose, loads
from compose_lint.rules.CL0020_credential_env_keys import CredentialEnvKeysRule
from compose_lint.rules.CL0021_connection_string_credentials import (
    ConnectionStringCredentialsRule,
)

FIXTURES = Path(__file__).parent / "compose_files"


class TestConnectionStringCredentialsRule:
    """Tests for CL-0021 detection of inline connection-string credentials."""

    def setup_method(self) -> None:
        self.rule = ConnectionStringCredentialsRule()

    def _check(self, service_name: str) -> list[Finding]:
        data, lines = load_compose(FIXTURES / "insecure_connection_string_creds.yml")
        return list(
            self.rule.check(service_name, data["services"][service_name], data, lines)
        )

    # ---- Schemes ----

    def test_detects_postgres_url(self) -> None:
        findings = self._check("postgres_url_literal")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0021"
        assert findings[0].severity == Severity.HIGH
        assert "postgresql" in findings[0].message

    def test_detects_mongo_url(self) -> None:
        findings = self._check("mongo_url_literal")
        assert len(findings) == 1
        assert "mongodb" in findings[0].message

    def test_detects_redis_url(self) -> None:
        findings = self._check("redis_url_literal")
        assert len(findings) == 1

    def test_detects_sqlalchemy_compound_scheme(self) -> None:
        # postgresql+psycopg2 — verifies scheme regex accepts '+' / '.'.
        findings = self._check("airflow_sqlalchemy_conn")
        assert len(findings) == 1
        assert "postgresql+psycopg2" in findings[0].message

    def test_detects_regardless_of_key_name(self) -> None:
        # Key is 'SOMETHING_ELSE' — rule is value-shaped, key-agnostic.
        findings = self._check("innocuous_key_with_inline_creds")
        assert len(findings) == 1

    # ---- Env-block forms ----

    def test_list_form_inline_creds(self) -> None:
        findings = self._check("list_form_inline_creds")
        assert len(findings) == 1

    def test_multiple_findings_one_service(self) -> None:
        findings = self._check("multiple_inline_creds")
        assert len(findings) == 2

    # ---- Skips: variable substitution ----

    def test_skip_user_var_password_var(self) -> None:
        findings = self._check("skip_user_var_password_var")
        assert findings == []

    def test_skip_user_literal_password_var(self) -> None:
        findings = self._check("skip_user_literal_password_var")
        assert findings == []

    def _check_inline(self, value: str) -> list[Finding]:
        data, lines = loads(
            "services:\n"
            "  app:\n"
            "    image: nginx\n"
            "    environment:\n"
            f"      URL: {value}\n"
        )
        return list(self.rule.check("app", data["services"]["app"], data, lines))

    def test_detect_password_only_userinfo(self) -> None:
        # RFC 3986 §3.2.1 permits an empty username, and `redis://:password@host`
        # is the standard Redis URL form — it must fire (issue #279 R2).
        findings = self._check_inline('"redis://:supersecret@redis:6379/0"')
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0021"
        assert "redis" in findings[0].message

    def test_skip_password_only_userinfo_var_password(self) -> None:
        # The empty-username form still honors the password-is-a-var guard.
        findings = self._check_inline('"redis://:${REDIS_PASSWORD}@redis:6379/0"')
        assert findings == []

    def test_detect_user_var_password_literal(self) -> None:
        # Only the password being a var means the secret is parameterized. A var
        # username with a literal password still leaks the password, so it must
        # fire (issue #277 F6).
        findings = self._check("detect_user_var_password_literal")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0021"

    def test_skip_pure_var_value(self) -> None:
        findings = self._check("skip_pure_var_value")
        assert findings == []

    def test_skip_list_form_with_var(self) -> None:
        findings = self._check("list_form_skipped_when_var")
        assert findings == []

    # ---- $$ escape: a literal dollar is not a substitution (issue #502) ----

    def test_detect_dollar_escaped_password_in_url(self) -> None:
        # `$$` is Compose's escape for a literal `$` — the password is a
        # literal credential, not parameterized.
        findings = self._check_inline('"postgres://app:pa$$w0rd@db/app"')
        assert len(findings) == 1

    def test_detect_trailing_dollar_password_in_url(self) -> None:
        # A trailing `$` cannot begin a substitution — still a literal.
        findings = self._check_inline('"postgres://u:hunter2$@db/x"')
        assert len(findings) == 1

    def test_skip_password_var_after_escaped_dollar(self) -> None:
        # `$$` is a literal `$`; the `${VAR}` after it is a real substitution,
        # so the password is still parameterized.
        findings = self._check_inline('"postgres://u:$$${DB_PASSWORD}@db/x"')
        assert findings == []

    def test_agrees_with_cl0020_on_dollar_passwords(self) -> None:
        # The same password must classify identically as an env-key value
        # (CL-0020) and inside a connection string (CL-0021) (issue #502).
        for password in ("pa$$w0rd", "hunter2$"):
            data, lines = loads(
                "services:\n"
                "  app:\n"
                "    image: nginx\n"
                "    environment:\n"
                f'      DB_PASSWORD: "{password}"\n'
                f'      DATABASE_URL: "postgres://app:{password}@db/app"\n'
            )
            svc = data["services"]["app"]
            key_findings = list(CredentialEnvKeysRule().check("app", svc, data, lines))
            url_findings = list(self.rule.check("app", svc, data, lines))
            assert [f.rule_id for f in key_findings] == ["CL-0020"], password
            assert [f.rule_id for f in url_findings] == ["CL-0021"], password

    # ---- Skips: structural ----

    def test_skip_no_password(self) -> None:
        findings = self._check("skip_no_password")
        assert findings == []

    def test_skip_empty_password(self) -> None:
        findings = self._check("skip_empty_password")
        assert findings == []

    def test_skip_no_userinfo(self) -> None:
        findings = self._check("skip_no_userinfo")
        assert findings == []

    def test_skip_empty_value(self) -> None:
        findings = self._check("skip_empty_value")
        assert findings == []

    def test_skip_no_environment(self) -> None:
        findings = self._check("skip_no_environment")
        assert findings == []

    # ---- Performance: ReDoS regression ----

    def test_large_value_without_at_is_linear(self) -> None:
        # A value shaped like `scheme://<many>:<many>` with no terminating '@'
        # can never match (the pattern requires '@'), but before the early
        # guard `finditer` rescanned the tail from every offset, giving O(n^2)
        # behavior on attacker-controlled env values — a cheap DoS when
        # sweeping untrusted Compose files. The unguarded path takes ~20s at
        # this size; the guard makes it instant.
        value = '"redis://' + "u" * 100_000 + ":" + "p" * 100_000 + '"'
        start = time.perf_counter()
        findings = self._check_inline(value)
        elapsed = time.perf_counter() - start
        assert findings == []
        assert elapsed < 2.0, f"CL-0021 scan took {elapsed:.2f}s (possible ReDoS)"

    # ---- Output shape ----

    def test_finding_has_fix_guidance(self) -> None:
        findings = self._check("postgres_url_literal")
        assert findings[0].fix is not None
        assert "secrets" in findings[0].fix.lower()

    def test_finding_has_references(self) -> None:
        findings = self._check("postgres_url_literal")
        # OWASP + Compose secrets + RFC 3986
        assert len(findings[0].references) >= 3

    def test_finding_has_line_number(self) -> None:
        findings = self._check("postgres_url_literal")
        assert findings[0].line is not None
        assert findings[0].line > 0

    def test_finding_has_line_number_list_form(self) -> None:
        findings = self._check("list_form_inline_creds")
        assert findings[0].line is not None

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0021"
        assert meta.severity == Severity.HIGH
        assert len(meta.references) >= 3
