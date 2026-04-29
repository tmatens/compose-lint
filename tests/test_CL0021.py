"""Tests for CL-0021: Credentials in connection-string env values."""

from __future__ import annotations

from pathlib import Path

from compose_lint.models import Finding, Severity
from compose_lint.parser import load_compose
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

    def test_skip_user_var_password_literal(self) -> None:
        # Either half being a var disqualifies — credential is parameterized
        # at least in part.
        findings = self._check("skip_user_var_password_literal")
        assert findings == []

    def test_skip_pure_var_value(self) -> None:
        findings = self._check("skip_pure_var_value")
        assert findings == []

    def test_skip_list_form_with_var(self) -> None:
        findings = self._check("list_form_skipped_when_var")
        assert findings == []

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
