"""Tests for CL-0020: Credential-shaped env keys with literal values."""

from __future__ import annotations

from pathlib import Path

from compose_lint.models import Finding, Severity
from compose_lint.parser import load_compose
from compose_lint.rules.CL0020_credential_env_keys import CredentialEnvKeysRule

FIXTURES = Path(__file__).parent / "compose_files"


class TestCredentialEnvKeysRule:
    """Tests for CL-0020 detection of credential-shaped env keys."""

    def setup_method(self) -> None:
        self.rule = CredentialEnvKeysRule()

    def _check(self, service_name: str) -> list[Finding]:
        data, lines = load_compose(FIXTURES / "insecure_credential_env.yml")
        return list(
            self.rule.check(service_name, data["services"][service_name], data, lines)
        )

    # ---- Built-in pattern coverage ----

    def test_detects_literal_postgres_password(self) -> None:
        findings = self._check("literal_postgres_password")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0020"
        assert findings[0].severity == Severity.HIGH
        assert "POSTGRES_PASSWORD" in findings[0].message

    def test_detects_decoy_value(self) -> None:
        # Placeholder values still fire — same leak path, same fix.
        findings = self._check("literal_password_decoy_value")
        assert len(findings) == 1

    def test_detects_token(self) -> None:
        findings = self._check("literal_token_map")
        assert len(findings) == 1
        assert "GITHUB_TOKEN" in findings[0].message

    def test_detects_secret(self) -> None:
        findings = self._check("literal_secret_map")
        assert len(findings) == 1
        assert "JWT_SECRET" in findings[0].message

    def test_detects_api_key(self) -> None:
        findings = self._check("literal_api_key")
        assert len(findings) == 1

    def test_detects_apikey_no_underscore(self) -> None:
        findings = self._check("literal_apikey_no_underscore")
        assert len(findings) == 1
        assert "MYAPIKEY" in findings[0].message

    def test_detects_access_key(self) -> None:
        findings = self._check("literal_access_key")
        assert len(findings) == 1

    def test_detects_secret_key(self) -> None:
        findings = self._check("literal_secret_key")
        assert len(findings) == 1

    def test_detects_credential(self) -> None:
        findings = self._check("literal_credential")
        assert len(findings) == 1

    def test_detects_private_key(self) -> None:
        findings = self._check("literal_private_key")
        assert len(findings) == 1

    # ---- Suffix-anchored patterns ----

    def test_detects_pass_suffix(self) -> None:
        findings = self._check("literal_pass_suffix")
        assert len(findings) == 1
        assert "DB_PASS" in findings[0].message

    def test_detects_pwd_suffix(self) -> None:
        findings = self._check("literal_pwd_suffix")
        assert len(findings) == 1

    def test_detects_passwd(self) -> None:
        findings = self._check("literal_passwd")
        assert len(findings) == 1

    def test_detects_salt(self) -> None:
        findings = self._check("literal_salt")
        assert len(findings) == 1

    def test_detects_dsn(self) -> None:
        findings = self._check("literal_dsn")
        assert len(findings) == 1

    # ---- Env-block forms ----

    def test_list_form_password(self) -> None:
        findings = self._check("list_form_password")
        assert len(findings) == 1
        assert "POSTGRES_PASSWORD" in findings[0].message

    def test_list_form_token(self) -> None:
        findings = self._check("list_form_token_inline")
        assert len(findings) == 1

    def test_multiple_findings_one_service(self) -> None:
        findings = self._check("multiple_findings_one_service")
        assert len(findings) == 3

    # ---- Exemptions: structural FPs ----

    def test_exempt_password_file_suffix(self) -> None:
        findings = self._check("exempt_password_file")
        assert findings == []

    def test_exempt_allow_empty_password_flag(self) -> None:
        findings = self._check("exempt_allow_empty_password")
        assert findings == []

    def test_exempt_random_root_password_flag(self) -> None:
        findings = self._check("exempt_random_root_password")
        assert findings == []

    def test_exempt_boolean_value_true(self) -> None:
        findings = self._check("exempt_boolean_value_true")
        assert findings == []

    def test_exempt_boolean_value_one(self) -> None:
        findings = self._check("exempt_boolean_value_one")
        assert findings == []

    def test_exempt_yaml_native_bool(self) -> None:
        # MYSQL_ALLOW_EMPTY_PASSWORD: true (no quotes) decodes to Python bool;
        # exempt key takes precedence, but even without it the bool value
        # would be skipped because the literal-value check requires str.
        findings = self._check("skip_yaml_bool_value")
        assert findings == []

    # ---- Variable-substitution skips ----

    def test_skip_pure_var_ref(self) -> None:
        findings = self._check("skip_pure_var_ref")
        assert findings == []

    def test_skip_pure_var_with_default(self) -> None:
        findings = self._check("skip_pure_var_default")
        assert findings == []

    def test_skip_short_var(self) -> None:
        findings = self._check("skip_short_var")
        assert findings == []

    def test_skip_mixed_var_reference(self) -> None:
        # Per design: any ${VAR} present → skip. Corpus shows 1 case in
        # 1554 files; not worth bespoke handling.
        findings = self._check("skip_mixed_var_reference")
        assert findings == []

    # ---- Negative cases ----

    def test_skip_empty_string(self) -> None:
        findings = self._check("skip_empty_string")
        assert findings == []

    def test_skip_unrelated_keys(self) -> None:
        findings = self._check("skip_unrelated_key")
        assert findings == []

    def test_skip_bare_list_key(self) -> None:
        # Bare KEY in list form sources value from process env, not literal.
        findings = self._check("skip_bare_list_key")
        assert findings == []

    def test_skip_no_environment(self) -> None:
        findings = self._check("skip_no_environment")
        assert findings == []

    def test_passport_substring_is_not_a_false_positive(self) -> None:
        # Verifies suffix anchoring on _PASS — Passport.js naming would
        # match a raw "PASS" substring but does not match `_PASS$`.
        findings = self._check("skip_passport_substring_false_positive")
        assert findings == []

    # ---- Output shape ----

    def test_finding_has_fix_guidance(self) -> None:
        findings = self._check("literal_postgres_password")
        assert findings[0].fix is not None
        assert "secrets" in findings[0].fix.lower()

    def test_finding_has_references(self) -> None:
        findings = self._check("literal_postgres_password")
        assert len(findings[0].references) >= 2

    def test_finding_has_line_number(self) -> None:
        findings = self._check("literal_postgres_password")
        assert findings[0].line is not None
        assert findings[0].line > 0

    def test_finding_has_line_number_list_form(self) -> None:
        findings = self._check("list_form_password")
        assert findings[0].line is not None
        assert findings[0].line > 0

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0020"
        assert meta.severity == Severity.HIGH
        assert len(meta.references) >= 2
