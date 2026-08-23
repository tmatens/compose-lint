"""Tests for CL-0020: Credential-shaped env keys with literal values."""

from __future__ import annotations

from pathlib import Path

import pytest

from compose_lint.models import Finding, Severity
from compose_lint.parser import load_compose, loads
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

    def test_detects_numeric_password(self) -> None:
        # An unquoted numeric value decodes to int and was skipped (#277 F7).
        data, lines = loads(
            "services:\n"
            "  a:\n"
            "    image: nginx:1.27\n"
            "    environment:\n"
            "      DB_PASSWORD: 12345678\n"
        )
        findings = list(self.rule.check("a", data["services"]["a"], data, lines))
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0020"

    def _check_key(self, key: str, value: str = "hunter2") -> list[Finding]:
        data, lines = loads(
            "services:\n"
            "  a:\n"
            "    image: nginx:1.27\n"
            "    environment:\n"
            f"      {key}: {value}\n"
        )
        return list(self.rule.check("a", data["services"]["a"], data, lines))

    def test_detects_passphrase(self) -> None:
        # PASSPHRASE is unambiguously a secret and was missed (issue #279 R3).
        findings = self._check_key("GPG_PASSPHRASE")
        assert len(findings) == 1
        assert "GPG_PASSPHRASE" in findings[0].message

    def test_detects_encryption_key(self) -> None:
        findings = self._check_key("ENCRYPTION_KEY")
        assert len(findings) == 1

    def test_license_key_not_flagged(self) -> None:
        # A generic `_KEY` suffix is deliberately not matched (issue #279 R3).
        assert self._check_key("LICENSE_KEY") == []

    def test_boolean_value_not_flagged(self) -> None:
        # A credential-shaped key whose value is a YAML boolean (decodes to a
        # Python bool) is a toggle, not a literal secret — keep it exempt (#277 F7).
        data, lines = loads(
            "services:\n"
            "  a:\n"
            "    image: nginx:1.27\n"
            "    environment:\n"
            "      DB_PASSWORD: no\n"
        )
        findings = list(self.rule.check("a", data["services"]["a"], data, lines))
        assert findings == []

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

    # ---- Exemptions: quantity knobs (issue #561) ----

    @pytest.mark.parametrize(
        "key",
        [
            "JWT_ACCESS_TOKEN_EXPIRE_MINUTES",
            "JWT_REFRESH_TOKEN_EXPIRE_DAYS",
            "ACCESS_TOKEN_EXPIRE_MINUTES",
            "DEEPFENCE_ACCESS_TOKEN_EXPIRY_MINUTES",
            "WF_AUTH_TOKEN_TTL_MINUTES",
            "PASSWORD_RESET_TOKEN_TTL",
            "PASSWORD_CHANGE_TICKET_TTL_SECONDS",
            "GF_AUTH_TOKEN_ROTATION_INTERVAL_MINUTES",
            "JWT__REFRESHTOKENEXPIRATIONDAYS",
            "TOKENVALIDITYMAX",
            "TOKEN_USAGE_RETENTION",
            "OPENAI_MAX_TOKENS",
            "SUMMARY_MAX_TOKENS",
            "CHATGPT2API_THREAD_TOKENS",
            "DEFAULT_TOKEN_LIMIT",
            "OLLAMA_MODEL_TOKEN_LIMIT",
            "INDEXING_MAX_SEGMENTATION_TOKENS_LENGTH",
            "PASSWORDMINCHAR",
            "USER_PASSWORD_MIN_LENGTH",
            "USER_PASSWORD_REQUIREMENTS",
            "OCIS_PASSWORD_POLICY_MIN_CHARACTERS",
            "TOKEN_SIGNUP_BONUS",
            "SECRET_PORT",
            "SECRET_FILE_SIZE",
            "SECRET_MAX_TEXT_SIZE",
        ],
    )
    def test_exempt_quantity_knob_keys(self, key: str) -> None:
        # A lifetime/size/policy knob is not the credential it is named after.
        # These are real corpus false positives from issue #561.
        assert self._check_key(key, "30") == []

    # ---- Exemptions: additional quantity knobs (issue #681) ----

    @pytest.mark.parametrize(
        "key",
        [
            "PASSWORD_ROUNDS",
            "PASSWORD_ITERATIONS",
            "PASSWORD_HISTORY",
            "PASSWORD_ATTEMPTS",
            "PASSWORD_RETRIES",
            "TOKEN_LENGTH",
            "SECRET_LENGTH",
            "PASSWORD_STRENGTH",
            "SALT_ROUNDS",
            "BCRYPT_ROUNDS",
            "ARGON2_ITERATIONS",
            "BCRYPT_COST",
            "PASSWORD_COST",
        ],
    )
    def test_exempt_additional_quantity_knob_keys(self, key: str) -> None:
        # These quantity knobs were added from issue #681 rather than
        # corpus false positives from issue #561.
        assert self._check_key(key, "30") == []

    def test_cost_exemption_is_suffix_anchored(self) -> None:
        # COST is suffix-anchored so unrelated names such as API_COST_TOKEN
        # remain credential findings.
        assert len(self._check_key("API_COST_TOKEN", "12345")) == 1

    @pytest.mark.parametrize(
        "value", ["30", "1.5", "900s", "500ms", "30m", "24h", "7d"]
    )
    def test_exempt_quantity_knob_value_forms(self, value: str) -> None:
        assert self._check_key("TOKEN_TTL", value) == []

    def test_knob_key_with_interpolated_default_is_exempt(self) -> None:
        # The parser resolves `${WF_TTL:-60}` to 60 before the rule runs, so
        # the defaulted form must be exempt exactly like the bare literal —
        # this is the form that grading defaults newly surfaced.
        assert self._check_key("WF_AUTH_TOKEN_TTL_MINUTES", '"${WF_TTL:-60}"') == []

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            # Value is a quantity but the key names the credential itself.
            ("DB_PASSWORD", "12345678"),
            ("POSTGRES_PASSWORD", "1234"),
            ("SECRET_KEY", "12345"),
            ("DB_PASS", "1234"),
            # Key is knob-shaped but the value is not a quantity.
            ("AUTH_TOKENS", "your_token_here"),
            ("TOKEN_TTL", "hunter2"),
            ("PASSWORD_RESET_REQUEST_THROTTLE_RATE", '"5/hour"'),
        ],
    )
    def test_quantity_exemption_needs_both_halves(self, key: str, value: str) -> None:
        # Exempting on either half alone would lose a real finding: a weak
        # numeric password (issue #277 F7) or a literal token.
        assert len(self._check_key(key, value)) == 1

    def test_passport_secret_is_not_read_as_a_port(self) -> None:
        # _PORT is suffix-anchored: PASSPORT_SECRET contains "PORT" but the
        # key does not end in it, so the credential still fires.
        assert len(self._check_key("PASSPORT_SECRET", "12345")) == 1

    # ---- Variable-substitution skips ----

    def test_skip_pure_var_ref(self) -> None:
        findings = self._check("skip_pure_var_ref")
        assert findings == []

    def test_defaulted_var_is_graded_on_the_value_it_ships(self) -> None:
        # "${POSTGRES_PASSWORD:-fallback}" ships the literal "fallback" with no
        # .env set (verified with `docker compose config`), so the credential is
        # in the file and the rule must say so. Previously exempted for carrying
        # a reference at all, which made the default a free bypass.
        findings = self._check("skip_pure_var_default")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0020"

    def test_skip_short_var(self) -> None:
        findings = self._check("skip_short_var")
        assert findings == []

    def test_mixed_var_reference_is_not_exempt(self) -> None:
        # Only a value that is *wholly* a reference is unknowable. A value that
        # merely contains one still ships its literal part: "hunter2$X" ships
        # "hunter2". The old "any reference → skip" rule made appending one
        # character enough to silence the rule on a hardcoded credential.
        findings = self._check("skip_mixed_var_reference")
        assert len(findings) == 1

    # ---- $$ escape: a literal dollar is not a substitution (issue #502) ----

    def test_detects_dollar_escaped_password(self) -> None:
        # `$$` is Compose's escape for a literal `$`; the `$w0rd` tail must
        # not be read as a `$VAR` reference.
        findings = self._check_key("DB_PASSWORD", '"pa$$w0rd"')
        assert len(findings) == 1

    def test_detects_trailing_dollar_password(self) -> None:
        # A trailing `$` cannot begin a substitution — still a literal.
        findings = self._check_key("DB_PASSWORD", '"hunter2$"')
        assert len(findings) == 1

    def test_skip_var_ref_following_escaped_dollar(self) -> None:
        # Compose consumes escapes left-to-right: `$$` is a literal `$`, the
        # `${VAR}` after it is a real substitution — still parameterized.
        findings = self._check_key("DB_PASSWORD", '"$$${DB_PASSWORD}"')
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
