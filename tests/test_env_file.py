"""Tests for the ``.env`` reader.

Two halves. The unit tests below pin the behaviour compose-lint promises,
including the two places it deliberately diverges from Compose. The
differential suite in ``test_env_semantics.py`` re-derives the grammar from the
``docker compose`` binary, so a Compose release that changes it fails there
rather than silently mis-resolving a user's stack.
"""

from __future__ import annotations

import os
import stat
from typing import TYPE_CHECKING

from compose_lint._env_file import MAX_ENV_BYTES, EnvFile, parse_env, read_env

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def values(text: str, wanted: list[str] | None = None) -> dict[str, str]:
    return dict(parse_env(text, wanted).values)


class TestGrammar:
    """The shapes a hand-written ``.env`` comes in."""

    def test_plain_pair(self) -> None:
        assert values("K=v") == {"K": "v"}

    def test_key_and_value_are_trimmed(self) -> None:
        assert values("  K  =  v  ") == {"K": "v"}

    def test_export_prefix_is_consumed(self) -> None:
        assert values("export K=v") == {"K": "v"}

    def test_comments_and_blank_lines_are_ignored(self) -> None:
        assert values("# note\n\n\t\nK=v\n  # trailing note\n") == {"K": "v"}

    def test_first_equals_splits(self) -> None:
        assert values("K=a=b") == {"K": "a=b"}

    def test_key_without_equals_is_empty(self) -> None:
        """Compose ships this as empty rather than leaving the key unset."""
        assert values("K") == {"K": ""}

    def test_empty_value(self) -> None:
        assert values("K=") == {"K": ""}

    def test_last_duplicate_wins(self) -> None:
        assert values("K=first\nK=second") == {"K": "second"}

    def test_crlf_and_bom_are_tolerated(self) -> None:
        assert values("\ufeffK=v\r\nJ=w\r\n") == {"K": "v", "J": "w"}


class TestLineBreaks:
    """Only ``\\n`` ends a line. Everything else stays inside the value.

    A splitter that breaks on more than Compose does would see entries Compose
    never reads \u2014 including a ``COMPOSE_FILE`` it never honours, which is the
    ADR-026 section 4 failure arriving through the lexer.
    """

    def test_bare_carriage_return_is_not_a_break(self) -> None:
        assert values("K=v\rJ=w\n") == {"K": "v\rJ=w"}

    def test_form_feed_is_not_a_break(self) -> None:
        assert values("K=v\fJ=w\n") == {"K": "v\fJ=w"}

    def test_next_line_u0085_is_not_a_break(self) -> None:
        assert values("K=v\x85J=w\n") == {"K": "v\x85J=w"}

    def test_line_separator_u2028_is_not_a_break(self) -> None:
        assert values("K=v\u2028J=w\n") == {"K": "v\u2028J=w"}

    def test_a_smuggled_key_is_not_seen(self) -> None:
        """The case that motivates the rule, stated as itself."""
        parsed = parse_env("K=v\rCOMPOSE_FILE=decoy.yml\n")
        assert "COMPOSE_FILE" not in parsed.values


class TestQuoting:
    """Quoting decides three separate things: trailing comments, escapes, expansion."""

    def test_double_quotes_are_stripped(self) -> None:
        assert values('K="v w"') == {"K": "v w"}

    def test_single_quotes_are_stripped(self) -> None:
        assert values("K='v w'") == {"K": "v w"}

    def test_unquoted_value_ends_at_a_comment(self) -> None:
        assert values("K=v # trail") == {"K": "v"}

    def test_quoted_value_keeps_a_hash(self) -> None:
        assert values('K="v # trail"') == {"K": "v # trail"}

    def test_double_quotes_process_escapes(self) -> None:
        assert values('K="a\\nb"') == {"K": "a\nb"}

    def test_single_quotes_do_not(self) -> None:
        assert values("K='a\\nb'") == {"K": "a\\nb"}

    def test_unquoted_does_not(self) -> None:
        assert values("K=a\\nb") == {"K": "a\\nb"}

    def test_unrecognized_escape_keeps_its_backslash(self) -> None:
        """A Windows path must survive: dropping the backslash mangles it."""
        assert values('K="C:\\Users\\me"') == {"K": "C:\\Users\\me"}


class TestExpansion:
    """Expansion runs in file order, against what the file has defined so far."""

    def test_braced_reference(self) -> None:
        assert values("A=one\nK=${A}-two") == {"A": "one", "K": "one-two"}

    def test_bare_reference(self) -> None:
        assert values("A=one\nK=$A-two") == {"A": "one", "K": "one-two"}

    def test_single_quotes_suppress_expansion(self) -> None:
        assert values("A=one\nK='${A}'") == {"A": "one", "K": "${A}"}

    def test_default_applies_when_undefined(self) -> None:
        assert values("K=${MISSING:-dflt}") == {"K": "dflt"}

    def test_forward_reference_does_not_resolve(self) -> None:
        """Compose resolves top-down; a later key is not yet defined."""
        parsed = parse_env("K=${LATER}\nLATER=x")
        assert "K" not in parsed.values
        assert "K" in parsed.unresolved
        assert parsed.values["LATER"] == "x"

    def test_escaped_dollar_ships_one_literal_dollar(self) -> None:
        assert values("K=a$$b") == {"K": "a$b"}

    def test_escaped_dollar_suppresses_the_reference_after_it(self) -> None:
        assert values("A=one\nK=a$$A") == {"A": "one", "K": "a$A"}


class TestDivergesFromCompose:
    """The two places mimicking Compose would be wrong. See ADR-026."""

    def test_unknown_reference_is_unresolved_not_empty(self) -> None:
        """Compose falls back to the shell, then to empty. Both describe the
        lint host rather than the project, so neither is claimed."""
        parsed = parse_env("K=${SOME_SHELL_VAR}/tail")
        assert parsed.values == {}
        assert parsed.unresolved == {"K"}

    def test_the_process_environment_is_never_consulted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The name is set in this very process, and must still not be found."""
        monkeypatch.setenv("CL_TEST_ENV_LEAK", "leaked")
        parsed = parse_env("K=${CL_TEST_ENV_LEAK}")
        assert "leaked" not in str(parsed.values)
        assert parsed.unresolved == {"K"}

    def test_malformed_line_is_skipped_not_fatal(self) -> None:
        """Compose refuses the whole file; a lint run keeps going and says so."""
        parsed = parse_env("this is not a pair\nK=v\n")
        assert parsed.values == {"K": "v"}
        assert parsed.skipped_lines == (1,)

    def test_orphan_equals_is_skipped(self) -> None:
        parsed = parse_env("=orphan\nK=v\n")
        assert parsed.values == {"K": "v"}
        assert parsed.skipped_lines == (1,)

    def test_a_redefinition_that_fails_clears_the_earlier_value(self) -> None:
        """Nothing downstream should read a value the file went on to replace."""
        parsed = parse_env("K=good\nK=${UNKNOWN}")
        assert parsed.values == {}
        assert parsed.unresolved == {"K"}


class TestWantedSetFilter:
    """Only what the run needs is retained (ADR-026 section 5)."""

    def test_unwanted_keys_are_dropped(self) -> None:
        text = "SECRET=hunter2\nWANTED=v\n"
        assert values(text, ["WANTED"]) == {"WANTED": "v"}

    def test_closure_pulls_in_what_a_wanted_value_needs(self) -> None:
        """WANTED cannot resolve without BASE, so BASE is needed even though
        the Compose document never names it."""
        text = "SECRET=hunter2\nBASE=/var/run\nWANTED=${BASE}/docker.sock\n"
        parsed = parse_env(text, ["WANTED"])
        assert parsed.values["WANTED"] == "/var/run/docker.sock"
        assert "SECRET" not in parsed.values

    def test_closure_follows_a_chain(self) -> None:
        text = "A=1\nB=${A}2\nC=${B}3\nUNUSED=x\n"
        parsed = parse_env(text, ["C"])
        assert parsed.values["C"] == "123"
        assert "UNUSED" not in parsed.values

    def test_closure_reaches_through_a_default(self) -> None:
        text = "FALLBACK=/fallback\nK=${MISSING:-${FALLBACK}}\n"
        assert parse_env(text, ["K"]).values["K"] == "/fallback"

    def test_wanting_nothing_keeps_nothing(self) -> None:
        assert values("SECRET=hunter2", []) == {}

    def test_none_means_everything(self) -> None:
        assert values("A=1\nB=2", None) == {"A": "1", "B": "2"}

    def test_unresolved_is_narrowed_to_the_wanted_set(self) -> None:
        parsed = parse_env("OTHER=${NOPE}\nK=v\n", ["K"])
        assert parsed.unresolved == frozenset()


class TestReadEnv:
    """Reading is bounded, located in the project directory, and never fatal."""

    def test_reads_the_sibling_file(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("K=v\n", encoding="utf-8", newline="")
        parsed = read_env(tmp_path)
        assert parsed is not None
        assert parsed.values == {"K": "v"}

    def test_absent_file_is_none(self, tmp_path: Path) -> None:
        assert read_env(tmp_path) is None

    def test_only_the_projects_env_is_read(self, tmp_path: Path) -> None:
        """A `.env` beside the shell's cwd is not the project's; Compose
        ignores it, and reading it would make the run depend on where it
        was launched from."""
        project = tmp_path / "project"
        project.mkdir()
        (tmp_path / ".env").write_text("K=from-cwd\n", encoding="utf-8", newline="")
        (project / ".env").write_text("K=from-project\n", encoding="utf-8", newline="")
        parsed = read_env(project)
        assert parsed is not None
        assert parsed.values == {"K": "from-project"}

    def test_oversized_file_is_treated_as_absent(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text(
            "K=" + "x" * (MAX_ENV_BYTES + 1), encoding="utf-8", newline=""
        )
        assert read_env(tmp_path) is None

    def test_a_fifo_does_not_hang_the_run(self, tmp_path: Path) -> None:
        if not hasattr(os, "mkfifo"):
            return
        os.mkfifo(tmp_path / ".env")
        assert stat.S_ISFIFO((tmp_path / ".env").stat().st_mode)
        assert read_env(tmp_path) is None

    def test_non_utf8_is_treated_as_absent(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_bytes(b"K=\xff\xfe\n")
        assert read_env(tmp_path) is None

    def test_wanted_set_applies_through_read(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text(
            "SECRET=hunter2\nK=v\n", encoding="utf-8", newline=""
        )
        parsed = read_env(tmp_path, ["K"])
        assert parsed is not None
        assert parsed.values == {"K": "v"}


class TestEnvFile:
    def test_is_falsy_when_it_supplies_nothing(self) -> None:
        assert not EnvFile(values={}, unresolved=frozenset(), skipped_lines=())

    def test_is_truthy_when_it_supplies_something(self) -> None:
        assert EnvFile(values={"K": "v"}, unresolved=frozenset(), skipped_lines=())
