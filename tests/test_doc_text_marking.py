"""A rule says which part of a finding it quoted from the document.

A value a sibling ``.env`` filled in is graded but not printed: the report
shows ``${NAME}``. Finding the value in a finished message means searching
for it, and that search missed pieces a rule had cut out of a value, values a
second substitution path filled in, and strings the parser rewrote after
substituting (GHSA-jf3h-8jvx-vcrg and the incomplete fixes after it).

So every value a rule takes from the document goes through
``_output.quoted`` or ``_output.inline``, which mark it, and the engine
replaces any run of a value inside a mark. Three tests hold that in place:

- every value interpolated into a rule's ``message=`` is marked, or is on the
  short list of the rule's own words (:func:`test_message_values_are_marked`);
- for every fixture and every string in it, a marker put into that string
  only ever appears inside a mark (:func:`test_document_text_is_marked`);
- for every fixture and every string in it, a marker supplied through a
  ``.env`` never appears in any output of a real run
  (:func:`test_no_env_value_reaches_any_output`).

Every value here is a synthetic marker.
"""

from __future__ import annotations

import ast
import copy
from pathlib import Path
from typing import Any

import pytest
import yaml

from compose_lint import _doc_text, _env_quote, cli, engine
from compose_lint._doc_text import GRAM, grams, mark, quote_spans, split
from compose_lint.parser import ComposeError, load_compose
from compose_lint.rules import get_registered_rules

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES = REPO_ROOT / "src" / "compose_lint" / "rules"
FIXTURES = sorted((REPO_ROOT / "tests" / "compose_files").glob("*.y*ml"))
ENV_NAME = "." + "env"

# Mixed case, so a rule that upper-cases what it quotes is still seen.
CANARY = "zqCanaryZq9x"
# The same marker with the characters a formatter escapes.
HOSTILE = "zqCan\\ary'Zq\"9x"


class TestMarks:
    def test_split_returns_the_text_and_where_the_marks_were(self) -> None:
        text = f"Image '{mark('nginx:1.27')}' is pinned"
        clean, spans = split(text)
        assert clean == "Image 'nginx:1.27' is pinned"
        assert spans == ((7, 17),)
        assert clean[7:17] == "nginx:1.27"

    def test_unmarked_text_is_returned_as_it_is(self) -> None:
        text = "Service does not drop all capabilities."
        assert split(text) == (text, ())

    def test_marking_marked_text_shows_the_inner_marks(self) -> None:
        # mark() cannot tell a mark a rule made from one a value carried in,
        # so it escapes both. A rule therefore marks a value once, and
        # test_document_text_is_marked fails if an escape shows up in a message.
        clean, spans = split(mark(f"a{mark('b')}c"))
        assert clean == "a\\ue000b\\ue001c"
        assert spans == ((0, len(clean)),)

    def test_split_reads_nested_marks_as_one_span(self) -> None:
        nested = (
            f"{_doc_text.OPEN}a{_doc_text.OPEN}b{_doc_text.CLOSE}c{_doc_text.CLOSE}"
        )
        assert split(nested) == ("abc", ((0, 3),))

    def test_a_value_cannot_close_its_own_mark(self) -> None:
        hostile = f"registry{_doc_text.CLOSE}/secret-part"
        clean, spans = split(f"Image '{mark(hostile)}' has no tag")
        start, end = spans[0]
        assert "secret-part" in clean[start:end]
        assert _doc_text.CLOSE not in clean
        assert _doc_text.OPEN not in clean

    def test_an_unclosed_mark_covers_the_rest(self) -> None:
        clean, spans = split(f"a {_doc_text.OPEN}bcd")
        assert (clean, spans) == ("a bcd", ((2, 5),))

    def test_an_empty_mark_leaves_no_span(self) -> None:
        assert split(f"a{mark('')}b") == ("ab", ())


class TestQuoteSpans:
    VALUES = {"TOKEN": "s3cr3tTokenValue99"}

    def _quote(self, text: str) -> str:
        clean, spans = split(text)
        return quote_spans(clean, spans, grams(self.VALUES))

    def test_a_whole_value_is_replaced(self) -> None:
        assert self._quote(f"in a {mark('s3cr3tTokenValue99')}:// string") == (
            "in a ${TOKEN}:// string"
        )

    def test_a_piece_cut_anywhere_is_replaced(self) -> None:
        # Cut where no separator is: the cautious search never looked here.
        assert self._quote(f"scheme {mark('TokenValue99')}") == "scheme ${TOKEN}"

    def test_a_value_inside_a_longer_string_is_replaced(self) -> None:
        marked = mark("/srv/s3cr3tTokenValue99/docker.sock")
        assert self._quote(f"via '{marked}'") == "via '/srv/${TOKEN}/docker.sock'"

    def test_case_does_not_hide_a_value(self) -> None:
        assert self._quote(mark("S3CR3TTOKENVALUE99")) == "${TOKEN}"

    def test_text_outside_a_mark_is_left_alone(self) -> None:
        text = f"s3cr3tTokenValue99 and {mark('other-text')}"
        assert self._quote(text) == "s3cr3tTokenValue99 and other-text"

    def test_a_run_shorter_than_the_floor_is_left_alone(self) -> None:
        short = "s3cr3tTokenValue99"[: GRAM - 1]
        assert self._quote(mark(short)) == short

    def test_an_escaped_spelling_is_replaced(self) -> None:
        known = grams({"PW": "pass\\word'with\"quotes"})
        for spelling in (
            "pass\\\\word'with\"quotes",
            "pass\\\\word\\'with\"quotes",
            "pass\\\\word'with\\\"quotes",
        ):
            assert quote_spans(spelling, ((0, len(spelling)),), known) == "${PW}"

    def test_a_line_break_written_as_an_escape_is_replaced(self) -> None:
        known = grams({"KEY": "first-line\nsecond-line"})
        text = "first-line\\u000asecond-line"
        assert quote_spans(text, ((0, len(text)),), known) == "${KEY}"

    def test_two_values_side_by_side_are_two_references(self) -> None:
        known = grams({"A": "alphaalphaalpha", "B": "bravobravobravo"})
        text = "alphaalphaalphabravobravobravo"
        assert quote_spans(text, ((0, len(text)),), known) == "${A}${B}"

    def test_no_values_means_no_change(self) -> None:
        assert quote_spans("anything at all", ((0, 8),), {}) == "anything at all"


def test_a_rule_never_yields_a_mark() -> None:
    """The marks are stripped at the rule's boundary, with the spans kept."""
    data, lines = load_compose(
        REPO_ROOT / "tests" / "compose_files" / "insecure_socket.yml", use_env=False
    )
    seen_span = False
    for cls in get_registered_rules():
        rule = cls()
        for name, config in data["services"].items():
            for finding in rule.check(name, config, data, lines):
                for text in (finding.message, finding.fix or ""):
                    assert _doc_text.OPEN not in text
                    assert _doc_text.CLOSE not in text
                for start, end in finding.message_spans:
                    assert 0 <= start < end <= len(finding.message)
                    seen_span = True
    assert seen_span, "no finding on the socket fixture marked anything"


def test_the_engine_hands_out_findings_without_spans() -> None:
    data, lines = load_compose(
        REPO_ROOT / "tests" / "compose_files" / "insecure_socket.yml", use_env=False
    )
    findings = engine.run_rules(data, lines)
    assert findings
    assert all(not f.message_spans and not f.fix_spans for f in findings)


# --- every interpolated message value is marked ------------------------------

# A rule's own words: names it chose from its own tables, never text from the
# document. Adding to this list is a review decision, which is the point.
OWN_WORDS = {
    "CL0001_docker_socket.py": {"runtime", "_SOCKET_DIRS[directory]"},
    "CL0009_security_profile.py": {"profile_name", "removal"},
    "CL0010_host_namespace.py": {"desc"},
    "CL0011_dangerous_cap_add.py": {"STRONG_CAPS[bare]"},
    "CL0013_sensitive_mount.py": {"matched", "reason"},
    "CL0016_dangerous_devices.py": {"description"},
    "CL0020_credential_env_keys.py": {"location"},
    "CL0024_host_exec_cap_add.py": {"HOST_EXEC_CAPS[bare]"},
    "CL0025_writable_host_root.py": {"matched", "_GRANTS[matched]"},
    "CL0026_resource_limits.py": {"missing"},
    "CL0027_lesser_cap_add.py": {"LESSER_CAPS[bare]"},
    "CL0028_host_reach_cap_add.py": {"HOST_REACH_CAPS[bare]"},
    "CL0029_host_availability_cap_add.py": {"HOST_AVAILABILITY_CAPS[bare]"},
    "CL0030_host_disclosure_cap_add.py": {"HOST_DISCLOSURE_CAPS[bare]"},
}


def _message_root(node: ast.AST) -> ast.expr | None:
    if isinstance(node, ast.keyword) and node.arg == "message":
        return node.value
    if isinstance(node, ast.Assign) and any(
        isinstance(t, ast.Name) and t.id == "message" for t in node.targets
    ):
        return node.value
    return None


def _message_expressions() -> list[tuple[str, int, ast.expr]]:
    found = []
    for path in sorted(RULES.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            root = _message_root(node)
            if root is None:
                continue
            for field in ast.walk(root):
                if isinstance(field, ast.FormattedValue):
                    found.append((path.name, field.lineno, field.value))
    return found


def test_message_values_are_marked() -> None:
    expressions = _message_expressions()
    assert expressions, "the scan found no interpolated message at all"
    unmarked = [
        f"{name}:{line}: {ast.unparse(value)}"
        for name, line, value in expressions
        if not (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id in ("quoted", "inline")
        )
        and ast.unparse(value) not in OWN_WORDS.get(name, set())
    ]
    assert unmarked == []


def test_the_own_words_list_names_only_what_exists() -> None:
    present: dict[str, set[str]] = {}
    for name, _line, value in _message_expressions():
        present.setdefault(name, set()).add(ast.unparse(value))
    stale = {
        name: sorted(words - present.get(name, set()))
        for name, words in OWN_WORDS.items()
        if words - present.get(name, set())
    }
    assert stale == {}


# --- a marker put into any string only appears inside a mark -----------------


def _strings(
    node: Any, path: tuple[Any, ...] = ()
) -> list[tuple[tuple[Any, ...], str]]:
    found: list[tuple[tuple[Any, ...], str]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            found += _strings(value, (*path, key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found += _strings(value, (*path, index))
    elif isinstance(node, str):
        found.append((path, node))
    return found


def _put(root: Any, path: tuple[Any, ...], value: str) -> None:
    for step in path[:-1]:
        root = root[step]
    root[path[-1]] = value


def _spellings(text: str, marker: str) -> list[str]:
    """``text`` with ``marker`` put where a rule might cut it out."""
    out = [text + marker, marker + text]
    if "/" in text:
        cut = text.rindex("/")
        out.append(f"{text[:cut]}/{marker}{text[cut:]}")
    if ":" in text:
        cut = text.index(":")
        out.append(f"{text[:cut]}{marker}{text[cut:]}")
    return out


def _outside_marks(text: str, spans: tuple[tuple[int, int], ...]) -> list[int]:
    low, needle = text.lower(), CANARY.lower()
    bad = []
    at = low.find(needle)
    while at != -1:
        if not any(start <= at and at + len(needle) <= end for start, end in spans):
            bad.append(at)
        at = low.find(needle, at + 1)
    return bad


def _loadable(fixture: Path) -> tuple[dict[str, Any], dict[str, int]] | None:
    try:
        return load_compose(fixture, use_env=False)
    except ComposeError:
        return None


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda p: p.name)
def test_document_text_is_marked(fixture: Path) -> None:
    loaded = _loadable(fixture)
    if loaded is None:
        pytest.skip("not a loadable Compose file")
    data, lines = loaded
    rules = [cls() for cls in get_registered_rules()]
    unmarked: list[str] = []
    for path, text in _strings(data):
        for spelling in _spellings(text, CANARY):
            mutated = copy.deepcopy(data)
            _put(mutated, path, spelling)
            services = mutated.get("services")
            if not isinstance(services, dict):
                continue
            for name, config in services.items():
                if not isinstance(config, dict):
                    continue
                for rule in rules:
                    try:
                        findings = list(rule.check(name, config, mutated, lines))
                    except Exception:  # noqa: BLE001 - a mutation can break a rule
                        continue
                    for finding in findings:
                        for label, body, spans in (
                            ("message", finding.message, finding.message_spans),
                            ("fix", finding.fix or "", finding.fix_spans),
                        ):
                            assert "\\ue000" not in body, "a value was marked twice"
                            if _outside_marks(body, spans):
                                unmarked.append(
                                    f"{finding.rule_id} {label} at {path}: {body!r}"
                                )
    assert unmarked == []


# --- a marker supplied through a .env never reaches any output ---------------


def _raw_document(fixture: Path) -> Any:
    try:
        return yaml.safe_load(fixture.read_text(encoding="utf-8"))
    except yaml.YAMLError:
        return None


def _run(
    args: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> str:
    monkeypatch.setenv("NO_COLOR", "1")
    capsys.readouterr()
    with pytest.raises(SystemExit):
        cli.main(args)
    captured = capsys.readouterr()
    return captured.out + captured.err


def _leaks(output: str, marker: str) -> bool:
    """Whether ``marker`` is in ``output`` under any escaping or case."""
    plain = marker.replace("\\", "").lower()
    return plain in output.replace("\\", "").lower()


def _distinct(strings: list[tuple[tuple[Any, ...], str]]) -> list[tuple[Any, ...]]:
    """One path per distinct (field, text) pair.

    A fixture repeats the same value in the same field across many services,
    and each repeat is the same run. The service name and list positions are
    left out of the key, so `image: nginx:1.27` is swept once per fixture.
    """
    seen: set[tuple[tuple[str, ...], str]] = set()
    paths = []
    for path, text in strings:
        field = tuple(step for step in path[2:] if isinstance(step, str))
        if (field, text) not in seen:
            seen.add((field, text))
            paths.append(path)
    return paths


def _sweep(
    fixture: Path,
    marker: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    *,
    every_spelling: bool,
) -> list[str]:
    """Supply ``marker`` through a `.env` to each string of ``fixture``.

    With ``every_spelling`` each string is tried with the marker in every
    position, in JSON, and with one position in text and SARIF: a finding's
    message is built once and printed three ways, so the positions matter to
    the rules and the formats to the printers. Without it, one position in
    all three formats.
    """
    document = _raw_document(fixture)
    if not isinstance(document, dict):
        return []
    monkeypatch.chdir(tmp_path)
    compose = tmp_path / "compose.yml"
    leaked: list[str] = []
    strings = dict(_strings(document))
    for path in _distinct(list(strings.items())):
        spellings = _spellings(strings[path], marker)
        mutated = copy.deepcopy(document)
        _put(mutated, path, "${CL_CANARY}")
        compose.write_text(yaml.safe_dump(mutated), encoding="utf-8")
        runs = [(spellings[0], fmt) for fmt in ("json", "text", "sarif")]
        if every_spelling:
            runs += [(spelling, "json") for spelling in spellings[1:]]
        for spelling, fmt in runs:
            quoted = "'" + spelling.replace("'", "\\'") + "'"
            (tmp_path / ENV_NAME).write_text(f"CL_CANARY={quoted}\n", encoding="utf-8")
            output = _run(["--format", fmt, "compose.yml"], monkeypatch, capsys)
            if _leaks(output, marker):
                leaked.append(f"{fmt} at {path} as {spelling!r}")
    return leaked


@pytest.mark.parametrize("marker", [CANARY, HOSTILE], ids=["plain", "hostile"])
@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda p: p.name)
def test_no_env_value_reaches_any_output(
    fixture: Path,
    marker: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    leaked = _sweep(
        fixture, marker, tmp_path, monkeypatch, capsys, every_spelling=marker == CANARY
    )
    assert leaked == []


def test_the_sweep_sees_a_value_when_nothing_quotes_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The control: with quoting switched off, the same sweep reports leaks."""

    def unquoted(findings: list[Any], *_args: Any, **_kwargs: Any) -> list[Any]:
        return findings

    monkeypatch.setattr(engine, "_quote_references", unquoted)
    monkeypatch.setattr(_env_quote, "quote", lambda text: text)
    fixture = REPO_ROOT / "tests" / "compose_files" / "insecure_socket.yml"
    assert _sweep(fixture, CANARY, tmp_path, monkeypatch, capsys, every_spelling=True)
