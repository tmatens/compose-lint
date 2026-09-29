"""A file name that is not valid UTF-8 is reported, not a crash.

Python carries such a name byte as a lone surrogate (``b"\\xe9"`` becomes
``"\\udce9"``). SARIF percent-encoded the path with a strict UTF-8 encode and
raised, so the run exited 2 through the internal-error backstop with no
results. Text raised the same way wherever stdout encodes strictly, which is
any UTF-8 locale other than C, or ``PYTHONIOENCODING=utf-8``. JSON already
escaped it. All three now report the file and agree on the exit code.
"""

from __future__ import annotations

import io
import json
import os
import sys
from typing import TYPE_CHECKING

import pytest

from compose_lint import cli
from compose_lint._output import sanitize

if TYPE_CHECKING:
    from pathlib import Path

# What Linux's ``os.fsdecode(b"c\xe9.yml")`` gives. Spelled out rather than
# decoded here, because Windows refuses to decode that byte at import time.
NAME = "c\udce9.yml"
DOC = b"services:\n  web:\n    image: nginx:1.27\n    privileged: true\n"


def test_a_lone_surrogate_is_escaped() -> None:
    assert sanitize(NAME) == "c\\udce9.yml"


@pytest.mark.skipif(
    sys.platform != "linux", reason="macOS and Windows refuse a non-UTF-8 name"
)
@pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
def test_every_format_reports_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fmt: str
) -> None:
    monkeypatch.chdir(tmp_path)
    with open(os.fsencode(NAME), "wb") as fh:
        fh.write(DOC)
    # Streams that encode strictly, as a desktop UTF-8 locale's do.
    out = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", errors="strict")
    err = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", errors="strict")
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)

    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "--format", fmt, NAME])

    out.flush()
    buffer = out.buffer
    assert isinstance(buffer, io.BytesIO)
    stdout = buffer.getvalue().decode("utf-8")
    # CL-0002 (privileged) is CRITICAL: the file was graded, not skipped.
    assert exc.value.code == 1
    if fmt == "sarif":
        uris = {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in json.loads(stdout)["runs"][0]["results"]
        }
        # The original byte, percent-encoded: the file that is on disk.
        assert uris == {"c%E9.yml"}
    elif fmt == "text":
        assert "c\\udce9.yml" in stdout
