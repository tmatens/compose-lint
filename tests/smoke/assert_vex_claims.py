"""Prove the runtime image still matches the OpenVEX base-image statements.

The OpenVEX document declares a set of Debian base-image CVEs ``not_affected``
(#1365). Those statements name no package and no version, because that is the
only form Docker Scout and Trivy both honour without an edit on every base
bump (ADR-012). The cost is that a statement keeps applying after the base
image or compose-lint itself changes, whether or not it is still true. This
script is what stops that: it re-checks, inside the built image, every fact an
impact statement relies on, and fails the Docker smokes when one stops
holding. ``GUARDED`` lists the statements it covers; a unit test keeps that
list equal to the document's non-pip statements.

It first runs compose-lint in this process over its main paths, then inspects
the process and the filesystem:

* which Python modules were loaded, and whether ``pkgutil.get_data`` was called;
* which shared objects are mapped, and what each one imports from libc;
* which files the image ships, and who owns the directories Python searches
  for a source-tree landmark at startup.

Runs inside the image, as its default user, where there is no shell::

    docker run --rm --entrypoint /venv/bin/python3 \\
        -v "$PWD/tests/smoke:/src/smoke:ro" \\
        composelint/compose-lint:<tag> /src/smoke/assert_vex_claims.py

Exits 0 when every fact holds and 1 otherwise, with one ``::error::`` line per
violation naming the CVE statements it falsifies. Shared by the PR Dockerfile
smoke (``ci.yml``) and the release smoke (``release-docker-smoke.yml``).
"""

from __future__ import annotations

import contextlib
import io
import os
import pkgutil
import struct
import sys
import sysconfig
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMPOSE_FILE = HERE / "insecure.yml"

# Every OpenVEX statement this script guards. tests/test_vex_claims.py fails
# when the document gains a non-pip statement that is missing here.
GUARDED = frozenset(
    {
        "CVE-2010-0928",
        "CVE-2010-4756",
        "CVE-2018-5709",
        "CVE-2018-20796",
        "CVE-2019-9192",
        "CVE-2019-1010023",
        "CVE-2021-45346",
        "CVE-2022-0563",
        "CVE-2024-26458",
        "CVE-2024-26461",
        "CVE-2025-70873",
        "CVE-2026-3479",
        "CVE-2026-12003",
    }
)

# The UID the Dockerfile's USER line sets.
IMAGE_UID = 65532

# compose-lint invocations that together cover linting, every output format,
# the fixer's dry run and the rule documentation reader.
RUNS: tuple[tuple[str, ...], ...] = (
    (str(COMPOSE_FILE),),
    ("--format", "json", str(COMPOSE_FILE)),
    ("--format", "sarif", str(COMPOSE_FILE)),
    ("fix", str(COMPOSE_FILE)),
    ("--explain", "CL-0001"),
    ("--version",),
)

# Python modules whose presence after the runs falsifies a statement.
FORBIDDEN_MODULES = {
    "ssl": "CVE-2010-0928",
    "_ssl": "CVE-2010-0928",
    "sqlite3": "CVE-2021-45346",
    "_sqlite3": "CVE-2021-45346",
    "_ctypes": "CVE-2019-1010023",
}

# Shared objects that must never be mapped into a compose-lint process.
FORBIDDEN_LIBRARIES = {
    "libgssapi_krb5": "CVE-2024-26461, CVE-2010-4756",
    "libkrb5": "CVE-2018-20796, CVE-2019-9192",
    "libformw": "CVE-2018-20796, CVE-2019-9192",
    "libtirpc": "CVE-2024-26461",
    "libnsl": "CVE-2024-26461",
    "libsqlite3": "CVE-2021-45346",
    "libssl": "CVE-2010-0928",
}

# libc entry points to the affected code. No mapped object may import them.
FORBIDDEN_IMPORTS = {
    "glob": "CVE-2010-4756",
    "glob64": "CVE-2010-4756",
    "wordexp": "CVE-2010-4756",
    "regcomp": "CVE-2018-20796, CVE-2019-9192",
    "regexec": "CVE-2018-20796, CVE-2019-9192",
    "re_comp": "CVE-2018-20796, CVE-2019-9192",
    "re_exec": "CVE-2018-20796, CVE-2019-9192",
    "rpmatch": "CVE-2018-20796, CVE-2019-9192",
}

# Files whose presence anywhere in the image falsifies a statement. Matched
# on the file name: exactly, or as a prefix where the entry ends in "*".
FORBIDDEN_FILES = {
    "chfn": "CVE-2022-0563",
    "chsh": "CVE-2022-0563",
    "libkadm5*": "CVE-2018-5709",
    "libkdb5*": "CVE-2018-5709",
    "kdb5_util": "CVE-2018-5709",
    "kadmin": "CVE-2018-5709",
    "kadmin.local": "CVE-2018-5709",
    "krb5kdc": "CVE-2018-5709",
    "libgssrpc*": "CVE-2024-26458",
    "sqlite3": "CVE-2025-70873",
    "Setup.local": "CVE-2026-12003",
    "sh": "CVE-2019-1010023",
    "bash": "CVE-2019-1010023",
    "dash": "CVE-2019-1010023",
    "ash": "CVE-2019-1010023",
    "busybox": "CVE-2019-1010023",
}

# Names that only count when the file is executable: a data file that happens
# to be called `sh` or `sqlite3` runs nothing.
EXECUTABLE_ONLY = frozenset({"sh", "bash", "dash", "ash", "busybox", "sqlite3"})

# Walking these would only list kernel interfaces, or this script's own mount.
SKIPPED_ROOTS = ("/proc", "/sys", "/dev", str(HERE))

_SHT_DYNSYM = 11
_SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
_SYMBOL = struct.Struct("<IBBHQQ")


def undefined_dynamic_symbols(data: bytes) -> set[str]:
    """Return the symbols a 64-bit little-endian ELF object imports.

    Raises ``ValueError`` for anything else, so an object this cannot read is
    reported instead of being treated as importing nothing.
    """
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    if data[4] != 2 or data[5] != 1:
        raise ValueError("not a 64-bit little-endian ELF file")
    (shoff,) = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
    if shentsize != _SECTION_HEADER.size or shnum == 0:
        raise ValueError("no readable section headers")
    sections = [
        _SECTION_HEADER.unpack_from(data, shoff + index * shentsize)
        for index in range(shnum)
    ]
    names: set[str] = set()
    found = False
    for section in sections:
        _name, kind, _flags, _addr, offset, size, link, _info, _align, entsize = section
        if kind != _SHT_DYNSYM:
            continue
        found = True
        if entsize != _SYMBOL.size or link >= len(sections):
            raise ValueError("unexpected dynamic symbol table layout")
        strings_offset, strings_size = sections[link][4], sections[link][5]
        strings = data[strings_offset : strings_offset + strings_size]
        for position in range(offset, offset + size, entsize):
            name_index, _sym, _other, section_index, _value, _size = (
                _SYMBOL.unpack_from(data, position)
            )
            if section_index == 0 and name_index:
                end = strings.index(b"\0", name_index)
                names.add(strings[name_index:end].decode("ascii", "replace"))
    if not found:
        raise ValueError("no dynamic symbol table")
    return names


def mapped_files() -> list[Path]:
    """Return every file mapped into this process, from /proc/self/maps."""
    paths: set[str] = set()
    for line in Path("/proc/self/maps").read_text(encoding="utf-8").splitlines():
        fields = line.split(None, 5)
        if len(fields) == 6 and fields[5].startswith("/"):
            paths.add(fields[5].removesuffix(" (deleted)"))
    return sorted(Path(path) for path in paths)


def run_compose_lint(problems: list[str]) -> int:
    """Run compose-lint over RUNS in this process; return get_data's call count."""
    calls = 0
    original = pkgutil.get_data

    def recording_get_data(package: str, resource: str) -> bytes | None:
        nonlocal calls
        calls += 1
        return original(package, resource)

    # Assigned before compose_lint is imported, so `from pkgutil import
    # get_data` there would bind the recorder too.
    pkgutil.get_data = recording_get_data

    from compose_lint.cli import main

    saved_argv = sys.argv
    for argv in RUNS:
        sink = io.StringIO()
        sys.argv = ["compose-lint", *argv]
        code: object = 0
        try:
            with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                main()
        except SystemExit as exc:
            code = exc.code
        finally:
            sys.argv = saved_argv
        # 0 is clean and 1 is findings. Anything else means the path was not
        # exercised, and a fact checked after it would be checked on nothing.
        if code not in (0, 1, None):
            shown = " ".join(argv).replace(str(HERE), ".")
            problems.append(
                f"`compose-lint {shown}` exited {code!r}, so that path was not "
                f"exercised: {sink.getvalue().strip()[:200]}"
            )
    return calls


def check_process(problems: list[str], get_data_calls: int) -> None:
    for module, cves in sorted(FORBIDDEN_MODULES.items()):
        if module in sys.modules:
            problems.append(f"compose-lint loaded the `{module}` module ({cves})")

    if get_data_calls:
        problems.append(
            f"pkgutil.get_data was called {get_data_calls} time(s) (CVE-2026-3479)"
        )

    objects = 0
    for path in mapped_files():
        for library, cves in sorted(FORBIDDEN_LIBRARIES.items()):
            # "libkrb5" must not match on libkrb5support alone: both belong to
            # krb5, and either one being mapped falsifies the same statements.
            if path.name.startswith(library):
                problems.append(f"{path} is mapped into the process ({cves})")
        try:
            data = path.read_bytes()
        except OSError as exc:
            problems.append(f"cannot read mapped file {path}: {exc}")
            continue
        if data[:4] != b"\x7fELF":
            continue
        objects += 1
        try:
            imports = undefined_dynamic_symbols(data)
        except ValueError as exc:
            problems.append(f"cannot read the imports of {path}: {exc}")
            continue
        for symbol in sorted(imports & FORBIDDEN_IMPORTS.keys()):
            problems.append(
                f"{path} imports libc's {symbol}() and is mapped into the "
                f"process ({FORBIDDEN_IMPORTS[symbol]})"
            )
    print(f"{objects} mapped ELF objects checked for libc glob and regex imports")
    if objects == 0:
        problems.append("no mapped ELF object was found, so nothing was checked")


def _forbidden_file(name: str) -> str | None:
    for pattern, cves in FORBIDDEN_FILES.items():
        if pattern.endswith("*"):
            if name.startswith(pattern[:-1]):
                return cves
        elif name == pattern:
            return cves
    return None


def check_filesystem(problems: list[str]) -> None:
    files = 0
    sqlite_libraries = 0
    for directory, subdirs, names in os.walk("/"):
        subdirs[:] = [
            sub for sub in subdirs if os.path.join(directory, sub) not in SKIPPED_ROOTS
        ]
        for name in names:
            files += 1
            path = Path(directory) / name
            cves = _forbidden_file(name)
            if cves is not None and name in EXECUTABLE_ONLY:
                cves = cves if os.access(path, os.X_OK) else None
            if cves is not None:
                problems.append(f"{path} is in the image ({cves})")
            if name == "ldd":
                _check_ldd(path, problems)
            if name.startswith("libsqlite3.so") and not path.is_symlink():
                sqlite_libraries += 1
                try:
                    data = path.read_bytes()
                except OSError as exc:
                    problems.append(f"cannot read {path}: {exc}")
                    continue
                if b"zipfile" in data.lower():
                    problems.append(
                        f"{path} contains the zipfile extension (CVE-2025-70873)"
                    )
    print(f"{files} files walked; {sqlite_libraries} SQLite library file(s) read")
    # A walk that saw almost nothing proves no absence.
    if files < 500:
        problems.append(f"only {files} files were walked, so absences prove nothing")


def _check_ldd(path: Path, problems: list[str]) -> None:
    """ldd must stay a script whose interpreter the image does not ship."""
    try:
        first = path.read_bytes().splitlines()[0]
    except (OSError, IndexError) as exc:
        problems.append(f"cannot read {path}: {exc}")
        return
    if not first.startswith(b"#!"):
        problems.append(f"{path} is not a script any more (CVE-2019-1010023)")
        return
    interpreter = first[2:].split()[0].decode("ascii", "replace")
    if Path(interpreter).exists():
        problems.append(
            f"{path} can run: its interpreter {interpreter} is in the image "
            "(CVE-2019-1010023)"
        )


def check_landmark_directories(problems: list[str]) -> None:
    """The directories Python searches for Modules/Setup.local are root's."""
    uid = os.getuid()
    if uid != IMAGE_UID:
        problems.append(
            f"running as UID {uid}, not the image's default {IMAGE_UID}; run this "
            "check without --user, or with the default (CVE-2026-12003)"
        )
    vpath = sysconfig.get_config_var("VPATH")
    if vpath != "..":
        problems.append(
            f"Python was built with VPATH={vpath!r}, not '..', so the landmark "
            "is no longer looked up in the directories checked here "
            "(CVE-2026-12003)"
        )
    # Relative to the executable as invoked (the venv's) and as resolved.
    executables = {Path(sys.executable), Path(sys.executable).resolve()}
    for directory in sorted({exe.parent.parent for exe in executables}):
        status = directory.stat()
        if status.st_uid != 0 or status.st_mode & 0o022:
            problems.append(
                f"{directory} is owned by UID {status.st_uid} with mode "
                f"{status.st_mode & 0o7777:o}: not root-owned and closed to "
                "others (CVE-2026-12003)"
            )
        if uid != 0 and os.access(directory, os.W_OK):
            problems.append(f"{directory} is writable by UID {uid} (CVE-2026-12003)")
        print(f"{directory}: owner {status.st_uid}, mode {status.st_mode & 0o7777:o}")


def main() -> int:
    problems: list[str] = []

    get_data_calls = run_compose_lint(problems)
    check_process(problems, get_data_calls)
    check_filesystem(problems)
    check_landmark_directories(problems)

    if problems:
        for problem in problems:
            print(f"::error::{problem}")
        return 1

    print(
        f"the image matches all {len(GUARDED)} OpenVEX base-image statements "
        "this check guards"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
