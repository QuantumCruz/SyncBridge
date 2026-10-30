
"""Offline safety checks for a packaged SyncBridge Windows distribution.

A successful PyInstaller process is not proof that its output is safe to ship.
This module checks the PE subsystem, required onedir layout, source freshness,
and accidental inclusion of private local configuration. It does not run the
application or replace end-to-end UI and two-computer tests.
"""
from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from pathlib import Path

PRIVATE_FILENAMES = frozenset({
    "identity.json",
    "trust.json",
    "settings.json",
    "pending_readiness.json",
    "folder-change-recovery.json",
})
PE_GUI = 2
PE_CONSOLE = 3


class ReleaseAuditError(RuntimeError):
    """An executable must not be distributed in its current state."""


@dataclass(frozen=True)
class ReleaseAuditResult:
    executable: Path
    subsystem: str
    checked_files: int
    executable_bytes: int


def _pe_subsystem(executable: Path) -> int:
    """Read IMAGE_OPTIONAL_HEADER.Subsystem from PE32 or PE32+ safely."""
    try:
        if executable.is_symlink() or not executable.is_file():
            raise ReleaseAuditError("SyncBridge.exe must be a regular file")
        size = executable.stat().st_size
        if size < 512:
            raise ReleaseAuditError("SyncBridge.exe is unexpectedly small")
        with executable.open("rb") as stream:
            header = stream.read(64)
            if len(header) != 64 or header[:2] != b"MZ":
                raise ReleaseAuditError("SyncBridge.exe has no DOS/PE signature")
            offset = struct.unpack_from("<I", header, 0x3C)[0]
            if offset < 64 or offset + 24 + 70 > size:
                raise ReleaseAuditError("SyncBridge.exe has an invalid PE header offset")
            stream.seek(offset)
            signature_and_coff = stream.read(24)
            if len(signature_and_coff) != 24 or signature_and_coff[:4] != b"PE\0\0":
                raise ReleaseAuditError("SyncBridge.exe has no valid PE signature")
            optional_size = struct.unpack_from("<H", signature_and_coff, 20)[0]
            if optional_size < 70 or offset + 24 + optional_size > size:
                raise ReleaseAuditError("SyncBridge.exe has an invalid optional header")
            optional = stream.read(70)
            if struct.unpack_from("<H", optional, 0)[0] not in (0x10B, 0x20B):
                raise ReleaseAuditError("SyncBridge.exe has an unknown PE format")
            return struct.unpack_from("<H", optional, 68)[0]
    except OSError as exc:
        raise ReleaseAuditError(f"Cannot inspect SyncBridge.exe: {exc}") from exc


def verify_distribution(
    directory: Path,
    *,
    expect_console: bool = False,
    project_root: Path | None = None,
) -> ReleaseAuditResult:
    """Verify a complete PyInstaller onedir build without executing it.

    If project_root is supplied, reject EXEs older than any application source.
    This is a final-build check, not a generic antivirus or signing check.
    """
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ReleaseAuditError("The dist/SyncBridge distribution folder is missing")
    internal = directory / "_internal"
    if internal.is_symlink() or not internal.is_dir():
        raise ReleaseAuditError(
            "The _internal dependency folder is missing. "
            "Distribute the entire SyncBridge folder, not just the EXE."
        )
    executable = directory / "SyncBridge.exe"
    subsystem = _pe_subsystem(executable)
    expected = PE_CONSOLE if expect_console else PE_GUI
    if subsystem != expected:
        mode = "console" if expect_console else "windowed GUI"
        actual = {
            PE_CONSOLE: "console",
            PE_GUI: "windowed GUI",
        }.get(subsystem, f"unknown ({subsystem})")
        raise ReleaseAuditError(
            f"Expected a {mode} executable but found {actual}. "
            "Rebuild with python scripts/build_windows.py"
            + (" --console" if expect_console else "")
        )

    checked_files = 0
    private_paths = []
    try:
        for path in directory.rglob("*"):
            if path.is_symlink():
                # An external link could secretly bundle local private data.
                raise ReleaseAuditError(
                    f"Distribution contains a symbolic link: {path.relative_to(directory)}"
                )
            if path.is_file():
                checked_files += 1
                if path.name.lower() in PRIVATE_FILENAMES:
                    private_paths.append(str(path.relative_to(directory)))
    except OSError as exc:
        raise ReleaseAuditError(f"Cannot inspect distribution files: {exc}") from exc

    if private_paths:
        raise ReleaseAuditError(
            "Private SyncBridge profile files found in the distribution: "
            + ", ".join(sorted(private_paths)[:8])
        )
    if checked_files < 2:
        raise ReleaseAuditError("Distribution has no packaged dependency files")

    if project_root is not None:
        root = Path(project_root)
        source_tree = root / "src" / "syncbridge"
        entry = root / "scripts" / "desktop_qt.py"
        if not source_tree.is_dir() or not entry.is_file():
            raise ReleaseAuditError("Application sources are missing from project root")
        sources = [entry, *source_tree.rglob("*.py")]
        newest = max(sources, key=lambda file: file.stat().st_mtime)
        if newest.stat().st_mtime > executable.stat().st_mtime + 2:
            raise ReleaseAuditError(
                "The EXE is older than application source code: "
                + str(newest.relative_to(root))
                + ". Rebuild before distribution."
            )

    return ReleaseAuditResult(
        executable=executable,
        subsystem="console" if expect_console else "windowed GUI",
        checked_files=checked_files,
        executable_bytes=executable.stat().st_size,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit a packaged SyncBridge Windows executable"
    )
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--console", action="store_true")
    parser.add_argument("--project-root", type=Path)
    args = parser.parse_args(argv)
    try:
        report = verify_distribution(
            args.dist,
            expect_console=args.console,
            project_root=args.project_root,
        )
    except ReleaseAuditError as exc:
        print(f"SyncBridge build audit FAILED: {exc}")
        return 1
    print(
        f"SyncBridge build audit PASSED: {report.subsystem}; "
        f"{report.checked_files} packaged files; "
        f"{report.executable_bytes} EXE bytes"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
