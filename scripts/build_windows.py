
"""Build the real SyncBridge Qt desktop as a standalone Windows folder.

Run from any working directory using the project's Python environment:
    python scripts/build_windows.py

For a diagnostic build that keeps a console window:
    python scripts/build_windows.py --console

This build does not modify user profiles or synchronized folders.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
from pathlib import Path


PROJECT = Path(__file__).resolve().parent.parent
SOURCE = PROJECT / "src"
ENTRY = PROJECT / "scripts" / "desktop_qt.py"
DIST = PROJECT / "dist"
WORK = PROJECT / "build" / "windows-pyinstaller"
EXE = DIST / "SyncBridge" / "SyncBridge.exe"


class BuildError(RuntimeError):
    """A prerequisite for producing the Windows application is missing."""


def _preflight() -> None:
    if os.name != "nt":
        raise BuildError("Build the Windows executable on Windows 10 or 11.")
    if sys.version_info < (3, 10):
        raise BuildError("SyncBridge needs Python 3.10 or newer to build.")

    required = (
        ENTRY,
        SOURCE / "syncbridge" / "ui" / "desktop_controller.py",
        SOURCE / "syncbridge" / "ui" / "qt_onboarding.py",
        SOURCE / "syncbridge" / "ui" / "qt_progress_window.py",
        SOURCE / "syncbridge" / "ui" / "qt_local_refresh.py",
    )
    missing = [
        str(path.relative_to(PROJECT))
        for path in required
        if not path.is_file()
    ]
    if missing:
        raise BuildError(
            "Missing Qt desktop source file(s): " + ", ".join(missing)
        )

    if importlib.util.find_spec("PyInstaller") is None:
        raise BuildError(
            'PyInstaller is not installed. Run: '
            'python -m pip install "pyinstaller>=6,<7"'
        )
    if importlib.util.find_spec("PySide6") is None:
        raise BuildError(
            "PySide6 is missing from this Python environment. Activate the "
            "SyncBridge virtual environment before building."
        )


def _command(*, console: bool) -> list[str]:
    return [
        sys.executable,
        "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onedir",
        "--console" if console else "--windowed",
        "--noupx",
        "--name", "SyncBridge",
        "--paths", str(SOURCE),
        "--distpath", str(DIST),
        "--workpath", str(WORK / "work"),
        "--specpath", str(WORK / "spec"),
        "--exclude-module", "PyQt5",
        "--exclude-module", "PyQt6",
        "--exclude-module", "PySide2",
        str(ENTRY),
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build a standalone Windows distribution "
            "of the SyncBridge Qt desktop."
        )
    )
    parser.add_argument(
        "--console",
        action="store_true",
        help="Keep a console window for diagnosing startup problems.",
    )
    args = parser.parse_args(argv)

    try:
        _preflight()
    except BuildError as exc:
        parser.exit(2, f"Build preparation failed: {exc}\n")

    (WORK / "spec").mkdir(parents=True, exist_ok=True)
    (WORK / "work").mkdir(parents=True, exist_ok=True)

    print(
        "Building the PySide6 SyncBridge desktop "
        "(not the Tkinter prototype).",
        flush=True,
    )
    print(f"Python: {sys.executable}", flush=True)
    print(f"Entry:  {ENTRY}", flush=True)
    print(f"Output: {EXE}", flush=True)

    try:
        completed = subprocess.run(
            _command(console=args.console),
            cwd=PROJECT,
            check=False,
        )
    except OSError as exc:
        print(
            f"Could not start PyInstaller: {exc}",
            file=sys.stderr,
        )
        return 1

    if completed.returncode != 0:
        print(
            f"PyInstaller failed with exit code {completed.returncode}.",
            file=sys.stderr,
        )
        return completed.returncode

    if not EXE.is_file():
        print(
            f"Build ended without creating {EXE}.",
            file=sys.stderr,
        )
        return 1

    print("\nWindows build complete.", flush=True)
    print(f"Run: {EXE}", flush=True)
    print(
        "Distribute the whole dist\\SyncBridge folder, "
        "not only SyncBridge.exe."
    )
    print(
        "This is a build artifact, not a verified public release. "
        "Test first-run pairing, folder setup, sync and crash "
        "recovery on the packaged app."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
