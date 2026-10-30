
"""Build and audit the Windows-first SyncBridge Qt desktop.

Normal user build (no console):
    python scripts/build_windows.py
Diagnostic build (visible console):
    python scripts/build_windows.py --console

A successful PyInstaller return code is not sufficient. The generated EXE
must also have the expected Windows subsystem and contain no private profiles.
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
AUDIT = PROJECT / "scripts" / "windows_release_audit.py"
DIST = PROJECT / "dist"
WORK = PROJECT / "build" / "windows-pyinstaller"
EXE = DIST / "SyncBridge" / "SyncBridge.exe"


class BuildError(RuntimeError):
    """A prerequisite for a reliable Windows application build is missing."""


def _preflight() -> None:
    if os.name != "nt":
        raise BuildError("Build the Windows executable on Windows 10 or 11.")
    if sys.version_info < (3, 10):
        raise BuildError("SyncBridge needs Python 3.10 or newer to build.")

    required = (
        ENTRY,
        AUDIT,
        SOURCE / "syncbridge" / "ui" / "desktop_controller.py",
        SOURCE / "syncbridge" / "ui" / "qt_onboarding.py",
        SOURCE / "syncbridge" / "ui" / "qt_clean_start_window.py",
        SOURCE / "syncbridge" / "ui" / "qt_crash_recovery_window.py",
        SOURCE / "syncbridge" / "storage" / "folder_change_recovery.py",
        SOURCE / "syncbridge" / "ui" / "qt_local_refresh.py",
    )
    missing = [
        str(path.relative_to(PROJECT))
        for path in required
        if not path.is_file()
    ]
    if missing:
        raise BuildError("Missing SyncBridge source file(s): " + ", ".join(missing))

    for package in ("PyInstaller", "PySide6", "cryptography"):
        if importlib.util.find_spec(package) is None:
            raise BuildError(
                f"{package} is not installed. "
                'Run: python -m pip install -e ".[dev,build]"'
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
    parser = argparse.ArgumentParser(description="Build the SyncBridge Windows app")
    parser.add_argument(
        "--console", action="store_true",
        help="Keep a console window for diagnosing startup problems.",
    )
    args = parser.parse_args(argv)

    try:
        _preflight()
    except BuildError as exc:
        parser.exit(2, f"Build preparation failed: {exc}\n")

    (WORK / "spec").mkdir(parents=True, exist_ok=True)
    (WORK / "work").mkdir(parents=True, exist_ok=True)

    print("Building the SyncBridge PySide6 desktop.", flush=True)
    print(f"Python: {sys.executable}", flush=True)
    print(f"Entry:  {ENTRY}", flush=True)
    print(f"Output: {EXE}", flush=True)
    print(
        "Mode: diagnostic console" if args.console else "Mode: windowed desktop",
        flush=True,
    )

    try:
        build = subprocess.run(_command(console=args.console), cwd=PROJECT, check=False)
    except OSError as exc:
        print(f"Could not run PyInstaller: {exc}", file=sys.stderr)
        return 1

    if build.returncode != 0:
        print(
            f"PyInstaller failed (exit {build.returncode}).",
            file=sys.stderr,
        )
        return build.returncode

    verification = [
        sys.executable, str(AUDIT),
        "--dist", str(EXE.parent),
        "--project-root", str(PROJECT),
    ]
    if args.console:
        verification.append("--console")

    try:
        audited = subprocess.run(verification, cwd=PROJECT, check=False)
    except OSError as exc:
        print(f"Could not audit packaged EXE: {exc}", file=sys.stderr)
        return 1
    if audited.returncode != 0:
        print(
            "Build was produced but FAILED release audit. Do not share it.",
            file=sys.stderr,
        )
        return 1

    print("\nWindows build and offline audit complete.", flush=True)
    print(f"Run: {EXE}", flush=True)
    print("Distribute the whole dist\\SyncBridge folder, not only SyncBridge.exe.")
    print(
        "Do not publish until packaged transfer tests and real two-computer "
        "reconnect testing have also passed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
