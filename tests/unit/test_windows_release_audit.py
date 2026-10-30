
"""Portable tests for the Windows packaged-release audit.

Generate minimal synthetic PE files: these are only test fixtures, not runnable
Windows applications. No PyInstaller or Windows environment is required.
"""
from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

from scripts.windows_release_audit import (
    ReleaseAuditError,
    verify_distribution,
)


def _fake_build(tmp_path: Path, subsystem: int = 2) -> Path:
    directory = tmp_path / "dist" / "SyncBridge"
    internal = directory / "_internal"
    internal.mkdir(parents=True)
    (internal / "dependency.bin").write_bytes(b"safe dependency")

    raw = bytearray(1024)
    raw[:2] = b"MZ"
    struct.pack_into("<I", raw, 0x3C, 0x80)
    raw[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", raw, 0x80 + 20, 0xF0)
    struct.pack_into("<H", raw, 0x80 + 24, 0x20B)
    struct.pack_into("<H", raw, 0x80 + 24 + 68, subsystem)
    (directory / "SyncBridge.exe").write_bytes(raw)
    return directory


def test_gui_build_passes_offline_verification(tmp_path):
    directory = _fake_build(tmp_path)
    result = verify_distribution(directory)
    assert result.subsystem == "windowed GUI"
    assert result.checked_files == 2
    assert result.executable_bytes == 1024


def test_debug_console_build_requires_explicit_console_mode(tmp_path):
    directory = _fake_build(tmp_path, subsystem=3)
    with pytest.raises(ReleaseAuditError, match="Expected a windowed GUI"):
        verify_distribution(directory)
    assert verify_distribution(directory, expect_console=True).subsystem == "console"


def test_unknown_pe_subsystem_fails(tmp_path):
    directory = _fake_build(tmp_path, subsystem=9)
    with pytest.raises(ReleaseAuditError, match="unknown"):
        verify_distribution(directory)


def test_missing_bundled_dependencies_fails(tmp_path):
    directory = _fake_build(tmp_path)
    (directory / "_internal" / "dependency.bin").unlink()
    (directory / "_internal").rmdir()
    with pytest.raises(ReleaseAuditError, match="_internal"):
        verify_distribution(directory)


def test_private_profile_files_cannot_be_distributed(tmp_path):
    for name in (
        "identity.json",
        "trust.json",
        "settings.json",
        "pending_readiness.json",
        "folder-change-recovery.json",
    ):
        directory = _fake_build(tmp_path / name)
        (directory / "_internal" / name).write_text("private data")
        with pytest.raises(ReleaseAuditError, match="Private SyncBridge"):
            verify_distribution(directory)


def test_bad_executable_header_fails(tmp_path):
    directory = _fake_build(tmp_path)
    (directory / "SyncBridge.exe").write_bytes(b"not an executable")
    with pytest.raises(ReleaseAuditError, match="small"):
        verify_distribution(directory)


def test_stale_sources_fail_before_distribution(tmp_path):
    directory = _fake_build(tmp_path)
    source = tmp_path / "project" / "src" / "syncbridge"
    source.mkdir(parents=True)
    (source / "__init__.py").write_text("")
    entry = tmp_path / "project" / "scripts" / "desktop_qt.py"
    entry.parent.mkdir(parents=True)
    entry.write_text("print('test')")

    when = (directory / "SyncBridge.exe").stat().st_mtime
    os.utime(entry, (when + 20, when + 20))
    with pytest.raises(ReleaseAuditError, match="older than application"):
        verify_distribution(directory, project_root=tmp_path / "project")


def test_current_sources_pass_freshness_check(tmp_path):
    directory = _fake_build(tmp_path)
    source = tmp_path / "project" / "src" / "syncbridge"
    source.mkdir(parents=True)
    (source / "__init__.py").write_text("")
    entry = tmp_path / "project" / "scripts" / "desktop_qt.py"
    entry.parent.mkdir(parents=True)
    entry.write_text("print('test')")

    when = (directory / "SyncBridge.exe").stat().st_mtime
    old = when - 20
    os.utime(entry, (old, old))
    for path in source.rglob("*.py"):
        os.utime(path, (old, old))
    assert (
        verify_distribution(directory, project_root=tmp_path / "project")
        .checked_files == 2
    )
