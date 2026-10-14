
"""Unit tests for SyncBridge's read-only filesystem scanner."""

from __future__ import annotations

import hashlib
import os
from types import SimpleNamespace

import pytest

from syncbridge.core.scanner import FileScanner


def test_scans_nested_files_and_hashes_contents(tmp_path):
    folder = tmp_path / "projects" / "work"
    folder.mkdir(parents=True)
    data = b"SyncBridge works!\n"
    (folder / "notes.txt").write_bytes(data)
    (tmp_path / "empty.txt").write_bytes(b"")

    result = FileScanner(tmp_path).scan()

    assert result.complete
    assert set(result.files) == {"projects/work/notes.txt", "empty.txt"}
    record = result.files["projects/work/notes.txt"]
    assert record.relative_path == "projects/work/notes.txt"
    assert record.size == len(data)
    assert record.sha256 == hashlib.sha256(data).hexdigest()
    assert result.files["empty.txt"].sha256 == hashlib.sha256(b"").hexdigest()
    assert (folder / "notes.txt").read_bytes() == data


def test_default_exclusions(tmp_path):
    for name in (".git", ".venv", "__pycache__", ".syncbridge"):
        folder = tmp_path / name
        folder.mkdir()
        (folder / "ignored.bin").write_bytes(b"ignore me")
    (tmp_path / "keep.txt").write_text("keep", encoding="utf-8")

    result = FileScanner(tmp_path).scan()

    assert result.complete
    assert set(result.files) == {"keep.txt"}


def test_custom_exclusion_patterns(tmp_path):
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "old.txt").write_text("omit", encoding="utf-8")
    (tmp_path / "memo.tmp").write_text("omit", encoding="utf-8")
    (tmp_path / "memo.txt").write_text("keep", encoding="utf-8")

    result = FileScanner(tmp_path, excludes=("logs", "*.tmp")).scan()

    assert result.complete
    assert set(result.files) == {"memo.txt"}


def test_scanning_detects_content_changes_without_storing_state(tmp_path):
    file = tmp_path / "file.txt"
    file.write_text("first", encoding="utf-8")
    scanner = FileScanner(tmp_path)
    first = scanner.scan()

    file.write_text("a different value", encoding="utf-8")
    second = scanner.scan()

    assert first.complete and second.complete
    assert first.files["file.txt"].sha256 != second.files["file.txt"].sha256

    file.unlink()
    third = scanner.scan()
    assert third.complete
    assert not third.files
    assert "file.txt" in first.files


def test_missing_root_and_file_root_raise(tmp_path):
    with pytest.raises(FileNotFoundError):
        FileScanner(tmp_path / "missing")

    file = tmp_path / "not-a-folder.txt"
    file.write_bytes(b"text")
    with pytest.raises(NotADirectoryError):
        FileScanner(file)


def test_hash_failure_is_reported_not_silent(tmp_path, monkeypatch):
    (tmp_path / "locked.txt").write_bytes(b"private")

    def refuse(*args, **kwargs):
        raise PermissionError("File is locked")

    monkeypatch.setattr(FileScanner, "_hash_file", refuse)
    result = FileScanner(tmp_path).scan()

    assert not result.complete
    assert not result.files
    assert len(result.errors) == 1
    assert result.errors[0].relative_path == "locked.txt"
    assert "locked" in result.errors[0].message


def test_symlink_is_not_followed(tmp_path):
    target = tmp_path / "source.txt"
    target.write_text("source", encoding="utf-8")
    link = tmp_path / "link.txt"

    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("Symbolic links are not available")

    result = FileScanner(tmp_path).scan()

    assert result.complete
    assert set(result.files) == {"source.txt"}


def test_windows_scandir_stat_difference_is_accepted():
    # Simulate Windows Python 3.12 directory-entry metadata.
    directory_stat = SimpleNamespace(
        st_size=32,
        st_mtime_ns=123_000_000,
        st_ctime_ns=0,
        st_dev=0,
        st_ino=0,
    )

    opened_stat = SimpleNamespace(
        st_size=32,
        st_mtime_ns=123_000_000,
        st_ctime_ns=999_000_000,
        st_dev=18,
        st_ino=450,
    )

    assert FileScanner._same_file_state(directory_stat, opened_stat)


def test_file_state_comparison_rejects_real_changes():
    before = SimpleNamespace(
        st_size=10,
        st_mtime_ns=1000,
        st_dev=5,
        st_ino=50,
    )

    different_size = SimpleNamespace(
        st_size=11,
        st_mtime_ns=1000,
        st_dev=5,
        st_ino=50,
    )

    different_time = SimpleNamespace(
        st_size=10,
        st_mtime_ns=2000,
        st_dev=5,
        st_ino=50,
    )

    different_file = SimpleNamespace(
        st_size=10,
        st_mtime_ns=1000,
        st_dev=5,
        st_ino=51,
    )

    assert not FileScanner._same_file_state(before, different_size)
    assert not FileScanner._same_file_state(before, different_time)
    assert not FileScanner._same_file_state(before, different_file)
