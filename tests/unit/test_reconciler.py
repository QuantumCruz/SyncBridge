
"""Unit tests for SyncBridge's read-only file reconciliation."""

from __future__ import annotations

import os

import pytest

from syncbridge.core.reconciler import (
    ChangeType,
    FileReconciler,
    IncompleteScanError,
)
from syncbridge.core.scanner import FileScanner, ScanError


def test_two_empty_scans_have_no_changes(tmp_path):
    scanner = FileScanner(tmp_path)
    result = FileReconciler.compare(scanner.scan(), scanner.scan())

    assert not result.has_changes
    assert result.changes == ()
    assert result.unchanged_count == 0
    assert result.previous_count == 0
    assert result.current_count == 0


def test_new_files_are_added(tmp_path):
    scanner = FileScanner(tmp_path)
    previous = scanner.scan()

    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "notes.txt").write_bytes(b"hello")
    (tmp_path / "empty.txt").write_bytes(b"")

    result = FileReconciler.compare(previous, scanner.scan())

    assert [change.path for change in result.added] == [
        "docs/notes.txt",
        "empty.txt",
    ]
    assert all(
        change.kind is ChangeType.ADDED
        for change in result.changes
    )
    assert all(
        change.before is None and change.after is not None
        for change in result.added
    )
    assert result.previous_count == 0
    assert result.current_count == 2


def test_modified_file_has_before_and_after_hash(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_bytes(b"before")

    scanner = FileScanner(tmp_path)
    previous = scanner.scan()

    path.write_bytes(b"after and longer")

    result = FileReconciler.compare(previous, scanner.scan())

    assert len(result.modified) == 1
    change = result.modified[0]
    assert change.path == "notes.txt"
    assert change.before.sha256 != change.after.sha256
    assert not result.added
    assert not result.deleted


def test_same_size_content_change_is_modified_even_if_mtime_restored(tmp_path):
    path = tmp_path / "same.txt"
    path.write_bytes(b"AAAA")

    scanner = FileScanner(tmp_path)
    previous = scanner.scan()
    original_stat = path.stat()

    path.write_bytes(b"BBBB")
    os.utime(
        path,
        ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
    )

    result = FileReconciler.compare(previous, scanner.scan())

    assert len(result.modified) == 1
    assert result.modified[0].before.size == result.modified[0].after.size


def test_deleted_file_has_before_record_only(tmp_path):
    path = tmp_path / "remove.txt"
    path.write_bytes(b"remove")

    scanner = FileScanner(tmp_path)
    previous = scanner.scan()

    path.unlink()

    result = FileReconciler.compare(previous, scanner.scan())

    assert len(result.deleted) == 1
    assert result.deleted[0].before is not None
    assert result.deleted[0].after is None
    assert result.current_count == 0


def test_unchanged_file_is_not_flagged_by_timestamp_only(tmp_path):
    path = tmp_path / "keep.txt"
    path.write_bytes(b"unchanged")

    scanner = FileScanner(tmp_path)
    previous = scanner.scan()

    file_stat = path.stat()
    os.utime(
        path,
        ns=(
            file_stat.st_atime_ns,
            file_stat.st_mtime_ns + 2_000_000_000,
        ),
    )

    result = FileReconciler.compare(previous, scanner.scan())

    assert not result.has_changes
    assert result.unchanged_count == 1


def test_combined_changes_are_sorted_and_counted(tmp_path):
    scanner = FileScanner(tmp_path)

    (tmp_path / "z_unmodified.txt").write_bytes(b"same")
    (tmp_path / "b_delete.txt").write_bytes(b"delete")
    (tmp_path / "a_modify.txt").write_bytes(b"old")

    previous = scanner.scan()

    (tmp_path / "b_delete.txt").unlink()
    (tmp_path / "a_modify.txt").write_bytes(b"different")
    (tmp_path / "c_add.txt").write_bytes(b"new")

    result = FileReconciler.compare(previous, scanner.scan())

    assert [
        (change.path, change.kind)
        for change in result.changes
    ] == [
        ("a_modify.txt", ChangeType.MODIFIED),
        ("b_delete.txt", ChangeType.DELETED),
        ("c_add.txt", ChangeType.ADDED),
    ]

    assert result.unchanged_count == 1
    assert result.previous_count == 3
    assert result.current_count == 3


def test_rename_is_added_plus_deleted_for_now(tmp_path):
    old = tmp_path / "old.txt"
    old.write_bytes(b"data")

    scanner = FileScanner(tmp_path)
    previous = scanner.scan()

    old.rename(tmp_path / "new.txt")

    result = FileReconciler.compare(previous, scanner.scan())

    assert [change.path for change in result.added] == ["new.txt"]
    assert [change.path for change in result.deleted] == ["old.txt"]


def test_different_roots_are_rejected(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()

    with pytest.raises(ValueError, match="different folders"):
        FileReconciler.compare(
            FileScanner(first).scan(),
            FileScanner(second).scan(),
        )


@pytest.mark.parametrize(
    "which_is_incomplete",
    ["previous", "current"],
)
def test_incomplete_scans_cannot_produce_deletions(
    tmp_path,
    which_is_incomplete,
):
    scanner = FileScanner(tmp_path)
    (tmp_path / "important.txt").write_bytes(b"important")

    previous = scanner.scan()

    (tmp_path / "important.txt").unlink()
    current = scanner.scan()

    error = ScanError("important.txt", "Access denied")

    if which_is_incomplete == "previous":
        previous.errors.append(error)
    else:
        current.errors.append(error)

    with pytest.raises(
        IncompleteScanError,
        match="incomplete scans",
    ):
        FileReconciler.compare(previous, current)


def test_inputs_are_not_mutated(tmp_path):
    scanner = FileScanner(tmp_path)
    previous = scanner.scan()

    (tmp_path / "new.txt").write_bytes(b"content")
    current = scanner.scan()

    original_previous = dict(previous.files)
    original_current = dict(current.files)

    result = FileReconciler.compare(previous, current)

    assert previous.files == original_previous
    assert current.files == original_current
    assert isinstance(result.changes, tuple)
    assert result.has_changes
