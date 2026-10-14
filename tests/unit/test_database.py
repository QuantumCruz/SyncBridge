
"""Persistence and safety tests for SyncBridge's SQLite snapshot database."""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import closing
from datetime import timezone

import pytest

from syncbridge.core.reconciler import ChangeType, FileReconciler
from syncbridge.core.scanner import FileRecord, FileScanner, ScanError
from syncbridge.storage.database import SnapshotDatabase


def test_database_creates_missing_parent_directories(tmp_path):
    path = tmp_path / "internal" / "state" / "snapshots.sqlite3"
    database = SnapshotDatabase(path)

    assert path.is_file()
    assert database.list_snapshots() == ()


def test_missing_snapshot_is_distinct_from_empty_snapshot(tmp_path):
    database = SnapshotDatabase(tmp_path / "index.sqlite3")
    assert database.load_snapshot(tmp_path / "folder") is None

    folder = tmp_path / "folder"
    folder.mkdir()
    info = database.save_snapshot(FileScanner(folder).scan())

    assert info.file_count == 0
    stored = database.load_snapshot(folder)
    assert stored is not None
    assert stored.complete
    assert stored.files == {}


def test_saves_and_restores_nested_file_records(tmp_path):
    folder = tmp_path / "folder"
    (folder / "nested").mkdir(parents=True)
    (folder / "nested" / "report.txt").write_bytes(b"report")
    (folder / "empty.txt").write_bytes(b"")

    original = FileScanner(folder).scan()
    database = SnapshotDatabase(tmp_path / ".syncbridge" / "state.db")

    info = database.save_snapshot(original)
    restored = database.load_snapshot(folder)

    assert restored is not None
    assert restored.root == original.root
    assert restored.files == original.files
    assert restored.errors == []
    assert info.file_count == 2
    assert info.root == original.root
    assert info.saved_at.tzinfo == timezone.utc


def test_data_survives_creating_another_database_instance(tmp_path):
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "resume.txt").write_bytes(b"saved")
    path = tmp_path / "state.db"

    first = SnapshotDatabase(path)
    original = FileScanner(folder).scan()
    first.save_snapshot(original)

    second = SnapshotDatabase(path)
    restored = second.load_snapshot(folder)
    assert restored is not None
    assert restored.files == original.files


def test_saved_snapshot_supports_reconciliation_after_restart(tmp_path):
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "modified.txt").write_bytes(b"old")
    (folder / "deleted.txt").write_bytes(b"remove")
    (folder / "untouched.txt").write_bytes(b"same")
    path = tmp_path / "db.sqlite3"

    SnapshotDatabase(path).save_snapshot(FileScanner(folder).scan())

    (folder / "modified.txt").write_bytes(b"new value")
    (folder / "deleted.txt").unlink()
    (folder / "added.txt").write_bytes(b"new")

    last_saved = SnapshotDatabase(path).load_snapshot(folder)
    current = FileScanner(folder).scan()
    changes = FileReconciler.compare(last_saved, current)

    assert [(change.path, change.kind) for change in changes.changes] == [
        ("added.txt", ChangeType.ADDED),
        ("deleted.txt", ChangeType.DELETED),
        ("modified.txt", ChangeType.MODIFIED),
    ]
    assert changes.unchanged_count == 1


def test_new_snapshot_replaces_stale_entries(tmp_path):
    folder = tmp_path / "docs"
    folder.mkdir()
    keep = folder / "keep.txt"
    remove = folder / "remove.txt"
    keep.write_bytes(b"original")
    remove.write_bytes(b"temporary")
    database = SnapshotDatabase(tmp_path / "state.db")

    database.save_snapshot(FileScanner(folder).scan())
    keep.write_bytes(b"updated")
    remove.unlink()
    (folder / "added.txt").write_bytes(b"new")

    latest = FileScanner(folder).scan()
    database.save_snapshot(latest)

    restored = database.load_snapshot(folder)
    assert restored.files == latest.files
    assert set(restored.files) == {"keep.txt", "added.txt"}


def test_rejected_incomplete_scan_preserves_committed_snapshot(tmp_path):
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "important.txt").write_bytes(b"important")
    database = SnapshotDatabase(tmp_path / "state.db")
    initial = FileScanner(folder).scan()
    database.save_snapshot(initial)

    (folder / "important.txt").unlink()
    incomplete = FileScanner(folder).scan()
    incomplete.errors.append(ScanError("important.txt", "Permission denied"))

    with pytest.raises(ValueError, match="incomplete"):
        database.save_snapshot(incomplete)

    assert database.load_snapshot(folder).files == initial.files


def test_database_write_failure_rolls_back_entire_snapshot(tmp_path):
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "existing.txt").write_bytes(b"stored")
    db_path = tmp_path / "state.db"
    database = SnapshotDatabase(db_path)
    initial = FileScanner(folder).scan()
    database.save_snapshot(initial)

    (folder / "existing.txt").unlink()
    (folder / "blocked.txt").write_bytes(b"new")
    with closing(sqlite3.connect(db_path)) as connection:
        connection.executescript(
            """
            CREATE TRIGGER prevent_blocked_file BEFORE INSERT ON snapshot_files
            WHEN NEW.relative_path = 'blocked.txt'
            BEGIN
                SELECT RAISE(ABORT, 'write blocked for test');
            END;
            """
        )

    with pytest.raises(sqlite3.IntegrityError, match="write blocked"):
        database.save_snapshot(FileScanner(folder).scan())

    assert database.load_snapshot(folder).files == initial.files


def test_multiple_folders_do_not_overwrite_each_other(tmp_path):
    first_folder = tmp_path / "first"
    second_folder = tmp_path / "second"
    first_folder.mkdir()
    second_folder.mkdir()
    (first_folder / "a.txt").write_bytes(b"a")
    (second_folder / "b.txt").write_bytes(b"b")
    database = SnapshotDatabase(tmp_path / "state.db")

    first_scan = FileScanner(first_folder).scan()
    second_scan = FileScanner(second_folder).scan()
    database.save_snapshot(first_scan)
    database.save_snapshot(second_scan)

    assert database.load_snapshot(first_folder).files == first_scan.files
    assert database.load_snapshot(second_folder).files == second_scan.files


def test_list_snapshots_reports_metadata_for_each_folder(tmp_path):
    first_folder = tmp_path / "a"
    second_folder = tmp_path / "b"
    first_folder.mkdir()
    second_folder.mkdir()
    (first_folder / "content.txt").write_bytes(b"data")
    database = SnapshotDatabase(tmp_path / "state.db")

    database.save_snapshot(FileScanner(second_folder).scan())
    database.save_snapshot(FileScanner(first_folder).scan())
    infos = database.list_snapshots()

    assert [info.root for info in infos] == [first_folder, second_folder]
    assert [info.file_count for info in infos] == [1, 0]
    assert all(info.saved_at.tzinfo == timezone.utc for info in infos)


def test_invalid_hash_rejected_without_overwriting_snapshot(tmp_path):
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "correct.txt").write_bytes(b"correct")
    database = SnapshotDatabase(tmp_path / "state.db")
    good_scan = FileScanner(folder).scan()
    database.save_snapshot(good_scan)

    changed = FileScanner(folder).scan()
    changed.files["correct.txt"] = FileRecord(
        relative_path="correct.txt",
        size=7,
        modified_ns=123456,
        sha256="not-a-valid-hash",
    )

    with pytest.raises(ValueError, match="SHA-256"):
        database.save_snapshot(changed)

    assert database.load_snapshot(folder).files == good_scan.files


def test_snapshot_storage_is_excluded_when_stored_under_sync_folder(tmp_path):
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "notes.txt").write_bytes(b"keep")
    database = SnapshotDatabase(folder / ".syncbridge" / "state.db")
    database.save_snapshot(FileScanner(folder).scan())

    later = FileScanner(folder).scan()
    assert later.complete
    assert set(later.files) == {"notes.txt"}


def test_saved_files_are_not_modified_by_database_operations(tmp_path):
    folder = tmp_path / "docs"
    folder.mkdir()
    original_bytes = b"don't change my file"
    file = folder / "notes.txt"
    file.write_bytes(original_bytes)
    original_digest = hashlib.sha256(original_bytes).hexdigest()
    database = SnapshotDatabase(tmp_path / "state.db")

    database.save_snapshot(FileScanner(folder).scan())
    loaded = database.load_snapshot(folder)

    assert file.read_bytes() == original_bytes
    assert loaded.files["notes.txt"].sha256 == original_digest
