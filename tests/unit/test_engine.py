
"""Tests for the integrated SyncBridge core engine."""

from __future__ import annotations

import threading
import time

import pytest

from syncbridge.core.engine import SyncEngine
from syncbridge.core.watcher import FileWatcher
from syncbridge.core.scanner import FileScanner, ScanError
from syncbridge.core.reconciler import IncompleteScanError


def test_initial_scan_creates_baseline_no_notification(tmp_path):
    (tmp_path / "existing.txt").write_bytes(b"x")

    events = []
    engine = SyncEngine(tmp_path, events.append)

    assert engine.check_once() is None
    assert events == []

    saved = engine.database.load_snapshot(tmp_path)

    assert set(saved.files) == {"existing.txt"}
    assert not any(
        ".syncbridge" in path
        for path in FileScanner(tmp_path).scan().files
    )


def test_followup_changes_are_stored_and_reported(tmp_path):
    events = []
    engine = SyncEngine(tmp_path, events.append)

    engine.check_once()

    file = tmp_path / "a.txt"
    file.write_bytes(b"first")

    result = engine.check_once()

    assert len(result.added) == 1
    assert events == [result]
    assert set(engine.database.load_snapshot(tmp_path).files) == {"a.txt"}
    assert not engine.check_once().has_changes

    file.write_bytes(b"second")
    assert len(engine.check_once().modified) == 1

    file.unlink()
    assert len(engine.check_once().deleted) == 1


def test_changes_while_offline_recovered_on_next_instance(tmp_path):
    engine = SyncEngine(tmp_path, lambda diff: None)
    engine.check_once()

    (tmp_path / "offline.txt").write_bytes(b"offline")

    events = []
    restarted = SyncEngine(tmp_path, events.append)

    result = restarted.check_once()

    assert [change.path for change in result.added] == [
        "offline.txt"
    ]
    assert len(events) == 1


def test_failed_observer_does_not_save_state(tmp_path):
    calls = []

    def unreliable(diff):
        calls.append(diff)

        if len(calls) == 1:
            raise RuntimeError("failure")

    engine = SyncEngine(tmp_path, unreliable)
    engine.check_once()

    (tmp_path / "new.txt").write_bytes(b"data")

    with pytest.raises(RuntimeError, match="failure"):
        engine.check_once()

    assert not engine.database.load_snapshot(tmp_path).files
    assert len(engine.check_once().added) == 1
    assert len(calls) == 2


def test_database_failure_does_not_lose_change(tmp_path, monkeypatch):
    events = []
    engine = SyncEngine(tmp_path, events.append)
    engine.check_once()

    (tmp_path / "new.txt").write_bytes(b"data")

    original_save = engine.database.save_snapshot
    attempts = [0]

    def failing_save(scan):
        if attempts[0] == 0:
            attempts[0] += 1
            raise OSError("disk full")

        return original_save(scan)

    monkeypatch.setattr(
        engine.database,
        "save_snapshot",
        failing_save,
    )

    with pytest.raises(OSError, match="disk full"):
        engine.check_once()

    assert not engine.database.load_snapshot(tmp_path).files

    engine.check_once()
    assert len(events) == 2


def test_incomplete_scan_preserves_db(tmp_path, monkeypatch):
    important = tmp_path / "important.txt"
    important.write_bytes(b"important")

    engine = SyncEngine(tmp_path, lambda diff: None)
    engine.check_once()

    previous = engine.database.load_snapshot(tmp_path).files.copy()
    important.unlink()

    original_scan = engine._scanner.scan

    def incomplete_scan():
        current = original_scan()
        current.errors.append(
            ScanError("important.txt", "access denied")
        )
        return current

    monkeypatch.setattr(
        engine._scanner,
        "scan",
        incomplete_scan,
    )

    with pytest.raises(IncompleteScanError, match="Scan incomplete"):
        engine.check_once()

    assert engine.database.load_snapshot(tmp_path).files == previous


def test_restarts_own_watcher_and_detects_changes(tmp_path):
    notification = threading.Event()
    events = []

    def on_change(diff):
        events.append(diff)
        notification.set()

    engine = SyncEngine(
        tmp_path,
        on_change,
        interval=0.02,
    )

    engine.start()
    engine.start()

    try:
        (tmp_path / "new.txt").write_bytes(b"one")
        assert notification.wait(timeout=3)

        notification.clear()

        engine.stop()
        assert not engine.is_running

        engine.start()

        (tmp_path / "second.txt").write_bytes(b"two")
        assert notification.wait(timeout=3)

    finally:
        engine.stop()

    assert len(events) >= 2
    assert len(engine.database.load_snapshot(tmp_path).files) == 2


def test_engine_start_detects_offline_changes(tmp_path):
    initial_engine = SyncEngine(
        tmp_path,
        lambda diff: None,
    )
    initial_engine.check_once()

    (tmp_path / "offline.txt").write_bytes(b"x")

    notification = threading.Event()
    events = []

    def on_change(diff):
        events.append(diff)
        notification.set()

    engine = SyncEngine(
        tmp_path,
        on_change,
        interval=0.02,
    )

    engine.start()

    try:
        assert notification.is_set()
        assert [
            change.path for change in events[0].added
        ] == ["offline.txt"]
    finally:
        engine.stop()


def test_watchers_accept_handed_off_baseline(tmp_path):
    previous = FileScanner(tmp_path).scan()

    (tmp_path / "new.txt").write_bytes(b"data")

    events = []
    watcher = FileWatcher(
        tmp_path,
        events.append,
        initial_scan=previous,
    )

    result = watcher.poll_once()

    assert len(result.added) == 1
    assert events == [result]


def test_initial_scan_validation(tmp_path):
    initial = FileScanner(tmp_path).scan()
    initial.errors.append(ScanError(".", "bad"))

    with pytest.raises(ValueError, match="complete"):
        FileWatcher(
            tmp_path,
            lambda diff: None,
            initial_scan=initial,
        )

    initial.errors.clear()

    other = tmp_path / "else"
    other.mkdir()

    with pytest.raises(ValueError, match="watched folder"):
        FileWatcher(
            other,
            lambda diff: None,
            initial_scan=initial,
        )


def test_external_database_path_allowed_and_unsafe_internal_path_rejected(
    tmp_path,
):
    folder = tmp_path / "folder"
    folder.mkdir()

    with pytest.raises(ValueError, match=".syncbridge"):
        SyncEngine(
            folder,
            lambda diff: None,
            database_path=folder / "db.sqlite",
        )

    engine = SyncEngine(
        folder,
        lambda diff: None,
        database_path=tmp_path / "outside.db",
    )

    assert engine.database.path == tmp_path / "outside.db"


def test_custom_exclusions_persist_across_watcher(tmp_path):
    events = []

    engine = SyncEngine(
        tmp_path,
        events.append,
        interval=0.02,
        excludes=("*.tmp",),
    )

    engine.start()

    try:
        (tmp_path / "ignored.tmp").write_bytes(b"data")
        (tmp_path / "included.txt").write_bytes(b"data")

        deadline = time.monotonic() + 3

        while not events and time.monotonic() < deadline:
            time.sleep(0.01)

        assert len(events) >= 1
        assert list(
            engine.database.load_snapshot(tmp_path).files
        ) == ["included.txt"]

    finally:
        engine.stop()
