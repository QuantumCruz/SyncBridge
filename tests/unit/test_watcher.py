
"""Tests for SyncBridge's polling-based filesystem watcher."""

from __future__ import annotations

import os
import threading

import pytest

from syncbridge.core.reconciler import ChangeType, IncompleteScanError
from syncbridge.core.scanner import ScanError
from syncbridge.core.watcher import FileWatcher


def test_first_complete_scan_only_establishes_baseline(tmp_path):
    received = []
    (tmp_path / "existing.txt").write_bytes(b"hello")
    watcher = FileWatcher(tmp_path, received.append)

    assert watcher.poll_once() is None
    result = watcher.poll_once()

    assert result is not None
    assert result.changes == ()
    assert result.unchanged_count == 1
    assert received == []


def test_detects_additions_modifications_and_deletions(tmp_path):
    (tmp_path / "edit.txt").write_bytes(b"original")
    (tmp_path / "remove.txt").write_bytes(b"old")

    changes = []
    watcher = FileWatcher(tmp_path, changes.append)
    watcher.poll_once()

    (tmp_path / "edit.txt").write_bytes(b"updated text")
    (tmp_path / "remove.txt").unlink()
    (tmp_path / "new.txt").write_bytes(b"new")

    result = watcher.poll_once()

    assert result is not None
    assert [(change.path, change.kind) for change in result.changes] == [
        ("edit.txt", ChangeType.MODIFIED),
        ("new.txt", ChangeType.ADDED),
        ("remove.txt", ChangeType.DELETED),
    ]
    assert changes == [result]
    assert watcher.poll_once().has_changes is False
    assert len(changes) == 1


def test_timestamp_only_does_not_emit_changes(tmp_path):
    file = tmp_path / "same.txt"
    file.write_bytes(b"same")

    changes = []
    watcher = FileWatcher(tmp_path, changes.append)
    watcher.poll_once()

    before = file.stat()
    os.utime(
        file,
        ns=(
            before.st_atime_ns,
            before.st_mtime_ns + 2_000_000_000,
        ),
    )

    result = watcher.poll_once()

    assert result is not None
    assert not result.has_changes
    assert changes == []


def test_incomplete_scan_preserves_baseline_and_reports_error(
    tmp_path,
    monkeypatch,
):
    important = tmp_path / "important.txt"
    important.write_bytes(b"contents")

    events = []
    errors = []
    watcher = FileWatcher(
        tmp_path,
        events.append,
        on_error=errors.append,
    )
    watcher.poll_once()
    important.unlink()

    true_scan = watcher._scanner.scan

    def incomplete_scan():
        scanned = true_scan()
        scanned.errors.append(
            ScanError("important.txt", "Access denied")
        )
        return scanned

    monkeypatch.setattr(
        watcher._scanner,
        "scan",
        incomplete_scan,
    )

    assert watcher.poll_once() is None
    assert not events
    assert len(errors) == 1
    assert isinstance(errors[0], IncompleteScanError)

    monkeypatch.setattr(
        watcher._scanner,
        "scan",
        true_scan,
    )

    result = watcher.poll_once()

    assert result is not None
    assert [
        (change.path, change.kind)
        for change in result.deleted
    ] == [
        ("important.txt", ChangeType.DELETED)
    ]
    assert events == [result]


def test_initial_incomplete_scan_does_not_set_baseline(
    tmp_path,
    monkeypatch,
):
    events = []
    errors = []

    watcher = FileWatcher(
        tmp_path,
        events.append,
        on_error=errors.append,
    )
    true_scan = watcher._scanner.scan

    def incomplete_scan():
        scanned = true_scan()
        scanned.errors.append(
            ScanError(".", "Access denied")
        )
        return scanned

    monkeypatch.setattr(
        watcher._scanner,
        "scan",
        incomplete_scan,
    )

    assert watcher.poll_once() is None
    assert errors
    assert isinstance(errors[0], IncompleteScanError)

    monkeypatch.setattr(
        watcher._scanner,
        "scan",
        true_scan,
    )

    (tmp_path / "already_there.txt").write_bytes(b"initial")

    assert watcher.poll_once() is None
    assert events == []


def test_failed_change_callback_retries_same_change(tmp_path):
    attempts = []
    errors = []

    def unreliable_callback(diff):
        attempts.append(diff)
        if len(attempts) == 1:
            raise RuntimeError("destination unavailable")

    watcher = FileWatcher(
        tmp_path,
        unreliable_callback,
        on_error=errors.append,
    )

    watcher.poll_once()
    (tmp_path / "new.txt").write_bytes(b"content")

    assert watcher.poll_once() is None
    assert len(errors) == 1
    assert isinstance(errors[0], RuntimeError)

    accepted = watcher.poll_once()

    assert accepted is not None
    assert len(attempts) == 2
    assert accepted == attempts[0] == attempts[1]
    assert not watcher.poll_once().has_changes


def test_custom_exclusions_are_used(tmp_path):
    received = []
    watcher = FileWatcher(
        tmp_path,
        received.append,
        excludes=("*.tmp",),
    )

    watcher.poll_once()

    (tmp_path / "ignored.tmp").write_bytes(b"ignore")
    assert not watcher.poll_once().has_changes

    (tmp_path / "actual.txt").write_bytes(b"include")

    assert [
        item.path
        for item in watcher.poll_once().added
    ] == ["actual.txt"]
    assert len(received) == 1


@pytest.mark.parametrize(
    "interval",
    [0, -0.5, float("inf"), float("nan")],
)
def test_invalid_interval_is_rejected(tmp_path, interval):
    with pytest.raises(ValueError, match="interval"):
        FileWatcher(
            tmp_path,
            lambda diff: None,
            interval=interval,
        )


def test_background_thread_reports_change_and_stops(tmp_path):
    notification = threading.Event()
    changes = []
    errors = []

    def on_change(diff):
        changes.append(diff)
        notification.set()

    watcher = FileWatcher(
        tmp_path,
        on_change,
        interval=0.02,
        on_error=errors.append,
    )

    # Establish baseline before starting the background thread.
    watcher.poll_once()

    watcher.start()
    watcher.start()

    try:
        (tmp_path / "created.txt").write_bytes(b"hello")

        assert notification.wait(timeout=3), (
            "Watcher missed a new file"
        )
    finally:
        watcher.stop()
        watcher.stop()

    assert not watcher.is_running
    assert not errors
    assert [
        item.path
        for item in changes[0].added
    ] == ["created.txt"]


def test_stop_from_change_callback_does_not_deadlock(tmp_path):
    finished = threading.Event()
    watcher = None

    def on_change(diff):
        watcher.stop()
        finished.set()

    watcher = FileWatcher(
        tmp_path,
        on_change,
        interval=0.01,
    )

    watcher.poll_once()
    watcher.start()

    try:
        (tmp_path / "created.txt").write_bytes(b"hello")
        assert finished.wait(timeout=3)
    finally:
        watcher.stop()

    assert not watcher.is_running


def test_invalid_callback_is_rejected(tmp_path):
    with pytest.raises(TypeError, match="on_change"):
        FileWatcher(tmp_path, None)

    with pytest.raises(TypeError, match="on_error"):
        FileWatcher(
            tmp_path,
            lambda diff: None,
            on_error="not callable",
        )
