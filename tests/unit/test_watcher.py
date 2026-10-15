
"""Tests for SyncBridge's polling-based filesystem watcher."""

from __future__ import annotations

import os
import threading
from uuid import uuid4

import pytest

from syncbridge.core.reconciler import ChangeType, IncompleteScanError
from syncbridge.core.scanner import ScanError
from syncbridge.core.watcher import FileWatcher


def _publish_complete_file(root, name: str, contents: bytes) -> None:
    """Atomically expose a fully written file to a running watcher.

    Staging outside root ensures even a watcher with no exclude patterns
    cannot hash a partially written file. The sibling directory is on the
    same filesystem, so os.replace publishes the complete file atomically.
    """
    staged = root.parent / f"{root.name}-staged-{uuid4().hex}.tmp"
    try:
        staged.write_bytes(contents)
        os.replace(staged, root / name)
    finally:
        staged.unlink(missing_ok=True)


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
        # Do not allow a scan to catch an incomplete file during write_bytes.
        _publish_complete_file(tmp_path, "created.txt", b"hello")

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


def test_background_transient_scan_error_recovers_without_losing_change(
    tmp_path,
    monkeypatch,
):
    """One incomplete poll cannot advance the baseline or lose a file.

    Test the actual background thread, but coordinate the simulated error
    using events instead of depending on Windows disk scheduling.
    """
    notification = threading.Event()
    error_reported = threading.Event()
    permit_retry = threading.Event()
    changes = []
    errors = []

    def on_change(diff):
        changes.append(diff)
        notification.set()

    def on_error(exc):
        errors.append(exc)
        error_reported.set()

    watcher = FileWatcher(
        tmp_path,
        on_change,
        interval=0.02,
        on_error=on_error,
    )
    watcher.poll_once()
    _publish_complete_file(tmp_path, "created.txt", b"hello")

    original_scan = watcher._scanner.scan
    attempts = 0

    def transient_scan():
        nonlocal attempts
        attempts += 1
        if attempts > 1 and not permit_retry.wait(timeout=3):
            raise RuntimeError("Test did not permit the watcher retry")
        scanned = original_scan()
        if attempts == 1:
            scanned.errors.append(
                ScanError("created.txt", "Simulated temporary read error")
            )
        return scanned

    monkeypatch.setattr(watcher._scanner, "scan", transient_scan)
    watcher.start()
    try:
        assert error_reported.wait(timeout=3), (
            "Watcher did not report the simulated incomplete scan"
        )
        assert watcher._previous is not None
        assert watcher._previous.files == {}, (
            "An incomplete scan advanced the watcher's baseline"
        )
        assert not changes

        permit_retry.set()
        assert notification.wait(timeout=3), (
            "Watcher did not recover and report the pending file"
        )
    finally:
        permit_retry.set()
        watcher.stop()

    assert not watcher.is_running
    assert len(errors) == 1
    assert isinstance(errors[0], IncompleteScanError)
    assert attempts >= 2
    assert len(changes) == 1
    assert [(entry.path, entry.kind) for entry in changes[0].added] == [
        ("created.txt", ChangeType.ADDED)
    ]
    assert not watcher.poll_once().has_changes


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
        _publish_complete_file(tmp_path, "created.txt", b"hello")
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
