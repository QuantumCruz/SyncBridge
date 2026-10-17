
"""End-to-end Qt recovery when the receiving desktop is forcibly killed.

Both peers run as independent, offscreen Windows processes and use only
pytest-owned temporary profiles and shared folders. A controlled pause in
Alice's sender callback makes the receiver crash reproducible.

Run:
    python -m pytest tests/integration/test_desktop_receiver_crash_resume.py -v -s

This simulates process termination, not power loss or an OS crash.
"""
from __future__ import annotations

import multiprocessing as mp
import os
import queue
import time
import traceback
from pathlib import Path

import pytest

pytest.importorskip("PySide6")

# Pytest's default import mode places this test directory on sys.path.
# Reuse the already-tested setup and receiver window rather than creating
# a second version of the security/pairing fixtures.
from test_desktop_crash_resume import (
    RELATIVE,
    _configure,
    _desktop_child,
    _hash,
    _payload_size,
    _terminate,
)


def _sender_desktop(
    profile: str,
    ports: tuple[int, int, int],
    lock_port: int,
    validation_port: int,
    cutoff: int,
    ready,
    reached_cutoff,
    release_sender,
    retry_sender,
    messages,
) -> None:
    """Run Alice's real desktop through a failed sync and same-process retry."""
    os.environ["QT_QPA_PLATFORM"] = "offscreen"

    try:
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication, QMessageBox
        from syncbridge.storage.config import ConfigStore
        from syncbridge.ui.desktop_controller import DesktopController
        from syncbridge.ui.qt_local_refresh import QtLocalFileRefresh
        from syncbridge.ui.qt_progress_window import SyncBridgeProgressWindow

        app = QApplication([])
        controller = DesktopController(
            ConfigStore(Path(profile) / "settings.json"),
            bind_address="127.0.0.1",
            listen_ports=ports,
            lock_port=lock_port,
            validation_port=validation_port,
        )
        QMessageBox.question = (
            lambda *args, **kwargs: QMessageBox.StandardButton.Yes
        )
        QMessageBox.warning = (
            lambda *args, **kwargs: QMessageBox.StandardButton.Ok
        )

        window = SyncBridgeProgressWindow(controller)
        window.local_view_refresh = QtLocalFileRefresh(
            window, interval_ms=100
        )
        window.show()

        attempt = 0
        did_hold = False
        did_report_offset = False
        ordinary_progress = window._on_progress

        def controlled_progress(event) -> None:
            nonlocal did_hold, did_report_offset
            direction = str(event.direction).lower()
            transferred = int(event.transferred)

            if attempt == 2 and direction == "send" and not did_report_offset:
                did_report_offset = True
                messages.put(("resume-offset", transferred))

            ordinary_progress(event)

            if (
                attempt == 1
                and direction == "send"
                and transferred >= cutoff
                and not did_hold
            ):
                did_hold = True
                reached_cutoff.set()
                if not release_sender.wait(timeout=35):
                    messages.put(("sender-release-timeout",))

        window._on_progress = controlled_progress
        original_sync = controller.sync_once

        def observed_sync(*, on_progress=None):
            nonlocal attempt
            attempt += 1
            current = attempt
            try:
                result = original_sync(on_progress=on_progress)
            except Exception as exc:
                messages.put(("sync-error", current, str(exc)))
                raise
            else:
                messages.put(("sync-result", current, bool(result.complete)))
                return result

        controller.sync_once = observed_sync

        is_ready = False
        first_preview_started = False
        first_sync_started = False
        second_preview_started = False
        second_sync_started = False
        started_at = time.monotonic()

        def poll() -> None:
            nonlocal is_ready
            nonlocal first_preview_started, first_sync_started
            nonlocal second_preview_started, second_sync_started

            if time.monotonic() - started_at > 105:
                messages.put(("sender-child-timeout",))
                app.quit()
                return

            if not is_ready and controller.running and not window._busy:
                is_ready = True
                ready.set()

            if not is_ready or window._busy:
                return

            if not first_preview_started:
                first_preview_started = True
                window.preview_button.click()
                return

            if not first_sync_started:
                if window.sync_button.isEnabled():
                    first_sync_started = True
                    window.sync_button.click()
                elif (
                    window._preview is not None
                    and not window._preview.items
                ):
                    messages.put(("unexpected-empty-preview", 1))
                    app.quit()
                return

            if not retry_sender.is_set():
                return

            if not second_preview_started:
                second_preview_started = True
                window.preview_button.click()
                return

            if not second_sync_started:
                if window.sync_button.isEnabled():
                    second_sync_started = True
                    window.sync_button.click()
                elif (
                    window._preview is not None
                    and not window._preview.items
                ):
                    messages.put(("unexpected-empty-preview", 2))
                    app.quit()

        timer = QTimer(window)
        timer.setInterval(40)
        timer.timeout.connect(poll)
        timer.start()
        app.exec()
    except BaseException:
        messages.put(("sender-child-exception", traceback.format_exc()))
        raise


def _get_message(messages, timeout: float):
    try:
        return messages.get(timeout=timeout)
    except queue.Empty:
        return None


def test_desktop_recovers_after_receiver_is_killed_mid_transfer(tmp_path):
    """A still-running sender retries safely after Bob's process restarts."""
    size = _payload_size()
    (
        profiles,
        roots,
        listeners,
        lock_port,
        validation_port,
        source,
    ) = _configure(tmp_path, size=size)

    destination = roots["Bob"] / RELATIVE
    ctx = mp.get_context("spawn")
    messages = ctx.Queue()
    bob_ready = ctx.Event()
    alice_ready = ctx.Event()
    bob_restarted_ready = ctx.Event()
    reached_cutoff = ctx.Event()
    release_sender = ctx.Event()
    retry_sender = ctx.Event()
    unused_checkpoint = ctx.Event()
    children: list[mp.Process] = []

    def start_bob(ready):
        child = ctx.Process(
            target=_desktop_child,
            args=(
                str(profiles["Bob"]),
                tuple(listeners["Bob"]),
                lock_port,
                validation_port,
                "serve",
                size // 4,
                ready,
                unused_checkpoint,
                messages,
            ),
            name="SyncBridgeReceiverCrash-Bob",
        )
        child.start()
        children.append(child)
        return child

    def staged_parts():
        return list(
            roots["Bob"].parent.glob(".syncbridge-transfer-*/*.part")
        )

    try:
        bob = start_bob(bob_ready)
        assert bob_ready.wait(timeout=25), (
            f"Bob's desktop did not become ready (exitcode={bob.exitcode})"
        )

        alice = ctx.Process(
            target=_sender_desktop,
            args=(
                str(profiles["Alice"]),
                tuple(listeners["Alice"]),
                lock_port,
                validation_port,
                size // 4,
                alice_ready,
                reached_cutoff,
                release_sender,
                retry_sender,
                messages,
            ),
            name="SyncBridgeReceiverCrash-Alice",
        )
        alice.start()
        children.append(alice)
        assert alice_ready.wait(timeout=25), (
            f"Alice's desktop did not become ready (exitcode={alice.exitcode})"
        )
        assert reached_cutoff.wait(timeout=45), (
            "Alice never reached the deliberately paused transfer checkpoint"
        )

        deadline = time.monotonic() + 12
        partial_size = 0
        while time.monotonic() < deadline:
            parts = staged_parts()
            if len(parts) == 1:
                partial_size = parts[0].stat().st_size
                if 0 < partial_size < size:
                    break
            time.sleep(0.03)

        assert 0 < partial_size < size, (
            "Bob had no unfinished staged data before termination"
        )
        assert not destination.exists(), "Incomplete data was published"
        assert bob.is_alive() and alice.is_alive(), (
            "A desktop exited before the deliberate receiver termination"
        )

        _terminate(bob)
        assert alice.is_alive(), "Alice exited when Bob was terminated"
        assert not destination.exists(), (
            "An unfinished file appeared after the receiver crash"
        )

        parts = staged_parts()
        assert len(parts) == 1, (
            "Bob did not preserve exactly one unfinished transfer"
        )
        saved_offset = parts[0].stat().st_size
        assert 0 < saved_offset < size

        release_sender.set()
        first_outcome = None
        observed = []
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            note = _get_message(messages, 1)
            if note is None:
                continue
            observed.append(note)
            if note[0] in {
                "sender-child-exception",
                "sender-child-timeout",
                "sender-release-timeout",
                "child-exception",
                "child-timeout",
                "unexpected-empty-preview",
            }:
                pytest.fail(f"Desktop failure: {note!r}")
            if note[0] in {"sync-error", "sync-result"} and note[1] == 1:
                first_outcome = note
                break

        assert first_outcome is not None, (
            f"Alice never reported the interrupted transfer: {observed!r}"
        )
        if first_outcome[0] == "sync-result":
            assert first_outcome[2] is False, (
                "Alice incorrectly reported complete after Bob's crash"
            )
        assert alice.is_alive(), "Alice did not survive the failed transfer"
        assert not destination.exists(), "An unfinished file was published"

        restarted_bob = start_bob(bob_restarted_ready)
        assert bob_restarted_ready.wait(timeout=25), (
            "Bob did not restart with the saved profile "
            f"(exitcode={restarted_bob.exitcode})"
        )
        assert alice.is_alive(), "Alice exited before the retry"
        retry_sender.set()

        successful_retry = False
        updated_receiver_view = False
        checked_resume_offset = False
        deadline = time.monotonic() + 55
        while time.monotonic() < deadline and not (
            successful_retry and updated_receiver_view and checked_resume_offset
        ):
            note = _get_message(messages, 1)
            if note is None:
                continue
            observed.append(note)
            if note[0] == "resume-offset":
                assert note[1] == saved_offset, (
                    f"The retry did not resume from {saved_offset}: {note!r}"
                )
                checked_resume_offset = True
            elif note[0] == "sync-result" and note[1] == 2:
                assert note[2] is True, (
                    f"The retry remained incomplete: {note!r}"
                )
                successful_retry = True
            elif note[0] == "receiver-view-updated":
                updated_receiver_view = True
            elif note[0] in {
                "sync-error",
                "child-exception",
                "child-timeout",
                "sender-child-exception",
                "sender-child-timeout",
                "sender-release-timeout",
                "unexpected-empty-preview",
            }:
                pytest.fail(f"Desktop reported a retry failure: {note!r}")

        assert successful_retry, f"No successful retry: {observed!r}"
        assert checked_resume_offset, f"Resume offset unverified: {observed!r}"
        assert updated_receiver_view, f"Bob's file list did not update: {observed!r}"
        assert alice.is_alive() and restarted_bob.is_alive()
        assert destination.is_file(), "Bob never published the completed file"
        assert destination.stat().st_size == size
        assert _hash(destination) == _hash(source), (
            "Bob's completed file differs from Alice's original"
        )
        assert not staged_parts(), "Completed transfer left a .part file behind"
    finally:
        release_sender.set()
        retry_sender.set()
        for child in reversed(children):
            _terminate(child)
            child.close()
        messages.close()
        messages.join_thread()
