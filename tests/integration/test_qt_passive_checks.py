
"""Isolated Qt tests for user-priority passive difference detection.

Tests real Qt controls and background worker scheduling with a mocked
guarded runtime. No peer networking or real synchronized files are used.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest


_CHILD_FLAG = "SYNCBRIDGE_QT_PASSIVE_CHECK_CHILD"


def _exercise(tmp_path, monkeypatch) -> None:
    pytest.importorskip("PySide6")

    from types import SimpleNamespace
    from uuid import uuid4

    from PySide6.QtWidgets import QApplication, QMessageBox

    from syncbridge.core.conflicts import SyncAction
    from syncbridge.storage.config import (
        AppConfig,
        ConfigStore,
        ShareConfig,
    )
    from syncbridge.ui.desktop_controller import DesktopController
    from syncbridge.ui.qt_progress_window import (
        SyncBridgeProgressWindow,
    )

    monkeypatch.setenv(
        "QT_QPA_PLATFORM",
        "offscreen",
    )

    app = QApplication.instance() or QApplication([])
    previous_quit = app.quitOnLastWindowClosed()
    app.setQuitOnLastWindowClosed(False)

    class Runtime:
        def __init__(self, store, **_options):
            self.store = store
            self.active = False
            self.preview_calls = 0
            self.sync_calls = 0
            self.decisions = ()
            self.unavailable = False

            self.hold_next = False
            self.preview_entered = threading.Event()
            self.release_preview = threading.Event()

        def start(self, *, background=False):
            assert background is False
            self.active = True

        def stop(self):
            self.active = False
            self.release_preview.set()

        def preview(self):
            self.preview_calls += 1

            if self.hold_next:
                self.hold_next = False
                self.preview_entered.set()

                if not self.release_preview.wait(timeout=5):
                    raise TimeoutError(
                        "Controlled preview was not released"
                    )

            if self.unavailable:
                raise ConnectionError(
                    "peer temporarily offline"
                )

            return SimpleNamespace(
                preview=SimpleNamespace(
                    plan=SimpleNamespace(
                        decisions=self.decisions,
                    ),
                    baseline_revision=3,
                ),
            )

        def sync_once(self, *, on_progress=None):
            self.sync_calls += 1
            raise AssertionError(
                "Passive previews must never write files"
            )

    def decision(action):
        return SimpleNamespace(
            path="notes.txt",
            action=action,
        )

    shared = tmp_path / "Share"
    shared.mkdir()

    store = ConfigStore(
        tmp_path / "Profile" / "settings.json"
    )

    store.save(
        AppConfig(
            device_name="Alice",
            shares=(
                ShareConfig(
                    share_id=uuid4().hex,
                    peer_node_id=uuid4().hex,
                    local_root=str(shared),
                    display_name="Test files",
                    remote_host="127.0.0.1",
                    enabled=True,
                ),
            ),
        )
    )

    controller = DesktopController(
        store,
        runtime_factory=Runtime,
    )
    runtime = controller.runtime

    def unexpected_warning(*_args, **_kwargs):
        raise AssertionError(
            "Background preview displayed a modal warning"
        )

    monkeypatch.setattr(
        QMessageBox,
        "warning",
        unexpected_warning,
    )

    window = SyncBridgeProgressWindow(controller)
    window.show()

    # Accelerate background checks only inside this test.
    window._passive_check_timer.setInterval(80)

    def until(condition, *, timeout=7.0):
        deadline = time.perf_counter() + timeout

        while time.perf_counter() < deadline:
            app.processEvents()

            if condition():
                return

            time.sleep(0.01)

        pytest.fail(
            "Qt preview did not reach the expected state. "
            f"Status={window.status.text()!r}, "
            f"Summary={window.summary.text()!r}, "
            f"Busy={window._busy}, "
            f"Calls={runtime.preview_calls}, "
            f"Writes={runtime.sync_calls}"
        )

    try:
        assert window._passive_check_timer.isActive()

        until(
            lambda: (
                controller.running
                and not window._busy
            )
        )

        # An idle connection gets an automatic read-only check.
        until(
            lambda: (
                runtime.preview_calls >= 1
                and not window._busy
            )
        )

        assert runtime.sync_calls == 0
        assert (
            window.summary.text()
            == "Everything is up to date."
        )

        # Ordinary changes appear without requiring manual Preview.
        runtime.decisions = (
            decision(SyncAction.UPLOAD),
        )

        until(
            lambda: (
                window._preview is not None
                and len(window._preview.items) == 1
                and window._preview.items[0].action == "Send"
                and not window._busy
            )
        )

        assert window.sync_button.isEnabled()
        assert runtime.sync_calls == 0

        # Actionable results must not be replaced by repeated
        # automatic scans while the user reviews them.
        before = runtime.preview_calls

        window._check_in_background()

        for _ in range(20):
            app.processEvents()
            time.sleep(0.01)

        assert runtime.preview_calls == before
        assert window.sync_button.isEnabled()
        assert len(window._preview.items) == 1

        # A manual check still refreshes the current plan.
        runtime.decisions = (
            decision(SyncAction.CONFLICT),
        )
        window._check_changes()

        until(
            lambda: (
                window._preview is not None
                and window._preview.requires_review
                and not window._busy
            )
        )

        assert not window.sync_button.isEnabled()
        assert runtime.sync_calls == 0

        # Deletion reviews remain blocked.
        runtime.decisions = (
            decision(SyncAction.REVIEW_DELETE_REMOTE),
        )
        window._check_changes()

        until(
            lambda: (
                window._preview is not None
                and len(window._preview.items) == 1
                and window._preview.items[0].action
                == "Deletion review"
                and not window._busy
            )
        )

        assert not window.sync_button.isEnabled()
        assert runtime.sync_calls == 0

        # Once the user gets a clean result, passive checks resume.
        runtime.decisions = ()
        window._check_changes()

        until(
            lambda: (
                window._preview is not None
                and not window._preview.items
                and not window._busy
            )
        )

        # A transient network failure produces useful information
        # without writing files or opening a modal dialog.
        window._passive_check_timer.stop()
        runtime.unavailable = True
        window._check_in_background()

        until(
            lambda: (
                window.status.text()
                == "Waiting for other computer"
                and not window._busy
            )
        )

        assert "ConnectionError" in window.summary.text()
        assert "peer temporarily offline" in window.summary.text()
        assert not window.sync_button.isEnabled()
        assert runtime.sync_calls == 0

        # Recovery restores the normal preview workflow.
        runtime.unavailable = False
        window._check_changes()

        until(
            lambda: (
                window._preview is not None
                and not window._preview.items
                and not window._busy
            )
        )

        # Simulate a slow background preview.
        runtime.hold_next = True
        runtime.preview_entered.clear()
        runtime.release_preview.clear()
        runtime.decisions = (
            decision(SyncAction.UPLOAD),
        )

        window._check_in_background()

        until(
            lambda: (
                runtime.preview_entered.is_set()
                and window._passive_working
                and window._busy
            )
        )

        # Preview stays available because a manual request can be
        # queued behind the existing worker.
        assert window.preview_button.isEnabled()

        window._check_changes()
        assert window._manual_preview_queued
        assert not window.preview_button.isEnabled()

        calls_before_release = runtime.preview_calls

        runtime.release_preview.set()

        until(
            lambda: (
                runtime.preview_calls
                > calls_before_release
                and window._preview is not None
                and len(window._preview.items) == 1
                and not window._busy
            )
        )

        assert not window._manual_preview_queued
        assert not window._passive_working
        assert not window._manual_preview_running
        assert window.sync_button.isEnabled()
        assert runtime.sync_calls == 0

        # A manually paused desktop must not schedule scans.
        window._paused = True
        calls_before_pause = runtime.preview_calls

        window._check_in_background()
        app.processEvents()

        assert runtime.preview_calls == calls_before_pause

    finally:
        runtime.release_preview.set()
        window._passive_check_timer.stop()
        window.close()

        until(
            lambda: not window.isVisible(),
            timeout=15,
        )

        app.setQuitOnLastWindowClosed(previous_quit)


def test_qt_passive_previews_never_modify_files(
    tmp_path,
    monkeypatch,
):
    if os.environ.get(_CHILD_FLAG) == "1":
        _exercise(tmp_path, monkeypatch)
        return

    project = Path(__file__).resolve().parents[2]
    environment = os.environ.copy()
    environment[_CHILD_FLAG] = "1"
    environment["QT_QPA_PLATFORM"] = "offscreen"

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "-s",
                str(Path(__file__).resolve()),
                "-k",
                "test_qt_passive_previews_never_modify_files",
            ],
            cwd=project,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(
            "Isolated Qt preview test exceeded 60 seconds. "
            f"Captured output: {exc.stdout!r}",
            pytrace=False,
        )

    assert result.returncode == 0, (
        "Isolated Qt preview test failed "
        f"(exit code {result.returncode}).\n"
        f"{result.stdout}"
    )
