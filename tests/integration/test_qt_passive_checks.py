
"""Regression tests for passive Qt previews (isolated from the pytest parent).

No network or user folders are used. The child drives the real Qt widget
with a fake guarded runtime to prove passive polling never writes files.
"""
from __future__ import annotations

import os
import subprocess
import sys
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
    from syncbridge.storage.config import AppConfig, ConfigStore, ShareConfig
    from syncbridge.ui.desktop_controller import DesktopController
    from syncbridge.ui.qt_progress_window import SyncBridgeProgressWindow

    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")

    app = QApplication.instance() or QApplication([])
    original = app.quitOnLastWindowClosed()
    app.setQuitOnLastWindowClosed(False)

    class Runtime:
        def __init__(self, store, **_options):
            self.store = store
            self.active = False
            self.preview_calls = 0
            self.sync_calls = 0
            self.decisions = ()
            self.unavailable = False

        def start(self, *, background=False):
            assert background is False
            self.active = True

        def stop(self):
            self.active = False

        def preview(self):
            self.preview_calls += 1
            if self.unavailable:
                raise ConnectionError("peer temporarily offline")
            return SimpleNamespace(
                preview=SimpleNamespace(
                    plan=SimpleNamespace(decisions=self.decisions),
                    baseline_revision=3,
                )
            )

        def sync_once(self, *, on_progress=None):
            self.sync_calls += 1
            raise AssertionError("Background previews must never synchronize")

    def decision(action):
        return SimpleNamespace(path="notes.txt", action=action)

    shared = tmp_path / "Share"
    shared.mkdir()
    store = ConfigStore(tmp_path / "Profile" / "settings.json")
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
    controller = DesktopController(store, runtime_factory=Runtime)
    runtime = controller.runtime

    def unexpected_warning(*_args, **_kwargs):
        raise AssertionError("Passive checking opened an intrusive warning dialog")

    monkeypatch.setattr(QMessageBox, "warning", unexpected_warning)
    window = SyncBridgeProgressWindow(controller)
    window.show()
    window._passive_check_timer.setInterval(80)

    def until(condition, *, timeout=6.0):
        deadline = time.perf_counter() + timeout
        while time.perf_counter() < deadline:
            app.processEvents()
            if condition():
                return
            time.sleep(0.01)
        pytest.fail(
            "Qt passive check did not reach expected state: "
            f"{window.status.text()!r}; {window.summary.text()!r}; "
            f"busy={window._busy}; previews={runtime.preview_calls}; "
            f"writes={runtime.sync_calls}"
        )

    try:
        assert window._passive_check_timer.isActive()
        assert not controller.running
        until(lambda: controller.running and not window._busy)
        until(lambda: runtime.preview_calls >= 1 and not window._busy)
        assert runtime.sync_calls == 0
        assert window.summary.text() == "Everything is up to date."

        runtime.decisions = (decision(SyncAction.UPLOAD),)
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

        runtime.decisions = (decision(SyncAction.CONFLICT),)
        until(
            lambda: (
                window._preview is not None
                and window._preview.requires_review
                and not window._busy
            )
        )
        assert not window.sync_button.isEnabled()
        assert runtime.sync_calls == 0

        runtime.decisions = (decision(SyncAction.REVIEW_DELETE_REMOTE),)
        until(
            lambda: (
                window._preview is not None
                and window._preview.items
                and window._preview.items[0].action == "Deletion review"
                and not window._busy
            )
        )
        assert not window.sync_button.isEnabled()

        runtime.unavailable = True
        until(
            lambda: (
                window.status.text() == "Waiting for other computer"
                and not window._busy
            )
        )
        assert runtime.sync_calls == 0
        assert not window.sync_button.isEnabled()

        runtime.unavailable = False
        runtime.decisions = ()
        until(
            lambda: (
                window._preview is not None
                and not window._preview.items
                and window.summary.text() == "Everything is up to date."
                and not window._busy
            )
        )
        assert runtime.sync_calls == 0

        window._paused = True
        calls_before = runtime.preview_calls
        window._check_in_background()
        app.processEvents()
        assert runtime.preview_calls == calls_before

    finally:
        window.close()
        until(lambda: not window.isVisible())
        app.setQuitOnLastWindowClosed(original)


def test_qt_passive_previews_never_modify_files(tmp_path, monkeypatch):
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
            timeout=45,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(
            "Isolated Qt passive preview test timed out. "
            f"Partial output: {exc.stdout!r}",
            pytrace=False,
        )

    assert result.returncode == 0, (
        "Isolated Qt passive preview test failed "
        f"(exit code {result.returncode}).\n{result.stdout}"
    )
