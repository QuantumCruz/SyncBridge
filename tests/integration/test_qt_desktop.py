
"""Qt GUI behavior checks without real sockets, files, or screen interactions."""
from __future__ import annotations

import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")
from PySide6.QtWidgets import QApplication, QMessageBox

from syncbridge.ui.desktop_controller import (
    DesktopPlanItem, DesktopPreview, DesktopProfile,
)
from syncbridge.ui.qt_window import SyncBridgeQtWindow


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class FakeController:
    def __init__(self, folder: Path):
        self.folder = folder
        self.running = False
        self.preview_calls = 0
        self.sync_calls = 0
        self.stop_calls = 0

    def profile(self):
        return DesktopProfile(
            device_name="Alice", folder_name="Test files",
            local_root=self.folder, peer_node_id="b" * 32,
            remote_host="127.0.0.1",
        )

    def start(self):
        self.running = True

    def stop(self):
        self.running = False
        self.stop_calls += 1

    def preview(self):
        self.preview_calls += 1
        return DesktopPreview(
            revision=0,
            items=(DesktopPlanItem("hello.txt", "Send", "Copy to Bob", False),),
            requires_review=False,
        )

    def sync_once(self, *, on_progress=None):
        self.sync_calls += 1
        return SimpleNamespace(complete=True, uploaded=("hello.txt",), downloaded=())


def until(app, predicate, seconds=3):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    app.processEvents()
    return bool(predicate())


def close_window(app, window):
    window.close()
    assert until(app, lambda: not window.isVisible())


def test_qt_opens_connects_and_can_preview_twice(app, tmp_path):
    backend = FakeController(tmp_path)
    window = SyncBridgeQtWindow(backend)
    window.show()
    try:
        assert until(app, lambda: backend.running and window.preview_button.isEnabled())
        window.preview_button.click()
        assert until(app, lambda: backend.preview_calls == 1 and window.table.rowCount() == 1)
        window.preview_button.click()
        assert until(app, lambda: backend.preview_calls == 2 and not window._busy)
    finally:
        close_window(app, window)
    assert backend.stop_calls == 1


def test_qt_sync_requires_confirmation_and_can_preview_afterward(app, tmp_path, monkeypatch):
    backend = FakeController(tmp_path)
    window = SyncBridgeQtWindow(backend)
    window.show()
    try:
        assert until(app, lambda: backend.running and not window._busy)
        window.preview_button.click()
        assert until(app, lambda: window.sync_button.isEnabled())
        monkeypatch.setattr(
            QMessageBox, "question", lambda *args, **kwargs: QMessageBox.StandardButton.No
        )
        window.sync_button.click()
        assert backend.sync_calls == 0
        monkeypatch.setattr(
            QMessageBox, "question", lambda *args, **kwargs: QMessageBox.StandardButton.Yes
        )
        window.sync_button.click()
        assert until(app, lambda: backend.sync_calls == 1 and not window._busy)
        window.preview_button.click()
        assert until(app, lambda: backend.preview_calls == 2 and not window._busy)
    finally:
        close_window(app, window)


def test_qt_close_does_not_block_during_shutdown(app, tmp_path):
    import threading

    release = threading.Event()
    backend = FakeController(tmp_path)
    original_stop = backend.stop

    def slow_stop():
        assert release.wait(timeout=3)
        original_stop()

    backend.stop = slow_stop
    window = SyncBridgeQtWindow(backend)
    window.show()
    try:
        assert until(app, lambda: backend.running and not window._busy)
        begin = time.monotonic()
        window.close()
        assert time.monotonic() - begin < 0.25
        assert window.isVisible()
    finally:
        release.set()
        assert until(app, lambda: not window.isVisible())


def test_qt_requires_an_existing_approved_folder(app):
    class NotConfigured(FakeController):
        def profile(self):
            raise RuntimeError("No configured share")

    backend = NotConfigured(Path("."))
    window = SyncBridgeQtWindow(backend)
    window.show()
    try:
        assert not window._configured
        assert not window.preview_button.isEnabled()
        assert not window.sync_button.isEnabled()
    finally:
        close_window(app, window)
    assert backend.stop_calls == 1
