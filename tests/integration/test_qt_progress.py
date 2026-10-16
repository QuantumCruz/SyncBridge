
"""GUI regression tests for progress feedback, disconnect, and responsive closing."""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication

from syncbridge.ui.desktop_controller import DesktopProfile
from syncbridge.ui.qt_window import SyncBridgeQtWindow


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class FakeController:
    def __init__(self, folder: Path):
        self.folder = folder
        self.running = False
        self.starts = 0
        self.stops = 0

    def profile(self):
        return DesktopProfile(
            device_name="Alice",
            folder_name="Example",
            local_root=self.folder,
            peer_node_id="b" * 32,
            remote_host="127.0.0.1",
        )

    def start(self):
        self.starts += 1
        self.running = True

    def stop(self):
        self.stops += 1
        self.running = False


def until(app, condition, seconds=3):
    limit = time.monotonic() + seconds
    while time.monotonic() < limit:
        app.processEvents()
        if condition():
            return True
        time.sleep(0.01)

    app.processEvents()
    return bool(condition())


def open_window(app, root):
    backend = FakeController(root)
    window = SyncBridgeQtWindow(backend)
    window.show()

    assert until(
        app, lambda: backend.running and not window._busy
    )

    return window, backend


def close_window(app, window):
    window.close()
    assert until(
        app, lambda: not window.isVisible()
    )


def test_indeterminate_and_current_file_percent(app, tmp_path):
    window, _ = open_window(app, tmp_path)

    try:
        window._show_activity("Checking the folder...")

        assert window.activity_bar.isVisible()
        assert window.activity_bar.minimum() == 0
        assert window.activity_bar.maximum() == 0

        window._show_activity(
            "Current file",
            done=500,
            total=2000,
        )

        assert window.activity_bar.maximum() == 100
        assert window.activity_bar.value() == 25

        window._hide_activity()
        assert not window.activity_bar.isVisible()

    finally:
        close_window(app, window)


def test_sync_progress_disables_disconnect_until_finished(
    app, tmp_path,
):
    window, _ = open_window(app, tmp_path)
    release = threading.Event()

    try:
        def transfer():
            release.wait(timeout=3)
            return SimpleNamespace(
                complete=True,
                uploaded=("big.bin",),
                downloaded=(),
            )

        window._work("sync", transfer)

        assert not window.disconnect_button.isEnabled()

        window._on_progress(
            SimpleNamespace(
                path="big.bin",
                direction="Send",
                transferred=50,
                total=100,
            )
        )

        assert until(
            app,
            lambda: window.activity_bar.value() == 50,
        )
        assert "big.bin" in window.activity_label.text()

    finally:
        release.set()
        assert until(app, lambda: not window._busy)
        close_window(app, window)


def test_disconnect_does_not_auto_reconnect(app, tmp_path):
    window, backend = open_window(app, tmp_path)

    try:
        assert backend.starts == 1

        window.disconnect_button.click()

        assert until(
            app,
            lambda: not backend.running and not window._busy,
        )

        assert window._paused
        assert not window.disconnect_button.isVisible()
        assert not window.disconnect_button.isEnabled()

        window._auto_connect()
        app.processEvents()

        assert backend.starts == 1

    finally:
        close_window(app, window)


def test_large_file_list_renders_in_batches_and_remains_closable(
    app, tmp_path,
):
    window, _ = open_window(app, tmp_path)

    try:
        data = [
            (f"file_{n:04d}.txt", n * 12)
            for n in range(400)
        ]

        window._display_files(
            "local", (data, False)
        )

        assert window._busy
        assert not window.disconnect_button.isEnabled()

        assert until(
            app, lambda: not window._busy
        )

        assert window.local_table.rowCount() == 400
        assert not window.activity_bar.isVisible()

        window._display_files(
            "local", (data * 10, True)
        )

        # Closing must cancel rendering rather than hang.
        window.close()

        assert until(
            app, lambda: not window.isVisible()
        )

    finally:
        if window.isVisible():
            close_window(app, window)
