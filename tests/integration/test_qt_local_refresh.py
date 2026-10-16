
"""The passive receiver's 'My files' view updates after local file changes."""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication

from syncbridge.ui.desktop_controller import DesktopProfile
from syncbridge.ui.qt_local_refresh import QtLocalFileRefresh
from syncbridge.ui.qt_window import SyncBridgeQtWindow


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class FakeController:
    def __init__(self, root: Path):
        self.root = root
        self.running = False
        self.starts = 0
        self.stops = 0

    def profile(self):
        return DesktopProfile(
            device_name="Bob",
            folder_name="Shared",
            local_root=self.root,
            peer_node_id="a" * 32,
            remote_host="127.0.0.1",
        )

    def start(self):
        self.starts += 1
        self.running = True

    def stop(self):
        self.stops += 1
        self.running = False

    def preview(self):
        raise AssertionError(
            "Passive receiver must not start Preview"
        )

    def sync_once(self, **kwargs):
        raise AssertionError(
            "Passive receiver must not initiate Sync"
        )


def wait_for(app, predicate, seconds=4):
    deadline = time.monotonic() + seconds

    while time.monotonic() < deadline:
        app.processEvents()

        if predicate():
            return True

        time.sleep(0.01)

    app.processEvents()
    return bool(predicate())


def open_receiver(app, folder: Path):
    (folder / "original.txt").write_text(
        "Original",
        encoding="utf-8",
    )

    controller = FakeController(folder)
    window = SyncBridgeQtWindow(controller)
    window.show()

    assert wait_for(
        app,
        lambda: (
            controller.running
            and not window._busy
            and "local" in window._loaded
            and window.local_table.rowCount() == 1
        ),
    )

    watcher = QtLocalFileRefresh(
        window,
        interval_ms=75,
    )

    return window, watcher, controller


def close_receiver(app, window):
    window.close()
    assert wait_for(
        app,
        lambda: not window.isVisible(),
    )


def test_receiving_new_file_refreshes_view_without_user_action(
    app, tmp_path,
):
    window, _watcher, controller = open_receiver(app, tmp_path)

    try:
        # Alice's transfer changes Bob's directory without using Bob's GUI.
        (tmp_path / "from_alice.txt").write_text(
            "Hello from Alice",
            encoding="utf-8",
        )

        assert wait_for(
            app,
            lambda: (
                window.local_table.rowCount() == 2
                and not window._busy
                and {
                    window.local_table.item(i, 0).text()
                    for i in range(window.local_table.rowCount())
                }
                == {"original.txt", "from_alice.txt"}
            ),
        )

        assert controller.starts == 1

    finally:
        close_receiver(app, window)


def test_unchanged_files_do_not_rebuild_table(
    app, tmp_path, monkeypatch,
):
    window, watcher, _controller = open_receiver(app, tmp_path)

    try:
        rebuilt = []
        old_display = window._display_files

        def record(kind, result):
            rebuilt.append(kind)
            old_display(kind, result)

        monkeypatch.setattr(
            window,
            "_display_files",
            record,
        )

        watcher.check()

        assert wait_for(
            app,
            lambda: not watcher._scanning,
        )

        assert rebuilt == []
        assert window.local_table.rowCount() == 1

    finally:
        close_receiver(app, window)


def test_disconnected_receiver_does_not_refresh(
    app, tmp_path,
):
    window, watcher, controller = open_receiver(app, tmp_path)

    try:
        window.disconnect_button.click()

        assert wait_for(
            app,
            lambda: (
                not controller.running
                and not window._busy
            ),
        )

        (tmp_path / "later.txt").write_text(
            "Not connected",
            encoding="utf-8",
        )

        watcher.check()
        app.processEvents()

        assert window._paused
        assert window.local_table.rowCount() == 0

    finally:
        close_receiver(app, window)
