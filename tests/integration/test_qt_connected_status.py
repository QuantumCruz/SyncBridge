
"""The desktop must not claim to be disconnected while synchronizing."""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

_CHILD = "SYNCBRIDGE_CONNECTED_STATUS_CHILD"


def _exercise(tmp_path):
    from PySide6.QtWidgets import QApplication

    from syncbridge.storage.config import ConfigStore, ShareConfig
    from syncbridge.ui.desktop_controller import DesktopPhase
    from syncbridge.ui.qt_clean_start_window import SyncBridgeCleanStartWindow
    from syncbridge.ui.qt_onboarding import NetworkOptions

    profile = tmp_path / "Profile"
    profile.mkdir()
    root = tmp_path / "Shared"
    root.mkdir()

    store = ConfigStore(profile / "settings.json")
    share = ShareConfig(
        share_id="a" * 32,
        peer_node_id="b" * 32,
        local_root=str(root),
        display_name="Test files",
        remote_host="127.0.0.1",
        enabled=True,
        grant_manifest=True,
        grant_read=True,
        grant_write=True,
        grant_agreement=True,
    )
    store.save(replace(store.load(), shares=(share,)))

    class OfflineController:
        def __init__(self):
            self.store = store
            self.runtime = SimpleNamespace(listen_ports=None)
            self.running = False

        def stop(self):
            self.running = False

    # Test the real Qt lifecycle without opening network sockets.
    original_start = SyncBridgeCleanStartWindow._start_network

    def offline_start(window):
        window._network_started = True
        window._apply_state()

    SyncBridgeCleanStartWindow._start_network = offline_start
    app = QApplication.instance() or QApplication([])
    previous = app.quitOnLastWindowClosed()
    app.setQuitOnLastWindowClosed(False)
    window = None

    try:
        controller = OfflineController()
        window = SyncBridgeCleanStartWindow(
            controller, network_options=NetworkOptions()
        )
        window.show()
        app.processEvents()

        window._move(DesktopPhase.CONNECTING)
        window._live_session = "c" * 32
        controller.running = True
        window._move(DesktopPhase.CONNECTED)

        assert window.connection.text().startswith("Connected to ")
        assert "not connected" not in window.hint.text().lower()

        window._busy = True
        window._move(DesktopPhase.SYNCHRONIZING)

        assert window.status.text() == "Synchronizing"
        assert window.connection.text().startswith("Connected to ")
        assert window.hint.text() == "Synchronizing files..."
        assert "not connected" not in window.hint.text().lower()

        window._busy = False
        window._move(DesktopPhase.CONNECTED)

        assert window.connection.text().startswith("Connected to ")
        assert (
            window.hint.text()
            == "Preview differences before synchronizing."
        )

        window._live_session = None
        controller.running = False
        window._move(DesktopPhase.DISCONNECTING)
        window._move(DesktopPhase.DISCONNECTED)

        assert "not connected" in window.hint.text().lower()

    finally:
        if window is not None:
            window._close_allowed = True
            window.close()
        app.setQuitOnLastWindowClosed(previous)
        SyncBridgeCleanStartWindow._start_network = original_start


def test_qt_connection_banner_through_sync_and_disconnect(tmp_path):
    pytest.importorskip("PySide6")

    if os.environ.get(_CHILD) == "1":
        _exercise(tmp_path)
        return

    env = os.environ.copy()
    env[_CHILD] = "1"
    env["QT_QPA_PLATFORM"] = "offscreen"

    done = subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-q", "-s"],
        cwd=Path(__file__).resolve().parents[2],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=45,
    )

    assert done.returncode == 0, done.stdout + "\n" + done.stderr
