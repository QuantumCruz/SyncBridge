
"""Check real Qt button activation without opening sockets.

Run in an isolated child process to avoid mixing QApplication lifetime with
other tests. Network and session protocols have their own integration tests.
"""
from __future__ import annotations

import os
import subprocess
import sys

import pytest


_CHILD = "SYNCBRIDGE_QT_BUTTONS_CHILD"


def _exercise(tmp_path, monkeypatch):
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication

    from syncbridge.storage.config import ConfigStore
    from syncbridge.ui.desktop_controller import DesktopPhase
    from syncbridge.ui.qt_mutual_session_window import SyncBridgeMutualSessionWindow
    from syncbridge.ui.qt_onboarding import NetworkOptions

    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")

    class Controller:
        def __init__(self):
            self.store = ConfigStore(tmp_path / "settings.json")
            self.runtime = type("Runtime", (), {"listen_ports": None})()
            self.running = False

        def stop(self):
            self.running = False

    def offline_network(self):
        self._network_started = True
        self._apply_state()

    monkeypatch.setattr(SyncBridgeMutualSessionWindow, "_start_network", offline_network)
    app = QApplication.instance() or QApplication([])
    old_setting = app.quitOnLastWindowClosed()
    app.setQuitOnLastWindowClosed(False)
    window = SyncBridgeMutualSessionWindow(
        Controller(), network_options=NetworkOptions(name="Alice")
    )
    try:
        app.processEvents()
        assert window.lifecycle.phase is DesktopPhase.DISCONNECTED
        assert window.find_button.isEnabled()
        assert not window.folder_select_button.isEnabled()
        assert not window.preview_button.isEnabled()
        assert not window.sync_button.isEnabled()
        assert not window.disconnect_button.isEnabled()
        assert not window.reconnect_button.isVisible()

        window._move(DesktopPhase.PAIRING)
        assert not window.find_button.isEnabled()
        assert not window.folder_select_button.isEnabled()

        window._move(DesktopPhase.CHOOSING_FOLDER)
        assert not window.find_button.isEnabled()
        assert window.folder_select_button.isEnabled()
        assert not window.preview_button.isEnabled()

        window._move(DesktopPhase.CONNECTING)
        assert not window.find_button.isEnabled()
        assert not window.folder_select_button.isEnabled()
        assert not window.preview_button.isEnabled()

        window.controller.running = True
        window._move(DesktopPhase.CONNECTED)
        assert window.preview_button.isEnabled()
        assert window.disconnect_button.isEnabled()
        assert not window.find_button.isEnabled()
        assert not window.folder_select_button.isEnabled()

        window._move(DesktopPhase.SYNCHRONIZING)
        assert not window.preview_button.isEnabled()
        assert not window.disconnect_button.isEnabled()

        window._move(DesktopPhase.DISCONNECTING)
        assert not window.find_button.isEnabled()
        assert not window.folder_select_button.isEnabled()
        assert not window.preview_button.isEnabled()

        window.controller.running = False
        window._move(DesktopPhase.DISCONNECTED)
        assert window.find_button.isEnabled()
        assert not window.folder_select_button.isEnabled()
        assert not window.preview_button.isEnabled()
        assert not window.disconnect_button.isEnabled()
    finally:
        window._close_allowed = True
        window.close()
        app.setQuitOnLastWindowClosed(old_setting)


def test_qt_button_permissions(tmp_path, monkeypatch):
    if os.environ.get(_CHILD) == "1":
        _exercise(tmp_path, monkeypatch)
        return

    env = os.environ.copy()
    env[_CHILD] = "1"
    env["QT_QPA_PLATFORM"] = "offscreen"
    result = subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-q", "-s"],
        env=env, capture_output=True, text=True, timeout=45,
        check=False,
    )
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
