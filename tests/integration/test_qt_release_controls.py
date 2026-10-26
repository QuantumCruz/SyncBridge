
"""The release desktop may offer folder replacement only while connected.

Qt runs in an isolated process. The test never opens network sockets or changes
an existing synchronized folder, private key or saved pairing.
"""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

_CHILD = "SYNCBRIDGE_RELEASE_CONTROLS_CHILD"


def _exercise(tmp_path: Path, monkeypatch) -> None:
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication, QInputDialog
    from syncbridge.storage.config import ConfigStore, ShareConfig
    from syncbridge.ui.desktop_controller import DesktopPhase
    from syncbridge.ui.qt_onboarding import NetworkOptions
    from syncbridge.ui.qt_release_window import SyncBridgeReleaseWindow

    root = tmp_path / "previous-files"
    root.mkdir()
    (root / "keep.txt").write_text("never delete", encoding="utf-8")
    store = ConfigStore(tmp_path / "profile" / "settings.json")
    store.save(replace(
        store.load(), shares=(ShareConfig(
            share_id="a" * 32, peer_node_id="b" * 32,
            local_root=str(root), display_name="Previous folder",
            remote_host="127.0.0.1", enabled=True,
            grant_manifest=True, grant_read=True,
            grant_write=True, grant_agreement=True,
        ),),
    ))
    original_share = store.load().shares[0]
    marker = store.path.parent / "identity.json"
    marker.write_text("test sentinel", encoding="utf-8")

    class FakeController:
        def __init__(self):
            self.store = store
            self.runtime = SimpleNamespace(listen_ports=None)
            self.running = False

        def stop(self):
            self.running = False

    def offline_network(window):
        window._network_started = True
        window._apply_state()

    monkeypatch.setattr(
        SyncBridgeReleaseWindow, "_start_network", offline_network,
    )
    monkeypatch.setattr(
        QInputDialog, "getText", lambda *args, **kwargs: ("Daniel's PC", True),
    )

    app = QApplication.instance() or QApplication([])
    old_quit = app.quitOnLastWindowClosed()
    app.setQuitOnLastWindowClosed(False)
    window = SyncBridgeReleaseWindow(
        FakeController(), network_options=NetworkOptions(),
    )
    window.show()
    try:
        app.processEvents()
        assert window.lifecycle.phase is DesktopPhase.DISCONNECTED
        assert not window.folder_select_button.isVisible()
        assert window.open_folder_button.isEnabled()
        window._choose_folder()  # Must not clear a disconnected saved share.
        assert store.load().shares == (original_share,)

        window.rename_button.click()
        assert store.load().device_name == "Daniel's PC"
        assert "Daniel's PC" in window.my_name_label.text()

        # Simulate a verified live session without starting a network.
        window.controller.running = True
        window._live_session = "c" * 32
        window.lifecycle.transition(DesktopPhase.PAIRING)
        window.lifecycle.transition(DesktopPhase.CHOOSING_FOLDER)
        window.lifecycle.transition(DesktopPhase.CONNECTING)
        window.lifecycle.transition(DesktopPhase.CONNECTED)
        window._apply_state()
        app.processEvents()
        assert window.folder_select_button.isVisible()
        assert window.folder_select_button.isEnabled()
        assert window.folder_select_button.text() == "Change folders"

        # A disconnected session must hide replacement immediately.
        window.controller.running = False
        window._live_session = None
        window.lifecycle.transition(DesktopPhase.DISCONNECTING)
        window.lifecycle.transition(DesktopPhase.DISCONNECTED)
        window._apply_state()
        app.processEvents()
        assert not window.folder_select_button.isVisible()
        assert store.load().shares == (original_share,)
        assert (root / "keep.txt").read_text(encoding="utf-8") == "never delete"
        assert marker.read_text(encoding="utf-8") == "test sentinel"
    finally:
        window._close_allowed = True
        window.close()
        app.setQuitOnLastWindowClosed(old_quit)


def test_release_controls_only_allow_connected_folder_change(tmp_path, monkeypatch):
    pytest.importorskip("PySide6")
    if os.environ.get(_CHILD) == "1":
        _exercise(tmp_path, monkeypatch)
        return
    env = os.environ.copy()
    env[_CHILD] = "1"
    env["QT_QPA_PLATFORM"] = "offscreen"
    result = subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-q", "-s"],
        cwd=Path(__file__).resolve().parents[2], env=env,
        capture_output=True, text=True, timeout=40, check=False,
    )
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
