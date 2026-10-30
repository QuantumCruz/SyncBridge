
"""The polished desktop must retain correct controls and lifecycle behavior.

Uses production preview models rather than placeholder objects, so changes
to the UI presentation are tested against the controller's real contract.
"""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

CHILD = "SYNCBRIDGE_POLISHED_QT_CHILD"


def _exercise(tmp_path: Path, monkeypatch) -> None:
    from PySide6.QtWidgets import QApplication

    from syncbridge.storage.config import ConfigStore, ShareConfig
    from syncbridge.ui.desktop_controller import (
        DesktopPhase,
        DesktopPlanItem,
        DesktopPreview,
    )
    from syncbridge.ui.qt_onboarding import NetworkOptions
    from syncbridge.ui.qt_polished_window import SyncBridgePolishedWindow

    profile = tmp_path / "profile"
    profile.mkdir()

    folder = tmp_path / "shared"
    folder.mkdir()

    test_file = folder / "report.txt"
    test_file.write_text(
        "SyncBridge UI regression test",
        encoding="utf-8",
    )

    store = ConfigStore(profile / "settings.json")

    share = ShareConfig(
        share_id="a" * 32,
        peer_node_id="b" * 32,
        local_root=str(folder),
        display_name="Test files",
        remote_host="127.0.0.1",
        enabled=True,
        grant_manifest=True,
        grant_read=True,
        grant_write=True,
        grant_agreement=True,
    )

    store.save(
        replace(store.load(), shares=(share,))
    )

    class Controller:
        def __init__(self):
            self.store = store
            self.runtime = SimpleNamespace(listen_ports=None)
            self.running = False

        def stop(self):
            self.running = False

    # Exercise actual Qt controls without opening network sockets.
    def no_network(window):
        window._network_started = True
        window._apply_state()

    monkeypatch.setattr(
        SyncBridgePolishedWindow,
        "_start_network",
        no_network,
    )

    app = QApplication.instance() or QApplication([])
    before = app.quitOnLastWindowClosed()
    app.setQuitOnLastWindowClosed(False)

    controller = Controller()

    window = SyncBridgePolishedWindow(
        controller,
        network_options=NetworkOptions(),
    )

    window.show()

    try:
        app.processEvents()

        # Disconnected: only relevant controls should appear.
        assert window.windowTitle() == "SyncBridge"
        assert window._empty_panel.isVisible()
        assert not window.tabs.isVisible()
        assert not window.preview_button.isVisible()
        assert not window.sync_button.isVisible()
        assert not window.fresh_button.isVisible()
        assert not window.rename_button.isVisible()
        assert window._options_button.isVisible()
        assert window._fresh_action.isEnabled()
        assert window._empty_title.text() == "Ready when you are"

        # Errors must remain readable.
        window.summary.setText(
            "The other computer could not be reached."
        )
        window._apply_state()

        assert window.summary.isVisible()

        # Simulate an approved live connection.
        window._move(DesktopPhase.CONNECTING)
        window._live_session = "c" * 32
        controller.running = True
        window._move(DesktopPhase.CONNECTED)

        assert window.connection.text().startswith(
            "Connected to "
        )
        assert window._empty_panel.isVisible()
        assert not window.tabs.isVisible()
        assert window.preview_button.isVisible()
        assert not window.sync_button.isVisible()
        assert not window._fresh_action.isEnabled()

        # Use the production preview contract.
        # A safe proposed change should reveal the Sync action.
        plan_item = DesktopPlanItem(
            path=test_file.name,
            action="Send",
            description="Copy this version to the paired computer",
            needs_review=False,
            size=test_file.stat().st_size,
        )

        preview = DesktopPreview(
            revision=0,
            items=(plan_item,),
            requires_review=False,
        )

        window._preview = preview
        window._apply_state()

        assert window.tabs.isVisible()
        assert not window._empty_panel.isVisible()
        assert window.sync_button.isVisible()
        assert "1 proposed change(s)" in window._preview_info.text()
        assert "1 to send" in window._preview_info.text()

        # Synchronization must retain the connected banner.
        window._busy = True
        window._move(DesktopPhase.SYNCHRONIZING)

        assert window.connection.text().startswith(
            "Connected to "
        )
        assert window.status.text() == "Synchronizing"
        assert "not connected" not in window.hint.text().lower()

        # The app should not expose conflicting actions during sync.
        assert not window.preview_button.isEnabled()
        assert not window.sync_button.isEnabled()

        # Return to the connected state.
        window._busy = False
        window._move(DesktopPhase.CONNECTED)

        assert window.connection.text().startswith(
            "Connected to "
        )

        # Disconnect removes the file controls again.
        window._preview = None
        window._live_session = None
        controller.running = False

        window._move(DesktopPhase.DISCONNECTING)
        window._move(DesktopPhase.DISCONNECTED)

        assert not window.tabs.isVisible()
        assert window._empty_panel.isVisible()
        assert not window.sync_button.isVisible()
        assert window._fresh_action.isEnabled()

        # GUI-only operations must never modify user files.
        assert test_file.read_text(
            encoding="utf-8"
        ) == "SyncBridge UI regression test"

    finally:
        window._close_allowed = True
        window.close()
        app.setQuitOnLastWindowClosed(before)


def test_polished_desktop_reuses_core_controls_and_simplifies_states(
    tmp_path, monkeypatch
):
    pytest.importorskip("PySide6")

    if os.environ.get(CHILD) == "1":
        _exercise(tmp_path, monkeypatch)
        return

    env = os.environ.copy()
    env[CHILD] = "1"
    env["QT_QPA_PLATFORM"] = "offscreen"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            __file__,
            "-q",
            "-s",
        ],
        cwd=Path(__file__).resolve().parents[2],
        env=env,
        text=True,
        capture_output=True,
        timeout=45,
        check=False,
    )

    assert result.returncode == 0, (
        result.stdout + "\n" + result.stderr
    )
