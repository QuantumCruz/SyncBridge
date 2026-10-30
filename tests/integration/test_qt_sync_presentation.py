
"""Validate the polished synchronization interface without network traffic."""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

CHILD = "SYNCBRIDGE_SYNC_PRESENTATION_CHILD"


def _exercise(tmp_path: Path, monkeypatch) -> None:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication

    from syncbridge.storage.config import ConfigStore, ShareConfig
    from syncbridge.ui.desktop_controller import DesktopPhase
    from syncbridge.ui.qt_onboarding import NetworkOptions
    from syncbridge.ui.qt_polished_window import SyncBridgePolishedWindow

    profile = tmp_path / "profile"
    profile.mkdir()

    folder = tmp_path / "shared"
    folder.mkdir()

    (folder / "keep.txt").write_text(
        "Preserve this file", encoding="utf-8"
    )

    store = ConfigStore(profile / "settings.json")
    share = ShareConfig(
        share_id="a" * 32,
        peer_node_id="b" * 32,
        local_root=str(folder),
        display_name="Files",
        remote_host="127.0.0.1",
        enabled=True,
        grant_manifest=True,
        grant_read=True,
        grant_write=True,
        grant_agreement=True,
    )
    store.save(replace(store.load(), shares=(share,)))

    class Controller:
        def __init__(self):
            self.store = store
            self.runtime = SimpleNamespace(listen_ports=None)
            self.running = False

        def stop(self):
            self.running = False

    def no_network(window):
        window._network_started = True
        window._apply_state()

    monkeypatch.setattr(
        SyncBridgePolishedWindow,
        "_start_network",
        no_network,
    )

    app = QApplication.instance() or QApplication([])
    previous = app.quitOnLastWindowClosed()
    app.setQuitOnLastWindowClosed(False)

    controller = Controller()
    window = SyncBridgePolishedWindow(
        controller,
        network_options=NetworkOptions(),
    )
    window.show()

    try:
        app.processEvents()

        assert window._empty_panel.isVisible()
        assert not window._transfer_card.isVisible()
        assert not window._preview_info.isVisible()
        assert not window.sync_button.isVisible()

        # Simulate an approved connection without using any sockets.
        window._move(DesktopPhase.CONNECTING)
        window._live_session = "c" * 32
        controller.running = True
        window._move(DesktopPhase.CONNECTED)

        assert window.preview_button.isVisible()
        assert not window.sync_button.isVisible()

        # Review-only changes must never enable synchronization.
        conflict = SimpleNamespace(
            action="Conflict",
            path="documents/important.txt",
            description="Both computers changed this file",
        )
        preview = SimpleNamespace(
            items=(conflict,),
            requires_review=True,
        )

        window._preview = preview
        window._display_preview(preview)
        app.processEvents()

        assert window.tabs.isVisible()
        assert not window.sync_button.isVisible()
        assert "Review required" in window._preview_info.text()
        assert (
            window.table.item(0, 1).toolTip()
            == "documents/important.txt"
        )

        # A safe preview presents accurate send/receive counts.
        send = SimpleNamespace(
            action="Send",
            path="reports/report.pdf",
            description="Copy this file to the other computer",
        )
        receive = SimpleNamespace(
            action="Receive",
            path="images/photo.png",
            description="Copy this file here",
        )

        preview = SimpleNamespace(
            items=(send, receive),
            requires_review=False,
        )
        window._preview = preview
        window._display_preview(preview)
        app.processEvents()

        assert "2 proposed change(s)" in window._preview_info.text()
        assert "1 to send" in window._preview_info.text()
        assert "1 to receive" in window._preview_info.text()
        assert window.sync_button.isVisible()

        # Previewing is read-only and has no fake transfer percentage.
        window._visual_operation = "preview"
        window._busy = True
        window._move(DesktopPhase.SYNCHRONIZING)
        app.processEvents()

        assert window._transfer_card.isVisible()
        assert window._transfer_title.text() == "Checking your files"
        assert window._file_progress.minimum() == 0
        assert window._file_progress.maximum() == 0

        # Use a transfer event matching the production event contract.
        # The transfer callback must not directly modify Qt widgets.
        window._visual_operation = "sync"
        window._transfer_filename.setText("")
        window._apply_state()

        event = SimpleNamespace(
            direction="send",
            path=r"reports\annual-report.pdf",
            transferred=512,
            total=1024,
        )
        window._transfer_progress(event)
        window._drain()
        app.processEvents()

        assert window._transfer_card.isVisible()
        assert window._transfer_title.text() == "Sending file"
        assert window._transfer_filename.text() == "annual-report.pdf"
        assert window._file_progress.value() == 500
        assert "50%" in window._transfer_detail.text()
        assert "of this file" in window._transfer_detail.text()
        assert not window.progress.isVisible()

        received = SimpleNamespace(
            direction="receive",
            path="images/photo.png",
            transferred=300,
            total=400,
        )
        window._transfer_progress(received)
        window._drain()

        assert window._transfer_title.text() == "Receiving file"
        assert window._file_progress.value() == 750
        assert "75%" in window._transfer_detail.text()

        # An incomplete operation must not receive a success message.
        window.summary.setText(
            "Some changes need attention. Preview again before retrying."
        )
        window._busy = False
        window._move(DesktopPhase.CONNECTED)
        window._drain()
        app.processEvents()

        assert window._result_card.isVisible()
        assert (
            window._result_card.property("tone")
            == "warning"
        )
        assert "attention" in window._result_title.text().lower()

        # A reported successful operation gets completion feedback,
        # without claiming a second verification occurred automatically.
        window._visual_operation = "sync"
        window._busy = True
        window._move(DesktopPhase.SYNCHRONIZING)
        window.summary.setText(
            "Synchronization finished. Preview again to check changes."
        )
        window._busy = False
        window._move(DesktopPhase.CONNECTED)
        window._drain()
        app.processEvents()

        assert window._result_card.isVisible()
        assert (
            window._result_card.property("tone")
            == "success"
        )
        assert "Preview again" in window._result_detail.text()

        # Disconnecting removes the transfer and preview display.
        window._preview = None
        window._live_session = None
        controller.running = False
        window._move(DesktopPhase.DISCONNECTING)
        window._move(DesktopPhase.DISCONNECTED)
        app.processEvents()

        assert not window._transfer_card.isVisible()
        assert not window._result_card.isVisible()
        assert not window.sync_button.isVisible()
        assert not window.tabs.isVisible()

        assert (
            folder / "keep.txt"
        ).read_text(encoding="utf-8") == "Preserve this file"

    finally:
        window._close_allowed = True
        window.close()
        app.setQuitOnLastWindowClosed(previous)


def test_polished_sync_interface_preserves_safety(
    tmp_path, monkeypatch
):
    pytest.importorskip("PySide6")

    if os.environ.get(CHILD) == "1":
        _exercise(tmp_path, monkeypatch)
        return

    environment = os.environ.copy()
    environment[CHILD] = "1"
    environment["QT_QPA_PLATFORM"] = "offscreen"

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
        env=environment,
        text=True,
        capture_output=True,
        timeout=55,
        check=False,
    )

    assert result.returncode == 0, (
        result.stdout + "\n" + result.stderr
    )
