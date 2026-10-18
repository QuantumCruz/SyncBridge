
"""Safe folder switching from the release Qt desktop.

Runs Qt in a subprocess so native Qt threads cannot affect other test suites.
Uses only disposable profiles, and does not start any network listeners.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

_CHILD = "SYNCBRIDGE_QT_FOLDER_SWITCH_CHILD"


def _exercise(tmp_path, monkeypatch) -> None:
    pytest.importorskip("PySide6")

    from uuid import uuid4
    from PySide6.QtWidgets import QApplication, QMessageBox
    from syncbridge.storage.config import AppConfig, ConfigStore, ShareConfig
    from syncbridge.ui.desktop_controller import DesktopController
    from syncbridge.ui.qt_folder_switch_window import SyncBridgeFolderWindow

    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication([])
    original_quit = app.quitOnLastWindowClosed()
    app.setQuitOnLastWindowClosed(False)

    class Runtime:
        def __init__(self, store, **kwargs):
            self.store = store
            self.bind_address = kwargs.get("bind_address", "127.0.0.1")
            self.listen_ports = kwargs.get("listen_ports")
            self.active = False
            self.stop_calls = 0

        def start(self, *, background=False):
            assert background is False
            self.active = True

        def stop(self):
            self.stop_calls += 1
            self.active = False

    profile = tmp_path / "Profile"
    profile.mkdir()
    folder = tmp_path / "Original Files"
    folder.mkdir()
    original = folder / "retain.txt"
    original.write_text("Keep this untouched", encoding="utf-8")

    store = ConfigStore(profile / "settings.json")
    share_id = uuid4().hex
    peer_id = uuid4().hex
    store.save(
        AppConfig(
            device_name="Alice",
            shares=(
                ShareConfig(
                    share_id=share_id,
                    peer_node_id=peer_id,
                    local_root=str(folder),
                    display_name="Original Files",
                    remote_host="127.0.0.1",
                    enabled=True,
                ),
            ),
        )
    )

    identity = profile / "identity.json"
    trust = profile / "trust.json"
    identity.write_bytes(b"keep identity unchanged")
    trust.write_bytes(b"keep trust unchanged")

    controller = DesktopController(store, runtime_factory=Runtime)
    window = SyncBridgeFolderWindow(controller)
    window.show()

    def until(condition, *, timeout=10.0):
        deadline = time.perf_counter() + timeout
        while time.perf_counter() < deadline:
            app.processEvents()
            if condition():
                return
            time.sleep(0.02)

        pytest.fail(
            "Folder change did not reach its expected state: "
            f"busy={window._busy}, running={controller.running}, "
            f"status={window.status.text()!r}, "
            f"shares={len(store.load().shares)}"
        )

    try:
        until(lambda: controller.running and not window._busy)
        assert window.folder_select_button.text() == "Change folders"
        assert window.folder_select_button.isEnabled()
        assert controller.runtime.active

        # A new incoming share must be blocked until the owner releases the old.
        accepted = []

        def accept(request_id, root):
            accepted.append((request_id, root))

        with pytest.raises(RuntimeError, match="Change folders"):
            window._approve_new_folder(accept, "r1", str(folder))
        assert accepted == []

        # Declining must preserve the running connection and saved share.
        monkeypatch.setattr(
            QMessageBox,
            "question",
            lambda *a, **kw: QMessageBox.StandardButton.No,
        )
        window.folder_select_button.click()
        app.processEvents()

        assert controller.running
        assert store.load().shares[0].share_id == share_id
        assert controller.runtime.stop_calls == 0

        monkeypatch.setattr(
            QMessageBox,
            "question",
            lambda *a, **kw: QMessageBox.StandardButton.Yes,
        )
        window.folder_select_button.click()

        until(
            lambda: (
                not window._busy
                and not window._changing_folders
                and not store.load().shares
            )
        )

        assert not controller.running
        assert controller.runtime.stop_calls == 1
        assert not controller.runtime.active
        assert window.folder_select_button.text() == "Choose my folder"
        assert original.read_text(encoding="utf-8") == "Keep this untouched"
        assert identity.read_bytes() == b"keep identity unchanged"
        assert trust.read_bytes() == b"keep trust unchanged"
        assert "paired" in window.summary.text().lower()

        # After explicitly ending the old relationship, a new folder
        # approval may proceed through the existing consent protocol.
        window._approve_new_folder(accept, "r2", str(tmp_path / "New"))
        assert accepted == [("r2", str(tmp_path / "New"))]

    finally:
        window.close()
        until(lambda: not window.isVisible())
        app.setQuitOnLastWindowClosed(original_quit)


def test_qt_change_folders_preserves_files_and_pairing(tmp_path, monkeypatch):
    if os.environ.get(_CHILD) == "1":
        _exercise(tmp_path, monkeypatch)
        return

    project = Path(__file__).resolve().parents[2]
    environment = os.environ.copy()
    environment[_CHILD] = "1"
    environment["QT_QPA_PLATFORM"] = "offscreen"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-s",
            str(Path(__file__).resolve()),
            "-k",
            "test_qt_change_folders_preserves_files_and_pairing",
        ],
        cwd=project,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        timeout=75,
        check=False,
    )

    assert result.returncode == 0, (
        f"Isolated folder-switch test failed ({result.returncode}):\n"
        f"{result.stdout}"
    )
