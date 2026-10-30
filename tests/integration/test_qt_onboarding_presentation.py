
"""Presentation checks for actual discovery, approval, and folder dialogs."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

CHILD = "SYNCBRIDGE_PRESENTATION_QT_CHILD"


def _exercise(tmp_path: Path, monkeypatch) -> None:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import (
        QApplication,
        QFileDialog,
        QLabel,
        QWidget,
    )

    from syncbridge.ui.qt_onboarding import (
        ConnectDialog,
        DevicesDialog,
        FolderRequestDialog,
    )
    from syncbridge.ui.qt_onboarding_presentation import (
        install_onboarding_presentation,
        present_dialog,
    )

    app = QApplication.instance() or QApplication([])
    previous = app.quitOnLastWindowClosed()
    app.setQuitOnLastWindowClosed(False)

    presenter = install_onboarding_presentation(app)

    parent = QWidget()
    peer = SimpleNamespace(
        node_id="a" * 32,
        name="Cruz",
    )
    requested = []

    class Bridge:
        stopping = False
        pairing = SimpleNamespace(
            trusted=lambda _id: False
        )

        def devices(self):
            return (peer,)

        def device(self, node_id):
            return (
                peer
                if node_id == peer.node_id
                else None
            )

        def select_device(self, selected):
            requested.append(selected)

    devices = DevicesDialog(parent, Bridge())

    pairing_calls = []
    rejected = []

    pairing = ConnectDialog(
        parent,
        SimpleNamespace(
            remote_name="Cruz",
            address="127.0.0.1",
            code="abcd",
        ),
        pairing_calls.append,
        lambda: rejected.append(True),
    )

    folder_calls = []

    folder = FolderRequestDialog(
        parent,
        SimpleNamespace(
            peer_name="Cruz",
            request_id="d" * 32,
        ),
        lambda request_id, directory: folder_calls.append(
            (request_id, directory)
        ),
        lambda request_id: rejected.append(request_id),
    )

    selected_root = tmp_path / "selected"
    selected_root.mkdir()

    monkeypatch.setattr(
        QFileDialog,
        "getExistingDirectory",
        lambda *args, **kwargs: str(selected_root),
    )

    try:
        devices.show()
        pairing.show()
        folder.show()
        app.processEvents()

        for dialog in (devices, pairing, folder):
            assert dialog.property(
                "syncbridgePresented"
            ) is True
            assert dialog.objectName() == "syncbridgeOnboarding"

            title = dialog.layout().itemAt(0).widget()
            assert isinstance(title, QLabel)
            assert (
                title.textFormat()
                == Qt.TextFormat.PlainText
            )

        # Reapplying presentation must not duplicate widgets.
        present_dialog(devices)
        present_dialog(devices)

        assert len(
            devices.findChildren(QLabel, "dialogHelp")
        ) == 1

        assert devices.listing.count() == 1
        assert devices.connect_button.isEnabled()

        devices.connect_button.click()

        assert requested == [peer]

        # The visual styling cannot bypass pairing approval.
        assert pairing.yes.text() == "Approve connection"

        pairing.yes.click()

        assert pairing_calls == ["abcd"]
        assert not pairing.yes.isEnabled()
        assert rejected == []

        # Folder selection still uses the original approve callback.
        assert folder.yes.text() == "Choose folder"

        folder.yes.click()

        assert folder_calls == [
            ("d" * 32, str(selected_root))
        ]
        assert rejected == []

    finally:
        folder.close()
        pairing.close()
        devices.close()
        parent.close()
        app.removeEventFilter(presenter)
        app.setQuitOnLastWindowClosed(previous)


def test_dialog_presentation_preserves_original_actions(
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
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )

    assert result.returncode == 0, (
        result.stdout + "\n" + result.stderr
    )
