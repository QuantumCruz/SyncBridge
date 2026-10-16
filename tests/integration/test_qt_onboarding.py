
"""Qt consent tests for simple two-person connection and folder selection."""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication

from syncbridge.network.pairing import PairingDetails
from syncbridge.network.share_setup import IncomingShareRequest
import syncbridge.ui.qt_onboarding as module
from syncbridge.ui.qt_onboarding import ConnectDialog, FolderRequestDialog


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def details():
    return PairingDetails(
        request_id="req",
        remote_name="Bob",
        remote_node_id="b" * 32,
        remote_fingerprint="b" * 64,
        address="127.0.0.1",
        code="ABCD-1234-5678-EF90",
    )


def test_connection_only_approves_after_person_clicks(app):
    approvals = []
    rejections = []

    dialog = ConnectDialog(
        None,
        details(),
        approvals.append,
        lambda: rejections.append(True),
    )

    try:
        dialog.show()
        app.processEvents()

        assert not approvals

        dialog.accept_connection()

        assert approvals == [details().code]
        assert not rejections
    finally:
        dialog.close()

    assert not rejections


def test_declining_connection_does_not_approve(app):
    approvals = []
    rejections = []

    dialog = ConnectDialog(
        None,
        details(),
        approvals.append,
        lambda: rejections.append(True),
    )

    dialog.reject_connection()

    assert not approvals
    assert rejections == [True]


def test_folder_request_requires_local_folder_choice(app, monkeypatch):
    request = IncomingShareRequest(
        request_id="req",
        share_id="a" * 32,
        peer_node_id="b" * 32,
        peer_name="Bob",
        display_name="Documents",
        peer_address="127.0.0.1",
        peer_ports=(45843, 45842, 45844),
    )

    approvals, rejections = [], []

    dialog = FolderRequestDialog(
        None,
        request,
        lambda *args: approvals.append(args),
        rejections.append,
    )

    try:
        dialog.show()
        app.processEvents()

        monkeypatch.setattr(
            module,
            "QFileDialog",
            SimpleNamespace(
                getExistingDirectory=lambda *a, **k: ""
            ),
        )

        dialog.choose()
        assert not approvals

        monkeypatch.setattr(
            module,
            "QFileDialog",
            SimpleNamespace(
                getExistingDirectory=lambda *a, **k: "C:/Temp/Shared"
            ),
        )

        dialog.choose()

        assert approvals == [
            ("req", "C:/Temp/Shared")
        ]
        assert not rejections

    finally:
        dialog.close()


def test_sync_listener_uses_unicast_for_local_demo():
    from syncbridge.ui.qt_window import local_address_for_peer

    assert local_address_for_peer("127.0.0.1") == "127.0.0.1"

    with pytest.raises(ValueError):
        local_address_for_peer("0.0.0.0")
