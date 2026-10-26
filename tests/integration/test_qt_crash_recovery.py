
"""The packaged-style Qt launch must stay offline after interrupted changes."""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

_CHILD = "SYNCBRIDGE_CRASH_RECOVERY_QT_CHILD"


def _exercise(tmp_path: Path, monkeypatch) -> None:
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication, QMessageBox

    from syncbridge.network.security import (
        DeviceIdentity,
        TrustStore,
        load_or_create_identity,
    )
    from syncbridge.storage.config import ConfigStore, ShareConfig
    from syncbridge.storage.folder_change_recovery import FolderChangeJournal
    from syncbridge.ui.qt_crash_recovery_window import (
        SyncBridgeCrashRecoveryWindow,
    )
    from syncbridge.ui.qt_onboarding import NetworkOptions

    profile = tmp_path / "profile"
    profile.mkdir()
    root = tmp_path / "Original files"
    root.mkdir()
    (root / "keep.txt").write_text("kept", encoding="utf-8")

    load_or_create_identity(profile / "identity.json")
    other = DeviceIdentity.generate()
    TrustStore(profile / "trust.json").add_verified(
        other.public_key_hex,
        confirmed_fingerprint=other.fingerprint,
        name="Other laptop",
    )

    store = ConfigStore(profile / "settings.json")
    share = ShareConfig(
        share_id="a" * 32,
        peer_node_id=other.node_id,
        local_root=str(root),
        display_name="Earlier folder",
        remote_host="127.0.0.1",
        enabled=True,
        grant_manifest=True,
        grant_read=True,
        grant_write=True,
        grant_agreement=True,
    )
    store.save(replace(store.load(), shares=(share,)))

    journal = FolderChangeJournal(store)
    journal.begin("c" * 32, share)

    class Controller:
        def __init__(self):
            self.store = store
            self.runtime = SimpleNamespace(listen_ports=None)
            self.running = False

        def stop(self):
            self.running = False

    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *args, **kwargs: QMessageBox.StandardButton.Yes,
    )

    app = QApplication.instance() or QApplication([])
    prior = app.quitOnLastWindowClosed()
    app.setQuitOnLastWindowClosed(False)

    window = SyncBridgeCrashRecoveryWindow(
        Controller(),
        network_options=NetworkOptions(),
    )
    window.show()

    try:
        app.processEvents()
        app.processEvents()

        assert window._recovery_required
        assert not window._network_started
        assert window.restore_button.isVisible()
        assert window.restore_button.isEnabled()
        assert not window.find_button.isEnabled()
        assert not window.reconnect_button.isEnabled()
        assert not window.folder_select_button.isVisible()
        assert journal.load() is not None

        window.restore_button.click()

        assert journal.load() is None
        assert store.load().shares == (share,)
        assert not window._network_started
        assert (
            root / "keep.txt"
        ).read_text(encoding="utf-8") == "kept"

    finally:
        window._close_allowed = True
        window.close()
        app.setQuitOnLastWindowClosed(prior)


def test_qt_interrupted_change_never_auto_connects(
    tmp_path, monkeypatch
):
    pytest.importorskip("PySide6")

    if os.environ.get(_CHILD) == "1":
        _exercise(tmp_path, monkeypatch)
        return

    env = os.environ.copy()
    env[_CHILD] = "1"
    env["QT_QPA_PLATFORM"] = "offscreen"

    result = subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-q", "-s"],
        cwd=Path(__file__).resolve().parents[2],
        env=env,
        capture_output=True,
        text=True,
        timeout=40,
        check=False,
    )
    assert result.returncode == 0, (
        result.stdout + "\n" + result.stderr
    )
