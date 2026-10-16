
"""Local computer switching must never delete files or silently keep grants."""
from __future__ import annotations

from pathlib import Path

import pytest

from syncbridge.storage.config import AppConfig, ConfigStore, ShareConfig
from syncbridge.ui.connection_switch import (
    ConnectionSwitchError,
    forget_local_folder_connection,
)
from syncbridge.ui.readiness_jobs import ReadinessJobs


@pytest.fixture
def connection(tmp_path: Path):
    root = tmp_path / "Shared"
    root.mkdir()
    sample = root / "my_file.txt"
    sample.write_text("Don't delete my files!", encoding="utf-8")
    store = ConfigStore(tmp_path / "Profile" / "settings.json")
    share = ShareConfig(
        share_id="a" * 32,
        peer_node_id="b" * 32,
        local_root=str(root),
        display_name="Family Documents",
        remote_host="127.0.0.1",
        enabled=True,
        grant_manifest=True,
        grant_read=True,
        grant_write=True,
        grant_agreement=True,
    )
    store.save(AppConfig(device_name="Alice", shares=(share,)))
    return store, share, sample


def test_switch_forgets_local_share_without_deleting_files(connection):
    store, share, sample = connection
    removed = forget_local_folder_connection(
        store, expected_share_id=share.share_id, running=False
    )
    assert removed == share
    assert store.load().shares == ()
    assert sample.read_text(encoding="utf-8") == "Don't delete my files!"
    assert store.load().device_name == "Alice"


def test_switch_refuses_to_change_active_connection(connection):
    store, share, _ = connection
    with pytest.raises(ConnectionSwitchError, match="Disconnect"):
        forget_local_folder_connection(
            store, expected_share_id=share.share_id, running=True
        )
    assert store.load().get_share(share.share_id) == share


def test_switch_refuses_wrong_saved_relationship(connection):
    store, share, _ = connection
    with pytest.raises(ConnectionSwitchError, match="changed"):
        forget_local_folder_connection(
            store, expected_share_id="c" * 32, running=False
        )
    assert store.load().get_share(share.share_id) == share


def test_switch_discards_only_matching_readiness_job(connection):
    store, share, _ = connection
    journal = ReadinessJobs(store.path.parent)
    journal.add(share.share_id, share.peer_node_id)
    forget_local_folder_connection(
        store, expected_share_id=share.share_id, running=False
    )
    assert journal.entries() == ()


def test_switch_is_not_silent_on_multiple_relationships(connection, tmp_path):
    store, share, _ = connection
    other_root = tmp_path / "Other"
    other_root.mkdir()
    second = ShareConfig(
        share_id="c" * 32,
        peer_node_id="d" * 32,
        local_root=str(other_root),
        display_name="Other",
        remote_host="127.0.0.1",
    )
    existing = store.load()
    store.save(AppConfig(
        revision=existing.revision,
        device_name=existing.device_name,
        shares=(share, second),
    ))
    with pytest.raises(ConnectionSwitchError, match="multiple"):
        forget_local_folder_connection(
            store, expected_share_id=share.share_id, running=False
        )
    assert len(store.load().shares) == 2


def _qt_switch_window(store, monkeypatch, *, approve: bool):
    import os
    from types import SimpleNamespace

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication, QMessageBox
    from syncbridge.ui.desktop_controller import DesktopProfile
    from syncbridge.ui.qt_window import SyncBridgeQtWindow

    class FakeController:
        def __init__(self):
            self.store = store
            self.running = False

        def profile(self):
            share = self.store.load().shares[0]
            return DesktopProfile(
                device_name="Alice",
                folder_name=share.display_name,
                local_root=Path(share.local_root),
                peer_node_id=share.peer_node_id,
                remote_host=share.remote_host,
            )

        def stop(self):
            self.running = False

        def start(self):
            self.running = True

    app = QApplication.instance() or QApplication([])
    window = SyncBridgeQtWindow(FakeController())
    window._paused = True
    window.onboarding = SimpleNamespace(
        current_peer=SimpleNamespace(node_id="c" * 32, name="Charlie"),
        started=True,
        paired_device=lambda: SimpleNamespace(node_id="c" * 32, name="Charlie"),
        _pair_busy=False,
        _folder_busy=False,
    )
    monkeypatch.setattr(
        QMessageBox, "question",
        lambda *args, **kwargs: (
            QMessageBox.StandardButton.Yes if approve
            else QMessageBox.StandardButton.No
        ),
    )
    try:
        window._paired("Charlie")
        return window, app
    except Exception:
        window.onboarding = None
        window._allow_close = True
        window.close()
        raise


def test_qt_approving_switch_returns_to_folder_selection(connection, monkeypatch):
    store, old_share, sample = connection
    window, app = _qt_switch_window(store, monkeypatch, approve=True)
    try:
        assert store.load().shares == ()
        assert not window._configured
        assert not window._paused
        assert "Charlie" in window.connection.text()
        assert sample.is_file()
    finally:
        window.onboarding = None
        window._allow_close = True
        window.close()
        app.processEvents()


def test_qt_declining_switch_keeps_saved_relationship(connection, monkeypatch):
    store, old_share, sample = connection
    window, app = _qt_switch_window(store, monkeypatch, approve=False)
    try:
        assert store.load().get_share(old_share.share_id) == old_share
        assert window._configured
        assert window._paused
        assert sample.is_file()
    finally:
        window.onboarding = None
        window._allow_close = True
        window.close()
        app.processEvents()
