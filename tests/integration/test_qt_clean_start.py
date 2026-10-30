
"""Verify Start fresh through the GUI and reapproval of known computers."""
from __future__ import annotations

import os
import queue
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

_CHILD = "SYNCBRIDGE_QT_CLEAN_START_CHILD"


def _exercise(tmp_path, monkeypatch):
    from PySide6.QtWidgets import QApplication, QMessageBox

    from syncbridge.network.security import (
        DeviceIdentity,
        TrustStore,
        load_or_create_identity,
    )
    from syncbridge.storage.config import ConfigStore, ShareConfig
    from syncbridge.ui.nearby_devices import NearbyDevice
    from syncbridge.ui.qt_clean_start_window import (
        ReapprovingOnboarding,
        SyncBridgeCleanStartWindow,
    )
    from syncbridge.ui.qt_onboarding import NetworkOptions

    profile = tmp_path / "Profile"
    profile.mkdir()

    root = tmp_path / "Shared"
    root.mkdir()

    original_file = root / "keep.txt"
    original_file.write_text("keep forever", encoding="utf-8")

    own = load_or_create_identity(profile / "identity.json")
    other = DeviceIdentity.generate()

    trust = TrustStore(profile / "trust.json")
    trust.add_verified(
        other.public_key_hex,
        confirmed_fingerprint=other.fingerprint,
        name="Cruz",
    )

    store = ConfigStore(profile / "settings.json")

    share = ShareConfig(
        share_id="a" * 32,
        peer_node_id=other.node_id,
        local_root=str(root),
        display_name="Old files",
        enabled=True,
        grant_manifest=True,
        grant_read=True,
        grant_write=True,
        grant_agreement=True,
        remote_host="127.0.0.1",
    )

    store.save(replace(store.load(), shares=(share,)))

    class Controller:
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
        SyncBridgeCleanStartWindow,
        "_start_network",
        offline_network,
    )

    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *a, **k: QMessageBox.StandardButton.Yes,
    )

    app = QApplication.instance() or QApplication([])
    old = app.quitOnLastWindowClosed()
    app.setQuitOnLastWindowClosed(False)

    window = SyncBridgeCleanStartWindow(
        Controller(),
        network_options=NetworkOptions(),
    )

    window.show()

    try:
        app.processEvents()

        assert window.fresh_button.isVisible()
        assert window.fresh_button.isEnabled()
        assert window.reconnect_button.isVisible()
        assert store.load().shares == (share,)

        # Exercise the same GUI action that a real user clicks.
        window.fresh_button.click()

        assert window._fresh_busy, (
            "Start fresh did not begin after the button was clicked. "
            f"Status: {window.status.text()!r}; "
            f"Message: {window.summary.text()!r}; "
            f"Phase: {window.lifecycle.phase.value!r}"
        )

        deadline = time.monotonic() + 15.0

        while time.monotonic() < deadline:
            app.processEvents()
            window._drain()

            if not window._fresh_busy:
                break

            time.sleep(0.02)

        assert not window._fresh_busy, (
            "Start fresh did not finish within 15 seconds. "
            f"Status: {window.status.text()!r}; "
            f"Message: {window.summary.text()!r}"
        )

        current = store.load()

        assert current.shares == (), (
            "The GUI's Start fresh operation finished without clearing "
            "the saved folder relationship. "
            f"Status: {window.status.text()!r}; "
            f"Message: {window.summary.text()!r}; "
            f"Shares remaining: {len(current.shares)}"
        )

        assert TrustStore(profile / "trust.json").devices == (), (
            "Start fresh left previously trusted computers in the profile."
        )

        assert window._network_started, (
            "Start fresh cleared the settings but did not restart "
            "the desktop's network setup. "
            f"Status: {window.status.text()!r}; "
            f"Message: {window.summary.text()!r}"
        )

        assert window.find_button.isEnabled()

        # A reset must not modify synchronized user files.
        assert original_file.read_text(
            encoding="utf-8"
        ) == "keep forever"

        # A reset must not replace the local cryptographic device identity.
        assert load_or_create_identity(
            profile / "identity.json"
        ).node_id == own.node_id

    finally:
        window._close_allowed = True
        window.close()
        app.setQuitOnLastWindowClosed(old)

    # A previously trusted peer must still initiate a new approval request.
    asked = []
    session = object()

    class Client:
        def request(
            self,
            host,
            port,
            *,
            expected_node_id,
            approval_timeout,
        ):
            asked.append(
                (
                    host,
                    port,
                    expected_node_id,
                    approval_timeout,
                )
            )
            return session

    onboarding = object.__new__(ReapprovingOnboarding)

    onboarding.pairing = SimpleNamespace(
        trusted=lambda _id: True,
        client=Client(),
        approval_timeout=120.0,
    )

    onboarding._pair_busy = False
    onboarding.stopping = False
    onboarding.events = queue.SimpleQueue()
    onboarding.devices_dialog = None
    onboarding._spawn = lambda _name, callback: callback()

    onboarding.on_paired = lambda _name: pytest.fail(
        "Pair approval was bypassed"
    )

    peer = NearbyDevice(
        other.node_id,
        "Cruz",
        "127.0.0.1",
        45841,
        45840,
    )

    onboarding.select_device(peer)

    kind, value = onboarding.events.get_nowait()

    assert kind == "pair_session"
    assert value is session

    assert asked == [
        (
            "127.0.0.1",
            45840,
            other.node_id,
            120.0,
        )
    ]


def test_qt_start_fresh_and_known_peer_reapproval(
    tmp_path, monkeypatch
):
    pytest.importorskip("PySide6")

    if os.environ.get(_CHILD) == "1":
        _exercise(tmp_path, monkeypatch)
        return

    env = os.environ.copy()
    env[_CHILD] = "1"
    env["QT_QPA_PLATFORM"] = "offscreen"

    completed = subprocess.run(
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
        timeout=55,
        check=False,
    )

    assert completed.returncode == 0, (
        completed.stdout + "\n" + completed.stderr
    )
