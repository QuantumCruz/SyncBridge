
"""Verify first-run Qt pairing and folder consent in an isolated process.

The parent pytest process never constructs a QApplication. Real Qt event-loop,
networking, and threading behavior is exercised by a dedicated pytest child.
This prevents Qt object lifetimes from affecting unrelated tests in a large
pytest session. The child uses disposable test profiles and loopback ports.

Run:
    python -m pytest tests/integration/test_qt_fresh_onboarding.py -v -s
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest


_CHILD_ENV = "SYNCBRIDGE_FRESH_QT_ONBOARDING_CHILD"


def _until(app, description, condition, *, timeout=35.0, windows=(), warnings=()):
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        app.processEvents()
        if condition():
            return
        time.sleep(0.025)

    states = [
        (
            window.windowTitle(),
            window.status.text(),
            window.summary.text(),
            window.controller.running,
            window.onboarding.started if window.onboarding else None,
        )
        for window in windows
    ]
    pytest.fail(
        f"Timed out waiting for {description}. "
        f"Desktop states: {states!r}; warnings: {list(warnings)!r}"
    )


def _options(name, own, other):
    from syncbridge.ui.qt_onboarding import NetworkOptions

    discovery, pairing, setup, activation = own
    other_discovery, _, other_setup, other_activation = other
    return NetworkOptions(
        name=name,
        discovery_port=discovery,
        discovery_bind="127.0.0.1",
        discovery_targets=(("127.0.0.1", other_discovery),),
        pairing_port=pairing,
        pairing_bind="127.0.0.1",
        setup_port=setup,
        remote_setup_port=other_setup,
        activation_port=activation,
        remote_activation_port=other_activation,
    )


def _exercise_onboarding(tmp_path, monkeypatch):
    # Import Qt only inside the child; the parent must never own QApplication.
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox
    from syncbridge.storage.config import ConfigStore
    from syncbridge.ui.desktop_controller import DesktopController
    from syncbridge.ui.qt_progress_window import SyncBridgeProgressWindow
    from test_desktop_crash_resume import _ports

    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication([])
    previous_setting = app.quitOnLastWindowClosed()
    app.setQuitOnLastWindowClosed(False)

    all_ports = _ports(16)
    lock_port, validation_port = all_ports[6:8]
    alice_network = tuple(all_ports[8:12])
    bob_network = tuple(all_ports[12:16])
    warnings = []

    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda _parent, title, message, *args, **kwargs: (
            warnings.append((str(title), str(message)))
            or QMessageBox.StandardButton.Ok
        ),
    )

    selections: list[str] = []

    def select_test_folder(*_args, **_kwargs):
        if not selections:
            raise AssertionError("Unexpected folder chooser request")
        return selections.pop(0)

    monkeypatch.setattr(
        QFileDialog,
        "getExistingDirectory",
        select_test_folder,
    )

    windows = {}
    profiles = {}
    folders = {}
    stores = {}

    try:
        for name, own_ports, own_network, remote_network in (
            ("Alice", all_ports[:3], alice_network, bob_network),
            ("Bob", all_ports[3:6], bob_network, alice_network),
        ):
            profile = tmp_path / name / "Profile"
            folder = tmp_path / name / "Shared"
            profile.mkdir(parents=True)
            folder.mkdir(parents=True)
            store = ConfigStore(profile / "settings.json")

            assert store.load().shares == ()
            assert not (profile / "trust.json").exists()

            controller = DesktopController(
                store,
                bind_address="127.0.0.1",
                listen_ports=tuple(own_ports),
                lock_port=lock_port,
                validation_port=validation_port,
            )
            window = SyncBridgeProgressWindow(
                controller,
                network_options=_options(name, own_network, remote_network),
            )
            windows[name] = window
            profiles[name] = profile
            folders[name] = folder
            stores[name] = store
            window.show()

        alice = windows["Alice"]
        bob = windows["Bob"]
        pair = (alice, bob)

        _until(
            app,
            "both network services to start",
            lambda: all(w.onboarding.started for w in pair),
            windows=pair,
            warnings=warnings,
        )
        _until(
            app,
            "each computer to discover the other",
            lambda: (
                any(peer.name == "Bob" for peer in alice.onboarding.devices())
                and any(peer.name == "Alice" for peer in bob.onboarding.devices())
            ),
            windows=pair,
            warnings=warnings,
        )

        peer_bob = next(
            peer for peer in alice.onboarding.devices() if peer.name == "Bob"
        )
        peer_alice = next(
            peer for peer in bob.onboarding.devices() if peer.name == "Alice"
        )

        assert not alice.onboarding.pairing.trusted(peer_bob.node_id)
        assert not bob.onboarding.pairing.trusted(peer_alice.node_id)

        alice.onboarding.select_device(peer_bob)
        _until(
            app,
            "both pairing consent windows",
            lambda: (
                bool(alice.onboarding.pair_dialogs)
                and bool(bob.onboarding.pair_dialogs)
            ),
            windows=pair,
            warnings=warnings,
        )

        alice_dialog = next(iter(alice.onboarding.pair_dialogs.values()))
        bob_dialog = next(iter(bob.onboarding.pair_dialogs.values()))

        assert alice_dialog.details.code == bob_dialog.details.code
        assert alice_dialog.details.remote_node_id == peer_bob.node_id
        assert bob_dialog.details.remote_node_id == peer_alice.node_id

        bob_dialog.yes.click()
        alice_dialog.yes.click()

        _until(
            app,
            "signed mutual trust to be saved",
            lambda: (
                alice.onboarding.pairing.trusted(peer_bob.node_id)
                and bob.onboarding.pairing.trusted(peer_alice.node_id)
            ),
            windows=pair,
            warnings=warnings,
        )

        # Pairing alone never authorizes file access.
        assert not stores["Alice"].load().shares
        assert not stores["Bob"].load().shares
        assert not alice.controller.running
        assert not bob.controller.running

        selections.append(str(folders["Alice"]))
        _until(
            app,
            "Alice's folder button to become available",
            lambda: alice.folder_select_button.isEnabled(),
            windows=pair,
            warnings=warnings,
        )
        alice.folder_select_button.click()

        _until(
            app,
            "Bob's incoming folder request",
            lambda: bool(bob.onboarding.folder_dialogs),
            windows=pair,
            warnings=warnings,
        )
        for store in stores.values():
            assert not any(share.enabled for share in store.load().shares)

        selections.append(str(folders["Bob"]))
        bob_folder_dialog = next(iter(bob.onboarding.folder_dialogs.values()))
        bob_folder_dialog.yes.click()

        def both_enabled():
            return all(
                len(store.load().shares) == 1
                and store.load().shares[0].enabled
                for store in stores.values()
            )

        _until(
            app,
            "both consented folders to activate",
            both_enabled,
            timeout=55,
            windows=pair,
            warnings=warnings,
        )
        _until(
            app,
            "both guarded desktops to connect",
            lambda: (
                alice.controller.running
                and bob.controller.running
                and not alice._busy
                and not bob._busy
            ),
            timeout=40,
            windows=pair,
            warnings=warnings,
        )

        a_share = stores["Alice"].load().shares[0]
        b_share = stores["Bob"].load().shares[0]

        assert a_share.share_id == b_share.share_id
        assert a_share.peer_node_id == peer_bob.node_id
        assert b_share.peer_node_id == peer_alice.node_id
        assert Path(a_share.local_root).resolve() == folders["Alice"].resolve()
        assert Path(b_share.local_root).resolve() == folders["Bob"].resolve()
        assert a_share.remote_host == b_share.remote_host == "127.0.0.1"

        for share in (a_share, b_share):
            assert all(
                (
                    share.grant_manifest,
                    share.grant_read,
                    share.grant_write,
                    share.grant_agreement,
                )
            )
            assert not share.preferences.auto_apply

        assert (profiles["Alice"] / "identity.json").exists()
        assert (profiles["Bob"] / "identity.json").exists()
        assert not selections
        assert not warnings, f"Unexpected desktop warnings: {warnings!r}"
    finally:
        for window in windows.values():
            window.close()
        if windows:
            _until(
                app,
                "both desktop windows to shut down cleanly",
                lambda: all(not window.isVisible() for window in windows.values()),
                timeout=25,
                windows=tuple(windows.values()),
                warnings=warnings,
            )
        app.setQuitOnLastWindowClosed(previous_setting)


def test_fresh_qt_desktops_pair_and_connect_user_chosen_folders(
    tmp_path, monkeypatch
):
    if os.environ.get(_CHILD_ENV) == "1":
        _exercise_onboarding(tmp_path, monkeypatch)
        return

    # The main suite must not import Qt or create a QApplication.
    # Run the real test in a dedicated process, without mocking or skipping.
    project = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env[_CHILD_ENV] = "1"
    env["QT_QPA_PLATFORM"] = "offscreen"
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "-s",
        str(Path(__file__).resolve()),
        "-k",
        "test_fresh_qt_desktops_pair_and_connect_user_chosen_folders",
    ]
    try:
        result = subprocess.run(
            command,
            cwd=project,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=125,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(
            "Fresh Qt onboarding child process exceeded 125 seconds. "
            f"Captured output: {exc.stdout!r}",
            pytrace=False,
        )

    if result.returncode != 0:
        pytest.fail(
            "Isolated first-run Qt onboarding failed "
            f"(exit code {result.returncode}).\n{result.stdout}",
            pytrace=False,
        )
