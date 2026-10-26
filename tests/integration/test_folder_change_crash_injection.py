
"""Two independent Windows processes: abrupt folder-change exit and Qt restart.

Each crash worker uses its own disposable profile and calls os._exit after a
specified durable checkpoint. The parent verifies both profiles, then opens
actual Qt recovery windows in independent subprocesses with network startup
explicitly forbidden. No real user folders, listeners, or transfers are used.

This tests local crash fences; it does NOT prove a distributed atomic commit.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from syncbridge.network.security import (
    DeviceIdentity,
    TrustStore,
    load_or_create_identity,
)
from syncbridge.storage.config import ConfigStore, ShareConfig
from syncbridge.storage.folder_change_recovery import FolderChangeJournal
from syncbridge.ui.connection_switch import forget_local_folder_connection

pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="Windows desktop recovery test"
)

SESSION = "c" * 32
SHARE = "a" * 32
REPLACEMENT = "d" * 32
CRASH_CODES = {
    "checkpoint": 71,
    "committing": 72,
    "cleared": 73,
    "replacement": 74,
}


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _create_profiles(tmp_path):
    identities = {}
    stores = {}
    roots = {}
    backups = {}

    for name in ("Alice", "Bob"):
        profile = tmp_path / name / "Profile"
        profile.mkdir(parents=True)
        original = tmp_path / name / "Original"
        original.mkdir()
        replacement = tmp_path / name / "Replacement"
        replacement.mkdir()
        marker = original / "sentinel.txt"
        marker.write_text(f"{name}: do not modify", encoding="utf-8")
        identities[name] = load_or_create_identity(profile / "identity.json")
        stores[name] = ConfigStore(profile / "settings.json")
        roots[name] = (original, replacement)
        backups[name] = {
            "marker": _hash(marker),
            "identity": _hash(profile / "identity.json"),
        }

    for name, other in (("Alice", "Bob"), ("Bob", "Alice")):
        profile = stores[name].path.parent
        remote = identities[other]
        TrustStore(profile / "trust.json").add_verified(
            remote.public_key_hex,
            confirmed_fingerprint=remote.fingerprint,
            name=other,
        )
        old = ShareConfig(
            share_id=SHARE,
            peer_node_id=remote.node_id,
            local_root=str(roots[name][0]),
            display_name="Original folder",
            remote_host="127.0.0.1",
            enabled=True,
            grant_manifest=True,
            grant_read=True,
            grant_write=True,
            grant_agreement=True,
        )
        stores[name].save(replace(stores[name].load(), shares=(old,)))

    return stores, roots, backups


def _crash_child(stage: str, profile: str, new_root: str) -> None:
    """Simulate a sudden process death at one real storage boundary."""
    store = ConfigStore(Path(profile) / "settings.json")
    original = store.load().shares[0]
    journal = FolderChangeJournal(store)
    journal.begin(SESSION, original)

    if stage in {"committing", "cleared", "replacement"}:
        journal.mark_committing(SESSION)

    if stage in {"cleared", "replacement"}:
        forget_local_folder_connection(
            store, expected_share_id=original.share_id, running=False
        )

    if stage == "replacement":
        new_share = replace(
            original,
            share_id=REPLACEMENT,
            local_root=str(Path(new_root)),
            display_name="Replacement folder",
        )
        store.save(replace(store.load(), shares=(new_share,)))

    # No finally handlers, destructors, or graceful Qt shutdown callbacks.
    os._exit(CRASH_CODES[stage])


def _probe_child(
    profile: str, *, attempt_invalid_connection: bool = False
) -> None:
    """Verify a real Qt window refuses to activate a crashed profile."""
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from PySide6.QtWidgets import QApplication

    from syncbridge.ui.qt_crash_recovery_window import (
        SyncBridgeCrashRecoveryWindow,
    )
    from syncbridge.ui.qt_onboarding import NetworkOptions, QtOnboarding

    def forbid_network(self):
        raise AssertionError("Recovery startup tried to open network services")

    QtOnboarding.start = forbid_network

    store = ConfigStore(Path(profile) / "settings.json")

    class OfflineController:
        def __init__(self):
            self.store = store
            self.runtime = SimpleNamespace(listen_ports=None)
            self.running = False

        def stop(self):
            self.running = False

    app = QApplication.instance() or QApplication([])
    app.setQuitOnLastWindowClosed(False)
    window = SyncBridgeCrashRecoveryWindow(
        OfflineController(), network_options=NetworkOptions()
    )
    window.show()
    try:
        for _ in range(5):
            app.processEvents()
        assert window._recovery_required
        assert not window._network_started
        assert not window.controller.running
        assert window.restore_button.isVisible()
        assert not window.find_button.isEnabled()
        assert not window.reconnect_button.isEnabled()
        assert not window.folder_select_button.isVisible()
        assert not window.preview_button.isEnabled()
        assert not window.sync_button.isEnabled()
        if attempt_invalid_connection:
            # Simulate the completion callback of an obsolete connection
            # attempt. A checkpoint for the original (not replacement)
            # share must be rejected BEFORE Connected is entered.
            from syncbridge.ui.desktop_controller import DesktopPhase

            window.controller.running = True
            window.lifecycle.transition(DesktopPhase.CONNECTING)
            window._connected("e" * 32)
            assert window.lifecycle.phase is DesktopPhase.DISCONNECTING
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                app.processEvents()
                if window.lifecycle.phase is DesktopPhase.DISCONNECTED:
                    break
                time.sleep(0.01)
            assert window.lifecycle.phase is DesktopPhase.DISCONNECTED
            assert not window.controller.running
            assert window._recovery_required
            assert FolderChangeJournal(store).load() is not None
    finally:
        window._close_allowed = True
        window.close()
    print("Recovery guard blocked desktop network startup", flush=True)


def _run_worker(args: list[str], *, expected: int) -> None:
    completed = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), *args],
        cwd=Path(__file__).resolve().parents[2],
        env={**os.environ, "QT_QPA_PLATFORM": "offscreen"},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == expected, (
        f"Unexpected subprocess result {completed.returncode}:\n"
        f"{completed.stdout}\n{completed.stderr}"
    )


@pytest.mark.parametrize(
    ("alice_stage", "bob_stage"),
    [
        ("checkpoint", "committing"),
        ("committing", "cleared"),
        ("cleared", "replacement"),
        ("replacement", "replacement"),
    ],
)
def test_interrupted_laptops_start_offline(
    tmp_path, alice_stage, bob_stage
):
    pytest.importorskip("PySide6")
    stores, roots, backups = _create_profiles(tmp_path)

    # Each laptop is a separate OS process with independent configuration.
    for name, stage in (("Alice", alice_stage), ("Bob", bob_stage)):
        _run_worker(
            [
                "--crash-child", stage,
                str(stores[name].path.parent), str(roots[name][1]),
            ],
            expected=CRASH_CODES[stage],
        )

    for name, stage in (("Alice", alice_stage), ("Bob", bob_stage)):
        store = stores[name]
        checkpoint = FolderChangeJournal(store).load()
        assert checkpoint is not None
        assert checkpoint.original.share_id == SHARE
        assert checkpoint.stage == (
            "preparing" if stage == "checkpoint" else "committing"
        )

        existing = store.load().shares
        if stage == "cleared":
            assert existing == ()
        elif stage == "replacement":
            assert len(existing) == 1 and existing[0].share_id == REPLACEMENT
        else:
            assert existing == (checkpoint.original,)

        assert _hash(roots[name][0] / "sentinel.txt") == backups[name]["marker"]
        assert _hash(store.path.parent / "identity.json") == backups[name]["identity"]

        _run_worker(
            ["--probe-child", str(store.path.parent)], expected=0
        )

    # A local rollback can safely restore an empty/old profile. A newer
    # approved relationship is never silently overwritten or synchronized.
    for name, stage in (("Alice", alice_stage), ("Bob", bob_stage)):
        journal = FolderChangeJournal(stores[name])
        if stage == "replacement":
            selected = journal.keep_replacement(running=False)
            assert selected.share_id == REPLACEMENT
        else:
            selected = journal.restore_previous(running=False)
            assert selected.share_id == SHARE
        assert journal.load() is None
        assert _hash(roots[name][0] / "sentinel.txt") == backups[name]["marker"]


def test_bad_checkpoint_still_blocks_desktop(tmp_path):
    pytest.importorskip("PySide6")
    stores, roots, _ = _create_profiles(tmp_path)
    alice = stores["Alice"]
    journal = FolderChangeJournal(alice)
    journal.begin(SESSION, alice.load().shares[0])
    with journal.path.open("ab") as stream:
        stream.write(b"altered")
    _run_worker(["--probe-child", str(alice.path.parent)], expected=0)
    assert alice.load().shares[0].share_id == SHARE


def test_recovery_checkpoint_blocks_obsolete_connected_callback(tmp_path):
    pytest.importorskip("PySide6")
    stores, roots, _ = _create_profiles(tmp_path)
    alice = stores["Alice"]
    _run_worker(
        ["--crash-child", "checkpoint", str(alice.path.parent), str(roots["Alice"][1])],
        expected=CRASH_CODES["checkpoint"],
    )
    _run_worker(
        ["--probe-rejected-connection", str(alice.path.parent)], expected=0
    )
    assert FolderChangeJournal(alice).load() is not None


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--crash-child":
        _crash_child(*sys.argv[2:])
    elif len(sys.argv) == 3 and sys.argv[1] == "--probe-child":
        _probe_child(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "--probe-rejected-connection":
        _probe_child(sys.argv[2], attempt_invalid_connection=True)
    else:
        raise SystemExit("Unknown folder-change test subprocess arguments")
