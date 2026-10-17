
"""End-to-end Qt desktop recovery after the initiating process is killed.

Two independent, offscreen PySide6 windows run in separate Windows processes.
Only pytest temporary folders are used; no actual user profile is opened.

Run the focused test:
    python -m pytest tests/integration/test_desktop_crash_resume.py -v

This tests process termination and restart, not sudden loss of electrical power.
"""
from __future__ import annotations

import hashlib
import multiprocessing as mp
import os
import queue
import socket
import threading
import time
import traceback
from pathlib import Path
from uuid import uuid4

import pytest

pytest.importorskip("PySide6")

from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.storage.config import AppConfig, ConfigStore, ShareConfig

MIB = 1024 * 1024
RELATIVE = "dataset/recovery-test.bin"


def _payload_size() -> int:
    raw = os.getenv("SYNCBRIDGE_DESKTOP_CRASH_MIB", "16")
    try:
        mib = int(raw)
    except ValueError as exc:
        raise ValueError(
            "SYNCBRIDGE_DESKTOP_CRASH_MIB must be an integer"
        ) from exc

    if not 8 <= mib <= 128:
        raise ValueError(
            "SYNCBRIDGE_DESKTOP_CRASH_MIB must be 8..128"
        )

    return mib * MIB


def _ports(count: int) -> list[int]:
    result: list[int] = []

    while len(result) < count:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]

        if port not in result:
            result.append(port)

    return result


def _hash(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(MIB), b""):
            digest.update(chunk)

    return digest.hexdigest()


def _configure(base: Path, *, size: int):
    ports = _ports(8)
    identities = {}
    profiles = {}
    roots = {}

    listeners = {
        "Alice": ports[:3],
        "Bob": ports[3:6],
    }

    share_id = uuid4().hex

    for name in ("Alice", "Bob"):
        profile = base / name / "Profile"
        root = base / name / "Shared"

        profile.mkdir(parents=True)
        root.mkdir(parents=True)

        profiles[name] = profile
        roots[name] = root

        identities[name] = load_or_create_identity(
            profile / "identity.json"
        )

    for name, other in (
        ("Alice", "Bob"),
        ("Bob", "Alice"),
    ):
        peer = identities[other]

        TrustStore(profiles[name] / "trust.json").add_verified(
            peer.public_key_hex,
            confirmed_fingerprint=peer.fingerprint,
            name=other,
        )

        store = ConfigStore(
            profiles[name] / "settings.json"
        )

        store.save(
            AppConfig(
                device_name=name,
                shares=(
                    ShareConfig(
                        share_id=share_id,
                        peer_node_id=peer.node_id,
                        local_root=str(roots[name]),
                        display_name="Disposable recovery folder",
                        remote_host="127.0.0.1",
                        manifest_port=listeners[other][0],
                        transfer_port=listeners[other][1],
                        agreement_port=listeners[other][2],
                        enabled=True,
                        grant_manifest=True,
                        grant_read=True,
                        grant_write=True,
                        grant_agreement=True,
                    ),
                ),
            )
        )

    source = roots["Alice"] / RELATIVE
    source.parent.mkdir(parents=True)

    block = os.urandom(128 * 1024)

    with source.open("wb") as stream:
        for _ in range(size // len(block)):
            stream.write(block)

    assert source.stat().st_size == size

    return (
        profiles,
        roots,
        listeners,
        ports[6],
        ports[7],
        source,
    )


def _desktop_child(
    profile: str,
    ports: tuple[int, int, int],
    lock_port: int,
    validation_port: int,
    mode: str,
    cutoff: int,
    ready,
    crash_checkpoint,
    messages,
):
    """Start the real controller and Qt window in a separate OS process."""
    os.environ["QT_QPA_PLATFORM"] = "offscreen"

    try:
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import (
            QApplication,
            QMessageBox,
        )

        from syncbridge.ui.desktop_controller import DesktopController
        from syncbridge.ui.qt_local_refresh import QtLocalFileRefresh
        from syncbridge.ui.qt_progress_window import (
            SyncBridgeProgressWindow,
        )

        app = QApplication([])

        controller = DesktopController(
            ConfigStore(
                Path(profile) / "settings.json"
            ),
            bind_address="127.0.0.1",
            listen_ports=ports,
            lock_port=lock_port,
            validation_port=validation_port,
        )

        # These folders and identities exist only in pytest's tmp_path.
        # The test explicitly approves the GUI confirmation dialog.
        QMessageBox.question = (
            lambda *a, **kw: QMessageBox.StandardButton.Yes
        )
        QMessageBox.warning = (
            lambda *a, **kw: QMessageBox.StandardButton.Ok
        )

        window = SyncBridgeProgressWindow(controller)

        window.local_view_refresh = QtLocalFileRefresh(
            window,
            interval_ms=100,
        )

        window.show()

        if mode == "crash":
            original_progress = window._on_progress

            def hold_transfer(event):
                original_progress(event)

                if (
                    str(event.direction).lower() == "send"
                    and event.transferred >= cutoff
                ):
                    crash_checkpoint.set()

                    # The parent will forcibly terminate this process.
                    # No graceful transfer pause occurs.
                    threading.Event().wait(90)

            window._on_progress = hold_transfer

        if mode == "resume":
            normal_progress = window._on_progress
            first_send = True

            def report_resumed_offset(event):
                nonlocal first_send

                if (
                    first_send
                    and str(event.direction).lower() == "send"
                ):
                    first_send = False
                    messages.put(
                        ("resume-offset", int(event.transferred))
                    )

                normal_progress(event)

            window._on_progress = report_resumed_offset

            original_sync = controller.sync_once

            def report_sync(*, on_progress=None):
                try:
                    result = original_sync(
                        on_progress=on_progress
                    )

                    messages.put(
                        ("sync-result", bool(result.complete))
                    )

                    return result

                except Exception as exc:
                    messages.put(
                        ("sync-error", str(exc))
                    )
                    raise

            controller.sync_once = report_sync

        ready_sent = False
        preview_started = False
        sync_started = False
        view_reported = False
        started_at = time.monotonic()

        def poll():
            nonlocal ready_sent
            nonlocal preview_started
            nonlocal sync_started
            nonlocal view_reported

            if time.monotonic() - started_at > 85:
                messages.put(
                    ("child-timeout", mode)
                )
                app.quit()
                return

            if (
                controller.running
                and not window._busy
                and not ready_sent
            ):
                ready_sent = True
                ready.set()

            if mode == "serve":
                if (
                    not view_reported
                    and "local" in window._loaded
                    and not window._busy
                    and any(
                        window.local_table.item(i, 0) is not None
                        and window.local_table.item(i, 0).text()
                        == RELATIVE
                        for i in range(
                            window.local_table.rowCount()
                        )
                    )
                ):
                    view_reported = True
                    messages.put(
                        ("receiver-view-updated", True)
                    )

                return

            if not ready_sent or window._busy:
                return

            if not preview_started:
                preview_started = True
                window.preview_button.click()

            elif (
                not sync_started
                and window.sync_button.isEnabled()
            ):
                sync_started = True
                window.sync_button.click()

            elif (
                preview_started
                and not sync_started
                and not window._busy
                and window._preview is not None
                and not window._preview.items
            ):
                messages.put(
                    ("unexpected-empty-preview", mode)
                )
                app.quit()

        timer = QTimer(window)
        timer.setInterval(40)
        timer.timeout.connect(poll)
        timer.start()

        app.exec()

    except BaseException:
        messages.put(
            (
                "child-exception",
                mode,
                traceback.format_exc(),
            )
        )
        raise


def _terminate(process: mp.Process) -> None:
    if process.pid is None:
        return

    if process.is_alive():
        process.terminate()

    process.join(timeout=8)

    if process.is_alive():
        process.kill()
        process.join(timeout=5)

    assert not process.is_alive(), (
        "Disposable desktop process did not terminate"
    )


def test_desktop_recovers_after_initiator_is_killed_mid_transfer(
    tmp_path,
):
    """Restart the real Qt UI while keeping guarded synchronization active."""
    size = _payload_size()

    (
        profiles,
        roots,
        listeners,
        lock,
        validation,
        source,
    ) = _configure(
        tmp_path,
        size=size,
    )

    destination = roots["Bob"] / RELATIVE

    ctx = mp.get_context("spawn")

    messages = ctx.Queue()
    ready_bob = ctx.Event()
    ready_alice = ctx.Event()
    resumed_ready = ctx.Event()
    crash_point = ctx.Event()

    children = []

    def start_peer(name, mode, ready):
        child = ctx.Process(
            target=_desktop_child,
            args=(
                str(profiles[name]),
                tuple(listeners[name]),
                lock,
                validation,
                mode,
                size // 4,
                ready,
                crash_point,
                messages,
            ),
            name=f"SyncBridgeTest-{name}-{mode}",
        )

        child.start()
        children.append(child)

        return child

    try:
        bob = start_peer(
            "Bob",
            "serve",
            ready_bob,
        )

        assert ready_bob.wait(timeout=25), (
            "Bob's Qt window did not start "
            f"(exitcode={bob.exitcode})"
        )

        alice = start_peer(
            "Alice",
            "crash",
            ready_alice,
        )

        assert ready_alice.wait(timeout=25), (
            "Alice's Qt window did not start "
            f"(exitcode={alice.exitcode})"
        )

        assert crash_point.wait(timeout=45), (
            "Alice never reached the mid-transfer crash checkpoint"
        )

        # Crash only after Bob has staged some incomplete bytes.
        staging = roots["Bob"].parent.glob(
            ".syncbridge-transfer-*/*.part"
        )

        deadline = time.monotonic() + 12
        partial_sizes = []

        while time.monotonic() < deadline:
            partial_sizes = [
                p.stat().st_size for p in staging
            ]

            if any(
                0 < n < size
                for n in partial_sizes
            ):
                break

            time.sleep(0.03)

            staging = roots["Bob"].parent.glob(
                ".syncbridge-transfer-*/*.part"
            )

        assert any(
            0 < n < size
            for n in partial_sizes
        ), "Bob did not retain partial data before Alice's crash"

        assert not destination.exists(), (
            "An incomplete file was published"
        )

        _terminate(alice)

        assert not destination.exists(), (
            "An incomplete file was published after crash"
        )

        staged_after_crash = list(
            roots["Bob"].parent.glob(
                ".syncbridge-transfer-*/*.part"
            )
        )

        assert len(staged_after_crash) == 1

        saved_offset = (
            staged_after_crash[0].stat().st_size
        )

        assert 0 < saved_offset < size

        # A crashed initiator can leave a live lease behind.
        # The guard's normal lease lifetime is 15 seconds.
        # Wait for expiration rather than bypassing authorization.
        time.sleep(16)

        restarted = start_peer(
            "Alice",
            "resume",
            resumed_ready,
        )

        assert resumed_ready.wait(timeout=25), (
            "Restarted desktop did not open "
            f"(exitcode={restarted.exitcode})"
        )

        confirmed_sync = False
        confirmed_view = False
        confirmed_resume_offset = False

        deadline = time.monotonic() + 55
        observed = []

        # Consume results together. Bob's UI might refresh before
        # Alice's sync worker reports success.
        while (
            time.monotonic() < deadline
            and not (
                confirmed_sync
                and confirmed_view
                and confirmed_resume_offset
            )
        ):
            try:
                note = messages.get(timeout=1)
            except queue.Empty:
                continue

            observed.append(note)

            if note[0] == "sync-result":
                assert note[1] is True, (
                    "Guarded sync did not complete: "
                    f"{note!r}"
                )

                confirmed_sync = True

            elif note[0] == "receiver-view-updated":
                confirmed_view = True

            elif note[0] == "resume-offset":
                assert note[1] == saved_offset, (
                    "Transfer restarted instead of resuming "
                    f"at {saved_offset}: {note!r}"
                )

                confirmed_resume_offset = True

            elif note[0] in {
                "child-exception",
                "child-timeout",
                "sync-error",
            }:
                pytest.fail(
                    f"Desktop process reported failure: {note!r}"
                )

        assert confirmed_sync, (
            f"No successful desktop sync; events: {observed!r}"
        )

        assert confirmed_view, (
            "Bob's My files tab did not refresh; "
            f"events: {observed!r}"
        )

        assert confirmed_resume_offset, (
            "No verified resume offset; "
            f"events: {observed!r}"
        )

        deadline = time.monotonic() + 12

        while (
            not destination.is_file()
            and time.monotonic() < deadline
        ):
            time.sleep(0.03)

        assert destination.is_file(), (
            "Bob never published the resumed file"
        )

        assert destination.stat().st_size == size
        assert _hash(destination) == _hash(source)

        assert not list(
            roots["Bob"].parent.glob(
                ".syncbridge-transfer-*/*.part"
            )
        )

    finally:
        for child in reversed(children):
            _terminate(child)
            child.close()

        messages.close()
        messages.join_thread()
