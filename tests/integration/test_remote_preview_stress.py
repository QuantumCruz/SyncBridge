
"""Stress the real desktop Preview path using two disposable peer processes.

Creates a large file inventory and injects a controlled delay before every
remote manifest request. The delay models one slow request, not full WAN RTT,
packet loss, or ZeroTier routing. The test does not transfer or alter files.

Run on Windows:
    python -m pytest tests/integration/test_remote_preview_stress.py -v -s
"""
from __future__ import annotations

import multiprocessing as mp
import os
import queue
import sys
import time
import traceback
from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from test_desktop_crash_resume import (
    MIB,
    RELATIVE,
    _configure,
    _desktop_child,
    _hash,
    _terminate,
)

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="The Windows desktop stress test requires Windows",
)

FILE_COUNT = 240
NETWORK_DELAY_SECONDS = 0.465


def _make_inventory(root: Path, *, owner: str, count: int) -> None:
    """Fill an isolated share with distinct real files and nested folders."""
    for index in range(count):
        destination = root / "stress" / f"batch-{index // 40:02d}" / (
            f"{owner}-{index:04d}.bin"
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        payload = os.urandom(2048)
        destination.write_bytes(payload)


def _delayed_preview_child(
    profile: str,
    ports: tuple[int, int, int],
    lock_port: int,
    validation_port: int,
    delay: float,
    ready,
    messages,
) -> None:
    """Drive the real Qt Preview button with latency on manifest fetches."""
    os.environ["QT_QPA_PLATFORM"] = "offscreen"

    try:
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication, QMessageBox
        from syncbridge.network.manifest import ManifestService
        from syncbridge.storage.config import ConfigStore
        from syncbridge.ui.preview_diagnostics import (
            DiagnosticDesktopController,
        )
        from syncbridge.ui.qt_progress_window import (
            SyncBridgeProgressWindow,
        )

        original_fetch = ManifestService.fetch

        def delayed_fetch(self, *args, **kwargs):
            time.sleep(delay)
            return original_fetch(self, *args, **kwargs)

        ManifestService.fetch = delayed_fetch

        app = QApplication([])

        controller = DiagnosticDesktopController(
            ConfigStore(Path(profile) / "settings.json"),
            bind_address="127.0.0.1",
            listen_ports=ports,
            lock_port=lock_port,
            validation_port=validation_port,
        )

        controller.preview_diagnostics.heartbeat_seconds = 0.05

        warnings: list[str] = []

        def no_modal(_parent, _title, message, *args, **kwargs):
            warnings.append(str(message))
            return QMessageBox.StandardButton.Ok

        QMessageBox.warning = no_modal

        window = SyncBridgeProgressWindow(controller)
        window.show()

        started_at = time.monotonic()
        preview_started_at = 0.0
        started = False
        reported = False

        def poll() -> None:
            nonlocal started, reported, preview_started_at

            if reported:
                return

            if time.monotonic() - started_at > 75:
                reported = True
                messages.put(
                    (
                        "timeout",
                        window.status.text(),
                        window.summary.text(),
                        tuple(warnings),
                    )
                )
                app.quit()
                return

            if warnings:
                reported = True
                messages.put(("warning", tuple(warnings)))
                app.quit()
                return

            if not started:
                if controller.running and not window._busy:
                    ready.set()
                    started = True
                    preview_started_at = time.monotonic()
                    window.preview_button.click()
                return

            if window._busy:
                return

            plan = window._preview

            if plan is not None:
                reported = True
                messages.put(
                    (
                        "preview",
                        len(plan.items),
                        plan.requires_review,
                        window.sync_button.isEnabled(),
                        time.monotonic() - preview_started_at,
                        window.status.text(),
                    )
                )
                app.quit()

            elif window.status.text() == "Needs attention":
                reported = True
                messages.put(
                    ("preview-error", window.summary.text())
                )
                app.quit()

        timer = QTimer(window)
        timer.setInterval(40)
        timer.timeout.connect(poll)
        timer.start()

        app.exec()

    except BaseException:
        messages.put(
            ("child-exception", traceback.format_exc())
        )
        raise


def test_large_folder_preview_completes_with_delayed_manifest(tmp_path):
    """A real guarded Preview exposes Sync after hashing both inventories."""
    (
        profiles,
        roots,
        listeners,
        lock_port,
        validation_port,
        source,
    ) = _configure(tmp_path, size=8 * MIB)

    _make_inventory(
        roots["Alice"],
        owner="alice",
        count=FILE_COUNT,
    )
    _make_inventory(
        roots["Bob"],
        owner="bob",
        count=FILE_COUNT,
    )

    original_hash = _hash(source)

    ctx = mp.get_context("spawn")
    messages = ctx.Queue()
    bob_ready = ctx.Event()
    alice_ready = ctx.Event()
    unused_checkpoint = ctx.Event()

    children: list[mp.Process] = []
    result = None

    try:
        bob = ctx.Process(
            target=_desktop_child,
            args=(
                str(profiles["Bob"]),
                tuple(listeners["Bob"]),
                lock_port,
                validation_port,
                "serve",
                0,
                bob_ready,
                unused_checkpoint,
                messages,
            ),
            name="SyncBridgePreviewStress-Bob",
        )

        bob.start()
        children.append(bob)

        assert bob_ready.wait(timeout=30), (
            "Bob's guarded desktop did not start "
            f"(exit={bob.exitcode})"
        )

        alice = ctx.Process(
            target=_delayed_preview_child,
            args=(
                str(profiles["Alice"]),
                tuple(listeners["Alice"]),
                lock_port,
                validation_port,
                NETWORK_DELAY_SECONDS,
                alice_ready,
                messages,
            ),
            name="SyncBridgePreviewStress-Alice",
        )

        alice.start()
        children.append(alice)

        deadline = time.monotonic() + 90

        while time.monotonic() < deadline:
            try:
                message = messages.get(timeout=1)
            except queue.Empty:
                if (
                    alice.exitcode is not None
                    or bob.exitcode is not None
                ):
                    pytest.fail(
                        "Desktop process terminated early: "
                        f"Alice={alice.exitcode}, "
                        f"Bob={bob.exitcode}"
                    )
                continue

            if message[0] == "preview":
                result = message
                break

            if message[0] in {
                "warning",
                "timeout",
                "preview-error",
                "child-exception",
                "child-timeout",
                "sync-error",
            }:
                pytest.fail(
                    f"Guarded desktop preview failed: {message!r}"
                )

        assert result is not None, (
            "No Preview result before test deadline"
        )

        (
            _,
            changes,
            needs_review,
            sync_enabled,
            elapsed,
            status,
        ) = result

        expected_changes = 2 * FILE_COUNT + 1

        assert changes == expected_changes, (
            f"Expected {expected_changes} changes, got {changes}"
        )

        assert not needs_review, (
            "Unrelated test files require unexpected review"
        )

        assert sync_enabled, (
            f"Sync button remained unavailable: {status}"
        )

    finally:
        for child in reversed(children):
            _terminate(child)
            child.close()

        messages.close()
        messages.join_thread()

    log_path = (
        profiles["Alice"]
        / "diagnostics"
        / "preview.log"
    )

    assert log_path.is_file(), (
        "No diagnostic log was written"
    )

    log = log_path.read_text(encoding="utf-8")

    assert "START read-only preview" in log
    assert "STAGE Scanning and hashing local files" in log
    assert (
        "STAGE Retrieving the other computer's file inventory"
        in log
    )
    assert "END total_seconds=" in log
    assert "FAILED" not in log

    # Preview must not modify either user's shared files.
    assert _hash(source) == original_hash
    assert not (roots["Bob"] / RELATIVE).exists()

    assert not (
        roots["Alice"]
        / "stress"
        / "batch-00"
        / "bob-0000.bin"
    ).exists()

    assert not (
        roots["Bob"]
        / "stress"
        / "batch-00"
        / "alice-0000.bin"
    ).exists()

    print(
        f"Guarded Preview: {changes} differences, "
        f"{elapsed:.2f}s, "
        f"injected manifest delay "
        f"{NETWORK_DELAY_SECONDS:.3f}s; "
        "Sync button enabled. No files transferred.",
        flush=True,
    )
