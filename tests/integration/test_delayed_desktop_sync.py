
"""Real two-process Qt Preview -> Sync with delayed authenticated manifests.

Windows only. Uses disposable profiles and loopback TCP, never a real user share.
Manifest requests from Alice incur one artificial 465 ms delay each. This
models slow request processing, not actual ZeroTier round-trip latency.
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


DELAY_SECONDS = 0.465
EXTRA_FILES_PER_SIDE = 4


def _alice_desktop(
    profile: str,
    ports: tuple[int, int, int],
    lock_port: int,
    validation_port: int,
    ready,
    messages,
) -> None:
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
            time.sleep(DELAY_SECONDS)
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

        original_sync = controller.sync_once

        def report_sync(*, on_progress=None):
            try:
                result = original_sync(
                    on_progress=on_progress
                )
            except Exception as exc:
                messages.put(
                    (
                        "sync-error",
                        type(exc).__name__,
                        str(exc),
                    )
                )
                raise

            messages.put(
                (
                    "sync-result",
                    bool(result.complete),
                    len(result.uploaded),
                    len(result.downloaded),
                )
            )
            return result

        controller.sync_once = report_sync

        # This approval is test-only and applies solely to the two
        # preconfigured disposable folders.
        QMessageBox.question = (
            lambda *_a, **_kw:
            QMessageBox.StandardButton.Yes
        )

        def no_modal_warning(*args, **kwargs):
            message = (
                str(args[2])
                if len(args) >= 3
                else "Unknown warning"
            )
            messages.put(("qt-warning", message))
            return QMessageBox.StandardButton.Ok

        QMessageBox.warning = no_modal_warning

        window = SyncBridgeProgressWindow(controller)

        original_finish = window._finish

        def report_gui_finish(kind, result):
            original_finish(kind, result)

            if kind == "sync":
                messages.put(
                    (
                        "gui-sync",
                        window.status.text(),
                        window.summary.text(),
                    )
                )

        window._finish = report_gui_finish
        window.show()

        started = time.monotonic()
        preview_requested = False
        sync_requested = False
        announced_ready = False

        def poll() -> None:
            nonlocal preview_requested
            nonlocal sync_requested
            nonlocal announced_ready

            if time.monotonic() - started > 175:
                messages.put(
                    (
                        "alice-timeout",
                        window.status.text(),
                        window.summary.text(),
                        bool(window._busy),
                    )
                )
                app.quit()
                return

            if not controller.running or window._busy:
                return

            if not announced_ready:
                announced_ready = True
                ready.set()

            if not preview_requested:
                if window.preview_button.isEnabled():
                    preview_requested = True
                    window.preview_button.click()
                return

            if not sync_requested:
                plan = window._preview

                if plan is None:
                    return

                messages.put(
                    (
                        "preview-result",
                        len(plan.items),
                        bool(plan.requires_review),
                        bool(window.sync_button.isEnabled()),
                    )
                )

                if (
                    plan.requires_review
                    or not window.sync_button.isEnabled()
                ):
                    app.quit()
                    return

                sync_requested = True
                window.sync_button.click()

        timer = QTimer(window)
        timer.setInterval(40)
        timer.timeout.connect(poll)
        timer.start()

        app.exec()

    except BaseException:
        messages.put(
            ("alice-exception", traceback.format_exc())
        )
        raise


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows desktop integration",
)
def test_delayed_manifest_preview_and_bidirectional_sync(
    tmp_path,
):
    pytest.importorskip("PySide6")

    from test_desktop_crash_resume import (
        MIB,
        RELATIVE,
        _configure,
        _desktop_child,
        _hash,
        _terminate,
    )

    (
        profiles,
        roots,
        listeners,
        lock_port,
        validation_port,
        source,
    ) = _configure(
        tmp_path,
        size=8 * MIB,
    )

    # Each device begins with files the other does not possess.
    # Both computers must end with the complete combined inventory.
    for side in ("Alice", "Bob"):
        for number in range(EXTRA_FILES_PER_SIDE):
            target = (
                roots[side]
                / side.lower()
                / f"entry-{number:02d}.bin"
            )
            target.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            target.write_bytes(
                os.urandom(32 * 1024)
            )

    def file_hashes(root: Path) -> dict[str, str]:
        return {
            path.relative_to(root).as_posix(): _hash(path)
            for path in root.rglob("*")
            if path.is_file()
        }

    alice_before = file_hashes(roots["Alice"])
    bob_before = file_hashes(roots["Bob"])

    assert len(alice_before) == EXTRA_FILES_PER_SIDE + 1
    assert len(bob_before) == EXTRA_FILES_PER_SIDE
    assert set(alice_before).isdisjoint(bob_before)

    expected = alice_before | bob_before

    assert (
        source.relative_to(
            roots["Alice"]
        ).as_posix() == RELATIVE
    )

    ctx = mp.get_context("spawn")

    messages = ctx.Queue()
    bob_ready = ctx.Event()
    alice_ready = ctx.Event()
    unused_crash_checkpoint = ctx.Event()

    children: list[mp.Process] = []
    observed = []

    preview = None
    sync_result = None
    gui_sync = None
    receiver_updated = False

    try:
        # Start Bob first. He serves authenticated inventories,
        # transfers and agreement requests.
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
                unused_crash_checkpoint,
                messages,
            ),
            name="SyncBridgeDelayedSync-Bob",
        )

        bob.start()
        children.append(bob)

        assert bob_ready.wait(timeout=30), (
            "Receiver desktop failed to start "
            f"(exitcode={bob.exitcode})"
        )

        # Alice initiates using the actual Qt controls and guarded
        # synchronization runtime.
        alice = ctx.Process(
            target=_alice_desktop,
            args=(
                str(profiles["Alice"]),
                tuple(listeners["Alice"]),
                lock_port,
                validation_port,
                alice_ready,
                messages,
            ),
            name="SyncBridgeDelayedSync-Alice",
        )

        alice.start()
        children.append(alice)

        assert alice_ready.wait(timeout=30), (
            "Initiating desktop failed to start "
            f"(exitcode={alice.exitcode})"
        )

        deadline = time.monotonic() + 180

        while time.monotonic() < deadline:
            try:
                message = messages.get(timeout=1)
            except queue.Empty:
                if (
                    alice.exitcode is not None
                    or bob.exitcode is not None
                ):
                    pytest.fail(
                        "Desktop exited unexpectedly: "
                        f"Alice={alice.exitcode}, "
                        f"Bob={bob.exitcode}; "
                        f"events={observed!r}"
                    )
                continue

            observed.append(message)
            kind = message[0]

            if kind == "preview-result":
                preview = message

                assert message[1] == len(expected), message
                assert message[2] is False, message
                assert message[3] is True, message

            elif kind == "sync-result":
                sync_result = message

                assert message[1] is True, message
                assert message[2] == len(alice_before), message
                assert message[3] == len(bob_before), message

            elif kind == "gui-sync":
                gui_sync = message

                assert message[1] == "Synchronized", message

            elif kind == "receiver-view-updated":
                receiver_updated = True

            elif kind in {
                "alice-exception",
                "alice-timeout",
                "qt-warning",
                "child-exception",
                "child-timeout",
                "sync-error",
                "unexpected-empty-preview",
            }:
                pytest.fail(
                    f"Desktop reported failure: {message!r}"
                )

            if (
                preview is not None
                and sync_result is not None
                and gui_sync is not None
                and receiver_updated
            ):
                break

        assert preview is not None, (
            f"Preview never completed: {observed!r}"
        )
        assert sync_result is not None, (
            f"Sync never completed: {observed!r}"
        )
        assert gui_sync is not None, (
            f"UI never reported completion: {observed!r}"
        )
        assert receiver_updated, (
            f"Receiver list did not refresh: {observed!r}"
        )

        # Check the exact contents on both real filesystems.
        # This also detects unexpected missing or extra files.
        for side in ("Alice", "Bob"):
            assert file_hashes(roots[side]) == expected, (
                f"{side}'s synchronized file hashes "
                "differ from the source union"
            )

        diagnostics = (
            profiles["Alice"]
            / "diagnostics"
            / "preview.log"
        )

        assert diagnostics.is_file(), (
            "Desktop did not record preview diagnostics"
        )

        log = diagnostics.read_text(
            encoding="utf-8"
        )

        assert "START read-only preview" in log
        assert "END total_seconds=" in log
        assert "FAILED" not in log

        print(
            "Delayed authenticated Preview -> Sync succeeded: "
            f"{len(expected)} files identical on both peers, "
            f"{DELAY_SECONDS:.3f}s extra "
            "per initiating manifest request, "
            "SHA-256 verified; GUI reported Synchronized.",
            flush=True,
        )

    finally:
        for child in reversed(children):
            _terminate(child)
            child.close()

        messages.close()
        messages.join_thread()
