
"""UI-automate approved bidirectional sync through the real packaged EXE.

The test starts disconnected, clicks Reconnect, approves the other person's
native connection dialog, and then uses Preview/Sync with a separate native
transfer confirmation. No application-internal test hooks are installed.

Keep the interactive Windows desktop unlocked during this test.
"""
from __future__ import annotations

import os
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path

import pytest

from test_desktop_crash_resume import (
    MIB,
    RELATIVE,
    _configure,
    _hash,
)

from test_packaged_windows_desktop import (
    _assert_alive,
    _click_enabled_button,
    _connect_pair,
    _connect_uia,
    _launch,
    _network_options,
    _require_executable,
    _require_ui,
    _stop,
    _until,
    _approve_dialog,
    _wait_for_listener,
)

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Packaged GUI transfer requires Windows",
)


def _sync(
    window,
    process: subprocess.Popen,
    log: Path,
) -> None:
    _click_enabled_button(
        window,
        "Preview differences",
        process,
        log,
        timeout=85,
    )

    _click_enabled_button(
        window,
        "Sync files",
        process,
        log,
        timeout=85,
    )

    _approve_dialog(
        process,
        log,
        "Synchronize?",
    )


def _wait_verified(
    destination: Path,
    digest: str,
    *,
    process,
    log,
    description,
):
    _until(
        description,
        lambda: (
            destination.is_file()
            and _hash(destination) == digest
        ),
        process=process,
        log=log,
        timeout=125,
    )


def test_packaged_windows_gui_sends_and_receives_files(tmp_path):
    """Actual EXEs require consent and verify transfers both ways."""
    _require_executable()
    _require_ui()

    (
        profiles,
        roots,
        listeners,
        lock,
        validation,
        alice_file,
    ) = _configure(tmp_path, size=8 * MIB)

    alice_digest = _hash(alice_file)
    bob_received = roots["Bob"] / RELATIVE

    used = {
        *listeners["Alice"],
        *listeners["Bob"],
        lock,
        validation,
    }

    alice_options = _network_options(used)
    bob_options = _network_options(used)
    processes = []

    with ExitStack() as stack:
        try:
            bob, bob_log = _launch(
                stack,
                processes,
                name="Bob",
                profile=profiles["Bob"],
                workdir=tmp_path / "Visible",
                listen_ports=tuple(listeners["Bob"]),
                lock_port=lock,
                validation_port=validation,
                options=bob_options,
                remote_options=alice_options,
                visible=True,
            )

            _wait_for_listener(
                bob,
                bob_options["pairing"],
                bob_log,
                description="Bob's pairing listener",
            )

            alice, alice_log = _launch(
                stack,
                processes,
                name="Alice",
                profile=profiles["Alice"],
                workdir=tmp_path / "Visible",
                listen_ports=tuple(listeners["Alice"]),
                lock_port=lock,
                validation_port=validation,
                options=alice_options,
                remote_options=bob_options,
                visible=True,
            )

            _wait_for_listener(
                alice,
                alice_options["pairing"],
                alice_log,
                description="Alice's pairing listener",
            )

            alice_window = _connect_uia(alice, alice_log)
            bob_window = _connect_uia(bob, bob_log)

            assert not bob_received.exists()

            _connect_pair(
                (alice, alice_log, alice_window, "Alice"),
                (bob, bob_log, bob_window, "Bob"),
            )

            _wait_for_listener(
                bob,
                listeners["Bob"][0],
                bob_log,
                description="Bob's authenticated manifest listener",
            )

            _wait_for_listener(
                alice,
                listeners["Alice"][0],
                alice_log,
                description="Alice's authenticated manifest listener",
            )

            assert not bob_received.exists(), (
                "Connecting must not automatically synchronize files"
            )

            # Alice -> Bob
            _sync(
                alice_window,
                alice,
                alice_log,
            )

            _wait_verified(
                bob_received,
                alice_digest,
                process=alice,
                log=alice_log,
                description=(
                    "Alice's file arriving with matching "
                    "SHA-256 on Bob"
                ),
            )

            _until(
                "Alice becoming idle after first sync",
                lambda: alice_window.child_window(
                    title="Preview differences",
                    control_type="Button",
                ).is_enabled(),
                process=alice,
                log=alice_log,
            )

            # Bob -> Alice
            bob_file = (
                roots["Bob"] / "dataset" / "bob-return.bin"
            )

            bob_file.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            bob_file.write_bytes(
                os.urandom(512 * 1024)
            )

            bob_digest = _hash(bob_file)

            alice_received = (
                roots["Alice"] / "dataset" / "bob-return.bin"
            )

            assert not alice_received.exists()

            _sync(
                bob_window,
                bob,
                bob_log,
            )

            _wait_verified(
                alice_received,
                bob_digest,
                process=bob,
                log=bob_log,
                description=(
                    "Bob's return file arriving with matching "
                    "SHA-256 on Alice"
                ),
            )

            assert _hash(alice_file) == alice_digest
            assert _hash(bob_received) == alice_digest

            _assert_alive(
                alice,
                alice_log,
                description="Alice after two transfers",
            )

            _assert_alive(
                bob,
                bob_log,
                description="Bob after two transfers",
            )

        finally:
            for process in reversed(processes):
                _stop(process)
