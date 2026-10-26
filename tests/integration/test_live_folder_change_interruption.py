
"""Crash an actually connected Alice/Bob Qt session during folder replacement.

Two separate SyncBridge desktop processes use disposable, pre-approved shares,
real authenticated session sockets and real guarded runtimes. Test-only hooks
terminate exactly one process at a durable production checkpoint. The parent
then restarts the recovery window and verifies that networking stays disabled.

No external network, real user profiles or file transfers are involved.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from test_desktop_crash_resume import RELATIVE, _configure
from test_packaged_windows_desktop import _network_options

PROJECT = Path(__file__).resolve().parents[2]
SOURCE = PROJECT / "src"
CRASH_EXIT = 79

pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="Windows process and Qt recovery test"
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _mark(directory: Path, name: str) -> None:
    (directory / name).write_text("ready\n", encoding="utf-8")


def _child(role: str, crash_role: str, stage: str, base: Path) -> None:
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication, QMessageBox

    from syncbridge.storage.config import ConfigStore
    from syncbridge.ui.desktop_controller import DesktopPhase
    from syncbridge.ui.preview_diagnostics import DiagnosticDesktopController
    from syncbridge.ui.qt_crash_recovery_window import SyncBridgeCrashRecoveryWindow
    from syncbridge.ui.qt_onboarding import NetworkOptions

    import json
    settings = json.loads((base / "network.json").read_text(encoding="utf-8"))
    own = settings[role]
    other = settings["Bob" if role == "Alice" else "Alice"]
    store = ConfigStore(base / role / "Profile" / "settings.json")

    # TEST ONLY: approve modal questions automatically.
    # The production window and secure protocol remain unchanged.
    QMessageBox.question = staticmethod(
        lambda *a, **k: QMessageBox.StandardButton.Yes
    )

    class CrashWindow(SyncBridgeCrashRecoveryWindow):
        def _connected(self, sid):
            super()._connected(sid)
            if (self.lifecycle.phase is DesktopPhase.CONNECTED
                    and self.controller.running):
                _mark(base, f"{role}.connected")

        def _checkpoint_before_stopping(self, sid, action_role):
            saved = super()._checkpoint_before_stopping(sid, action_role)
            expected = "receiver" if role == "Bob" else "initiator"
            if (saved and role == crash_role and stage == "checkpoint"
                    and action_role == expected):
                _mark(base, f"{role}.crash-point")
                os._exit(CRASH_EXIT)
            return saved

        def _replace_saved_folder(self, sid):
            if role == crash_role and stage == "committing":
                # Crash immediately after the production journal's
                # committing transition, before clearing local settings.
                self._change_journal.mark_committing(sid)
                _mark(base, f"{role}.crash-point")
                os._exit(CRASH_EXIT)
            super()._replace_saved_folder(sid)

    controller = DiagnosticDesktopController(
        store,
        bind_address="127.0.0.1",
        listen_ports=tuple(own["listeners"]),
        lock_port=settings["lock"],
        validation_port=settings["validation"],
    )
    options = NetworkOptions(
        name=role,
        discovery_port=own["discovery"],
        discovery_bind="127.0.0.1",
        discovery_targets=(("127.0.0.1", other["discovery"]),),
        pairing_port=own["pairing"],
        pairing_bind="127.0.0.1",
        setup_port=own["setup"],
        remote_setup_port=other["setup"],
        activation_port=own["activation"],
        remote_activation_port=other["activation"],
    )

    app = QApplication([])
    app.setQuitOnLastWindowClosed(False)
    window = CrashWindow(controller, network_options=options)
    window.show()
    started = time.monotonic()
    outgoing = False
    requested = False

    def drive() -> None:
        nonlocal outgoing, requested

        if time.monotonic() - started > 80:
            print(
                f"{role}: timed out in {window.lifecycle.phase.value}: "
                f"{window.summary.text()}",
                flush=True,
            )
            app.exit(88)
            return

        if not window._network_started or window._session_service is None:
            return

        if not (base / f"{role}.listening").exists():
            _mark(base, f"{role}.listening")

        if role != "Alice":
            return

        if not outgoing and (base / "Bob.listening").exists():
            outgoing = True
            window._begin_outgoing()

        if (not requested and (base / "Bob.connected").exists()
                and window.lifecycle.phase is DesktopPhase.CONNECTED
                and not window._busy and window.controller.running):
            requested = True
            window._request_folder_change()
            _mark(base, "Alice.requested")

    poll = QTimer()
    poll.timeout.connect(drive)
    poll.start(100)
    raise SystemExit(app.exec())


def _probe(profile: Path, base: Path) -> None:
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from PySide6.QtWidgets import QApplication

    from syncbridge.storage.config import ConfigStore
    from syncbridge.storage.folder_change_recovery import FolderChangeJournal
    from syncbridge.ui.desktop_controller import DesktopController
    from syncbridge.ui.qt_crash_recovery_window import SyncBridgeCrashRecoveryWindow
    from syncbridge.ui.qt_onboarding import NetworkOptions, QtOnboarding

    calls = []
    previous = QtOnboarding.start

    def forbidden(self):
        calls.append("network started")
        raise AssertionError("Recovery attempted to start network services")

    QtOnboarding.start = forbidden
    store = ConfigStore(profile / "settings.json")
    app = QApplication([])
    window = SyncBridgeCrashRecoveryWindow(
        DesktopController(store), network_options=NetworkOptions()
    )
    window.show()

    try:
        for _ in range(10):
            app.processEvents()
            time.sleep(0.01)

        assert FolderChangeJournal(store).load() is not None
        assert not calls, calls
        assert window._recovery_required
        assert not window._network_started
        assert not window.controller.running
        assert not window.find_button.isEnabled()
        assert not window.reconnect_button.isEnabled()
        assert not window.folder_select_button.isVisible()
        assert not window.preview_button.isEnabled()
        assert not window.sync_button.isEnabled()

    finally:
        window._close_allowed = True
        window.close()
        QtOnboarding.start = previous

    _mark(base, "restart-guard-passed")


def _wait_for(path: Path, processes: dict, deadline_seconds=75) -> None:
    deadline = time.monotonic() + deadline_seconds

    while time.monotonic() < deadline:
        if path.exists():
            return

        for role, (process, log) in processes.items():
            code = process.poll()
            if code is not None and code != CRASH_EXIT:
                pytest.fail(
                    f"{role} exited ({code}) before {path.name}:\n"
                    + log.read_text(
                        encoding="utf-8", errors="replace"
                    )[-5000:]
                )
        time.sleep(0.1)

    details = "\n".join(
        f"{role}: code={process.poll()}\n"
        + log.read_text(
            encoding="utf-8", errors="replace"
        )[-3500:]
        for role, (process, log) in processes.items()
    )
    pytest.fail(f"Timed out waiting for {path.name}\n{details}")


def _launch(base: Path, role: str, crash_role: str, stage: str):
    log = base / f"{role}.log"
    command = [
        sys.executable, "-u", str(Path(__file__).resolve()),
        "--child", role, crash_role, stage, str(base),
    ]
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment["PYTHONPATH"] = (
        str(SOURCE) + os.pathsep + environment.get("PYTHONPATH", "")
    )

    output = log.open("w", encoding="utf-8")
    try:
        process = subprocess.Popen(
            command,
            cwd=PROJECT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
        )
    finally:
        output.close()

    return process, log


def _stop(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


@pytest.mark.parametrize(
    ("crash_role", "stage"),
    [
        ("Bob", "checkpoint"),
        ("Alice", "checkpoint"),
        ("Bob", "committing"),
    ],
)
def test_real_connected_folder_change_crash_is_recoverable(
    tmp_path, crash_role, stage
):
    pytest.importorskip("PySide6")
    from syncbridge.storage.config import ConfigStore
    from syncbridge.storage.folder_change_recovery import FolderChangeJournal

    profiles, roots, listeners, lock, validation, _ = _configure(
        tmp_path, size=8 * 1024 * 1024
    )
    used = {*listeners["Alice"], *listeners["Bob"], lock, validation}

    network = {
        role: {
            **_network_options(used),
            "listeners": list(listeners[role]),
        }
        for role in ("Alice", "Bob")
    }
    network["lock"] = lock
    network["validation"] = validation

    import json
    (tmp_path / "network.json").write_text(
        json.dumps(network), encoding="utf-8"
    )

    snapshots = {
        role: (
            _sha(profiles[role] / "identity.json"),
            _sha(roots[role] / RELATIVE)
            if (roots[role] / RELATIVE).exists()
            else None,
        )
        for role in ("Alice", "Bob")
    }

    processes = {}

    try:
        processes["Bob"] = _launch(
            tmp_path, "Bob", crash_role, stage
        )
        _wait_for(tmp_path / "Bob.listening", processes)

        processes["Alice"] = _launch(
            tmp_path, "Alice", crash_role, stage
        )

        _wait_for(tmp_path / "Alice.connected", processes)
        _wait_for(tmp_path / "Bob.connected", processes)
        _wait_for(tmp_path / "Alice.requested", processes)
        _wait_for(
            tmp_path / f"{crash_role}.crash-point", processes
        )

        crashed, log = processes[crash_role]
        assert crashed.wait(timeout=10) == CRASH_EXIT, log.read_text(
            encoding="utf-8", errors="replace"
        )

    finally:
        for process, _ in processes.values():
            _stop(process)

    assert any(
        FolderChangeJournal(
            ConfigStore(profiles[role] / "settings.json")
        ).load() is not None
        for role in ("Alice", "Bob")
    )

    for role in ("Alice", "Bob"):
        store = ConfigStore(profiles[role] / "settings.json")
        checkpoint = FolderChangeJournal(store).load()

        if checkpoint is not None:
            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--probe",
                    str(profiles[role]),
                    str(tmp_path),
                ],
                cwd=PROJECT,
                env={
                    **os.environ,
                    "QT_QPA_PLATFORM": "offscreen",
                    "PYTHONPATH": str(SOURCE) + os.pathsep
                    + os.environ.get("PYTHONPATH", ""),
                },
                capture_output=True,
                text=True,
                timeout=40,
                check=False,
            )
            assert result.returncode == 0, (
                f"{role} recovery probe failed:\n"
                f"{result.stdout}\n{result.stderr}"
            )
            assert (tmp_path / "restart-guard-passed").is_file()

        assert _sha(
            profiles[role] / "identity.json"
        ) == snapshots[role][0]

        source = roots[role] / RELATIVE
        if snapshots[role][1] is None:
            assert not source.exists()
        else:
            assert _sha(source) == snapshots[role][1]


if __name__ == "__main__":
    if len(sys.argv) == 6 and sys.argv[1] == "--child":
        _child(
            sys.argv[2],
            sys.argv[3],
            sys.argv[4],
            Path(sys.argv[5]),
        )
    elif len(sys.argv) == 4 and sys.argv[1] == "--probe":
        _probe(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        raise SystemExit(
            "This file must be run by pytest or a test subprocess"
        )
