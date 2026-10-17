
"""Smoke-test the actual packaged SyncBridge Windows desktop.

Tests the PyInstaller executable, not the development Python launcher.

The tests run with disposable profiles, isolated loopback ports, and
Qt's offscreen platform. They never open the user's saved SyncBridge
configuration or synchronized folders.

Build first:
    python scripts/build_windows.py

Run:
    python -m pytest tests/integration/test_packaged_windows_desktop.py -v -s

These checks cover executable startup, pairing/listener availability,
identity persistence, peer isolation, and restart. They do not automate
GUI interaction or synchronize files.
"""
from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import sys
import time
from contextlib import ExitStack
from pathlib import Path

import pytest

from test_desktop_crash_resume import (
    MIB,
    RELATIVE,
    _configure,
    _hash,
)

PROJECT = Path(__file__).resolve().parents[2]
EXECUTABLE = PROJECT / "dist" / "SyncBridge" / "SyncBridge.exe"

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="The packaged desktop test requires Windows.",
)


def _require_executable() -> Path:
    if not EXECUTABLE.is_file():
        pytest.skip(
            "Windows executable not found. "
            "Run: python scripts/build_windows.py"
        )
    return EXECUTABLE


def _free_port(used: set[int], *, udp: bool = False) -> int:
    kind = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM

    for _ in range(100):
        with socket.socket(socket.AF_INET, kind) as listener:
            listener.bind(("127.0.0.1", 0))
            port = int(listener.getsockname()[1])

        if port not in used:
            used.add(port)
            return port

    raise RuntimeError("Could not allocate an unused test port")


def _network_options(used: set[int]) -> dict[str, int]:
    return {
        "discovery": _free_port(used, udp=True),
        "pairing": _free_port(used),
        "setup": _free_port(used),
        "activation": _free_port(used),
    }


def _diagnostics(log: Path) -> str:
    try:
        content = log.read_bytes()
    except OSError as exc:
        return f"Could not read packaged desktop log: {exc}"

    return content[-6000:].decode("utf-8", errors="replace")


def _launch(
    stack: ExitStack,
    processes: list[subprocess.Popen],
    *,
    name: str,
    profile: Path,
    workdir: Path,
    listen_ports: tuple[int, int, int],
    lock_port: int,
    validation_port: int,
    options: dict[str, int],
    remote_options: dict[str, int] | None = None,
) -> tuple[subprocess.Popen, Path]:
    executable = _require_executable()

    profile.mkdir(parents=True, exist_ok=True)
    workdir.mkdir(parents=True, exist_ok=True)

    log_path = workdir / f"{name}.log"
    log_handle = stack.enter_context(log_path.open("wb"))

    remote = remote_options or options

    command = [
        str(executable),
        "--profile",
        str(profile.resolve()),
        "--bind-address",
        "127.0.0.1",
        "--listen-ports",
        *(str(port) for port in listen_ports),
        "--lock-port",
        str(lock_port),
        "--validation-port",
        str(validation_port),
        "--discovery-name",
        name,
        "--discovery-port",
        str(options["discovery"]),
        "--discovery-bind",
        "127.0.0.1",
        "--pairing-port",
        str(options["pairing"]),
        "--pairing-bind",
        "127.0.0.1",
        "--setup-port",
        str(options["setup"]),
        "--remote-setup-port",
        str(remote["setup"]),
        "--activation-port",
        str(options["activation"]),
        "--remote-activation-port",
        str(remote["activation"]),
    ]

    if remote_options is not None:
        command.extend(
            [
                "--discovery-target",
                f"127.0.0.1:{remote['discovery']}",
            ]
        )

    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment["PYTHONNOUSERSITE"] = "1"
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)

    process = subprocess.Popen(
        command,
        cwd=workdir,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        close_fds=True,
    )
    processes.append(process)
    return process, log_path


def _wait_for_listener(
    process: subprocess.Popen,
    port: int,
    log: Path,
    *,
    description: str,
    timeout: float = 40.0,
) -> None:
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        exit_code = process.poll()

        if exit_code is not None:
            pytest.fail(
                f"{description} exited unexpectedly "
                f"with code {exit_code}.\n"
                f"{_diagnostics(log)}"
            )

        try:
            with socket.create_connection(
                ("127.0.0.1", port),
                timeout=0.25,
            ):
                return
        except OSError:
            time.sleep(0.15)

    pytest.fail(
        f"{description} did not start listening on "
        f"127.0.0.1:{port}.\n"
        f"{_diagnostics(log)}"
    )


def _assert_alive(
    process: subprocess.Popen,
    log: Path,
    *,
    description: str,
) -> None:
    exit_code = process.poll()

    assert exit_code is None, (
        f"{description} stopped unexpectedly "
        f"(exit code {exit_code}).\n"
        f"{_diagnostics(log)}"
    )


def _stop(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return

    process.terminate()

    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def test_packaged_desktop_first_run_preserves_identity(tmp_path):
    """Fresh packaged installations start pairing and retain identity."""
    _require_executable()

    profile = tmp_path / "FreshDevice" / "Profile"
    workdir = tmp_path / "Runs"
    used: set[int] = set()

    options = _network_options(used)
    listen_ports = tuple(_free_port(used) for _ in range(3))
    lock_port = _free_port(used)
    validation_port = _free_port(used)

    processes: list[subprocess.Popen] = []

    with ExitStack() as stack:
        try:
            first, first_log = _launch(
                stack,
                processes,
                name="FreshDevice",
                profile=profile,
                workdir=workdir,
                listen_ports=listen_ports,
                lock_port=lock_port,
                validation_port=validation_port,
                options=options,
            )

            _wait_for_listener(
                first,
                options["pairing"],
                first_log,
                description="First-run pairing service",
            )

            identity = profile / "identity.json"
            assert identity.is_file(), (
                "The packaged app did not create a device identity"
            )

            original_hash = hashlib.sha256(
                identity.read_bytes()
            ).hexdigest()

            _assert_alive(
                first,
                first_log,
                description="First-run desktop",
            )

            _stop(first)

            second, second_log = _launch(
                stack,
                processes,
                name="FreshDeviceRestart",
                profile=profile,
                workdir=workdir,
                listen_ports=listen_ports,
                lock_port=lock_port,
                validation_port=validation_port,
                options=options,
            )

            _wait_for_listener(
                second,
                options["pairing"],
                second_log,
                description="Restarted pairing service",
            )

            restarted_hash = hashlib.sha256(
                identity.read_bytes()
            ).hexdigest()

            assert restarted_hash == original_hash, (
                "Restarting the packaged app replaced its identity"
            )

            _assert_alive(
                second,
                second_log,
                description="Restarted first-run desktop",
            )

        finally:
            for process in reversed(processes):
                _stop(process)


def test_two_packaged_desktops_survive_receiver_restart(tmp_path):
    """Two actual executables start independently and Bob can restart."""
    _require_executable()

    (
        profiles,
        roots,
        listeners,
        lock_port,
        validation_port,
        source,
    ) = _configure(tmp_path, size=8 * MIB)

    destination = roots["Bob"] / RELATIVE
    original_digest = _hash(source)

    used = {
        *listeners["Alice"],
        *listeners["Bob"],
        lock_port,
        validation_port,
    }

    alice_options = _network_options(used)
    bob_options = _network_options(used)

    processes: list[subprocess.Popen] = []
    workdir = tmp_path / "PackagedRuns"

    with ExitStack() as stack:
        try:
            bob, bob_log = _launch(
                stack,
                processes,
                name="Bob",
                profile=profiles["Bob"],
                workdir=workdir,
                listen_ports=tuple(listeners["Bob"]),
                lock_port=lock_port,
                validation_port=validation_port,
                options=bob_options,
                remote_options=alice_options,
            )

            _wait_for_listener(
                bob,
                listeners["Bob"][0],
                bob_log,
                description="Bob's packaged manifest service",
            )
            _wait_for_listener(
                bob,
                bob_options["pairing"],
                bob_log,
                description="Bob's packaged pairing service",
            )

            alice, alice_log = _launch(
                stack,
                processes,
                name="Alice",
                profile=profiles["Alice"],
                workdir=workdir,
                listen_ports=tuple(listeners["Alice"]),
                lock_port=lock_port,
                validation_port=validation_port,
                options=alice_options,
                remote_options=bob_options,
            )

            _wait_for_listener(
                alice,
                listeners["Alice"][0],
                alice_log,
                description="Alice's packaged manifest service",
            )
            _wait_for_listener(
                alice,
                alice_options["pairing"],
                alice_log,
                description="Alice's packaged pairing service",
            )

            _assert_alive(
                alice,
                alice_log,
                description="Alice's packaged desktop",
            )
            _assert_alive(
                bob,
                bob_log,
                description="Bob's packaged desktop",
            )

            assert profiles["Alice"] != profiles["Bob"]
            assert roots["Alice"] != roots["Bob"]

            _stop(bob)

            _assert_alive(
                alice,
                alice_log,
                description="Alice after Bob stopped",
            )

            restarted_bob, restart_log = _launch(
                stack,
                processes,
                name="BobRestart",
                profile=profiles["Bob"],
                workdir=workdir,
                listen_ports=tuple(listeners["Bob"]),
                lock_port=lock_port,
                validation_port=validation_port,
                options=bob_options,
                remote_options=alice_options,
            )

            _wait_for_listener(
                restarted_bob,
                listeners["Bob"][0],
                restart_log,
                description="Restarted Bob manifest service",
            )
            _wait_for_listener(
                restarted_bob,
                bob_options["pairing"],
                restart_log,
                description="Restarted Bob pairing service",
            )

            _assert_alive(
                alice,
                alice_log,
                description="Alice after Bob restarted",
            )
            _assert_alive(
                restarted_bob,
                restart_log,
                description="Restarted Bob desktop",
            )

            assert source.is_file()
            assert _hash(source) == original_digest
            assert not destination.exists(), (
                "The packaged smoke test unexpectedly modified "
                "the receiver's shared folder"
            )

        finally:
            for process in reversed(processes):
                _stop(process)
