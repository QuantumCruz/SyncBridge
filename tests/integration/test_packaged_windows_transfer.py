
"""Verify bidirectional transfers through the packaged Windows desktop.

Uses the real PyInstaller executable and two visible Qt windows.
Only disposable pytest profiles and folders are used.

Requires an unlocked interactive Windows desktop and pywinauto.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from contextlib import ExitStack
from pathlib import Path
from typing import Callable

import pytest

from test_desktop_crash_resume import MIB, RELATIVE, _configure, _hash
from test_packaged_windows_desktop import (
    _assert_alive,
    _diagnostics,
    _network_options,
    _require_executable,
    _stop,
    _wait_for_listener,
)

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="The packaged GUI integration test requires Windows.",
)


def _process_windows(pid: int) -> list[tuple[int, str]]:
    """Read visible native Windows windows owned by a specific process."""
    import win32gui
    import win32process

    found: list[tuple[int, str]] = []

    def collect(hwnd: int, _argument) -> None:
        try:
            _, owner_pid = win32process.GetWindowThreadProcessId(hwnd)
            if owner_pid != pid:
                return
            if not win32gui.IsWindowVisible(hwnd):
                return

            title = win32gui.GetWindowText(hwnd).strip()
            found.append((hwnd, title))
        except Exception:
            return

    win32gui.EnumWindows(collect, None)
    return found


def _confirmation_handle(pid: int) -> int | None:
    """Find only this process's actual SyncBridge confirmation window."""
    for handle, title in _process_windows(pid):
        if title.casefold() == "sync these files?":
            return handle
    return None


def _desktop_diagnostics(pid: int) -> str:
    """Capture useful UI information if automation or syncing stalls."""
    lines = ["Native Windows windows:"]

    try:
        windows = _process_windows(pid)
        if not windows:
            lines.append("  No visible windows found.")

        for handle, title in windows:
            lines.append(f"  HWND={handle}: {title!r}")
    except Exception as exc:
        lines.append(f"  Native enumeration failed: {exc!r}")

    lines.append("UI Automation windows:")

    try:
        from pywinauto import Desktop

        found = False

        for window in Desktop(backend="uia").windows():
            try:
                if window.element_info.process_id != pid:
                    continue

                found = True
                lines.append(f"  Window: {window.window_text()!r}")

                visible_text = []

                for control in window.descendants(control_type="Text"):
                    value = control.window_text().strip()
                    if value:
                        visible_text.append(value[:180])
                    if len(visible_text) >= 15:
                        break

                for value in visible_text:
                    lines.append(f"    {value}")

                buttons = window.descendants(control_type="Button")

                for button in buttons[:15]:
                    lines.append(
                        f"    Button: {button.window_text()!r}, "
                        f"enabled={button.is_enabled()}"
                    )
            except Exception as exc:
                lines.append(f"  Could not inspect window: {exc!r}")

        if not found:
            lines.append("  No process-owned UIA windows found.")

    except Exception as exc:
        lines.append(f"  UIA diagnostics unavailable: {exc!r}")

    return "\n".join(lines)


def _failure_details(process: subprocess.Popen, log: Path) -> str:
    return (
        f"Process ID: {process.pid}\n"
        f"Return code: {process.poll()}\n"
        f"{_desktop_diagnostics(process.pid)}\n"
        f"Application output:\n{_diagnostics(log)}"
    )


def _launch_visible(
    stack: ExitStack,
    processes: list[subprocess.Popen],
    *,
    name: str,
    profile: Path,
    working_dir: Path,
    listen_ports: tuple[int, int, int],
    lock_port: int,
    validation_port: int,
    options: dict[str, int],
    remote_options: dict[str, int],
) -> tuple[subprocess.Popen, Path]:
    executable = _require_executable()

    working_dir.mkdir(parents=True, exist_ok=True)
    profile.mkdir(parents=True, exist_ok=True)

    log_path = working_dir / f"{name}.log"
    output = stack.enter_context(log_path.open("wb"))

    command = [
        str(executable),
        "--profile", str(profile.resolve()),
        "--bind-address", "127.0.0.1",
        "--listen-ports", *(str(port) for port in listen_ports),
        "--lock-port", str(lock_port),
        "--validation-port", str(validation_port),
        "--discovery-name", name,
        "--discovery-port", str(options["discovery"]),
        "--discovery-bind", "127.0.0.1",
        "--discovery-target",
        f"127.0.0.1:{remote_options['discovery']}",
        "--pairing-port", str(options["pairing"]),
        "--pairing-bind", "127.0.0.1",
        "--setup-port", str(options["setup"]),
        "--remote-setup-port", str(remote_options["setup"]),
        "--activation-port", str(options["activation"]),
        "--remote-activation-port",
        str(remote_options["activation"]),
    ]

    environment = os.environ.copy()

    for key in (
        "QT_QPA_PLATFORM",
        "QT_PLUGIN_PATH",
        "QT_QPA_PLATFORM_PLUGIN_PATH",
        "PYTHONHOME",
        "PYTHONPATH",
    ):
        environment.pop(key, None)

    environment["PYTHONNOUSERSITE"] = "1"

    process = subprocess.Popen(
        command,
        cwd=working_dir,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=output,
        stderr=subprocess.STDOUT,
        close_fds=True,
    )

    processes.append(process)
    return process, log_path


def _until(
    description: str,
    check: Callable[[], bool],
    *,
    process: subprocess.Popen,
    log: Path,
    timeout: float = 45.0,
) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None

    while time.monotonic() < deadline:
        if process.poll() is not None:
            pytest.fail(
                f"{description}: executable exited unexpectedly.\n"
                f"{_failure_details(process, log)}"
            )

        try:
            if check():
                return
        except Exception as exc:
            last_error = exc

        time.sleep(0.2)

    pytest.fail(
        f"Timed out waiting for {description}.\n"
        f"Last automation error: {last_error!r}\n"
        f"{_failure_details(process, log)}"
    )


def _connect_uia(process: subprocess.Popen, log: Path):
    from pywinauto.application import Application

    application = Application(backend="uia").connect(
        process=process.pid,
        timeout=40,
    )

    window = application.window(
        title="SyncBridge",
        control_type="Window",
    )

    _until(
        "the SyncBridge main window",
        lambda: window.exists() and window.is_visible(),
        process=process,
        log=log,
    )

    return application, window


def _click_enabled_button(
    window,
    label: str,
    process: subprocess.Popen,
    log: Path,
    *,
    physical: bool = False,
) -> None:
    button = window.child_window(
        title=label,
        control_type="Button",
    )

    _until(
        f"enabled {label!r} button",
        lambda: button.exists() and button.is_enabled(),
        process=process,
        log=log,
    )

    if physical:
        window.wrapper_object().set_focus()
        button.wrapper_object().click_input()
    else:
        button.wrapper_object().click()


def _keyboard_approve_dialog(handle: int) -> None:
    """Approve only the previously identified SyncBridge dialog."""
    from pywinauto import Desktop
    from pywinauto.keyboard import send_keys

    dialog = Desktop(backend="win32").window(handle=handle)
    dialog.set_focus()

    # Qt's standard Windows Yes button supports Alt+Y.
    send_keys("%y", pause=0.05)


def _approve_confirmation(
    process: subprocess.Popen,
    log: Path,
) -> None:
    """Locate the real modal window and explicitly approve the transfer."""
    print(
        f"[SyncBridge GUI test] Waiting for confirmation "
        f"from PID {process.pid}",
        flush=True,
    )

    _until(
        "the native Sync these files? confirmation window",
        lambda: _confirmation_handle(process.pid) is not None,
        process=process,
        log=log,
        timeout=15,
    )

    handle = _confirmation_handle(process.pid)
    assert handle is not None

    print(
        f"[SyncBridge GUI test] Found confirmation window HWND={handle}",
        flush=True,
    )

    accessibility_error: Exception | None = None

    try:
        from pywinauto import Desktop

        dialog = Desktop(backend="uia").window(handle=handle)
        yes_button = dialog.child_window(
            title_re=r"^&?Yes$",
            control_type="Button",
        )

        if not yes_button.exists(timeout=2):
            raise LookupError(
                "Qt Yes button was not exposed through UI Automation"
            )

        if not yes_button.is_enabled():
            raise RuntimeError(
                "Qt Yes button was exposed but disabled"
            )

        yes_button.wrapper_object().click_input()

        print(
            "[SyncBridge GUI test] Clicked Yes through UI Automation",
            flush=True,
        )

    except Exception as exc:
        accessibility_error = exc
        print(
            f"[SyncBridge GUI test] UIA button interaction unavailable: "
            f"{exc!r}",
            flush=True,
        )

    # Allow the modal window to close after a successful UIA click.
    deadline = time.monotonic() + 2.0

    while time.monotonic() < deadline:
        if _confirmation_handle(process.pid) is None:
            break
        time.sleep(0.1)

    # Qt/Windows accessibility varies between systems. When the
    # dialog remains visible, use its standard keyboard accelerator.
    remaining_handle = _confirmation_handle(process.pid)

    if remaining_handle is not None:
        try:
            print(
                "[SyncBridge GUI test] Trying focused Alt+Y confirmation",
                flush=True,
            )
            _keyboard_approve_dialog(remaining_handle)
        except Exception as exc:
            pytest.fail(
                "Could not approve the SyncBridge confirmation dialog.\n"
                f"UIA error: {accessibility_error!r}\n"
                f"Keyboard error: {exc!r}\n"
                f"{_failure_details(process, log)}"
            )

    _until(
        "the confirmation window to close after Yes",
        lambda: _confirmation_handle(process.pid) is None,
        process=process,
        log=log,
        timeout=15,
    )

    print(
        "[SyncBridge GUI test] Confirmation closed; "
        "checking the transfer result",
        flush=True,
    )


def _sync_from_gui(
    window,
    process: subprocess.Popen,
    log: Path,
) -> None:
    _click_enabled_button(
        window,
        "Preview differences",
        process,
        log,
    )

    _click_enabled_button(
        window,
        "Sync files",
        process,
        log,
        physical=True,
    )

    _approve_confirmation(process, log)


def _wait_for_file(
    destination: Path,
    expected_size: int,
    *,
    process: subprocess.Popen,
    log: Path,
    description: str,
) -> None:
    _until(
        description,
        lambda: (
            destination.is_file()
            and destination.stat().st_size == expected_size
        ),
        process=process,
        log=log,
        timeout=90,
    )


def _wait_for_sync_ready(
    window,
    process: subprocess.Popen,
    log: Path,
) -> None:
    button = window.child_window(
        title="Preview differences",
        control_type="Button",
    )

    _until(
        "the desktop to finish synchronization",
        lambda: button.exists() and button.is_enabled(),
        process=process,
        log=log,
        timeout=35,
    )


def test_packaged_windows_gui_sends_and_receives_files(tmp_path):
    """Use real Qt windows to transfer verified files in both directions."""
    _require_executable()

    try:
        import pywinauto  # noqa: F401
        import win32gui  # noqa: F401
        import win32process  # noqa: F401
    except ImportError:
        pytest.fail(
            "Install the Windows test dependency: "
            'python -m pip install "pywinauto>=0.6.8"',
            pytrace=False,
        )

    (
        profiles,
        roots,
        listeners,
        lock_port,
        validation_port,
        alice_original,
    ) = _configure(tmp_path, size=8 * MIB)

    bob_received = roots["Bob"] / RELATIVE
    original_digest = _hash(alice_original)

    used = {
        *listeners["Alice"],
        *listeners["Bob"],
        lock_port,
        validation_port,
    }

    alice_options = _network_options(used)
    bob_options = _network_options(used)

    workdir = tmp_path / "VisibleWindows"
    processes: list[subprocess.Popen] = []

    with ExitStack() as stack:
        try:
            bob, bob_log = _launch_visible(
                stack,
                processes,
                name="Bob",
                profile=profiles["Bob"],
                working_dir=workdir,
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
                description="Packaged Bob manifest service",
            )

            alice, alice_log = _launch_visible(
                stack,
                processes,
                name="Alice",
                profile=profiles["Alice"],
                working_dir=workdir,
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
                description="Packaged Alice manifest service",
            )

            _, alice_window = _connect_uia(alice, alice_log)
            _, bob_window = _connect_uia(bob, bob_log)

            assert not bob_received.exists()

            print(
                "[SyncBridge GUI test] Starting Alice -> Bob",
                flush=True,
            )

            _sync_from_gui(
                alice_window,
                alice,
                alice_log,
            )

            _wait_for_file(
                bob_received,
                alice_original.stat().st_size,
                process=alice,
                log=alice_log,
                description="Alice's file to arrive on Bob's disk",
            )

            assert _hash(bob_received) == original_digest, (
                "Alice-to-Bob transfer failed SHA-256 verification"
            )

            _wait_for_sync_ready(
                alice_window,
                alice,
                alice_log,
            )

            print(
                "[SyncBridge GUI test] Alice -> Bob verified",
                flush=True,
            )

            bob_original = (
                roots["Bob"] / "dataset" / "bob-return.bin"
            )
            bob_original.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            bob_original.write_bytes(os.urandom(512 * 1024))
            bob_original_digest = _hash(bob_original)

            alice_received = (
                roots["Alice"] / "dataset" / "bob-return.bin"
            )

            assert not alice_received.exists()

            print(
                "[SyncBridge GUI test] Starting Bob -> Alice",
                flush=True,
            )

            _sync_from_gui(
                bob_window,
                bob,
                bob_log,
            )

            _wait_for_file(
                alice_received,
                bob_original.stat().st_size,
                process=bob,
                log=bob_log,
                description="Bob's file to arrive on Alice's disk",
            )

            assert _hash(alice_received) == bob_original_digest, (
                "Bob-to-Alice transfer failed SHA-256 verification"
            )

            _wait_for_sync_ready(
                bob_window,
                bob,
                bob_log,
            )

            assert _hash(alice_original) == original_digest
            assert _hash(bob_received) == original_digest

            _assert_alive(
                alice,
                alice_log,
                description="Packaged Alice GUI",
            )

            _assert_alive(
                bob,
                bob_log,
                description="Packaged Bob GUI",
            )

            print(
                "[SyncBridge GUI test] Both directions verified",
                flush=True,
            )

        finally:
            for process in reversed(processes):
                _stop(process)
