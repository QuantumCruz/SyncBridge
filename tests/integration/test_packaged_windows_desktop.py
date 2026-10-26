
"""Exercise actual packaged Windows desktops using the current approval lifecycle.

First-run identity uses a headless Qt platform. Connected/restart scenarios
use real, visible Qt windows and Windows UI Automation. All settings, ports,
files and identities are disposable. Keep the Windows session unlocked.

Build the latest sources first: python scripts/build_windows.py --console
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
from typing import Callable

import pytest

from test_desktop_crash_resume import MIB, RELATIVE, _configure, _hash

PROJECT = Path(__file__).resolve().parents[2]
EXECUTABLE = PROJECT / "dist" / "SyncBridge" / "SyncBridge.exe"

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Packaged desktop tests require Windows"
)


def _require_executable() -> Path:
    if not EXECUTABLE.is_file():
        pytest.skip(
            "Build the Windows desktop first: "
            "python scripts/build_windows.py --console"
        )

    sources = (
        PROJECT / "scripts" / "desktop_qt.py",
        PROJECT / "src" / "syncbridge" / "ui"
        / "qt_crash_recovery_window.py",
        PROJECT / "src" / "syncbridge" / "ui"
        / "qt_release_window.py",
        PROJECT / "src" / "syncbridge" / "network"
        / "folder_change_session.py",
    )

    outdated = [
        path for path in sources
        if path.is_file()
        and path.stat().st_mtime > EXECUTABLE.stat().st_mtime + 2
    ]

    if outdated:
        pytest.fail(
            "The packaged EXE is older than the current "
            "SyncBridge sources. Rebuild with: "
            "python scripts/build_windows.py --console\n"
            + "\n".join(
                str(path.relative_to(PROJECT))
                for path in outdated
            ),
            pytrace=False,
        )

    return EXECUTABLE


def _require_ui() -> None:
    try:
        import pywinauto  # noqa: F401
        import win32gui  # noqa: F401
        import win32process  # noqa: F401
    except ImportError:
        pytest.fail(
            "Windows UI test requires: "
            'python -m pip install "pywinauto>=0.6.8"',
            pytrace=False,
        )


def _free_port(
    used: set[int],
    *,
    udp: bool = False,
) -> int:
    kind = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM

    for _ in range(100):
        with socket.socket(socket.AF_INET, kind) as sock:
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])

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
        return log.read_bytes()[-8000:].decode(
            "utf-8", errors="replace"
        )
    except OSError as exc:
        return f"Cannot read desktop log: {exc}"


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
    visible: bool = False,
) -> tuple[subprocess.Popen, Path]:
    executable = _require_executable()

    profile.mkdir(parents=True, exist_ok=True)
    workdir.mkdir(parents=True, exist_ok=True)

    log = workdir / f"{name}-{len(processes)}.log"
    output = stack.enter_context(log.open("wb"))
    remote = remote_options or options

    command = [
        str(executable),
        "--profile", str(profile.resolve()),
        "--bind-address", "127.0.0.1",
        "--listen-ports",
        *(str(port) for port in listen_ports),
        "--lock-port", str(lock_port),
        "--validation-port", str(validation_port),
        "--discovery-name", name,
        "--discovery-port", str(options["discovery"]),
        "--discovery-bind", "127.0.0.1",
        "--pairing-port", str(options["pairing"]),
        "--pairing-bind", "127.0.0.1",
        "--setup-port", str(options["setup"]),
        "--remote-setup-port", str(remote["setup"]),
        "--activation-port", str(options["activation"]),
        "--remote-activation-port", str(remote["activation"]),
    ]

    if remote_options is not None:
        command += [
            "--discovery-target",
            f'127.0.0.1:{remote["discovery"]}',
        ]

    environment = os.environ.copy()

    for key in (
        "QT_QPA_PLATFORM",
        "QT_PLUGIN_PATH",
        "QT_QPA_PLATFORM_PLUGIN_PATH",
        "PYTHONPATH",
        "PYTHONHOME",
    ):
        environment.pop(key, None)

    environment["PYTHONNOUSERSITE"] = "1"

    if not visible:
        environment["QT_QPA_PLATFORM"] = "offscreen"

    process = subprocess.Popen(
        command,
        cwd=workdir,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=output,
        stderr=subprocess.STDOUT,
        close_fds=True,
    )

    processes.append(process)
    return process, log


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
        _assert_alive(
            process,
            log,
            description=description,
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
        f"{description} did not listen on "
        f"127.0.0.1:{port}.\n{_diagnostics(log)}"
    )


def _assert_alive(
    process: subprocess.Popen,
    log: Path,
    *,
    description: str,
) -> None:
    code = process.poll()

    assert code is None, (
        f"{description} exited unexpectedly ({code}).\n"
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


def _process_windows(pid: int) -> list[tuple[int, str]]:
    import win32gui
    import win32process

    windows = []

    def collect(hwnd, _unused):
        try:
            _, owner = win32process.GetWindowThreadProcessId(hwnd)
            if owner == pid and win32gui.IsWindowVisible(hwnd):
                windows.append(
                    (
                        hwnd,
                        win32gui.GetWindowText(hwnd).strip(),
                    )
                )
        except Exception:
            pass

    win32gui.EnumWindows(collect, None)
    return windows


def _modal_handle(
    pid: int,
    title: str,
) -> int | None:
    return next(
        (
            hwnd
            for hwnd, caption in _process_windows(pid)
            if caption.casefold() == title.casefold()
        ),
        None,
    )


def _ui_diagnostics(
    process: subprocess.Popen,
    log: Path,
) -> str:
    info = [
        f"PID={process.pid}; exit={process.poll()}",
        "Visible native windows:",
    ]

    try:
        info.extend(
            f"  {hwnd} {title!r}"
            for hwnd, title in _process_windows(process.pid)
        )

        from pywinauto import Desktop

        for window in Desktop(backend="uia").windows():
            try:
                if window.element_info.process_id != process.pid:
                    continue

                info.append(
                    f"UIA window: {window.window_text()!r}"
                )

                for item in window.descendants(
                    control_type="Button"
                )[:20]:
                    info.append(
                        f"  Button {item.window_text()!r}: "
                        f"enabled={item.is_enabled()}"
                    )

                for item in window.descendants(
                    control_type="Text"
                )[:12]:
                    label = item.window_text().strip()
                    if label:
                        info.append(f"  Text: {label[:180]}")

            except Exception as exc:
                info.append(
                    f"  UIA inspection error: {exc!r}"
                )

    except Exception as exc:
        info.append(f"UI inspection error: {exc!r}")

    info.append(
        "Application log:\n" + _diagnostics(log)
    )
    return "\n".join(info)


def _until(
    description: str,
    predicate: Callable[[], bool],
    *,
    process: subprocess.Popen,
    log: Path,
    timeout: float = 55.0,
) -> None:
    deadline = time.monotonic() + timeout
    last_error = None

    while time.monotonic() < deadline:
        _assert_alive(
            process,
            log,
            description=description,
        )

        try:
            if predicate():
                return
        except Exception as exc:
            last_error = exc

        time.sleep(0.2)

    pytest.fail(
        f"Timed out waiting for {description}; "
        f"last error={last_error!r}\n"
        + _ui_diagnostics(process, log)
    )


def _connect_uia(
    process: subprocess.Popen,
    log: Path,
):
    from pywinauto.application import Application

    app = Application(backend="uia").connect(
        process=process.pid,
        timeout=40,
    )

    window = app.window(
        title="SyncBridge",
        control_type="Window",
    )

    _until(
        "the main SyncBridge window",
        lambda: window.exists() and window.is_visible(),
        process=process,
        log=log,
    )

    return window


def _enabled(window, label: str) -> bool:
    button = window.child_window(
        title=label,
        control_type="Button",
    )

    return (
        button.exists()
        and button.is_visible()
        and button.is_enabled()
    )


def _click_enabled_button(
    window,
    label: str,
    process: subprocess.Popen,
    log: Path,
    *,
    timeout: float = 75.0,
) -> None:
    _until(
        f"enabled {label!r} button",
        lambda: _enabled(window, label),
        process=process,
        log=log,
        timeout=timeout,
    )

    button = window.child_window(
        title=label,
        control_type="Button",
    )

    window.wrapper_object().set_focus()
    button.wrapper_object().click_input()


def _approve_dialog(
    process: subprocess.Popen,
    log: Path,
    title: str,
) -> None:
    from pywinauto import Desktop

    _until(
        f"{title!r} confirmation dialog",
        lambda: _modal_handle(process.pid, title) is not None,
        process=process,
        log=log,
        timeout=40,
    )

    handle = _modal_handle(process.pid, title)
    assert handle is not None

    click_error = None

    try:
        window = Desktop(backend="uia").window(handle=handle)
        yes = window.child_window(
            title_re=r"^&?Yes$",
            control_type="Button",
        )

        if not yes.exists(timeout=3) or not yes.is_enabled():
            raise LookupError(
                "Modal Yes button is not accessible"
            )

        yes.wrapper_object().click_input()

    except Exception as exc:
        click_error = exc

    # Give Qt time to process the UI Automation click.
    deadline = time.monotonic() + 1.5

    while (
        _modal_handle(process.pid, title) is not None
        and time.monotonic() < deadline
    ):
        time.sleep(0.1)

    # Fallback for Qt/Windows accessibility variations.
    if _modal_handle(process.pid, title) is not None:
        try:
            from pywinauto.keyboard import send_keys

            Desktop(
                backend="win32"
            ).window(handle=handle).set_focus()

            send_keys("%y", pause=0.05)

        except Exception as exc:
            pytest.fail(
                f"Cannot approve {title!r}: "
                f"UIA={click_error!r}; "
                f"keyboard={exc!r}\n"
                + _ui_diagnostics(process, log)
            )

    _until(
        f"{title!r} dialog to close",
        lambda: _modal_handle(process.pid, title) is None,
        process=process,
        log=log,
        timeout=20,
    )


def _wait_connected(
    window,
    process: subprocess.Popen,
    log: Path,
) -> None:
    _until(
        "desktop Connected with transfer controls",
        lambda: (
            _enabled(window, "Preview differences")
            and _enabled(window, "Disconnect")
            and _enabled(window, "Change folders")
        ),
        process=process,
        log=log,
        timeout=70,
    )


def _connect_pair(
    initiator: tuple[
        subprocess.Popen, Path, object, str
    ],
    receiver: tuple[
        subprocess.Popen, Path, object, str
    ],
) -> None:
    first, first_log, first_window, _ = initiator
    second, second_log, second_window, name = receiver

    _click_enabled_button(
        first_window,
        f"Reconnect to {name}",
        first,
        first_log,
        timeout=45,
    )

    _approve_dialog(
        second,
        second_log,
        "Connection request",
    )

    _wait_connected(
        first_window,
        first,
        first_log,
    )

    _wait_connected(
        second_window,
        second,
        second_log,
    )


def _wait_disconnected(
    window,
    process: subprocess.Popen,
    log: Path,
    peer: str,
) -> None:
    _until(
        f"disconnect detection after {peer} stopped",
        lambda: (
            _enabled(window, f"Reconnect to {peer}")
            and not _enabled(window, "Preview differences")
        ),
        process=process,
        log=log,
        timeout=50,
    )


def test_packaged_desktop_first_run_preserves_identity(tmp_path):
    _require_executable()

    profile = tmp_path / "FreshDevice" / "Profile"
    used: set[int] = set()

    options = _network_options(used)
    ports = tuple(_free_port(used) for _ in range(3))
    lock_port = _free_port(used)
    validation_port = _free_port(used)

    processes = []

    with ExitStack() as stack:
        try:
            first, first_log = _launch(
                stack,
                processes,
                name="FreshDevice",
                profile=profile,
                workdir=tmp_path / "Runs",
                listen_ports=ports,
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
            assert identity.is_file()

            original_hash = hashlib.sha256(
                identity.read_bytes()
            ).hexdigest()

            _stop(first)

            second, second_log = _launch(
                stack,
                processes,
                name="FreshDevice",
                profile=profile,
                workdir=tmp_path / "Runs",
                listen_ports=ports,
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

            assert hashlib.sha256(
                identity.read_bytes()
            ).hexdigest() == original_hash

            _assert_alive(
                second,
                second_log,
                description="Restarted desktop",
            )

        finally:
            for process in reversed(processes):
                _stop(process)


def test_two_packaged_desktops_survive_receiver_restart(tmp_path):
    """Both peers approve a live connection and reconnect after Bob dies."""
    _require_ui()
    _require_executable()

    (
        profiles,
        roots,
        listeners,
        lock,
        validation,
        source,
    ) = _configure(tmp_path, size=8 * MIB)

    digest = _hash(source)
    destination = roots["Bob"] / RELATIVE

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

            _connect_pair(
                (alice, alice_log, alice_window, "Alice"),
                (bob, bob_log, bob_window, "Bob"),
            )

            # Transfer listeners must open only after approval.
            _wait_for_listener(
                bob,
                listeners["Bob"][0],
                bob_log,
                description="Connected Bob manifest listener",
            )

            _wait_for_listener(
                alice,
                listeners["Alice"][0],
                alice_log,
                description="Connected Alice manifest listener",
            )

            assert not destination.exists(), (
                "Connection must not automatically synchronize"
            )

            _stop(bob)

            _wait_disconnected(
                alice_window,
                alice,
                alice_log,
                "Bob",
            )

            restarted, restart_log = _launch(
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
                restarted,
                bob_options["pairing"],
                restart_log,
                description="Restarted Bob pairing listener",
            )

            restart_window = _connect_uia(
                restarted,
                restart_log,
            )

            _connect_pair(
                (restarted, restart_log, restart_window, "Bob"),
                (alice, alice_log, alice_window, "Alice"),
            )

            _wait_for_listener(
                restarted,
                listeners["Bob"][0],
                restart_log,
                description="Reconnected Bob manifest listener",
            )

            assert not destination.exists(), (
                "Restart must not implicitly synchronize"
            )

            assert _hash(source) == digest

            _assert_alive(
                alice,
                alice_log,
                description="Alice after Bob's restart",
            )

            _assert_alive(
                restarted,
                restart_log,
                description="Bob after reconnecting",
            )

        finally:
            for process in reversed(processes):
                _stop(process)
