
"""Exercise the Qt local-file refresh workflow in isolated processes.

Each test uses its own QApplication and window lifetime. A native Qt abort in
one child is reported as a test failure, rather than terminating the entire
pytest session. The app's production behavior is unchanged by this file.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest


_CHILD_FLAG = "SYNCBRIDGE_QT_LOCAL_REFRESH_CHILD"


def _exercise(case: str, tmp_path: Path, monkeypatch) -> None:
    # Import Qt only inside the disposable child process.
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    pytest.importorskip("PySide6")

    from PySide6.QtWidgets import QApplication

    from syncbridge.ui.desktop_controller import DesktopProfile
    from syncbridge.ui.qt_local_refresh import QtLocalFileRefresh
    from syncbridge.ui.qt_window import SyncBridgeQtWindow

    class FakeController:
        def __init__(self, root: Path) -> None:
            self.root = root
            self.running = False
            self.starts = 0
            self.stops = 0

        def profile(self):
            return DesktopProfile(
                device_name="Bob",
                folder_name="Shared",
                local_root=self.root,
                peer_node_id="a" * 32,
                remote_host="127.0.0.1",
            )

        def start(self) -> None:
            self.starts += 1
            self.running = True

        def stop(self) -> None:
            self.stops += 1
            self.running = False

        def preview(self):
            raise AssertionError(
                "Passive receiver must not start Preview"
            )

        def sync_once(self, **kwargs):
            raise AssertionError(
                "Passive receiver must not initiate Sync"
            )

    app = QApplication.instance() or QApplication([])
    original_quit_setting = app.quitOnLastWindowClosed()
    app.setQuitOnLastWindowClosed(False)

    def wait_for(predicate, *, seconds: float = 8.0) -> bool:
        deadline = time.monotonic() + seconds

        while time.monotonic() < deadline:
            app.processEvents()

            if predicate():
                return True

            time.sleep(0.01)

        app.processEvents()
        return bool(predicate())

    window = None
    watcher = None

    try:
        (tmp_path / "original.txt").write_text(
            "Original",
            encoding="utf-8",
        )

        controller = FakeController(tmp_path)
        window = SyncBridgeQtWindow(controller)
        window.show()

        assert wait_for(
            lambda: (
                controller.running
                and not window._busy
                and "local" in window._loaded
                and window.local_table.rowCount() == 1
            )
        ), "Receiver did not load its initial file list"

        watcher = QtLocalFileRefresh(
            window,
            interval_ms=75,
        )

        if case == "new-file":
            (tmp_path / "from_alice.txt").write_text(
                "Hello from Alice",
                encoding="utf-8",
            )

            assert wait_for(
                lambda: (
                    window.local_table.rowCount() == 2
                    and not window._busy
                    and {
                        window.local_table.item(i, 0).text()
                        for i in range(window.local_table.rowCount())
                    }
                    == {"original.txt", "from_alice.txt"}
                )
            ), "Receiver did not refresh after a file arrived"

            assert controller.starts == 1

        elif case == "unchanged":
            rebuilt = []
            old_display = window._display_files

            def record(kind, result):
                rebuilt.append(kind)
                old_display(kind, result)

            monkeypatch.setattr(
                window,
                "_display_files",
                record,
            )

            watcher.check()

            assert wait_for(
                lambda: not watcher._scanning
            ), "Local refresh scanner did not finish"

            assert rebuilt == []
            assert window.local_table.rowCount() == 1

        elif case == "disconnected":
            window.disconnect_button.click()

            assert wait_for(
                lambda: (
                    not controller.running
                    and not window._busy
                )
            ), "Receiver did not disconnect"

            (tmp_path / "later.txt").write_text(
                "Not connected",
                encoding="utf-8",
            )

            watcher.check()
            app.processEvents()

            assert window._paused
            assert window.local_table.rowCount() == 0

        else:
            raise AssertionError(
                f"Unknown Qt test case: {case}"
            )

    finally:
        if watcher is not None:
            watcher.timer.stop()

            assert wait_for(
                lambda: not watcher._scanning
            ), (
                "A local refresh worker was still "
                "active during cleanup"
            )

        if window is not None:
            window.close()

            assert wait_for(
                lambda: not window.isVisible(),
                seconds=12,
            ), "Receiver did not close cleanly"

        app.setQuitOnLastWindowClosed(
            original_quit_setting
        )


def _run_case(
    test_name: str,
    case: str,
    tmp_path: Path,
    monkeypatch,
) -> None:
    if os.environ.get(_CHILD_FLAG) == "1":
        _exercise(case, tmp_path, monkeypatch)
        return

    project_root = Path(__file__).resolve().parents[2]

    environment = os.environ.copy()
    environment[_CHILD_FLAG] = "1"
    environment["QT_QPA_PLATFORM"] = "offscreen"

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "-s",
                str(Path(__file__).resolve()),
                "-k",
                test_name,
            ],
            cwd=project_root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=75,
            check=False,
        )

    except subprocess.TimeoutExpired as exc:
        pytest.fail(
            f"Isolated Qt test {test_name} timed out. "
            f"Output: {exc.stdout!r}",
            pytrace=False,
        )

    assert result.returncode == 0, (
        f"Isolated Qt test {test_name} failed "
        f"(exit code {result.returncode}):\n"
        f"{result.stdout}"
    )


def test_receiving_new_file_refreshes_view_without_user_action(
    tmp_path,
    monkeypatch,
):
    _run_case(
        "test_receiving_new_file_refreshes_view_without_user_action",
        "new-file",
        tmp_path,
        monkeypatch,
    )


def test_unchanged_files_do_not_rebuild_table(
    tmp_path,
    monkeypatch,
):
    _run_case(
        "test_unchanged_files_do_not_rebuild_table",
        "unchanged",
        tmp_path,
        monkeypatch,
    )


def test_disconnected_receiver_does_not_refresh(
    tmp_path,
    monkeypatch,
):
    _run_case(
        "test_disconnected_receiver_does_not_refresh",
        "disconnected",
        tmp_path,
        monkeypatch,
    )
