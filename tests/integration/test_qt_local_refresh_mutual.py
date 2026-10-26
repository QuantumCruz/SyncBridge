
"""Check passive local-file refresh in the mutual-session desktop.

An isolated Qt child process protects the main test run from native Qt aborts.
No network connections or synchronization operations are started.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest


_CHILD_FLAG = "SYNCBRIDGE_QT_MUTUAL_REFRESH_CHILD"


def _exercise(tmp_path: Path) -> None:
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import (
        QApplication, QTabWidget, QTableWidget, QTableWidgetItem, QWidget,
    )
    from syncbridge.ui.desktop_controller import DesktopPhase
    from syncbridge.ui.qt_local_refresh import QtLocalFileRefresh

    class Window(QWidget):
        def __init__(self) -> None:
            super().__init__()
            self._closing = False
            self._busy = False
            self.controller = SimpleNamespace(
                running=True,
                profile=lambda: SimpleNamespace(local_root=tmp_path),
            )
            self.lifecycle = SimpleNamespace(phase=DesktopPhase.CONNECTED)
            self.tabs = QTabWidget(self)
            self.tabs.addTab(QWidget(), "My files")
            self.local_table = QTableWidget(0, 2, self)
            self.updates = 0

        @staticmethod
        def _size(size: int) -> str:
            return f"{size} B"

        def _list_local(self):
            return sorted(
                (file.name, file.stat().st_size)
                for file in tmp_path.iterdir()
                if file.is_file()
            )

        def _show_files(self, table, rows):
            self.updates += 1
            table.setRowCount(len(rows))
            for index, (name, size) in enumerate(rows):
                table.setItem(index, 0, QTableWidgetItem(name))
                table.setItem(index, 1, QTableWidgetItem(self._size(size)))

    app = QApplication.instance() or QApplication([])
    previous_quit = app.quitOnLastWindowClosed()
    app.setQuitOnLastWindowClosed(False)
    window = Window()
    watcher = QtLocalFileRefresh(window, interval_ms=75)

    def until(predicate, seconds=4):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            app.processEvents()
            if predicate():
                return True
            time.sleep(0.01)
        app.processEvents()
        return bool(predicate())

    try:
        (tmp_path / "first.txt").write_text("first", encoding="utf-8")
        assert until(lambda: window.local_table.rowCount() == 1)
        assert window.local_table.item(0, 0).text() == "first.txt"
        updates = window.updates

        watcher.check()
        assert until(lambda: not watcher._scanning)
        assert window.updates == updates, "Unchanged files rebuilt the table"

        (tmp_path / "second.txt").write_text("second", encoding="utf-8")
        assert until(lambda: window.local_table.rowCount() == 2)
        assert window.updates > updates

        window.lifecycle.phase = DesktopPhase.DISCONNECTED
        (tmp_path / "third.txt").write_text("third", encoding="utf-8")
        watcher.check()
        end = time.monotonic() + 0.2
        while time.monotonic() < end:
            app.processEvents()
            time.sleep(0.01)
        assert window.local_table.rowCount() == 2
    finally:
        watcher.timer.stop()
        assert until(lambda: not watcher._scanning)
        window.close()
        app.setQuitOnLastWindowClosed(previous_quit)


def test_mutual_desktop_local_file_refresh(tmp_path):
    if os.environ.get(_CHILD_FLAG) == "1":
        _exercise(tmp_path)
        return

    env = os.environ.copy()
    env[_CHILD_FLAG] = "1"
    env["QT_QPA_PLATFORM"] = "offscreen"
    result = subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-q", "-s"],
        cwd=Path(__file__).resolve().parents[2],
        env=env,
        capture_output=True,
        text=True,
        timeout=40,
        check=False,
    )
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
