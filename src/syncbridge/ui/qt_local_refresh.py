
"""Refresh the visible local file list without initiating synchronization.

Supports both the legacy Qt window and the mutual-session desktop window.
Filesystem scanning runs on a worker; widgets update only on the Qt thread.
"""
from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import QObject, QTimer, Signal, Slot

from syncbridge.ui.desktop_controller import DesktopPhase


class QtLocalFileRefresh(QObject):
    """Refresh the My files tab when local file names or sizes change."""

    scan_finished = Signal(str, object)
    scan_failed = Signal()

    def __init__(self, window, *, interval_ms: int = 4000) -> None:
        super().__init__(window)
        if interval_ms < 50:
            raise ValueError("Refresh interval must be at least 50 ms")

        self.window = window
        self._scanning = False
        self.scan_finished.connect(self._apply_result)
        self.scan_failed.connect(self._reset_scan)

        self.timer = QTimer(self)
        self.timer.setInterval(interval_ms)
        self.timer.timeout.connect(self.check)
        self.timer.start()
        window.tabs.currentChanged.connect(self._on_tab_changed)

    def _modern(self) -> bool:
        return hasattr(self.window, "lifecycle")

    def _eligible(self) -> bool:
        window = self.window
        if (
            window._closing
            or window._busy
            or not window.controller.running
            or window.tabs.currentIndex() != 0
        ):
            return False

        if self._modern():
            return window.lifecycle.phase is DesktopPhase.CONNECTED

        return bool(
            not window._paused
            and "local" in window._loaded
            and window._render_kind is None
        )

    def _on_tab_changed(self, index: int) -> None:
        if index == 0:
            self.check()

    def check(self) -> None:
        if self._scanning or not self._eligible():
            return

        try:
            root = Path(
                self.window.controller.profile().local_root
            ).resolve()
        except Exception:
            return

        modern = self._modern()
        self._scanning = True

        def scan() -> None:
            try:
                if modern:
                    result = self.window._list_local()
                else:
                    result = self.window._list_local(root)
                self.scan_finished.emit(str(root), result)
            except Exception:
                try:
                    self.scan_failed.emit()
                except RuntimeError:
                    pass

        threading.Thread(
            target=scan,
            name="SyncBridgeQtLocalViewRefresh",
            daemon=True,
        ).start()

    @Slot()
    def _reset_scan(self) -> None:
        self._scanning = False

    @Slot(str, object)
    def _apply_result(self, checked_root: str, result) -> None:
        self._scanning = False
        if not self._eligible():
            return

        try:
            current_root = Path(
                self.window.controller.profile().local_root
            ).resolve()
        except Exception:
            return

        if str(current_root) != checked_root:
            return

        modern = self._modern()
        rows = result if modern else result[0]
        table = self.window.local_table

        if table.rowCount() == len(rows):
            unchanged = all(
                table.item(index, 0) is not None
                and table.item(index, 1) is not None
                and table.item(index, 0).text() == str(path)
                and table.item(index, 1).text() == self.window._size(size)
                for index, (path, size) in enumerate(rows)
            )
            if unchanged:
                return

        if modern:
            self.window._show_files(table, rows)
        else:
            self.window._display_files("local", result)
