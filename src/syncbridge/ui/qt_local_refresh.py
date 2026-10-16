
"""Refresh the receiving computer's visible file list without syncing.

Only file names and sizes are read; no hashes, writes or remote requests.
The scan runs on a background thread and Qt widgets update on the UI thread.
"""
from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import QObject, QTimer, Signal, Slot


class QtLocalFileRefresh(QObject):
    """Watch the displayed 'My files' list using lightweight periodic scans."""

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

        # Checking upon returning to the tab avoids waiting for the next tick.
        window.tabs.currentChanged.connect(self._on_tab_changed)

    def _eligible(self) -> bool:
        w = self.window

        return bool(
            not w._closing
            and not w._paused
            and not w._busy
            and w.controller.running
            and w.tabs.currentIndex() == 0
            and "local" in w._loaded
            and w._render_kind is None
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

        self._scanning = True

        def scan() -> None:
            try:
                result = self.window._list_local(root)
                self.scan_finished.emit(str(root), result)

            except Exception:
                # A transient filesystem error should not stop the UI.
                # If the window was destroyed, the signal may no longer exist.
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

        rows, _truncated = result
        table = self.window.local_table

        if table.rowCount() == len(rows):
            same = all(
                table.item(i, 0) is not None
                and table.item(i, 1) is not None
                and table.item(i, 0).text() == str(path)
                and table.item(i, 1).text() == self.window._size(size)
                for i, (path, size) in enumerate(rows)
            )

            if same:
                return

        # The receiver's directory really changed: reuse the GUI's tested
        # batched-rendering path. Never perform Preview or Sync here.
        self.window._display_files("local", result)
