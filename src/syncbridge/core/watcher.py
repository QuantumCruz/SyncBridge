
"""Polling-based filesystem change notifications for SyncBridge.

The watcher reuses the scanner and reconciler. It never modifies the watched
files, and it never treats an incomplete scan as evidence of a deletion.
"""

from __future__ import annotations

import logging
import math
import threading
from pathlib import Path
from typing import Callable, Iterable

from .reconciler import FileReconciler, IncompleteScanError, ReconcileResult
from .scanner import FileScanner, ScanResult


logger = logging.getLogger(__name__)


class FileWatcher:
    """Monitor a local directory using repeated scans.

    The first complete scan establishes a baseline without emitting changes.
    Later scans emit ReconcileResult objects only when contents differ.
    An incomplete scan never replaces the last known-good baseline.

    poll_once() is available for deterministic checks and unit tests.
    start()/stop() run the same check in a background thread.

    Callbacks execute in the thread that calls poll_once(); for automatic
    monitoring this is the watcher thread, not the GUI thread.
    """

    def __init__(
        self,
        root: str | Path,
        on_change: Callable[[ReconcileResult], None],
        *,
        interval: float = 2.0,
        excludes: Iterable[str] = (),
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        if not callable(on_change):
            raise TypeError("on_change must be callable")
        if on_error is not None and not callable(on_error):
            raise TypeError("on_error must be callable or None")

        try:
            interval_value = float(interval)
        except (TypeError, ValueError) as exc:
            raise ValueError("interval must be a positive finite number") from exc

        if not math.isfinite(interval_value) or interval_value <= 0:
            raise ValueError("interval must be a positive finite number")

        self._scanner = FileScanner(root, excludes=excludes)
        self._on_change = on_change
        self._on_error = on_error
        self.interval = interval_value

        self._previous: ScanResult | None = None
        self._poll_lock = threading.RLock()
        self._lifecycle_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def root(self) -> Path:
        return self._scanner.root

    @property
    def is_running(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    def poll_once(self) -> ReconcileResult | None:
        """Perform one check and notify on changes.

        Returns None on the initial scan, an incomplete scan, or a failed
        change callback. On subsequent successful checks, returns a diff,
        including an empty diff when nothing changed.
        """
        with self._poll_lock:
            current = self._scanner.scan()

            if not current.complete:
                details = "; ".join(
                    f"{item.relative_path}: {item.message}"
                    for item in current.errors[:3]
                )
                self._report_error(
                    IncompleteScanError(
                        f"Scan incomplete ({len(current.errors)} error(s)); "
                        f"baseline preserved. {details}"
                    )
                )
                return None

            if self._previous is None:
                self._previous = current
                return None

            result = FileReconciler.compare(self._previous, current)

            if result.has_changes:
                try:
                    self._on_change(result)
                except Exception as exc:
                    # Retry this diff on the next check: the callback did not
                    # confirm that the changes were handled successfully.
                    self._report_error(exc)
                    return None

            self._previous = current
            return result

    def start(self) -> None:
        """Start background polling; calling start twice is harmless."""
        with self._lifecycle_lock:
            if self.is_running:
                if self._stop_event.is_set():
                    raise RuntimeError(
                        "Previous watcher thread is still stopping"
                    )
                return

            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run,
                name="SyncBridgeFileWatcher",
                daemon=True,
            )
            self._thread.start()

    def stop(self) -> None:
        """Stop background polling and wait for it to finish.

        Safe to call multiple times, including from inside a callback.
        """
        with self._lifecycle_lock:
            self._stop_event.set()
            thread = self._thread

        if thread is not None and thread is not threading.current_thread():
            thread.join()

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.poll_once()
            except Exception as exc:
                self._report_error(exc)

            self._stop_event.wait(self.interval)

    def _report_error(self, error: Exception) -> None:
        if self._on_error is None:
            logger.error("SyncBridge watcher: %s", error)
            return

        try:
            self._on_error(error)
        except Exception:
            logger.exception(
                "SyncBridge watcher error handler failed"
            )
