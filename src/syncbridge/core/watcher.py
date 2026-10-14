
"""Polling-based filesystem change notifications for SyncBridge.

The watcher reuses the scanner and reconciler, never modifies watched files,
and does not interpret incomplete scans as evidence of deletion.
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
    """Monitor a local folder and deliver changes after complete scans.

    initial_scan allows another component to hand off an existing snapshot
    without a gap between initial scanning and background watching.

    Callbacks execute in the polling thread when start() is used.
    """

    def __init__(
        self,
        root: str | Path,
        on_change: Callable[[ReconcileResult], None],
        *,
        interval: float = 2.0,
        excludes: Iterable[str] = (),
        on_error: Callable[[Exception], None] | None = None,
        initial_scan: ScanResult | None = None,
    ) -> None:
        if not callable(on_change):
            raise TypeError("on_change must be callable")

        if on_error is not None and not callable(on_error):
            raise TypeError("on_error must be callable or None")

        try:
            interval_value = float(interval)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "interval must be a positive finite number"
            ) from exc

        if not math.isfinite(interval_value) or interval_value <= 0:
            raise ValueError("interval must be a positive finite number")

        self._scanner = FileScanner(root, excludes=excludes)
        self._on_change = on_change
        self._on_error = on_error
        self.interval = interval_value

        if initial_scan is not None:
            if not initial_scan.complete:
                raise ValueError("initial_scan must be complete")

            if initial_scan.root != self._scanner.root:
                raise ValueError(
                    "initial_scan must belong to the watched folder"
                )

            self._previous: ScanResult | None = ScanResult(
                root=initial_scan.root,
                files=dict(initial_scan.files),
            )
        else:
            self._previous = None

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
        """Scan once and return differences from the previous scan.

        An initial scan or incomplete scan returns None.
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

            result = FileReconciler.compare(
                self._previous,
                current,
            )

            if result.has_changes:
                try:
                    self._on_change(result)
                except Exception as exc:
                    self._report_error(exc)
                    return None

            self._previous = current
            return result

    def start(self) -> None:
        """Start background monitoring."""
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
        """Stop background monitoring and wait for shutdown."""
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
