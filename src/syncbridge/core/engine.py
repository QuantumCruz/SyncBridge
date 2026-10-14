
"""Local inventory coordination for SyncBridge.

The engine combines scanning, reconciliation, snapshot persistence and file
watching. No files are transferred or acknowledged by a remote peer.
"""

from __future__ import annotations

import logging
import math
import threading
from pathlib import Path
from typing import Callable, Iterable

from .reconciler import FileReconciler, IncompleteScanError, ReconcileResult
from .scanner import FileScanner, ScanResult
from .watcher import FileWatcher
from syncbridge.storage.database import SnapshotDatabase


logger = logging.getLogger(__name__)


class SyncEngine:
    """Monitor one folder and persist its last successfully reported scan.

    The first scan establishes a baseline. Subsequent scans notify on_change
    before committing the new inventory to SQLite.

    Failed scans or notifications leave the stored baseline unchanged.

    on_change is a LOCAL notification, not confirmation of remote syncing.
    Callbacks may be retried after crashes or database failures, so their
    consumers must tolerate duplicate notifications.
    """

    def __init__(
        self,
        root: str | Path,
        on_change: Callable[[ReconcileResult], None],
        *,
        database_path: str | Path | None = None,
        interval: float = 2.0,
        excludes: Iterable[str] = (),
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        if not callable(on_change):
            raise TypeError("on_change must be callable")

        if on_error is not None and not callable(on_error):
            raise TypeError("on_error must be callable or None")

        patterns = tuple(excludes)
        self._scanner = FileScanner(root, excludes=patterns)

        self.root = self._scanner.root
        self._excludes = patterns

        try:
            interval_value = float(interval)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "interval must be a positive finite number"
            ) from exc

        if not math.isfinite(interval_value) or interval_value <= 0:
            raise ValueError("interval must be a positive finite number")

        self.interval = interval_value
        self._on_change = on_change
        self._on_error = on_error

        self._lock = threading.RLock()
        self._lifecycle_lock = threading.RLock()

        self._watcher: FileWatcher | None = None
        self._last_scan: ScanResult | None = None

        db_path = (
            self.root / ".syncbridge" / "state.db"
            if database_path is None
            else Path(database_path).expanduser().resolve()
        )

        # Prevent SQLite writes from appearing as watched file changes.
        if db_path.is_relative_to(self.root):
            relative = db_path.relative_to(self.root)

            if not relative.parts or relative.parts[0] != ".syncbridge":
                raise ValueError(
                    "A database within the watched folder "
                    "must be in .syncbridge/"
                )

        self.database = SnapshotDatabase(db_path)

    @property
    def is_running(self) -> bool:
        watcher = self._watcher
        return watcher is not None and watcher.is_running

    def check_once(self) -> ReconcileResult | None:
        """Scan, reconcile, notify and persist one complete inventory.

        Returns None when establishing the first baseline.

        Raises on incomplete scans, failed notifications or database errors.
        The previous persistent snapshot remains unchanged on failure.
        """
        with self._lock:
            current = self._scanner.scan()

            if not current.complete:
                summary = "; ".join(
                    f"{error.relative_path}: {error.message}"
                    for error in current.errors[:3]
                )

                raise IncompleteScanError(
                    f"Scan incomplete ({len(current.errors)} error(s)); "
                    f"snapshot not saved. {summary}"
                )

            previous = self.database.load_snapshot(self.root)

            result = (
                FileReconciler.compare(previous, current)
                if previous is not None
                else None
            )

            if result is not None and result.has_changes:
                self._on_change(result)

            self.database.save_snapshot(current)
            self._last_scan = current

            return result

    def start(self) -> None:
        """Restore stored state, check for changes and begin monitoring."""
        with self._lifecycle_lock:
            if self.is_running:
                return

            if self._watcher is not None:
                self._watcher.stop()

            # First reconcile any changes made while SyncBridge was closed.
            self.check_once()

            assert self._last_scan is not None

            # Hand off this exact snapshot, avoiding a startup blind spot.
            watcher = FileWatcher(
                self.root,
                self._on_watcher_change,
                interval=self.interval,
                excludes=self._excludes,
                on_error=self._report_error,
                initial_scan=self._last_scan,
            )

            self._watcher = watcher
            watcher.start()

    def stop(self) -> None:
        """Stop automatic monitoring."""
        with self._lifecycle_lock:
            watcher = self._watcher

        if watcher is not None:
            watcher.stop()

    def _on_watcher_change(self, _: ReconcileResult) -> None:
        """Handle an automatic watcher notification.

        Re-scan to reconcile and persist the exact inventory reported
        by the engine, rather than assuming the watcher and SQLite
        baselines are always identical.
        """
        self.check_once()

    def _report_error(self, error: Exception) -> None:
        if self._on_error is None:
            logger.error("SyncBridge engine: %s", error)
            return

        try:
            self._on_error(error)
        except Exception:
            logger.exception(
                "SyncBridge engine error handler failed"
            )
