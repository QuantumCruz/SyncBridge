
"""Optional background scheduling for an existing, authenticated SyncLifecycle.

A local FileWatcher wakes the worker promptly; periodic cycles also detect
remote-only changes. All file writes and baseline commits remain delegated to
SyncLifecycle. A single worker prevents overlapping cycles *within this service*.

This is not an OS-level singleton. Only one writable service may control a
folder pair, and callers must retain exclusive share/folder configuration.
Auto-apply is intentionally disabled by default.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from syncbridge.core.lifecycle import LifecycleResult, LifecycleStatus, SyncLifecycle
from syncbridge.core.watcher import FileWatcher
from syncbridge.network.transfer import TransferProgress

logger = logging.getLogger(__name__)


class ServiceState(str, Enum):
    STOPPED = "stopped"
    RUNNING = "running"
    RETRYING = "retrying"
    NEEDS_REVIEW = "needs_review"
    PAUSED = "paused"
    STOPPING = "stopping"


@dataclass(frozen=True, slots=True)
class ServiceSnapshot:
    state: ServiceState
    auto_apply: bool
    failures: int
    last_result: LifecycleResult | None
    last_error: str | None

    @property
    def requires_review(self) -> bool:
        return self.state is ServiceState.NEEDS_REVIEW


class AutoSyncService:
    """Poll remote changes, react to local edits, and retry failed sync cycles.

    Set ``auto_apply=True`` only after both peers have been explicitly paired,
    their three services point to the same approved share, and a single writer
    controls each folder pair. Existing conflicts and deletions remain blocked
    by SyncLifecycle; this scheduler never resolves them itself.

    Callbacks run on worker/watcher threads. UI code must marshal updates to
    the GUI thread. Callback failures are logged and do not kill the service.
    """

    def __init__(
        self,
        lifecycle: SyncLifecycle,
        *,
        auto_apply: bool = False,
        poll_interval: float = 15.0,
        watch_interval: float = 1.0,
        settle_delay: float = 0.75,
        retry_initial: float = 2.0,
        retry_max: float = 60.0,
        watch_local: bool = True,
        on_result: Callable[[LifecycleResult], None] | None = None,
        on_status: Callable[[ServiceSnapshot], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
        on_progress: Callable[[TransferProgress], None] | None = None,
    ) -> None:
        if not isinstance(lifecycle, SyncLifecycle):
            raise TypeError("lifecycle must be a SyncLifecycle")
        if type(auto_apply) is not bool or type(watch_local) is not bool:
            raise TypeError("auto_apply and watch_local must be bool")
        for name, value, permit_zero in (
            ("poll_interval", poll_interval, False),
            ("watch_interval", watch_interval, False),
            ("settle_delay", settle_delay, True),
            ("retry_initial", retry_initial, False),
            ("retry_max", retry_max, False),
        ):
            if (type(value) not in (int, float)
                or not math.isfinite(value)
                or value < 0
                or (not permit_zero and value == 0)):
                raise ValueError(f"{name} must be finite and positive"
                                 if not permit_zero else
                                 f"{name} must be finite and nonnegative")
        if retry_max < retry_initial:
            raise ValueError("retry_max must be at least retry_initial")
        for callback in (on_result, on_status, on_error, on_progress):
            if callback is not None and not callable(callback):
                raise TypeError("Callbacks must be callable or None")

        self.lifecycle = lifecycle
        self.auto_apply = auto_apply
        self.poll_interval = float(poll_interval)
        self.watch_interval = float(watch_interval)
        self.settle_delay = float(settle_delay)
        self.retry_initial = float(retry_initial)
        self.retry_max = float(retry_max)
        self.watch_local = watch_local
        self._on_result = on_result
        self._on_status = on_status
        self._on_error = on_error
        self._on_progress = on_progress

        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._stop.set()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._watcher: FileWatcher | None = None
        self._cancel_cycle: threading.Event | None = None
        self._paused = False
        self._last_local_change = float("-inf")
        self._snapshot = ServiceSnapshot(ServiceState.STOPPED, auto_apply, 0, None, None)

    @property
    def status(self) -> ServiceSnapshot:
        with self._lock:
            return self._snapshot

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive() and not self._stop.is_set()

    def _callback(self, listener, value) -> None:
        if listener is not None:
            try:
                listener(value)
            except Exception:
                logger.exception("SyncBridge background callback failed")

    def _publish(
        self,
        state: ServiceState,
        *,
        failures: int | None = None,
        result: LifecycleResult | None = None,
        error: str | None = None,
    ) -> None:
        with self._lock:
            previous = self._snapshot
            snapshot = ServiceSnapshot(
                state,
                self.auto_apply,
                previous.failures if failures is None else failures,
                previous.last_result if result is None else result,
                error,
            )
            self._snapshot = snapshot
            changed = snapshot != previous
        if changed:
            self._callback(self._on_status, snapshot)

    def _local_changed(self, _changes: object) -> None:
        with self._lock:
            self._last_local_change = time.monotonic()
        self._wake.set()

    def _watch_error(self, error: Exception) -> None:
        # A file changing while being hashed can cause a temporary incomplete
        # watcher scan. The watcher retries; it must not commit an invalid scan.
        logger.debug("Local watcher reported: %s", error)
        self._callback(self._on_error, error)

    def _progress(self, progress: TransferProgress) -> None:
        self._callback(self._on_progress, progress)

    def start(self) -> None:
        """Start one background worker. Repeated calls are idempotent."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                if self._stop.is_set():
                    raise RuntimeError("Previous synchronization worker is stopping")
                return
            self._stop.clear()
            self._paused = False
            self._wake.set()
            self._last_local_change = float("-inf")
            self._cancel_cycle = None
            self._watcher = None

            try:
                if self.watch_local:
                    watcher = FileWatcher(
                        self.lifecycle.coordinator.root,
                        self._local_changed,
                        interval=self.watch_interval,
                        on_error=self._watch_error,
                    )
                    self._watcher = watcher
                    watcher.poll_once()  # Establish baseline before watching.
                    watcher.start()
                worker = threading.Thread(
                    target=self._run,
                    name="SyncBridgeAutoSync",
                    daemon=True,
                )
                self._thread = worker
                worker.start()
            except BaseException:
                self._stop.set()
                self._wake.set()
                if self._watcher is not None:
                    self._watcher.stop()
                    self._watcher = None
                self._thread = None
                raise

    def request_sync(self) -> None:
        """Wake the worker; it still respects pause and local settle delay."""
        self._wake.set()

    def pause(self) -> None:
        """Pause further cycles and request cancellation of the current copy."""
        with self._lock:
            self._paused = True
            if self._cancel_cycle is not None:
                self._cancel_cycle.set()
        self._wake.set()

    def resume(self) -> None:
        with self._lock:
            self._paused = False
        self._wake.set()

    def stop(self, *, timeout: float | None = 5.0) -> None:
        """Request stop and wait briefly, unless called from the worker itself."""
        if timeout is not None and (
            type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout < 0
        ):
            raise ValueError("timeout must be finite nonnegative or None")
        with self._lock:
            worker = self._thread
            watcher, self._watcher = self._watcher, None
            self._stop.set()
            if self._cancel_cycle is not None:
                self._cancel_cycle.set()
            self._wake.set()
        if watcher is not None:
            watcher.stop()
        if worker is not None and worker.is_alive():
            if worker is not threading.current_thread():
                worker.join(timeout=timeout)
        with self._lock:
            still_alive = worker is not None and worker.is_alive()
        self._publish(ServiceState.STOPPING if still_alive else ServiceState.STOPPED)

    def _wait(self, delay: float | None) -> None:
        self._wake.wait(delay)
        self._wake.clear()

    def _run(self) -> None:
        delay = 0.0
        try:
            while not self._stop.is_set():
                with self._lock:
                    paused = self._paused
                    settling = max(
                        0.0,
                        self._last_local_change + self.settle_delay - time.monotonic(),
                    )
                if paused:
                    self._publish(ServiceState.PAUSED)
                    self._wait(None)
                    continue
                if delay > 0:
                    self._wait(delay)
                    delay = 0.0
                    continue
                if settling > 0:
                    self._wait(settling)
                    continue
                with self._lock:
                    if self._paused or self._stop.is_set():
                        continue
                    if self._last_local_change + self.settle_delay > time.monotonic():
                        continue
                    # Consume the wakeup that brought us to THIS cycle, not a
                    # wakeup emitted during its network/file work.
                    self._wake.clear()
                    cancel = threading.Event()
                    self._cancel_cycle = cancel
                try:
                    result = self.lifecycle.run_once(
                        apply=self.auto_apply,
                        cancel_event=cancel,
                        on_progress=self._progress,
                    )
                except Exception as exc:
                    with self._lock:
                        interrupted = self._stop.is_set() or self._paused
                        count = self._snapshot.failures + 1
                    if interrupted:
                        delay = 0.0
                        continue
                    self._publish(ServiceState.RETRYING, failures=count, error=str(exc))
                    self._callback(self._on_error, exc)
                    delay = min(self.retry_max, self.retry_initial * 2 ** min(count - 1, 30))
                else:
                    with self._lock:
                        interrupted = self._stop.is_set() or self._paused
                    if interrupted:
                        delay = 0.0
                        continue
                    status = (
                        ServiceState.NEEDS_REVIEW
                        if result.status is LifecycleStatus.NEEDS_REVIEW
                        else ServiceState.PAUSED
                        if result.status is LifecycleStatus.PAUSED
                        else ServiceState.RUNNING
                    )
                    self._publish(status, failures=0, result=result)
                    self._callback(self._on_result, result)
                    delay = self.poll_interval
                finally:
                    with self._lock:
                        if self._cancel_cycle is cancel:
                            self._cancel_cycle = None
        finally:
            self._publish(ServiceState.STOPPED)
