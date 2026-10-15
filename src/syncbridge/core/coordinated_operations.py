
"""Lease-aware entry point for manual SyncBridge operations.

Every call through this class asks the elected share authority for permission.
A local non-blocking mutex prevents two threads using the same entry point.

This is COOPERATIVE serialization, not network fencing. Existing standalone
lifecycle/transfer/approval APIs and AutoSyncService can still operate without
this wrapper. A peer that ignores leases, or continues after a lease expires,
can still reach older receivers. Keep auto-apply OFF and use temporary folders
until the receivers reject unleased/stale writes.
"""
from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Callable, Iterator

from syncbridge.core.approved_deletion import (
    ApprovedDeletionCoordinator,
    DeletionOutcome,
)
from syncbridge.core.lifecycle import LifecycleResult, SyncLifecycle
from syncbridge.network.operation_lock import (
    LeaseCoordinator,
    LeaseGuard,
    OperationLeaseLost,
    OperationLockError,
)
from syncbridge.network.transfer import TransferProgress


class LocalOperationBusy(OperationLockError):
    """A call through this runner is already working on the share."""


class CoordinatedOperations:
    """Manual sync and explicitly approved deletion using the same lease.

    The wrapper checks a lease before and after the operation. During sync,
    a monitor propagates lease loss or user cancellation to the lifecycle's
    cancellation event. Transfer progress also checks the active lease.

    This cannot revoke an in-flight server write and cannot fence old lease
    holders at the network boundary. Owner-approved deletion is therefore
    manual-only, with the normal Phase 18 recovery vault safeguards.
    """

    def __init__(
        self,
        lifecycle: SyncLifecycle,
        leases: LeaseCoordinator,
        *,
        approved_deletion: ApprovedDeletionCoordinator | None = None,
    ) -> None:
        if not isinstance(lifecycle, SyncLifecycle):
            raise TypeError("lifecycle must be SyncLifecycle")
        if not isinstance(leases, LeaseCoordinator):
            raise TypeError("leases must be LeaseCoordinator")

        coordinator = lifecycle.coordinator
        if (
            leases.share_id != coordinator.share_id
            or leases.peer_node_id != coordinator.peer_node_id
            or leases.identity.node_id
            != coordinator.manifest_client.identity.node_id
        ):
            raise ValueError(
                "Lease and synchronization must use the same share, "
                "paired device, and local identity"
            )
        if approved_deletion is not None:
            if not isinstance(approved_deletion, ApprovedDeletionCoordinator):
                raise TypeError("approved_deletion must be ApprovedDeletionCoordinator")
            if approved_deletion.lifecycle is not lifecycle:
                raise ValueError("Deletion and sync must use the same lifecycle")

        self.lifecycle = lifecycle
        self.leases = leases
        self.approved_deletion = approved_deletion
        self._local_lock = threading.Lock()

    @contextmanager
    def _hold(self, operation: str) -> Iterator[LeaseGuard]:
        if not self._local_lock.acquire(blocking=False):
            raise LocalOperationBusy(
                "[SB-OPS-423] This computer is already working on "
                "the folder. Wait for it to finish."
            )
        try:
            with self.leases.hold(operation) as guard:
                guard.check()
                yield guard
                guard.check()
        finally:
            self._local_lock.release()

    def preview(self) -> LifecycleResult:
        """Read-only; locally serialized but requires no distributed lease."""
        if not self._local_lock.acquire(blocking=False):
            raise LocalOperationBusy(
                "[SB-OPS-423] This computer is currently changing the folder."
            )
        try:
            return self.lifecycle.run_once(apply=False)
        finally:
            self._local_lock.release()

    def sync_once(
        self,
        *,
        cancel_event: threading.Event | None = None,
        on_progress: Callable[[TransferProgress], None] | None = None,
    ) -> LifecycleResult:
        """Cooperatively execute a real two-way sync under one lease.

        A heartbeat failure cancels work at the lifecycle's next cancellation
        point. If a network write was already in progress, it may finish before
        cancellation takes effect. No success is reported after known lease loss.
        """
        if cancel_event is not None and not isinstance(cancel_event, threading.Event):
            raise TypeError("cancel_event must be a threading.Event or None")
        if on_progress is not None and not callable(on_progress):
            raise TypeError("on_progress must be callable or None")
        if cancel_event is not None and cancel_event.is_set():
            raise OperationLockError(
                "[SB-OPS-409] Synchronization was cancelled before starting."
            )

        with self._hold("sync") as guard:
            operation_cancel = threading.Event()
            finished = threading.Event()

            def watch() -> None:
                while not finished.wait(0.05):
                    if cancel_event is not None and cancel_event.is_set():
                        operation_cancel.set()
                    try:
                        guard.check()
                    except OperationLeaseLost:
                        operation_cancel.set()
                        return

            watcher = threading.Thread(
                target=watch,
                name="SyncBridgeLeaseCancellation",
                daemon=True,
            )

            def progress(update: TransferProgress) -> None:
                guard.check()
                if cancel_event is not None and cancel_event.is_set():
                    operation_cancel.set()
                if on_progress is not None:
                    on_progress(update)

            watcher.start()
            try:
                result = self.lifecycle.run_once(
                    apply=True,
                    cancel_event=operation_cancel,
                    on_progress=progress,
                )
                guard.check()
                return result
            finally:
                finished.set()
                watcher.join(timeout=1.0)

    def delete_approved(
        self,
        request_id: str,
        *,
        confirmed: bool = False,
    ) -> DeletionOutcome:
        """Manually execute existing consent + recovery flow under a lease.

        A lease failure may occur AFTER the copy moves into recovery; callers
        must inspect the recovery center and shared baseline before retrying.
        Never retry using a different request ID without a fresh review.
        """
        if type(confirmed) is not bool or not confirmed:
            raise ValueError(
                "[SB-DEL-111] Explicit local confirmation is required "
                "before moving a file to recovery."
            )
        if self.approved_deletion is None:
            raise OperationLockError(
                "[SB-DEL-111] Deletion has not been configured for this folder."
            )
        if not isinstance(request_id, str) or not request_id:
            raise ValueError("A deletion request ID is required")

        with self._hold("deletion") as guard:
            guard.check()
            outcome = self.approved_deletion.apply(request_id)
            guard.check()
            return outcome
