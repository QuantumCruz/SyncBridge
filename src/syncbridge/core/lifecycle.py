
"""One conservative synchronization-and-checkpoint lifecycle for a folder pair.

The existing SyncCoordinator copies content; BaselineCoordinator negotiates a
shared baseline. This wrapper joins them without altering either component.

The caller must configure manifest, transfer, and agreement servers for the
SAME remote share/root, with explicit permissions. Run at most one lifecycle
per folder pair at a time. Cross-process locks and concurrent filesystem
writers remain responsibilities of the future application service.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from syncbridge.core.baseline import BaselineCoordinator, CheckpointResult
from syncbridge.core.conflicts import SyncDecision
from syncbridge.core.coordinator import (
    CoordinationError,
    StaleSyncState,
    SyncCoordinator,
    SyncCycleResult,
    SyncPreview,
)
from syncbridge.core.scanner import FileScanner
from syncbridge.network.agreement import AgreementError, AgreementStatus
from syncbridge.network.transfer import TransferProgress, TransferResult
from syncbridge.storage.shared_state import _canonical_rows, _digest


class LifecycleStatus(str, Enum):
    PREVIEW = "preview"
    PAUSED = "paused"
    NEEDS_REVIEW = "needs_review"
    NOT_CONVERGED = "not_converged"
    COMMITTED = "committed"


@dataclass(frozen=True, slots=True)
class LifecycleResult:
    status: LifecycleStatus
    preview: SyncPreview
    cycle: SyncCycleResult | None = None
    checkpoint: CheckpointResult | None = None
    recovered_pending: bool = False
    unapproved_joint_deletions: tuple[str, ...] = ()

    @property
    def uploaded(self) -> tuple[TransferResult, ...]:
        return () if self.cycle is None else self.cycle.uploaded

    @property
    def downloaded(self) -> tuple[TransferResult, ...]:
        return () if self.cycle is None else self.cycle.downloaded

    @property
    def conflicts(self) -> tuple[SyncDecision, ...]:
        return self.preview.plan.conflicts

    @property
    def pending_deletions(self) -> tuple[SyncDecision, ...]:
        return self.preview.plan.pending_deletions

    @property
    def complete(self) -> bool:
        return self.status is LifecycleStatus.COMMITTED


class SyncLifecycle:
    """Coordinate a user-approved two-way sync followed by baseline agreement.

    run_once() is a read-only preview. run_once(apply=True) requires the
    coordinator's strict, share-bound two-way transfer configuration.

    An interrupted remote-first commit is recovered before any new transfers.
    Unapproved deletions (including deletions on both sides) block baseline
    advancement. Divergent modifications are never automatically resolved.
    """

    def __init__(
        self,
        coordinator: SyncCoordinator,
        baseline: BaselineCoordinator,
    ) -> None:
        if not isinstance(coordinator, SyncCoordinator):
            raise TypeError("coordinator must be a SyncCoordinator")
        if not isinstance(baseline, BaselineCoordinator):
            raise TypeError("baseline must be a BaselineCoordinator")

        if (
            coordinator.root != baseline.root
            or coordinator.peer_node_id != baseline.peer_node_id
            or coordinator.share_id != baseline.share_id
            or coordinator.host != baseline.host
            or coordinator.shared_state.path != baseline.state.path
            or coordinator.manifest_client.identity.node_id
            != baseline.client.identity.node_id
        ):
            raise ValueError(
                "Sync and baseline coordinators must use the same "
                "folder pair and identity"
            )

        self.coordinator = coordinator
        self.baseline = baseline
        self._lock = threading.Lock()

    def _remote_status(self) -> AgreementStatus:
        return self.baseline.client.status(
            self.baseline.host,
            self.baseline.port,
            self.baseline.peer_node_id,
            self.baseline.share_id,
        )

    def _check_remote_agreement(
        self,
        inventory_sha256: str,
    ) -> None:
        """Reject a different agreement root, stale history, or foreign proposal."""
        status = self._remote_status()

        current = self.coordinator.shared_state.load(
            self.coordinator.root,
            self.coordinator.peer_node_id,
            self.coordinator.share_id,
        )

        local_revision = 0 if current is None else current.revision
        local_hash = None if current is None else current.sha256

        if status.pending_id is not None:
            raise AgreementError(
                "Remote has an unresolved baseline proposal"
            )

        if (
            status.revision != local_revision
            or status.sha256 != local_hash
        ):
            raise StaleSyncState(
                "Agreement service baseline differs from local baseline"
            )

        if status.inventory_sha256 != inventory_sha256:
            raise StaleSyncState(
                "Remote agreement and manifest inventories disagree; "
                "verify both services point to the same folder"
            )

    def _local_inventory_hash(
        self,
    ) -> tuple[str, set[str]]:
        snapshot = FileScanner(self.coordinator.root).scan()
        rows = _canonical_rows(
            snapshot,
            self.coordinator.root,
        )
        return _digest(rows), set(snapshot.files)

    def _joint_deletions(
        self,
        present: set[str],
    ) -> tuple[str, ...]:
        """Detect deletions the planner omits when BOTH sides delete."""
        baseline = self.coordinator.shared_state.load(
            self.coordinator.root,
            self.coordinator.peer_node_id,
            self.coordinator.share_id,
        )

        if baseline is None:
            return ()

        return tuple(
            sorted(set(baseline.snapshot.files) - present)
        )

    def run_once(
        self,
        *,
        apply: bool = False,
        cancel_event: threading.Event | None = None,
        on_progress: Callable[[TransferProgress], None] | None = None,
    ) -> LifecycleResult:
        """Preview by default; opt into two-way transfer and agreement.

        Raises on stale revisions, invalid credentials, interrupted agreements,
        and transport failures. Such failures must never be treated as a
        successful checkpoint; call again to recover pending state.
        """
        if type(apply) is not bool:
            raise TypeError("apply must be bool")

        if (
            cancel_event is not None
            and not isinstance(cancel_event, threading.Event)
        ):
            raise TypeError(
                "cancel_event must be threading.Event or None"
            )

        if (
            on_progress is not None
            and not callable(on_progress)
        ):
            raise TypeError(
                "on_progress must be callable or None"
            )

        with self._lock:
            if not apply:
                preview = self.coordinator.inspect()
                return LifecycleResult(
                    LifecycleStatus.PREVIEW,
                    preview,
                )

            # Recover any in-flight remote-first commit BEFORE new transfers.
            # Retain the original durable proposal ID on retry.
            pending = self.coordinator.shared_state.pending(
                self.coordinator.root,
                self.coordinator.peer_node_id,
                self.coordinator.share_id,
            )

            recovered = False

            if pending is not None:
                recovered_result = self.baseline.checkpoint()
                recovered = recovered_result.recovered_pending

            preview = self.coordinator.inspect()
            self._check_remote_agreement(
                preview.remote.inventory_sha256
            )

            cycle = self.coordinator.execute_changes(
                preview,
                cancel_event=cancel_event,
                on_progress=on_progress,
            )

            if (
                cycle.paused
                or (
                    cancel_event is not None
                    and cancel_event.is_set()
                )
            ):
                return LifecycleResult(
                    LifecycleStatus.PAUSED,
                    preview,
                    cycle,
                    recovered_pending=recovered,
                )

            if (
                cycle.pending_conflicts
                or cycle.pending_deletions
            ):
                return LifecycleResult(
                    LifecycleStatus.NEEDS_REVIEW,
                    preview,
                    cycle,
                    recovered_pending=recovered,
                )

            # Verify live contents after all copies.
            local_hash, local_paths = self._local_inventory_hash()

            remote = self.coordinator.manifest_client.fetch(
                self.coordinator.host,
                self.coordinator.manifest_port,
                self.coordinator.peer_node_id,
                self.coordinator.share_id,
            )

            if (
                remote.peer_node_id != self.coordinator.peer_node_id
                or remote.share_id != self.coordinator.share_id
            ):
                raise CoordinationError(
                    "Unexpected authenticated manifest response"
                )

            if local_hash != remote.inventory_sha256:
                return LifecycleResult(
                    LifecycleStatus.NOT_CONVERGED,
                    preview,
                    cycle,
                    recovered_pending=recovered,
                )

            # The conflict planner ignores a file absent on both devices.
            # Its deletion must nevertheless be approved before checkpoint.
            omitted_deletions = self._joint_deletions(
                local_paths
            )

            if omitted_deletions:
                return LifecycleResult(
                    LifecycleStatus.NEEDS_REVIEW,
                    preview,
                    cycle,
                    recovered_pending=recovered,
                    unapproved_joint_deletions=omitted_deletions,
                )

            # Confirm that agreement and manifest endpoints still see
            # identical contents and matching committed revision history.
            self._check_remote_agreement(
                remote.inventory_sha256
            )

            if (
                cancel_event is not None
                and cancel_event.is_set()
            ):
                return LifecycleResult(
                    LifecycleStatus.PAUSED,
                    preview,
                    cycle,
                    recovered_pending=recovered,
                )

            # The baseline coordinator handles remote-first commit and
            # recovery. It performs its own fresh local/remote checks.
            checkpoint = self.baseline.checkpoint()

            return LifecycleResult(
                LifecycleStatus.COMMITTED,
                preview,
                cycle,
                checkpoint,
                recovered_pending=recovered,
            )
