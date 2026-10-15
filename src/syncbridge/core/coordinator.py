
"""Conservative, explicit synchronization cycles for paired SyncBridge folders.

Inspect both inventories and optionally push newly created files. Existing
files, remote-only files, conflicts and deletions are NOT modified here.

This is NOT a complete two-way sync service: TransferService has no pull RPC,
no conditional overwrite, and no remote share identifier in its transfer offer.
Never finalize a shared baseline merely because a transfer succeeded.
"""

from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from syncbridge.core.conflicts import (
    ConflictResolver,
    SyncDecision,
    SyncPlan,
)
from syncbridge.core.scanner import FileRecord, FileScanner, ScanResult
from syncbridge.network.manifest import ManifestService, RemoteManifest
from syncbridge.network.transfer import (
    TransferProgress,
    TransferResult,
    TransferService,
)
from syncbridge.storage.shared_state import SharedStateDatabase


class CoordinationError(RuntimeError):
    """A folder pair cannot be safely planned or synchronized."""


class StaleSyncState(CoordinationError):
    """A local or remote inventory or shared baseline changed during the cycle."""


@dataclass(frozen=True, slots=True)
class SyncPreview:
    plan: SyncPlan
    local: ScanResult
    remote: RemoteManifest
    baseline_revision: int

    @property
    def new_uploads(self) -> tuple[SyncDecision, ...]:
        """Safe-to-attempt creates; receiver must reject existing targets."""
        return tuple(
            decision for decision in self.plan.uploads
            if decision.remote is None
        )

    @property
    def deferred_updates(self) -> tuple[SyncDecision, ...]:
        """Overwrites await an expected-hash conditional transfer protocol."""
        return tuple(
            decision for decision in self.plan.uploads
            if decision.remote is not None
        )


@dataclass(frozen=True, slots=True)
class SyncCycleResult:
    preview: SyncPreview
    uploaded: tuple[TransferResult, ...]
    paused: bool

    @property
    def pending_downloads(self) -> tuple[SyncDecision, ...]:
        return self.preview.plan.downloads

    @property
    def pending_conflicts(self) -> tuple[SyncDecision, ...]:
        return self.preview.plan.conflicts

    @property
    def pending_deletions(self) -> tuple[SyncDecision, ...]:
        return self.preview.plan.pending_deletions

    @property
    def pending_updates(self) -> tuple[SyncDecision, ...]:
        return self.preview.deferred_updates


def _content(snapshot: ScanResult) -> dict[str, tuple[int, str]]:
    return {
        path: (record.size, record.sha256)
        for path, record in snapshot.files.items()
    }


def _fingerprint(record: FileRecord) -> tuple[int, str]:
    return record.size, record.sha256


class SyncCoordinator:
    """Non-destructive synchronization planning and opt-in create-only pushes.

    The remote manifest and transfer servers MUST be configured for the same
    user-approved share. TransferService currently lacks a share_id field; its
    receiver must be configured with allow_overwrite=False. A future protocol
    revision will make the remote share and preconditions cryptographically
    bound to each transfer.

    This class does not alter or acknowledge SQLite shared baselines.
    """

    def __init__(
        self,
        local_root: str | Path,
        peer_node_id: str,
        share_id: str,
        host: str,
        manifest_port: int,
        transfer_port: int,
        *,
        manifest_client: ManifestService,
        transfer_sender: TransferService,
        shared_state: SharedStateDatabase,
    ) -> None:
        if not isinstance(manifest_client, ManifestService):
            raise TypeError("manifest_client must be a ManifestService")

        if not isinstance(transfer_sender, TransferService):
            raise TypeError("transfer_sender must be a TransferService")

        if not isinstance(shared_state, SharedStateDatabase):
            raise TypeError("shared_state must be a SharedStateDatabase")

        if (
            manifest_client.identity.node_id
            != transfer_sender.identity.node_id
        ):
            raise ValueError(
                "Manifest and transfer clients must use the same identity"
            )

        for label, value in (
            ("peer_node_id", peer_node_id),
            ("share_id", share_id),
        ):
            if (
                not isinstance(value, str)
                or len(value) != 32
                or any(c not in "0123456789abcdef" for c in value)
            ):
                raise ValueError(
                    f"{label} must be 32 lowercase hex characters"
                )

        if peer_node_id == manifest_client.identity.node_id:
            raise ValueError(
                "Cannot synchronize with our own identity"
            )

        if not isinstance(host, str):
            raise ValueError("host must be numeric IPv4")

        try:
            address = ipaddress.IPv4Address(host)
        except ValueError as exc:
            raise ValueError(
                "host must be numeric IPv4"
            ) from exc

        if (
            address.is_unspecified
            or address.is_multicast
            or str(address) == "255.255.255.255"
        ):
            raise ValueError(
                "host must be unicast IPv4"
            )

        for label, port in (
            ("manifest_port", manifest_port),
            ("transfer_port", transfer_port),
        ):
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError(
                    f"{label} must be between 1 and 65535"
                )

        candidate = Path(local_root).expanduser()

        if (
            candidate.is_symlink()
            or (
                hasattr(candidate, "is_junction")
                and candidate.is_junction()
            )
        ):
            raise ValueError(
                "Local share cannot be a link or junction"
            )

        root = candidate.resolve(strict=True)

        if not root.is_dir():
            raise NotADirectoryError(root)

        self.root = root
        self.peer_node_id = peer_node_id
        self.share_id = share_id
        self.host = str(address)
        self.manifest_port = manifest_port
        self.transfer_port = transfer_port

        self.manifest_client = manifest_client
        self.transfer_sender = transfer_sender
        self.shared_state = shared_state

        self._scanner = FileScanner(root)
        self._cycle_lock = threading.Lock()

    def _scan(self) -> ScanResult:
        snapshot = self._scanner.scan()

        if not snapshot.complete:
            raise CoordinationError(
                "Local scan incomplete; refusing synchronization"
            )

        return snapshot

    def _fetch(self) -> RemoteManifest:
        response = self.manifest_client.fetch(
            self.host,
            self.manifest_port,
            self.peer_node_id,
            self.share_id,
        )

        if (
            response.peer_node_id != self.peer_node_id
            or response.share_id != self.share_id
        ):
            raise CoordinationError(
                "Wrong authenticated peer or share in remote manifest"
            )

        return response

    def _check_baseline(
        self,
        remote: RemoteManifest,
    ) -> tuple[ScanResult | None, int]:
        base = self.shared_state.load(
            self.root,
            self.peer_node_id,
            self.share_id,
        )

        revision = (
            base.revision if base is not None else 0
        )
        digest = (
            base.sha256 if base is not None else None
        )

        if (
            remote.baseline_revision != revision
            or remote.baseline_sha256 != digest
        ):
            raise StaleSyncState(
                "Shared baseline differs between devices; "
                "reconcile agreement before syncing"
            )

        return (
            base.snapshot if base is not None else None
        ), revision

    def inspect(self) -> SyncPreview:
        """Read-only three-way plan; unknown, conflicting files are retained."""
        with self._cycle_lock:
            local = self._scan()
            remote = self._fetch()
            base, revision = self._check_baseline(remote)

            plan = ConflictResolver.plan(
                local,
                remote.snapshot,
                base=base,
            )

            return SyncPreview(
                plan,
                local,
                remote,
                revision,
            )

    def _validate_remote(
        self,
        expected: dict[str, tuple[int, str]],
        revision: int,
        digest: str | None,
    ) -> None:
        remote = self._fetch()

        if (
            remote.baseline_revision != revision
            or remote.baseline_sha256 != digest
        ):
            raise StaleSyncState(
                "Remote shared baseline changed during synchronization"
            )

        if _content(remote.snapshot) != expected:
            raise StaleSyncState(
                "Remote files changed during synchronization"
            )

    def execute_new_files(
        self,
        preview: SyncPreview,
        *,
        cancel_event: threading.Event | None = None,
        on_progress: Callable[[TransferProgress], None] | None = None,
    ) -> SyncCycleResult:
        """Push only absent targets. No overwrites, downloads or deletions.

        The receiver MUST use TransferService(allow_overwrite=False). The
        coordinator checks the remote manifest before and after every push,
        but cannot close a network race without conditional receiver writes.
        """
        if not isinstance(preview, SyncPreview):
            raise TypeError(
                "preview must be a SyncPreview"
            )

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

        with self._cycle_lock:
            if (
                preview.local.root != self.root
                or preview.remote.peer_node_id != self.peer_node_id
                or preview.remote.share_id != self.share_id
            ):
                raise CoordinationError(
                    "Preview belongs to another folder or device"
                )

            if self.shared_state.pending(
                self.root,
                self.peer_node_id,
                self.share_id,
            ) is not None:
                raise CoordinationError(
                    "Unresolved shared-baseline proposal; resolve it first"
                )

            _, revision = self._check_baseline(
                preview.remote
            )

            if revision != preview.baseline_revision:
                raise StaleSyncState(
                    "Shared baseline changed since planning"
                )

            original = _content(
                preview.local
            )

            expected_remote = _content(
                preview.remote.snapshot
            )

            completed: list[TransferResult] = []
            paused = False

            for decision in preview.new_uploads:
                if (
                    cancel_event is not None
                    and cancel_event.is_set()
                ):
                    paused = True
                    break

                if _content(self._scan()) != original:
                    raise StaleSyncState(
                        "Local files changed since the preview"
                    )

                self._validate_remote(
                    expected_remote,
                    revision,
                    preview.remote.baseline_sha256,
                )

                if (
                    decision.path in expected_remote
                    or decision.local is None
                ):
                    raise StaleSyncState(
                        "Proposed creation is no longer safe"
                    )

                result = self.transfer_sender.send_file(
                    self.host,
                    self.transfer_port,
                    self.peer_node_id,
                    self.root,
                    decision.path,
                    cancel_event=cancel_event,
                    on_progress=on_progress,
                )

                if not result.completed:
                    paused = True
                    break

                if (
                    result.path != decision.path
                    or (
                        result.total,
                        result.sha256,
                    ) != _fingerprint(decision.local)
                ):
                    raise StaleSyncState(
                        "Source content changed during transfer"
                    )

                expected_remote[
                    decision.path
                ] = _fingerprint(
                    decision.local
                )

                self._validate_remote(
                    expected_remote,
                    revision,
                    preview.remote.baseline_sha256,
                )

                completed.append(result)

            return SyncCycleResult(
                preview,
                tuple(completed),
                paused,
            )

    def run_once(
        self,
        *,
        push_new: bool = False,
        cancel_event: threading.Event | None = None,
        on_progress: Callable[[TransferProgress], None] | None = None,
    ) -> SyncCycleResult:
        """Dry-run by default; opt-in to creating missing remote files."""
        if type(push_new) is not bool:
            raise TypeError(
                "push_new must be bool"
            )

        preview = self.inspect()

        if not push_new:
            return SyncCycleResult(
                preview,
                (),
                False,
            )

        return self.execute_new_files(
            preview,
            cancel_event=cancel_event,
            on_progress=on_progress,
        )
