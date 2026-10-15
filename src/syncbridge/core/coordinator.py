
"""Conservative synchronization orchestration for one approved folder pair.

Dry-run is the default. ``push_new=True`` retains the original create-only
behavior. ``sync=True`` opts into share-bound uploads, downloads, and conditional
updates. Divergent edits and deletions are NEVER resolved automatically.

This class does not commit shared baselines; both devices still need a durable,
recoverable agreement protocol. The remote manifest and transfer services must
be configured to serve the SAME physical folder for the SAME share_id.
"""

from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from syncbridge.core.conflicts import ConflictResolver, SyncAction, SyncDecision, SyncPlan
from syncbridge.core.scanner import FileRecord, FileScanner, ScanResult
from syncbridge.network.manifest import ManifestService, RemoteManifest
from syncbridge.network.transfer import TransferProgress, TransferResult, TransferService
from syncbridge.storage.shared_state import SharedStateDatabase


class CoordinationError(RuntimeError):
    """The selected folder pair cannot safely carry out this operation."""


class StaleSyncState(CoordinationError):
    """A file inventory or shared baseline has changed since planning."""


@dataclass(frozen=True, slots=True)
class SyncPreview:
    plan: SyncPlan
    local: ScanResult
    remote: RemoteManifest
    baseline_revision: int

    @property
    def new_uploads(self) -> tuple[SyncDecision, ...]:
        return tuple(d for d in self.plan.uploads if d.remote is None)

    @property
    def new_downloads(self) -> tuple[SyncDecision, ...]:
        return tuple(d for d in self.plan.downloads if d.local is None)

    @property
    def deferred_updates(self) -> tuple[SyncDecision, ...]:
        """Existing-file changes; only the new strict sync mode can attempt them."""
        return tuple(
            d for d in self.plan.decisions
            if (d.action is SyncAction.UPLOAD and d.remote is not None)
            or (d.action is SyncAction.DOWNLOAD and d.local is not None)
        )


@dataclass(frozen=True, slots=True)
class SyncCycleResult:
    preview: SyncPreview
    uploaded: tuple[TransferResult, ...]
    paused: bool
    downloaded: tuple[TransferResult, ...] = ()

    @property
    def pending_uploads(self) -> tuple[SyncDecision, ...]:
        completed = {result.path for result in self.uploaded if result.completed}
        return tuple(d for d in self.preview.plan.uploads if d.path not in completed)

    @property
    def pending_downloads(self) -> tuple[SyncDecision, ...]:
        completed = {result.path for result in self.downloaded if result.completed}
        return tuple(d for d in self.preview.plan.downloads if d.path not in completed)

    @property
    def pending_updates(self) -> tuple[SyncDecision, ...]:
        uploaded = {result.path for result in self.uploaded if result.completed}
        downloaded = {result.path for result in self.downloaded if result.completed}
        return tuple(
            d for d in self.preview.deferred_updates
            if not (
                d.action is SyncAction.UPLOAD and d.path in uploaded
                or d.action is SyncAction.DOWNLOAD and d.path in downloaded
            )
        )

    @property
    def pending_conflicts(self) -> tuple[SyncDecision, ...]:
        return self.preview.plan.conflicts

    @property
    def pending_deletions(self) -> tuple[SyncDecision, ...]:
        return self.preview.plan.pending_deletions


def _contents(snapshot: ScanResult) -> dict[str, tuple[int, str]]:
    return {path: (record.size, record.sha256) for path, record in snapshot.files.items()}


def _fingerprint(record: FileRecord | None) -> tuple[int, str] | None:
    return None if record is None else (record.size, record.sha256)


def _decisions(plan: SyncPlan) -> tuple:
    """Compare plans by content, ignoring harmless mtime-only changes."""
    return tuple(
        (d.path, d.action, _fingerprint(d.base),
         _fingerprint(d.local), _fingerprint(d.remote))
        for d in plan.decisions
    )


class SyncCoordinator:
    """Run read-only previews, legacy create-only pushes, or strict two-way sync.

    An instance serializes its own cycles. Cross-process synchronization and
    concurrent local application writes require additional orchestration.
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
        if manifest_client.identity.node_id != transfer_sender.identity.node_id:
            raise ValueError("Manifest and transfer clients must use the same identity")

        for label, value in (("peer_node_id", peer_node_id), ("share_id", share_id)):
            if (not isinstance(value, str) or len(value) != 32
                    or any(c not in "0123456789abcdef" for c in value)):
                raise ValueError(f"{label} must be 32 lowercase hex characters")
        if peer_node_id == manifest_client.identity.node_id:
            raise ValueError("Cannot synchronize with our own identity")
        if not isinstance(host, str):
            raise ValueError("host must be numeric IPv4")
        try:
            address = ipaddress.IPv4Address(host)
        except ValueError as exc:
            raise ValueError("host must be numeric IPv4") from exc
        if address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255":
            raise ValueError("host must be unicast IPv4")
        for label, port in (("manifest_port", manifest_port), ("transfer_port", transfer_port)):
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError(f"{label} must be between 1 and 65535")

        candidate = Path(local_root).expanduser()
        if candidate.is_symlink() or (
            hasattr(candidate, "is_junction") and candidate.is_junction()
        ):
            raise ValueError("Local share cannot be a link or junction")
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
            raise CoordinationError("Local scan incomplete; refusing synchronization")
        return snapshot

    def _fetch(self) -> RemoteManifest:
        response = self.manifest_client.fetch(
            self.host, self.manifest_port, self.peer_node_id, self.share_id
        )
        if response.peer_node_id != self.peer_node_id or response.share_id != self.share_id:
            raise CoordinationError("Wrong authenticated peer or share in remote manifest")
        return response

    def _check_baseline(self, remote: RemoteManifest) -> tuple[ScanResult | None, int]:
        baseline = self.shared_state.load(self.root, self.peer_node_id, self.share_id)
        revision = baseline.revision if baseline is not None else 0
        digest = baseline.sha256 if baseline is not None else None
        if remote.baseline_revision != revision or remote.baseline_sha256 != digest:
            raise StaleSyncState("Shared baseline differs between devices; reconcile agreement before syncing")
        return (baseline.snapshot if baseline is not None else None), revision

    def inspect(self) -> SyncPreview:
        """Get a conflict-safe read-only plan; remote content stays untouched."""
        with self._cycle_lock:
            local = self._scan()
            remote = self._fetch()
            baseline, revision = self._check_baseline(remote)
            plan = ConflictResolver.plan(local, remote.snapshot, base=baseline)
            return SyncPreview(plan, local, remote, revision)

    def _validate_preview(self, preview: SyncPreview) -> tuple[dict, dict]:
        if not isinstance(preview, SyncPreview):
            raise TypeError("preview must be a SyncPreview")
        if (preview.local.root != self.root
                or preview.remote.peer_node_id != self.peer_node_id
                or preview.remote.share_id != self.share_id):
            raise CoordinationError("Preview belongs to another folder or device")
        if self.shared_state.pending(self.root, self.peer_node_id, self.share_id) is not None:
            raise CoordinationError("Unresolved shared-baseline proposal; resolve it first")
        baseline, revision = self._check_baseline(preview.remote)
        if revision != preview.baseline_revision:
            raise StaleSyncState("Shared baseline changed since planning")
        correct_plan = ConflictResolver.plan(preview.local, preview.remote.snapshot, base=baseline)
        if _decisions(correct_plan) != _decisions(preview.plan):
            raise CoordinationError("Preview decisions do not match its inventories")
        return _contents(preview.local), _contents(preview.remote.snapshot)

    def _validate_current(
        self,
        local: dict[str, tuple[int, str]],
        remote: dict[str, tuple[int, str]],
        revision: int,
        digest: str | None,
    ) -> None:
        if self.shared_state.pending(self.root, self.peer_node_id, self.share_id) is not None:
            raise CoordinationError("Unresolved shared-baseline proposal appeared during synchronization")
        if _contents(self._scan()) != local:
            raise StaleSyncState("Local files changed since the preview")
        current_remote = self._fetch()
        _, current_revision = self._check_baseline(current_remote)
        if current_revision != revision or current_remote.baseline_sha256 != digest:
            raise StaleSyncState("Shared baseline changed during synchronization")
        if _contents(current_remote.snapshot) != remote:
            raise StaleSyncState("Remote files changed during synchronization")

    def _require_share_bound_receiver(self) -> None:
        """Downloads MUST land in the exact approved local sync folder."""
        sender = self.transfer_sender
        if sender.share_id != self.share_id:
            raise CoordinationError("Full sync requires a share-bound transfer service")
        if sender.destination_root.resolve() != self.root:
            raise CoordinationError("Transfer receiver must use the synchronized local folder")

    @staticmethod
    def _validate_args(
        cancel_event: threading.Event | None,
        on_progress: Callable[[TransferProgress], None] | None,
    ) -> None:
        if cancel_event is not None and not isinstance(cancel_event, threading.Event):
            raise TypeError("cancel_event must be threading.Event or None")
        if on_progress is not None and not callable(on_progress):
            raise TypeError("on_progress must be callable or None")

    def _execute(
        self,
        preview: SyncPreview,
        *,
        full_sync: bool,
        cancel_event: threading.Event | None,
        on_progress: Callable[[TransferProgress], None] | None,
    ) -> SyncCycleResult:
        self._validate_args(cancel_event, on_progress)
        with self._cycle_lock:
            local, remote = self._validate_preview(preview)
            if full_sync:
                self._require_share_bound_receiver()
                actions = tuple(
                    d for d in preview.plan.decisions
                    if d.action in (SyncAction.UPLOAD, SyncAction.DOWNLOAD)
                )
                if not self.transfer_sender.allow_overwrite and any(
                    d.action is SyncAction.DOWNLOAD and d.local is not None
                    for d in actions
                ):
                    raise CoordinationError("Local transfer receiver must opt into conditional updates")
            else:
                actions = preview.new_uploads

            uploads: list[TransferResult] = []
            downloads: list[TransferResult] = []
            paused = False
            for decision in actions:
                if cancel_event is not None and cancel_event.is_set():
                    paused = True
                    break
                self._validate_current(
                    local, remote, preview.baseline_revision,
                    preview.remote.baseline_sha256,
                )
                if decision.action is SyncAction.UPLOAD:
                    expected = _fingerprint(decision.local)
                    if expected is None or local.get(decision.path) != expected:
                        raise StaleSyncState("Upload source no longer matches preview")
                    if remote.get(decision.path) != _fingerprint(decision.remote):
                        raise StaleSyncState("Upload destination no longer matches preview")
                    kwargs = (
                        {"share_id": self.share_id,
                         "expected_destination_sha256": (
                             decision.remote.sha256 if decision.remote is not None else None
                         )}
                        if full_sync else {}
                    )
                    result = self.transfer_sender.send_file(
                        self.host, self.transfer_port, self.peer_node_id,
                        self.root, decision.path,
                        cancel_event=cancel_event, on_progress=on_progress,
                        **kwargs,
                    )
                    if not result.completed:
                        paused = True
                        break
                    if (result.path != decision.path
                            or (result.total, result.sha256) != expected):
                        raise StaleSyncState("Uploaded content differs from planned inventory")
                    remote[decision.path] = expected
                    self._validate_current(
                        local, remote, preview.baseline_revision,
                        preview.remote.baseline_sha256,
                    )
                    uploads.append(result)

                elif full_sync and decision.action is SyncAction.DOWNLOAD:
                    expected = _fingerprint(decision.remote)
                    if expected is None or remote.get(decision.path) != expected:
                        raise StaleSyncState("Download source no longer matches preview")
                    if local.get(decision.path) != _fingerprint(decision.local):
                        raise StaleSyncState("Download destination no longer matches preview")
                    result = self.transfer_sender.fetch_file(
                        self.host, self.transfer_port, self.peer_node_id,
                        self.share_id, decision.path,
                        expected_source_sha256=decision.remote.sha256,
                        expected_destination_sha256=(
                            decision.local.sha256 if decision.local is not None else None
                        ),
                        cancel_event=cancel_event, on_progress=on_progress,
                    )
                    if not result.completed:
                        paused = True
                        break
                    if (result.path != decision.path
                            or (result.total, result.sha256) != expected):
                        raise StaleSyncState("Downloaded content differs from planned inventory")
                    local[decision.path] = expected
                    self._validate_current(
                        local, remote, preview.baseline_revision,
                        preview.remote.baseline_sha256,
                    )
                    downloads.append(result)

            # Deliberately do NOT advance a shared baseline here. A successful
            # file copy does not mean the remote side has acknowledged a commit.
            return SyncCycleResult(preview, tuple(uploads), paused, tuple(downloads))

    def execute_new_files(
        self,
        preview: SyncPreview,
        *,
        cancel_event: threading.Event | None = None,
        on_progress: Callable[[TransferProgress], None] | None = None,
    ) -> SyncCycleResult:
        """Backward-compatible: only push files that don't exist remotely."""
        return self._execute(
            preview, full_sync=False,
            cancel_event=cancel_event, on_progress=on_progress,
        )

    def execute_changes(
        self,
        preview: SyncPreview,
        *,
        cancel_event: threading.Event | None = None,
        on_progress: Callable[[TransferProgress], None] | None = None,
    ) -> SyncCycleResult:
        """Opt-in strict two-way sync; conflicts and deletions remain pending."""
        return self._execute(
            preview, full_sync=True,
            cancel_event=cancel_event, on_progress=on_progress,
        )

    def run_once(
        self,
        *,
        push_new: bool = False,
        sync: bool = False,
        cancel_event: threading.Event | None = None,
        on_progress: Callable[[TransferProgress], None] | None = None,
    ) -> SyncCycleResult:
        """Dry-run by default, legacy create-only or opt-in two-way sync."""
        if type(push_new) is not bool or type(sync) is not bool:
            raise TypeError("push_new and sync must be bool")
        if push_new and sync:
            raise ValueError("Choose either push_new or sync, not both")
        self._validate_args(cancel_event, on_progress)
        preview = self.inspect()
        if sync:
            return self.execute_changes(
                preview, cancel_event=cancel_event, on_progress=on_progress,
            )
        if push_new:
            return self.execute_new_files(
                preview, cancel_event=cancel_event, on_progress=on_progress,
            )
        return SyncCycleResult(preview, (), False)
