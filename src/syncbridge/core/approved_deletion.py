
"""Owner-executed, recoverable deletion after authenticated peer consent.

The file is already missing on the requesting peer. The owner of the remaining
copy explicitly approves it through DeletionApprovalService.decide(). Only the
owner runs this module. No remote-delete RPC is exposed.

The remaining file is moved to a durable recovery vault OUTSIDE the shared
folder (and on the same filesystem). Both devices then commit the resulting
inventory through BaselineCoordinator. On network/commit failure, retain the
vault entry and retry the SAME request; never silently restore or discard it.

IMPORTANT: callers MUST serialize synchronization and owner execution for the
folder pair. Cross-device locks and arbitrary filesystem writers are outside
this module's guarantees. Do not run unattended with background auto_apply.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

from syncbridge.core.lifecycle import SyncLifecycle
from syncbridge.core.scanner import FileScanner
from syncbridge.network.deletion_approval import (
    DeletionApprovalService, DeletionRequest,
)
from syncbridge.storage.shared_state import _validate_path


class ApprovedDeletionError(RuntimeError):
    """An approved deletion could not be applied without risking user data."""


@dataclass(frozen=True, slots=True)
class DeletionOutcome:
    code: str
    message: str
    recovery_path: Path
    revision: int | None
    completed: bool


def _hash_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ApprovedDeletionError("Only regular files can be removed")
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def _safe_path(root: Path, relative: str) -> Path:
    _validate_path(relative)
    current = root
    parts = relative.split("/")
    for part in parts[:-1]:
        current = current / part
        if current.is_symlink() or (
            hasattr(current, "is_junction") and current.is_junction()
        ):
            raise ApprovedDeletionError("Folder contains an unsafe link")
        if not current.is_dir():
            raise ApprovedDeletionError("Parent folder no longer exists")
    path = current / parts[-1]
    if path.is_symlink() or (
        hasattr(path, "is_junction") and path.is_junction()
    ):
        raise ApprovedDeletionError("File changed into a link")
    return path


class RecoveryVault:
    """An append-only journal plus recoverable blobs, stored off the share.

    One request ID corresponds to exactly one immutable JSON entry and blob.
    Journal is written before the atomic same-volume move. A crash between
    those steps leaves the original file intact and can be retried safely.
    """

    def __init__(self, root: Path | str, directory: Path | str) -> None:
        self.root = Path(root).expanduser().resolve(strict=True)
        if not self.root.is_dir():
            raise NotADirectoryError(self.root)

        candidate = Path(directory).expanduser()
        if candidate.is_symlink() or (
            hasattr(candidate, "is_junction") and candidate.is_junction()
        ):
            raise ValueError("Recovery directory cannot be a link")
        self.directory = candidate.resolve(strict=False)
        if (
            self.directory == self.root
            or self.root in self.directory.parents
            or self.directory in self.root.parents
        ):
            raise ValueError("Recovery storage must be separate from the shared folder")
        self.directory.mkdir(parents=True, exist_ok=True)
        if os.stat(self.root).st_dev != os.stat(self.directory).st_dev:
            raise ValueError("Recovery storage must be on the same filesystem as the share")
        self._lock = threading.RLock()

    def _paths(self, request_id: str) -> tuple[Path, Path]:
        if (
            not isinstance(request_id, str)
            or len(request_id) != 32
            or any(c not in "0123456789abcdef" for c in request_id)
        ):
            raise ValueError("Invalid deletion request ID")
        return (
            self.directory / f"{request_id}.json",
            self.directory / f"{request_id}.recovery",
        )

    @staticmethod
    def _details(request: DeletionRequest) -> dict:
        return {
            "request_id": request.request_id,
            "share_id": request.share_id,
            "peer_node_id": request.peer_node_id,
            "path": request.path,
            "baseline_revision": request.baseline_revision,
            "baseline_sha256": request.baseline_sha256,
            "file_sha256": request.file_sha256,
            "file_size": request.file_size,
        }

    def stored(self, request: DeletionRequest) -> Path | None:
        with self._lock:
            metadata, blob = self._paths(request.request_id)
            if not metadata.exists():
                if blob.exists():
                    raise ApprovedDeletionError("Orphaned recovery blob needs manual inspection")
                return None
            if metadata.is_symlink() or blob.is_symlink():
                raise ApprovedDeletionError("Recovery storage contains an unsafe link")
            try:
                details = json.loads(metadata.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise ApprovedDeletionError("Recovery journal is damaged") from exc
            if details != self._details(request):
                raise ApprovedDeletionError("Recovery record does not match the approved file")
            if not blob.exists():
                return None
            if _hash_file(blob) != (request.file_size, request.file_sha256):
                raise ApprovedDeletionError("Recovered copy failed its integrity check")
            return blob

    def preserve(self, request: DeletionRequest) -> Path:
        with self._lock:
            metadata, blob = self._paths(request.request_id)
            source = _safe_path(self.root, request.path)
            existing = self.stored(request)
            if existing is not None:
                if source.exists():
                    raise ApprovedDeletionError(
                        "The file reappeared after being preserved; review before proceeding"
                    )
                return existing

            if not source.is_file():
                raise ApprovedDeletionError("The approved file is no longer present")
            if _hash_file(source) != (request.file_size, request.file_sha256):
                raise ApprovedDeletionError("The file changed after approval. Review it again")

            if not metadata.exists():
                fd, temporary = tempfile.mkstemp(prefix="journal-", dir=self.directory)
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as handle:
                        json.dump(self._details(request), handle, sort_keys=True)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.link(temporary, metadata)
                except FileExistsError as exc:
                    raise ApprovedDeletionError("Recovery journal already exists") from exc
                finally:
                    Path(temporary).unlink(missing_ok=True)

            if blob.exists() or blob.is_symlink():
                raise ApprovedDeletionError("Recovery destination is already occupied")

            # Recheck immediately before the same-volume move.
            if _hash_file(source) != (request.file_size, request.file_sha256):
                raise ApprovedDeletionError("File was edited before recovery move")
            os.replace(source, blob)
            if _hash_file(blob) != (request.file_size, request.file_sha256):
                raise ApprovedDeletionError(
                    "File changed during removal. Its moved copy is in recovery "
                    "storage; do not continue syncing until it is inspected"
                )
            return blob

    def restore(self, request: DeletionRequest) -> Path:
        """Explicit local recovery, never overwriting an existing destination."""
        with self._lock:
            blob = self.stored(request)
            if blob is None:
                raise ApprovedDeletionError("No recoverable copy was found")
            destination = _safe_path(self.root, request.path)
            if destination.exists() or destination.is_symlink():
                raise ApprovedDeletionError("A file already exists at the original location")

            # Copy into a temporary file, then publish without overwriting.
            fd, temporary = tempfile.mkstemp(prefix="restore-", dir=destination.parent)
            temp = Path(temporary)
            try:
                with os.fdopen(fd, "wb") as target, blob.open("rb") as source:
                    while chunk := source.read(1024 * 1024):
                        target.write(chunk)
                    target.flush()
                    os.fsync(target.fileno())
                if _hash_file(temp) != (request.file_size, request.file_sha256):
                    raise ApprovedDeletionError("Recovery copy was damaged")
                try:
                    os.link(temp, destination)
                except FileExistsError as exc:
                    raise ApprovedDeletionError("A file appeared during restore") from exc
            finally:
                temp.unlink(missing_ok=True)
            return destination


class ApprovedDeletionCoordinator:
    """Apply a LOCAL owner's approval and jointly commit the resulting deletion.

    Caller must pause background sync on both peers and serialize this action
    with other synchronization cycles. Retry the identical request after any
    network failure; a saved recovery copy is never discarded automatically.
    """

    def __init__(
        self,
        lifecycle: SyncLifecycle,
        approval_service: DeletionApprovalService,
        vault: RecoveryVault,
    ) -> None:
        if not isinstance(lifecycle, SyncLifecycle):
            raise TypeError("lifecycle must be SyncLifecycle")
        if not isinstance(approval_service, DeletionApprovalService):
            raise TypeError("approval_service must be DeletionApprovalService")
        if not isinstance(vault, RecoveryVault):
            raise TypeError("vault must be RecoveryVault")
        coordinator = lifecycle.coordinator
        if coordinator.root != vault.root:
            raise ValueError("Recovery vault points to a different shared folder")
        if approval_service.shared_state.path != coordinator.shared_state.path:
            raise ValueError("Consent and lifecycle must use the same baseline database")
        if approval_service._shares.get(coordinator.share_id) != coordinator.root:
            raise ValueError("Consent service does not manage this share")
        self.lifecycle = lifecycle
        self.approvals = approval_service
        self.vault = vault
        self._lock = threading.RLock()

    def _approved(self, request_id: str) -> DeletionRequest:
        co = self.lifecycle.coordinator
        for item in self.approvals.incoming(co.share_id, co.peer_node_id):
            if item.request_id == request_id:
                if item.state != "approved":
                    raise ApprovedDeletionError(
                        "The other device's deletion request has not been approved locally"
                    )
                return item
        raise ApprovedDeletionError("Deletion request was not found")

    def _inventory_matches(
        self, request: DeletionRequest, *, already_preserved: bool
    ) -> None:
        co = self.lifecycle.coordinator
        preview = co.inspect()
        baseline = co.shared_state.load(co.root, co.peer_node_id, co.share_id)
        if baseline is None or (
            baseline.revision, baseline.sha256
        ) != (request.baseline_revision, request.baseline_sha256):
            raise ApprovedDeletionError("Shared history changed; request a new review")
        if co.shared_state.pending(co.root, co.peer_node_id, co.share_id) is not None:
            raise ApprovedDeletionError("An earlier checkpoint is unfinished")
        base = {p: (f.size, f.sha256) for p, f in baseline.snapshot.files.items()}
        if base.get(request.path) != (request.file_size, request.file_sha256):
            raise ApprovedDeletionError("File no longer matches approved history")
        original = dict(base)
        original.pop(request.path)
        remote = {p: (f.size, f.sha256) for p, f in preview.remote.snapshot.files.items()}
        local = {p: (f.size, f.sha256) for p, f in preview.local.files.items()}
        expected_local = original if already_preserved else base
        if remote != original or local != expected_local:
            raise ApprovedDeletionError(
                "Other files changed, or the requesting device restored the file. "
                "Finish those changes and review deletion again"
            )

    def apply(self, request_id: str) -> DeletionOutcome:
        with self._lock:
            request = self._approved(request_id)
            co = self.lifecycle.coordinator
            baseline = co.shared_state.load(co.root, co.peer_node_id, co.share_id)
            recovered = self.vault.stored(request)

            # A previous attempt may already have successfully committed.
            if baseline is not None and baseline.revision > request.baseline_revision:
                if (
                    baseline.revision == request.baseline_revision + 1
                    and request.path not in baseline.snapshot.files
                    and recovered is not None
                ):
                    current = co.inspect()
                    if (
                        request.path in current.local.files
                        or request.path in current.remote.snapshot.files
                    ):
                        raise ApprovedDeletionError(
                            "The previously removed file has reappeared; review it"
                        )
                    return DeletionOutcome(
                        "SB-DEL-109",
                        f"'{request.path}' was already removed from both synchronized "
                        "folders. A copy remains in recovery storage.",
                        recovered, baseline.revision, True,
                    )
                raise ApprovedDeletionError("Shared history advanced; this approval is no longer valid")

            if recovered is None:
                self._inventory_matches(request, already_preserved=False)
                self.approvals._fresh(co.root, co.peer_node_id, co.share_id, request)
                recovered = self.vault.preserve(request)
            else:
                if _safe_path(co.root, request.path).exists():
                    raise ApprovedDeletionError("A file was recreated; do not overwrite it")

            # Resume a previously staged baseline proposal if one exists.
            pending = co.shared_state.pending(co.root, co.peer_node_id, co.share_id)
            if pending is None:
                self._inventory_matches(request, already_preserved=True)

            try:
                checkpoint = self.lifecycle.baseline.checkpoint()
            except Exception as exc:
                raise ApprovedDeletionError(
                    "The file is safely stored in recovery, but both computers "
                    "have not confirmed the deletion yet. Keep both apps running "
                    "and retry this same approval. [SB-DEL-110]"
                ) from exc

            if request.path in checkpoint.baseline.snapshot.files:
                raise ApprovedDeletionError("Checkpoint unexpectedly still contains the deleted file")

            return DeletionOutcome(
                "SB-DEL-109",
                f"'{request.path}' is no longer in either synchronized folder. "
                "The original can be restored from recovery storage.",
                recovered,
                checkpoint.baseline.revision,
                True,
            )
