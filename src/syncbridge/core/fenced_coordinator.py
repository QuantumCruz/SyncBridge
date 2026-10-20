
"""Adapt the existing conflict-safe coordinator to an active fenced session.

Keeps the proven per-file manifest/baseline checks. Only file-transfer calls
are routed through FencedSyncSession. No direct legacy transfer fallback exists.
"""
from __future__ import annotations

import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator

from syncbridge.core.conflicts import SyncAction
from syncbridge.core.coordinator import SyncCoordinator, SyncCycleResult, SyncPreview
from syncbridge.network.fenced_download import FencedDownloadClient
from syncbridge.network.fenced_sync_session import FencedSyncSession
from syncbridge.network.transfer import TransferError, TransferProgress, TransferResult


class FencedCoordinatorTransfer(FencedDownloadClient):
    """TransferService-compatible endpoint, usable only during a fenced cycle.

    It never starts a listener; all writes are done by a fenced publisher.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._session: FencedSyncSession | None = None
        self._session_thread: int | None = None

    @contextmanager
    def activate(self, session: FencedSyncSession) -> Iterator[None]:
        if not isinstance(session, FencedSyncSession) or not session.active:
            raise TransferError("A live fenced sync session is required")
        if self._session is not None:
            raise TransferError("Another fenced session is already active")
        self._session = session
        self._session_thread = threading.get_ident()
        try:
            yield
        finally:
            self._session = None
            self._session_thread = None

    def _require_session(self, host: str, port: int, peer: str) -> FencedSyncSession:
        session = self._session
        if (
            session is None
            or not session.active
            or self._session_thread != threading.get_ident()
        ):
            raise TransferError("Transfer requires an active guarded sync cycle")
        if host != session.remote_host or peer != session.peer_node_id:
            raise TransferError("Transfer destination does not match the approved session")
        if port not in (session.remote_upload_port, session.remote_read_port):
            raise TransferError("Transfer port does not match the approved session")
        if session.share_id != self.share_id:
            raise TransferError("Transfer share differs from the approved session")
        return session

    def send_file(
        self, host: str, port: int, expected_node_id: str,
        source_root: str | Path, relative_path: str, *,
        share_id: str | None = None,
        expected_destination_sha256: str | None = None,
        cancel_event: threading.Event | None = None,
        on_progress: Callable[[TransferProgress], None] | None = None,
    ) -> TransferResult:
        session = self._require_session(host, port, expected_node_id)
        if port != session.remote_upload_port:
            raise TransferError("Incorrect fenced upload port")
        if share_id not in (None, self.share_id):
            raise TransferError("Incorrect upload share")
        if Path(source_root).resolve() != self.destination_root.resolve():
            raise TransferError("Upload source must be the selected sync folder")
        return session.upload(
            relative_path,
            expected_destination_sha256=expected_destination_sha256,
            cancel_event=cancel_event,
            on_progress=on_progress,
        )

    def fetch_file(
        self, host: str, port: int, expected_node_id: str,
        share_id: str, relative_path: str, *,
        expected_source_sha256: str,
        expected_destination_sha256: str | None = None,
        cancel_event: threading.Event | None = None,
        on_progress: Callable[[TransferProgress], None] | None = None,
    ) -> TransferResult:
        session = self._require_session(host, port, expected_node_id)
        if port != session.remote_read_port or share_id != self.share_id:
            raise TransferError("Incorrect fenced download destination")
        return session.download(
            relative_path,
            expected_source_sha256=expected_source_sha256,
            expected_destination_sha256=expected_destination_sha256,
            cancel_event=cancel_event,
            on_progress=on_progress,
        )


class FencedSyncCoordinator(SyncCoordinator):
    """Preserve the original coordinator's checks, but fence every mutation."""

    def __init__(
        self, *args,
        session_factory: Callable[..., FencedSyncSession],
        **kwargs,
    ) -> None:
        if not callable(session_factory):
            raise TypeError("session_factory must be callable")
        super().__init__(*args, **kwargs)
        if not isinstance(self.transfer_sender, FencedCoordinatorTransfer):
            raise TypeError("FencedSyncCoordinator requires a fenced transfer adapter")
        self._session_factory = session_factory
        self._fencing_lock = threading.RLock()

    def _execute(
        self,
        preview: SyncPreview,
        *,
        full_sync: bool,
        cancel_event: threading.Event | None,
        on_progress: Callable[[TransferProgress], None] | None,
    ) -> SyncCycleResult:
        with self._fencing_lock:
            if full_sync:
                actions = tuple(
                    action for action in preview.plan.decisions
                    if action.action in (SyncAction.UPLOAD, SyncAction.DOWNLOAD)
                )
            else:
                actions = preview.new_uploads

            if not actions or (cancel_event is not None and cancel_event.is_set()):
                return super()._execute(
                    preview, full_sync=full_sync,
                    cancel_event=cancel_event, on_progress=on_progress,
                )

            with self._session_factory(
                need_upload=any(action.action is SyncAction.UPLOAD for action in actions),
                need_download=any(action.action is SyncAction.DOWNLOAD for action in actions),
            ) as session:
                with self.transfer_sender.activate(session):
                    return super()._execute(
                        preview, full_sync=full_sync,
                        cancel_event=cancel_event, on_progress=on_progress,
                    )
