
"""Recoverable two-device checkpoint coordination for identical folder inventories.

This deliberately DOES NOT perform transfers, resolve conflicts or delete files.
After a completed two-way sync, both folder inventories must match exactly.
The peer commits first, then the initiator. If the reply is lost or the process
crashes, the initiator's staged SQLite proposal makes the same commit retryable.

No protocol can atomically commit two disconnected SQLite databases. While a
commit is pending or revisions differ, normal sync must remain blocked.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from syncbridge.core.scanner import FileScanner
from syncbridge.network.agreement import AgreementClient, AgreementError
from syncbridge.storage.shared_state import (
    SharedBaseline, SharedStateDatabase, _canonical_rows, _digest,
)


@dataclass(frozen=True, slots=True)
class CheckpointResult:
    baseline: SharedBaseline
    newly_committed: bool
    recovered_pending: bool


class BaselineCoordinator:
    """Agreement client for ONE local folder and ONE authorized remote share.

    Invoke only after the file-transfer coordinator converges the inventories.
    The remote AgreementService must map the same share_id to its actual folder.
    """

    def __init__(
        self,
        local_root: str | Path,
        peer_node_id: str,
        share_id: str,
        host: str,
        port: int,
        *,
        agreement_client: AgreementClient,
        shared_state: SharedStateDatabase,
    ) -> None:
        if not isinstance(agreement_client, AgreementClient):
            raise TypeError('agreement_client must be an AgreementClient')
        if not isinstance(shared_state, SharedStateDatabase):
            raise TypeError('shared_state must be a SharedStateDatabase')
        root = Path(local_root).expanduser()
        if root.is_symlink() or (hasattr(root, 'isjunction') and root.isjunction()):
            raise ValueError('Local share cannot be a link or junction')
        self.root = root.resolve(strict=True)
        if not self.root.is_dir():
            raise NotADirectoryError(self.root)
        self.peer_node_id = peer_node_id
        self.share_id = share_id
        self.host = host
        self.port = port
        self.client = agreement_client
        self.state = shared_state
        self._scanner = FileScanner(self.root)
        self._lock = threading.Lock()

    def _snapshot(self):
        snapshot = self._scanner.scan()
        digest = _digest(_canonical_rows(snapshot, self.root))
        return snapshot, digest

    def checkpoint(self) -> CheckpointResult:
        """Commit or resume one agreed inventory without changing any files.

        A retry uses the persisted proposal ID. Do not clear staging manually
        if a remote commit might already have succeeded.
        """
        with self._lock:
            local_scan, local_digest = self._snapshot()
            committed = self.state.load(self.root, self.peer_node_id, self.share_id)
            pending = self.state.pending(self.root, self.peer_node_id, self.share_id)
            current_rev = 0 if committed is None else committed.revision
            base_digest = None if committed is None else committed.sha256
            remote = self.client.status(
                self.host, self.port, self.peer_node_id, self.share_id
            )

            if pending is None:
                if remote.pending_id is not None:
                    raise AgreementError('Remote has an unresolved baseline proposal')
                if remote.revision != current_rev or remote.sha256 != base_digest:
                    raise AgreementError('Baseline revisions differ; manual recovery required')
                if committed is not None and committed.sha256 == local_digest:
                    if remote.inventory_sha256 != local_digest:
                        raise AgreementError("Remote live inventory differs from local inventory")
                    return CheckpointResult(committed, False, False)
                proposal_id = uuid4().hex
            else:
                if pending.expected_revision != current_rev or pending.sha256 != local_digest:
                    raise AgreementError('Local pending proposal no longer matches the folder')
                if remote.revision == current_rev:
                    if remote.sha256 != base_digest:
                        raise AgreementError('Remote committed history disagrees with local history')
                    if remote.pending_id not in (None, pending.proposal_id):
                        raise AgreementError('Another remote baseline proposal is pending')
                    if remote.pending_id is not None and (
                        remote.pending_revision != current_rev
                        or remote.pending_sha256 != pending.sha256
                    ):
                        raise AgreementError('Remote pending proposal does not match')
                elif remote.revision == current_rev + 1:
                    if remote.sha256 != pending.sha256 or remote.pending_id is not None:
                        raise AgreementError('Remote revision advanced to a different baseline')
                else:
                    raise AgreementError('Remote revision cannot be recovered automatically')
                proposal_id = pending.proposal_id

            # A valid local staging record survives restart and preserves the ID.
            proposal = self.state.stage(
                self.root, self.peer_node_id, self.share_id, local_scan,
                expected_revision=current_rev, proposal_id=proposal_id
            )
            self.state.confirm_local(
                self.root, self.peer_node_id, self.share_id, proposal_id, local_scan
            )

            # The remote compares its own fresh scanner inventory before
            # accepting the same content hash and expected revision.
            self.client.prepare(
                self.host, self.port, self.peer_node_id, self.share_id,
                proposal_id, current_rev, proposal.sha256
            )
            self.state.confirm_remote(
                self.root, self.peer_node_id, self.share_id, proposal_id,
                authenticated_peer_id=self.peer_node_id,
                acknowledged_sha256=proposal.sha256,
            )

            # Remote-first commit. If the network breaks after remote commit,
            # local staging is kept so this exact proposal can be retried.
            self.client.commit(
                self.host, self.port, self.peer_node_id, self.share_id,
                proposal_id, current_rev, proposal.sha256
            )
            final_scan, final_digest = self._snapshot()
            if final_digest != proposal.sha256:
                raise AgreementError(
                    'Local folder changed after remote commit; keep pending '
                    'proposal and recover only when contents match again'
                )
            baseline = self.state.finalize(
                self.root, self.peer_node_id, self.share_id, proposal_id, final_scan
            )
            return CheckpointResult(baseline, True, pending is not None)

    def abort_uncommitted(self) -> bool:
        """Cancel staging on both sides, but NEVER abort a remote commit.

        This can be used when a proposal is stuck before commitment. Do not
        use it to resolve a revision mismatch or throw away a committed state.
        """
        with self._lock:
            pending = self.state.pending(self.root, self.peer_node_id, self.share_id)
            if pending is None:
                return False
            current = self.state.load(self.root, self.peer_node_id, self.share_id)
            current_rev = 0 if current is None else current.revision
            if pending.expected_revision != current_rev:
                raise AgreementError('Cannot abort a stale local proposal')
            self.client.abort(
                self.host, self.port, self.peer_node_id, self.share_id,
                pending.proposal_id, pending.expected_revision, pending.sha256
            )
            return self.state.abort(
                self.root, self.peer_node_id, self.share_id, pending.proposal_id
            )
