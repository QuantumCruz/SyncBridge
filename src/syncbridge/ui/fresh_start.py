
"""Explicitly reset local SyncBridge connection setup without touching user files.

Only use after the application has stopped its listeners and runtime.
This removes saved folder relationships, pending readiness jobs, and trusted
peer records. Device identity, baseline/recovery histories, and user files
are retained. An incomplete coordinated folder change blocks this operation.
"""
from __future__ import annotations

from dataclasses import dataclass

from syncbridge.network.security import TrustStore
from syncbridge.storage.config import ConfigStore
from syncbridge.storage.folder_change_recovery import FolderChangeJournal
from syncbridge.ui.connection_switch import forget_local_folder_connection
from syncbridge.ui.readiness_jobs import ReadinessJobs


class FreshStartError(RuntimeError):
    """Local setup cannot be safely reset in the present state."""


@dataclass(frozen=True)
class FreshStartResult:
    removed_shares: int
    removed_devices: int


def start_fresh_locally(store: ConfigStore, *, running: bool) -> FreshStartResult:
    """Clear previous local connection setup only after explicit UI consent.

    Not a recovery reset, a filesystem delete, or a reset of cryptographic
    identity. The other computer must independently agree to start fresh.
    All networking must already be stopped by the caller.
    """
    if not isinstance(store, ConfigStore):
        raise TypeError("Expected a SyncBridge configuration store")
    if type(running) is not bool or running:
        raise FreshStartError("Disconnect before starting fresh")

    journal = FolderChangeJournal(store)
    if journal.load() is not None:
        raise FreshStartError(
            "An interrupted folder change needs recovery first. "
            "Start fresh will not erase that recovery record."
        )

    current = store.load()
    if len(current.shares) > 1:
        raise FreshStartError(
            "More than one folder relationship is saved. "
            "Start fresh cannot safely choose which to remove."
        )

    jobs = ReadinessJobs(store.path.parent)
    pending = jobs.entries()
    trust = TrustStore(store.path.parent / "trust.json")
    known = trust.devices

    if current.shares:
        forget_local_folder_connection(
            store,
            expected_share_id=current.shares[0].share_id,
            running=False,
        )

    for share_id, peer_id in pending:
        jobs.remove(share_id, peer_id)

    removed = 0
    for device in known:
        if trust.remove(device.node_id):
            removed += 1

    return FreshStartResult(len(current.shares), removed)
