
"""Safely forget the LOCAL folder relationship when switching computers.

This operation does not touch synchronized files, device identity, or trust.
The remote computer's separate configuration is unchanged. The running
synchronization session must be stopped before calling it.
"""
from __future__ import annotations

from dataclasses import replace

from syncbridge.storage.config import ConfigStore, ShareConfig
from syncbridge.ui.readiness_jobs import ReadinessJobs


class ConnectionSwitchError(RuntimeError):
    """The previous connection cannot safely be replaced yet."""


def forget_local_folder_connection(
    store: ConfigStore,
    *,
    expected_share_id: str,
    running: bool,
) -> ShareConfig:
    """Remove one explicitly selected LOCAL share after its runtime has stopped.

    Revision-aware ConfigStore.save refuses concurrent configuration changes.
    We never modify the peer's configuration or delete folder contents.
    """
    if running:
        raise ConnectionSwitchError(
            "Disconnect before switching to another computer."
        )

    config = store.load()
    if len(config.shares) != 1:
        raise ConnectionSwitchError(
            "This profile contains multiple folder relationships. "
            "SyncBridge cannot switch them automatically."
        )

    share = config.shares[0]
    if share.share_id != expected_share_id:
        raise ConnectionSwitchError(
            "The saved folder connection changed. Reopen the computer list."
        )

    # Cancel any retry record before removing its approved share. If settings
    # are concurrently edited, the revision check below fails closed.
    ReadinessJobs(store.path.parent).remove(
        share.share_id, share.peer_node_id
    )
    store.save(replace(config, shares=()))
    return share
