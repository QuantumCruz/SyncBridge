
"""Opt-in fail-closed SyncBridge runtime using receiver-enforced transfers.

This composes the existing manifest, shared-baseline, and lifecycle services
with a single-port fenced upload/read endpoint and a receiver-local lease
service. It does not change the default desktop runtime until its integration
tests pass and the desktop launcher is intentionally migrated.

Lease-control port defaults to 45849. Override both local and remote lease
ports for ephemeral loopback integration tests; ordinary users never manage
these settings. No automatic syncing is enabled by this class itself.
"""
from __future__ import annotations

from pathlib import Path

from syncbridge.core.baseline import BaselineCoordinator
from syncbridge.core.fenced_coordinator import (
    FencedCoordinatorTransfer,
    FencedSyncCoordinator,
)
from syncbridge.core.lifecycle import SyncLifecycle
from syncbridge.core.sync_service import AutoSyncService, ServiceState
from syncbridge.network.agreement import AgreementClient, AgreementService
from syncbridge.network.fenced_duplex import FencedDuplexService
from syncbridge.network.fenced_lease_channel import (
    FencedLeaseClient,
    FencedLeaseService,
    LEASE_CHANNEL_PORT,
)
from syncbridge.network.fenced_sync_session import FencedSyncSession
from syncbridge.network.fenced_transfer import FencedTransferClient
from syncbridge.network.lease_fencing import LeaseAuthority
from syncbridge.network.manifest import ManifestService
from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.runtime import StartupError, SyncBridgeRuntime
from syncbridge.storage.config import ConfigStore
from syncbridge.storage.shared_state import SharedStateDatabase


class FencedSyncBridgeRuntime(SyncBridgeRuntime):
    """Drop-in runtime for fenced-mode integration and migration testing.

    Same status, lifecycle and stop interface as SyncBridgeRuntime. The
    inbound transfer listener never accepts legacy unfenced uploads.
    """

    def __init__(
        self,
        config_store: ConfigStore | None = None,
        *,
        bind_address: str = "127.0.0.1",
        listen_ports: tuple[int, int, int] | None = None,
        lease_listen_port: int = LEASE_CHANNEL_PORT,
        remote_lease_port: int = LEASE_CHANNEL_PORT,
    ) -> None:
        super().__init__(
            config_store,
            bind_address=bind_address,
            listen_ports=listen_ports,
        )
        if type(lease_listen_port) is not int or not 0 <= lease_listen_port <= 65535:
            raise ValueError("Invalid local lease listener port")
        if type(remote_lease_port) is not int or not 1 <= remote_lease_port <= 65535:
            raise ValueError("Invalid remote lease listener port")
        self.lease_listen_port = lease_listen_port
        self.remote_lease_port = remote_lease_port
        self.lease_authority: LeaseAuthority | None = None
        self.lease_server: FencedLeaseService | None = None
        self.lease_client: FencedLeaseClient | None = None
        self.upload_client: FencedTransferClient | None = None

    def _clear(self) -> None:
        super()._clear()
        self.lease_authority = None
        self.lease_server = None
        self.lease_client = None
        self.upload_client = None

    def start(self, *, background: bool = False):
        if type(background) is not bool:
            raise TypeError("background must be bool")

        with self._guard:
            if self._running:
                return self.status

            self._profile_lock.acquire()
            started = []

            try:
                config = self.config_store.load()
                selected = self._selected(config)
                profile = self.config_store.path.parent

                self.identity = load_or_create_identity(profile / "identity.json")
                self.trust_store = TrustStore(profile / "trust.json")
                self.config = config

                if selected is not None:
                    if self.trust_store.get(selected.peer_node_id) is None:
                        raise StartupError(
                            "Configured peer has not been explicitly paired"
                        )

                    root = Path(selected.local_root).resolve(strict=True)
                    share = selected.share_id
                    peer = selected.peer_node_id
                    remote = selected.remote_host
                    ports = self.listen_ports or (
                        selected.manifest_port,
                        selected.transfer_port,
                        selected.agreement_port,
                    )
                    opts = {"bind_address": self.bind_address}

                    self.shared_state = SharedStateDatabase(
                        profile / "shared_state.sqlite"
                    )
                    self.lease_authority = LeaseAuthority(
                        profile / "lease_fences.sqlite"
                    )

                    self.manifest_server = ManifestService(
                        self.identity,
                        self.trust_store,
                        {share: root},
                        allowed_readers={
                            share: [peer] if selected.grant_manifest else []
                        },
                        shared_state=self.shared_state,
                        listen_port=ports[0],
                        **opts,
                    )
                    self.transfer_server = FencedDuplexService(
                        self.identity,
                        self.trust_store,
                        root,
                        authority=self.lease_authority,
                        share_id=share,
                        allowed_senders=[peer] if selected.grant_write else [],
                        allowed_readers=[peer] if selected.grant_read else [],
                        allow_overwrite=selected.grant_write,
                        listen_port=ports[1],
                        **opts,
                    )
                    self.agreement_server = AgreementService(
                        self.identity,
                        self.trust_store,
                        self.shared_state,
                        {share: root},
                        allowed_peers={
                            share: [peer] if selected.grant_agreement else []
                        },
                        listen_port=ports[2],
                        **opts,
                    )
                    self.lease_server = FencedLeaseService(
                        self.identity,
                        self.trust_store,
                        self.config_store,
                        self.lease_authority,
                        bind_address=self.bind_address,
                        port=self.lease_listen_port,
                    )
                    self.manifest_client = ManifestService(
                        self.identity,
                        self.trust_store,
                        bind_address="127.0.0.1",
                        listen_port=0,
                    )
                    self.transfer_client = FencedCoordinatorTransfer(
                        self.identity,
                        self.trust_store,
                        root,
                        authority=self.lease_authority,
                        share_id=share,
                        allow_overwrite=True,
                        bind_address="127.0.0.1",
                        listen_port=0,
                    )
                    self.upload_client = FencedTransferClient(
                        self.identity,
                        self.trust_store,
                        root,
                        share_id=share,
                        bind_address="127.0.0.1",
                        listen_port=0,
                    )
                    self.lease_client = FencedLeaseClient(
                        self.identity,
                        self.trust_store,
                    )
                    self.agreement_client = AgreementClient(
                        self.identity,
                        self.trust_store,
                    )

                    def make_session(*, need_upload: bool, need_download: bool):
                        return FencedSyncSession(
                            local_root=root,
                            share_id=share,
                            peer_node_id=peer,
                            remote_host=remote,
                            remote_lease_port=self.remote_lease_port,
                            remote_upload_port=selected.transfer_port,
                            remote_read_port=selected.transfer_port,
                            lease_client=self.lease_client,
                            local_authority=self.lease_authority,
                            upload_client=self.upload_client,
                            download_client=self.transfer_client,
                            need_upload=need_upload,
                            need_download=need_download,
                            ttl_seconds=30,
                            renewal_interval_seconds=5,
                        )

                    self.coordinator = FencedSyncCoordinator(
                        root, peer, share, remote,
                        selected.manifest_port,
                        selected.transfer_port,
                        manifest_client=self.manifest_client,
                        transfer_sender=self.transfer_client,
                        shared_state=self.shared_state,
                        session_factory=make_session,
                    )
                    self.baseline = BaselineCoordinator(
                        root, peer, share, remote,
                        selected.agreement_port,
                        agreement_client=self.agreement_client,
                        shared_state=self.shared_state,
                    )
                    self.lifecycle = SyncLifecycle(self.coordinator, self.baseline)
                    prefs = selected.preferences
                    self.sync_service = AutoSyncService(
                        self.lifecycle,
                        auto_apply=prefs.auto_apply,
                        poll_interval=prefs.poll_interval,
                        watch_interval=prefs.watch_interval,
                        settle_delay=prefs.settle_delay,
                        retry_initial=prefs.retry_initial,
                        retry_max=prefs.retry_max,
                    )

                    for listener in (
                        self.manifest_server,
                        self.agreement_server,
                        self.lease_server,
                        self.transfer_server,
                    ):
                        listener.start()
                        started.append(listener)

                    if background:
                        self.sync_service.start()
                        started.append(self.sync_service)

                self._running = True
                return self.status

            except BaseException:
                for service in reversed(started):
                    try:
                        service.stop()
                    except Exception:
                        pass
                self._clear()
                self._profile_lock.release()
                raise

    def stop(self) -> None:
        with self._guard:
            if not self._running:
                return

            if self.sync_service is not None:
                self.sync_service.stop(timeout=10)
                if self.sync_service.status.state is ServiceState.STOPPING:
                    raise StartupError(
                        "Background synchronization has not stopped; retry stop"
                    )

            for service in (
                self.transfer_server,
                self.lease_server,
                self.agreement_server,
                self.manifest_server,
            ):
                if service is not None:
                    service.stop()

            self._clear()
            self._profile_lock.release()
