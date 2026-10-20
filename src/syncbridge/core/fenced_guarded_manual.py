
"""Opt-in manual SyncBridge runtime with operation-bound fenced publication.

The elected operation lease serializes cooperating sync initiators. Receiver-
issued fencing grants protect destination writes, and operation proofs are
validated again at final publication, including LOCAL downloads.

This combined runtime remains opt-in; Qt still uses the older guarded mode.
Only paired, approved shares are accepted. No automatic file changes.
Remote operation validation is not atomic with a local filesystem replace.
"""
from __future__ import annotations

import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from syncbridge.core.baseline import BaselineCoordinator
from syncbridge.core.coordinated_operations import CoordinatedOperations
from syncbridge.core.fenced_coordinator import (
    FencedCoordinatorTransfer,
    FencedSyncCoordinator,
)
from syncbridge.core.lifecycle import SyncLifecycle
from syncbridge.network.agreement import AgreementClient, AgreementService
from syncbridge.network.fenced_publish import FencedFilePublisher
from syncbridge.network.fenced_sync_session import FencedSyncSession
from syncbridge.network.fenced_transfer import FencedTransferClient
from syncbridge.network.lease_fencing import LeaseAuthority, LeaseGrant
from syncbridge.network.lease_validation import (
    LeaseProof,
    LeaseProofRejected,
    LeaseValidationClient,
    LeaseValidationService,
    WriteAdmissionGate,
)
from syncbridge.network.manifest import ManifestService
from syncbridge.network.operation_bound_duplex import (
    OperationBoundDuplexService,
)
from syncbridge.network.operation_bound_lease import (
    OperationBoundFencedLeaseClient,
    OperationBoundFencedLeaseService,
)
from syncbridge.network.operation_lock import (
    DEFAULT_PORT as DEFAULT_LOCK_PORT,
    LeaseCoordinator,
    OperationLockClient,
    OperationLockService,
)
from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.network.transfer import TransferError
from syncbridge.runtime import StartupError, SyncBridgeRuntime
from syncbridge.storage.config import ConfigStore
from syncbridge.storage.shared_state import SharedStateDatabase


class OperationBoundCoordinatorTransfer(FencedCoordinatorTransfer):
    """Require the elected sync operation when publishing local downloads."""

    def __init__(
        self,
        *args,
        admission: WriteAdmissionGate,
        **kwargs,
    ) -> None:
        if not isinstance(admission, WriteAdmissionGate):
            raise TypeError("A valid operation admission gate is required")

        super().__init__(*args, **kwargs)

        if admission.share_id != self.share_id:
            raise ValueError("Operation gate belongs to another share")

        self._admission = admission
        self._operation = threading.local()

        self.publisher = FencedFilePublisher(
            self.authority,
            self.share_id,
            self.destination_root,
            self._staging,
            before_publish=self._require_local_operation,
        )

    @contextmanager
    def use_operation(
        self,
        proof: LeaseProof,
    ) -> Iterator[None]:
        if not isinstance(proof, LeaseProof):
            raise TypeError("An elected sync operation proof is required")

        if (
            proof.share_id != self.share_id
            or proof.owner_id != self.identity.node_id
            or proof.operation != "sync"
        ):
            raise TransferError(
                "Operation proof does not match this device/share"
            )

        if getattr(self._operation, "proof", None) is not None:
            raise TransferError("Nested operation proof is not permitted")

        self._operation.proof = proof

        try:
            yield
        finally:
            del self._operation.proof

    def _require_local_operation(self, lease: LeaseGrant) -> None:
        proof = getattr(self._operation, "proof", None)

        if (
            proof is None
            or lease.share_id != self.share_id
            or lease.owner_node_id != self.identity.node_id
            or proof.share_id != lease.share_id
        ):
            raise LeaseProofRejected(
                "Local file publication requires a current elected sync operation"
            )

        self._admission.require(
            proof,
            authenticated_owner_id=self.identity.node_id,
        )


class OperationBoundManualOperations(CoordinatedOperations):
    """Bind elected ownership to remote grants and local publication."""

    def __init__(
        self,
        lifecycle: SyncLifecycle,
        leases: LeaseCoordinator,
        transfer: OperationBoundCoordinatorTransfer,
        lease_client: OperationBoundFencedLeaseClient,
    ) -> None:
        if lifecycle.coordinator.transfer_sender is not transfer:
            raise ValueError(
                "Operation transfer client differs from coordinator"
            )

        if leases.identity.node_id != lease_client.identity.node_id:
            raise ValueError(
                "Operation and fencing clients use different identities"
            )

        super().__init__(lifecycle, leases)

        self._transfer = transfer
        self._lease_client = lease_client

    @contextmanager
    def _hold(self, operation: str):
        with super()._hold(operation) as guard:
            if operation != "sync":
                yield guard
                return

            proof = LeaseProof(
                self.leases.share_id,
                self.leases.identity.node_id,
                "sync",
                guard.token,
            )

            with self._transfer.use_operation(proof):
                with self._lease_client.use_operation(proof):
                    yield guard


class FencedGuardedManualRuntime(SyncBridgeRuntime):
    """Manual runtime with operation-bound, receiver-fenced file writes.

    Separate computers use the same default lock, validation and lease
    ports. Localhost integration tests may supply independent local ports.

    This class is not yet the default Qt desktop runtime.
    """

    def __init__(
        self,
        config_store: ConfigStore | None = None,
        *,
        bind_address: str = "127.0.0.1",
        listen_ports: tuple[int, int, int] | None = None,
        lock_port: int = DEFAULT_LOCK_PORT,
        validation_port: int = 45847,
        lease_listen_port: int = 45849,
        remote_lease_port: int = 45849,
    ) -> None:
        super().__init__(
            config_store,
            bind_address=bind_address,
            listen_ports=listen_ports,
        )

        for label, port, minimum in (
            ("lock_port", lock_port, 1),
            ("validation_port", validation_port, 1),
            ("lease_listen_port", lease_listen_port, 0),
            ("remote_lease_port", remote_lease_port, 1),
        ):
            if type(port) is not int or not minimum <= port <= 65535:
                raise ValueError(f"Invalid {label}")

        if lock_port == validation_port:
            raise ValueError(
                "Operation and validation ports must differ"
            )

        self.lock_port = lock_port
        self.validation_port = validation_port
        self.lease_listen_port = lease_listen_port
        self.remote_lease_port = remote_lease_port

        self.operation_authority = None
        self.validation_service = None
        self.leases = None
        self.operations = None

        self.lease_authority = None
        self.lease_server = None
        self.lease_client = None
        self.upload_client = None
        self.admission = None

    def _clear(self) -> None:
        super()._clear()

        for field in (
            "operation_authority",
            "validation_service",
            "leases",
            "operations",
            "lease_authority",
            "lease_server",
            "lease_client",
            "upload_client",
            "admission",
        ):
            setattr(self, field, None)

    def start(self, *, background: bool = False):
        if type(background) is not bool or background:
            raise StartupError(
                "Operation-bound mode only supports manual synchronization"
            )

        with self._guard:
            if self._running:
                return self.status

            self._profile_lock.acquire()
            started = []

            try:
                config = self.config_store.load()
                selected = self._selected(config)

                if selected is None:
                    raise StartupError(
                        "Choose and enable a folder before starting"
                    )

                if selected.preferences.auto_apply:
                    raise StartupError(
                        "Disable automatic changes for guarded manual mode"
                    )

                profile = self.config_store.path.parent

                self.identity = load_or_create_identity(
                    profile / "identity.json"
                )

                self.trust_store = TrustStore(
                    profile / "trust.json"
                )

                if self.trust_store.get(selected.peer_node_id) is None:
                    raise StartupError(
                        "Configured peer has not been explicitly paired"
                    )

                self.config = config

                root = Path(selected.local_root).resolve(strict=True)
                share = selected.share_id
                peer = selected.peer_node_id
                host = selected.remote_host

                ports = self.listen_ports or (
                    selected.manifest_port,
                    selected.transfer_port,
                    selected.agreement_port,
                )

                opts = {
                    "bind_address": self.bind_address
                }

                authority_id = min(
                    self.identity.node_id,
                    peer,
                )

                self.shared_state = SharedStateDatabase(
                    profile / "shared_state.sqlite"
                )

                self.lease_authority = LeaseAuthority(
                    profile / "lease_fences.sqlite"
                )

                if authority_id == self.identity.node_id:
                    self.operation_authority = OperationLockService(
                        self.identity,
                        self.trust_store,
                        {share: peer},
                        listen_port=self.lock_port,
                        **opts,
                    )

                    self.operation_authority.start()
                    started.append(self.operation_authority)

                    self.validation_service = LeaseValidationService(
                        self.operation_authority,
                        bind_address=self.bind_address,
                        listen_port=self.validation_port,
                    )

                    self.validation_service.start()
                    started.append(self.validation_service)

                    self.admission = WriteAdmissionGate(
                        share,
                        authority_id,
                        peer,
                        local_validation=self.validation_service,
                    )

                    self.leases = LeaseCoordinator(
                        self.identity,
                        peer,
                        share,
                        local_service=self.operation_authority,
                    )

                else:
                    self.admission = WriteAdmissionGate(
                        share,
                        authority_id,
                        self.identity.node_id,
                        remote_validation=LeaseValidationClient(
                            self.identity,
                            self.trust_store,
                        ),
                        authority_host=host,
                        authority_port=self.validation_port,
                    )

                    self.leases = LeaseCoordinator(
                        self.identity,
                        peer,
                        share,
                        client=OperationLockClient(
                            self.identity,
                            self.trust_store,
                        ),
                        host=host,
                        port=self.lock_port,
                    )

                self.manifest_server = ManifestService(
                    self.identity,
                    self.trust_store,
                    {share: root},
                    allowed_readers={
                        share: (
                            [peer]
                            if selected.grant_manifest
                            else []
                        )
                    },
                    shared_state=self.shared_state,
                    listen_port=ports[0],
                    **opts,
                )

                self.agreement_server = AgreementService(
                    self.identity,
                    self.trust_store,
                    self.shared_state,
                    {share: root},
                    allowed_peers={
                        share: (
                            [peer]
                            if selected.grant_agreement
                            else []
                        )
                    },
                    listen_port=ports[2],
                    **opts,
                )

                self.lease_server = OperationBoundFencedLeaseService(
                    self.identity,
                    self.trust_store,
                    self.config_store,
                    self.lease_authority,
                    admission=self.admission,
                    bind_address=self.bind_address,
                    port=self.lease_listen_port,
                )

                self.transfer_server = OperationBoundDuplexService(
                    self.identity,
                    self.trust_store,
                    root,
                    authority=self.lease_authority,
                    operation_leases=self.lease_server,
                    share_id=share,
                    allowed_senders=(
                        [peer]
                        if selected.grant_write
                        else []
                    ),
                    allowed_readers=(
                        [peer]
                        if selected.grant_read
                        else []
                    ),
                    allow_overwrite=selected.grant_write,
                    listen_port=ports[1],
                    **opts,
                )

                self.manifest_client = ManifestService(
                    self.identity,
                    self.trust_store,
                    bind_address="127.0.0.1",
                    listen_port=0,
                )

                self.transfer_client = OperationBoundCoordinatorTransfer(
                    self.identity,
                    self.trust_store,
                    root,
                    authority=self.lease_authority,
                    admission=self.admission,
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

                self.lease_client = OperationBoundFencedLeaseClient(
                    self.identity,
                    self.trust_store,
                )

                self.agreement_client = AgreementClient(
                    self.identity,
                    self.trust_store,
                )

                def make_session(
                    *,
                    need_upload: bool,
                    need_download: bool,
                ):
                    return FencedSyncSession(
                        local_root=root,
                        share_id=share,
                        peer_node_id=peer,
                        remote_host=host,
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
                    root,
                    peer,
                    share,
                    host,
                    selected.manifest_port,
                    selected.transfer_port,
                    manifest_client=self.manifest_client,
                    transfer_sender=self.transfer_client,
                    shared_state=self.shared_state,
                    session_factory=make_session,
                )

                self.baseline = BaselineCoordinator(
                    root,
                    peer,
                    share,
                    host,
                    selected.agreement_port,
                    agreement_client=self.agreement_client,
                    shared_state=self.shared_state,
                )

                self.lifecycle = SyncLifecycle(
                    self.coordinator,
                    self.baseline,
                )

                self.operations = OperationBoundManualOperations(
                    self.lifecycle,
                    self.leases,
                    self.transfer_client,
                    self.lease_client,
                )

                for listener in (
                    self.manifest_server,
                    self.agreement_server,
                    self.lease_server,
                    self.transfer_server,
                ):
                    listener.start()
                    started.append(listener)

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

    def preview(self):
        with self._guard:
            if not self._running or self.operations is None:
                raise StartupError(
                    "Start SyncBridge before previewing folders"
                )

            return self.operations.preview()

    def sync_once(
        self,
        *,
        cancel_event=None,
        on_progress=None,
    ):
        with self._guard:
            if not self._running or self.operations is None:
                raise StartupError(
                    "Start SyncBridge before synchronizing"
                )

            return self.operations.sync_once(
                cancel_event=cancel_event,
                on_progress=on_progress,
            )

    def stop(self) -> None:
        with self._guard:
            if not self._running:
                return

            for service in (
                self.transfer_server,
                self.lease_server,
                self.agreement_server,
                self.manifest_server,
                self.validation_service,
                self.operation_authority,
            ):
                if service is not None:
                    service.stop()

            self._clear()
            self._profile_lock.release()
