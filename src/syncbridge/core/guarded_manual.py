
"""Opt-in, manual-only SyncBridge runtime with lease-guarded file transfers.

This runtime intentionally does not replace SyncBridgeRuntime yet. Both peers
must use this mode: mixing it with the legacy transfer listener fails closed.
No background auto-sync or unattended deletions. Baseline agreement is still
unfenced and a remote lease check is not atomic with filesystem publication.
Use test folders until the remaining protocols are hardened.
"""
from __future__ import annotations

import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from syncbridge.core.baseline import BaselineCoordinator
from syncbridge.core.coordinated_operations import CoordinatedOperations
from syncbridge.core.coordinator import SyncCoordinator
from syncbridge.core.lifecycle import SyncLifecycle
from syncbridge.network.agreement import AgreementClient, AgreementService
from syncbridge.network.guarded_transfer import GuardedTransferService
from syncbridge.network.lease_validation import (
    LeaseProof,
    LeaseValidationClient,
    LeaseValidationService,
    WriteAdmissionGate,
)
from syncbridge.network.manifest import ManifestService
from syncbridge.network.operation_lock import (
    DEFAULT_PORT as DEFAULT_LOCK_PORT,
    LeaseCoordinator,
    OperationLockClient,
    OperationLockService,
)
from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.network.transfer import TransferError
from syncbridge.runtime import StartupError, SyncBridgeRuntime
from syncbridge.storage.shared_state import SharedStateDatabase


class LeaseBoundTransferService(GuardedTransferService):
    """Supply the initiating thread's lease to the normal SyncCoordinator API.

    No explicit proof or active bound lease means fail closed. The listener
    itself still verifies the authenticated remote sender's proof independently.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._bound_lease = threading.local()

    @contextmanager
    def use_lease(self, proof: LeaseProof) -> Iterator[None]:
        if not isinstance(proof, LeaseProof):
            raise TypeError("A LeaseProof is required")
        if (
            proof.share_id != self.share_id
            or proof.owner_id != self.identity.node_id
            or proof.operation != "sync"
        ):
            raise TransferError(
                "[SB-OPS-403] Incorrect local transfer lease"
            )
        if getattr(self._bound_lease, "proof", None) is not None:
            raise TransferError("Nested transfer lease is not permitted")

        self._bound_lease.proof = proof
        try:
            yield
        finally:
            del self._bound_lease.proof

    def _current_proof(self) -> LeaseProof:
        proof = getattr(self._bound_lease, "proof", None)
        if proof is None:
            raise TransferError(
                "[SB-OPS-403] Start synchronization through "
                "the guarded operation runner"
            )
        return proof

    def send_file(self, *args, **kwargs):
        if "lease_proof" in kwargs:
            raise TransferError(
                "Use the current operation lease, not an ad-hoc proof"
            )
        return super().send_file(
            *args,
            lease_proof=self._current_proof(),
            **kwargs,
        )

    def fetch_file(self, *args, **kwargs):
        if "lease_proof" in kwargs:
            raise TransferError(
                "Use the current operation lease, not an ad-hoc proof"
            )
        return super().fetch_file(
            *args,
            lease_proof=self._current_proof(),
            **kwargs,
        )


class GuardedOperations(CoordinatedOperations):
    """Bind the elected lease to both upload and download calls."""

    def __init__(
        self,
        lifecycle,
        leases,
        sender: LeaseBoundTransferService,
    ):
        if lifecycle.coordinator.transfer_sender is not sender:
            raise ValueError(
                "Guarded sender must be the lifecycle's transfer service"
            )
        super().__init__(lifecycle, leases)
        self._sender = sender

    @contextmanager
    def _hold(self, operation: str):
        with super()._hold(operation) as guard:
            if operation == "sync":
                proof = LeaseProof(
                    self.leases.share_id,
                    self.leases.identity.node_id,
                    "sync",
                    guard.token,
                )
                with self._sender.use_lease(proof):
                    yield guard
            else:
                yield guard


class GuardedManualRuntime(SyncBridgeRuntime):
    """A separately opted-in runtime with no legacy write listener.

    Both devices must agree on lock_port and validation_port. On two real
    computers each may use the same defaults, since only the lower-node-ID
    authority binds those two ports. For localhost tests choose spare ports.

    start(background=True) and auto_apply are intentionally refused.
    sync_once() uses the authenticated lease runner; use preview() for a
    read-only plan. Do not use raw coordinator/lifecycle methods to write.
    """

    def __init__(
        self,
        *args,
        lock_port: int = DEFAULT_LOCK_PORT,
        validation_port: int = 45847,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)

        for label, value in (
            ("lock_port", lock_port),
            ("validation_port", validation_port),
        ):
            if (
                type(value) is not int
                or not 1 <= value <= 65535
            ):
                raise ValueError(
                    f"{label} must be a TCP port between 1 and 65535"
                )

        if lock_port == validation_port:
            raise ValueError(
                "Lock and validation ports must be different"
            )

        self.lock_port = lock_port
        self.validation_port = validation_port
        self.operation_authority = None
        self.validation_service = None
        self.leases = None
        self.operations = None

    def _reset_guarded(self):
        self.operation_authority = None
        self.validation_service = None
        self.leases = None
        self.operations = None

    def start(self, *, background: bool = False):
        if type(background) is not bool or background:
            raise StartupError(
                "Guarded mode only supports manual synchronization"
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
                        "Choose and enable one folder before starting"
                    )

                if selected.preferences.auto_apply:
                    raise StartupError(
                        "Turn off automatic synchronization "
                        "before using guarded manual mode"
                    )

                profile = self.config_store.path.parent

                self.identity = load_or_create_identity(
                    profile / "identity.json"
                )
                self.trust_store = TrustStore(
                    profile / "trust.json"
                )

                peer = selected.peer_node_id

                if self.trust_store.get(peer) is None:
                    raise StartupError(
                        "Configured peer has not been explicitly paired"
                    )

                self.config = config
                root = Path(selected.local_root).resolve(strict=True)
                share = selected.share_id
                host = selected.remote_host

                self.shared_state = SharedStateDatabase(
                    profile / "shared_state.sqlite"
                )

                ports = self.listen_ports or (
                    selected.manifest_port,
                    selected.transfer_port,
                    selected.agreement_port,
                )

                opts = {
                    "bind_address": self.bind_address,
                }

                authority_id = min(
                    self.identity.node_id,
                    peer,
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
                        listen_port=self.validation_port,
                        **opts,
                    )
                    self.validation_service.start()
                    started.append(self.validation_service)

                    gate = WriteAdmissionGate(
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
                    gate = WriteAdmissionGate(
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
                        ),
                    },
                    shared_state=self.shared_state,
                    listen_port=ports[0],
                    **opts,
                )

                self.transfer_server = LeaseBoundTransferService(
                    self.identity,
                    self.trust_store,
                    root,
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
                    admission=gate,
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
                        ),
                    },
                    listen_port=ports[2],
                    **opts,
                )

                self.manifest_client = ManifestService(
                    self.identity,
                    self.trust_store,
                    bind_address="127.0.0.1",
                    listen_port=0,
                )

                self.transfer_client = self.transfer_server

                self.agreement_client = AgreementClient(
                    self.identity,
                    self.trust_store,
                )

                self.coordinator = SyncCoordinator(
                    root,
                    peer,
                    share,
                    host,
                    selected.manifest_port,
                    selected.transfer_port,
                    manifest_client=self.manifest_client,
                    transfer_sender=self.transfer_client,
                    shared_state=self.shared_state,
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

                self.operations = GuardedOperations(
                    self.lifecycle,
                    self.leases,
                    self.transfer_server,
                )

                for listener in (
                    self.manifest_server,
                    self.transfer_server,
                    self.agreement_server,
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
                self._reset_guarded()
                self._profile_lock.release()
                raise

    def preview(self):
        with self._guard:
            if not self._running or self.operations is None:
                raise StartupError(
                    "Start the guarded runtime first"
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
                    "Start the guarded runtime first"
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
                self.agreement_server,
                self.transfer_server,
                self.manifest_server,
                self.validation_service,
                self.operation_authority,
            ):
                if service is not None:
                    service.stop()

            self._clear()
            self._reset_guarded()
            self._profile_lock.release()
