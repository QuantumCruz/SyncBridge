
"""Manual-only, distributed-lock-guarded, fenced synchronization runtime.

Combines the existing elected operation-lock coordinator with the opt-in
receiver-fenced transfer runtime.

All ordinary manual changes must enter through sync_once(). A local preview
uses preview() and never acquires a write lease.

This is an integration-stage runtime, not yet the Qt desktop default.

SECURITY LIMIT: the receiver's FencedLeaseService currently issues a fencing
lease based on trusted share permissions, without requiring proof of the
elected operation lock. An external authenticated, approved writer could
therefore bypass this class's cooperative operation gate. Before desktop
migration, bind receiver-side lease issuance and publication to the elected
operation authorization; do not claim the combined protocol is fully enforced.
"""

from __future__ import annotations

from syncbridge.core.coordinated_operations import CoordinatedOperations
from syncbridge.network.operation_lock import (
    DEFAULT_PORT as DEFAULT_LOCK_PORT,
    LeaseCoordinator,
    OperationLockClient,
    OperationLockService,
)
from syncbridge.runtime import StartupError
from syncbridge.runtime_fenced import FencedSyncBridgeRuntime


class FencedGuardedManualRuntime(FencedSyncBridgeRuntime):
    """Manual synchronization with both operation locking and file fencing."""

    def __init__(
        self,
        *args,
        lock_port: int = DEFAULT_LOCK_PORT,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)

        if type(lock_port) is not int or not 1 <= lock_port <= 65535:
            raise ValueError(
                "lock_port must be a TCP port between 1 and 65535"
            )

        self.lock_port = lock_port
        self.operation_authority: OperationLockService | None = None
        self.leases: LeaseCoordinator | None = None
        self.operations: CoordinatedOperations | None = None

    def _clear(self) -> None:
        super()._clear()
        self.operation_authority = None
        self.leases = None
        self.operations = None

    def start(self, *, background: bool = False):
        """Start a manual-only runtime, rolling back if locking cannot start."""
        if type(background) is not bool or background:
            raise StartupError(
                "This SyncBridge mode only supports manual synchronization"
            )

        with self._guard:
            if self._running:
                return self.status

            settings = self.config_store.load()
            selected = self._selected(settings)

            if selected is None:
                raise StartupError(
                    "Choose and enable one folder before starting SyncBridge"
                )

            if selected.preferences.auto_apply:
                raise StartupError(
                    "Automatic file changes must be disabled for manual mode"
                )

            # The fenced base owns the profile lock, encrypted transfer
            # listener, lease authority, manifest and agreement services.
            super().start(background=False)

            try:
                if self.identity is None or self.trust_store is None:
                    raise StartupError(
                        "Device identity was not initialized"
                    )

                if self.lifecycle is None:
                    raise StartupError(
                        "Synchronization lifecycle was not initialized"
                    )

                peer = selected.peer_node_id
                share = selected.share_id
                authority_id = min(
                    self.identity.node_id,
                    peer,
                )

                if authority_id == self.identity.node_id:
                    authority = OperationLockService(
                        self.identity,
                        self.trust_store,
                        {share: peer},
                        bind_address=self.bind_address,
                        listen_port=self.lock_port,
                    )

                    # Store before starting so startup rollback can
                    # close it even if later initialization fails.
                    self.operation_authority = authority
                    authority.start()

                    self.leases = LeaseCoordinator(
                        self.identity,
                        peer,
                        share,
                        local_service=authority,
                    )

                else:
                    self.leases = LeaseCoordinator(
                        self.identity,
                        peer,
                        share,
                        client=OperationLockClient(
                            self.identity,
                            self.trust_store,
                        ),
                        host=selected.remote_host,
                        port=self.lock_port,
                    )

                self.operations = CoordinatedOperations(
                    self.lifecycle,
                    self.leases,
                )

                return self.status

            except BaseException:
                try:
                    if self.operation_authority is not None:
                        self.operation_authority.stop()
                finally:
                    super().stop()
                raise

    def preview(self):
        """Make a read-only plan without opening a write session."""
        with self._guard:
            if not self._running or self.operations is None:
                raise StartupError(
                    "Start SyncBridge before checking your folders"
                )

            return self.operations.preview()

    def sync_once(
        self,
        *,
        cancel_event=None,
        on_progress=None,
    ):
        """Run the existing lifecycle inside the elected operation lease.

        The lifecycle's coordinator separately obtains receiver-side fencing
        grants for actual file transfers.
        """
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
        """Stop elected coordination before retiring fenced listeners."""
        with self._guard:
            if not self._running:
                return

            if self.operation_authority is not None:
                self.operation_authority.stop()

            super().stop()
