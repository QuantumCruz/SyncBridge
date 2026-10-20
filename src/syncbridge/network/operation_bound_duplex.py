
"""Single-port fenced receiver with elected-operation validation.

Combines the authenticated read/fenced-write duplex endpoint with the strict
operation-bound lease channel.

The final elected-operation proof check runs from FencedFilePublisher while its
receiver-local SQLite fencing transaction is held. Remote operation authority
validation remains a point-in-time check, not a distributed atomic transaction.
"""
from __future__ import annotations

from syncbridge.network.fenced_duplex import FencedDuplexService
from syncbridge.network.fenced_publish import (
    FencedFilePublisher,
    PublishConflict,
)
from syncbridge.network.operation_bound_lease import (
    OperationBoundFencedLeaseService,
)


class OperationBoundDuplexService(FencedDuplexService):
    """Reject stale operation holders before encrypted file publication."""

    def __init__(
        self,
        *args,
        operation_leases: OperationBoundFencedLeaseService,
        **kwargs,
    ) -> None:
        if not isinstance(
            operation_leases,
            OperationBoundFencedLeaseService,
        ):
            raise TypeError(
                "operation_leases must be an operation-bound lease service"
            )

        super().__init__(*args, **kwargs)

        if (
            operation_leases.authority is not self.authority
            or operation_leases.identity.node_id
            != self.identity.node_id
            or operation_leases.admission.share_id
            != self.share_id
        ):
            raise ValueError(
                "Operation binding does not match this receiver and share"
            )

        self.operation_leases = operation_leases

        # Replace only the publication authority hook. The normal
        # path verification, encrypted streaming, and SHA-256 checks
        # remain those of the existing fenced transfer implementation.
        self.publisher = FencedFilePublisher(
            self.authority,
            self.share_id,
            self.destination_root,
            self._staging,
            before_publish=self._require_elected_operation,
        )

    def _require_elected_operation(self, lease) -> None:
        try:
            self.operation_leases.require_operation_bound(
                lease
            )

        except Exception as exc:
            # Fail closed without putting operation tokens,
            # database paths, or validation details on the wire.
            raise PublishConflict(
                "The elected synchronization operation is no longer authorized"
            ) from exc

    def _receive_fenced(
        self,
        secure,
        sender_id: str,
        offer: dict,
        lease,
    ):
        # Reject known-invalid operation authority before accepting
        # potentially large amounts of file data.
        self._require_elected_operation(lease)

        # The publisher independently calls the same check inside
        # its final receiver-local publication transaction.
        return super()._receive_fenced(
            secure,
            sender_id,
            offer,
            lease,
        )
