
"""One encrypted endpoint for fenced uploads and authenticated file reads.

Only "fenced_offer" can publish a file. An authenticated "get" request may
read an explicitly approved share, but never writes to this computer.

Legacy "offer" requests are rejected. The final incoming file publication
continues to use FencedFilePublisher through FencedTransferService.

This service is not selected by SyncBridgeRuntime yet. That migration must
change the coordinator and listeners together, so no legacy write endpoint
remains active.

The local lease authority must be shared with this computer's authenticated
FencedLeaseService. Do not put its database inside a synchronized folder.
"""

from __future__ import annotations

import socket

from syncbridge.network.fenced_publish import PublishConflict
from syncbridge.network.fenced_transfer import (
    FencedTransferService,
    _FENCED_FIELDS,
)
from syncbridge.network.lease_fencing import (
    LeaseError,
    LeaseGrant,
)
from syncbridge.network.secure_channel import accept_secure_channel
from syncbridge.network.security import SecurityError
from syncbridge.network.transfer import (
    TransferError,
    _close,
    _expect,
    _read,
    _send,
)


_GET_FIELDS = {
    "share_id",
    "path",
    "expected_source_sha256",
    "expected_destination_sha256",
}


class FencedDuplexService(FencedTransferService):
    """A single-port, share-bound, authenticated transfer receiver.

    Incoming writes always require a receiver-issued lease. Incoming GET
    requests only expose files to peers with explicit read permission.
    """

    def _serve(self, sock: socket.socket) -> None:
        secure = None

        try:
            secure, peer = accept_secure_channel(
                sock,
                self.identity,
                self.trust_store,
                timeout=self.handshake_timeout,
            )

            secure.settimeout(self.io_timeout)

            request = _read(
                secure,
                {"fenced_offer", "offer", "get"},
            )

            kind = request["type"]

            if kind == "get":
                _expect(
                    request,
                    "get",
                    _GET_FIELDS,
                )

                self._verify_share(
                    request["share_id"]
                )

                self._check_permission(
                    peer.node_id,
                    secure.remote_public_key,
                    read=True,
                )

                # This existing method reads and sends bytes.
                # It does not publish anything to this computer.
                self._send_source(
                    secure,
                    peer.node_id,
                    self.destination_root,
                    request["path"],
                    share_id=self.share_id,
                    expected_source=request[
                        "expected_source_sha256"
                    ],
                    expected_destination=request[
                        "expected_destination_sha256"
                    ],
                    outbound=False,
                )

            elif kind == "fenced_offer":
                _expect(
                    request,
                    "fenced_offer",
                    _FENCED_FIELDS,
                )

                self._verify_share(
                    request["share_id"]
                )

                self._check_permission(
                    peer.node_id,
                    secure.remote_public_key,
                )

                # The owner comes from the authenticated secure
                # channel. A client-provided owner is never trusted.
                lease = LeaseGrant(
                    share_id=self.share_id,
                    owner_node_id=peer.node_id,
                    session_token=request["lease_token"],
                    generation=request["lease_generation"],
                    expires_at=0.0,
                )

                # This is an early rejection check. The final,
                # authoritative check remains inside the fenced
                # publisher's SQLite write transaction.
                self.authority.assert_current(lease)

                self._receive_fenced(
                    secure,
                    peer.node_id,
                    request,
                    lease,
                )

            else:
                # In particular, a legacy "offer" is never
                # dispatched to TransferService._receive.
                raise TransferError(
                    "Unfenced uploads are not supported"
                )

        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            TransferError,
            SecurityError,
            LeaseError,
            PublishConflict,
        ) as exc:
            if secure is not None and not self._stop.is_set():
                try:
                    _send(
                        secure,
                        "error",
                        reason="Transfer request refused",
                    )
                except Exception:
                    pass

            if not self._stop.is_set():
                self._report(exc)

        finally:
            _close(sock)

            with self._lock:
                self._connections.discard(sock)
