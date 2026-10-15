
"""Opt-in authenticated, lease-checked file transfer protocol.

Unlike the legacy TransferService, both offer and get messages MUST carry a
current share-scoped sync lease. This class rejects unguarded connections.
The authenticated requesting peer must own that lease. Pushes are checked on
receipt; pulls are checked when requested and at local file publication.

Reuse the base class's resumable staging, hashing and conditional publishing.
The last precondition check verifies lease currency immediately before the
base-class publication logic, but this does not make verification and rename
atomic. This is a receiver-side enforcement prototype, NOT complete fencing.
Never enable unattended deletion or claim protection from arbitrary local
writers on the strength of this implementation.
"""
from __future__ import annotations

import os
import stat
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from syncbridge.network.lease_validation import (
    LeaseProof,
    LeaseProofError,
    WriteAdmissionGate,
)
from syncbridge.network.security import SecurityError
from syncbridge.network.transfer import (
    TransferError,
    TransferResult,
    TransferService,
    _MAX_SIZE,
    _child,
    _close,
    _expect,
    _hash_file,
    _identity,
    _path,
    _read,
    _reply,
    _same_stat,
    _send,
    _sha,
)


def _wire(proof: LeaseProof) -> dict:
    if not isinstance(proof, LeaseProof):
        raise TypeError("A current LeaseProof is required")

    if proof.operation != "sync":
        raise TransferError(
            "[SB-OPS-403] A sync lease is required for file transfers"
        )

    return {
        "share_id": proof.share_id,
        "owner_id": proof.owner_id,
        "operation": proof.operation,
        "token": proof.token,
    }


def _unwire(value) -> LeaseProof:
    if not isinstance(value, dict) or set(value) != {
        "share_id",
        "owner_id",
        "operation",
        "token",
    }:
        raise TransferError(
            "[SB-OPS-403] Transfer has no valid lease proof"
        )

    try:
        proof = LeaseProof(**value)
    except (TypeError, ValueError) as exc:
        raise TransferError(
            "[SB-OPS-403] Transfer has an invalid lease proof"
        ) from exc

    _wire(proof)
    return proof


class GuardedTransferService(TransferService):
    """Strict, opt-in lease-aware replacement for a share-bound receiver.

    Instantiate on BOTH peers with a WriteAdmissionGate appropriate for that
    device (local validator on authority, remote validator on follower).
    Use send_file(..., lease_proof=proof) and fetch_file(..., lease_proof=proof).
    A plain TransferService client cannot push into this listener.
    """

    def __init__(
        self,
        *args,
        admission: WriteAdmissionGate,
        **kwargs,
    ):
        if not isinstance(admission, WriteAdmissionGate):
            raise TypeError("admission must be WriteAdmissionGate")

        super().__init__(*args, **kwargs)

        if (
            self.share_id is None
            or admission.share_id != self.share_id
        ):
            raise ValueError(
                "Guarded transfers require the matching share ID"
            )

        if self.identity.node_id not in (
            admission.authority_id,
            admission.peer_id,
        ):
            raise ValueError(
                "Admission gate does not describe this device"
            )

        if self.identity.node_id == admission.authority_id:
            if admission.local_validation is None:
                raise ValueError(
                    "Lease authority needs local validation"
                )
        elif admission.remote_validation is None:
            raise ValueError(
                "Non-authority device needs remote validation"
            )

        self.admission = admission
        self._active_proof = threading.local()

    @contextmanager
    def _proof(
        self,
        proof: LeaseProof,
    ) -> Iterator[None]:
        if getattr(
            self._active_proof,
            "value",
            None,
        ) is not None:
            raise TransferError(
                "Nested guarded transfer is not supported"
            )

        self._active_proof.value = proof

        try:
            yield
        finally:
            del self._active_proof.value

    def _require(
        self,
        *,
        owner: str,
    ) -> LeaseProof:
        proof = getattr(
            self._active_proof,
            "value",
            None,
        )

        if proof is None:
            raise TransferError(
                "[SB-OPS-403] Transfer requires a valid lease"
            )

        try:
            self.admission.require(
                proof,
                authenticated_owner_id=owner,
            )
        except LeaseProofError as exc:
            raise TransferError(
                "[SB-OPS-409] Coordination permission is "
                "invalid or unavailable"
            ) from exc

        return proof

    def _precondition(
        self,
        target,
        size,
        digest,
        expected,
        *,
        strict,
    ):
        # Called by the underlying receiver both BEFORE staging and
        # just BEFORE final publication. Fail closed in either case.

        proof = getattr(
            self._active_proof,
            "value",
            None,
        )

        if proof is None:
            raise TransferError(
                "[SB-OPS-403] Transfer has no lease"
            )

        self._require(owner=proof.owner_id)

        result = super()._precondition(
            target,
            size,
            digest,
            expected,
            strict=strict,
        )

        self._require(owner=proof.owner_id)
        return result

    def _serve(self, sock):
        secure = None

        try:
            from syncbridge.network.secure_channel import (
                accept_secure_channel,
            )

            secure, peer = accept_secure_channel(
                sock,
                self.identity,
                self.trust_store,
                timeout=self.handshake_timeout,
            )

            secure.settimeout(self.io_timeout)
            message = _read(secure, {"offer", "get"})

            if message["type"] == "offer":
                _expect(
                    message,
                    "offer",
                    {
                        "path",
                        "size",
                        "sha256",
                        "share_id",
                        "expected_destination_sha256",
                        "lease_proof",
                    },
                )

                self._verify_share(message["share_id"])
                self._check_permission(
                    peer.node_id,
                    secure.remote_public_key,
                )

                proof = _unwire(
                    message.pop("lease_proof")
                )

                if proof.owner_id != peer.node_id:
                    raise TransferError(
                        "[SB-OPS-403] Sender does not own this lease"
                    )

                with self._proof(proof):
                    self._require(owner=peer.node_id)

                    self._receive(
                        secure,
                        peer.node_id,
                        message,
                        outbound=False,
                    )

            else:
                _expect(
                    message,
                    "get",
                    {
                        "share_id",
                        "path",
                        "expected_source_sha256",
                        "expected_destination_sha256",
                        "lease_proof",
                    },
                )

                self._verify_share(message["share_id"])

                self._check_permission(
                    peer.node_id,
                    secure.remote_public_key,
                    read=True,
                )

                proof = _unwire(
                    message["lease_proof"]
                )

                if proof.owner_id != peer.node_id:
                    raise TransferError(
                        "[SB-OPS-403] Reader does not own this lease"
                    )

                with self._proof(proof):
                    self._require(owner=peer.node_id)

                    self._send_source(
                        secure,
                        peer.node_id,
                        self.destination_root,
                        message["path"],
                        share_id=self.share_id,
                        expected_source=message[
                            "expected_source_sha256"
                        ],
                        expected_destination=message[
                            "expected_destination_sha256"
                        ],
                        outbound=False,
                    )

        except (
            OSError,
            TransferError,
            SecurityError,
            ValueError,
            LeaseProofError,
        ) as exc:
            if (
                secure is not None
                and not self._stop.is_set()
            ):
                try:
                    # Never return the supplied lease token in an error.
                    _send(
                        secure,
                        "error",
                        reason=str(exc)[:256],
                    )
                except (OSError, TransferError):
                    pass

            if not self._stop.is_set():
                self._report(exc)

        finally:
            _close(sock)

            with self._lock:
                self._connections.discard(sock)

    def _send_source(
        self,
        secure,
        peer_id,
        root: Path,
        relative: str,
        *,
        share_id: str | None,
        expected_source: str | None,
        expected_destination: str | None,
        cancel_event=None,
        on_progress=None,
        outbound: bool,
    ) -> TransferResult:
        proof = getattr(
            self._active_proof,
            "value",
            None,
        )

        if (
            proof is None
            or share_id != self.share_id
        ):
            raise TransferError(
                "[SB-OPS-403] Share-bound sync lease required"
            )

        self._require(owner=proof.owner_id)

        segments = _path(relative)
        _sha(expected_source)
        _sha(expected_destination)

        source = _child(root, segments)

        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )

        try:
            fd = os.open(source, flags)
        except OSError as exc:
            raise TransferError(
                f"Cannot read source: {exc}"
            ) from exc

        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())

            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_size > _MAX_SIZE
            ):
                raise TransferError(
                    "Source must be a regular file of supported size"
                )

            digest = _hash_file(stream)

            if not _same_stat(
                before,
                os.fstat(stream.fileno()),
            ):
                raise TransferError(
                    "Source changed while hashing"
                )

            if (
                expected_source is not None
                and digest != expected_source
            ):
                raise TransferError(
                    "Source changed from expected SHA-256"
                )

            stream.seek(0)
            self._require(owner=proof.owner_id)

            _send(
                secure,
                "offer",
                path=relative,
                size=before.st_size,
                sha256=digest,
                share_id=share_id,
                expected_destination_sha256=expected_destination,
                lease_proof=_wire(proof),
            )

            return self._transmit(
                secure,
                peer_id,
                stream,
                before,
                digest,
                relative,
                cancel_event=cancel_event,
                on_progress=on_progress,
                outbound=outbound,
            )

    def send_file(
        self,
        host,
        port,
        expected_node_id,
        source_root,
        relative_path,
        *,
        lease_proof: LeaseProof,
        share_id=None,
        expected_destination_sha256=None,
        cancel_event=None,
        on_progress=None,
    ) -> TransferResult:
        _wire(lease_proof)

        if lease_proof.owner_id != self.identity.node_id:
            raise TransferError(
                "[SB-OPS-403] Only the lease owner may initiate a push"
            )

        if (
            share_id != self.share_id
            or lease_proof.share_id != share_id
        ):
            raise TransferError(
                "[SB-OPS-403] Wrong transfer share"
            )

        with self._proof(lease_proof):
            self._require(
                owner=self.identity.node_id
            )

            return super().send_file(
                host,
                port,
                expected_node_id,
                source_root,
                relative_path,
                share_id=share_id,
                expected_destination_sha256=(
                    expected_destination_sha256
                ),
                cancel_event=cancel_event,
                on_progress=on_progress,
            )

    def fetch_file(
        self,
        host,
        port,
        expected_node_id,
        share_id,
        relative_path,
        *,
        lease_proof: LeaseProof,
        expected_source_sha256=None,
        expected_destination_sha256=None,
        cancel_event=None,
        on_progress=None,
    ) -> TransferResult:
        _wire(lease_proof)

        if lease_proof.owner_id != self.identity.node_id:
            raise TransferError(
                "[SB-OPS-403] Only the lease owner may initiate a pull"
            )

        if (
            share_id != self.share_id
            or lease_proof.share_id != share_id
        ):
            raise TransferError(
                "[SB-OPS-403] Wrong transfer share"
            )

        _identity(share_id)
        _path(relative_path)
        _sha(expected_source_sha256)
        _sha(expected_destination_sha256)

        if (
            cancel_event is not None
            and not isinstance(cancel_event, threading.Event)
        ):
            raise TypeError(
                "cancel_event must be threading.Event"
            )

        if (
            on_progress is not None
            and not callable(on_progress)
        ):
            raise TypeError(
                "on_progress must be callable"
            )

        with self._proof(lease_proof):
            self._require(
                owner=self.identity.node_id
            )

            sock, secure, peer = self._connect(
                host,
                port,
                expected_node_id,
            )

            try:
                _send(
                    secure,
                    "get",
                    share_id=share_id,
                    path=relative_path,
                    expected_source_sha256=(
                        expected_source_sha256
                    ),
                    expected_destination_sha256=(
                        expected_destination_sha256
                    ),
                    lease_proof=_wire(lease_proof),
                )

                offer = _reply(
                    _read(
                        secure,
                        {"offer", "error"},
                    ),
                    "offer",
                )

                _expect(
                    offer,
                    "offer",
                    {
                        "share_id",
                        "path",
                        "size",
                        "sha256",
                        "expected_destination_sha256",
                        "lease_proof",
                    },
                )

                if (
                    offer["share_id"] != share_id
                    or offer["path"] != relative_path
                    or offer[
                        "expected_destination_sha256"
                    ] != expected_destination_sha256
                    or (
                        expected_source_sha256 is not None
                        and offer["sha256"]
                        != expected_source_sha256
                    )
                    or _unwire(
                        offer.pop("lease_proof")
                    ) != lease_proof
                ):
                    raise TransferError(
                        "Remote offer differs from the "
                        "authorized request"
                    )

                self._require(
                    owner=self.identity.node_id
                )

                return self._receive(
                    secure,
                    peer.node_id,
                    offer,
                    outbound=True,
                    cancel_event=cancel_event,
                    on_progress=on_progress,
                )

            finally:
                _close(sock)
