
"""Authenticated receiver fencing leases tied to elected sync operations.

A freshly validated elected operation can supersede an unexpired fencing
grant left behind by a crashed session. Takeover increments the durable
SQLite generation in a single receiver-local transaction.

An active fencing grant belonging to the SAME elected operation cannot be
taken over by a second acquisition.

The final file publisher must separately validate the current elected
operation. Remote operation validation remains a point-in-time observation,
not an atomic distributed filesystem transaction.
"""
from __future__ import annotations

import secrets
import socket
import threading
from contextlib import contextmanager
from typing import Iterator

from syncbridge.network.fenced_lease_channel import (
    FencedLeaseClient,
    FencedLeaseService,
    LeaseChannelError,
    _TIMEOUT,
    _grant_fields,
    _grant_from_reply,
)
from syncbridge.network.lease_fencing import (
    LeaseAuthority,
    LeaseBusy,
    LeaseError,
    LeaseGrant,
)
from syncbridge.network.lease_validation import (
    LeaseProof,
    WriteAdmissionGate,
)
from syncbridge.network.secure_channel import accept_secure_channel
from syncbridge.network.share_setup import _id, _recv, _send


_MAX_GENERATION = (1 << 63) - 1


class OperationBoundFencedLeaseService(FencedLeaseService):
    """Issue only receiver-owned fencing grants under elected authorization."""

    def __init__(
        self,
        *args,
        admission: WriteAdmissionGate,
        **kwargs,
    ) -> None:
        if not isinstance(admission, WriteAdmissionGate):
            raise TypeError(
                "admission must be a WriteAdmissionGate"
            )

        super().__init__(*args, **kwargs)

        self.admission = admission
        self._binding_lock = threading.RLock()

        # Serializes acquisitions from this listener. Unlike _binding_lock,
        # it is NEVER acquired by a file publisher while holding SQLite.
        self._acquire_lock = threading.Lock()

        self._bindings: dict[
            str,
            tuple[int, str, LeaseProof],
        ] = {}

    def start(self) -> None:
        if self._stop.is_set():
            with self._binding_lock:
                self._bindings.clear()

        super().start()

    def stop(self) -> None:
        super().stop()

        with self._binding_lock:
            self._bindings.clear()

    def _require_bound(self, grant: LeaseGrant) -> None:
        LeaseAuthority._valid_grant(grant)

        with self._binding_lock:
            bound = self._bindings.get(grant.share_id)

        if (
            bound is None
            or bound[0] != grant.generation
            or bound[1] != grant.session_token
            or bound[2].owner_id != grant.owner_node_id
        ):
            raise LeaseChannelError(
                "Grant does not belong to an authorized sync operation"
            )

        self.admission.require(
            bound[2],
            authenticated_owner_id=grant.owner_node_id,
        )

    def require_operation_bound(self, grant: LeaseGrant) -> None:
        """Require a current operation binding for a given fencing grant."""
        if self._stop.is_set():
            raise LeaseChannelError(
                "Lease-control service is not running"
            )

        self._require_bound(grant)

        if self._stop.is_set():
            raise LeaseChannelError(
                "Lease-control service stopped during validation"
            )

    def require_current_bound(self, grant: LeaseGrant) -> None:
        self.authority.assert_current(grant)
        self.require_operation_bound(grant)

    def _acquire_for_operation(
        self,
        share_id: str,
        owner_id: str,
        proof: LeaseProof,
        *,
        ttl_seconds: float,
    ) -> LeaseGrant:
        """Acquire or supersede an orphaned fencing generation.

        This is called ONLY after authenticating the peer and verifying the
        new elected-operation proof through WriteAdmissionGate.

        SQLite serialization prevents an old generation from publishing
        concurrently with the generation replacement.

        _acquire_lock serializes other acquisitions in this service. We
        never hold _binding_lock while waiting for the SQLite write lock,
        avoiding lock inversion with FencedFilePublisher.
        """
        with self._acquire_lock:
            try:
                grant = self.authority.acquire(
                    share_id,
                    owner_id,
                    ttl_seconds=ttl_seconds,
                )

            except LeaseBusy:
                with self.authority._write() as connection:
                    now = self.authority._now()
                    row = self.authority._row(
                        connection,
                        share_id,
                    )

                    self.authority._check_clock(row, now)

                    if row is None:
                        raise LeaseError(
                            "Fencing state disappeared during recovery"
                        )

                    previous_generation = row[0]
                    previous_owner = row[1]
                    previous_token = row[2]
                    previous_expiry = row[3]

                    if (
                        previous_expiry is not None
                        and now < previous_expiry
                    ):
                        # Lock order is SQLite -> _binding_lock.
                        # The fenced publisher uses the same order.
                        with self._binding_lock:
                            bound = self._bindings.get(
                                share_id
                            )

                        if (
                            bound is not None
                            and bound[0] == previous_generation
                            and bound[1] == previous_token
                            and bound[2].owner_id == previous_owner
                            and bound[2].token == proof.token
                        ):
                            raise LeaseBusy(
                                "This operation already holds a fencing lease"
                            )

                        # The elected authority has validated a DIFFERENT
                        # operation, or the old binding disappeared with
                        # a receiver restart. The old generation cannot
                        # survive replacement, and a missing binding
                        # cannot authorize publication.

                    generation = previous_generation + 1

                    if generation > _MAX_GENERATION:
                        raise LeaseError(
                            "Fencing generation counter exhausted"
                        )

                    token = secrets.token_hex(32)
                    expires_at = now + float(ttl_seconds)

                    connection.execute(
                        """UPDATE lease_fences
                           SET generation = ?,
                               owner_node_id = ?,
                               session_token = ?,
                               expires_at = ?,
                               observed_at = ?
                           WHERE share_id = ?""",
                        (
                            generation,
                            owner_id,
                            token,
                            expires_at,
                            now,
                            share_id,
                        ),
                    )

                    grant = LeaseGrant(
                        share_id,
                        owner_id,
                        token,
                        generation,
                        expires_at,
                    )

            with self._binding_lock:
                self._bindings[share_id] = (
                    grant.generation,
                    grant.session_token,
                    proof,
                )

            return grant

    def _handle(
        self,
        sock: socket.socket,
        observed_host: str,
    ) -> None:
        secure = None

        try:
            sock.settimeout(_TIMEOUT)

            secure, authenticated = accept_secure_channel(
                sock,
                self.identity,
                self.trust,
                timeout=_TIMEOUT,
            )

            secure.settimeout(_TIMEOUT)

            kind, message = _recv(
                secure,
                {
                    "acquire": {
                        "share_id",
                        "ttl_seconds",
                        "operation_token",
                    },
                    "renew": {
                        "share_id",
                        "generation",
                        "session_token",
                        "ttl_seconds",
                        "operation_token",
                    },
                    "release": {
                        "share_id",
                        "generation",
                        "session_token",
                    },
                },
            )

            share_id = _id(message["share_id"])
            owner_id = authenticated.node_id

            self._require_writer(
                share_id,
                owner_id,
            )

            if self._stop.is_set():
                raise LeaseChannelError(
                    "Lease listener is stopping"
                )

            if kind == "acquire":
                proof = LeaseProof(
                    share_id,
                    owner_id,
                    "sync",
                    message["operation_token"],
                )

                # Check authorization BEFORE a takeover.
                self.admission.require(
                    proof,
                    authenticated_owner_id=owner_id,
                )

                grant = self._acquire_for_operation(
                    share_id,
                    owner_id,
                    proof,
                    ttl_seconds=message["ttl_seconds"],
                )

                try:
                    # Recheck after allocation. If the elected operation
                    # disappeared during acquisition, revoke this grant.
                    self.require_current_bound(grant)

                except Exception:
                    try:
                        self.authority.release(grant)
                    except Exception:
                        pass

                    with self._binding_lock:
                        bound = self._bindings.get(share_id)

                        if (
                            bound is not None
                            and (
                                bound[0],
                                bound[1],
                            ) == (
                                grant.generation,
                                grant.session_token,
                            )
                        ):
                            del self._bindings[share_id]

                    raise

            else:
                claimed = LeaseGrant(
                    share_id,
                    owner_id,
                    message["session_token"],
                    message["generation"],
                    0.0,
                )

                if kind == "renew":
                    self.require_current_bound(claimed)

                    with self._binding_lock:
                        bound = self._bindings.get(share_id)

                    if (
                        bound is None
                        or message["operation_token"]
                        != bound[2].token
                    ):
                        raise LeaseChannelError(
                            "Incorrect operation proof for renewal"
                        )

                    grant = self.authority.renew(
                        claimed,
                        ttl_seconds=message["ttl_seconds"],
                    )

                    self.require_current_bound(grant)

                else:
                    # Old generation holders cannot release a successor.
                    self.authority.release(claimed)

                    with self._binding_lock:
                        bound = self._bindings.get(share_id)

                        if (
                            bound is not None
                            and (
                                bound[0],
                                bound[1],
                            ) == (
                                claimed.generation,
                                claimed.session_token,
                            )
                        ):
                            del self._bindings[share_id]

                    grant = None

            self._require_writer(
                share_id,
                owner_id,
            )

            if self._stop.is_set():
                raise LeaseChannelError(
                    "Lease listener is stopping"
                )

            if grant is None:
                _send(
                    secure,
                    "released",
                    share_id=share_id,
                )
            else:
                _send(
                    secure,
                    "granted",
                    **_grant_fields(grant),
                )

        except Exception:
            if secure is not None and not self._stop.is_set():
                try:
                    _send(secure, "rejected")
                except Exception:
                    pass

        finally:
            with self._lock:
                self._sockets.discard(sock)
                self._workers.discard(
                    threading.current_thread()
                )

            if secure is not None:
                secure.close()

            sock.close()


class OperationBoundFencedLeaseClient(FencedLeaseClient):
    """Preserve elected proof identity across authenticated renewals."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._active = threading.local()
        self._lock = threading.Lock()
        self._proofs: dict[str, LeaseProof] = {}

    @contextmanager
    def use_operation(
        self,
        proof: LeaseProof,
    ) -> Iterator[None]:
        if not isinstance(proof, LeaseProof):
            raise TypeError(
                "A valid elected operation proof is required"
            )

        if (
            proof.owner_id != self.identity.node_id
            or proof.operation != "sync"
        ):
            raise LeaseChannelError(
                "Operation proof belongs to another device or operation"
            )

        if getattr(
            self._active,
            "proof",
            None,
        ) is not None:
            raise LeaseChannelError(
                "Nested operation proof is not permitted"
            )

        self._active.proof = proof

        try:
            yield
        finally:
            del self._active.proof

    def acquire(
        self,
        host: str,
        port: int,
        peer_id: str,
        share_id: str,
        *,
        ttl_seconds: float = 30.0,
    ) -> LeaseGrant:
        share_id = _id(share_id)
        proof = getattr(self._active, "proof", None)

        if proof is None or proof.share_id != share_id:
            raise LeaseChannelError(
                "Acquire requires the active elected operation proof"
            )

        response, payload = self._request(
            host,
            port,
            peer_id,
            "acquire",
            share_id=share_id,
            ttl_seconds=ttl_seconds,
            operation_token=proof.token,
        )

        if response != "granted":
            raise LeaseChannelError(
                "Invalid operation-bound lease response"
            )

        grant = _grant_from_reply(
            payload,
            self.identity.node_id,
            share_id,
        )

        with self._lock:
            self._proofs[grant.session_token] = proof

        return grant

    def renew(
        self,
        host: str,
        port: int,
        peer_id: str,
        grant: LeaseGrant,
        *,
        ttl_seconds: float = 30.0,
    ) -> LeaseGrant:
        LeaseAuthority._valid_grant(grant)

        if grant.owner_node_id != self.identity.node_id:
            raise LeaseChannelError(
                "Lease belongs to another device"
            )

        with self._lock:
            proof = self._proofs.get(grant.session_token)

        if proof is None or proof.share_id != grant.share_id:
            raise LeaseChannelError(
                "Renewal has no matching elected operation proof"
            )

        response, payload = self._request(
            host,
            port,
            peer_id,
            "renew",
            share_id=grant.share_id,
            generation=grant.generation,
            session_token=grant.session_token,
            ttl_seconds=ttl_seconds,
            operation_token=proof.token,
        )

        if response != "granted":
            raise LeaseChannelError(
                "Invalid operation-bound renewal response"
            )

        renewed = _grant_from_reply(
            payload,
            self.identity.node_id,
            grant.share_id,
        )

        if (
            renewed.generation != grant.generation
            or renewed.session_token != grant.session_token
        ):
            raise LeaseChannelError(
                "Lease identity changed during renewal"
            )

        return renewed

    def release(
        self,
        host: str,
        port: int,
        peer_id: str,
        grant: LeaseGrant,
    ) -> None:
        try:
            super().release(
                host,
                port,
                peer_id,
                grant,
            )

        finally:
            with self._lock:
                self._proofs.pop(
                    grant.session_token,
                    None,
                )
