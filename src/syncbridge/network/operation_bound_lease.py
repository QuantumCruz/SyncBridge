
"""Authenticated fencing grants bound to an elected SyncBridge operation lease.

This strict channel denies fencing grants without a currently valid elected
operation proof. Existing FencedLeaseService remains unchanged for its tests;
only runtimes explicitly choosing this service get this extra authorization.

A receiver must ALSO revalidate this binding at the final file-publication
boundary before claiming end-to-end operation fencing. This service alone
protects acquisition/renewal, not every later filesystem mutation.
"""
from __future__ import annotations

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
from syncbridge.network.lease_fencing import LeaseAuthority, LeaseGrant
from syncbridge.network.lease_validation import LeaseProof, WriteAdmissionGate
from syncbridge.network.secure_channel import accept_secure_channel
from syncbridge.network.share_setup import _id, _recv, _send


class OperationBoundFencedLeaseService(FencedLeaseService):
    """Issue grants only under a validated, elected sync operation.

    Binding records are intentionally process-local: after service restart,
    an old still-unexpired grant cannot be renewed through this channel.
    The forthcoming publish gate must likewise fail closed for absent bindings.
    """

    def __init__(self, *args, admission: WriteAdmissionGate, **kwargs) -> None:
        if not isinstance(admission, WriteAdmissionGate):
            raise TypeError("admission must be a WriteAdmissionGate")
        super().__init__(*args, **kwargs)
        self.admission = admission
        self._binding_lock = threading.RLock()
        self._bindings: dict[str, tuple[int, str, LeaseProof]] = {}

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
            bound[2], authenticated_owner_id=grant.owner_node_id,
        )

    def require_current_bound(self, grant: LeaseGrant) -> None:
        """Check both authorities; this does NOT reserve a later file write."""
        if self._stop.is_set():
            raise LeaseChannelError("Lease-control service is not running")
        self.authority.assert_current(grant)
        self._require_bound(grant)

    def _handle(self, sock: socket.socket, observed_host: str) -> None:
        secure = None
        try:
            sock.settimeout(_TIMEOUT)
            secure, authenticated = accept_secure_channel(
                sock, self.identity, self.trust, timeout=_TIMEOUT,
            )
            secure.settimeout(_TIMEOUT)
            kind, message = _recv(secure, {
                "acquire": {
                    "share_id", "ttl_seconds", "operation_token"
                },
                "renew": {
                    "share_id", "generation", "session_token",
                    "ttl_seconds", "operation_token"
                },
                "release": {
                    "share_id", "generation", "session_token"
                },
            })
            share_id = _id(message["share_id"])
            owner_id = authenticated.node_id
            self._require_writer(share_id, owner_id)
            if self._stop.is_set():
                raise LeaseChannelError("Lease listener is stopping")

            if kind == "acquire":
                proof = LeaseProof(
                    share_id, owner_id, "sync", message["operation_token"],
                )
                self.admission.require(
                    proof, authenticated_owner_id=owner_id
                )
                grant = self.authority.acquire(
                    share_id, owner_id, ttl_seconds=message["ttl_seconds"],
                )
                with self._binding_lock:
                    self._bindings[share_id] = (
                        grant.generation, grant.session_token, proof,
                    )
                # A lost operation cannot be converted into a usable fencing
                # token. Best-effort cleanup leaves no token with the client.
                try:
                    self._require_bound(grant)
                except Exception:
                    try:
                        self.authority.release(grant)
                    except Exception:
                        pass
                    with self._binding_lock:
                        self._bindings.pop(share_id, None)
                    raise
            else:
                claimed = LeaseGrant(
                    share_id, owner_id, message["session_token"],
                    message["generation"], 0.0,
                )
                if kind == "renew":
                    self._require_bound(claimed)
                    with self._binding_lock:
                        bound = self._bindings.get(share_id)
                    if (
                        bound is None
                        or message["operation_token"] != bound[2].token
                    ):
                        raise LeaseChannelError(
                            "Incorrect operation proof for renewal"
                        )
                    grant = self.authority.renew(
                        claimed, ttl_seconds=message["ttl_seconds"],
                    )
                    self._require_bound(grant)
                else:
                    self.authority.release(claimed)
                    with self._binding_lock:
                        bound = self._bindings.get(share_id)
                        if bound is not None and (
                            bound[0], bound[1]
                        ) == (claimed.generation, claimed.session_token):
                            del self._bindings[share_id]
                    grant = None

            self._require_writer(share_id, owner_id)
            if self._stop.is_set():
                raise LeaseChannelError("Lease listener is stopping")
            if grant is None:
                _send(secure, "released", share_id=share_id)
            else:
                _send(secure, "granted", **_grant_fields(grant))
        except Exception:
            if secure is not None and not self._stop.is_set():
                try:
                    _send(secure, "rejected")
                except Exception:
                    pass
        finally:
            with self._lock:
                self._sockets.discard(sock)
                self._workers.discard(threading.current_thread())
            if secure is not None:
                secure.close()
            sock.close()


class OperationBoundFencedLeaseClient(FencedLeaseClient):
    """Carry the held operation proof into acquisition and renewal.

    The acquisition proof is thread-bound; renewal runs on LeaseKeepAlive's
    worker and therefore reads the proof saved for that exact grant token.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._active = threading.local()
        self._lock = threading.Lock()
        self._proofs: dict[str, LeaseProof] = {}

    @contextmanager
    def use_operation(self, proof: LeaseProof) -> Iterator[None]:
        if not isinstance(proof, LeaseProof):
            raise TypeError("A valid elected operation proof is required")
        if (
            proof.owner_id != self.identity.node_id
            or proof.operation != "sync"
        ):
            raise LeaseChannelError(
                "Operation proof belongs to another device or operation"
            )
        if getattr(self._active, "proof", None) is not None:
            raise LeaseChannelError("Nested operation proof is not permitted")
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
            host, port, peer_id, "acquire",
            share_id=share_id,
            ttl_seconds=ttl_seconds,
            operation_token=proof.token,
        )
        if response != "granted":
            raise LeaseChannelError(
                "Invalid operation-bound lease response"
            )
        grant = _grant_from_reply(
            payload, self.identity.node_id, share_id
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
            raise LeaseChannelError("Lease belongs to another device")
        with self._lock:
            proof = self._proofs.get(grant.session_token)
        if proof is None or proof.share_id != grant.share_id:
            raise LeaseChannelError(
                "Renewal has no matching elected operation proof"
            )
        response, payload = self._request(
            host, port, peer_id, "renew",
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
            payload, self.identity.node_id, grant.share_id
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
            super().release(host, port, peer_id, grant)
        finally:
            with self._lock:
                self._proofs.pop(grant.session_token, None)
