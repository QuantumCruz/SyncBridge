
"""Authenticated lease-control channel for a future fenced transfer receiver.

This endpoint only issues/renews/releases receiver-owned fencing grants. It does
NOT authorize or publish files, and is not enabled by the desktop runtime yet.
No lease owner is accepted from a network request: the secure handshake's peer
identity supplies it. Each request rechecks the receiver's share permissions.
"""
from __future__ import annotations

import math
import socket
import threading

from syncbridge.network.lease_fencing import LeaseAuthority, LeaseGrant
from syncbridge.network.secure_channel import accept_secure_channel, open_secure_channel
from syncbridge.network.security import DeviceIdentity, SecurityError, TrustStore
from syncbridge.network.share_setup import ShareSetupError, ShareSetupService, _host, _id, _recv, _send
from syncbridge.storage.config import ConfigStore


class LeaseChannelError(RuntimeError):
    """An authenticated remote lease request could not be completed."""


LEASE_CHANNEL_PORT = 45849
_TIMEOUT = 8.0


def _port(value: int, *, listening: bool = False) -> int:
    if type(value) is not int or not (0 if listening else 1) <= value <= 65535:
        raise ValueError("Invalid lease-control port")
    return value


def _grant_fields(grant: LeaseGrant) -> dict:
    return {
        "share_id": grant.share_id,
        "generation": grant.generation,
        "session_token": grant.session_token,
        "expires_at": grant.expires_at,
    }


def _grant_from_reply(payload: dict, owner_id: str, expected_share: str) -> LeaseGrant:
    if payload["share_id"] != expected_share:
        raise LeaseChannelError("Incorrect lease share in response")
    lease = LeaseGrant(
        share_id=expected_share,
        owner_node_id=owner_id,
        session_token=payload["session_token"],
        generation=payload["generation"],
        expires_at=payload["expires_at"],
    )
    LeaseAuthority._valid_grant(lease)
    if type(lease.expires_at) not in (float, int) or not math.isfinite(lease.expires_at):
        raise LeaseChannelError("Invalid lease expiry in response")
    return lease


class FencedLeaseService(ShareSetupService):
    """Receiver-controlled secure lease endpoint, disabled until explicitly started.

    Only a trusted, approved remote writer to an enabled share can request a
    lease. This class never trusts client-specified owner IDs. Normal file
    transfers remain unchanged until explicitly integrated with the publisher.
    """

    def __init__(
        self,
        identity: DeviceIdentity,
        trust: TrustStore,
        store: ConfigStore,
        authority: LeaseAuthority,
        *,
        bind_address: str = "127.0.0.1",
        port: int = LEASE_CHANNEL_PORT,
    ) -> None:
        if not isinstance(authority, LeaseAuthority):
            raise TypeError("authority must be LeaseAuthority")
        super().__init__(
            identity, trust, store, bind_address=bind_address,
            port=_port(port, listening=True), approval_timeout=_TIMEOUT,
        )
        self.authority = authority

    def _require_writer(self, share_id: str, authenticated_peer_id: str) -> None:
        share = self.store.load().get_share(_id(share_id))
        if (
            share is None
            or share.peer_node_id != authenticated_peer_id
            or not share.enabled
            or not share.grant_write
            or self.trust.get(authenticated_peer_id) is None
        ):
            raise LeaseChannelError("No approved write access to this folder")

    def _handle(self, sock: socket.socket, observed_host: str) -> None:
        secure = None
        try:
            sock.settimeout(_TIMEOUT)
            secure, authenticated = accept_secure_channel(
                sock, self.identity, self.trust, timeout=_TIMEOUT,
            )
            secure.settimeout(_TIMEOUT)
            kind, message = _recv(secure, {
                "acquire": {"share_id", "ttl_seconds"},
                "renew": {"share_id", "generation", "session_token", "ttl_seconds"},
                "release": {"share_id", "generation", "session_token"},
            })
            share_id = _id(message["share_id"])
            peer_id = authenticated.node_id
            self._require_writer(share_id, peer_id)
            if self._stop.is_set():
                raise LeaseChannelError("Lease listener is stopping")

            if kind == "acquire":
                grant = self.authority.acquire(
                    share_id, peer_id, ttl_seconds=message["ttl_seconds"],
                )
            else:
                # The server derives owner_node_id from the authenticated
                # connection, not from client-supplied JSON.
                claimed = LeaseGrant(
                    share_id, peer_id, message["session_token"],
                    message["generation"], 0.0,
                )
                if kind == "renew":
                    grant = self.authority.renew(
                        claimed, ttl_seconds=message["ttl_seconds"],
                    )
                else:
                    self.authority.release(claimed)
                    grant = None

            # Recheck permissions before responding. An interim revoke
            # must not be presented as successful authorization.
            self._require_writer(share_id, peer_id)
            if self._stop.is_set():
                raise LeaseChannelError("Lease listener is stopping")
            if grant is None:
                _send(secure, "released", share_id=share_id)
            else:
                _send(secure, "granted", **_grant_fields(grant))

        except Exception:
            # Avoid exposing tokens, database exceptions or private profile
            # paths in remotely visible errors.
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


class FencedLeaseClient:
    """Request a receiver-issued grant from an explicitly trusted peer."""

    def __init__(self, identity: DeviceIdentity, trust: TrustStore) -> None:
        if not isinstance(identity, DeviceIdentity) or not isinstance(trust, TrustStore):
            raise TypeError("Device identity and trust store required")
        self.identity = identity
        self.trust = trust

    def _request(
        self, host: str, port: int, peer_id: str, kind: str, **fields,
    ) -> tuple[str, dict]:
        host = _host(host)
        port = _port(port)
        peer_id = _id(peer_id)
        if peer_id == self.identity.node_id or self.trust.get(peer_id) is None:
            raise LeaseChannelError("Remote device is not trusted")
        try:
            with socket.create_connection((host, port), timeout=_TIMEOUT) as sock:
                secure, authenticated = open_secure_channel(
                    sock, self.identity, self.trust, peer_id, timeout=_TIMEOUT,
                )
                try:
                    if authenticated.node_id != peer_id:
                        raise LeaseChannelError("Remote device identity changed")
                    secure.settimeout(_TIMEOUT)
                    _send(secure, kind, **fields)
                    response, payload = _recv(secure, {
                        "granted": {"share_id", "generation", "session_token", "expires_at"},
                        "released": {"share_id"},
                        "rejected": set(),
                    })
                finally:
                    secure.close()
        except (OSError, SecurityError, ShareSetupError) as exc:
            raise LeaseChannelError("Secure lease request failed") from exc
        if response == "rejected":
            raise LeaseChannelError("Lease request rejected by other computer")
        return response, payload

    def acquire(
        self, host: str, port: int, peer_id: str, share_id: str, *, ttl_seconds: float = 30.0,
    ) -> LeaseGrant:
        share_id = _id(share_id)
        response, payload = self._request(
            host, port, peer_id, "acquire", share_id=share_id,
            ttl_seconds=ttl_seconds,
        )
        if response != "granted":
            raise LeaseChannelError("Invalid lease acquisition response")
        return _grant_from_reply(payload, self.identity.node_id, share_id)

    def renew(
        self, host: str, port: int, peer_id: str, grant: LeaseGrant, *, ttl_seconds: float = 30.0,
    ) -> LeaseGrant:
        LeaseAuthority._valid_grant(grant)
        if grant.owner_node_id != self.identity.node_id:
            raise LeaseChannelError("Lease belongs to another device")
        response, payload = self._request(
            host, port, peer_id, "renew", share_id=grant.share_id,
            generation=grant.generation, session_token=grant.session_token,
            ttl_seconds=ttl_seconds,
        )
        if response != "granted":
            raise LeaseChannelError("Invalid lease renewal response")
        new = _grant_from_reply(payload, self.identity.node_id, grant.share_id)
        if new.generation != grant.generation or new.session_token != grant.session_token:
            raise LeaseChannelError("Lease identity changed during renewal")
        return new

    def release(
        self, host: str, port: int, peer_id: str, grant: LeaseGrant,
    ) -> None:
        LeaseAuthority._valid_grant(grant)
        if grant.owner_node_id != self.identity.node_id:
            raise LeaseChannelError("Lease belongs to another device")
        response, payload = self._request(
            host, port, peer_id, "release", share_id=grant.share_id,
            generation=grant.generation, session_token=grant.session_token,
        )
        if response != "released" or payload["share_id"] != grant.share_id:
            raise LeaseChannelError("Invalid lease release response")
