
"""Authenticated and encrypted peer manager for paired SyncBridge devices.

Use this rather than the legacy unauthenticated PeerManager for any access to
synchronization metadata or file contents. Discovery alone never grants trust.
"""

from __future__ import annotations

import ipaddress
import socket
import time

from .peer import (
    ConnectedPeer,
    PeerConnectionError,
    PeerManager,
    _close_socket,
    _identity_payload,
    _parse_identity,
    _validate_port,
)
from .protocol import Message, MessageType, ProtocolError, receive_message, send_message
from .secure_channel import accept_secure_channel, open_secure_channel
from .security import AuthenticationError, DeviceIdentity, SecurityError, TrustStore


class SecurePeerManager(PeerManager):
    """Drop-in peer lifecycle with mandatory mutual trust and encrypted traffic.

    The stable node ID is derived from DeviceIdentity, never randomly generated.
    Both devices must explicitly pair public keys out-of-band beforehand.
    connect() requires the discovered/confirmed expected node ID to prevent
    connecting to an arbitrary claimed identity.
    """

    def __init__(
        self,
        identity: DeviceIdentity,
        trust_store: TrustStore,
        name: str,
        **manager_options: object,
    ) -> None:
        if not isinstance(identity, DeviceIdentity):
            raise TypeError("identity must be a DeviceIdentity")
        if not isinstance(trust_store, TrustStore):
            raise TypeError("trust_store must be a TrustStore")
        if "node_id" in manager_options:
            raise TypeError("node_id is always derived from device identity")
        self.identity = identity
        self.trust_store = trust_store
        super().__init__(identity.node_id, name, **manager_options)

    def start(self) -> None:
        was_running = self.is_running
        super().start()
        if not was_running:
            self._spawn(self._revocation_loop)

    def connect(
        self,
        host: str,
        port: int,
        *,
        expected_node_id: str,
    ) -> ConnectedPeer:
        """Connect only to a paired device; do not send plaintext HELLO."""
        if not isinstance(host, str):
            raise ValueError("host must be a numeric unicast IPv4 address")
        try:
            address = ipaddress.IPv4Address(host)
        except ValueError as exc:
            raise ValueError("host must be a numeric unicast IPv4 address") from exc
        if address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255":
            raise ValueError("host must be a unicast IPv4 address")
        _validate_port(port)
        if not isinstance(expected_node_id, str) or len(expected_node_id) != 32 or any(
            char not in "0123456789abcdef" for char in expected_node_id
        ):
            raise ValueError("expected_node_id must be 32 lowercase hexadecimal characters")
        if expected_node_id == self.node_id:
            raise PeerConnectionError("Cannot connect to our own device identity")
        peer_record = self.trust_store.get(expected_node_id)
        if peer_record is None:
            raise AuthenticationError("Expected device is not paired")
        self.trust_store.require(bytes.fromhex(peer_record.public_key_hex))

        with self._lock:
            advertised_port = self._bound_port
            if self._stop_event.is_set() or advertised_port is None:
                raise RuntimeError("Peer manager must be started before connecting")
            if port == advertised_port and str(address) in ("127.0.0.1", self.bind_address):
                raise PeerConnectionError("Cannot connect to our own listener")

        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        registered = False
        with self._lock:
            if self._stop_event.is_set():
                connection.close()
                raise RuntimeError("Peer manager is stopping")
            self._pending.add(connection)

        try:
            connection.settimeout(self.handshake_timeout)
            connection.connect((str(address), port))
            secure, verified = open_secure_channel(
                connection, self.identity, self.trust_store,
                expected_node_id, timeout=self.handshake_timeout,
            )
            secure.settimeout(self.handshake_timeout)
            hello = Message(
                MessageType.HELLO,
                _identity_payload(self.node_id, self.name, advertised_port),
            )
            send_message(secure, hello)
            answer = receive_message(secure)
            if answer.kind is not MessageType.HELLO_ACK:
                raise PeerConnectionError("Expected encrypted HELLO_ACK")
            remote_id, remote_name, remote_port = _parse_identity(
                answer.payload, acknowledgement=True,
            )
            if remote_id != verified.node_id:
                raise PeerConnectionError("HELLO_ACK identity differs from authenticated key")
            if answer.payload["in_reply_to"] != hello.message_id:
                raise PeerConnectionError("HELLO_ACK does not reference our HELLO")
            self.trust_store.require(secure.remote_public_key)
            secure.settimeout(None)
            peer = ConnectedPeer(
                remote_id, remote_name, str(address), remote_port, False, time.time(),
            )
            session = self._register(secure, peer)
            if session is None:
                raise PeerConnectionError("Duplicate secure peer connection")
            registered = True
            self._spawn(self._receive_loop, session)
            return peer
        except (OSError, ProtocolError, SecurityError, PeerConnectionError) as exc:
            if isinstance(exc, (PeerConnectionError, AuthenticationError)):
                raise
            raise PeerConnectionError(f"Encrypted peer connection failed: {exc}") from exc
        finally:
            with self._lock:
                self._pending.discard(connection)
            if not registered:
                _close_socket(connection)

    def _inbound(self, connection: socket.socket, address: str) -> None:
        registered = False
        try:
            secure, verified = accept_secure_channel(
                connection, self.identity, self.trust_store,
                timeout=self.handshake_timeout,
            )
            secure.settimeout(self.handshake_timeout)
            hello = receive_message(secure)
            if hello.kind is not MessageType.HELLO:
                raise PeerConnectionError("Expected encrypted HELLO")
            remote_id, remote_name, remote_port = _parse_identity(hello.payload)
            if remote_id != verified.node_id:
                raise PeerConnectionError("HELLO identity differs from authenticated key")
            with self._lock:
                advertised_port = self._bound_port
            if self._stop_event.is_set() or advertised_port is None:
                return
            send_message(
                secure,
                Message(
                    MessageType.HELLO_ACK,
                    {
                        **_identity_payload(self.node_id, self.name, advertised_port),
                        "in_reply_to": hello.message_id,
                    },
                ),
            )
            self.trust_store.require(secure.remote_public_key)
            secure.settimeout(None)
            peer = ConnectedPeer(
                remote_id, remote_name, address, remote_port, True, time.time(),
            )
            session = self._register(secure, peer)
            if session is not None:
                registered = True
                with self._lock:
                    self._pending.discard(connection)
                self._receive_loop(session)
        except (OSError, ProtocolError, PeerConnectionError, SecurityError) as exc:
            if not self._stop_event.is_set():
                self._report_error(exc)
        finally:
            with self._lock:
                self._pending.discard(connection)
            if not registered:
                _close_socket(connection)

    def _revocation_loop(self) -> None:
        """Revoke active connections when their public key is removed from trust."""
        while not self._stop_event.wait(min(0.2, self.heartbeat_interval / 2)):
            with self._lock:
                sessions = tuple(self._sessions.values())
            for session in sessions:
                try:
                    self.trust_store.require(session.connection.remote_public_key)
                except (SecurityError, OSError) as exc:
                    if not self._stop_event.is_set():
                        self._report_error(exc)
                        self._remove(session)
