
"""TCP peer connections and unauthenticated control handshakes for SyncBridge.

A node ID received in HELLO/HELLO_ACK is only a CLAIM, not proof of identity.
Do not exchange private manifests or file contents until a future security layer
has authenticated and authorized the remote peer.
"""

from __future__ import annotations

import ipaddress
import logging
import math
import re
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from .protocol import (
    ConnectionClosedError,
    Message,
    MessageType,
    ProtocolError,
    receive_message,
    send_message,
)

logger = logging.getLogger(__name__)
_NODE_ID = re.compile(r"[0-9a-f]{32}\Z")
_MAX_PENDING_HANDSHAKES = 16


class PeerConnectionError(Exception):
    """A TCP peer could not connect, handshake, or follow the control protocol."""


@dataclass(frozen=True, slots=True)
class ConnectedPeer:
    """Unauthenticated, peer-claimed identity associated with a live TCP link."""

    node_id: str
    name: str
    address: str
    port: int  # Advertised TCP listening port, not the ephemeral source port.
    incoming: bool
    connected_at: float


@dataclass(slots=True)
class _Session:
    peer: ConnectedPeer
    connection: socket.socket
    send_lock: threading.Lock = field(default_factory=threading.Lock)
    pending_ping: str | None = None
    ping_sent_at: float = 0.0
    next_ping_at: float = 0.0


def _validate_identity(node_id: str, name: str, port: int) -> None:
    if not isinstance(node_id, str) or not _NODE_ID.fullmatch(node_id):
        raise ValueError("node_id must be 32 lowercase hexadecimal characters")
    if not isinstance(name, str):
        raise ValueError("name must be printable UTF-8, 1 to 128 bytes")
    try:
        size = len(name.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ValueError("name contains invalid Unicode") from exc
    if not name.strip() or size > 128 or any(
        ord(character) < 32 or ord(character) == 127 for character in name
    ):
        raise ValueError("name must be printable UTF-8, 1 to 128 bytes")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("peer port must be between 1 and 65535")


def _validate_port(port: int, *, allow_zero: bool = False) -> int:
    if type(port) is not int or not (0 if allow_zero else 1) <= port <= 65535:
        raise ValueError("port must be an integer between 1 and 65535")
    return port


def _identity_payload(node_id: str, name: str, port: int) -> dict[str, object]:
    return {"node_id": node_id, "name": name, "peer_port": port}


def _parse_identity(
    payload: dict, *, acknowledgement: bool = False
) -> tuple[str, str, int]:
    fields = {"node_id", "name", "peer_port"}
    if acknowledgement:
        fields.add("in_reply_to")
    if set(payload) != fields:
        raise PeerConnectionError("Invalid handshake payload fields")
    try:
        _validate_identity(
            payload["node_id"],
            payload["name"],
            payload["peer_port"],
        )
    except ValueError as exc:
        raise PeerConnectionError(str(exc)) from exc
    if acknowledgement and (
        not isinstance(payload["in_reply_to"], str)
        or not _NODE_ID.fullmatch(payload["in_reply_to"])
    ):
        raise PeerConnectionError("Invalid handshake reply reference")
    return payload["node_id"], payload["name"], payload["peer_port"]


def _close_socket(connection: socket.socket) -> None:
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        connection.close()
    except OSError:
        pass


class PeerManager:
    """Manage mutually reachable TCP control connections.

    start() begins an IPv4 TCP listener and heartbeat worker. connect() is an
    explicit action: discovery alone never opens a connection. Callbacks run
    on background threads (except synchronous disconnect/stop); UI code must
    dispatch them to the UI thread. A callback may safely call stop().
    """

    def __init__(
        self,
        node_id: str,
        name: str,
        *,
        listen_port: int = 45840,
        bind_address: str = "0.0.0.0",
        handshake_timeout: float = 3.0,
        heartbeat_interval: float = 2.0,
        idle_timeout: float = 8.0,
        on_connected: Callable[[ConnectedPeer], None] | None = None,
        on_disconnected: Callable[[ConnectedPeer], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        _validate_identity(node_id, name, 1)
        _validate_port(listen_port, allow_zero=True)
        try:
            ipaddress.IPv4Address(bind_address)
        except ValueError as exc:
            raise ValueError(
                "bind_address must be a numeric IPv4 address"
            ) from exc
        for value in (
            handshake_timeout,
            heartbeat_interval,
            idle_timeout,
        ):
            if (
                type(value) not in (int, float)
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(
                    "Connection timeouts must be finite positive numbers"
                )
        if idle_timeout <= heartbeat_interval:
            raise ValueError(
                "idle_timeout must exceed heartbeat_interval"
            )
        if any(
            callback is not None and not callable(callback)
            for callback in (
                on_connected,
                on_disconnected,
                on_error,
            )
        ):
            raise TypeError(
                "Peer callbacks must be callable or None"
            )

        self.node_id = node_id
        self.name = name
        self.listen_port = listen_port
        self.bind_address = bind_address
        self.handshake_timeout = float(handshake_timeout)
        self.heartbeat_interval = float(heartbeat_interval)
        self.idle_timeout = float(idle_timeout)
        self._on_connected = on_connected
        self._on_disconnected = on_disconnected
        self._on_error = on_error

        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._stop_event.set()
        self._server: socket.socket | None = None
        self._bound_port: int | None = None
        self._sessions: dict[str, _Session] = {}
        self._pending: set[socket.socket] = set()
        self._threads: set[threading.Thread] = set()

    @property
    def is_running(self) -> bool:
        with self._lock:
            return (
                self._server is not None
                and not self._stop_event.is_set()
            )

    @property
    def bound_port(self) -> int | None:
        with self._lock:
            return self._bound_port

    @property
    def peers(self) -> tuple[ConnectedPeer, ...]:
        with self._lock:
            return tuple(
                sorted(
                    (
                        session.peer
                        for session in self._sessions.values()
                    ),
                    key=lambda peer: peer.node_id,
                )
            )

    def _spawn(
        self,
        target: Callable[..., None],
        *args: object,
    ) -> None:
        def run() -> None:
            try:
                target(*args)
            finally:
                with self._lock:
                    self._threads.discard(
                        threading.current_thread()
                    )

        thread = threading.Thread(
            target=run,
            daemon=True,
            name=f"SyncBridge-{target.__name__}",
        )
        with self._lock:
            self._threads.add(thread)
        thread.start()

    def start(self) -> None:
        with self._lock:
            if self._server is not None:
                return
            if self._threads:
                raise RuntimeError(
                    "Previous peer workers are still stopping"
                )
            server = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM,
            )
            try:
                server.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_REUSEADDR,
                    1,
                )
                server.bind(
                    (self.bind_address, self.listen_port)
                )
                server.listen(_MAX_PENDING_HANDSHAKES)
                server.settimeout(0.2)
            except Exception:
                server.close()
                raise

            self._server = server
            self._bound_port = server.getsockname()[1]
            self._stop_event.clear()
            self._spawn(self._accept_loop)
            self._spawn(self._heartbeat_loop)

    def stop(self) -> None:
        with self._lock:
            self._stop_event.set()
            server, self._server = self._server, None
            self._bound_port = None
            sessions = list(self._sessions.values())
            self._sessions.clear()
            pending = list(self._pending)
            self._pending.clear()
            threads = list(self._threads)

        if server is not None:
            _close_socket(server)

        for connection in pending:
            _close_socket(connection)

        for session in sessions:
            _close_socket(session.connection)
            self._callback(
                self._on_disconnected,
                session.peer,
            )

        for thread in threads:
            if thread is not threading.current_thread():
                thread.join(
                    timeout=self.handshake_timeout + 1.0
                )

    def connect(
        self,
        host: str,
        port: int,
        *,
        expected_node_id: str | None = None,
    ) -> ConnectedPeer:
        """Connect and perform a HELLO handshake; identity remains unverified."""
        try:
            address = str(
                ipaddress.IPv4Address(host)
            )
        except ValueError as exc:
            raise ValueError(
                "host must be a numeric IPv4 address"
            ) from exc

        if (
            address == "0.0.0.0"
            or ipaddress.IPv4Address(address).is_multicast
        ):
            raise ValueError(
                "host must be a usable unicast IPv4 address"
            )

        _validate_port(port)

        if expected_node_id is not None and (
            not isinstance(expected_node_id, str)
            or not _NODE_ID.fullmatch(expected_node_id)
        ):
            raise ValueError(
                "expected_node_id must be 32 lowercase hexadecimal characters"
            )

        with self._lock:
            if (
                self._stop_event.is_set()
                or self._bound_port is None
            ):
                raise RuntimeError(
                    "Peer manager must be started before connecting"
                )
            advertised_port = self._bound_port
            if (
                port == advertised_port
                and address in (
                    "127.0.0.1",
                    self.bind_address,
                )
            ):
                raise PeerConnectionError(
                    "Cannot connect to our own node"
                )

        connection = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )
        registered = False

        with self._lock:
            if self._stop_event.is_set():
                connection.close()
                raise RuntimeError(
                    "Peer manager is stopping"
                )
            self._pending.add(connection)

        try:
            connection.settimeout(
                self.handshake_timeout
            )
            connection.connect((address, port))
            hello = Message(
                MessageType.HELLO,
                _identity_payload(
                    self.node_id,
                    self.name,
                    advertised_port,
                ),
            )
            send_message(connection, hello)
            response = receive_message(connection)

            if response.kind is not MessageType.HELLO_ACK:
                raise PeerConnectionError(
                    "Expected HELLO_ACK from remote peer"
                )

            remote_id, remote_name, remote_port = _parse_identity(
                response.payload,
                acknowledgement=True,
            )

            if (
                response.payload["in_reply_to"]
                != hello.message_id
            ):
                raise PeerConnectionError(
                    "HELLO_ACK does not match our HELLO"
                )

            if remote_id == self.node_id:
                raise PeerConnectionError(
                    "Cannot connect to our own node ID"
                )

            if (
                expected_node_id is not None
                and remote_id != expected_node_id
            ):
                raise PeerConnectionError(
                    "Remote node ID does not match discovered peer"
                )

            connection.settimeout(None)
            peer = ConnectedPeer(
                remote_id,
                remote_name,
                address,
                remote_port,
                False,
                time.time(),
            )

            session = self._register(
                connection,
                peer,
            )

            if session is None:
                raise PeerConnectionError(
                    "Duplicate connection to peer"
                )

            registered = True
            self._spawn(
                self._receive_loop,
                session,
            )
            return peer

        except (OSError, ProtocolError) as exc:
            raise PeerConnectionError(
                f"Could not connect or handshake: {exc}"
            ) from exc

        finally:
            with self._lock:
                self._pending.discard(connection)

            if not registered:
                _close_socket(connection)

    def disconnect(self, node_id: str) -> bool:
        """Disconnect a peer; false if it has already left."""
        with self._lock:
            session = self._sessions.get(node_id)

        if session is None:
            return False

        self._remove(session)
        return True

    def _accept_loop(self) -> None:
        while not self._stop_event.is_set():
            with self._lock:
                server = self._server

            if server is None:
                break

            try:
                connection, (address, _) = server.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if not self._stop_event.is_set():
                    self._report_error(exc)
                break

            with self._lock:
                if (
                    self._stop_event.is_set()
                    or len(self._pending)
                    >= _MAX_PENDING_HANDSHAKES
                ):
                    accepted = False
                else:
                    self._pending.add(connection)
                    accepted = True

            if accepted:
                self._spawn(
                    self._inbound,
                    connection,
                    address,
                )
            else:
                _close_socket(connection)

    def _inbound(
        self,
        connection: socket.socket,
        address: str,
    ) -> None:
        registered = False

        try:
            connection.settimeout(
                self.handshake_timeout
            )
            hello = receive_message(connection)

            if hello.kind is not MessageType.HELLO:
                raise PeerConnectionError(
                    "First message must be HELLO"
                )

            remote_id, remote_name, remote_port = (
                _parse_identity(hello.payload)
            )

            if remote_id == self.node_id:
                raise PeerConnectionError(
                    "Refusing connection from our own node ID"
                )

            with self._lock:
                advertised_port = self._bound_port

            if (
                self._stop_event.is_set()
                or advertised_port is None
            ):
                return

            response = Message(
                MessageType.HELLO_ACK,
                {
                    **_identity_payload(
                        self.node_id,
                        self.name,
                        advertised_port,
                    ),
                    "in_reply_to": hello.message_id,
                },
            )
            send_message(connection, response)
            connection.settimeout(None)

            peer = ConnectedPeer(
                remote_id,
                remote_name,
                address,
                remote_port,
                True,
                time.time(),
            )

            session = self._register(
                connection,
                peer,
            )

            if session is not None:
                registered = True

                with self._lock:
                    self._pending.discard(connection)

                self._receive_loop(session)

        except (
            OSError,
            ProtocolError,
            PeerConnectionError,
        ) as exc:
            if not self._stop_event.is_set():
                self._report_error(exc)

        finally:
            with self._lock:
                self._pending.discard(connection)

            if not registered:
                _close_socket(connection)

    def _register(
        self,
        connection: socket.socket,
        peer: ConnectedPeer,
    ) -> _Session | None:
        replaced = None

        with self._lock:
            if self._stop_event.is_set():
                return None

            old = self._sessions.get(peer.node_id)

            if old is not None:
                # The smaller node keeps its outgoing socket;
                # the larger node keeps its incoming socket.
                prefer_incoming = (
                    self.node_id > peer.node_id
                )

                if (
                    peer.incoming != prefer_incoming
                    or old.peer.incoming == prefer_incoming
                ):
                    return None

                replaced = old

            now = time.monotonic()
            session = _Session(
                peer,
                connection,
                next_ping_at=(
                    now + self.heartbeat_interval
                ),
            )
            self._sessions[peer.node_id] = session

        if replaced is not None:
            _close_socket(replaced.connection)
            self._callback(
                self._on_disconnected,
                replaced.peer,
            )

        self._callback(
            self._on_connected,
            peer,
        )
        return session

    def _remove(self, session: _Session) -> None:
        with self._lock:
            if (
                self._sessions.get(
                    session.peer.node_id
                )
                is not session
            ):
                return

            del self._sessions[
                session.peer.node_id
            ]

        _close_socket(session.connection)
        self._callback(
            self._on_disconnected,
            session.peer,
        )

    def _receive_loop(self, session: _Session) -> None:
        try:
            while not self._stop_event.is_set():
                message = receive_message(
                    session.connection
                )

                if message.kind is MessageType.PING:
                    if message.payload:
                        raise PeerConnectionError(
                            "PING must have an empty payload"
                        )

                    self._send(
                        session,
                        Message(
                            MessageType.PONG,
                            {
                                "in_reply_to":
                                    message.message_id
                            },
                        ),
                    )

                elif message.kind is MessageType.PONG:
                    if (
                        set(message.payload)
                        != {"in_reply_to"}
                        or not isinstance(
                            message.payload["in_reply_to"],
                            str,
                        )
                    ):
                        raise PeerConnectionError(
                            "Invalid PONG payload"
                        )

                    with self._lock:
                        if (
                            session.pending_ping
                            != message.payload[
                                "in_reply_to"
                            ]
                        ):
                            raise PeerConnectionError(
                                "Unsolicited or mismatched PONG"
                            )

                        session.pending_ping = None
                        session.next_ping_at = (
                            time.monotonic()
                            + self.heartbeat_interval
                        )

                else:
                    raise PeerConnectionError(
                        "Unexpected message after handshake"
                    )

        except (
            OSError,
            ProtocolError,
            PeerConnectionError,
        ) as exc:
            if not self._stop_event.is_set():
                if not isinstance(
                    exc,
                    ConnectionClosedError,
                ):
                    self._report_error(exc)

        finally:
            self._remove(session)

    def _send(
        self,
        session: _Session,
        message: Message,
    ) -> None:
        with session.send_lock:
            with self._lock:
                if (
                    self._sessions.get(
                        session.peer.node_id
                    )
                    is not session
                ):
                    raise PeerConnectionError(
                        "Peer is no longer connected"
                    )

            send_message(
                session.connection,
                message,
            )

    def _heartbeat_loop(self) -> None:
        while not self._stop_event.wait(
            min(0.2, self.heartbeat_interval / 2)
        ):
            with self._lock:
                sessions = tuple(
                    self._sessions.values()
                )

            for session in sessions:
                now = time.monotonic()

                with self._lock:
                    if (
                        self._sessions.get(
                            session.peer.node_id
                        )
                        is not session
                    ):
                        continue

                    if session.pending_ping is not None:
                        stale = (
                            now - session.ping_sent_at
                            >= self.idle_timeout
                        )
                        ping = None

                    elif now >= session.next_ping_at:
                        stale = False
                        ping = Message(
                            MessageType.PING
                        )
                        session.pending_ping = (
                            ping.message_id
                        )
                        session.ping_sent_at = now

                    else:
                        stale = False
                        ping = None

                if stale:
                    self._report_error(
                        PeerConnectionError(
                            "Peer heartbeat timed out"
                        )
                    )
                    self._remove(session)

                elif ping is not None:
                    try:
                        self._send(
                            session,
                            ping,
                        )
                    except (
                        OSError,
                        ProtocolError,
                        PeerConnectionError,
                    ) as exc:
                        if not self._stop_event.is_set():
                            self._report_error(exc)

                        self._remove(session)

    def _callback(
        self,
        callback: (
            Callable[[ConnectedPeer], None] | None
        ),
        peer: ConnectedPeer,
    ) -> None:
        if callback is None:
            return

        try:
            callback(peer)
        except Exception as exc:
            self._report_error(exc)

    def _report_error(self, exc: Exception) -> None:
        if self._on_error is None:
            logger.warning(
                "SyncBridge peer connection: %s",
                exc,
            )
            return

        try:
            self._on_error(exc)
        except Exception:
            logger.exception(
                "SyncBridge peer error callback failed"
            )
