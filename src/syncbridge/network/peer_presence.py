
"""Authenticated, ephemeral peer liveness for the SyncBridge desktop.

Presence confirms an approved peer application is online NOW; it is not
pairing, permission to read or write files, or a synchronization operation.
No presence state is persisted. The file-transfer protocol is unchanged.
"""
from __future__ import annotations

import ipaddress
import math
import secrets
import socket
import threading
from collections.abc import Callable

from syncbridge.network.secure_channel import (
    accept_secure_channel,
    open_secure_channel,
)
from syncbridge.network.security import DeviceIdentity, TrustStore
from syncbridge.network.transfer import (
    _close,
    _expect,
    _identity,
    _read,
    _send,
)


_DEFAULT_TRANSFER_PORT = 45842
_DEFAULT_PRESENCE_PORT = 45850
_LOW_PORT = 1025
_SPAN = 65535 - _LOW_PORT + 1
_SHIFT = 30000


class PresenceError(RuntimeError):
    """The paired peer cannot be authenticated or reached right now."""


def presence_port_for_transfer(port: int) -> int:
    """Derive a repeatable control port from a configured transfer port."""
    if type(port) is not int or not _LOW_PORT <= port <= 65535:
        raise ValueError(
            "A fixed transfer port from 1025 to 65535 is required"
        )

    if port == _DEFAULT_TRANSFER_PORT:
        return _DEFAULT_PRESENCE_PORT

    def rotate(value: int) -> int:
        return _LOW_PORT + (
            (value - _LOW_PORT + _SHIFT) % _SPAN
        )

    candidate = rotate(port)
    if candidate == _DEFAULT_PRESENCE_PORT:
        return rotate(_DEFAULT_TRANSFER_PORT)

    return candidate


def _address(value: str, *, listener: bool = False) -> str:
    address = ipaddress.IPv4Address(value)

    if (
        address.is_multicast
        or str(address) == "255.255.255.255"
    ):
        raise ValueError("Invalid presence IPv4 address")

    if not listener and address.is_unspecified:
        raise ValueError("Peer address must not be 0.0.0.0")

    return str(address)


class PeerPresenceService:
    """Small authenticated TCP responder for one previously approved share."""

    def __init__(
        self,
        identity: DeviceIdentity,
        trust: TrustStore,
        share_id: str,
        peer_id: str,
        *,
        bind_address: str = "127.0.0.1",
        port: int = _DEFAULT_PRESENCE_PORT,
        timeout: float = 3.0,
        on_goodbye: Callable[[], None] | None = None,
    ) -> None:
        if (
            not isinstance(identity, DeviceIdentity)
            or not isinstance(trust, TrustStore)
        ):
            raise TypeError(
                "Device identity and trust store are required"
            )

        self.share_id = _identity(share_id)
        self.peer_id = _identity(peer_id)

        if (
            self.peer_id == identity.node_id
            or trust.get(peer_id) is None
        ):
            raise ValueError(
                "Presence requires an explicitly paired other device"
            )

        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("Invalid presence listening port")

        if (
            type(timeout) not in (float, int)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("Invalid presence timeout")

        if on_goodbye is not None and not callable(on_goodbye):
            raise TypeError("on_goodbye must be callable")

        self.identity = identity
        self.trust = trust
        self.bind_address = _address(
            bind_address, listener=True
        )
        self.port = port
        self.timeout = float(timeout)
        self.on_goodbye = on_goodbye

        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._stop.set()

        self._listener: socket.socket | None = None
        self._connections: set[socket.socket] = set()
        self._threads: set[threading.Thread] = set()
        self._epoch: str | None = None
        self._bound_port: int | None = None

    @property
    def epoch(self) -> str | None:
        with self._lock:
            return self._epoch

    @property
    def bound_port(self) -> int | None:
        with self._lock:
            return self._bound_port

    def start(self) -> None:
        with self._lock:
            if self._listener is not None:
                return

            if any(
                thread.is_alive()
                for thread in self._threads
            ):
                raise RuntimeError(
                    "Previous presence connections are still stopping"
                )

            listener = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM,
            )

            try:
                listener.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_REUSEADDR,
                    1,
                )
                listener.bind((
                    self.bind_address,
                    self.port,
                ))
                listener.listen(8)
                listener.settimeout(0.2)
            except BaseException:
                listener.close()
                raise

            self._listener = listener
            self._bound_port = listener.getsockname()[1]
            self._epoch = secrets.token_hex(16)
            self._stop.clear()
            self._spawn(self._accept)

    def _spawn(self, fn, *args) -> None:
        def run():
            try:
                fn(*args)
            finally:
                with self._lock:
                    self._threads.discard(
                        threading.current_thread()
                    )

        worker = threading.Thread(
            target=run,
            name="SyncBridgePresence",
            daemon=True,
        )

        with self._lock:
            self._threads.add(worker)

        worker.start()

    def _accept(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                listener = self._listener

            if listener is None:
                return

            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return

            with self._lock:
                accepted = (
                    not self._stop.is_set()
                    and len(self._connections) < 8
                )

                if accepted:
                    self._connections.add(connection)

            if accepted:
                self._spawn(self._serve, connection)
            else:
                _close(connection)

    def _serve(self, connection: socket.socket) -> None:
        try:
            secure, peer = accept_secure_channel(
                connection,
                self.identity,
                self.trust,
                timeout=self.timeout,
            )
            secure.settimeout(self.timeout)

            if peer.node_id != self.peer_id:
                return

            request = _read(
                secure,
                {"presence_ping", "presence_goodbye"},
            )
            kind = request["type"]

            if kind == "presence_ping":
                _expect(request, kind, {"share_id"})
            else:
                _expect(
                    request,
                    kind,
                    {"share_id", "target_epoch"},
                )

            if (
                request["share_id"] != self.share_id
                or self._stop.is_set()
            ):
                return

            with self._lock:
                current_epoch = self._epoch

            if current_epoch is None:
                return

            if kind == "presence_ping":
                _send(
                    secure,
                    "presence_live",
                    share_id=self.share_id,
                    epoch=current_epoch,
                )

            else:
                # Ignore delayed departures targeting a previous launch.
                target = request["target_epoch"]
                if (
                    type(target) is not str
                    or not secrets.compare_digest(
                        target, current_epoch
                    )
                ):
                    return

                _send(
                    secure,
                    "presence_ack",
                    share_id=self.share_id,
                )

                if (
                    self.on_goodbye is not None
                    and not self._stop.is_set()
                ):
                    self.on_goodbye()

        except Exception:
            # Do not expose peer identities, session epochs, or
            # authentication details in background logs.
            pass

        finally:
            _close(connection)

            with self._lock:
                self._connections.discard(connection)

    def stop(self) -> None:
        with self._lock:
            self._stop.set()

            listener, self._listener = self._listener, None
            self._epoch = None
            self._bound_port = None

            connections = tuple(self._connections)
            threads = tuple(self._threads)

        if listener is not None:
            _close(listener)

        for connection in connections:
            _close(connection)

        for thread in threads:
            if thread is not threading.current_thread():
                thread.join(timeout=self.timeout + 1)


class PeerPresenceClient:
    """Verify a currently running approved app or announce departure."""

    def __init__(
        self,
        identity: DeviceIdentity,
        trust: TrustStore,
        *,
        timeout: float = 2.5,
    ):
        if (
            not isinstance(identity, DeviceIdentity)
            or not isinstance(trust, TrustStore)
        ):
            raise TypeError(
                "Device identity and trust store are required"
            )

        if (
            type(timeout) not in (float, int)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("Invalid presence timeout")

        self.identity = identity
        self.trust = trust
        self.timeout = float(timeout)

    def _request(
        self,
        host: str,
        port: int,
        peer_id: str,
        kind: str,
        **fields,
    ) -> dict:
        address = _address(host)
        _identity(peer_id)

        if (
            type(port) is not int
            or not 1 <= port <= 65535
        ):
            raise ValueError(
                "Invalid peer presence port"
            )

        if self.trust.get(peer_id) is None:
            raise PresenceError(
                "Peer is not paired"
            )

        try:
            connection = socket.create_connection(
                (address, port),
                timeout=self.timeout,
            )
        except OSError as exc:
            raise PresenceError(
                "The paired computer is not reachable"
            ) from exc

        try:
            secure, trusted = open_secure_channel(
                connection,
                self.identity,
                self.trust,
                peer_id,
                timeout=self.timeout,
            )

            if trusted.node_id != peer_id:
                raise PresenceError(
                    "Incorrect paired computer"
                )

            secure.settimeout(self.timeout)
            _send(secure, kind, **fields)

            allowed = (
                {"presence_live"}
                if kind == "presence_ping"
                else {"presence_ack"}
            )

            response = _read(secure, allowed)

            _expect(
                response,
                next(iter(allowed)),
                (
                    {"share_id", "epoch"}
                    if kind == "presence_ping"
                    else {"share_id"}
                ),
            )

            return response

        except Exception as exc:
            raise PresenceError(
                "Cannot authenticate the paired computer's live session"
            ) from exc

        finally:
            _close(connection)

    def probe(
        self,
        host: str,
        port: int,
        peer_id: str,
        share_id: str,
    ) -> str:
        share_id = _identity(share_id)

        response = self._request(
            host,
            port,
            peer_id,
            "presence_ping",
            share_id=share_id,
        )

        if response["share_id"] != share_id:
            raise PresenceError(
                "Peer belongs to another folder relationship"
            )

        epoch = response["epoch"]

        if (
            type(epoch) is not str
            or len(epoch) != 32
            or any(
                x not in "0123456789abcdef"
                for x in epoch
            )
        ):
            raise PresenceError(
                "Invalid peer session identity"
            )

        return epoch

    def goodbye(
        self,
        host: str,
        port: int,
        peer_id: str,
        share_id: str,
        target_epoch: str,
    ) -> None:
        share_id = _identity(share_id)

        if (
            type(target_epoch) is not str
            or len(target_epoch) != 32
            or any(
                x not in "0123456789abcdef"
                for x in target_epoch
            )
        ):
            raise ValueError(
                "Invalid peer session identity"
            )

        response = self._request(
            host,
            port,
            peer_id,
            "presence_goodbye",
            share_id=share_id,
            target_epoch=target_epoch,
        )

        if response["share_id"] != share_id:
            raise PresenceError(
                "Incorrect peer goodbye acknowledgement"
            )
