
"""Authenticated, explicitly approved live sessions between paired computers.

Saved pairing and folder configuration do not establish a live connection.
Each connection requires a fresh random session ID and peer approval.

This channel controls session presence only. It grants no filesystem or
synchronization permissions and never modifies saved pairing or history.
"""
from __future__ import annotations

import ipaddress
import secrets
import socket
import threading
import time
from collections.abc import Callable

from syncbridge.network.peer_presence import presence_port_for_transfer
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


REQUESTS = {
    "session_invite",
    "session_status",
    "session_commit",
    "session_ping",
    "session_leave",
}
STATES = {"waiting", "approved", "active", "denied", "closed"}


class SessionControlError(RuntimeError):
    """A live connection could not be requested or verified."""


def new_session_id() -> str:
    return secrets.token_hex(16)


def session_port_for_transfer(port: int) -> int:
    return presence_port_for_transfer(port)


def _host(value: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Expected a numeric IPv4 address") from exc

    if (
        address.is_unspecified
        or address.is_multicast
        or str(address) == "255.255.255.255"
    ):
        raise ValueError("Expected a unicast IPv4 address")

    return str(address)


class PeerSessionService:
    """Accept one explicitly approved live session per paired folder."""

    def __init__(
        self,
        identity: DeviceIdentity,
        trust: TrustStore,
        share_id: str,
        peer_id: str,
        *,
        bind_address: str = "0.0.0.0",
        port: int = 45850,
        on_event: Callable[[str, str], None] | None = None,
        invitation_seconds: float = 60.0,
        timeout: float = 3.0,
    ) -> None:
        if (
            not isinstance(identity, DeviceIdentity)
            or not isinstance(trust, TrustStore)
        ):
            raise TypeError("Identity and trust store are required")

        self.share_id = _identity(share_id)
        self.peer_id = _identity(peer_id)

        if (
            self.peer_id == identity.node_id
            or trust.get(self.peer_id) is None
        ):
            raise ValueError("The other computer must already be paired")

        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("Invalid listening port")
        if not 5.0 <= invitation_seconds <= 300.0:
            raise ValueError("Invalid invitation lifetime")
        if not 0.5 <= timeout <= 15.0:
            raise ValueError("Invalid connection timeout")
        if on_event is not None and not callable(on_event):
            raise TypeError("on_event must be callable")

        self.identity = identity
        self.trust = trust
        self.bind_address = str(ipaddress.IPv4Address(bind_address))
        self.port = port
        self.timeout = float(timeout)
        self.invitation_seconds = float(invitation_seconds)
        self.on_event = on_event

        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._connections: set[socket.socket] = set()
        self._workers: set[threading.Thread] = set()
        self._accept_thread: threading.Thread | None = None
        self._bound_port: int | None = None

        # Each entry is temporary and never written to disk.
        self._invitation: tuple[str, str, float] | None = None
        self._active: str | None = None

    @property
    def bound_port(self) -> int | None:
        with self._lock:
            return self._bound_port

    @property
    def active_session(self) -> str | None:
        with self._lock:
            return self._active

    @property
    def pending_invitation(self) -> str | None:
        with self._lock:
            return (
                self._invitation[0]
                if self._invitation is not None
                and self._invitation[1] == "waiting"
                else None
            )

    def _notify(self, kind: str, session_id: str) -> None:
        if self.on_event is not None:
            try:
                self.on_event(kind, session_id)
            except Exception:
                pass

    def _expire(self) -> None:
        expired = None
        with self._lock:
            invitation = self._invitation
            if (
                invitation is not None
                and time.monotonic() >= invitation[2]
            ):
                self._invitation = None
                expired = invitation[0]

        if expired is not None:
            self._notify("expired", expired)

    def start(self) -> None:
        with self._lock:
            if self._listener is not None:
                return

            if self._accept_thread is not None and self._accept_thread.is_alive():
                raise RuntimeError("Previous session listener is stopping")

            listener = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM
            )
            try:
                listener.setsockopt(
                    socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
                )
                listener.bind((self.bind_address, self.port))
                listener.listen(8)
                listener.settimeout(0.2)
            except BaseException:
                listener.close()
                raise

            self._listener = listener
            self._bound_port = listener.getsockname()[1]
            self._invitation = None
            self._active = None
            self._stop.clear()

            self._accept_thread = threading.Thread(
                target=self._accept,
                name="SyncBridgeSessionListener",
                daemon=True,
            )
            self._accept_thread.start()

    def _accept(self) -> None:
        while not self._stop.is_set():
            self._expire()

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
                permitted = (
                    not self._stop.is_set()
                    and len(self._connections) < 8
                )
                if permitted:
                    self._connections.add(connection)

            if not permitted:
                _close(connection)
                continue

            worker = threading.Thread(
                target=self._serve,
                args=(connection,),
                name="SyncBridgeSessionRequest",
                daemon=True,
            )
            with self._lock:
                self._workers.add(worker)
            worker.start()

    def _handle(self, kind: str, session_id: str) -> tuple[str, str | None]:
        """Return (status, event). Invocations hold self._lock."""
        invitation = self._invitation

        if kind == "session_invite":
            if self._active is not None:
                return "denied", None

            if invitation is not None:
                if invitation[0] == session_id:
                    return invitation[1], None
                return "denied", None

            self._invitation = (
                session_id,
                "waiting",
                time.monotonic() + self.invitation_seconds,
            )
            return "waiting", "invite"

        if kind == "session_leave":
            if self._active == session_id:
                self._active = None
                return "closed", "left"

            if invitation is not None and invitation[0] == session_id:
                self._invitation = None
                return "closed", "left"

            return "closed", None

        if kind == "session_ping":
            return (
                "active" if self._active == session_id else "closed",
                None,
            )

        if kind == "session_status":
            if self._active == session_id:
                return "active", None
            if invitation is not None and invitation[0] == session_id:
                return invitation[1], None
            return "closed", None

        if kind == "session_commit":
            if (
                invitation is not None
                and invitation[0] == session_id
                and invitation[1] == "approved"
                and self._active is None
            ):
                self._active = session_id
                self._invitation = None
                return "active", "joined"

            return "closed", None

        return "denied", None

    def _serve(self, connection: socket.socket) -> None:
        event = None
        session_id = None

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

            request = _read(secure, REQUESTS)
            kind = request["type"]
            _expect(
                request,
                kind,
                {"share_id", "session_id"},
            )

            if request["share_id"] != self.share_id:
                return

            session_id = _identity(request["session_id"])

            with self._lock:
                if self._stop.is_set():
                    return
                state, event = self._handle(
                    kind, session_id
                )

            _send(
                secure,
                "session_state",
                share_id=self.share_id,
                session_id=session_id,
                state=state,
            )

        except Exception:
            # Session messages contain no file content and must not
            # reveal private identity or authentication information.
            return

        finally:
            _close(connection)
            with self._lock:
                self._connections.discard(connection)
                self._workers.discard(threading.current_thread())

            if event is not None and session_id is not None:
                self._notify(event, session_id)

    def approve(self, session_id: str) -> bool:
        """Called after the local user accepts and runtime starts."""
        session_id = _identity(session_id)

        with self._lock:
            invitation = self._invitation
            if (
                invitation is None
                or invitation[0] != session_id
                or invitation[1] != "waiting"
                or time.monotonic() >= invitation[2]
            ):
                return False

            self._invitation = (
                session_id,
                "approved",
                invitation[2],
            )
            return True

    def reject(self, session_id: str) -> None:
        session_id = _identity(session_id)

        with self._lock:
            invitation = self._invitation
            if invitation is not None and invitation[0] == session_id:
                self._invitation = (
                    session_id,
                    "denied",
                    time.monotonic() + 10.0,
                )

    def activate_outgoing(self, session_id: str) -> None:
        """Initiator's runtime must already be started."""
        session_id = _identity(session_id)

        with self._lock:
            if (
                self._stop.is_set()
                or self._listener is None
                or self._active is not None
                or self._invitation is not None
            ):
                raise SessionControlError(
                    "A different connection is already being prepared"
                )

            self._active = session_id

    def clear(self, session_id: str | None = None) -> None:
        """End the local live session without deleting saved relationships."""
        with self._lock:
            if session_id is None or session_id == self._active:
                self._active = None

            if (
                self._invitation is not None
                and (
                    session_id is None
                    or session_id == self._invitation[0]
                )
            ):
                self._invitation = None

    def stop(self) -> None:
        with self._lock:
            self._stop.set()
            listener, self._listener = self._listener, None
            connections = tuple(self._connections)
            accept_thread = self._accept_thread
            workers = tuple(self._workers)
            self._bound_port = None
            self._active = None
            self._invitation = None

        if listener is not None:
            _close(listener)

        for connection in connections:
            _close(connection)

        if (
            accept_thread is not None
            and accept_thread is not threading.current_thread()
        ):
            accept_thread.join(timeout=self.timeout + 1)

        for worker in workers:
            if worker is not threading.current_thread():
                worker.join(timeout=self.timeout + 1)


class PeerSessionClient:
    """Send a control request only to the exact trusted peer identity."""

    def __init__(
        self,
        identity: DeviceIdentity,
        trust: TrustStore,
        *,
        timeout: float = 3.0,
    ) -> None:
        if (
            not isinstance(identity, DeviceIdentity)
            or not isinstance(trust, TrustStore)
        ):
            raise TypeError("Identity and trust store are required")

        self.identity = identity
        self.trust = trust
        self.timeout = float(timeout)

    def request(
        self,
        host: str,
        port: int,
        peer_id: str,
        share_id: str,
        session_id: str,
        action: str,
    ) -> str:
        if action not in REQUESTS:
            raise ValueError("Unsupported session action")

        host = _host(host)
        peer_id = _identity(peer_id)
        share_id = _identity(share_id)
        session_id = _identity(session_id)

        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("Invalid session control port")

        if (
            peer_id == self.identity.node_id
            or self.trust.get(peer_id) is None
        ):
            raise SessionControlError(
                "The requested computer is not paired"
            )

        try:
            with socket.create_connection(
                (host, port),
                timeout=self.timeout,
            ) as connection:
                secure, peer = open_secure_channel(
                    connection,
                    self.identity,
                    self.trust,
                    peer_id,
                    timeout=self.timeout,
                )

                if peer.node_id != peer_id:
                    raise SessionControlError(
                        "The responding computer is not the paired device"
                    )

                secure.settimeout(self.timeout)
                _send(
                    secure,
                    action,
                    share_id=share_id,
                    session_id=session_id,
                )

                response = _read(
                    secure,
                    {"session_state"},
                )
                _expect(
                    response,
                    "session_state",
                    {"share_id", "session_id", "state"},
                )

                if (
                    response["share_id"] != share_id
                    or response["session_id"] != session_id
                    or response["state"] not in STATES
                ):
                    raise SessionControlError(
                        "Session reply did not match this connection"
                    )

                return response["state"]

        except (OSError, ValueError) as exc:
            raise SessionControlError(
                "The other computer is unavailable"
            ) from exc
        except SessionControlError:
            raise
        except Exception as exc:
            raise SessionControlError(
                "Could not authenticate the live connection"
            ) from exc
