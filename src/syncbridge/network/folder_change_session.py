
"""Authenticated, two-person folder-change negotiation over the session port.

An approval is not a filesystem authorization: only the Qt owner can stop the
runtime and subsequently replace its local saved share. No network command
modifies settings, user files or device trust.
"""
from __future__ import annotations

import socket
import threading
import time

from syncbridge.network.secure_channel import accept_secure_channel, open_secure_channel
from syncbridge.network.session_control import (
    PeerSessionClient,
    PeerSessionService,
    REQUESTS,
    STATES,
    SessionControlError,
    _host,
)
from syncbridge.network.transfer import _close, _expect, _identity, _read, _send

FOLDER_ACTIONS = frozenset({
    "folder_change_invite", "folder_change_status", "folder_change_prepare",
    "folder_change_commit", "folder_change_cancel",
})
FOLDER_STATES = frozenset({"preparing", "ready", "committed"})


class FolderChangeSessionService(PeerSessionService):
    """Only an existing, authenticated live session can request replacement."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._folder_change: tuple[str, str, float] | None = None

    def start(self) -> None:
        super().start()
        with self._lock:
            self._folder_change = None

    def _expire(self) -> None:
        super()._expire()
        expired = None
        with self._lock:
            proposal = self._folder_change
            if proposal and time.monotonic() >= proposal[2]:
                if proposal[1] not in ("denied", "committed"):
                    expired = proposal[0]
                self._folder_change = None
        if expired:
            self._notify("folder-change-cancelled", expired)

    def _handle(self, kind: str, session_id: str) -> tuple[str, str | None]:
        if kind not in FOLDER_ACTIONS:
            state, event = super()._handle(kind, session_id)
            if kind == "session_leave" and self._active != session_id:
                if self._folder_change is not None:
                    self._notify("folder-change-cancelled", session_id)
                self._folder_change = None
            return state, event

        if self._active != session_id:
            return "closed", None
        proposal = self._folder_change
        state = proposal[1] if proposal is not None else None

        if kind == "folder_change_invite":
            if proposal is None:
                self._folder_change = (
                    session_id, "waiting", time.monotonic() + 90.0
                )
                return "waiting", "folder-change-invite"
            return state, None
        if kind == "folder_change_status":
            return state or "closed", None
        if kind == "folder_change_cancel":
            if state != "committed":
                self._folder_change = None
                return "closed", "folder-change-cancelled"
            return "committed", None
        if kind == "folder_change_prepare":
            if state == "approved":
                self._folder_change = (session_id, "preparing", proposal[2])
                return "preparing", "folder-change-prepare"
            return state or "closed", None
        if kind == "folder_change_commit":
            if state == "ready":
                self._folder_change = (session_id, "committed", proposal[2])
                return "committed", "folder-change-committed"
            return state or "closed", None
        return "denied", None

    def approve_folder_change(self, session_id: str) -> bool:
        session_id = _identity(session_id)
        with self._lock:
            proposal = self._folder_change
            if (self._active != session_id or not proposal
                    or proposal[0] != session_id or proposal[1] != "waiting"
                    or time.monotonic() >= proposal[2]):
                return False
            self._folder_change = (session_id, "approved", proposal[2])
            return True

    def ready_folder_change(self, session_id: str) -> bool:
        session_id = _identity(session_id)
        with self._lock:
            proposal = self._folder_change
            if (self._active != session_id or not proposal
                    or proposal[0] != session_id or proposal[1] != "preparing"
                    or time.monotonic() >= proposal[2]):
                return False
            self._folder_change = (session_id, "ready", proposal[2])
            return True

    def reject_folder_change(self, session_id: str) -> None:
        session_id = _identity(session_id)
        with self._lock:
            proposal = self._folder_change
            if (proposal and proposal[0] == session_id
                    and proposal[1] != "committed"):
                self._folder_change = (session_id, "denied", proposal[2])

    def clear(self, session_id: str | None = None) -> None:
        with self._lock:
            if session_id is None or (
                self._folder_change is not None
                and self._folder_change[0] == session_id
            ):
                self._folder_change = None
        super().clear(session_id)

    def stop(self) -> None:
        super().stop()
        with self._lock:
            self._folder_change = None

    def _serve(self, connection: socket.socket) -> None:
        event = None
        session_id = None
        try:
            secure, peer = accept_secure_channel(
                connection, self.identity, self.trust, timeout=self.timeout
            )
            secure.settimeout(self.timeout)
            if peer.node_id != self.peer_id:
                return
            request = _read(secure, REQUESTS | FOLDER_ACTIONS)
            kind = request["type"]
            _expect(request, kind, {"share_id", "session_id"})
            if request["share_id"] != self.share_id:
                return
            session_id = _identity(request["session_id"])
            with self._lock:
                if self._stop.is_set():
                    return
                state, event = self._handle(kind, session_id)
            _send(
                secure, "session_state", share_id=self.share_id,
                session_id=session_id, state=state,
            )
        except Exception:
            return
        finally:
            _close(connection)
            with self._lock:
                self._connections.discard(connection)
                self._workers.discard(threading.current_thread())
            if event is not None and session_id is not None:
                self._notify(event, session_id)


class FolderChangeSessionClient(PeerSessionClient):
    """Uses the existing mutually authenticated session-control endpoint."""

    def request(self, host, port, peer_id, share_id, session_id, action):
        if action in REQUESTS:
            return super().request(
                host, port, peer_id, share_id, session_id, action
            )
        if action not in FOLDER_ACTIONS:
            raise ValueError("Unsupported session action")
        host = _host(host)
        peer_id = _identity(peer_id)
        share_id = _identity(share_id)
        session_id = _identity(session_id)
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("Invalid session control port")
        if (peer_id == self.identity.node_id
                or self.trust.get(peer_id) is None):
            raise SessionControlError("The requested computer is not paired")
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as connection:
                secure, peer = open_secure_channel(
                    connection, self.identity, self.trust, peer_id,
                    timeout=self.timeout,
                )
                if peer.node_id != peer_id:
                    raise SessionControlError("The responding computer is not the paired device")
                secure.settimeout(self.timeout)
                _send(
                    secure, action, share_id=share_id, session_id=session_id
                )
                response = _read(secure, {"session_state"})
                _expect(
                    response, "session_state",
                    {"share_id", "session_id", "state"},
                )
                if (
                    response["share_id"] != share_id
                    or response["session_id"] != session_id
                    or response["state"] not in STATES | FOLDER_STATES
                ):
                    raise SessionControlError("Session reply did not match this connection")
                return response["state"]
        except (OSError, ValueError) as exc:
            raise SessionControlError("The other computer is unavailable") from exc
        except SessionControlError:
            raise
        except Exception as exc:
            raise SessionControlError("Could not authenticate the live connection") from exc
