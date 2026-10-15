
"""Authenticated single-authority operation leases for a paired SyncBridge share.

For two peers, the lexicographically smaller node ID is the sole authority.
Both cooperating initiators must obtain that authority's lease before starting
an operation. Leases use the authority's monotonic clock and are renewed by a
heartbeat. A remote peer can never acquire a lease for an unapproved share.

This is an ADVISORY coordination layer. It is not yet enforced by existing
Transfer/Agreement/Deletion receivers; expired holders are not fenced from
those older protocols. Do NOT enable unattended or destructive operations on
the strength of this module alone. Integration and fencing are separate work.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import math
import secrets
import socket
import struct
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Iterator, Mapping

from syncbridge.network.secure_channel import accept_secure_channel, open_secure_channel
from syncbridge.network.security import DeviceIdentity, TrustStore

LOG = logging.getLogger(__name__)
VERSION = 1
DEFAULT_PORT = 45846
_MAX_FRAME = 2048
_MAX_CONNECTIONS = 8
_OPERATIONS = frozenset({"sync", "deletion", "recovery"})
_HEX = frozenset("0123456789abcdef")


class OperationLockError(RuntimeError):
    """The requested coordinated operation could not begin or continue."""


class OperationBusy(OperationLockError):
    """Another device currently owns the share."""

    def __init__(self, owner: str, operation: str, seconds: float) -> None:
        self.owner = owner
        self.operation = operation
        self.seconds = seconds
        super().__init__(
            f"[SB-OPS-423] Another device ({owner}) is already performing "
            f"'{operation}' on this folder. Wait for it to finish and retry."
        )


class OperationLeaseLost(OperationLockError):
    """The authority cannot confirm continued exclusive ownership."""


@dataclass(frozen=True, slots=True)
class LeaseStatus:
    owner: str | None
    operation: str | None
    seconds_left: float


@dataclass(frozen=True, slots=True)
class LeaseGrant:
    token: str
    seconds_left: float


@dataclass(slots=True)
class _Lease:
    owner: str
    operation: str
    token: str
    deadline: float


def _id(value: str, field: str) -> str:
    if not isinstance(value, str) or len(value) != 32 or any(c not in _HEX for c in value):
        raise ValueError(f"{field} must be a 32-character lowercase hex identifier")
    return value


def _op(value: str) -> str:
    if value not in _OPERATIONS:
        raise ValueError("Operation must be sync, deletion, or recovery")
    return value


def _duration(value: float, field: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{field} must be finite and positive")
    return float(value)


def _exact(stream, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = stream.recv(count - len(data))
        if not chunk:
            raise OperationLockError("The other device closed the coordination connection")
        data.extend(chunk)
    return bytes(data)


def _unique(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("Duplicate coordination field")
        document[key] = value
    return document


def _send(stream, document: dict) -> None:
    data = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(data) > _MAX_FRAME:
        raise OperationLockError("Coordination message is too large")
    stream.sendall(struct.pack("!I", len(data)) + data)


def _receive(stream) -> dict:
    size = struct.unpack("!I", _exact(stream, 4))[0]
    if not 0 < size <= _MAX_FRAME:
        raise OperationLockError("Invalid coordination frame length")
    try:
        document = json.loads(
            _exact(stream, size).decode("utf-8"), object_pairs_hook=_unique,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise OperationLockError("Malformed coordination message") from exc
    if not isinstance(document, dict) or type(document.get("version")) is not int or document["version"] != VERSION:
        raise OperationLockError("Unsupported coordination message")
    return document


def _close(sock) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


class OperationLockService:
    """An in-memory authoritative lease table, one holder per approved share."""

    def __init__(
        self,
        identity: DeviceIdentity,
        trust_store: TrustStore,
        shares: Mapping[str, str],
        *,
        bind_address: str = "127.0.0.1",
        listen_port: int = DEFAULT_PORT,
        lease_seconds: float = 15.0,
        timeout: float = 5.0,
    ) -> None:
        if not isinstance(identity, DeviceIdentity) or not isinstance(trust_store, TrustStore):
            raise TypeError("A real device identity and trust store are required")
        if type(listen_port) is not int or not 0 <= listen_port <= 65535:
            raise ValueError("Invalid coordination port")
        address = ipaddress.IPv4Address(bind_address)
        if address.is_multicast:
            raise ValueError("Multicast coordination binding is not supported")
        lease_seconds = _duration(lease_seconds, "lease_seconds")
        if not 2 <= lease_seconds <= 300:
            raise ValueError("Lease duration must be between 2 and 300 seconds")
        self.identity = identity
        self.trust_store = trust_store
        self.shares = {_id(share, "share_id"): _id(peer, "peer_node_id") for share, peer in shares.items()}
        if any(identity.node_id >= peer for peer in self.shares.values()):
            raise ValueError("Only the lower node ID may be the lease authority")
        self.bind_address = str(address)
        self.listen_port = listen_port
        self.lease_seconds = lease_seconds
        self.timeout = _duration(timeout, "timeout")
        self._lock = threading.RLock()
        self._leases: dict[str, _Lease] = {}
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._port: int | None = None
        self._sockets: set[socket.socket] = set()
        self._threads: set[threading.Thread] = set()

    @property
    def bound_port(self) -> int | None:
        with self._lock:
            return self._port

    def _validate(self, share: str, owner: str) -> None:
        _id(share, "share_id")
        _id(owner, "owner")
        if self.shares.get(share) != owner and owner != self.identity.node_id:
            raise OperationLockError("[SB-OPS-403] Device has no permission for this folder")
        if share not in self.shares:
            raise OperationLockError("[SB-OPS-403] This folder is not authorized")
        if owner != self.identity.node_id and self.trust_store.get(owner) is None:
            raise OperationLockError("[SB-OPS-403] Device is no longer paired")

    def _active(self, share: str) -> _Lease | None:
        record = self._leases.get(share)
        if record is not None and record.deadline <= time.monotonic():
            del self._leases[share]
            return None
        return record

    def _status(self, share: str) -> LeaseStatus:
        record = self._active(share)
        if record is None:
            return LeaseStatus(None, None, 0.0)
        return LeaseStatus(record.owner, record.operation, max(0.0, record.deadline - time.monotonic()))

    def status_local(self, share: str) -> LeaseStatus:
        with self._lock:
            self._validate(share, self.identity.node_id)
            return self._status(share)

    def _acquire(self, share: str, owner: str, operation: str) -> tuple[LeaseGrant | None, LeaseStatus]:
        self._validate(share, owner)
        _op(operation)
        with self._lock:
            if self._active(share) is not None:
                return None, self._status(share)
            token = secrets.token_hex(16)
            self._leases[share] = _Lease(
                owner, operation, token, time.monotonic() + self.lease_seconds
            )
            return LeaseGrant(token, self.lease_seconds), self._status(share)

    def acquire_local(self, share: str, operation: str) -> LeaseGrant:
        granted, busy = self._acquire(share, self.identity.node_id, operation)
        if granted is None:
            raise OperationBusy(busy.owner, busy.operation, busy.seconds_left)
        return granted

    def _renew(self, share: str, owner: str, token: str) -> bool:
        self._validate(share, owner)
        _id(token, "lease token")
        with self._lock:
            active = self._active(share)
            if active is None or active.owner != owner or not secrets.compare_digest(active.token, token):
                return False
            active.deadline = time.monotonic() + self.lease_seconds
            return True

    def renew_local(self, share: str, token: str) -> bool:
        return self._renew(share, self.identity.node_id, token)

    def _release(self, share: str, owner: str, token: str) -> bool:
        self._validate(share, owner)
        _id(token, "lease token")
        with self._lock:
            active = self._active(share)
            if active is None or active.owner != owner or not secrets.compare_digest(active.token, token):
                return False
            del self._leases[share]
            return True

    def release_local(self, share: str, token: str) -> bool:
        return self._release(share, self.identity.node_id, token)

    def _spawn(self, fn, *args):
        def run():
            try:
                fn(*args)
            finally:
                with self._lock:
                    self._threads.discard(threading.current_thread())
        thread = threading.Thread(target=run, daemon=True, name="SyncBridgeOperationLock")
        with self._lock:
            self._threads.add(thread)
        thread.start()

    def start(self) -> None:
        with self._lock:
            if self._listener is not None:
                return
            if self._threads:
                raise RuntimeError("Previous coordination connections are still closing")
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((self.bind_address, self.listen_port))
                listener.listen(_MAX_CONNECTIONS)
                listener.settimeout(0.2)
            except BaseException:
                listener.close()
                raise
            self._listener = listener
            self._port = listener.getsockname()[1]
            self._stop.clear()
            self._spawn(self._accept)

    def stop(self) -> None:
        with self._lock:
            self._stop.set()
            listener, self._listener = self._listener, None
            self._port = None
            sockets, threads = tuple(self._sockets), tuple(self._threads)
        if listener is not None:
            _close(listener)
        for sock in sockets:
            _close(sock)
        for thread in threads:
            if thread is not threading.current_thread():
                thread.join(self.timeout + 1)

    def _accept(self):
        while not self._stop.is_set():
            with self._lock:
                listener = self._listener
            if listener is None:
                return
            try:
                sock, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                accept = not self._stop.is_set() and len(self._sockets) < _MAX_CONNECTIONS
                if accept:
                    self._sockets.add(sock)
            if accept:
                self._spawn(self._serve, sock)
            else:
                _close(sock)

    def _serve(self, sock: socket.socket):
        channel = None
        try:
            channel, peer = accept_secure_channel(
                sock, self.identity, self.trust_store, timeout=self.timeout
            )
            channel.settimeout(self.timeout)
            req = _receive(channel)
            if set(req) != {"version", "type", "action", "share_id", "operation", "token"} or req["type"] != "command":
                raise OperationLockError("Malformed coordination request")
            action = req["action"]
            share = req["share_id"]
            self.trust_store.require(channel.remote_public_key)
            self._validate(share, peer.node_id)
            result_token = None
            granted = False
            if action == "acquire":
                if req["token"] is not None:
                    raise OperationLockError("Acquire must not provide a token")
                grant, _ = self._acquire(share, peer.node_id, req["operation"])
                if grant is not None:
                    result_token, granted = grant.token, True
            elif action in ("renew", "release"):
                if req["operation"] is not None:
                    raise OperationLockError("Renew/release must not provide an operation")
                if action == "renew":
                    granted = self._renew(share, peer.node_id, req["token"])
                else:
                    granted = self._release(share, peer.node_id, req["token"])
            elif action == "status":
                if req["operation"] is not None or req["token"] is not None:
                    raise OperationLockError("Status does not accept a token")
                granted = True
            else:
                raise OperationLockError("Unknown coordination action")
            with self._lock:
                state = self._status(share)
            _send(channel, {
                "version": VERSION, "type": "result", "action": action, "share_id": share,
                "granted": granted, "token": result_token, "owner": state.owner,
                "operation": state.operation, "remaining": state.seconds_left,
            })
        except Exception as exc:
            LOG.debug("Operation coordination refused: %s", exc)
            if channel is not None and not self._stop.is_set():
                try:
                    _send(channel, {"version": VERSION, "type": "error", "message": str(exc)[:180]})
                except Exception:
                    pass
        finally:
            _close(sock)
            with self._lock:
                self._sockets.discard(sock)


class OperationLockClient:
    """Mutually authenticated RPC client for the elected authority."""

    def __init__(self, identity: DeviceIdentity, trust_store: TrustStore, *, timeout: float = 5.0) -> None:
        if not isinstance(identity, DeviceIdentity) or not isinstance(trust_store, TrustStore):
            raise TypeError("A real device identity and trust store are required")
        self.identity = identity
        self.trust_store = trust_store
        self.timeout = _duration(timeout, "timeout")

    def _call(self, host: str, port: int, authority: str, share: str, action: str, *, operation=None, token=None):
        authority, share = _id(authority, "authority"), _id(share, "share_id")
        if authority >= self.identity.node_id:
            raise ValueError("The authority must have the lower node ID")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("Invalid coordination TCP port")
        address = ipaddress.IPv4Address(host)
        if address.is_multicast or address.is_unspecified or str(address) == "255.255.255.255":
            raise ValueError("Coordination host must be a reachable unicast IPv4 address")
        try:
            sock = socket.create_connection((str(address), port), timeout=self.timeout)
        except OSError as exc:
            raise OperationLockError(
                "[SB-OPS-503] Cannot reach the coordination device; no operation was started"
            ) from exc
        try:
            channel, peer = open_secure_channel(
                sock, self.identity, self.trust_store, authority, timeout=self.timeout
            )
            if peer.node_id != authority:
                raise OperationLockError("The wrong device answered the coordination request")
            channel.settimeout(self.timeout)
            _send(channel, {
                "version": VERSION, "type": "command", "action": action,
                "share_id": share, "operation": operation, "token": token,
            })
            reply = _receive(channel)
            if reply.get("type") == "error":
                if set(reply) != {"version", "type", "message"} or not isinstance(reply["message"], str):
                    raise OperationLockError("Malformed coordination error")
                raise OperationLockError(reply["message"])
            required = {"version", "type", "action", "share_id", "granted", "token", "owner", "operation", "remaining"}
            if set(reply) != required or reply["type"] != "result" or reply["action"] != action or reply["share_id"] != share:
                raise OperationLockError("Malformed coordination response")
            if type(reply["granted"]) is not bool:
                raise OperationLockError("Invalid coordination acknowledgement")
            owner, op, returned_token, remaining = reply["owner"], reply["operation"], reply["token"], reply["remaining"]
            if owner is not None:
                _id(owner, "lease owner")
            if op is not None:
                _op(op)
            if (owner is None) != (op is None):
                raise OperationLockError("Inconsistent lease status")
            if returned_token is not None:
                _id(returned_token, "lease token")
            if type(remaining) not in (int, float) or not math.isfinite(remaining) or remaining < 0:
                raise OperationLockError("Invalid lease expiry")
            if action != "acquire" and returned_token is not None:
                raise OperationLockError("Unexpected lease secret in reply")
            return reply
        except (OSError, TimeoutError) as exc:
            raise OperationLockError("[SB-OPS-503] Coordination connection failed; stop this operation") from exc
        finally:
            _close(sock)

    def acquire(self, host: str, port: int, authority: str, share: str, operation: str) -> LeaseGrant:
        reply = self._call(host, port, authority, share, "acquire", operation=_op(operation))
        if not reply["granted"]:
            raise OperationBusy(reply["owner"], reply["operation"], reply["remaining"])
        if reply["token"] is None or reply["owner"] != self.identity.node_id:
            raise OperationLockError("Coordination authority returned an invalid lease")
        return LeaseGrant(reply["token"], reply["remaining"])

    def renew(self, host: str, port: int, authority: str, share: str, token: str) -> bool:
        return self._call(host, port, authority, share, "renew", token=_id(token, "token"))["granted"]

    def release(self, host: str, port: int, authority: str, share: str, token: str) -> bool:
        return self._call(host, port, authority, share, "release", token=_id(token, "token"))["granted"]

    def status(self, host: str, port: int, authority: str, share: str) -> LeaseStatus:
        data = self._call(host, port, authority, share, "status")
        return LeaseStatus(data["owner"], data["operation"], data["remaining"])


class LeaseGuard:
    """Context-owned heartbeat; callers should call check() before critical steps."""

    def __init__(self, grant: LeaseGrant, renew: Callable[[str], bool], release: Callable[[str], bool]):
        self.token = grant.token
        self._renew = renew
        self._release = release
        self._interval = max(0.2, grant.seconds_left / 3)
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._thread = threading.Thread(target=self._heartbeat, name="SyncBridgeLeaseHeartbeat", daemon=True)
        self._closed = False

    def start(self):
        self._thread.start()
        return self

    def _heartbeat(self):
        while not self._stop.wait(self._interval):
            try:
                if not self._renew(self.token):
                    self._lost.set()
                    return
            except Exception:
                self._lost.set()
                return

    def check(self) -> None:
        if self._lost.is_set():
            raise OperationLeaseLost(
                "[SB-OPS-409] This computer lost coordination permission. "
                "Stop modifying the folder and retry after checking both devices."
            )
        if self._closed:
            raise OperationLeaseLost("[SB-OPS-409] The coordination lease was already released")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=self._interval + 1)
        try:
            self._release(self.token)
        except Exception:
            # TTL expiry is the last-resort cleanup mechanism.
            LOG.warning("Could not release coordination lease; it will expire")


class LeaseCoordinator:
    """Elect the lower node ID and hold one cooperative share-scoped lease."""

    def __init__(
        self,
        identity: DeviceIdentity,
        peer_node_id: str,
        share_id: str,
        *,
        client: OperationLockClient | None = None,
        local_service: OperationLockService | None = None,
        host: str = "127.0.0.1",
        port: int = DEFAULT_PORT,
    ) -> None:
        self.identity = identity
        self.peer_node_id = _id(peer_node_id, "peer_node_id")
        self.share_id = _id(share_id, "share_id")
        if self.peer_node_id == identity.node_id:
            raise ValueError("Peer cannot be the local device")
        self.authority = min(identity.node_id, self.peer_node_id)
        self.client = client
        self.local_service = local_service
        self.host, self.port = host, port
        if self.authority == identity.node_id:
            if local_service is None or local_service.identity.node_id != identity.node_id:
                raise ValueError("The authority must supply its own local lease service")
        elif client is None or client.identity.node_id != identity.node_id:
            raise ValueError("The other device requires an authenticated lease client")

    @contextmanager
    def hold(self, operation: str) -> Iterator[LeaseGuard]:
        _op(operation)
        if self.authority == self.identity.node_id:
            service = self.local_service
            grant = service.acquire_local(self.share_id, operation)
            renew = lambda token: service.renew_local(self.share_id, token)
            release = lambda token: service.release_local(self.share_id, token)
        else:
            client = self.client
            args = (self.host, self.port, self.authority, self.share_id)
            grant = client.acquire(*args, operation)
            renew = lambda token: client.renew(*args, token)
            release = lambda token: client.release(*args, token)
        guard = LeaseGuard(grant, renew, release)
        try:
            guard.start()
            yield guard
            guard.check()
        finally:
            guard.close()
