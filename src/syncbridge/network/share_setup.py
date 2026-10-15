
"""Explicit folder setup between trusted devices over encrypted TCP.

Both users choose their own folders. The resulting ShareConfig on each
device is DISABLED with all grants False. No files are transferred.

Interrupted setup may leave a disabled entry on one or both computers.
That is safe but needs reconciliation before a later activation step.
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
import select
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

from syncbridge.network.secure_channel import (
    accept_secure_channel,
    open_secure_channel,
)
from syncbridge.network.security import (
    DeviceIdentity,
    SecurityError,
    TrustStore,
)
from syncbridge.storage.config import (
    AppConfig,
    ConfigStore,
    ShareConfig,
)


SETUP_PORT = 45845
_MAX_FRAME = 2048
_VERSION = 1

# Manifest, transfer, and agreement ports, in that order.
_DEFAULT_PORTS = (45843, 45842, 45844)


class ShareSetupError(RuntimeError):
    """A folder proposal was rejected, unsafe, or interrupted."""


def _ports(value: Any) -> tuple[int, int, int]:
    if (
        not isinstance(value, (tuple, list))
        or len(value) != 3
        or any(
            type(port) is not int
            or not 1 <= port <= 65535
            for port in value
        )
        or len(set(value)) != 3
    ):
        raise ShareSetupError(
            "Three distinct valid TCP ports are required"
        )
    return tuple(value)


def _label(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ShareSetupError("Choose a nonempty share name")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ShareSetupError("Invalid share name") from exc
    if (
        size > 96
        or any(
            ord(c) < 32 or ord(c) == 127
            for c in value
        )
    ):
        raise ShareSetupError(
            "Share name is too long or contains control characters"
        )
    return value


def _id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 32
        or any(
            c not in "0123456789abcdef"
            for c in value
        )
    ):
        raise ShareSetupError("Invalid share identifier")
    return value


def _host(value: Any) -> str:
    if not isinstance(value, str):
        raise ShareSetupError(
            "A numeric IPv4 peer address is required"
        )
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise ShareSetupError(
            "A numeric IPv4 peer address is required"
        ) from exc

    if (
        address.is_unspecified
        or address.is_multicast
        or str(address) == "255.255.255.255"
    ):
        raise ShareSetupError(
            "A unicast peer address is required"
        )
    return str(address)


def _folder(value: str | Path, config_path: Path) -> Path:
    candidate = Path(value).expanduser()
    if candidate.is_symlink() or (
        hasattr(os.path, "isjunction")
        and os.path.isjunction(candidate)
    ):
        raise ShareSetupError(
            "Cannot synchronize a folder link or junction"
        )

    root = candidate.resolve(strict=True)
    if not root.is_dir():
        raise ShareSetupError("Choose an existing directory")

    profile = config_path.parent.resolve()
    if (
        root == profile
        or root in profile.parents
        or profile in root.parents
    ):
        raise ShareSetupError(
            "The shared folder cannot contain or be inside the profile"
        )

    if len(root.parts) <= 1:
        raise ShareSetupError(
            "Cannot share a filesystem root"
        )
    return root


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(
                "Duplicate share setup field"
            )
        result[key] = value
    return result


def _send(secure, kind: str, **fields) -> None:
    payload = json.dumps(
        {
            "version": _VERSION,
            "type": kind,
            **fields,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

    if len(payload) > _MAX_FRAME:
        raise ShareSetupError(
            "Share setup message too large"
        )

    secure.sendall(
        struct.pack("!I", len(payload)) + payload
    )


def _exact(secure, amount: int) -> bytes:
    result = bytearray()
    while len(result) < amount:
        piece = secure.recv(
            amount - len(result)
        )
        if not piece:
            raise ShareSetupError(
                "Share setup connection closed"
            )
        result.extend(piece)
    return bytes(result)


def _recv(
    secure,
    expected: dict[str, set[str]],
) -> tuple[str, dict]:
    (length,) = struct.unpack(
        "!I", _exact(secure, 4)
    )
    if not 0 < length <= _MAX_FRAME:
        raise ShareSetupError(
            "Invalid share setup message length"
        )

    try:
        data = json.loads(
            _exact(secure, length).decode("utf-8"),
            object_pairs_hook=_unique,
            parse_constant=lambda value: (
                _ for _ in ()
            ).throw(ValueError(value)),
        )
    except (
        ValueError,
        UnicodeError,
        RecursionError,
    ) as exc:
        raise ShareSetupError(
            "Malformed share setup message"
        ) from exc

    if (
        not isinstance(data, dict)
        or type(data.get("version")) is not int
        or data["version"] != _VERSION
    ):
        raise ShareSetupError(
            "Unexpected share setup protocol version"
        )

    kind = data.get("type")
    if (
        not isinstance(kind, str)
        or kind not in expected
        or set(data)
        != expected[kind] | {"version", "type"}
    ):
        raise ShareSetupError(
            "Unexpected share setup message"
        )
    return kind, data


def _save_disabled(
    store: ConfigStore,
    *,
    share_id: str,
    peer_id: str,
    root: Path,
    name: str,
    peer_host: str,
    peer_ports: tuple[int, int, int],
) -> ShareConfig:
    """Save one share with every file permission disabled."""
    share = ShareConfig(
        share_id=_id(share_id),
        peer_node_id=_id(peer_id),
        local_root=str(
            _folder(root, store.path)
        ),
        display_name=_label(name),
        remote_host=_host(peer_host),
        manifest_port=peer_ports[0],
        transfer_port=peer_ports[1],
        agreement_port=peer_ports[2],
        enabled=False,
        grant_manifest=False,
        grant_read=False,
        grant_write=False,
        grant_agreement=False,
    )

    existing = store.load()

    if existing.get_share(share_id) is not None:
        raise ShareSetupError(
            "This share ID already exists; no settings overwritten"
        )

    store.save(
        AppConfig(
            revision=existing.revision,
            device_name=existing.device_name,
            shares=(
                *existing.shares,
                share,
            ),
        )
    )
    return share


@dataclass(frozen=True, slots=True)
class IncomingShareRequest:
    request_id: str
    share_id: str
    peer_node_id: str
    peer_name: str
    display_name: str
    peer_address: str
    peer_ports: tuple[int, int, int]


@dataclass(slots=True)
class _Pending:
    details: IncomingShareRequest
    decision: threading.Event = field(
        default_factory=threading.Event
    )
    folder: Path | None = None
    local_ports: tuple[int, int, int] | None = None
    denied: bool = False


class ShareSetupSession:
    """Outgoing request awaiting the other user's folder approval."""

    def __init__(
        self,
        secure,
        sock: socket.socket,
        store: ConfigStore,
        *,
        share_id: str,
        peer_id: str,
        trust: TrustStore,
        local_root: Path,
        name: str,
        remote_host: str,
        approval_timeout: float,
    ):
        self.secure = secure
        self.sock = sock
        self.store = store
        self.share_id = share_id
        self.peer_id = peer_id
        self.trust = trust
        self.local_root = local_root
        self.name = name
        self.remote_host = remote_host
        self.approval_timeout = approval_timeout
        self._finished = False

    def wait(self) -> ShareConfig:
        """Wait for approval and persist a disabled share.

        Call from a worker thread, not Tkinter's UI thread.
        """
        if self._finished:
            raise ShareSetupError(
                "This share setup request is already finished"
            )

        try:
            self.secure.settimeout(
                self.approval_timeout + 10
            )

            kind, reply = _recv(
                self.secure,
                {
                    "approved": {
                        "share_id",
                        "ports",
                    },
                    "rejected": set(),
                },
            )

            if kind == "rejected":
                raise ShareSetupError(
                    "The other device declined or timed out"
                )

            if _id(reply["share_id"]) != self.share_id:
                raise ShareSetupError(
                    "Share ID changed during approval"
                )

            if self.trust.get(self.peer_id) is None:
                raise ShareSetupError(
                    "The remote device is no longer paired"
                )

            remote_ports = _ports(
                reply["ports"]
            )

            saved = _save_disabled(
                self.store,
                share_id=self.share_id,
                peer_id=self.peer_id,
                root=self.local_root,
                name=self.name,
                peer_host=self.remote_host,
                peer_ports=remote_ports,
            )

            _send(
                self.secure,
                "stored",
                share_id=self.share_id,
            )

            _, complete = _recv(
                self.secure,
                {
                    "complete": {
                        "share_id",
                    }
                },
            )

            if _id(complete["share_id"]) != self.share_id:
                raise ShareSetupError(
                    "Mismatched completion receipt"
                )

            return saved

        except (
            OSError,
            TimeoutError,
            ValueError,
        ) as exc:
            raise ShareSetupError(
                "Share setup failed; inspect disabled entries before retrying"
            ) from exc

        finally:
            self.close()

    def cancel(self) -> None:
        self.close()

    def close(self) -> None:
        self._finished = True
        self.secure.close()
        self.sock.close()


class ShareSetupClient:
    """Request a folder relationship with one trusted device."""

    def __init__(
        self,
        identity: DeviceIdentity,
        trust: TrustStore,
        store: ConfigStore,
    ):
        self.identity = identity
        self.trust = trust
        self.store = store

    def request(
        self,
        host: str,
        peer_id: str,
        local_root: str | Path,
        display_name: str,
        *,
        port: int = SETUP_PORT,
        local_ports: tuple[int, int, int] = _DEFAULT_PORTS,
        connect_timeout: float = 5,
        approval_timeout: float = 60,
    ) -> ShareSetupSession:
        host = _host(host)
        root = _folder(
            local_root,
            self.store.path,
        )
        name = _label(display_name)
        ports = _ports(local_ports)

        if (
            type(port) is not int
            or not 1 <= port <= 65535
        ):
            raise ValueError(
                "Invalid share setup port"
            )

        if any(
            type(t) not in (int, float)
            or not math.isfinite(t)
            or not 0 < t <= 300
            for t in (
                connect_timeout,
                approval_timeout,
            )
        ):
            raise ValueError(
                "Invalid timeout"
            )

        if self.trust.get(peer_id) is None:
            raise ShareSetupError(
                "Device must be paired before sharing a folder"
            )

        share_id = uuid4().hex

        # Validate overlaps before sending a remote request.
        current = self.store.load()

        proposed = ShareConfig(
            share_id=share_id,
            peer_node_id=_id(peer_id),
            local_root=str(root),
            display_name=name,
            remote_host=host,
            manifest_port=ports[0],
            transfer_port=ports[1],
            agreement_port=ports[2],
        )

        AppConfig(
            revision=current.revision,
            device_name=current.device_name,
            shares=(
                *current.shares,
                proposed,
            ),
        )

        sock = socket.create_connection(
            (host, port),
            timeout=connect_timeout,
        )

        try:
            secure, authenticated = open_secure_channel(
                sock,
                self.identity,
                self.trust,
                peer_id,
                timeout=connect_timeout,
            )

            secure.settimeout(
                connect_timeout
            )

            _send(
                secure,
                "offer",
                share_id=share_id,
                name=name,
                ports=list(ports),
            )

            _, reply = _recv(
                secure,
                {
                    "queued": {
                        "share_id",
                    }
                },
            )

            if _id(reply["share_id"]) != share_id:
                raise ShareSetupError(
                    "Share request acknowledgement mismatch"
                )

            return ShareSetupSession(
                secure,
                sock,
                self.store,
                share_id=share_id,
                peer_id=authenticated.node_id,
                trust=self.trust,
                local_root=root,
                name=name,
                remote_host=host,
                approval_timeout=approval_timeout,
            )

        except BaseException:
            sock.close()
            raise


class ShareSetupService:
    """Receive trusted requests and wait for explicit folder selection."""

    def __init__(
        self,
        identity: DeviceIdentity,
        trust: TrustStore,
        store: ConfigStore,
        *,
        bind_address: str = "127.0.0.1",
        port: int = SETUP_PORT,
        approval_timeout: float = 60,
        max_pending: int = 8,
    ) -> None:
        if (
            type(port) is not int
            or not 0 <= port <= 65535
        ):
            raise ValueError(
                "Invalid setup listening port"
            )

        if bind_address != "0.0.0.0":
            _host(bind_address)

        if (
            type(approval_timeout)
            not in (int, float)
            or not math.isfinite(approval_timeout)
            or not 0 < approval_timeout <= 300
        ):
            raise ValueError(
                "Invalid approval timeout"
            )

        if (
            type(max_pending) is not int
            or not 1 <= max_pending <= 16
        ):
            raise ValueError(
                "Invalid pending limit"
            )

        self.identity = identity
        self.trust = trust
        self.store = store
        self.bind_address = bind_address
        self.port = port
        self.approval_timeout = approval_timeout
        self.max_pending = max_pending
        self.bound_port: int | None = None

        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._sockets: set[socket.socket] = set()
        self._workers: set[threading.Thread] = set()
        self._pending: dict[str, _Pending] = {}

    def start(self) -> None:
        with self._lock:
            if (
                self._thread is not None
                and self._thread.is_alive()
            ):
                if self._stop.is_set():
                    raise RuntimeError(
                        "Share setup listener is still shutting down"
                    )
                return

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM,
            )

            try:
                sock.bind(
                    (
                        self.bind_address,
                        self.port,
                    )
                )
                sock.listen(16)
                sock.settimeout(0.2)
            except BaseException:
                sock.close()
                raise

            self._listener = sock
            self.bound_port = sock.getsockname()[1]
            self._stop.clear()

            self._thread = threading.Thread(
                target=self._accept,
                daemon=True,
                name="ShareSetupListener",
            )
            self._thread.start()

    def pending(self) -> tuple[IncomingShareRequest, ...]:
        with self._lock:
            return tuple(
                request.details
                for request in self._pending.values()
            )

    def approve(
        self,
        request_id: str,
        folder: str | Path,
        *,
        local_ports: tuple[int, int, int] = _DEFAULT_PORTS,
    ) -> None:
        # The receiver must choose their own directory.
        root = _folder(
            folder,
            self.store.path,
        )
        ports = _ports(local_ports)

        with self._lock:
            pending = self._pending.get(
                request_id
            )

            if (
                pending is None
                or pending.decision.is_set()
            ):
                raise ShareSetupError(
                    "Unknown or already decided request"
                )

            config = self.store.load()

            if (
                config.get_share(
                    pending.details.share_id
                )
                is not None
            ):
                raise ShareSetupError(
                    "Share ID already exists"
                )

            # AppConfig verifies that the chosen folder
            # doesn't overlap an existing shared folder.
            proposed = ShareConfig(
                share_id=pending.details.share_id,
                peer_node_id=pending.details.peer_node_id,
                local_root=str(root),
                display_name=pending.details.display_name,
                remote_host=pending.details.peer_address,
                manifest_port=pending.details.peer_ports[0],
                transfer_port=pending.details.peer_ports[1],
                agreement_port=pending.details.peer_ports[2],
            )

            AppConfig(
                revision=config.revision,
                device_name=config.device_name,
                shares=(
                    *config.shares,
                    proposed,
                ),
            )

            pending.folder = root
            pending.local_ports = ports
            pending.decision.set()

    def reject(self, request_id: str) -> None:
        with self._lock:
            pending = self._pending.get(
                request_id
            )

            if (
                pending is None
                or pending.decision.is_set()
            ):
                raise ShareSetupError(
                    "Unknown or already decided request"
                )

            pending.denied = True
            pending.decision.set()

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                listener = self._listener
                if listener is None:
                    return

                sock, address = listener.accept()

            except socket.timeout:
                continue
            except OSError:
                return

            with self._lock:
                if (
                    len(self._sockets)
                    >= self.max_pending + 4
                ):
                    sock.close()
                    continue

                self._sockets.add(sock)
                worker = threading.Thread(
                    target=self._handle,
                    args=(
                        sock,
                        address[0],
                    ),
                    daemon=True,
                    name="ShareSetupRequest",
                )
                self._workers.add(worker)

            worker.start()

    def _await_decision(
        self,
        sock: socket.socket,
        pending: _Pending,
    ) -> bool:
        """Reject abandoned connections while waiting for approval."""
        deadline = (
            time.monotonic()
            + self.approval_timeout
        )

        while (
            not pending.decision.is_set()
            and not self._stop.is_set()
        ):
            remaining = (
                deadline - time.monotonic()
            )

            if remaining <= 0:
                return False

            if pending.decision.wait(
                timeout=min(0.1, remaining)
            ):
                break

            try:
                readable, _, _ = select.select(
                    [sock],
                    [],
                    [],
                    0,
                )

                # No client traffic is allowed before approval.
                # A disconnect or unexpected input abandons the request.
                if readable:
                    return False

            except (OSError, ValueError):
                return False

        return (
            pending.decision.is_set()
            and not pending.denied
            and not self._stop.is_set()
        )

    def _handle(
        self,
        sock: socket.socket,
        observed_host: str,
    ) -> None:
        request_id = None
        secure = None

        try:
            sock.settimeout(5)

            secure, authenticated = accept_secure_channel(
                sock,
                self.identity,
                self.trust,
                timeout=5,
            )
            secure.settimeout(5)

            _, offer = _recv(
                secure,
                {
                    "offer": {
                        "share_id",
                        "name",
                        "ports",
                    }
                },
            )

            share_id = _id(offer["share_id"])
            name = _label(offer["name"])
            ports = _ports(offer["ports"])

            if (
                self.store.load().get_share(
                    share_id
                )
                is not None
            ):
                raise ShareSetupError(
                    "Share identifier already registered"
                )

            request_id = uuid4().hex

            request = _Pending(
                IncomingShareRequest(
                    request_id,
                    share_id,
                    authenticated.node_id,
                    authenticated.name,
                    name,
                    _host(observed_host),
                    ports,
                )
            )

            with self._lock:
                if (
                    self._stop.is_set()
                    or len(self._pending)
                    >= self.max_pending
                ):
                    raise ShareSetupError(
                        "No approval capacity"
                    )

                self._pending[
                    request_id
                ] = request

            _send(
                secure,
                "queued",
                share_id=share_id,
            )

            approved = self._await_decision(
                sock,
                request,
            )

            if not approved:
                try:
                    _send(
                        secure,
                        "rejected",
                    )
                except OSError:
                    pass
                return

            # A cancellation that arrives before persistence
            # must not create a share.
            readable, _, _ = select.select(
                [sock],
                [],
                [],
                0,
            )
            if readable:
                return

            if (
                self.trust.get(
                    authenticated.node_id
                )
                is None
            ):
                raise ShareSetupError(
                    "Device trust was revoked"
                )

            assert request.folder is not None
            assert request.local_ports is not None

            _save_disabled(
                self.store,
                share_id=share_id,
                peer_id=authenticated.node_id,
                root=request.folder,
                name=name,
                peer_host=observed_host,
                peer_ports=ports,
            )

            secure.settimeout(10)

            _send(
                secure,
                "approved",
                share_id=share_id,
                ports=list(
                    request.local_ports
                ),
            )

            _, stored = _recv(
                secure,
                {
                    "stored": {
                        "share_id",
                    }
                },
            )

            if (
                _id(stored["share_id"])
                != share_id
            ):
                raise ShareSetupError(
                    "Incorrect stored acknowledgement"
                )

            _send(
                secure,
                "complete",
                share_id=share_id,
            )

        except (
            OSError,
            ValueError,
            ShareSetupError,
            SecurityError,
        ):
            # Any incomplete exchange fails closed.
            # Disabled partial records cannot transfer files.
            pass

        finally:
            with self._lock:
                if request_id is not None:
                    self._pending.pop(
                        request_id,
                        None,
                    )

                self._sockets.discard(sock)
                self._workers.discard(
                    threading.current_thread()
                )

            if secure is not None:
                secure.close()
            sock.close()

    def stop(self) -> None:
        with self._lock:
            self._stop.set()

            listener = self._listener
            self._listener = None
            self.bound_port = None

            sockets = tuple(
                self._sockets
            )
            workers = tuple(
                self._workers
            )
            thread = self._thread

            for pending in self._pending.values():
                pending.denied = True
                pending.decision.set()

        if listener is not None:
            listener.close()

        for sock in sockets:
            try:
                sock.shutdown(
                    socket.SHUT_RDWR
                )
            except OSError:
                pass
            sock.close()

        if (
            thread is not None
            and thread
            is not threading.current_thread()
        ):
            thread.join(
                timeout=2
            )

        for worker in workers:
            if (
                worker
                is not threading.current_thread()
            ):
                worker.join(
                    timeout=2
                )
