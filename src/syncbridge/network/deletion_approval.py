
"""Authenticated, persistent deletion approval requests for SyncBridge.

This module never deletes, moves, or modifies synchronized files.
The remote peer can REQUEST consent, but only a LOCAL call to decide()
can approve or decline it.

Requests are bound to:
- The authenticated peer and share.
- A committed shared baseline revision and SHA-256.
- A specific file path, size, and content SHA-256.

Phase 18 will implement backup-first deletion and recovery after consent.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import math
import os
import socket
import sqlite3
import struct
import threading

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping
from uuid import uuid4

from syncbridge.core.scanner import FileScanner
from syncbridge.network.secure_channel import (
    accept_secure_channel,
    open_secure_channel,
)
from syncbridge.network.security import (
    DeviceIdentity,
    SecurityError,
    TrustStore,
)
from syncbridge.storage.shared_state import (
    SharedStateDatabase,
    _validate_path,
)

LOG = logging.getLogger(__name__)

VERSION = 1
DEFAULT_PORT = 45845
_MAX_FRAME = 4096
_MAX_CONNECTIONS = 8
_HEX = frozenset("0123456789abcdef")
_STATES = frozenset(("pending", "approved", "declined"))


class DeletionApprovalError(RuntimeError):
    """A deletion request was refused or cannot safely be approved."""


def _identifier(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 32
        or any(c not in _HEX for c in value)
    ):
        raise ValueError(
            f"{label} must be 32 lowercase hex characters"
        )

    return value


def _digest(value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(c not in _HEX for c in value)
    ):
        raise ValueError(
            "SHA-256 must be 64 lowercase hex characters"
        )

    return value


def _revision(value: int) -> int:
    if (
        type(value) is not int
        or not 1 <= value < 2**63 - 1
    ):
        raise ValueError(
            "A committed baseline revision is required"
        )

    return value


def _file_size(value: int) -> int:
    if (
        type(value) is not int
        or not 0 <= value <= 2**63 - 1
    ):
        raise ValueError("Invalid file size")

    return value


def _timeout(value: float) -> float:
    if (
        type(value) not in (int, float)
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError(
            "Timeout must be finite and positive"
        )

    return float(value)


def _root(value: str | Path) -> Path:
    root = Path(value).expanduser()

    if root.is_symlink() or (
        hasattr(os.path, "isjunction")
        and os.path.isjunction(root)
    ):
        raise ValueError(
            "A share root cannot be a symbolic link or junction"
        )

    resolved = root.resolve(strict=True)

    if not resolved.is_dir():
        raise NotADirectoryError(resolved)

    return resolved


def _unique(pairs):
    output = {}

    for key, value in pairs:
        if key in output:
            raise ValueError("Duplicate JSON key")

        output[key] = value

    return output


def _send(channel, kind: str, **kwargs) -> None:
    payload = json.dumps(
        {
            "version": VERSION,
            "type": kind,
            **kwargs,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

    if len(payload) > _MAX_FRAME:
        raise DeletionApprovalError(
            "Approval message too large"
        )

    channel.sendall(
        struct.pack("!I", len(payload)) + payload
    )


def _exact(channel, length: int) -> bytes:
    received = bytearray()

    while len(received) < length:
        block = channel.recv(
            length - len(received)
        )

        if not block:
            raise DeletionApprovalError(
                "Approval connection closed"
            )

        received.extend(block)

    return bytes(received)


def _read(channel, kinds: set[str]) -> dict:
    (length,) = struct.unpack(
        "!I",
        _exact(channel, 4),
    )

    if not 0 < length <= _MAX_FRAME:
        raise DeletionApprovalError(
            "Invalid approval frame size"
        )

    try:
        data = json.loads(
            _exact(channel, length).decode("utf-8"),
            object_pairs_hook=_unique,
            parse_constant=lambda constant: (
                _ for _ in ()
            ).throw(ValueError(constant)),
        )

    except (
        ValueError,
        UnicodeError,
        RecursionError,
    ) as exc:
        raise DeletionApprovalError(
            "Invalid approval message"
        ) from exc

    if (
        not isinstance(data, dict)
        or type(data.get("version")) is not int
        or data["version"] != VERSION
        or data.get("type") not in kinds
    ):
        raise DeletionApprovalError(
            "Unexpected approval message"
        )

    return data


def _shape(
    data: dict,
    kind: str,
    fields: set[str],
) -> None:
    if (
        data["type"] != kind
        or set(data) != fields | {"version", "type"}
    ):
        raise DeletionApprovalError(
            f"Malformed {kind} message"
        )


def _close(sock) -> None:
    try:
        sock.shutdown(
            socket.SHUT_RDWR
        )
    except OSError:
        pass

    try:
        sock.close()
    except OSError:
        pass


@dataclass(frozen=True, slots=True)
class DeletionRequest:
    request_id: str
    share_id: str
    peer_node_id: str
    path: str
    baseline_revision: int
    baseline_sha256: str
    file_sha256: str
    file_size: int
    state: str


@dataclass(frozen=True, slots=True)
class ApprovalNotice:
    code: str
    title: str
    explanation: str
    next_step: str


def describe_status(
    state: str,
    other_device: str,
) -> ApprovalNotice:
    """Translate protocol status into user-facing language."""

    if (
        not isinstance(other_device, str)
        or not other_device.strip()
        or len(other_device) > 70
    ):
        raise ValueError(
            "A readable device name is required"
        )

    device = other_device.strip()

    messages = {
        "pending": ApprovalNotice(
            "SB-DEL-104",
            f"Waiting for {device} to review the deletion",
            f"{device} has not approved removing the file "
            "from both computers. Nothing has been deleted "
            "by this request.",
            f"Ask the person using {device} to open their "
            "deletion requests and choose Approve or Decline.",
        ),
        "approved": ApprovalNotice(
            "SB-DEL-107",
            f"{device} approved the deletion request",
            "Both users' intentions can now be checked "
            "before a recoverable deletion. This approval "
            "has NOT deleted any files.",
            "Keep the file unchanged. The backup-first "
            "deletion operation will be added in the next phase.",
        ),
        "declined": ApprovalNotice(
            "SB-DEL-105",
            f"{device} declined the deletion",
            "The other person chose to keep their copy. "
            "SyncBridge has not changed the file.",
            "Use Restore or discuss which version should "
            "be kept. A declined request cannot be reused.",
        ),
        "stale": ApprovalNotice(
            "SB-DEL-106",
            "Deletion approval is no longer valid",
            "The file or shared synchronization history "
            "changed after the request. Old approval "
            "cannot be trusted.",
            "Refresh the file review; only create a new "
            "request after checking the current file.",
        ),
    }

    if state not in messages:
        raise ValueError(
            "Unknown deletion approval status"
        )

    return messages[state]


class DeletionApprovalStore:
    """Durable request inbox, containing no secrets or file contents."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with self._connect() as db:
            db.execute(
                "PRAGMA journal_mode=WAL"
            )

            db.execute(
                """
                CREATE TABLE IF NOT EXISTS deletion_requests (
                    root TEXT NOT NULL,
                    share_id TEXT NOT NULL,
                    peer_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    path TEXT NOT NULL,
                    baseline_revision INTEGER NOT NULL,
                    baseline_sha256 TEXT NOT NULL,
                    file_sha256 TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    state TEXT NOT NULL
                        CHECK(state IN ('pending','approved','declined')),
                    PRIMARY KEY(root, share_id, peer_id, request_id)
                )
                """
            )

    def _connect(self):
        db = sqlite3.connect(
            self.path,
            timeout=10,
        )
        db.row_factory = sqlite3.Row
        db.execute(
            "PRAGMA busy_timeout=10000"
        )

        return db

    @staticmethod
    def _key(
        root: Path,
        peer: str,
        share: str,
    ):
        return (
            str(root),
            _identifier(share, "share_id"),
            _identifier(peer, "peer_node_id"),
        )

    @staticmethod
    def _request(row):
        return DeletionRequest(
            row["request_id"],
            row["share_id"],
            row["peer_id"],
            row["path"],
            row["baseline_revision"],
            row["baseline_sha256"],
            row["file_sha256"],
            row["file_size"],
            row["state"],
        )

    def submit(
        self,
        root: Path,
        peer: str,
        share: str,
        request_id: str,
        path: str,
        revision: int,
        baseline_sha256: str,
        file_sha256: str,
        size: int,
    ) -> DeletionRequest:

        key = self._key(
            root,
            peer,
            share,
        )

        _identifier(request_id, "request_id")
        _validate_path(path)
        _revision(revision)
        _digest(baseline_sha256)
        _digest(file_sha256)
        _file_size(size)

        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")

            old = db.execute(
                """
                SELECT * FROM deletion_requests
                WHERE root=? AND share_id=?
                  AND peer_id=? AND request_id=?
                """,
                (*key, request_id),
            ).fetchone()

            if old is not None:
                existing = self._request(old)

                if (
                    existing.path,
                    existing.baseline_revision,
                    existing.baseline_sha256,
                    existing.file_sha256,
                    existing.file_size,
                ) != (
                    path,
                    revision,
                    baseline_sha256,
                    file_sha256,
                    size,
                ):
                    raise DeletionApprovalError(
                        "Request ID has different file "
                        "or baseline details"
                    )

                return existing

            current = db.execute(
                """
                SELECT COUNT(*) FROM deletion_requests
                WHERE root=? AND share_id=?
                  AND peer_id=? AND state != 'declined'
                """,
                key,
            ).fetchone()[0]

            if current >= 50:
                raise DeletionApprovalError(
                    "Too many outstanding deletion requests"
                )

            db.execute(
                """
                INSERT INTO deletion_requests
                    (root, share_id, peer_id, request_id,
                     path, baseline_revision, baseline_sha256,
                     file_sha256, file_size, state)
                VALUES (?,?,?,?,?,?,?,?,?,'pending')
                """,
                (
                    *key,
                    request_id,
                    path,
                    revision,
                    baseline_sha256,
                    file_sha256,
                    size,
                ),
            )

        item = self.get(
            root,
            peer,
            share,
            request_id,
        )

        assert item is not None
        return item

    def get(
        self,
        root: Path,
        peer: str,
        share: str,
        request_id: str,
    ) -> DeletionRequest | None:

        key = self._key(
            root,
            peer,
            share,
        )

        _identifier(request_id, "request_id")

        with self._connect() as db:
            row = db.execute(
                """
                SELECT * FROM deletion_requests
                WHERE root=? AND share_id=?
                  AND peer_id=? AND request_id=?
                """,
                (*key, request_id),
            ).fetchone()

        return (
            None
            if row is None
            else self._request(row)
        )

    def list_requests(
        self,
        root: Path,
        peer: str,
        share: str,
    ) -> tuple[DeletionRequest, ...]:

        key = self._key(
            root,
            peer,
            share,
        )

        with self._connect() as db:
            rows = db.execute(
                """
                SELECT * FROM deletion_requests
                WHERE root=? AND share_id=? AND peer_id=?
                ORDER BY path, request_id
                """,
                key,
            ).fetchall()

        return tuple(
            self._request(row)
            for row in rows
        )

    def decide(
        self,
        root: Path,
        peer: str,
        share: str,
        request_id: str,
        *,
        approve: bool,
    ) -> DeletionRequest:

        if type(approve) is not bool:
            raise TypeError(
                "approve must be bool"
            )

        key = self._key(
            root,
            peer,
            share,
        )

        _identifier(request_id, "request_id")

        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")

            row = db.execute(
                """
                SELECT * FROM deletion_requests
                WHERE root=? AND share_id=?
                  AND peer_id=? AND request_id=?
                """,
                (*key, request_id),
            ).fetchone()

            if row is None:
                raise DeletionApprovalError(
                    "Deletion request not found"
                )

            request = self._request(row)

            target = (
                "approved"
                if approve
                else "declined"
            )

            if (
                request.state != "pending"
                and request.state != target
            ):
                raise DeletionApprovalError(
                    "This request was already decided; "
                    "use a new request"
                )

            if request.state == "pending":
                db.execute(
                    """
                    UPDATE deletion_requests
                    SET state=?
                    WHERE root=? AND share_id=?
                      AND peer_id=? AND request_id=?
                    """,
                    (
                        target,
                        *key,
                        request_id,
                    ),
                )

        updated = self.get(
            root,
            peer,
            share,
            request_id,
        )

        assert updated is not None
        return updated


class DeletionApprovalService:
    """Authenticated deletion-consent inbox for approved shares."""

    def __init__(
        self,
        identity: DeviceIdentity,
        trust_store: TrustStore,
        shared_state: SharedStateDatabase,
        store: DeletionApprovalStore,
        shares: Mapping[str, Path | str],
        *,
        allowed_requesters: Mapping[
            str, Iterable[str]
        ] | None = None,
        bind_address: str = "127.0.0.1",
        listen_port: int = DEFAULT_PORT,
        handshake_timeout: float = 5.0,
        io_timeout: float = 30.0,
    ) -> None:

        if (
            not isinstance(identity, DeviceIdentity)
            or not isinstance(trust_store, TrustStore)
        ):
            raise TypeError(
                "Identity and trust store required"
            )

        if (
            not isinstance(shared_state, SharedStateDatabase)
            or not isinstance(store, DeletionApprovalStore)
        ):
            raise TypeError(
                "Shared state and deletion approval store required"
            )

        if (
            type(listen_port) is not int
            or not 0 <= listen_port <= 65535
        ):
            raise ValueError(
                "Invalid approval port"
            )

        address = ipaddress.IPv4Address(
            bind_address
        )

        if address.is_multicast:
            raise ValueError(
                "Multicast binding is not supported"
            )

        self.identity = identity
        self.trust_store = trust_store
        self.shared_state = shared_state
        self.store = store

        self._shares = {
            _identifier(share, "share_id"): _root(root)
            for share, root in shares.items()
        }

        if any(
            self.store.path == root
            or root in self.store.path.parents
            for root in self._shares.values()
        ):
            raise ValueError(
                "Deletion approval database must be "
                "outside synchronized folders"
            )

        self._allowed = {
            share: set()
            for share in self._shares
        }

        for share, peers in (
            allowed_requesters or {}
        ).items():
            if share not in self._shares:
                raise ValueError(
                    "Authorization refers to an unknown share"
                )

            self._allowed[share] = {
                _identifier(peer, "peer_node_id")
                for peer in peers
            }

        self.bind_address = str(address)
        self.listen_port = listen_port
        self.handshake_timeout = _timeout(
            handshake_timeout
        )
        self.io_timeout = _timeout(
            io_timeout
        )

        self._lock = threading.RLock()
        self._transaction = threading.RLock()

        self._stop = threading.Event()
        self._stop.set()

        self._listener: socket.socket | None = None
        self._port: int | None = None
        self._sockets: set[socket.socket] = set()
        self._threads: set[threading.Thread] = set()

    @property
    def bound_port(self) -> int | None:
        with self._lock:
            return self._port

    def authorize_requester(
        self,
        share: str,
        peer: str,
    ) -> None:
        with self._lock:
            if share not in self._shares:
                raise ValueError(
                    "Unknown share"
                )

            self._allowed[share].add(
                _identifier(peer, "peer_node_id")
            )

    def revoke_requester(
        self,
        share: str,
        peer: str,
    ) -> None:
        with self._lock:
            self._allowed.get(
                share, set()
            ).discard(
                _identifier(peer, "peer_node_id")
            )

    def _root_for(
        self,
        share: str,
        peer: str,
        public_key: bytes | None = None,
    ) -> Path:

        if public_key is not None:
            self.trust_store.require(public_key)

        with self._lock:
            root = self._shares.get(share)

            authorized = (
                peer in self._allowed.get(
                    share, set()
                )
            )

        if root is None or not authorized:
            raise DeletionApprovalError(
                "Device lacks permission to request "
                "deletion review for this share"
            )

        return root

    def _fresh(
        self,
        root: Path,
        peer: str,
        share: str,
        request: DeletionRequest,
    ) -> None:
        """Recheck the committed baseline and actual file contents."""

        baseline = self.shared_state.load(
            root, peer, share
        )

        if (
            baseline is None
            or baseline.revision
            != request.baseline_revision
            or baseline.sha256
            != request.baseline_sha256
        ):
            raise DeletionApprovalError(
                "Shared synchronization history changed; "
                "request a fresh review"
            )

        if self.shared_state.pending(
            root, peer, share
        ) is not None:
            raise DeletionApprovalError(
                "An unfinished synchronization agreement "
                "must be recovered first"
            )

        original = baseline.snapshot.files.get(
            request.path
        )

        if (
            original is None
            or (
                original.size,
                original.sha256,
            ) != (
                request.file_size,
                request.file_sha256,
            )
        ):
            raise DeletionApprovalError(
                "File was not part of that agreed baseline"
            )

        scan = FileScanner(root).scan()

        if not scan.complete:
            raise DeletionApprovalError(
                "Cannot read all files to verify "
                "deletion approval"
            )

        current = scan.files.get(
            request.path
        )

        if (
            current is None
            or (
                current.size,
                current.sha256,
            ) != (
                request.file_size,
                request.file_sha256,
            )
        ):
            raise DeletionApprovalError(
                "File was removed or edited; "
                "request a fresh review"
            )

    def incoming(
        self,
        share: str,
        peer: str,
    ) -> tuple[DeletionRequest, ...]:
        """Local application may display the owner's request inbox."""

        root = self._root_for(
            share, peer
        )

        return self.store.list_requests(
            root, peer, share
        )

    def decide(
        self,
        share: str,
        peer: str,
        request_id: str,
        *,
        approve: bool,
    ) -> DeletionRequest:
        """LOCAL owner-only API. No remote RPC can invoke this method."""

        with self._transaction:
            root = self._root_for(
                share, peer
            )

            request = self.store.get(
                root,
                peer,
                share,
                request_id,
            )

            if request is None:
                raise DeletionApprovalError(
                    "Deletion request not found"
                )

            if approve:
                self._fresh(
                    root, peer, share, request
                )

            return self.store.decide(
                root,
                peer,
                share,
                request_id,
                approve=approve,
            )

    def _worker(self, method, *args) -> None:
        def run():
            try:
                method(*args)
            finally:
                with self._lock:
                    self._threads.discard(
                        threading.current_thread()
                    )

        thread = threading.Thread(
            target=run,
            name="SyncBridgeDeletionReview",
            daemon=True,
        )

        with self._lock:
            self._threads.add(thread)

        thread.start()

    def start(self) -> None:
        with self._lock:
            if self._listener is not None:
                return

            if self._threads:
                raise RuntimeError(
                    "Previous approval listener still stopping"
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

                listener.bind(
                    (
                        self.bind_address,
                        self.listen_port,
                    )
                )

                listener.listen(
                    _MAX_CONNECTIONS
                )

                listener.settimeout(0.2)

            except BaseException:
                listener.close()
                raise

            self._listener = listener
            self._port = listener.getsockname()[1]

            self._stop.clear()
            self._worker(self._accept)

    def stop(self) -> None:
        with self._lock:
            self._stop.set()

            listener, self._listener = (
                self._listener,
                None,
            )

            self._port = None

            sockets = tuple(self._sockets)
            threads = tuple(self._threads)

        if listener:
            _close(listener)

        for sock in sockets:
            _close(sock)

        for thread in threads:
            if thread is not threading.current_thread():
                thread.join(
                    timeout=self.handshake_timeout + 1
                )

    def _accept(self) -> None:
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
                accepted = (
                    not self._stop.is_set()
                    and len(self._sockets)
                    < _MAX_CONNECTIONS
                )

                if accepted:
                    self._sockets.add(sock)

            if accepted:
                self._worker(
                    self._serve, sock
                )
            else:
                _close(sock)

    def _serve(
        self,
        sock: socket.socket,
    ) -> None:
        secure = None

        try:
            secure, peer = accept_secure_channel(
                sock,
                self.identity,
                self.trust_store,
                timeout=self.handshake_timeout,
            )

            secure.settimeout(
                self.io_timeout
            )

            req = _read(
                secure,
                {"request", "status"},
            )

            _identifier(
                req.get("share_id"),
                "share_id",
            )

            with self._transaction:
                root = self._root_for(
                    req["share_id"],
                    peer.node_id,
                    secure.remote_public_key,
                )

                if req["type"] == "request":
                    _shape(
                        req,
                        "request",
                        {
                            "share_id",
                            "request_id",
                            "path",
                            "baseline_revision",
                            "baseline_sha256",
                            "file_sha256",
                            "file_size",
                        },
                    )

                    request = DeletionRequest(
                        _identifier(
                            req["request_id"],
                            "request_id",
                        ),
                        req["share_id"],
                        peer.node_id,
                        _validate_path(
                            req["path"]
                        ),
                        _revision(
                            req["baseline_revision"]
                        ),
                        _digest(
                            req["baseline_sha256"]
                        ),
                        _digest(
                            req["file_sha256"]
                        ),
                        _file_size(
                            req["file_size"]
                        ),
                        "pending",
                    )

                    self._fresh(
                        root,
                        peer.node_id,
                        req["share_id"],
                        request,
                    )

                    item = self.store.submit(
                        root,
                        peer.node_id,
                        req["share_id"],
                        request.request_id,
                        request.path,
                        request.baseline_revision,
                        request.baseline_sha256,
                        request.file_sha256,
                        request.file_size,
                    )

                else:
                    _shape(
                        req,
                        "status",
                        {
                            "share_id",
                            "request_id",
                        },
                    )

                    item = self.store.get(
                        root,
                        peer.node_id,
                        req["share_id"],
                        _identifier(
                            req["request_id"],
                            "request_id",
                        ),
                    )

                    if item is None:
                        raise DeletionApprovalError(
                            "Deletion request not found"
                        )

                state = item.state

                if state == "approved":
                    try:
                        self._fresh(
                            root,
                            peer.node_id,
                            req["share_id"],
                            item,
                        )

                    except DeletionApprovalError:
                        state = "stale"

            _send(
                secure,
                "result",
                request_id=item.request_id,
                state=state,
            )

        except (
            OSError,
            ValueError,
            DeletionApprovalError,
            SecurityError,
        ) as exc:

            if (
                secure is not None
                and not self._stop.is_set()
            ):
                try:
                    _send(
                        secure,
                        "error",
                        reason=str(exc)[:240],
                    )
                except OSError:
                    pass

            if not self._stop.is_set():
                LOG.debug(
                    "Deletion review request refused: %s",
                    exc,
                )

        finally:
            _close(sock)

            with self._lock:
                self._sockets.discard(sock)


class DeletionApprovalClient:
    """Remote request/status only; never remote approval."""

    def __init__(
        self,
        identity: DeviceIdentity,
        trust_store: TrustStore,
        *,
        handshake_timeout: float = 5.0,
        io_timeout: float = 30.0,
    ) -> None:

        if (
            not isinstance(identity, DeviceIdentity)
            or not isinstance(trust_store, TrustStore)
        ):
            raise TypeError(
                "Identity and trust store required"
            )

        self.identity = identity
        self.trust_store = trust_store
        self.handshake_timeout = _timeout(
            handshake_timeout
        )
        self.io_timeout = _timeout(
            io_timeout
        )

    def _call(
        self,
        host: str,
        port: int,
        peer: str,
        kind: str,
        share: str,
        **fields,
    ) -> tuple[str, str]:

        _identifier(
            peer,
            "peer_node_id",
        )

        _identifier(
            share,
            "share_id",
        )

        if peer == self.identity.node_id:
            raise ValueError(
                "Cannot request deletion approval from self"
            )

        if (
            type(port) is not int
            or not 1 <= port <= 65535
        ):
            raise ValueError(
                "Invalid approval server port"
            )

        try:
            address = ipaddress.IPv4Address(
                host
            )
        except ValueError as exc:
            raise ValueError(
                "Approval server host must be numeric IPv4"
            ) from exc

        if (
            address.is_unspecified
            or address.is_multicast
            or str(address) == "255.255.255.255"
        ):
            raise ValueError(
                "Approval server host must be unicast IPv4"
            )

        try:
            sock = socket.create_connection(
                (str(address), port),
                timeout=self.handshake_timeout,
            )

        except OSError as exc:
            raise DeletionApprovalError(
                f"Cannot reach other computer: {exc}"
            ) from exc

        try:
            channel, authenticated = open_secure_channel(
                sock,
                self.identity,
                self.trust_store,
                peer,
                timeout=self.handshake_timeout,
            )

            if authenticated.node_id != peer:
                raise DeletionApprovalError(
                    "Unexpected authenticated device"
                )

            channel.settimeout(
                self.io_timeout
            )

            _send(
                channel,
                kind,
                share_id=share,
                **fields,
            )

            reply = _read(
                channel,
                {"result", "error"},
            )

            if reply["type"] == "error":
                _shape(
                    reply,
                    "error",
                    {"reason"},
                )

                raise DeletionApprovalError(
                    str(reply["reason"])[:240]
                )

            _shape(
                reply,
                "result",
                {
                    "request_id",
                    "state",
                },
            )

            _identifier(
                reply["request_id"],
                "request_id",
            )

            if reply["state"] not in (
                _STATES | {"stale"}
            ):
                raise DeletionApprovalError(
                    "Invalid deletion request status"
                )

            self.trust_store.require(
                channel.remote_public_key
            )

            return (
                reply["request_id"],
                reply["state"],
            )

        except (
            OSError,
            SecurityError,
        ) as exc:
            raise DeletionApprovalError(
                f"Encrypted approval request failed: {exc}"
            ) from exc

        finally:
            _close(sock)

    def request(
        self,
        host: str,
        port: int,
        peer: str,
        share: str,
        path: str,
        *,
        baseline_revision: int,
        baseline_sha256: str,
        file_sha256: str,
        file_size: int,
        request_id: str | None = None,
    ) -> tuple[str, str]:
        """Create an approval request. Return (request_id, state)."""

        request_id = _identifier(
            request_id or uuid4().hex,
            "request_id",
        )

        _validate_path(path)
        _revision(baseline_revision)
        _digest(baseline_sha256)
        _digest(file_sha256)
        _file_size(file_size)

        result = self._call(
            host,
            port,
            peer,
            "request",
            share,
            request_id=request_id,
            path=path,
            baseline_revision=baseline_revision,
            baseline_sha256=baseline_sha256,
            file_sha256=file_sha256,
            file_size=file_size,
        )

        if result[0] != request_id:
            raise DeletionApprovalError(
                "Response request ID differs"
            )

        return result

    def status(
        self,
        host: str,
        port: int,
        peer: str,
        share: str,
        request_id: str,
    ) -> str:
        """Check whether the other device approved, declined, or became stale."""

        _identifier(
            request_id,
            "request_id",
        )

        returned_id, state = self._call(
            host,
            port,
            peer,
            "status",
            share,
            request_id=request_id,
        )

        if returned_id != request_id:
            raise DeletionApprovalError(
                "Response request ID differs"
            )

        return state
