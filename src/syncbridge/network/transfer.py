
"""Resumable, encrypted transfers with optional strict share binding.

For new deployments configure ``share_id`` on the listening service and
pass the same ID in send_file/fetch_file. Such listeners reject legacy offers.
Read and write permissions are separate. Content replacement requires both an
opt-in receiver and the expected existing SHA-256; deletions are not supported.

The receiver rechecks the existing hash immediately before publishing, but
ordinary Windows/POSIX filesystem APIs cannot provide atomic hash-and-replace
against unrelated local writers. Coordinators must serialize local writers and
retain conflict backups for a production synchronization service.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import math
import os
import re
import socket
import stat
import struct
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from .secure_channel import accept_secure_channel, open_secure_channel
from .security import DeviceIdentity, SecurityError, TrustStore

logger = logging.getLogger(__name__)
_VERSION = 2
_CHUNK_SIZE = 64 * 1024
_MAX_JSON = 4096
_MAX_CONNECTIONS = 8
_MAX_SIZE = 2**63 - 1
_NODE_ID = re.compile(r"[0-9a-f]{32}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_RESERVED = re.compile(r"(?i)^(con|prn|aux|nul|conin\$|conout\$|com[0-9]|lpt[0-9])(?:\..*)?$")


class TransferError(Exception):
    """Transfer failed, was refused, or cannot be resumed safely."""


@dataclass(frozen=True, slots=True)
class TransferProgress:
    direction: str
    peer_id: str
    path: str
    transferred: int
    total: int


@dataclass(frozen=True, slots=True)
class TransferResult:
    path: str
    sha256: str
    total: int
    transferred: int
    completed: bool


def _identity(value: str) -> str:
    if not isinstance(value, str) or _NODE_ID.fullmatch(value) is None:
        raise ValueError("Expected 32 lowercase hexadecimal characters")
    return value


def _sha(value: str | None) -> str | None:
    if value is not None and (not isinstance(value, str) or _HASH.fullmatch(value) is None):
        raise TransferError("Invalid SHA-256 precondition")
    return value


def _path(value: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value:
        raise TransferError("Invalid relative file path")
    try:
        if len(value.encode("utf-8")) > 1024:
            raise TransferError("Path exceeds 1024 bytes")
    except UnicodeEncodeError as exc:
        raise TransferError("Invalid Unicode path") from exc
    segments = value.split("/")
    for segment in segments:
        if (
            segment in ("", ".", "..") or segment.endswith((" ", "."))
            or len(segment.encode("utf-8")) > 255
            or any(ord(c) < 32 or ord(c) == 127 or c in '<>:"|?*' for c in segment)
            or _RESERVED.fullmatch(segment) is not None
            or segment.casefold() in (".git", ".venv", ".syncbridge", "__pycache__")
        ):
            raise TransferError("Unsafe relative file path")
    return tuple(segments)


def _linked(path: Path) -> bool:
    return path.is_symlink() or (hasattr(os.path, "isjunction") and os.path.isjunction(path))


def _directory(path: Path) -> None:
    if _linked(path) or (path.exists() and not path.is_dir()):
        raise TransferError("Unsafe directory")
    path.mkdir(parents=True, exist_ok=True)
    if _linked(path) or not path.is_dir():
        raise TransferError("Unsafe directory")


def _child(root: Path, segments: tuple[str, ...], *, create: bool = False) -> Path:
    current = root
    for part in segments[:-1]:
        current = current / part
        if _linked(current):
            raise TransferError("Path passes through a link or junction")
        if create:
            _directory(current)
        elif current.exists() and not current.is_dir():
            raise TransferError("Parent component is not a directory")
    target = current / segments[-1]
    if _linked(target):
        raise TransferError("Linked files are not transferable")
    return target


def _regular(path: Path) -> None:
    if _linked(path):
        raise TransferError("Linked staging file")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(metadata.st_mode):
        raise TransferError("Staging file must be regular")


def _hash_file(stream) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _same_stat(a: os.stat_result, b: os.stat_result) -> bool:
    return (a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns) == (
        b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns
    )


def _send(connection, kind: str, **fields) -> None:
    raw = json.dumps(
        {"version": _VERSION, "type": kind, **fields},
        ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    if len(raw) > _MAX_JSON:
        raise TransferError("Transfer control frame too large")
    connection.sendall(struct.pack("!I", len(raw)) + raw)


def _exact(connection, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        chunk = connection.recv(count - len(result))
        if not chunk:
            raise TransferError("Transfer stream disconnected")
        result.extend(chunk)
    return bytes(result)


def _unique(pairs):
    obj = {}
    for key, val in pairs:
        if key in obj:
            raise ValueError("Duplicate JSON key")
        obj[key] = val
    return obj


def _read(connection, kinds: set[str]) -> dict:
    size = struct.unpack("!I", _exact(connection, 4))[0]
    if not 0 < size <= _MAX_JSON:
        raise TransferError("Invalid control frame length")
    try:
        data = json.loads(
            _exact(connection, size).decode("utf-8"),
            object_pairs_hook=_unique,
            parse_constant=lambda v: (_ for _ in ()).throw(ValueError(v))
        )
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise TransferError("Invalid control JSON") from exc
    if (
        not isinstance(data, dict)
        or type(data.get("version")) is not int
        or data["version"] != _VERSION
        or data.get("type") not in kinds
    ):
        raise TransferError("Unexpected transfer message")
    return data


def _expect(data: dict, kind: str, fields: set[str]) -> None:
    if data["type"] != kind or set(data) != {"version", "type"} | fields:
        raise TransferError(f"Malformed {kind} message")


def _reply(data: dict, kind: str) -> dict:
    if data["type"] == "error":
        _expect(data, "error", {"reason"})
        raise TransferError(str(data["reason"])[:256])
    if data["type"] != kind:
        raise TransferError("Unexpected transfer reply")
    return data


def _close(connection) -> None:
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        connection.close()
    except OSError:
        pass


class TransferService:
    """One destination root and optionally one strictly bound share identifier.

    A share-bound receiver refuses legacy (unscoped) sends and only responds to
    pull requests from peers in allowed_readers. In legacy mode, only existing
    push operations are permitted for compatibility with the first milestone.
    """

    def __init__(
        self, identity: DeviceIdentity, trust_store: TrustStore,
        destination_root: str | Path, *,
        allowed_senders: Iterable[str] = (), allowed_readers: Iterable[str] = (),
        share_id: str | None = None,
        bind_address: str = "0.0.0.0", listen_port: int = 45842,
        handshake_timeout: float = 5.0, io_timeout: float = 120.0,
        allow_overwrite: bool = False,
        on_progress: Callable[[TransferProgress], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        if not isinstance(identity, DeviceIdentity) or not isinstance(trust_store, TrustStore):
            raise TypeError("Device identity and trust store required")
        if share_id is not None:
            _identity(share_id)
        if type(listen_port) is not int or not 0 <= listen_port <= 65535:
            raise ValueError("Invalid transfer port")
        try:
            socket.inet_pton(socket.AF_INET, bind_address)
        except OSError as exc:
            raise ValueError("Bind address must be IPv4") from exc
        if any(
            type(t) not in (float, int) or not math.isfinite(t) or t <= 0
            for t in (handshake_timeout, io_timeout)
        ):
            raise ValueError("Invalid timeouts")
        if type(allow_overwrite) is not bool:
            raise TypeError("allow_overwrite must be bool")
        if any(cb is not None and not callable(cb) for cb in (on_progress, on_error)):
            raise TypeError("Callbacks must be callable")

        self.identity, self.trust_store = identity, trust_store
        self.destination_root = Path(destination_root).expanduser().absolute()
        _directory(self.destination_root)

        folder_hash = hashlib.sha256(
            os.fsencode(str(self.destination_root))
        ).hexdigest()[:16]
        self._staging = (
            self.destination_root.parent
            / f".syncbridge-transfer-{folder_hash}"
        )
        _directory(self._staging)

        self.share_id = share_id
        self._allowed = {_identity(x) for x in allowed_senders}
        self._readers = {_identity(x) for x in allowed_readers}
        self.bind_address, self.listen_port = bind_address, listen_port
        self.handshake_timeout = float(handshake_timeout)
        self.io_timeout = float(io_timeout)
        self.allow_overwrite = allow_overwrite
        self._on_progress, self._on_error = on_progress, on_error

        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._stop.set()
        self._listener: socket.socket | None = None
        self._bound_port: int | None = None
        self._connections: set[socket.socket] = set()
        self._active_paths: set[str] = set()
        self._threads: set[threading.Thread] = set()

    @property
    def bound_port(self) -> int | None:
        with self._lock:
            return self._bound_port

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._listener is not None and not self._stop.is_set()

    def authorize_sender(self, node_id: str) -> None:
        with self._lock:
            self._allowed.add(_identity(node_id))

    def revoke_sender(self, node_id: str) -> None:
        with self._lock:
            self._allowed.discard(_identity(node_id))

    def authorize_reader(self, node_id: str) -> None:
        with self._lock:
            self._readers.add(_identity(node_id))

    def revoke_reader(self, node_id: str) -> None:
        with self._lock:
            self._readers.discard(_identity(node_id))

    def _check_permission(
        self, peer_id: str, key: bytes, *,
        read: bool = False, outbound: bool = False
    ) -> None:
        self.trust_store.require(key)
        if outbound:
            return
        with self._lock:
            allowed = (
                peer_id in (self._readers if read else self._allowed)
                and not self._stop.is_set()
            )
        if not allowed:
            raise TransferError(
                "Device lacks permission to read this share"
                if read else
                "Sending device is not authorized for this folder"
            )

    def _spawn(self, method, *args) -> None:
        def task():
            try:
                method(*args)
            finally:
                with self._lock:
                    self._threads.discard(threading.current_thread())
        worker = threading.Thread(
            target=task, name="SyncBridgeTransfer", daemon=True
        )
        with self._lock:
            self._threads.add(worker)
        worker.start()

    def start(self) -> None:
        with self._lock:
            if self._listener is not None:
                return
            if self._threads:
                raise RuntimeError("Previous transfer workers still stopping")

            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                listener.setsockopt(
                    socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
                )
                listener.bind((self.bind_address, self.listen_port))
                listener.listen(_MAX_CONNECTIONS)
                listener.settimeout(0.2)
            except BaseException:
                listener.close()
                raise

            self._listener = listener
            self._bound_port = listener.getsockname()[1]
            self._stop.clear()
            self._spawn(self._accept_loop)

    def stop(self) -> None:
        with self._lock:
            self._stop.set()
            listener, self._listener = self._listener, None
            self._bound_port = None
            sockets = tuple(self._connections)
            threads = tuple(self._threads)

        if listener:
            _close(listener)
        for sock in sockets:
            _close(sock)
        for thread in threads:
            if thread is not threading.current_thread():
                thread.join(timeout=2)

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                listener = self._listener
            if listener is None:
                return
            try:
                sock, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if not self._stop.is_set():
                    self._report(exc)
                return

            with self._lock:
                accepted = (
                    not self._stop.is_set()
                    and len(self._connections) < _MAX_CONNECTIONS
                )
                if accepted:
                    self._connections.add(sock)

            if accepted:
                self._spawn(self._serve, sock)
            else:
                _close(sock)

    def _verify_share(self, provided: str | None) -> None:
        if provided != self.share_id:
            raise TransferError("Unknown or mismatched transfer share")

    def _serve(self, sock: socket.socket) -> None:
        secure = None
        try:
            secure, peer = accept_secure_channel(
                sock, self.identity, self.trust_store,
                timeout=self.handshake_timeout
            )
            secure.settimeout(self.io_timeout)
            request = _read(secure, {"offer", "get"})

            if request["type"] == "offer":
                self._check_permission(
                    peer.node_id, secure.remote_public_key
                )
                if self.share_id is None:
                    _expect(
                        request, "offer",
                        {"path", "size", "sha256"}
                    )
                else:
                    _expect(
                        request, "offer",
                        {
                            "path", "size", "sha256", "share_id",
                            "expected_destination_sha256"
                        }
                    )
                    self._verify_share(request["share_id"])
                self._receive(
                    secure, peer.node_id, request, outbound=False
                )
            else:
                _expect(
                    request, "get",
                    {
                        "share_id", "path",
                        "expected_source_sha256",
                        "expected_destination_sha256"
                    }
                )
                self._verify_share(request["share_id"])
                if self.share_id is None:
                    raise TransferError(
                        "Pull requires a configured share"
                    )
                self._check_permission(
                    peer.node_id, secure.remote_public_key, read=True
                )
                self._send_source(
                    secure, peer.node_id, self.destination_root,
                    request["path"],
                    share_id=self.share_id,
                    expected_source=request["expected_source_sha256"],
                    expected_destination=request["expected_destination_sha256"],
                    outbound=False
                )
        except (OSError, TransferError, SecurityError, ValueError) as exc:
            if secure is not None and not self._stop.is_set():
                try:
                    _send(
                        secure, "error", reason=str(exc)[:256]
                    )
                except OSError:
                    pass
            if not self._stop.is_set():
                self._report(exc)
        finally:
            _close(sock)
            with self._lock:
                self._connections.discard(sock)

    def _precondition(
        self, target: Path, size: int, digest: str,
        expected: str | None, *, strict: bool
    ) -> bool:
        if not target.exists():
            if expected is not None:
                raise TransferError(
                    "Destination disappeared; expected existing file"
                )
            return False
        if not target.is_file():
            raise TransferError("Destination is not a regular file")

        with target.open("rb") as stream:
            before = os.fstat(stream.fileno())
            current_hash = _hash_file(stream)
            if not _same_stat(
                before, os.fstat(stream.fileno())
            ):
                raise TransferError(
                    "Destination changed while checking precondition"
                )

        if current_hash == digest and target.stat().st_size == size:
            return True

        if not self.allow_overwrite:
            raise TransferError(
                "Destination already exists; conflict resolution required"
            )
        if strict and expected is None:
            raise TransferError(
                "Conditional overwrite requires expected destination SHA-256"
            )
        if expected is not None and current_hash != expected:
            raise TransferError(
                "Destination changed; expected SHA-256 mismatch"
            )
        return False

    def _receive(
        self, secure, sender_id: str, offer: dict, *,
        outbound: bool, cancel_event=None, on_progress=None
    ) -> TransferResult:
        segments = _path(offer["path"])
        relative = offer["path"]
        size, digest = offer["size"], offer["sha256"]

        if type(size) is not int or not 0 <= size <= _MAX_SIZE:
            raise TransferError("Invalid file size")
        if not isinstance(digest, str) or _HASH.fullmatch(digest) is None:
            raise TransferError("Invalid content hash")
        expected = _sha(
            offer.get("expected_destination_sha256")
        )

        with self._lock:
            if relative in self._active_paths:
                raise TransferError("Transfer for path already active")
            self._active_paths.add(relative)

        try:
            if not outbound:
                self._check_permission(
                    sender_id, secure.remote_public_key
                )

            target = _child(
                self.destination_root, segments
            )
            strict = (
                self.share_id is not None
                or "share_id" in offer
            )
            if self._precondition(
                target, size, digest, expected, strict=strict
            ):
                _send(
                    secure, "already_complete", size=size, sha256=digest
                )
                return TransferResult(
                    relative, digest, size, size, True
                )

            slot = hashlib.sha256(
                f"{sender_id}\0{offer.get('share_id', self.share_id)}\0"
                f"{relative}\0{size}\0{digest}\0{expected}".encode("utf-8")
            ).hexdigest()

            partial = self._staging / (slot + ".part")
            metadata = self._staging / (slot + ".json")

            _regular(partial)
            _regular(metadata)

            manifest = {
                "sender": sender_id,
                "share_id": offer.get("share_id", self.share_id),
                "path": relative,
                "size": size,
                "sha256": digest,
                "expected": expected
            }

            if partial.exists() and metadata.exists():
                try:
                    old = json.loads(
                        metadata.read_text("utf-8")
                    )
                except (ValueError, UnicodeError) as exc:
                    raise TransferError(
                        "Corrupt resume metadata"
                    ) from exc

                if old != manifest:
                    raise TransferError(
                        "Resume metadata mismatch"
                    )

                offset = partial.stat().st_size
                if offset > size:
                    raise TransferError(
                        "Partial exceeds offered file size"
                    )
            else:
                partial.unlink(missing_ok=True)
                metadata.unlink(missing_ok=True)

                with metadata.open(
                    "x", encoding="utf-8"
                ) as stream:
                    json.dump(
                        manifest, stream, sort_keys=True
                    )
                    stream.flush()
                    os.fsync(stream.fileno())

                with partial.open("xb"):
                    pass
                offset = 0

            _send(secure, "ready", offset=offset)
            received = offset

            if outbound:
                self._progress(
                    "receive", sender_id, relative,
                    received, size, on_progress
                )

            with partial.open("ab", buffering=0) as output:
                while received < size:
                    self._check_permission(
                        sender_id, secure.remote_public_key,
                        outbound=outbound
                    )
                    length = struct.unpack(
                        "!I", _exact(secure, 4)
                    )[0]

                    if length == 0:
                        paused = _read(
                            secure, {"pause"}
                        )
                        _expect(paused, "pause", set())
                        os.fsync(output.fileno())
                        _send(
                            secure, "paused", offset=received
                        )
                        return TransferResult(
                            relative, digest, size, received, False
                        )

                    if (
                        length > _CHUNK_SIZE
                        or length > size - received
                    ):
                        raise TransferError(
                            "Invalid file chunk length"
                        )

                    output.write(_exact(secure, length))
                    received += length

                    self._progress(
                        "receive", sender_id, relative,
                        received, size, on_progress
                    )

                    if (
                        cancel_event is not None
                        and cancel_event.is_set()
                    ):
                        os.fsync(output.fileno())
                        return TransferResult(
                            relative, digest, size, received, False
                        )

                os.fsync(output.fileno())

            if struct.unpack(
                "!I", _exact(secure, 4)
            )[0] != 0:
                raise TransferError(
                    "Missing end-of-file marker"
                )

            _expect(
                _read(secure, {"finish"}),
                "finish", set()
            )
            self._check_permission(
                sender_id, secure.remote_public_key,
                outbound=outbound
            )

            with partial.open("rb") as stream:
                calculated = _hash_file(stream)

            if (
                calculated != digest
                or partial.stat().st_size != size
            ):
                partial.unlink(missing_ok=True)
                metadata.unlink(missing_ok=True)
                raise TransferError(
                    "File hash mismatch; corrupt partial discarded"
                )

            self._check_permission(
                sender_id, secure.remote_public_key,
                outbound=outbound
            )

            target = _child(
                self.destination_root, segments, create=True
            )

            if self._precondition(
                target, size, digest, expected, strict=strict
            ):
                # Correct file appeared during transfer; no rewrite.
                partial.unlink(missing_ok=True)
                metadata.unlink(missing_ok=True)

            elif target.exists():
                os.replace(partial, target)
                metadata.unlink(missing_ok=True)

            else:
                # Atomic create-if-absent on the same filesystem.
                os.link(partial, target)
                partial.unlink()
                metadata.unlink(missing_ok=True)

            _send(
                secure, "complete", size=size, sha256=digest
            )
            return TransferResult(
                relative, digest, size, size, True
            )

        finally:
            with self._lock:
                self._active_paths.discard(relative)

    def _transmit(
        self, secure, peer_id: str, stream,
        before: os.stat_result, digest: str, relative: str,
        *, cancel_event, on_progress, outbound: bool
    ) -> TransferResult:
        answer = _read(
            secure, {"ready", "error", "already_complete"}
        )

        if answer["type"] == "already_complete":
            _expect(
                answer, "already_complete", {"size", "sha256"}
            )
            if (
                type(answer["size"]) is not int
                or answer["size"] != before.st_size
                or answer["sha256"] != digest
            ):
                raise TransferError(
                    "Invalid already-complete receipt"
                )

            return TransferResult(
                relative, digest, before.st_size,
                before.st_size, True
            )

        _expect(
            _reply(answer, "ready"),
            "ready", {"offset"}
        )
        offset = answer["offset"]

        if (
            type(offset) is not int
            or not 0 <= offset <= before.st_size
        ):
            raise TransferError("Invalid resume offset")

        stream.seek(offset)
        sent = offset

        self._progress(
            "send", peer_id, relative, sent,
            before.st_size, on_progress
        )

        while sent < before.st_size:
            self._check_permission(
                peer_id, secure.remote_public_key,
                read=not outbound, outbound=outbound
            )

            if (
                cancel_event is not None
                and cancel_event.is_set()
            ):
                secure.sendall(struct.pack("!I", 0))
                _send(secure, "pause")

                reply = _reply(
                    _read(secure, {"paused", "error"}),
                    "paused"
                )
                _expect(
                    reply, "paused", {"offset"}
                )

                if (
                    type(reply["offset"]) is not int
                    or reply["offset"] != sent
                ):
                    raise TransferError(
                        "Invalid pause response"
                    )

                return TransferResult(
                    relative, digest, before.st_size,
                    sent, False
                )

            chunk = stream.read(
                min(_CHUNK_SIZE, before.st_size - sent)
            )

            if not chunk:
                raise TransferError(
                    "Source truncated during transfer"
                )

            secure.sendall(
                struct.pack("!I", len(chunk)) + chunk
            )
            sent += len(chunk)

            self._progress(
                "send", peer_id, relative, sent,
                before.st_size, on_progress
            )

        if not _same_stat(
            before, os.fstat(stream.fileno())
        ):
            raise TransferError(
                "Source changed during transfer"
            )

        secure.sendall(struct.pack("!I", 0))
        _send(secure, "finish")

        receipt = _reply(
            _read(secure, {"complete", "error"}),
            "complete"
        )
        _expect(
            receipt, "complete", {"size", "sha256"}
        )

        if (
            type(receipt["size"]) is not int
            or receipt["size"] != before.st_size
            or receipt["sha256"] != digest
        ):
            raise TransferError(
                "Invalid completion receipt"
            )

        self._check_permission(
            peer_id, secure.remote_public_key,
            read=not outbound, outbound=outbound
        )
        return TransferResult(
            relative, digest, before.st_size,
            sent, True
        )

    def _send_source(
        self, secure, peer_id: str, root: Path,
        relative: str, *, share_id: str | None,
        expected_source: str | None,
        expected_destination: str | None,
        cancel_event=None, on_progress=None,
        outbound: bool
    ) -> TransferResult:
        segments = _path(relative)
        _sha(expected_source)
        _sha(expected_destination)

        source = _child(root, segments)

        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )

        try:
            fd = os.open(source, flags)
        except OSError as exc:
            raise TransferError(
                f"Cannot read source: {exc}"
            ) from exc

        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())

            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_size > _MAX_SIZE
            ):
                raise TransferError(
                    "Source must be a regular file of supported size"
                )

            digest = _hash_file(stream)

            if not _same_stat(
                before, os.fstat(stream.fileno())
            ):
                raise TransferError(
                    "Source changed while hashing"
                )

            if (
                expected_source is not None
                and expected_source != digest
            ):
                raise TransferError(
                    "Source changed from expected SHA-256"
                )

            stream.seek(0)

            if share_id is None:
                _send(
                    secure, "offer",
                    path=relative,
                    size=before.st_size,
                    sha256=digest
                )
            else:
                _send(
                    secure, "offer",
                    path=relative,
                    size=before.st_size,
                    sha256=digest,
                    share_id=share_id,
                    expected_destination_sha256=expected_destination
                )

            return self._transmit(
                secure, peer_id, stream, before,
                digest, relative,
                cancel_event=cancel_event,
                on_progress=on_progress,
                outbound=outbound
            )

    def _connect(
        self, host: str, port: int, expected_id: str
    ):
        _identity(expected_id)
        if expected_id == self.identity.node_id:
            raise TransferError("Cannot transfer to self")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("Invalid remote port")
        if not isinstance(host, str):
            raise ValueError("Expected a numeric IPv4 host")

        try:
            address = ipaddress.IPv4Address(host)
        except ValueError as exc:
            raise ValueError(
                "Expected a numeric IPv4 host"
            ) from exc

        if (
            address.is_unspecified
            or address.is_multicast
            or str(address) == "255.255.255.255"
        ):
            raise ValueError("Invalid remote address")

        try:
            sock = socket.create_connection(
                (str(address), port),
                timeout=self.handshake_timeout
            )
        except OSError as exc:
            raise TransferError(
                f"Cannot reach remote device: {exc}"
            ) from exc

        try:
            secure, peer = open_secure_channel(
                sock, self.identity, self.trust_store,
                expected_id, timeout=self.handshake_timeout
            )
            secure.settimeout(self.io_timeout)
            return sock, secure, peer
        except BaseException:
            _close(sock)
            raise

    def send_file(
        self, host: str, port: int,
        expected_node_id: str,
        source_root: str | Path,
        relative_path: str, *,
        share_id: str | None = None,
        expected_destination_sha256: str | None = None,
        cancel_event: threading.Event | None = None,
        on_progress: Callable[[TransferProgress], None] | None = None
    ) -> TransferResult:
        """Push a file, enforcing the receiver's optional share binding."""
        if share_id is not None:
            _identity(share_id)

        if self.share_id is not None and self.share_id != share_id:
            raise TransferError(
                "Local service is configured for another share"
            )
        if (
            share_id is None
            and expected_destination_sha256 is not None
        ):
            raise ValueError(
                "Conditional writes require share_id"
            )

        _sha(expected_destination_sha256)

        if (
            cancel_event is not None
            and not isinstance(cancel_event, threading.Event)
        ):
            raise TypeError(
                "cancel_event must be threading.Event"
            )
        if on_progress is not None and not callable(on_progress):
            raise TypeError("on_progress must be callable")

        _path(relative_path)
        root = Path(source_root).expanduser().absolute()

        if _linked(root) or not root.is_dir():
            raise TransferError(
                "Invalid shared source directory"
            )

        try:
            sock, secure, peer = self._connect(
                host, port, expected_node_id
            )
        except SecurityError as exc:
            raise TransferError(
                f"Secure transfer failed: {exc}"
            ) from exc

        try:
            return self._send_source(
                secure, peer.node_id, root, relative_path,
                share_id=share_id,
                expected_source=None,
                expected_destination=expected_destination_sha256,
                cancel_event=cancel_event,
                on_progress=on_progress,
                outbound=True
            )
        except (OSError, SecurityError) as exc:
            raise TransferError(
                f"Secure transfer failed: {exc}"
            ) from exc
        finally:
            _close(sock)

    def fetch_file(
        self, host: str, port: int,
        expected_node_id: str,
        share_id: str, relative_path: str, *,
        expected_source_sha256: str | None = None,
        expected_destination_sha256: str | None = None,
        cancel_event: threading.Event | None = None,
        on_progress: Callable[[TransferProgress], None] | None = None
    ) -> TransferResult:
        """Download a file from a peer granting explicit share-read access."""
        _identity(share_id)
        _path(relative_path)
        _sha(expected_source_sha256)
        _sha(expected_destination_sha256)

        if (
            self.share_id is not None
            and self.share_id != share_id
        ):
            raise TransferError(
                "Local receiver is configured for another share"
            )

        if (
            cancel_event is not None
            and not isinstance(cancel_event, threading.Event)
        ):
            raise TypeError(
                "cancel_event must be threading.Event"
            )
        if (
            on_progress is not None
            and not callable(on_progress)
        ):
            raise TypeError(
                "on_progress must be callable"
            )

        try:
            sock, secure, peer = self._connect(
                host, port, expected_node_id
            )
        except SecurityError as exc:
            raise TransferError(
                f"Secure transfer failed: {exc}"
            ) from exc

        try:
            _send(
                secure, "get",
                share_id=share_id,
                path=relative_path,
                expected_source_sha256=expected_source_sha256,
                expected_destination_sha256=expected_destination_sha256
            )

            offer = _read(
                secure, {"offer", "error"}
            )
            _reply(offer, "offer")

            _expect(
                offer, "offer",
                {
                    "share_id", "path", "size",
                    "sha256", "expected_destination_sha256"
                }
            )

            if (
                offer["share_id"] != share_id
                or offer["path"] != relative_path
                or offer["expected_destination_sha256"]
                    != expected_destination_sha256
                or (
                    expected_source_sha256 is not None
                    and offer["sha256"] != expected_source_sha256
                )
            ):
                raise TransferError(
                    "Remote offer differs from requested file/preconditions"
                )

            return self._receive(
                secure, peer.node_id, offer,
                outbound=True,
                cancel_event=cancel_event,
                on_progress=on_progress
            )
        except (OSError, SecurityError) as exc:
            raise TransferError(
                f"Secure transfer failed: {exc}"
            ) from exc
        finally:
            _close(sock)

    def _progress(
        self, direction, peer_id, path,
        transferred, total, listener=None
    ):
        event = TransferProgress(
            direction, peer_id, path,
            transferred, total
        )
        for callback in (self._on_progress, listener):
            if callback is not None:
                try:
                    callback(event)
                except Exception:
                    logger.exception(
                        "Progress callback failed"
                    )

    def _report(self, exc: Exception) -> None:
        if self._on_error is None:
            logger.warning(
                "SyncBridge transfer: %s", exc
            )
        else:
            try:
                self._on_error(exc)
            except Exception:
                logger.exception(
                    "Transfer error callback failed"
                )
