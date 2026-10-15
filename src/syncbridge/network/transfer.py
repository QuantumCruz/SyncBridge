
"""Authenticated, resumable file transfer over dedicated encrypted TCP sockets.

Only explicitly permitted senders may write into a receiver's destination root.
The sender selects files from an explicitly supplied source root. Transfers do
not use the PeerManager control connection, so heartbeats remain independent.
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
from .security import AuthenticationError, DeviceIdentity, SecurityError, TrustStore

logger = logging.getLogger(__name__)

_VERSION = 1
_CHUNK_SIZE = 64 * 1024
_MAX_JSON = 4096
_MAX_CONNECTIONS = 8
_MAX_FILE_SIZE = 2**63 - 1

_NODE_ID = re.compile(r"[0-9a-f]{32}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_WINDOWS_RESERVED = re.compile(
    r"(?i)^(con|prn|aux|nul|conin\$|conout\$|com[0-9]|lpt[0-9])(?:\..*)?$"
)


class TransferError(Exception):
    """Rejected or interrupted transfer; incomplete staging files are retained."""


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


def _path(value: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value:
        raise TransferError("Invalid relative file path")

    try:
        if len(value.encode("utf-8")) > 1024:
            raise TransferError("Invalid relative file path")
    except UnicodeEncodeError as exc:
        raise TransferError("Invalid Unicode file path") from exc

    if "\\" in value or value.startswith("/") or "//" in value:
        raise TransferError("Invalid relative file path")

    segments = value.split("/")

    for segment in segments:
        try:
            segment_bytes = len(segment.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise TransferError("Invalid Unicode file path") from exc

        if (
            segment in ("", ".", "..")
            or segment.endswith((" ", "."))
            or segment_bytes > 255
            or any(
                ord(c) < 32 or ord(c) == 127 or c in '<>:"|?*'
                for c in segment
            )
            or _WINDOWS_RESERVED.fullmatch(segment) is not None
        ):
            raise TransferError("Unsafe relative file path")

    return tuple(segments)


def _validate_node(value: str) -> str:
    if not isinstance(value, str) or not _NODE_ID.fullmatch(value):
        raise ValueError("Expected a 32-character lowercase node ID")
    return value


def _linked(path: Path) -> bool:
    return path.is_symlink() or (
        hasattr(os.path, "isjunction") and os.path.isjunction(path)
    )


def _check_directory(path: Path) -> None:
    if _linked(path):
        raise TransferError("Refusing a symbolic link or junction directory")

    if path.exists() and not path.is_dir():
        raise TransferError("Expected a directory")

    path.mkdir(parents=True, exist_ok=True)

    if _linked(path) or not path.is_dir():
        raise TransferError("Unsafe directory")


def _safe_child(
    root: Path,
    segments: tuple[str, ...],
    *,
    create: bool,
) -> Path:
    current = root

    for segment in segments[:-1]:
        current = current / segment

        if _linked(current):
            raise TransferError(
                "Path traverses a symbolic link or junction"
            )

        if create:
            _check_directory(current)
        elif current.exists() and not current.is_dir():
            raise TransferError(
                "Parent component is not a directory"
            )

    leaf = current / segments[-1]

    if _linked(leaf):
        raise TransferError(
            "Refusing a symbolic link or junction file"
        )

    return leaf


def _regular_or_absent(path: Path) -> None:
    if _linked(path):
        raise TransferError("Refusing a linked staging file")

    try:
        info = path.lstat()
    except FileNotFoundError:
        return

    if not stat.S_ISREG(info.st_mode):
        raise TransferError(
            "Staging path is not a regular file"
        )


def _json_packet(connection: object, data: dict) -> None:
    raw = json.dumps(
        data,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode()

    if len(raw) > _MAX_JSON:
        raise TransferError(
            "Transfer control message too large"
        )

    connection.sendall(struct.pack("!I", len(raw)) + raw)


def _exact(connection: object, size: int) -> bytes:
    data = bytearray()

    while len(data) < size:
        part = connection.recv(size - len(data))

        if not part:
            raise TransferError(
                "Transfer connection closed unexpectedly"
            )

        data.extend(part)

    return bytes(data)


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError(
                "Duplicate transfer control field"
            )
        result[key] = value

    return result


def _read_json(
    connection: object,
    expected: set[str],
) -> dict:
    (length,) = struct.unpack(
        "!I",
        _exact(connection, 4),
    )

    if not 0 < length <= _MAX_JSON:
        raise TransferError(
            "Invalid transfer control length"
        )

    try:
        document = json.loads(
            _exact(connection, length).decode("utf-8"),
            object_pairs_hook=_pairs,
        )
    except (
        ValueError,
        UnicodeDecodeError,
        RecursionError,
    ) as exc:
        raise TransferError(
            "Malformed transfer control message"
        ) from exc

    if (
        not isinstance(document, dict)
        or document.get("version") != _VERSION
        or type(document.get("version")) is not int
    ):
        raise TransferError(
            "Unsupported transfer control message"
        )

    if document.get("type") not in expected:
        raise TransferError(
            "Unexpected transfer control message"
        )

    return document


def _response(
    connection: object,
    kind: str,
    **fields: object,
) -> None:
    _json_packet(
        connection,
        {
            "version": _VERSION,
            "type": kind,
            **fields,
        },
    )


def _error_or(response: dict, expected: str) -> dict:
    if response["type"] == "error":
        raise TransferError(
            str(
                response.get(
                    "reason",
                    "Remote transfer rejected",
                )
            )[:256]
        )

    if response["type"] != expected:
        raise TransferError(
            "Unexpected transfer response"
        )

    return response


def _file_hash(stream: object) -> str:
    digest = hashlib.sha256()

    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)

    return digest.hexdigest()


def _same_file(
    before: os.stat_result,
    after: os.stat_result,
) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )


def _close(connection: object) -> None:
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass

    try:
        connection.close()
    except OSError:
        pass


class TransferService:
    """Receive and send explicit pushes using independent encrypted sessions.

    The receiving root must be chosen by the user. allowed_senders defaults to
    empty (deny all). A trusted key alone does not grant write permission.

    Partials live in a sibling staging directory on the same filesystem so a
    completed file can be published atomically. No existing target is replaced
    unless allow_overwrite=True is explicitly selected.
    """

    def __init__(
        self,
        identity: DeviceIdentity,
        trust_store: TrustStore,
        destination_root: str | Path,
        *,
        allowed_senders: Iterable[str] = (),
        bind_address: str = "0.0.0.0",
        listen_port: int = 45842,
        handshake_timeout: float = 5.0,
        io_timeout: float = 120.0,
        allow_overwrite: bool = False,
        on_progress: Callable[[TransferProgress], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        if (
            not isinstance(identity, DeviceIdentity)
            or not isinstance(trust_store, TrustStore)
        ):
            raise TypeError(
                "identity and trust_store are required"
            )

        if (
            type(listen_port) is not int
            or not 0 <= listen_port <= 65535
        ):
            raise ValueError(
                "Invalid transfer TCP port"
            )

        try:
            socket.inet_pton(
                socket.AF_INET,
                bind_address,
            )
        except OSError as exc:
            raise ValueError(
                "bind_address must be numeric IPv4"
            ) from exc

        for value in (
            handshake_timeout,
            io_timeout,
        ):
            if (
                type(value) not in (int, float)
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(
                    "Timeouts must be finite positive numbers"
                )

        if type(allow_overwrite) is not bool:
            raise TypeError(
                "allow_overwrite must be bool"
            )

        if any(
            callback is not None and not callable(callback)
            for callback in (on_progress, on_error)
        ):
            raise TypeError(
                "Callbacks must be callable or None"
            )

        self.identity = identity
        self.trust_store = trust_store

        self.destination_root = (
            Path(destination_root)
            .expanduser()
            .absolute()
        )

        _check_directory(
            self.destination_root
        )

        directory_id = hashlib.sha256(
            os.fsencode(
                str(self.destination_root)
            )
        ).hexdigest()[:16]

        self._staging = (
            self.destination_root.parent
            / f".syncbridge-transfer-{directory_id}"
        )

        _check_directory(
            self._staging
        )

        self._allowed = {
            _validate_node(item)
            for item in allowed_senders
        }

        self.bind_address = bind_address
        self.listen_port = listen_port
        self.handshake_timeout = float(
            handshake_timeout
        )
        self.io_timeout = float(io_timeout)
        self.allow_overwrite = allow_overwrite

        self._on_progress = on_progress
        self._on_error = on_error

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
            return (
                self._listener is not None
                and not self._stop.is_set()
            )

    def authorize_sender(self, node_id: str) -> None:
        _validate_node(node_id)

        with self._lock:
            self._allowed.add(node_id)

    def revoke_sender(self, node_id: str) -> None:
        _validate_node(node_id)

        with self._lock:
            self._allowed.discard(node_id)

    def _spawn(
        self,
        method: Callable,
        *args: object,
    ) -> None:
        def run() -> None:
            try:
                method(*args)
            finally:
                with self._lock:
                    self._threads.discard(
                        threading.current_thread()
                    )

        thread = threading.Thread(
            target=run,
            daemon=True,
            name="SyncBridgeTransfer",
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
                    "Previous transfer workers are stopping"
                )

            connection = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM,
            )

            try:
                connection.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_REUSEADDR,
                    1,
                )

                connection.bind(
                    (
                        self.bind_address,
                        self.listen_port,
                    )
                )

                connection.listen(
                    _MAX_CONNECTIONS
                )

                connection.settimeout(0.2)

            except BaseException:
                connection.close()
                raise

            self._listener = connection
            self._bound_port = (
                connection.getsockname()[1]
            )
            self._stop.clear()
            self._spawn(self._accept_loop)

    def stop(self) -> None:
        with self._lock:
            self._stop.set()

            server, self._listener = (
                self._listener,
                None,
            )

            self._bound_port = None

            sockets = tuple(
                self._connections
            )

            threads = tuple(
                self._threads
            )

        if server is not None:
            _close(server)

        for connection in sockets:
            _close(connection)

        for thread in threads:
            if thread is not threading.current_thread():
                thread.join(timeout=2.0)

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                server = self._listener

            if server is None:
                return

            try:
                connection, _ = server.accept()

            except socket.timeout:
                continue

            except OSError as exc:
                if not self._stop.is_set():
                    self._report(exc)
                return

            with self._lock:
                accepted = (
                    not self._stop.is_set()
                    and len(self._connections)
                    < _MAX_CONNECTIONS
                )

                if accepted:
                    self._connections.add(connection)

            if accepted:
                self._spawn(
                    self._serve,
                    connection,
                )
            else:
                _close(connection)

    def _serve(
        self,
        connection: socket.socket,
    ) -> None:
        secure = None

        try:
            secure, peer = accept_secure_channel(
                connection,
                self.identity,
                self.trust_store,
                timeout=self.handshake_timeout,
            )

            secure.settimeout(
                self.io_timeout
            )

            with self._lock:
                allowed = (
                    peer.node_id in self._allowed
                    and not self._stop.is_set()
                )

            if not allowed:
                raise TransferError(
                    "Sending device is not authorized for this folder"
                )

            request = _read_json(
                secure,
                {"offer"},
            )

            self._receive_file(
                secure,
                peer.node_id,
                request,
            )

        except (
            OSError,
            TransferError,
            SecurityError,
        ) as exc:
            if (
                secure is not None
                and not self._stop.is_set()
            ):
                try:
                    _response(
                        secure,
                        "error",
                        reason=str(exc)[:256],
                    )
                except OSError:
                    pass

            if not self._stop.is_set():
                self._report(exc)

        finally:
            _close(connection)

            with self._lock:
                self._connections.discard(
                    connection
                )

    def _receive_file(
        self,
        secure: object,
        sender_id: str,
        offer: dict,
    ) -> None:
        if set(offer) != {
            "version",
            "type",
            "path",
            "size",
            "sha256",
        }:
            raise TransferError(
                "Invalid file offer"
            )

        relative = offer["path"]
        segments = _path(relative)

        size = offer["size"]
        digest = offer["sha256"]

        if (
            type(size) is not int
            or not 0 <= size <= _MAX_FILE_SIZE
        ):
            raise TransferError(
                "Invalid file size"
            )

        if (
            not isinstance(digest, str)
            or not _HASH.fullmatch(digest)
        ):
            raise TransferError(
                "Invalid content hash"
            )

        with self._lock:
            if relative in self._active_paths:
                raise TransferError(
                    "A transfer for this path is already active"
                )

            self._active_paths.add(relative)

        try:
            self._receive_locked(
                secure,
                sender_id,
                relative,
                segments,
                size,
                digest,
            )

        finally:
            with self._lock:
                self._active_paths.discard(
                    relative
                )

    def _receive_locked(
        self,
        secure: object,
        sender_id: str,
        relative: str,
        segments: tuple[str, ...],
        size: int,
        digest: str,
    ) -> None:
        # No directories are created in the visible tree before verification.
        destination = _safe_child(
            self.destination_root,
            segments,
            create=False,
        )

        if destination.exists():
            if not destination.is_file():
                raise TransferError(
                    "Destination is not a regular file"
                )

            if destination.stat().st_size == size:
                with destination.open("rb") as existing_file:
                    if _file_hash(existing_file) == digest:
                        _response(
                            secure,
                            "already_complete",
                            size=size,
                            sha256=digest,
                        )
                        return

            if not self.allow_overwrite:
                raise TransferError(
                    "Destination already exists; conflict resolution required"
                )

        slot = hashlib.sha256(
            f"{sender_id}\0{relative}\0{size}\0{digest}".encode("utf-8")
        ).hexdigest()

        partial = self._staging / (
            slot + ".part"
        )

        metadata = self._staging / (
            slot + ".json"
        )

        _regular_or_absent(partial)
        _regular_or_absent(metadata)

        manifest = {
            "sender": sender_id,
            "path": relative,
            "size": size,
            "sha256": digest,
        }

        if partial.exists() and metadata.exists():
            try:
                stored = json.loads(
                    metadata.read_text("utf-8")
                )
            except (
                ValueError,
                UnicodeError,
            ) as exc:
                raise TransferError(
                    "Corrupted transfer resume metadata"
                ) from exc

            if stored != manifest:
                raise TransferError(
                    "Transfer resume metadata mismatch"
                )

            offset = partial.stat().st_size

            if offset > size:
                raise TransferError(
                    "Partial file exceeds advertised size"
                )

        else:
            partial.unlink(
                missing_ok=True
            )
            metadata.unlink(
                missing_ok=True
            )

            with metadata.open(
                "x",
                encoding="utf-8",
            ) as stream:
                json.dump(
                    manifest,
                    stream,
                    sort_keys=True,
                )
                stream.flush()
                os.fsync(
                    stream.fileno()
                )

            with partial.open("xb"):
                pass

            offset = 0

        _response(
            secure,
            "ready",
            offset=offset,
        )

        transferred = offset

        with partial.open(
            "ab",
            buffering=0,
        ) as output:
            while transferred < size:
                self._check_authorized(
                    sender_id,
                    secure,
                )

                (length,) = struct.unpack(
                    "!I",
                    _exact(secure, 4),
                )

                if length == 0:
                    control = _read_json(
                        secure,
                        {"pause"},
                    )

                    if set(control) != {
                        "version",
                        "type",
                    }:
                        raise TransferError(
                            "Invalid pause message"
                        )

                    os.fsync(
                        output.fileno()
                    )

                    _response(
                        secure,
                        "paused",
                        offset=transferred,
                    )
                    return

                if (
                    length > _CHUNK_SIZE
                    or length > size - transferred
                ):
                    raise TransferError(
                        "Invalid file chunk length"
                    )

                output.write(
                    _exact(secure, length)
                )

                transferred += length

                self._progress(
                    "receive",
                    sender_id,
                    relative,
                    transferred,
                    size,
                )

            os.fsync(
                output.fileno()
            )

        (marker,) = struct.unpack(
            "!I",
            _exact(secure, 4),
        )

        if marker != 0:
            raise TransferError(
                "Expected end-of-file marker"
            )

        control = _read_json(
            secure,
            {"finish"},
        )

        if set(control) != {
            "version",
            "type",
        }:
            raise TransferError(
                "Invalid finish message"
            )

        self._check_authorized(
            sender_id,
            secure,
        )

        with partial.open("rb") as check:
            actual = _file_hash(check)

        if (
            actual != digest
            or partial.stat().st_size != size
        ):
            partial.unlink(
                missing_ok=True
            )
            metadata.unlink(
                missing_ok=True
            )

            raise TransferError(
                "File hash mismatch; corrupted partial discarded"
            )

        destination = _safe_child(
            self.destination_root,
            segments,
            create=True,
        )

        if (
            destination.exists()
            and not self.allow_overwrite
        ):
            raise TransferError(
                "Destination appeared while transfer was running"
            )

        if self.allow_overwrite:
            os.replace(
                partial,
                destination,
            )
        else:
            # Hard-link creates the destination atomically WITHOUT overwriting it.
            # Stage and destination are on the same filesystem by construction.
            os.link(
                partial,
                destination,
            )
            partial.unlink()

        metadata.unlink(
            missing_ok=True
        )

        _response(
            secure,
            "complete",
            size=size,
            sha256=digest,
        )

    def _check_authorized(
        self,
        sender_id: str,
        secure: object,
    ) -> None:
        with self._lock:
            allowed = (
                sender_id in self._allowed
                and not self._stop.is_set()
            )

        if not allowed:
            raise TransferError(
                "Sender permission revoked during transfer"
            )

        self.trust_store.require(
            secure.remote_public_key
        )

    def send_file(
        self,
        host: str,
        port: int,
        expected_node_id: str,
        source_root: str | Path,
        relative_path: str,
        *,
        cancel_event: threading.Event | None = None,
        on_progress: Callable[[TransferProgress], None] | None = None,
    ) -> TransferResult:
        """Push one file. Cancellation retains a resumable partial on the receiver."""
        _validate_node(
            expected_node_id
        )

        if (
            type(port) is not int
            or not 1 <= port <= 65535
        ):
            raise ValueError(
                "Invalid remote transfer port"
            )

        if not isinstance(host, str):
            raise ValueError(
                "Remote host must be numeric IPv4"
            )

        try:
            destination_ip = ipaddress.IPv4Address(
                host
            )
        except ValueError as exc:
            raise ValueError(
                "Remote host must be numeric IPv4"
            ) from exc

        if (
            destination_ip.is_unspecified
            or destination_ip.is_multicast
            or host == "255.255.255.255"
        ):
            raise ValueError(
                "Remote host must be unicast IPv4"
            )

        if expected_node_id == self.identity.node_id:
            raise TransferError(
                "Cannot transfer to our own device"
            )

        if (
            on_progress is not None
            and not callable(on_progress)
        ):
            raise TypeError(
                "on_progress must be callable or None"
            )

        if (
            cancel_event is not None
            and not isinstance(cancel_event, threading.Event)
        ):
            raise TypeError(
                "cancel_event must be threading.Event or None"
            )

        segments = _path(
            relative_path
        )

        root = (
            Path(source_root)
            .expanduser()
            .absolute()
        )

        if not root.is_dir() or _linked(root):
            raise TransferError(
                "Invalid shared source directory"
            )

        source = _safe_child(
            root,
            segments,
            create=False,
        )

        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )

        try:
            fd = os.open(
                source,
                flags,
            )
        except OSError as exc:
            raise TransferError(
                f"Cannot open source file: {exc}"
            ) from exc

        with os.fdopen(fd, "rb") as input_file:
            before = os.fstat(
                input_file.fileno()
            )

            if not stat.S_ISREG(
                before.st_mode
            ):
                raise TransferError(
                    "Source must be a regular file"
                )

            if before.st_size > _MAX_FILE_SIZE:
                raise TransferError(
                    "File is too large"
                )

            digest = _file_hash(
                input_file
            )

            if not _same_file(
                before,
                os.fstat(input_file.fileno()),
            ):
                raise TransferError(
                    "Source changed while hashing"
                )

            input_file.seek(0)

            try:
                connection = socket.create_connection(
                    (host, port),
                    timeout=self.handshake_timeout,
                )
            except OSError as exc:
                raise TransferError(
                    f"Cannot reach receiver: {exc}"
                ) from exc

            try:
                secure, peer = open_secure_channel(
                    connection,
                    self.identity,
                    self.trust_store,
                    expected_node_id,
                    timeout=self.handshake_timeout,
                )

                secure.settimeout(
                    self.io_timeout
                )

                _response(
                    secure,
                    "offer",
                    path=relative_path,
                    size=before.st_size,
                    sha256=digest,
                )

                reply = _read_json(
                    secure,
                    {
                        "ready",
                        "error",
                        "already_complete",
                    },
                )

                if reply["type"] == "already_complete":
                    if (
                        set(reply) != {
                            "version",
                            "type",
                            "size",
                            "sha256",
                        }
                        or type(reply["size"]) is not int
                        or reply["size"] != before.st_size
                        or reply["sha256"] != digest
                    ):
                        raise TransferError(
                            "Invalid already-complete receipt"
                        )

                    return TransferResult(
                        relative_path,
                        digest,
                        before.st_size,
                        before.st_size,
                        True,
                    )

                _error_or(
                    reply,
                    "ready",
                )

                if set(reply) != {
                    "version",
                    "type",
                    "offset",
                }:
                    raise TransferError(
                        "Invalid transfer resume response"
                    )

                offset = reply["offset"]

                if (
                    type(offset) is not int
                    or not 0 <= offset <= before.st_size
                ):
                    raise TransferError(
                        "Invalid remote resume offset"
                    )

                input_file.seek(
                    offset
                )

                sent = offset

                self._progress(
                    "send",
                    peer.node_id,
                    relative_path,
                    sent,
                    before.st_size,
                    on_progress,
                )

                while sent < before.st_size:
                    if (
                        cancel_event is not None
                        and cancel_event.is_set()
                    ):
                        secure.sendall(
                            struct.pack("!I", 0)
                        )

                        _response(
                            secure,
                            "pause",
                        )

                        paused = _error_or(
                            _read_json(
                                secure,
                                {
                                    "paused",
                                    "error",
                                },
                            ),
                            "paused",
                        )

                        if (
                            type(paused.get("offset")) is not int
                            or paused["offset"] != sent
                        ):
                            raise TransferError(
                                "Invalid remote pause offset"
                            )

                        return TransferResult(
                            relative_path,
                            digest,
                            before.st_size,
                            sent,
                            False,
                        )

                    chunk = input_file.read(
                        min(
                            _CHUNK_SIZE,
                            before.st_size - sent,
                        )
                    )

                    if not chunk:
                        raise TransferError(
                            "Source truncated during transfer"
                        )

                    secure.sendall(
                        struct.pack(
                            "!I",
                            len(chunk),
                        ) + chunk
                    )

                    sent += len(chunk)

                    self._progress(
                        "send",
                        peer.node_id,
                        relative_path,
                        sent,
                        before.st_size,
                        on_progress,
                    )

                if not _same_file(
                    before,
                    os.fstat(
                        input_file.fileno()
                    ),
                ):
                    raise TransferError(
                        "Source changed during transfer"
                    )

                secure.sendall(
                    struct.pack("!I", 0)
                )

                _response(
                    secure,
                    "finish",
                )

                done = _error_or(
                    _read_json(
                        secure,
                        {
                            "complete",
                            "error",
                        },
                    ),
                    "complete",
                )

                if (
                    set(done) != {
                        "version",
                        "type",
                        "size",
                        "sha256",
                    }
                    or type(done["size"]) is not int
                    or done["size"] != before.st_size
                    or done["sha256"] != digest
                ):
                    raise TransferError(
                        "Invalid transfer completion receipt"
                    )

                self.trust_store.require(
                    secure.remote_public_key
                )

                return TransferResult(
                    relative_path,
                    digest,
                    before.st_size,
                    sent,
                    True,
                )

            except (
                OSError,
                SecurityError,
            ) as exc:
                raise TransferError(
                    f"Secure file transfer failed: {exc}"
                ) from exc

            finally:
                _close(connection)

    def _progress(
        self,
        direction: str,
        peer_id: str,
        path: str,
        transferred: int,
        total: int,
        callback: Callable[[TransferProgress], None] | None = None,
    ) -> None:
        update = TransferProgress(
            direction,
            peer_id,
            path,
            transferred,
            total,
        )

        for listener in (
            self._on_progress,
            callback,
        ):
            if listener is not None:
                try:
                    listener(update)
                except Exception:
                    logger.exception(
                        "Transfer progress callback failed"
                    )

    def _report(self, error: Exception) -> None:
        if self._on_error is None:
            logger.warning(
                "SyncBridge transfer: %s",
                error,
            )
        else:
            try:
                self._on_error(error)
            except Exception:
                logger.exception(
                    "Transfer error callback failed"
                )
