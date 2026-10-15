
"""Authenticated, read-only exchange of SyncBridge folder inventories.

Each request uses a separate mutually authenticated encrypted TCP connection.
A trusted device also needs explicit per-share read permission. No absolute
folder path is transmitted, and this module never modifies synchronized files.

A manifest is an observation, NOT an authorization to overwrite or delete a
file. The future sync coordinator must rescan before executing transfers and
must commit a shared baseline only after both devices agree on the result.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import os
import re
import socket
import struct
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping
from uuid import uuid4

from syncbridge.core.scanner import FileRecord, FileScanner, ScanResult
from syncbridge.storage.shared_state import (
    SharedStateDatabase,
    SharedStateError,
    _canonical_rows,
    _digest,
)

from .secure_channel import accept_secure_channel, open_secure_channel
from .security import DeviceIdentity, SecurityError, TrustStore

logger = logging.getLogger(__name__)

MANIFEST_VERSION = 1
DEFAULT_MANIFEST_PORT = 45843
MAX_MANIFEST_FILES = 250_000
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
_MAX_CONTROL_BYTES = 48 * 1024
_MAX_CLIENTS = 8
_ID = re.compile(r"[0-9a-f]{32}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class ManifestError(Exception):
    """Malformed inventory, denied access, or interrupted manifest exchange."""


@dataclass(frozen=True, slots=True)
class RemoteManifest:
    peer_node_id: str
    share_id: str
    snapshot: ScanResult
    inventory_sha256: str
    baseline_revision: int
    baseline_sha256: str | None


def _id(value: str, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValueError(f"{label} must be 32 lowercase hexadecimal characters")
    return value


def _timeout(value: float, label: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{label} must be a finite positive number")
    return float(value)


def _normal_root(root: str | Path) -> Path:
    candidate = Path(root).expanduser()
    if candidate.is_symlink() or (
        hasattr(os.path, "isjunction") and os.path.isjunction(candidate)
    ):
        raise ValueError("Share root cannot be a symbolic link or junction")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir():
        raise NotADirectoryError(resolved)
    return resolved


def _unique(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate manifest JSON key")
        result[key] = value
    return result


def _bad_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")


def _send(connection: object, kind: str, **fields: object) -> int:
    encoded = json.dumps(
        {"version": MANIFEST_VERSION, "type": kind, **fields},
        ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > _MAX_CONTROL_BYTES:
        raise ManifestError("Manifest control frame exceeds size limit")
    connection.sendall(struct.pack("!I", len(encoded)) + encoded)
    return len(encoded)


def _read_exact(connection: object, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = connection.recv(length - len(result))
        if not chunk:
            raise ManifestError("Manifest connection closed unexpectedly")
        result.extend(chunk)
    return bytes(result)


def _receive(connection: object, kinds: set[str]) -> tuple[dict, int]:
    (length,) = struct.unpack("!I", _read_exact(connection, 4))
    if not 0 < length <= _MAX_CONTROL_BYTES:
        raise ManifestError("Invalid manifest control frame length")
    try:
        data = json.loads(
            _read_exact(connection, length).decode("utf-8"),
            object_pairs_hook=_unique,
            parse_constant=_bad_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ManifestError("Malformed manifest JSON") from exc
    if (
        not isinstance(data, dict)
        or type(data.get("version")) is not int
        or data["version"] != MANIFEST_VERSION
        or data.get("type") not in kinds
    ):
        raise ManifestError("Unexpected or unsupported manifest message")
    return data, length


def _expect(document: dict, kind: str, fields: set[str]) -> None:
    if document["type"] != kind or set(document) != fields | {"version", "type"}:
        raise ManifestError(f"Invalid {kind} message fields")


def _close(connection: socket.socket) -> None:
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        connection.close()
    except OSError:
        pass


def _check_remote_record(raw: object) -> FileRecord:
    if not isinstance(raw, list) or len(raw) != 3:
        raise ManifestError("Malformed manifest file entry")
    path, size, digest = raw
    if (
        not isinstance(path, str)
        or type(size) is not int
        or not 0 <= size <= 2**63 - 1
        or not isinstance(digest, str)
        or _SHA.fullmatch(digest) is None
    ):
        raise ManifestError("Invalid manifest file entry")
    return FileRecord(path, size, 0, digest)


class ManifestService:
    """Serve or fetch read-only inventories of explicitly authorized folders.

    Each share_id maps to a local root and an independent reader allowlist.
    Pairing alone never grants access. Reader grants are in-memory at this
    stage and must be restored from user-approved settings at application start.
    """

    def __init__(
        self,
        identity: DeviceIdentity,
        trust_store: TrustStore,
        shares: Mapping[str, str | Path] | None = None,
        *,
        allowed_readers: Mapping[str, Iterable[str]] | None = None,
        shared_state: SharedStateDatabase | None = None,
        bind_address: str = "0.0.0.0",
        listen_port: int = DEFAULT_MANIFEST_PORT,
        handshake_timeout: float = 5.0,
        io_timeout: float = 300.0,
    ) -> None:
        if not isinstance(identity, DeviceIdentity) or not isinstance(trust_store, TrustStore):
            raise TypeError("identity and trust_store must be provided")
        if shared_state is not None and not isinstance(shared_state, SharedStateDatabase):
            raise TypeError("shared_state must be a SharedStateDatabase or None")
        if type(listen_port) is not int or not 0 <= listen_port <= 65535:
            raise ValueError("Invalid manifest listening port")
        try:
            address = ipaddress.IPv4Address(bind_address)
        except ValueError as exc:
            raise ValueError("bind_address must be numeric IPv4") from exc
        if address.is_multicast:
            raise ValueError("Cannot bind to a multicast address")
        self.bind_address = str(address)
        self.listen_port = listen_port
        self.handshake_timeout = _timeout(handshake_timeout, "handshake_timeout")
        self.io_timeout = _timeout(io_timeout, "io_timeout")
        self.identity = identity
        self.trust_store = trust_store
        self.shared_state = shared_state
        self._shares = {
            _id(share, "share_id"): _normal_root(root)
            for share, root in (shares or {}).items()
        }
        self._readers: dict[str, set[str]] = {share: set() for share in self._shares}
        for share, readers in (allowed_readers or {}).items():
            _id(share, "share_id")
            if share not in self._shares:
                raise ValueError("Reader authorization refers to an unknown share")
            self._readers[share] = {_id(node, "reader_node_id") for node in readers}
        self._lock = threading.RLock()
        self._stopped = threading.Event()
        self._stopped.set()
        self._listener: socket.socket | None = None
        self._bound_port: int | None = None
        self._connections: set[socket.socket] = set()
        self._threads: set[threading.Thread] = set()

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._listener is not None and not self._stopped.is_set()

    @property
    def bound_port(self) -> int | None:
        with self._lock:
            return self._bound_port

    def register_share(self, share_id: str, root: str | Path) -> None:
        share_id = _id(share_id, "share_id")
        normalized = _normal_root(root)
        with self._lock:
            if share_id in self._shares and self._shares[share_id] != normalized:
                raise ValueError("Share identifier already belongs to another folder")
            self._shares[share_id] = normalized
            self._readers.setdefault(share_id, set())

    def authorize_reader(self, share_id: str, node_id: str) -> None:
        share_id = _id(share_id, "share_id")
        node_id = _id(node_id, "reader_node_id")
        with self._lock:
            if share_id not in self._shares:
                raise ValueError("Unknown share")
            self._readers[share_id].add(node_id)

    def revoke_reader(self, share_id: str, node_id: str) -> None:
        share_id = _id(share_id, "share_id")
        node_id = _id(node_id, "reader_node_id")
        with self._lock:
            if share_id in self._readers:
                self._readers[share_id].discard(node_id)

    def _permitted_root(self, share_id: str, node_id: str, public_key: bytes) -> Path:
        self.trust_store.require(public_key)
        with self._lock:
            root = self._shares.get(share_id)
            allowed = (
                root is not None
                and node_id in self._readers.get(share_id, ())
                and not self._stopped.is_set()
            )
        if not allowed:
            raise ManifestError("Share is not available to this device")
        return root

    def _spawn(self, method, *args) -> None:
        def run() -> None:
            try:
                method(*args)
            finally:
                with self._lock:
                    self._threads.discard(threading.current_thread())
        thread = threading.Thread(target=run, daemon=True, name="SyncBridgeManifest")
        with self._lock:
            self._threads.add(thread)
        thread.start()

    def start(self) -> None:
        with self._lock:
            if self._listener is not None:
                return
            if self._threads:
                raise RuntimeError("Previous manifest workers are still stopping")
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((self.bind_address, self.listen_port))
                listener.listen(_MAX_CLIENTS)
                listener.settimeout(0.2)
            except BaseException:
                listener.close()
                raise
            self._listener = listener
            self._bound_port = listener.getsockname()[1]
            self._stopped.clear()
            self._spawn(self._accept_loop)

    def stop(self) -> None:
        with self._lock:
            self._stopped.set()
            listener, self._listener = self._listener, None
            self._bound_port = None
            connections = tuple(self._connections)
            threads = tuple(self._threads)
        if listener is not None:
            _close(listener)
        for connection in connections:
            _close(connection)
        for thread in threads:
            if thread is not threading.current_thread():
                thread.join(timeout=self.handshake_timeout + 1)

    def _accept_loop(self) -> None:
        while not self._stopped.is_set():
            with self._lock:
                listener = self._listener
            if listener is None:
                return
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if not self._stopped.is_set():
                    logger.exception("Manifest listener failed")
                return
            with self._lock:
                allowed = not self._stopped.is_set() and len(self._connections) < _MAX_CLIENTS
                if allowed:
                    self._connections.add(connection)
            if allowed:
                self._spawn(self._serve, connection)
            else:
                _close(connection)

    def _serve(self, connection: socket.socket) -> None:
        secure = None
        try:
            secure, peer = accept_secure_channel(
                connection, self.identity, self.trust_store,
                timeout=self.handshake_timeout,
            )
            secure.settimeout(self.io_timeout)
            request, _ = _receive(secure, {"manifest_request"})
            _expect(request, "manifest_request", {"share_id", "request_id"})
            share_id = _id(request["share_id"], "share_id")
            request_id = _id(request["request_id"], "request_id")
            root = self._permitted_root(share_id, peer.node_id, secure.remote_public_key)
            snapshot = FileScanner(root).scan()
            try:
                rows = _canonical_rows(snapshot, root)
                inventory_hash = _digest(rows)
            except SharedStateError as exc:
                raise ManifestError(f"Share cannot be inventoried safely: {exc}") from exc
            if len(rows) > MAX_MANIFEST_FILES:
                raise ManifestError("Manifest file limit exceeded")
            baseline = None
            if self.shared_state is not None:
                baseline = self.shared_state.load(root, peer.node_id, share_id)
            self._permitted_root(share_id, peer.node_id, secure.remote_public_key)
            _send(
                secure, "manifest_start", request_id=request_id,
                share_id=share_id, file_count=len(rows),
                baseline_revision=baseline.revision if baseline is not None else 0,
                baseline_sha256=baseline.sha256 if baseline is not None else None,
            )
            total_bytes = 0
            index = 0
            batch: list[list[object]] = []
            batch_bytes = 128  # Frame fields, separators, and small integer indices.
            for path, size, digest in rows:
                entry: list[object] = [path, size, digest]
                entry_size = len(json.dumps(
                    entry, ensure_ascii=False, separators=(",", ":"),
                ).encode("utf-8")) + 1
                if batch and batch_bytes + entry_size > _MAX_CONTROL_BYTES - 512:
                    self._permitted_root(share_id, peer.node_id, secure.remote_public_key)
                    total_bytes += _send(
                        secure, "manifest_chunk", request_id=request_id,
                        index=index, entries=batch,
                    )
                    if total_bytes > MAX_MANIFEST_BYTES:
                        raise ManifestError("Manifest total size limit exceeded")
                    index += 1
                    batch = []
                    batch_bytes = 128
                batch.append(entry)
                batch_bytes += entry_size
            if batch:
                self._permitted_root(share_id, peer.node_id, secure.remote_public_key)
                total_bytes += _send(
                    secure, "manifest_chunk", request_id=request_id,
                    index=index, entries=batch,
                )
            if total_bytes > MAX_MANIFEST_BYTES:
                raise ManifestError("Manifest total size limit exceeded")
            self._permitted_root(share_id, peer.node_id, secure.remote_public_key)
            _send(secure, "manifest_end", request_id=request_id, file_count=len(rows), inventory_sha256=inventory_hash)
        except (OSError, ManifestError, SecurityError, SharedStateError, ValueError) as exc:
            if secure is not None and not self._stopped.is_set():
                try:
                    _send(secure, "manifest_error", reason=str(exc)[:192])
                except OSError:
                    pass
            if not self._stopped.is_set():
                logger.debug("Manifest request rejected: %s", exc)
        finally:
            _close(connection)
            with self._lock:
                self._connections.discard(connection)

    def fetch(
        self,
        host: str,
        port: int,
        expected_node_id: str,
        share_id: str,
    ) -> RemoteManifest:
        """Request a remote inventory over a fresh encrypted TCP connection."""
        expected_node_id = _id(expected_node_id, "expected_node_id")
        share_id = _id(share_id, "share_id")
        if not isinstance(host, str):
            raise ValueError("host must be numeric IPv4")
        try:
            address = ipaddress.IPv4Address(host)
        except ValueError as exc:
            raise ValueError("host must be numeric IPv4") from exc
        if address.is_unspecified or address.is_multicast or address.is_reserved or str(address) == "255.255.255.255":
            raise ValueError("host must be a usable IPv4 address")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("port must be 1-65535")
        if expected_node_id == self.identity.node_id:
            raise ManifestError("Cannot fetch an inventory from our own identity")
        if self.trust_store.get(expected_node_id) is None:
            raise ManifestError("Device is not paired")
        try:
            connection = socket.create_connection(
                (str(address), port), timeout=self.handshake_timeout,
            )
        except OSError as exc:
            raise ManifestError(f"Cannot reach manifest service: {exc}") from exc
        try:
            secure, peer = open_secure_channel(
                connection, self.identity, self.trust_store,
                expected_node_id, timeout=self.handshake_timeout,
            )
            secure.settimeout(self.io_timeout)
            request_id = uuid4().hex
            _send(secure, "manifest_request", share_id=share_id, request_id=request_id)
            start, _ = _receive(secure, {"manifest_start", "manifest_error"})
            if start["type"] == "manifest_error":
                _expect(start, "manifest_error", {"reason"})
                raise ManifestError(str(start["reason"])[:192])
            _expect(start, "manifest_start", {
                "request_id", "share_id", "file_count", "baseline_revision", "baseline_sha256",
            })
            if start["request_id"] != request_id or start["share_id"] != share_id:
                raise ManifestError("Manifest response does not match request")
            count = start["file_count"]
            revision = start["baseline_revision"]
            baseline_hash = start["baseline_sha256"]
            if type(count) is not int or not 0 <= count <= MAX_MANIFEST_FILES:
                raise ManifestError("Invalid remote file count")
            if type(revision) is not int or revision < 0 or revision > 2**63 - 1:
                raise ManifestError("Invalid baseline revision")
            if not (
                (revision == 0 and baseline_hash is None)
                or (revision > 0 and isinstance(baseline_hash, str) and _SHA.fullmatch(baseline_hash))
            ):
                raise ManifestError("Invalid remote baseline digest")
            records: dict[str, FileRecord] = {}
            packet_index = 0
            total_bytes = 0
            while len(records) < count:
                packet, encoded_length = _receive(secure, {"manifest_chunk", "manifest_error"})
                if packet["type"] == "manifest_error":
                    _expect(packet, "manifest_error", {"reason"})
                    raise ManifestError(str(packet["reason"])[:192])
                _expect(packet, "manifest_chunk", {"request_id", "index", "entries"})
                if packet["request_id"] != request_id or type(packet["index"]) is not int or packet["index"] != packet_index:
                    raise ManifestError("Out-of-order manifest chunk")
                entries = packet["entries"]
                if not isinstance(entries, list) or not entries or len(entries) > count - len(records):
                    raise ManifestError("Invalid manifest chunk count")
                total_bytes += encoded_length
                if total_bytes > MAX_MANIFEST_BYTES:
                    raise ManifestError("Manifest exceeds maximum encoded size")
                for raw in entries:
                    record = _check_remote_record(raw)
                    if record.relative_path in records:
                        raise ManifestError("Duplicate remote file path")
                    records[record.relative_path] = record
                packet_index += 1
            end, _ = _receive(secure, {"manifest_end", "manifest_error"})
            if end["type"] == "manifest_error":
                _expect(end, "manifest_error", {"reason"})
                raise ManifestError(str(end["reason"])[:192])
            _expect(end, "manifest_end", {"request_id", "file_count", "inventory_sha256"})
            if end["request_id"] != request_id or type(end["file_count"]) is not int or end["file_count"] != count:
                raise ManifestError("Invalid manifest completion")
            virtual_root = Path(f"remote-share-{share_id}")
            snapshot = ScanResult(root=virtual_root, files=records)
            try:
                rows = _canonical_rows(snapshot, virtual_root.resolve())
                calculated = _digest(rows)
            except SharedStateError as exc:
                raise ManifestError(f"Unsafe remote manifest: {exc}") from exc
            if end["inventory_sha256"] != calculated:
                raise ManifestError("Remote manifest integrity digest mismatch")
            self.trust_store.require(secure.remote_public_key)
            return RemoteManifest(
                peer.node_id, share_id, snapshot, calculated, revision, baseline_hash,
            )
        except (OSError, SecurityError) as exc:
            raise ManifestError(f"Encrypted manifest exchange failed: {exc}") from exc
        finally:
            _close(connection)
