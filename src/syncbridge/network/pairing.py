
"""Explicit, signed, two-person pairing over TCP. No share permissions are granted.

Both users MUST independently compare the same 64-bit verification code on
separate devices (in person or via an authenticated out-of-band channel), then
enter the code shown by the OTHER person. Never auto-approve in production.
Discovery announcements are untrusted hints. Pairing messages are public and
are not encrypted; only keys, names, nonces and consent signals are exchanged.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import socket
import struct
import threading
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from syncbridge.network.security import DeviceIdentity, TrustStore, PairingError

PAIRING_PORT = 45840
_VERSION = 1
_CONTEXT = b"SyncBridge user-approved pairing v1\x00"
_MAX_FRAME = 2048


def _name(value: str) -> str:
    if not isinstance(value, str):
        raise PairingError("Invalid device name")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise PairingError("Invalid Unicode device name") from exc
    if (not value.strip() or size > 64
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise PairingError("Invalid device name")
    return value


def _raw(value: Any, size: int, label: str) -> bytes:
    if not isinstance(value, str) or len(value) != size * 2:
        raise PairingError(f"Invalid {label}")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise PairingError(f"Invalid {label}") from exc
    if result.hex() != value:
        raise PairingError(f"Invalid {label}")
    return result


def _exact_pairs(pairs):
    result = {}
    for key, val in pairs:
        if key in result:
            raise ValueError("Duplicate pairing field")
        result[key] = val
    return result


def _send(sock: socket.socket, kind: str, **fields: str) -> None:
    body = json.dumps(
        {"version": _VERSION, "type": kind, **fields},
        separators=(",", ":"), sort_keys=True, ensure_ascii=False,
    ).encode("utf-8")
    if len(body) > _MAX_FRAME:
        raise PairingError("Oversized pairing frame")
    sock.sendall(struct.pack("!I", len(body)) + body)


def _read(sock: socket.socket, size: int) -> bytes:
    output = bytearray()
    while len(output) < size:
        part = sock.recv(size - len(output))
        if not part:
            raise PairingError("Pairing connection closed")
        output.extend(part)
    return bytes(output)


def _recv(sock: socket.socket, kind: str, fields: set[str]) -> dict:
    (length,) = struct.unpack("!I", _read(sock, 4))
    if not 0 < length <= _MAX_FRAME:
        raise PairingError("Invalid pairing frame size")
    try:
        data = json.loads(
            _read(sock, length).decode("utf-8"),
            object_pairs_hook=_exact_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise PairingError("Malformed pairing message") from exc
    if (not isinstance(data, dict) or set(data) != fields | {"version", "type"}
            or type(data["version"]) is not int or data["version"] != _VERSION
            or data["type"] != kind):
        raise PairingError("Unexpected pairing message")
    return data


def _hello(key: bytes, nonce: bytes, name: str) -> bytes:
    encoded = name.encode("utf-8")
    return _CONTEXT + b"hello\x00" + key + nonce + struct.pack("!H", len(encoded)) + encoded


def _transcript(ik: bytes, rk: bytes, inc: bytes, rnc: bytes,
                initiator_name: str, responder_name: str) -> bytes:
    return (_CONTEXT + b"session\x00" + _hello(ik, inc, initiator_name)
            + _hello(rk, rnc, responder_name))


def _verify(key: bytes, signature: str, data: bytes) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(
            _raw(signature, 64, "signature"), data
        )
    except (InvalidSignature, ValueError) as exc:
        raise PairingError("Invalid device signature") from exc


def _fingerprint(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()


def _code(transcript: bytes) -> str:
    hex_code = hashlib.sha256(
        _CONTEXT + b"human-code\x00" + transcript
    ).hexdigest()[:16].upper()
    return "-".join(
        hex_code[index:index + 4]
        for index in range(0, 16, 4)
    )


def _check_code(expected: str, provided: str) -> None:
    if (not isinstance(provided, str)
            or not hmac.compare_digest(expected, provided.strip().upper())):
        raise PairingError("Verification codes did not match: pairing refused")


@dataclass(frozen=True, slots=True)
class PairingDetails:
    request_id: str
    remote_name: str
    remote_node_id: str
    remote_fingerprint: str
    address: str
    code: str


@dataclass(slots=True)
class _Pending:
    details: PairingDetails
    remote_key: bytes
    allowed: threading.Event = field(default_factory=threading.Event)
    denied: bool = False


class PairingSession:
    """Client-side pending request; caller MUST approve or reject/close it."""

    def __init__(self, sock: socket.socket, details: PairingDetails,
                 key: bytes, identity: DeviceIdentity, trust: TrustStore):
        self._sock = sock
        self.details = details
        self._key = key
        self._identity = identity
        self._trust = trust
        self._done = False

    def approve(self, code_from_other_device: str) -> None:
        if self._done:
            raise PairingError("Pairing session already completed")
        try:
            _check_code(self.details.code, code_from_other_device)
            _send(self._sock, "approve")
            _recv(self._sock, "approve", set())
            _recv(self._sock, "saved", set())
            self._trust.add_verified(
                self._key.hex(),
                confirmed_fingerprint=self.details.remote_fingerprint,
                name=self.details.remote_name,
                own_node_id=self._identity.node_id,
            )
        except (OSError, socket.timeout) as exc:
            raise PairingError("Pairing request failed or timed out") from exc
        finally:
            self.close()

    def reject(self) -> None:
        if not self._done:
            try:
                _send(self._sock, "reject")
            except OSError:
                pass
            self.close()

    def close(self) -> None:
        if not self._done:
            self._done = True
            self._sock.close()


class PairingClient:
    def __init__(self, identity: DeviceIdentity, trust: TrustStore, name: str):
        self.identity = identity
        self.trust = trust
        self.name = _name(name)

    def request(
        self,
        host: str,
        port: int = PAIRING_PORT,
        *,
        expected_node_id: str | None = None,
        timeout: float = 5.0,
        approval_timeout: float = 60.0,
    ) -> PairingSession:
        if (
            type(port) is not int
            or not 1 <= port <= 65535
            or any(
                type(value) not in (int, float)
                or not math.isfinite(value)
                or not 0 < value <= 300
                for value in (timeout, approval_timeout)
            )
        ):
            raise ValueError("Invalid pairing destination or timeout")

        sock = socket.create_connection((host, port), timeout=timeout)

        try:
            ik = self.identity.public_key
            inc = os.urandom(32)

            _send(
                sock,
                "hello",
                key=ik.hex(),
                nonce=inc.hex(),
                name=self.name,
                signature=self.identity.sign(
                    _hello(ik, inc, self.name)
                ).hex(),
            )

            reply = _recv(
                sock,
                "challenge",
                {"key", "nonce", "name", "signature"},
            )

            rk = _raw(reply["key"], 32, "public key")
            rnc = _raw(reply["nonce"], 32, "nonce")
            remote_name = _name(reply["name"])

            if rk == ik:
                raise PairingError("Cannot pair this device with itself")

            fingerprint = _fingerprint(rk)

            if (
                expected_node_id is not None
                and fingerprint[:32] != expected_node_id
            ):
                raise PairingError(
                    "Peer identity differs from the discovered device"
                )

            transcript = _transcript(
                ik, rk, inc, rnc, self.name, remote_name
            )

            _verify(
                rk,
                reply["signature"],
                b"responder\x00" + transcript,
            )

            _send(
                sock,
                "proof",
                signature=self.identity.sign(
                    b"initiator\x00" + transcript
                ).hex(),
            )

            ready = _recv(sock, "ready", {"signature"})

            _verify(
                rk,
                ready["signature"],
                b"ready\x00" + transcript,
            )

            sock.settimeout(approval_timeout)

            details = PairingDetails(
                os.urandom(12).hex(),
                remote_name,
                fingerprint[:32],
                fingerprint,
                host,
                _code(transcript),
            )

            return PairingSession(
                sock,
                details,
                rk,
                self.identity,
                self.trust,
            )

        except BaseException:
            sock.close()
            raise


class PairingService:
    """Listener with an explicit approval queue. Never auto-trust requests."""

    def __init__(
        self,
        identity: DeviceIdentity,
        trust: TrustStore,
        name: str,
        *,
        bind_address: str = "127.0.0.1",
        listen_port: int = PAIRING_PORT,
        approval_timeout: float = 60.0,
        max_pending: int = 8,
    ):
        if (
            type(listen_port) is not int
            or not 0 <= listen_port <= 65535
            or type(max_pending) is not int
            or not 1 <= max_pending <= 32
            or type(approval_timeout) not in (int, float)
            or not math.isfinite(approval_timeout)
            or not 0 < approval_timeout <= 300
        ):
            raise ValueError("Invalid pairing service options")

        self.identity = identity
        self.trust = trust
        self.name = _name(name)
        self.bind_address = bind_address
        self.listen_port = listen_port
        self.approval_timeout = approval_timeout
        self.max_pending = max_pending
        self.bound_port: int | None = None

        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._pending: dict[str, _Pending] = {}
        self._sockets: set[socket.socket] = set()
        self._workers: set[threading.Thread] = set()

    @property
    def running(self) -> bool:
        return (
            self._thread is not None
            and self._thread.is_alive()
            and not self._stop.is_set()
        )

    def start(self) -> None:
        with self._lock:
            if self.running:
                return

            if (
                self._thread is not None
                and self._thread.is_alive()
            ):
                raise RuntimeError(
                    "Pairing listener is still shutting down"
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
                    (self.bind_address, self.listen_port)
                )
                listener.listen(8)
                listener.settimeout(0.2)

            except BaseException:
                listener.close()
                raise

            self._listener = listener
            self.bound_port = listener.getsockname()[1]
            self._stop.clear()

            self._thread = threading.Thread(
                target=self._accept,
                name="SyncBridgePairing",
                daemon=True,
            )
            self._thread.start()

    def pending(self) -> tuple[PairingDetails, ...]:
        with self._lock:
            return tuple(
                item.details
                for item in self._pending.values()
            )

    def approve(
        self,
        request_id: str,
        code_from_other_device: str,
    ) -> None:
        with self._lock:
            request = self._pending.get(request_id)
            if request is None:
                raise PairingError(
                    "Unknown or expired pairing request"
                )

            _check_code(
                request.details.code,
                code_from_other_device,
            )

            request.allowed.set()

    def reject(self, request_id: str) -> None:
        with self._lock:
            request = self._pending.get(request_id)
            if request is None:
                raise PairingError(
                    "Unknown or expired pairing request"
                )

            request.denied = True
            request.allowed.set()

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                listener = self._listener
                if listener is None:
                    break
                sock, address = listener.accept()

            except socket.timeout:
                continue

            except OSError:
                break

            with self._lock:
                if len(self._sockets) >= self.max_pending + 4:
                    sock.close()
                    continue

                self._sockets.add(sock)

                worker = threading.Thread(
                    target=self._handle,
                    args=(sock, address[0]),
                    daemon=True,
                    name="SyncBridgePairRequest",
                )
                self._workers.add(worker)

            worker.start()

    def _handle(
        self,
        sock: socket.socket,
        host: str,
    ) -> None:
        request_id = None

        try:
            sock.settimeout(5)

            hello = _recv(
                sock,
                "hello",
                {"key", "nonce", "name", "signature"},
            )

            ik = _raw(hello["key"], 32, "public key")
            inc = _raw(hello["nonce"], 32, "nonce")
            other_name = _name(hello["name"])

            if ik == self.identity.public_key:
                raise PairingError(
                    "Cannot pair with this device"
                )

            _verify(
                ik,
                hello["signature"],
                _hello(ik, inc, other_name),
            )

            rk = self.identity.public_key
            rnc = os.urandom(32)

            transcript = _transcript(
                ik, rk, inc, rnc,
                other_name, self.name,
            )

            _send(
                sock,
                "challenge",
                key=rk.hex(),
                nonce=rnc.hex(),
                name=self.name,
                signature=self.identity.sign(
                    b"responder\x00" + transcript
                ).hex(),
            )

            proof = _recv(
                sock,
                "proof",
                {"signature"},
            )

            _verify(
                ik,
                proof["signature"],
                b"initiator\x00" + transcript,
            )

            fingerprint = _fingerprint(ik)
            request_id = os.urandom(12).hex()

            request = _Pending(
                PairingDetails(
                    request_id,
                    other_name,
                    fingerprint[:32],
                    fingerprint,
                    host,
                    _code(transcript),
                ),
                ik,
            )

            with self._lock:
                if len(self._pending) >= self.max_pending:
                    raise PairingError(
                        "Too many pending pairing requests"
                    )

                self._pending[request_id] = request

            _send(
                sock,
                "ready",
                signature=self.identity.sign(
                    b"ready\x00" + transcript
                ).hex(),
            )

            if (
                not request.allowed.wait(
                    timeout=self.approval_timeout
                )
                or request.denied
                or self._stop.is_set()
            ):
                return

            sock.settimeout(self.approval_timeout)

            _send(sock, "approve")
            _recv(sock, "approve", set())

            if self._stop.is_set():
                return

            self.trust.add_verified(
                ik.hex(),
                confirmed_fingerprint=fingerprint,
                name=other_name,
                own_node_id=self.identity.node_id,
            )

            _send(sock, "saved")

        except (OSError, PairingError, ValueError):
            # Malformed requests never grant access or
            # terminate the listener.
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

            sock.close()

    def stop(self) -> None:
        with self._lock:
            self._stop.set()

            listener = self._listener
            self._listener = None
            self.bound_port = None

            sockets = tuple(self._sockets)
            workers = tuple(self._workers)
            thread = self._thread

            for request in self._pending.values():
                request.denied = True
                request.allowed.set()

        if listener is not None:
            listener.close()

        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

        if (
            thread is not None
            and thread is not threading.current_thread()
        ):
            thread.join(timeout=2)

        for worker in workers:
            if worker is not threading.current_thread():
                worker.join(timeout=2)
