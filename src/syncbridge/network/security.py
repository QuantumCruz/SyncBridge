
"""Persistent device identities, explicit pairing and mutual TCP authentication.

Authentication is NOT encryption. Do not send file names, manifests or file
contents through these sockets until a separately verified encrypted channel
is installed. The current PeerManager HELLO handshake is unauthenticated and
is not automatically upgraded by importing this module.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import stat
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

IDENTITY_VERSION = 1
TRUST_VERSION = 1
AUTH_VERSION = 1
MAX_AUTH_FRAME = 1024
MAX_TRUSTED_DEVICES = 256
_HANDSHAKE_CONTEXT = b"SyncBridge mutual-auth v1\x00"
_ALLOWED_ROLES = frozenset({"responder", "initiator", "accepted"})


class SecurityError(Exception):
    """Invalid or unsafe security operation."""


class PairingError(SecurityError):
    """Explicit fingerprint confirmation or trust verification failed."""


class AuthenticationError(SecurityError):
    """Authentication proof, trusted identity or handshake is invalid."""


def _exact_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _decode_json(data: bytes) -> Any:
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_exact_object)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise SecurityError("Invalid security JSON document") from exc


def _hex_bytes(value: str, length: int, label: str) -> bytes:
    if not isinstance(value, str) or len(value) != length * 2:
        raise SecurityError(f"Invalid {label}")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise SecurityError(f"Invalid {label}") from exc
    if decoded.hex() != value or len(decoded) != length:
        raise SecurityError(f"Invalid {label}")
    return decoded


def _public_bytes(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _fingerprint(public_key: bytes) -> str:
    if type(public_key) is not bytes or len(public_key) != 32:
        raise SecurityError("Invalid public key length")
    try:
        Ed25519PublicKey.from_public_bytes(public_key)
    except ValueError as exc:
        raise SecurityError("Invalid Ed25519 public key") from exc
    return hashlib.sha256(public_key).hexdigest()


def _node_id(public_key: bytes) -> str:
    return _fingerprint(public_key)[:32]


def _name(value: str) -> str:
    if not isinstance(value, str):
        raise SecurityError("Device name must be text")
    try:
        raw = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SecurityError("Invalid Unicode device name") from exc
    if not value.strip() or len(raw) > 128 or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise SecurityError("Device name must be printable and 1-128 UTF-8 bytes")
    return value


def _safe_read(path: Path, maximum: int) -> bytes | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode):
        raise SecurityError(f"Security path must be a regular file: {path}")
    if metadata.st_size > maximum:
        raise SecurityError("Security file is too large")
    with path.open("rb") as stream:
        contents = stream.read(maximum + 1)
    if len(contents) > maximum:
        raise SecurityError("Security file is too large")
    return contents


def _ensure_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir() or path.is_symlink():
        raise SecurityError("Security directory is not a normal directory")


def _exclusive_write(path: Path, data: bytes) -> bool:
    """Create once without overwriting an identity belonging to another process."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        return False
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return True


def _json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(
        value, ensure_ascii=False, allow_nan=False,
        sort_keys=True, separators=(",", ":"),
    ) + "\n").encode("utf-8")


@dataclass(frozen=True, slots=True)
class DeviceIdentity:
    """Local Ed25519 private identity; never serialize this dataclass as a log."""

    _private_key: Ed25519PrivateKey = field(repr=False)

    @classmethod
    def generate(cls) -> DeviceIdentity:
        return cls(Ed25519PrivateKey.generate())

    @property
    def public_key(self) -> bytes:
        return _public_bytes(self._private_key)

    @property
    def public_key_hex(self) -> str:
        return self.public_key.hex()

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self.public_key)

    @property
    def node_id(self) -> str:
        return self.fingerprint[:32]

    def sign(self, document: bytes) -> bytes:
        if type(document) is not bytes:
            raise TypeError("Signed document must be bytes")
        return self._private_key.sign(document)

    def _to_document(self) -> dict[str, Any]:
        secret = self._private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        return {
            "version": IDENTITY_VERSION,
            "algorithm": "ed25519",
            "private_key": secret.hex(),
            "public_key": self.public_key_hex,
            "node_id": self.node_id,
        }

    @classmethod
    def _from_document(cls, document: Any) -> DeviceIdentity:
        if not isinstance(document, dict) or set(document) != {
            "version", "algorithm", "private_key", "public_key", "node_id"
        } or type(document["version"]) is not int or document["version"] != IDENTITY_VERSION or document["algorithm"] != "ed25519":
            raise SecurityError("Unsupported or malformed identity")
        secret = _hex_bytes(document["private_key"], 32, "private key")
        identity = cls(Ed25519PrivateKey.from_private_bytes(secret))
        if (document["public_key"] != identity.public_key_hex or
                document["node_id"] != identity.node_id):
            raise SecurityError("Identity key and public metadata disagree")
        return identity


def _create_identity_once(target: Path, data: bytes) -> bool:
    """Make identity visible only after its complete contents are on disk.

    os.link creates the final path atomically without replacing another
    process's identity; both paths reside on the same filesystem.
    """
    temp = target.with_name(f".{target.name}.{os.urandom(8).hex()}.tmp")
    if not _exclusive_write(temp, data):
        raise SecurityError("Unable to create identity staging file")
    try:
        try:
            os.link(temp, target)
        except FileExistsError:
            return False
        return True
    finally:
        temp.unlink(missing_ok=True)


def load_or_create_identity(path: str | Path) -> DeviceIdentity:
    """Create a private identity once and use it across app restarts.

    On Windows the secret file inherits its parent directory's ACL. Store it
    under the current user's private profile, never in a shared sync folder.
    """
    target = Path(path)
    _ensure_directory(target.parent)
    for _ in range(20):
        contents = _safe_read(target, 4096)
        if contents is not None:
            # Never overwrite an existing corrupt/private identity.
            return DeviceIdentity._from_document(_decode_json(contents))
        identity = DeviceIdentity.generate()
        if _create_identity_once(target, _json_bytes(identity._to_document())):
            return identity
    raise SecurityError("Identity file cannot be created")


@dataclass(frozen=True, slots=True)
class TrustedDevice:
    node_id: str
    name: str
    public_key_hex: str
    fingerprint: str
    added_at: float


class TrustStore:
    """Local explicit allowlist; no trust-on-first-use or silent key rotation."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        _ensure_directory(self.path.parent)
        self._devices: dict[str, TrustedDevice] = {}
        with self._lock:
            self._load()

    @property
    def devices(self) -> tuple[TrustedDevice, ...]:
        with self._lock:
            self._load()
            return tuple(sorted(self._devices.values(), key=lambda item: item.node_id))

    def get(self, node_id: str) -> TrustedDevice | None:
        with self._lock:
            self._load()
            return self._devices.get(node_id)

    def add_verified(
        self, public_key_hex: str, *, confirmed_fingerprint: str, name: str,
        own_node_id: str | None = None,
    ) -> TrustedDevice:
        """Trust only after the user compares the FULL fingerprint out-of-band.

        A fingerprint copied from the untrusted connection itself does not
        establish trust. UI must show the fingerprint on BOTH devices.
        """
        public_key = _hex_bytes(public_key_hex, 32, "public key")
        actual = _fingerprint(public_key)
        _hex_bytes(confirmed_fingerprint, 32, "confirmed fingerprint")
        if not hmac.compare_digest(actual, confirmed_fingerprint):
            raise PairingError("Fingerprint confirmation does not match public key")
        node_id = actual[:32]
        if node_id == own_node_id:
            raise PairingError("Cannot pair with the local device")
        validated_name = _name(name)
        with self._lock:
            self._load()
            existing = self._devices.get(node_id)
            if existing is not None:
                if existing.public_key_hex != public_key_hex:
                    raise PairingError("Node ID already belongs to a different key")
                if existing.name != validated_name:
                    updated = TrustedDevice(
                        node_id, validated_name, public_key_hex, actual, existing.added_at,
                    )
                    snapshot = dict(self._devices)
                    snapshot[node_id] = updated
                    self._save(snapshot)
                    self._devices = snapshot
                    return updated
                return existing
            if len(self._devices) >= MAX_TRUSTED_DEVICES:
                raise PairingError("Trusted device limit reached")
            device = TrustedDevice(node_id, validated_name, public_key_hex, actual, time.time())
            snapshot = dict(self._devices)
            snapshot[node_id] = device
            self._save(snapshot)
            self._devices = snapshot
            return device

    def remove(self, node_id: str) -> bool:
        with self._lock:
            self._load()
            if node_id not in self._devices:
                return False
            snapshot = dict(self._devices)
            del snapshot[node_id]
            self._save(snapshot)
            self._devices = snapshot
            return True

    def require(self, public_key: bytes) -> TrustedDevice:
        node_id = _node_id(public_key)
        with self._lock:
            self._load()
            device = self._devices.get(node_id)
        if device is None or not hmac.compare_digest(
            device.public_key_hex, public_key.hex()
        ):
            raise AuthenticationError("Remote device is not paired")
        return device

    def _load(self) -> None:
        data = _safe_read(self.path, 128 * 1024)
        if data is None:
            self._devices = {}
            return
        document = _decode_json(data)
        if (not isinstance(document, dict) or set(document) != {"version", "devices"}
                or type(document["version"]) is not int
                or document["version"] != TRUST_VERSION
                or not isinstance(document["devices"], list)
                or len(document["devices"]) > MAX_TRUSTED_DEVICES):
            raise SecurityError("Invalid trust store schema")
        devices = {}
        for record in document["devices"]:
            if not isinstance(record, dict) or set(record) != {
                "node_id", "name", "public_key", "fingerprint", "added_at"
            }:
                raise SecurityError("Invalid trusted device record")
            public_key = _hex_bytes(record["public_key"], 32, "public key")
            fingerprint = _fingerprint(public_key)
            if record["fingerprint"] != fingerprint or record["node_id"] != fingerprint[:32]:
                raise SecurityError("Corrupt trusted device identity")
            _name(record["name"])
            timestamp = record["added_at"]
            if type(timestamp) not in (float, int) or not 0 < timestamp < 10**12:
                raise SecurityError("Invalid trusted device timestamp")
            node_id = fingerprint[:32]
            if node_id in devices:
                raise SecurityError("Duplicate trusted device")
            devices[node_id] = TrustedDevice(
                node_id, record["name"], record["public_key"], fingerprint, float(timestamp)
            )
        self._devices = devices

    def _save(self, devices: dict[str, TrustedDevice]) -> None:
        document = {
            "version": TRUST_VERSION,
            "devices": [
                {
                    "node_id": item.node_id,
                    "name": item.name,
                    "public_key": item.public_key_hex,
                    "fingerprint": item.fingerprint,
                    "added_at": item.added_at,
                }
                for item in sorted(devices.values(), key=lambda entry: entry.node_id)
            ],
        }
        # An exclusive temporary file prevents partial/corrupted trust snapshots.
        temp = self.path.with_name(f".{self.path.name}.{os.urandom(8).hex()}.tmp")
        if not _exclusive_write(temp, _json_bytes(document)):
            raise SecurityError("Could not create trust store temporary file")
        try:
            if self.path.is_symlink():
                raise SecurityError("Refusing symlink as trust store")
            os.replace(temp, self.path)
        finally:
            temp.unlink(missing_ok=True)


def _transcript(
    role: str,
    initiator_key: bytes,
    responder_key: bytes,
    initiator_nonce: bytes,
    responder_nonce: bytes,
) -> bytes:
    if role not in _ALLOWED_ROLES:
        raise AuthenticationError("Unknown authentication role")
    for value in (initiator_key, responder_key, initiator_nonce, responder_nonce):
        if type(value) is not bytes or len(value) != 32:
            raise AuthenticationError("Invalid handshake transcript")
    return (_HANDSHAKE_CONTEXT + role.encode("ascii") + b"\x00" +
            initiator_key + responder_key + initiator_nonce + responder_nonce)


def _proof(identity: DeviceIdentity, role: str, ik: bytes, rk: bytes, inc: bytes, rnc: bytes) -> str:
    return identity.sign(_transcript(role, ik, rk, inc, rnc)).hex()


def _verify_proof(public_key: bytes, signature_hex: str, role: str,
                  ik: bytes, rk: bytes, inc: bytes, rnc: bytes) -> None:
    signature = _hex_bytes(signature_hex, 64, "signature")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, _transcript(role, ik, rk, inc, rnc)
        )
    except (InvalidSignature, ValueError) as exc:
        raise AuthenticationError("Invalid authentication signature") from exc


def _send(connection: socket.socket, kind: str, **fields: Any) -> None:
    payload = _json_bytes({"version": AUTH_VERSION, "type": kind, **fields})
    if len(payload) > MAX_AUTH_FRAME:
        raise AuthenticationError("Oversized authentication frame")
    connection.sendall(struct.pack("!I", len(payload)) + payload)


def _read_exact(connection: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        part = connection.recv(count - len(result))
        if not part:
            raise AuthenticationError("Connection closed during authentication")
        result.extend(part)
    return bytes(result)


def _receive(connection: socket.socket, kind: str, fields: set[str]) -> dict[str, Any]:
    length = struct.unpack("!I", _read_exact(connection, 4))[0]
    if not 0 < length <= MAX_AUTH_FRAME:
        raise AuthenticationError("Invalid authentication frame length")
    try:
        document = _decode_json(_read_exact(connection, length))
    except SecurityError as exc:
        raise AuthenticationError(str(exc)) from exc
    if (not isinstance(document, dict)
            or set(document) != (fields | {"version", "type"})
            or type(document["version"]) is not int
            or document["version"] != AUTH_VERSION
            or document["type"] != kind):
        raise AuthenticationError("Unexpected authentication message")
    return document


def _validate_timeout(timeout: float) -> float:
    import math
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Authentication timeout must be positive and finite")
    return float(timeout)


def authenticate_initiator(
    connection: socket.socket,
    identity: DeviceIdentity,
    trust_store: TrustStore,
    expected_node_id: str,
    *,
    timeout: float = 5.0,
) -> TrustedDevice:
    """Mutual challenge-response over an existing, otherwise unused TCP socket.

    Caller owns the socket; on failure caller MUST close it. On success this
    does NOT encrypt or authorize transferring file content.
    """
    timeout = _validate_timeout(timeout)
    peer = trust_store.get(expected_node_id)
    if peer is None:
        raise AuthenticationError("Expected remote device is not paired")
    previous_timeout = connection.gettimeout()
    connection.settimeout(timeout)
    try:
        ik = identity.public_key
        inc = os.urandom(32)
        _send(connection, "init", public_key=ik.hex(), nonce=inc.hex())
        answer = _receive(connection, "challenge", {"public_key", "nonce", "signature"})
        rk = _hex_bytes(answer["public_key"], 32, "public key")
        rnc = _hex_bytes(answer["nonce"], 32, "responder nonce")
        if not hmac.compare_digest(peer.public_key_hex, rk.hex()):
            raise AuthenticationError("Remote public key differs from paired device")
        _verify_proof(rk, answer["signature"], "responder", ik, rk, inc, rnc)
        _send(connection, "proof", signature=_proof(identity, "initiator", ik, rk, inc, rnc))
        finished = _receive(connection, "accepted", {"signature"})
        _verify_proof(rk, finished["signature"], "accepted", ik, rk, inc, rnc)
        trust_store.require(rk)  # Revocation during handshake is authoritative.
        return peer
    except (OSError, SecurityError) as exc:
        if isinstance(exc, AuthenticationError):
            raise
        raise AuthenticationError(f"Authentication failed: {exc}") from exc
    finally:
        connection.settimeout(previous_timeout)


def authenticate_responder(
    connection: socket.socket,
    identity: DeviceIdentity,
    trust_store: TrustStore,
    *,
    timeout: float = 5.0,
) -> TrustedDevice:
    """Verify remote initiator's proof before acknowledging authentication."""
    timeout = _validate_timeout(timeout)
    previous_timeout = connection.gettimeout()
    connection.settimeout(timeout)
    try:
        hello = _receive(connection, "init", {"public_key", "nonce"})
        ik = _hex_bytes(hello["public_key"], 32, "public key")
        inc = _hex_bytes(hello["nonce"], 32, "initiator nonce")
        if ik == identity.public_key:
            raise AuthenticationError("Cannot authenticate self")
        peer = trust_store.require(ik)
        rk = identity.public_key
        rnc = os.urandom(32)
        _send(
            connection, "challenge", public_key=rk.hex(), nonce=rnc.hex(),
            signature=_proof(identity, "responder", ik, rk, inc, rnc),
        )
        answer = _receive(connection, "proof", {"signature"})
        _verify_proof(ik, answer["signature"], "initiator", ik, rk, inc, rnc)
        # Revocations during handshake must prevent acceptance.
        trust_store.require(ik)
        _send(connection, "accepted", signature=_proof(identity, "accepted", ik, rk, inc, rnc))
        return peer
    except (OSError, SecurityError) as exc:
        if isinstance(exc, AuthenticationError):
            raise
        raise AuthenticationError(f"Authentication failed: {exc}") from exc
    finally:
        connection.settimeout(previous_timeout)
