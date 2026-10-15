
"""Mutually authenticated encrypted TCP stream for paired SyncBridge devices.

Protocol v1 uses an ephemeral X25519 exchange signed with each installation's
persistent Ed25519 key. HKDF derives independent AES-256-GCM record keys.

The caller owns the underlying TCP socket, including closing it after a failed
handshake. No application data should be sent before the handshake completes.
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
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .security import AuthenticationError, DeviceIdentity, TrustStore, TrustedDevice

_SECURE_VERSION = 1
_CONTEXT = b"SyncBridge X25519-Ed25519 AESGCM transport v1\x00"
_RECORD_CONTEXT = b"SyncBridge encrypted record v1\x00"
_MAX_HANDSHAKE_FRAME = 1024
_MAX_PLAINTEXT = 64 * 1024
_MAX_CIPHERTEXT = _MAX_PLAINTEXT + 16
_MAX_RECORDS = 2**32


def _hex(value: Any, length: int, label: str) -> bytes:
    if not isinstance(value, str) or len(value) != length * 2:
        raise AuthenticationError(f"Invalid {label}")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise AuthenticationError(f"Invalid {label}") from exc
    if raw.hex() != value or len(raw) != length:
        raise AuthenticationError(f"Invalid {label}")
    return raw


def _no_duplicates(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate handshake field")
        result[key] = value
    return result


def _json_send(sock: socket.socket, kind: str, **fields: str) -> None:
    packet = json.dumps(
        {"version": _SECURE_VERSION, "type": kind, **fields},
        allow_nan=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    if len(packet) > _MAX_HANDSHAKE_FRAME:
        raise AuthenticationError("Oversized handshake")
    sock.sendall(struct.pack("!I", len(packet)) + packet)


def _read_exact(sock: socket.socket, length: int, *, eof_ok: bool = False) -> bytes | None:
    result = bytearray()
    while len(result) < length:
        part = sock.recv(length - len(result))
        if not part:
            if eof_ok and not result:
                return None
            raise OSError("Truncated encrypted or authentication frame")
        result.extend(part)
    return bytes(result)


def _json_receive(sock: socket.socket, kind: str, fields: set[str]) -> dict[str, Any]:
    header = _read_exact(sock, 4)
    assert header is not None
    (size,) = struct.unpack("!I", header)
    if not 0 < size <= _MAX_HANDSHAKE_FRAME:
        raise AuthenticationError("Invalid handshake frame length")
    packet = _read_exact(sock, size)
    assert packet is not None
    try:
        document = json.loads(
            packet.decode("utf-8"), object_pairs_hook=_no_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise AuthenticationError("Malformed handshake JSON") from exc
    if (
        not isinstance(document, dict)
        or set(document) != fields | {"version", "type"}
        or type(document["version"]) is not int
        or document["version"] != _SECURE_VERSION
        or document["type"] != kind
    ):
        raise AuthenticationError("Unexpected handshake message")
    return document


def _transcript(
    initiator_key: bytes, responder_key: bytes,
    initiator_ephemeral: bytes, responder_ephemeral: bytes,
    initiator_nonce: bytes, responder_nonce: bytes,
) -> bytes:
    return (
        _CONTEXT + initiator_key + responder_key + initiator_ephemeral
        + responder_ephemeral + initiator_nonce + responder_nonce
    )


def _signature(identity: DeviceIdentity, role: bytes, transcript: bytes) -> str:
    return identity.sign(role + b"\x00" + transcript).hex()


def _check_signature(key: bytes, signature: Any, role: bytes, transcript: bytes) -> None:
    proof = _hex(signature, 64, "signature")
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(
            proof, role + b"\x00" + transcript,
        )
    except (InvalidSignature, ValueError) as exc:
        raise AuthenticationError("Handshake signature verification failed") from exc


def _derive(shared_secret: bytes, transcript: bytes) -> tuple[bytes, bytes]:
    keys = HKDF(
        algorithm=hashes.SHA256(), length=64,
        salt=hashlib.sha256(transcript).digest(),
        info=_CONTEXT + b"record keys",
    ).derive(shared_secret)
    return keys[:32], keys[32:]


def _ephemeral_keypair() -> tuple[X25519PrivateKey, bytes]:
    private = X25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private, public


def _exchange(private: X25519PrivateKey, remote: bytes) -> bytes:
    try:
        return private.exchange(X25519PublicKey.from_public_bytes(remote))
    except ValueError as exc:
        raise AuthenticationError("Invalid ephemeral exchange key") from exc


def _timeout(value: float) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise ValueError("Handshake timeout must be a positive finite number")
    return float(value)


class SecureSocket:
    """Socket-like encrypted stream compatible with send_message/receive_message.

    A record boundary is not an application message boundary: recv() retains
    decrypted surplus bytes. Concurrent sends are serialized, as are receives.
    """

    def __init__(
        self, connection: socket.socket, send_key: bytes, receive_key: bytes,
        *, initiator: bool, remote_public_key: bytes,
    ) -> None:
        if not isinstance(connection, socket.socket):
            raise TypeError("connection must be a TCP socket")
        if type(send_key) is not bytes or len(send_key) != 32:
            raise ValueError("Invalid outgoing AES-256 key")
        if type(receive_key) is not bytes or len(receive_key) != 32:
            raise ValueError("Invalid incoming AES-256 key")
        if type(remote_public_key) is not bytes or len(remote_public_key) != 32:
            raise ValueError("Invalid remote public key")
        self._socket = connection
        self._encryptor = AESGCM(send_key)
        self._decryptor = AESGCM(receive_key)
        self._send_direction = b"\x01" if initiator else b"\x02"
        self._receive_direction = b"\x02" if initiator else b"\x01"
        self._send_seq = 0
        self._receive_seq = 0
        self._read_buffer = bytearray()
        self._send_lock = threading.Lock()
        self._receive_lock = threading.Lock()
        self._closed = False
        self.remote_public_key = remote_public_key

    def sendall(self, data: bytes | bytearray | memoryview) -> None:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("Encrypted stream requires bytes")
        source = memoryview(data)
        with self._send_lock:
            if self._closed:
                raise OSError("Encrypted channel is closed")
            for position in range(0, len(source), _MAX_PLAINTEXT):
                if self._send_seq >= _MAX_RECORDS:
                    self.close()
                    raise OSError("Encrypted record counter exhausted")
                chunk = source[position: position + _MAX_PLAINTEXT]
                sequence = self._send_seq.to_bytes(12, "big")
                size = len(chunk) + 16
                header = struct.pack("!I", size)
                aad = _RECORD_CONTEXT + self._send_direction + sequence + header
                ciphertext = self._encryptor.encrypt(sequence, chunk, aad)
                self._socket.sendall(header + ciphertext)
                self._send_seq += 1

    def recv(self, size: int) -> bytes:
        if type(size) is not int or size < 0:
            raise ValueError("recv size must be a nonnegative integer")
        if size == 0:
            return b""
        with self._receive_lock:
            if not self._read_buffer and not self._closed:
                self._read_record()
            if not self._read_buffer:
                return b""
            chunk = bytes(self._read_buffer[:size])
            del self._read_buffer[:size]
            return chunk

    def _read_record(self) -> None:
        try:
            header = _read_exact(self._socket, 4, eof_ok=True)
            if header is None:
                self._closed = True
                return
            (length,) = struct.unpack("!I", header)
            if not 16 < length <= _MAX_CIPHERTEXT:
                raise OSError("Invalid encrypted record size")
            if self._receive_seq >= _MAX_RECORDS:
                raise OSError("Encrypted record counter exhausted")
            ciphertext = _read_exact(self._socket, length)
            assert ciphertext is not None
            sequence = self._receive_seq.to_bytes(12, "big")
            aad = _RECORD_CONTEXT + self._receive_direction + sequence + header
            plaintext = self._decryptor.decrypt(sequence, ciphertext, aad)
            self._receive_seq += 1
            self._read_buffer.extend(plaintext)
        except (OSError, InvalidTag) as exc:
            self.close()
            raise OSError("Encrypted record invalid, truncated or tampered") from exc

    def settimeout(self, timeout: float | None) -> None:
        self._socket.settimeout(timeout)

    def gettimeout(self) -> float | None:
        return self._socket.gettimeout()

    def shutdown(self, how: int) -> None:
        self._socket.shutdown(how)

    def close(self) -> None:
        self._closed = True
        self._socket.close()

    def fileno(self) -> int:
        return self._socket.fileno()


def open_secure_channel(
    connection: socket.socket,
    identity: DeviceIdentity,
    trust_store: TrustStore,
    expected_node_id: str,
    *,
    timeout: float = 5.0,
) -> tuple[SecureSocket, TrustedDevice]:
    """Initiate an encrypted session with a previously confirmed remote key."""
    limit = _timeout(timeout)
    peer = trust_store.get(expected_node_id)
    if peer is None:
        raise AuthenticationError("Expected remote device is not paired")
    original_timeout = connection.gettimeout()
    connection.settimeout(limit)
    try:
        ik = identity.public_key
        ie_private, ie = _ephemeral_keypair()
        inc = os.urandom(32)
        _json_send(
            connection, "hello", public_key=ik.hex(),
            ephemeral_key=ie.hex(), nonce=inc.hex(),
        )
        answer = _json_receive(
            connection, "challenge", {"public_key", "ephemeral_key", "nonce", "signature"},
        )
        rk = _hex(answer["public_key"], 32, "responder public key")
        re = _hex(answer["ephemeral_key"], 32, "responder ephemeral key")
        rnc = _hex(answer["nonce"], 32, "responder nonce")
        if not hmac.compare_digest(peer.public_key_hex, rk.hex()):
            raise AuthenticationError("Remote public key differs from paired device")
        transcript = _transcript(ik, rk, ie, re, inc, rnc)
        _check_signature(rk, answer["signature"], b"responder", transcript)
        shared = _exchange(ie_private, re)
        _json_send(connection, "proof", signature=_signature(identity, b"initiator", transcript))
        accepted = _json_receive(connection, "accepted", {"signature"})
        _check_signature(rk, accepted["signature"], b"accepted", transcript)
        trust_store.require(rk)
        outbound, inbound = _derive(shared, transcript)
        return SecureSocket(
            connection, outbound, inbound,
            initiator=True, remote_public_key=rk,
        ), peer
    except (OSError, AuthenticationError) as exc:
        if isinstance(exc, AuthenticationError):
            raise
        raise AuthenticationError(f"Secure handshake failed: {exc}") from exc
    finally:
        connection.settimeout(original_timeout)


def accept_secure_channel(
    connection: socket.socket,
    identity: DeviceIdentity,
    trust_store: TrustStore,
    *,
    timeout: float = 5.0,
) -> tuple[SecureSocket, TrustedDevice]:
    """Accept only devices in the local trust store, proving both key holders."""
    limit = _timeout(timeout)
    original_timeout = connection.gettimeout()
    connection.settimeout(limit)
    try:
        request = _json_receive(connection, "hello", {"public_key", "ephemeral_key", "nonce"})
        ik = _hex(request["public_key"], 32, "initiator public key")
        ie = _hex(request["ephemeral_key"], 32, "initiator ephemeral key")
        inc = _hex(request["nonce"], 32, "initiator nonce")
        if ik == identity.public_key:
            raise AuthenticationError("Cannot authenticate our own identity")
        peer = trust_store.require(ik)
        rk = identity.public_key
        re_private, re = _ephemeral_keypair()
        rnc = os.urandom(32)
        transcript = _transcript(ik, rk, ie, re, inc, rnc)
        shared = _exchange(re_private, ie)
        _json_send(
            connection, "challenge", public_key=rk.hex(),
            ephemeral_key=re.hex(), nonce=rnc.hex(),
            signature=_signature(identity, b"responder", transcript),
        )
        proof = _json_receive(connection, "proof", {"signature"})
        _check_signature(ik, proof["signature"], b"initiator", transcript)
        trust_store.require(ik)
        _json_send(connection, "accepted", signature=_signature(identity, b"accepted", transcript))
        outbound, inbound = _derive(shared, transcript)
        return SecureSocket(
            connection, inbound, outbound,
            initiator=False, remote_public_key=ik,
        ), peer
    except (OSError, AuthenticationError) as exc:
        if isinstance(exc, AuthenticationError):
            raise
        raise AuthenticationError(f"Secure handshake failed: {exc}") from exc
    finally:
        connection.settimeout(original_timeout)
