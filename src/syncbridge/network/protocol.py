
"""Versioned, length-prefixed control messages for SyncBridge.

Wire format: four-byte unsigned big-endian body length, followed by a
UTF-8 encoded JSON object. This module does not establish encrypted or
authenticated connections; that belongs to network.security and network.peer.
Binary file contents must use the separate transfer protocol.
"""

from __future__ import annotations

import json
import re
import socket
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from uuid import uuid4


PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 64 * 1024
_LENGTH_FORMAT = "!I"
_HEADER_SIZE = struct.calcsize(_LENGTH_FORMAT)
_ID_PATTERN = re.compile(r"[0-9a-f]{32}\Z")
_REQUIRED_FIELDS = frozenset({"version", "type", "id", "payload"})


class ProtocolError(Exception):
    """Invalid or unsupported SyncBridge control data."""


class UnsupportedVersionError(ProtocolError):
    """A message uses a protocol version we cannot interpret."""


class ConnectionClosedError(ProtocolError):
    """The peer disconnected before delivering an entire frame."""


class MessageType(str, Enum):
    """Message types available before the transfer layer is implemented."""

    HELLO = "hello"
    HELLO_ACK = "hello_ack"
    PING = "ping"
    PONG = "pong"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class Message:
    """One control message. Payload must contain JSON-compatible values."""

    kind: MessageType
    payload: dict[str, Any] = field(default_factory=dict)
    message_id: str = field(default_factory=lambda: uuid4().hex)
    version: int = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        _validate_message(self)


def _validate_message(message: Message) -> None:
    if not isinstance(message.kind, MessageType):
        raise ProtocolError("Message kind must be a recognized MessageType")

    if type(message.version) is not int or message.version != PROTOCOL_VERSION:
        raise UnsupportedVersionError(
            f"Unsupported protocol version: {message.version!r}; "
            f"expected {PROTOCOL_VERSION}"
        )

    if not isinstance(message.message_id, str) or not _ID_PATTERN.fullmatch(
        message.message_id
    ):
        raise ProtocolError("Message ID must be 32 lowercase hexadecimal characters")

    if not isinstance(message.payload, dict) or not all(
        isinstance(key, str) for key in message.payload
    ):
        raise ProtocolError("Message payload must be a JSON object with string keys")


def pack_message(message: Message) -> bytes:
    """Return a full wire frame, including its four-byte length prefix."""
    if not isinstance(message, Message):
        raise TypeError("message must be a Message")
    _validate_message(message)

    contents = {
        "version": message.version,
        "type": message.kind.value,
        "id": message.message_id,
        "payload": message.payload,
    }

    try:
        body = json.dumps(
            contents,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProtocolError("Message payload cannot be encoded as JSON") from exc

    if len(body) > MAX_MESSAGE_BYTES:
        raise ProtocolError(
            f"Control message exceeds {MAX_MESSAGE_BYTES} bytes"
        )

    return struct.pack(_LENGTH_FORMAT, len(body)) + body


def _reject_non_json_constant(value: str) -> None:
    raise ValueError(f"Non-standard JSON constant: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value

    return result


def unpack_message(frame: bytes) -> Message:
    """Parse one complete wire frame, rejecting trailing or invalid data."""
    if not isinstance(frame, bytes):
        raise TypeError("frame must be bytes")

    if len(frame) < _HEADER_SIZE:
        raise ProtocolError("Frame is missing its four-byte length prefix")

    (body_size,) = struct.unpack(_LENGTH_FORMAT, frame[:_HEADER_SIZE])

    if body_size == 0 or body_size > MAX_MESSAGE_BYTES:
        raise ProtocolError("Invalid control message length")

    if len(frame) - _HEADER_SIZE != body_size:
        raise ProtocolError("Frame length does not match the payload")

    try:
        document = json.loads(
            frame[_HEADER_SIZE:].decode("utf-8"),
            parse_constant=_reject_non_json_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
    ) as exc:
        raise ProtocolError("Frame does not contain valid UTF-8 JSON") from exc

    if not isinstance(document, dict) or set(document) != _REQUIRED_FIELDS:
        raise ProtocolError("Control message has invalid top-level fields")

    if type(document["version"]) is not int or document["version"] != PROTOCOL_VERSION:
        raise UnsupportedVersionError(
            f"Unsupported protocol version: {document['version']!r}; "
            f"expected {PROTOCOL_VERSION}"
        )

    try:
        kind = MessageType(document["type"])
    except (ValueError, TypeError) as exc:
        raise ProtocolError(f"Unknown message type: {document['type']!r}") from exc

    return Message(
        kind=kind,
        payload=document["payload"],
        message_id=document["id"],
        version=document["version"],
    )


def send_message(connection: socket.socket, message: Message) -> None:
    """Send an entire message over a connected socket.

    Caller must ensure simultaneous writers don't interleave their frames.
    A socket timeout is the responsibility of the connection manager.
    """
    connection.sendall(pack_message(message))


def _read_exact(connection: socket.socket, count: int) -> bytes:
    data = bytearray()

    while len(data) < count:
        chunk = connection.recv(count - len(data))

        if not chunk:
            raise ConnectionClosedError(
                f"Peer disconnected after {len(data)} of {count} expected bytes"
            )

        data.extend(chunk)

    return bytes(data)


def receive_message(connection: socket.socket) -> Message:
    """Read exactly one framed message, safely handling split TCP packets."""
    header = _read_exact(connection, _HEADER_SIZE)

    (body_size,) = struct.unpack(_LENGTH_FORMAT, header)

    if body_size == 0 or body_size > MAX_MESSAGE_BYTES:
        raise ProtocolError("Invalid control message length")

    return unpack_message(header + _read_exact(connection, body_size))
