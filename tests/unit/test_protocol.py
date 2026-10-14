
"""Unit tests for SyncBridge version-one control message framing."""

from __future__ import annotations

import json
import socket
import struct
from contextlib import contextmanager

import pytest

from syncbridge.network.protocol import (
    MAX_MESSAGE_BYTES,
    PROTOCOL_VERSION,
    ConnectionClosedError,
    Message,
    MessageType,
    ProtocolError,
    UnsupportedVersionError,
    pack_message,
    receive_message,
    send_message,
    unpack_message,
)


FIXED_ID = "0123456789abcdef0123456789abcdef"


@contextmanager
def paired_sockets():
    sender, receiver = socket.socketpair()

    try:
        sender.settimeout(2)
        receiver.settimeout(2)
        yield sender, receiver
    finally:
        sender.close()
        receiver.close()


def raw_frame(document: object) -> bytes:
    body = json.dumps(
        document,
        separators=(",", ":"),
    ).encode("utf-8")

    return struct.pack("!I", len(body)) + body


def valid_document(**overrides):
    document = {
        "version": PROTOCOL_VERSION,
        "type": "ping",
        "id": FIXED_ID,
        "payload": {},
    }

    document.update(overrides)
    return document


def test_round_trip_preserves_unicode_and_nested_payload():
    source = Message(
        MessageType.HELLO,
        payload={
            "device": "Àkín's laptop 💻",
            "capabilities": ["ping", {"v": 1}],
        },
        message_id=FIXED_ID,
    )

    decoded = unpack_message(pack_message(source))

    assert decoded == source


def test_frame_uses_big_endian_length_and_json():
    frame = pack_message(
        Message(
            MessageType.PING,
            message_id=FIXED_ID,
        )
    )

    assert struct.unpack("!I", frame[:4])[0] == len(frame) - 4
    assert json.loads(frame[4:].decode("utf-8")) == valid_document()


def test_each_message_gets_a_unique_id():
    first = Message(MessageType.PING)
    second = Message(MessageType.PING)

    assert first.message_id != second.message_id
    assert len(first.message_id) == 32


@pytest.mark.parametrize(
    "invalid_payload",
    [[], "hello", {1: "bad"}],
)
def test_rejects_non_object_or_non_string_key_payload(invalid_payload):
    with pytest.raises(ProtocolError, match="payload"):
        Message(
            MessageType.PING,
            payload=invalid_payload,
        )


def test_rejects_payload_that_cannot_be_serialized():
    message = Message(
        MessageType.PING,
        payload={"not_json": {1, 2}},
    )

    with pytest.raises(ProtocolError, match="JSON"):
        pack_message(message)


def test_rejects_nan_and_infinite_numbers():
    for invalid in (
        float("nan"),
        float("inf"),
        float("-inf"),
    ):
        with pytest.raises(ProtocolError, match="JSON"):
            pack_message(
                Message(
                    MessageType.PING,
                    {"invalid": invalid},
                )
            )


def test_rejects_invalid_message_id_and_type():
    with pytest.raises(ProtocolError, match="ID"):
        Message(
            MessageType.PING,
            message_id="not-an-id",
        )

    with pytest.raises(ProtocolError, match="kind"):
        Message("ping")


def test_rejects_oversized_outgoing_message():
    with pytest.raises(ProtocolError, match="exceeds"):
        pack_message(
            Message(
                MessageType.PING,
                {"data": "X" * MAX_MESSAGE_BYTES},
            )
        )


@pytest.mark.parametrize(
    "bad_frame",
    [
        b"",
        b"\x00\x00\x00",
        b"\x00\x00\x00\x00",
        struct.pack("!I", MAX_MESSAGE_BYTES + 1),
        b"\x00\x00\x00\x05{}",
        b"\x00\x00\x00\x02{}EXTRA",
    ],
)
def test_rejects_invalid_frame_sizes(bad_frame):
    with pytest.raises(ProtocolError):
        unpack_message(bad_frame)


@pytest.mark.parametrize(
    "bad_document",
    [
        [],
        {"version": 1},
        valid_document(type="unknown"),
        valid_document(payload=[]),
        valid_document(id="A" * 32),
        valid_document(extra="unexpected"),
    ],
)
def test_rejects_invalid_json_message_shapes(bad_document):
    with pytest.raises(ProtocolError):
        unpack_message(raw_frame(bad_document))


@pytest.mark.parametrize(
    "version",
    [0, 2, True, "1"],
)
def test_rejects_unsupported_version(version):
    with pytest.raises(UnsupportedVersionError):
        unpack_message(
            raw_frame(valid_document(version=version))
        )


def test_rejects_malformed_utf8_and_json():
    for body in (b"\xff", b"{broken"):
        with pytest.raises(ProtocolError):
            unpack_message(
                struct.pack("!I", len(body)) + body
            )


def test_rejects_nonstandard_nan_json():
    body = (
        b'{"version":1,"type":"ping","id":"'
        + FIXED_ID.encode()
        + b'","payload":{"x":NaN}}'
    )

    with pytest.raises(ProtocolError):
        unpack_message(
            struct.pack("!I", len(body)) + body
        )


def test_rejects_duplicate_json_keys():
    body = (
        b'{"version":1,"type":"ping","type":"pong","id":"'
        + FIXED_ID.encode()
        + b'","payload":{}}'
    )

    with pytest.raises(ProtocolError, match="JSON"):
        unpack_message(
            struct.pack("!I", len(body)) + body
        )


def test_actual_socket_round_trip():
    with paired_sockets() as (sender, receiver):
        sender.settimeout(2)
        receiver.settimeout(2)

        message = Message(
            MessageType.HELLO,
            {"name": "Laptop A"},
        )

        send_message(sender, message)

        assert receive_message(receiver) == message


def test_multiple_frames_on_one_connection():
    with paired_sockets() as (sender, receiver):
        sender.settimeout(2)
        receiver.settimeout(2)

        first = Message(MessageType.PING)
        second = Message(MessageType.PONG)

        sender.sendall(
            pack_message(first) + pack_message(second)
        )

        assert receive_message(receiver) == first
        assert receive_message(receiver) == second


def test_split_frame_is_reassembled():
    with paired_sockets() as (sender, receiver):
        sender.settimeout(2)
        receiver.settimeout(2)

        message = Message(MessageType.HELLO_ACK)
        frame = pack_message(message)

        for segment in (
            frame[:1],
            frame[1:3],
            frame[3:9],
            frame[9:],
        ):
            sender.sendall(segment)

        assert receive_message(receiver) == message


def test_truncated_header_raises_disconnect():
    with paired_sockets() as (sender, receiver):
        sender.sendall(b"\x00\x00")
        sender.shutdown(socket.SHUT_WR)

        with pytest.raises(ConnectionClosedError):
            receive_message(receiver)


def test_truncated_body_raises_disconnect():
    with paired_sockets() as (sender, receiver):
        sender.sendall(
            struct.pack("!I", 50) + b"{}"
        )
        sender.shutdown(socket.SHUT_WR)

        with pytest.raises(ConnectionClosedError):
            receive_message(receiver)


def test_oversized_header_rejected_without_waiting_for_body():
    with paired_sockets() as (sender, receiver):
        sender.settimeout(2)
        receiver.settimeout(2)

        sender.sendall(
            struct.pack("!I", MAX_MESSAGE_BYTES + 1)
        )

        with pytest.raises(ProtocolError, match="length"):
            receive_message(receiver)
