
"""Unit and localhost integration tests for UDP peer discovery."""

from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import replace
from uuid import uuid4

import pytest

from syncbridge.network.discovery import (
    DISCOVERY_VERSION,
    MAX_ANNOUNCEMENT_BYTES,
    DiscoveryError,
    PeerAnnouncement,
    PeerDiscovery,
    decode_announcement,
    encode_announcement,
)


def node_id() -> str:
    return uuid4().hex


def advertisement(**changes) -> PeerAnnouncement:
    return replace(
        PeerAnnouncement(
            node_id(),
            "Àkín's laptop 💻",
            34567,
            45678,
        ),
        **changes,
    )


def make_receiver(**kwargs) -> PeerDiscovery:
    options = {
        "listen_port": 0,
        "bind_address": "127.0.0.1",
        "targets": (),
        "announce_interval": 0.05,
        "peer_timeout": 0.4,
    }

    options.update(kwargs)

    return PeerDiscovery(
        node_id(),
        "Receiver",
        34567,
        **options,
    )


def send_udp(destination: int, packet: bytes) -> None:
    with socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    ) as sender:
        sender.sendto(
            packet,
            ("127.0.0.1", destination),
        )


def wait_for(predicate, timeout=2.0) -> bool:
    end = time.monotonic() + timeout

    while time.monotonic() < end:
        if predicate():
            return True

        time.sleep(0.01)

    return predicate()


def test_round_trip_preserves_unicode():
    original = advertisement()
    assert decode_announcement(
        encode_announcement(original)
    ) == original


def test_announcement_schema_and_version():
    payload = json.loads(
        encode_announcement(advertisement())
    )

    assert payload["magic"] == "syncbridge-discovery"
    assert payload["version"] == DISCOVERY_VERSION
    assert set(payload) == {
        "magic",
        "version",
        "node_id",
        "name",
        "peer_port",
        "discovery_port",
    }


@pytest.mark.parametrize(
    "identifier",
    ["", "A" * 32, "x" * 32, 123, "f" * 31],
)
def test_rejects_bad_node_id(identifier):
    with pytest.raises(DiscoveryError, match="node_id"):
        encode_announcement(
            advertisement(node_id=identifier)
        )


@pytest.mark.parametrize(
    "name",
    ["", "  ", "Hi\nthere", "a" * 129, 23],
)
def test_rejects_invalid_names(name):
    with pytest.raises(DiscoveryError, match="name"):
        encode_announcement(
            advertisement(name=name)
        )


@pytest.mark.parametrize(
    "port",
    [0, 65536, True, "42000", -1],
)
def test_rejects_bad_tcp_or_udp_ports(port):
    for field in ("peer_port", "discovery_port"):
        with pytest.raises(DiscoveryError, match="Port"):
            encode_announcement(
                advertisement(**{field: port})
            )


@pytest.mark.parametrize(
    "packet",
    [
        b"",
        b"invalid",
        b"\xff",
        b"[]",
        b"{}",
        b"x" * (MAX_ANNOUNCEMENT_BYTES + 1),
    ],
)
def test_rejects_malformed_and_oversized_packets(packet):
    with pytest.raises(DiscoveryError):
        decode_announcement(packet)


def test_rejects_duplicate_json_keys():
    packet = encode_announcement(
        advertisement()
    ).decode()

    tampered = packet.replace(
        '"version":1',
        '"version":1,"version":1',
    )

    with pytest.raises(DiscoveryError, match="JSON"):
        decode_announcement(tampered.encode())


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", 2),
        ("version", True),
        ("magic", "different"),
        ("name", None),
        ("peer_port", 1.5),
        ("discovery_port", 0),
    ],
)
def test_rejects_bad_document_fields(field, value):
    payload = json.loads(
        encode_announcement(advertisement())
    )

    payload[field] = value

    with pytest.raises(DiscoveryError):
        decode_announcement(
            json.dumps(payload).encode()
        )


def test_rejects_invalid_unicode_name_without_stopping_worker():
    payload = json.loads(
        encode_announcement(advertisement())
    )

    payload["name"] = "\ud800"

    with pytest.raises(DiscoveryError, match="Unicode"):
        decode_announcement(
            json.dumps(payload).encode()
        )


def test_rejects_unknown_fields():
    payload = json.loads(
        encode_announcement(advertisement())
    )

    payload["ip"] = "10.0.0.2"

    with pytest.raises(DiscoveryError, match="fields"):
        decode_announcement(
            json.dumps(payload).encode()
        )


def test_validates_configuration():
    with pytest.raises(ValueError, match="peer_timeout"):
        make_receiver(
            announce_interval=2,
            peer_timeout=1,
        )


def test_rejects_invalid_target_and_callback():
    receiver = make_receiver()

    with pytest.raises(ValueError, match="numeric IPv4"):
        receiver.add_target(
            "not-a-host",
            9999,
        )

    with pytest.raises(ValueError, match="multicast"):
        receiver.add_target(
            "239.0.0.1",
            9999,
        )

    with pytest.raises(TypeError, match="callbacks"):
        make_receiver(on_lost="not callable")


def test_start_stop_restart_and_ephemeral_port():
    receiver = make_receiver()

    assert receiver.bound_port is None

    receiver.start()

    try:
        assert receiver.is_running

        first_port = receiver.bound_port

        assert isinstance(first_port, int)
        assert first_port > 0

        receiver.start()

        assert receiver.bound_port == first_port

    finally:
        receiver.stop()

    assert not receiver.is_running
    assert receiver.bound_port is None

    receiver.stop()
    receiver.start()

    try:
        assert receiver.is_running
    finally:
        receiver.stop()


def test_announce_requires_start():
    with pytest.raises(RuntimeError, match="not running"):
        make_receiver().announce()


def test_receives_external_announcement_and_tracks_source_address():
    found = []

    receiver = make_receiver(
        on_discovered=found.append,
    )

    sender_announcement = advertisement()

    receiver.start()

    try:
        send_udp(
            receiver.bound_port,
            encode_announcement(sender_announcement),
        )

        assert wait_for(lambda: len(found) == 1)

        peer = receiver.peers[0]

        assert peer.node_id == sender_announcement.node_id
        assert peer.address == "127.0.0.1"
        assert peer.port == sender_announcement.peer_port
        assert peer.name == sender_announcement.name
        assert (
            peer.discovery_port
            == sender_announcement.discovery_port
        )

    finally:
        receiver.stop()


def test_ignores_own_beacon_and_network_noise():
    found = []

    receiver = make_receiver(
        on_discovered=found.append,
    )

    receiver.start()

    try:
        own_beacon = PeerAnnouncement(
            receiver.node_id,
            receiver.name,
            receiver.peer_port,
            receiver.bound_port,
        )

        send_udp(
            receiver.bound_port,
            encode_announcement(own_beacon),
        )

        send_udp(
            receiver.bound_port,
            b"not a discovery packet",
        )

        time.sleep(0.1)

        assert receiver.peers == ()
        assert found == []
        assert receiver.is_running

    finally:
        receiver.stop()


def test_refresh_does_not_repeat_callback_and_metadata_updates_do():
    seen = []

    receiver = make_receiver(
        on_discovered=seen.append,
    )

    peer = advertisement()

    receiver.start()

    try:
        send_udp(
            receiver.bound_port,
            encode_announcement(peer),
        )

        assert wait_for(lambda: len(seen) == 1)

        send_udp(
            receiver.bound_port,
            encode_announcement(peer),
        )

        time.sleep(0.08)

        assert len(seen) == 1

        send_udp(
            receiver.bound_port,
            encode_announcement(
                replace(peer, name="Renamed")
            ),
        )

        assert wait_for(lambda: len(seen) == 2)
        assert receiver.peers[0].name == "Renamed"

    finally:
        receiver.stop()


def test_peer_expires_after_beacons_stop():
    lost = []

    receiver = make_receiver(
        on_lost=lost.append,
    )

    peer = advertisement()

    receiver.start()

    try:
        send_udp(
            receiver.bound_port,
            encode_announcement(peer),
        )

        assert wait_for(
            lambda: len(receiver.peers) == 1
        )

        assert wait_for(
            lambda: len(lost) == 1
        )

        assert lost[0].node_id == peer.node_id
        assert receiver.peers == ()

    finally:
        receiver.stop()


def test_two_live_peers_find_each_other_via_unicast():
    a_seen = threading.Event()
    b_seen = threading.Event()

    a = make_receiver(
        on_discovered=lambda peer: a_seen.set()
    )

    b = make_receiver(
        on_discovered=lambda peer: b_seen.set()
    )

    a.start()
    b.start()

    try:
        a.add_target(
            "127.0.0.1",
            b.bound_port,
        )

        b.add_target(
            "127.0.0.1",
            a.bound_port,
        )

        a.announce()
        b.announce()

        assert a_seen.wait(2)
        assert b_seen.wait(2)

        assert a.peers[0].node_id == b.node_id
        assert b.peers[0].node_id == a.node_id

        a.remove_target(
            "127.0.0.1",
            b.bound_port,
        )

        b.remove_target(
            "127.0.0.1",
            a.bound_port,
        )

    finally:
        a.stop()
        b.stop()


def test_callback_can_stop_its_own_service():
    stopped = threading.Event()
    holder = {}

    def stop_when_found(peer):
        holder["service"].stop()
        stopped.set()

    receiver = make_receiver(
        on_discovered=stop_when_found,
    )

    holder["service"] = receiver

    receiver.start()

    send_udp(
        receiver.bound_port,
        encode_announcement(advertisement()),
    )

    assert stopped.wait(2)
    assert not receiver.is_running

    receiver.stop()


def test_callback_exception_reported_and_worker_survives():
    errors = []

    receiver = make_receiver(
        on_discovered=lambda peer: 1 / 0,
        on_error=errors.append,
    )

    receiver.start()

    try:
        send_udp(
            receiver.bound_port,
            encode_announcement(advertisement()),
        )

        assert wait_for(
            lambda: len(errors) == 1
        )

        assert isinstance(
            errors[0],
            ZeroDivisionError,
        )

        assert receiver.is_running

    finally:
        receiver.stop()


def test_remove_target_is_idempotent():
    receiver = make_receiver()

    receiver.add_target(
        "127.0.0.1",
        45841,
    )

    receiver.remove_target(
        "127.0.0.1",
        45841,
    )

    receiver.remove_target(
        "127.0.0.1",
        45841,
    )


def test_decode_requires_bytes():
    with pytest.raises(TypeError):
        decode_announcement("not bytes")

    with pytest.raises(TypeError):
        encode_announcement({})


def test_timeout_rejects_infinite_or_nan():
    for invalid in (
        float("inf"),
        float("nan"),
        -1,
        0,
    ):
        with pytest.raises(ValueError):
            make_receiver(
                announce_interval=invalid
            )


def test_udp_connection_reset_is_recoverable(monkeypatch):
    """A Windows-style ICMP port-unreachable must not stop the listener."""
    from syncbridge.network import discovery

    real_socket = socket.socket
    reset_injected = threading.Event()

    class ResetOnceSocket:
        def __init__(self, *args, **kwargs):
            self._socket = real_socket(
                *args,
                **kwargs,
            )
            self._first_receive = True

        def __getattr__(self, name):
            return getattr(
                self._socket,
                name,
            )

        def recvfrom(self, size):
            if self._first_receive:
                self._first_receive = False
                reset_injected.set()

                raise OSError(
                    10054,
                    "Simulated Windows UDP ICMP error",
                )

            return self._socket.recvfrom(size)

    monkeypatch.setattr(
        discovery.socket,
        "socket",
        ResetOnceSocket,
    )

    errors = []

    receiver = make_receiver(
        on_error=errors.append,
    )

    receiver.start()

    try:
        assert reset_injected.wait(2)

        with real_socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        ) as sender:
            sender.sendto(
                encode_announcement(
                    advertisement(
                        discovery_port=receiver.bound_port
                    )
                ),
                ("127.0.0.1", receiver.bound_port),
            )

        assert wait_for(
            lambda: len(receiver.peers) == 1
        )

        assert receiver.is_running
        assert errors == []

    finally:
        receiver.stop()
