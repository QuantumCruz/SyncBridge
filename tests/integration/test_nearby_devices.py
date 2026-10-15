
"""Real UDP discovery from the headless desktop directory, no pairing required."""
from __future__ import annotations

import socket
import time
from uuid import uuid4

import pytest

from syncbridge.ui.nearby_devices import NearbyDirectory


def wait_until(predicate, seconds=3.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


def directory(name: str, *, peer_timeout=0.5) -> NearbyDirectory:
    return NearbyDirectory(
        uuid4().hex, name, listen_port=0,
        bind_address="127.0.0.1", targets=(),
        announce_interval=0.05, peer_timeout=peer_timeout,
    )


def test_two_independent_instances_discover_each_other():
    alice, bob = directory("Alice"), directory("Bob")
    alice.start()
    bob.start()
    try:
        alice.add_target("127.0.0.1", bob.bound_port)
        bob.add_target("127.0.0.1", alice.bound_port)
        alice.refresh()
        bob.refresh()
        assert wait_until(lambda: len(alice.devices()) == len(bob.devices()) == 1)
        assert alice.devices()[0].name == "Bob"
        assert bob.devices()[0].name == "Alice"
        assert alice.devices()[0].address == "127.0.0.1"
        assert bob.devices()[0].address == "127.0.0.1"
        assert alice.devices()[0].node_id == bob.discovery.node_id
        assert bob.devices()[0].node_id == alice.discovery.node_id
    finally:
        bob.stop()
        alice.stop()


def test_peer_disappears_after_timeout():
    alice, bob = directory("Alice", peer_timeout=0.3), directory("Bob", peer_timeout=0.3)
    alice.start()
    bob.start()
    try:
        alice.add_target("127.0.0.1", bob.bound_port)
        bob.add_target("127.0.0.1", alice.bound_port)
        alice.refresh()
        assert wait_until(lambda: len(alice.devices()) == 1)
        bob.stop()
        assert wait_until(lambda: alice.devices() == (), seconds=2.0)
    finally:
        bob.stop()
        alice.stop()


def test_stop_releases_udp_port():
    item = directory("Alice")
    item.start()
    port = item.bound_port
    item.stop()
    assert not item.running
    assert item.bound_port is None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as another:
        another.bind(("127.0.0.1", port))


def test_restarting_does_not_retain_stale_devices():
    item = directory("Alice")
    other = directory("Bob")
    item.start()
    other.start()
    try:
        other.add_target("127.0.0.1", item.bound_port)
        other.refresh()
        assert wait_until(lambda: len(item.devices()) == 1)
        item.stop()
        item.start()
        assert item.devices() == ()
    finally:
        item.stop()
        other.stop()


def test_invalid_target_is_rejected_without_stopping_discovery():
    item = directory("Alice")
    item.start()
    try:
        with pytest.raises(ValueError):
            item.add_target("this-is-not-an-ip", 45841)
        assert item.running
    finally:
        item.stop()


def test_reading_device_list_does_not_pair_or_write_files(tmp_path):
    item = directory("Alice")
    item.start()
    try:
        assert item.devices() == ()
        assert item.errors() == ()
        assert list(tmp_path.iterdir()) == []
    finally:
        item.stop()
