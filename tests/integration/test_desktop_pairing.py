
"""Real TCP/UDP tests for pairing wired to desktop discovery (no Tk needed)."""
from __future__ import annotations

import time

import pytest

from syncbridge.network.pairing import PairingError
from syncbridge.ui.nearby_devices import DesktopPresence
from syncbridge.ui.pairing_desktop import PairingController


def wait_for(predicate, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.01)
    return predicate()


@pytest.fixture
def pair(tmp_path):
    alice = PairingController(
        tmp_path / "Alice", "Alice", bind_address="127.0.0.1",
        port=0, approval_timeout=5.0,
    )
    bob = PairingController(
        tmp_path / "Bob", "Bob", bind_address="127.0.0.1",
        port=0, approval_timeout=5.0,
    )
    alice.start()
    bob.start()
    da = DesktopPresence(
        tmp_path / "Alice", device_name="Alice", listen_port=0,
        bind_address="127.0.0.1", targets=(), announce_interval=0.05,
        peer_timeout=0.5, pairing_port=alice.port,
    )
    db = DesktopPresence(
        tmp_path / "Bob", device_name="Bob", listen_port=0,
        bind_address="127.0.0.1", targets=(), announce_interval=0.05,
        peer_timeout=0.5, pairing_port=bob.port,
    )
    da.start()
    db.start()
    da.directory.add_target("127.0.0.1", db.directory.bound_port)
    db.directory.add_target("127.0.0.1", da.directory.bound_port)
    da.directory.refresh()
    db.directory.refresh()
    assert wait_for(lambda: bool(da.directory.devices()) and bool(db.directory.devices()))
    try:
        yield alice, bob, da, db, tmp_path
    finally:
        db.stop()
        da.stop()
        bob.stop()
        alice.stop()


def test_discovery_advertises_actual_pairing_port(pair):
    alice, bob, da, db, _ = pair
    seen = da.directory.devices()[0]
    assert seen.node_id == bob.identity.node_id
    assert seen.pairing_port == bob.port
    assert db.directory.devices()[0].pairing_port == alice.port


def test_request_from_discovery_requires_two_explicit_approvals(pair):
    alice, bob, da, _, _ = pair
    session = alice.request(da.directory.devices()[0])
    try:
        assert wait_for(lambda: bool(bob.pending()))
        incoming = bob.pending()[0]
        assert incoming.code == session.details.code
        assert not alice.trusted(bob.identity.node_id)
        assert not bob.trusted(alice.identity.node_id)
        bob.approve_incoming(incoming, session.details.code)
        assert not alice.trusted(bob.identity.node_id)
        session.approve(incoming.code)
        assert alice.trusted(bob.identity.node_id)
        assert wait_for(lambda: bob.trusted(alice.identity.node_id))
    finally:
        session.close()


def test_wrong_verification_code_creates_no_trust(pair):
    alice, bob, da, _, _ = pair
    session = alice.request(da.directory.devices()[0])
    try:
        assert wait_for(lambda: bool(bob.pending()))
        with pytest.raises(PairingError):
            bob.approve_incoming(bob.pending()[0], "0000-0000-0000-0000")
        assert not alice.trusted(bob.identity.node_id)
        assert not bob.trusted(alice.identity.node_id)
    finally:
        session.reject()


def test_incoming_rejection_refuses_request(pair):
    alice, bob, da, _, _ = pair
    session = alice.request(da.directory.devices()[0])
    try:
        assert wait_for(lambda: bool(bob.pending()))
        incoming = bob.pending()[0]
        bob.reject_incoming(incoming.request_id)
        with pytest.raises((PairingError, OSError)):
            session.approve(incoming.code)
        assert not alice.trusted(bob.identity.node_id)
        assert not bob.trusted(alice.identity.node_id)
    finally:
        session.close()


def test_pairing_is_persisted_but_no_share_configuration(pair):
    alice, bob, da, _, tmp_path = pair
    session = alice.request(da.directory.devices()[0])
    try:
        assert wait_for(lambda: bool(bob.pending()))
        incoming = bob.pending()[0]
        bob.approve_incoming(incoming, session.details.code)
        session.approve(incoming.code)
        assert alice.trusted(bob.identity.node_id)
        assert wait_for(lambda: bob.trusted(alice.identity.node_id))
        assert list(tmp_path.rglob("settings.json")) == []
        assert list(tmp_path.rglob("shared_state.sqlite")) == []
    finally:
        session.close()


def test_cannot_request_pairing_with_own_advertised_node_id(pair):
    alice, _, da, _, _ = pair
    other = da.directory.devices()[0]
    from dataclasses import replace
    fake = replace(other, node_id=alice.identity.node_id)
    with pytest.raises(PairingError):
        alice.request(fake)


def test_pairing_listener_stops_and_releases_port(pair):
    import socket
    alice, _, _, _, _ = pair
    port = alice.port
    alice.stop()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", port))
