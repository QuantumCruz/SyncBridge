
"""Authenticated online/offline checks between two previously paired devices."""
from __future__ import annotations

import threading

import pytest

from syncbridge.network.peer_presence import (
    PeerPresenceClient,
    PeerPresenceService,
    PresenceError,
    presence_port_for_transfer,
)
from syncbridge.network.security import DeviceIdentity, TrustStore


SHARE = "a" * 32


def _trust(path, peer):
    trust = TrustStore(path)
    trust.add_verified(
        peer.public_key_hex,
        confirmed_fingerprint=peer.fingerprint,
        name="Test peer",
    )
    return trust


@pytest.fixture
def peers(tmp_path):
    alice = DeviceIdentity.generate()
    bob = DeviceIdentity.generate()

    alice_trust = _trust(
        tmp_path / "a.json",
        bob,
    )
    bob_trust = _trust(
        tmp_path / "b.json",
        alice,
    )

    left = threading.Event()

    service = PeerPresenceService(
        bob,
        bob_trust,
        SHARE,
        alice.node_id,
        bind_address="127.0.0.1",
        port=0,
        on_goodbye=left.set,
    )
    service.start()

    try:
        yield {
            "alice": alice,
            "bob": bob,
            "service": service,
            "client": PeerPresenceClient(
                alice,
                alice_trust,
                timeout=2,
            ),
            "left": left,
        }
    finally:
        service.stop()


def test_authenticated_probe_has_fresh_session_identity(peers):
    p = peers

    current = p["client"].probe(
        "127.0.0.1",
        p["service"].bound_port,
        p["bob"].node_id,
        SHARE,
    )

    assert current == p["service"].epoch
    assert len(current) == 32

    assert current == p["client"].probe(
        "127.0.0.1",
        p["service"].bound_port,
        p["bob"].node_id,
        SHARE,
    )


def test_goodbye_notifies_only_current_session(peers):
    p = peers
    port = p["service"].bound_port

    epoch = p["client"].probe(
        "127.0.0.1",
        port,
        p["bob"].node_id,
        SHARE,
    )

    with pytest.raises(PresenceError):
        p["client"].goodbye(
            "127.0.0.1",
            port,
            p["bob"].node_id,
            SHARE,
            "0" * 32,
        )

    assert not p["left"].is_set()

    p["client"].goodbye(
        "127.0.0.1",
        port,
        p["bob"].node_id,
        SHARE,
        epoch,
    )

    assert p["left"].wait(2)


def test_restart_does_not_reuse_old_session(peers):
    p = peers
    service = p["service"]

    old = p["client"].probe(
        "127.0.0.1",
        service.bound_port,
        p["bob"].node_id,
        SHARE,
    )

    service.stop()

    with pytest.raises(PresenceError):
        p["client"].probe(
            "127.0.0.1",
            1,
            p["bob"].node_id,
            SHARE,
        )

    service.start()

    new = p["client"].probe(
        "127.0.0.1",
        service.bound_port,
        p["bob"].node_id,
        SHARE,
    )

    assert old != new

    with pytest.raises(PresenceError):
        p["client"].goodbye(
            "127.0.0.1",
            service.bound_port,
            p["bob"].node_id,
            SHARE,
            old,
        )

    assert not p["left"].is_set()


def test_wrong_share_cannot_claim_liveness(peers):
    p = peers

    with pytest.raises(PresenceError):
        p["client"].probe(
            "127.0.0.1",
            p["service"].bound_port,
            p["bob"].node_id,
            "b" * 32,
        )


def test_unpaired_identity_cannot_probe(peers, tmp_path):
    p = peers

    stranger = DeviceIdentity.generate()

    empty_trust = TrustStore(
        tmp_path / "stranger.json"
    )

    client = PeerPresenceClient(
        stranger,
        empty_trust,
    )

    with pytest.raises(PresenceError):
        client.probe(
            "127.0.0.1",
            p["service"].bound_port,
            p["bob"].node_id,
            SHARE,
        )


def test_port_derivation_matches_both_directions():
    assert presence_port_for_transfer(45842) == 45850

    one = presence_port_for_transfer(55142)
    two = presence_port_for_transfer(55242)

    assert one != two
    assert 1025 <= one <= 65535
    assert 1025 <= two <= 65535

    with pytest.raises(ValueError):
        presence_port_for_transfer(0)

    with pytest.raises(ValueError):
        presence_port_for_transfer(True)
