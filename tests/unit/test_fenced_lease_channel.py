
"""Real authenticated-loopback tests for receiver-issued fencing grants."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from syncbridge.network.fenced_lease_channel import (
    FencedLeaseClient,
    FencedLeaseService,
    LeaseChannelError,
)
from syncbridge.network.lease_fencing import FencedOut, LeaseAuthority
from syncbridge.network.security import DeviceIdentity, TrustStore
from syncbridge.storage.config import AppConfig, ConfigStore, ShareConfig

SHARE = "a" * 32


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def _trust(path, own, other):
    store = TrustStore(path)
    store.add_verified(
        other.public_key_hex,
        confirmed_fingerprint=other.fingerprint,
        name="Test peer",
    )
    return store


@pytest.fixture
def peers(tmp_path):
    alice = DeviceIdentity.generate()
    bob = DeviceIdentity.generate()
    alice_trust = _trust(tmp_path / "alice-trust.json", alice, bob)
    bob_trust = _trust(tmp_path / "bob-trust.json", bob, alice)
    bob_share = tmp_path / "BobShare"
    bob_share.mkdir()
    store = ConfigStore(tmp_path / "BobProfile" / "settings.json")
    store.save(AppConfig(
        device_name="Bob",
        shares=(ShareConfig(
            share_id=SHARE,
            peer_node_id=alice.node_id,
            local_root=str(bob_share),
            display_name="Shared",
            remote_host="127.0.0.1",
            enabled=True,
            grant_write=True,
            grant_read=True,
            grant_manifest=True,
            grant_agreement=True,
        ),),
    ))
    clock = Clock()
    authority = LeaseAuthority(tmp_path / "BobProfile" / "lease_fences.db", clock=clock)
    server = FencedLeaseService(
        bob, bob_trust, store, authority,
        bind_address="127.0.0.1", port=0,
    )
    client = FencedLeaseClient(alice, alice_trust)
    server.start()
    try:
        yield {
            "server": server, "client": client, "clock": clock,
            "authority": authority, "alice": alice, "bob": bob,
            "bob_trust": bob_trust, "store": store, "tmp": tmp_path,
        }
    finally:
        server.stop()


def _rpc(peers):
    return "127.0.0.1", peers["server"].bound_port, peers["bob"].node_id


def test_secure_acquire_renew_release(peers):
    client = peers["client"]
    args = _rpc(peers)
    grant = client.acquire(*args, SHARE, ttl_seconds=10)
    assert grant.generation == 1
    assert grant.owner_node_id == peers["alice"].node_id
    assert grant.session_token not in repr(grant)
    assert peers["authority"].assert_current(grant).generation == 1
    peers["clock"].advance(3)
    renewed = client.renew(*args, grant, ttl_seconds=10)
    assert renewed.generation == 1
    assert renewed.expires_at == 1013
    client.release(*args, renewed)
    with pytest.raises(FencedOut):
        peers["authority"].assert_current(grant)
    another = client.acquire(*args, SHARE)
    assert another.generation == 2


def test_busy_lease_is_rejected_on_wire(peers):
    args = _rpc(peers)
    first = peers["client"].acquire(*args, SHARE)
    with pytest.raises(LeaseChannelError, match="rejected"):
        peers["client"].acquire(*args, SHARE)
    assert peers["authority"].assert_current(first).generation == 1


def test_expiration_and_old_grant_cannot_be_reused(peers):
    args = _rpc(peers)
    first = peers["client"].acquire(*args, SHARE, ttl_seconds=5)
    peers["clock"].advance(6)
    with pytest.raises(LeaseChannelError, match="rejected"):
        peers["client"].renew(*args, first)
    second = peers["client"].acquire(*args, SHARE)
    assert second.generation == 2
    with pytest.raises(LeaseChannelError, match="rejected"):
        peers["client"].release(*args, first)
    assert peers["authority"].assert_current(second).generation == 2


def test_forged_token_cannot_release_current_holder(peers):
    args = _rpc(peers)
    original = peers["client"].acquire(*args, SHARE)
    forged = replace(original, session_token="f" * 64)
    with pytest.raises(LeaseChannelError, match="rejected"):
        peers["client"].release(*args, forged)
    assert peers["authority"].assert_current(original).generation == 1


def test_wrong_share_and_unapproved_peer_are_refused(peers):
    args = _rpc(peers)
    with pytest.raises(LeaseChannelError, match="rejected"):
        peers["client"].acquire(*args, "f" * 32)

    eve = DeviceIdentity.generate()
    eve_trust = _trust(peers["tmp"] / "eve-trust.json", eve, peers["bob"])
    peers["bob_trust"].add_verified(
        eve.public_key_hex, confirmed_fingerprint=eve.fingerprint,
        name="Eve",
    )
    # Eve passes device authentication but has no approved folder grant.
    with pytest.raises(LeaseChannelError, match="rejected"):
        FencedLeaseClient(eve, eve_trust).acquire(*args, SHARE)


def test_disabled_share_refuses_acquire(peers):
    config = peers["store"].load()
    disabled = replace(
        config.shares[0], enabled=False,
        grant_write=False, grant_read=False,
        grant_manifest=False, grant_agreement=False,
    )
    peers["store"].save(replace(config, shares=(disabled,)))
    with pytest.raises(LeaseChannelError, match="rejected"):
        peers["client"].acquire(*_rpc(peers), SHARE)


def test_concurrent_authenticated_acquires_get_one_grant(peers):
    args = _rpc(peers)

    def request(_):
        try:
            return peers["client"].acquire(*args, SHARE)
        except LeaseChannelError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(request, range(2)))
    assert sum(lease is not None for lease in results) == 1


def test_receiver_reboot_preserves_fencing_generation(peers):
    args = _rpc(peers)
    original = peers["client"].acquire(*args, SHARE, ttl_seconds=5)
    peers["server"].stop()
    peers["clock"].advance(6)
    server = FencedLeaseService(
        peers["bob"], peers["bob_trust"], peers["store"],
        LeaseAuthority(peers["authority"].path, clock=peers["clock"]),
        bind_address="127.0.0.1", port=0,
    )
    server.start()
    try:
        replacement = peers["client"].acquire(
            "127.0.0.1", server.bound_port, peers["bob"].node_id, SHARE,
        )
        assert replacement.generation == original.generation + 1
        with pytest.raises(LeaseChannelError, match="rejected"):
            peers["client"].renew(
                "127.0.0.1", server.bound_port, peers["bob"].node_id, original,
            )
    finally:
        server.stop()
