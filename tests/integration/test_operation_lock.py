
"""Phase 20: two-device lease coordination over authenticated TCP.

These tests use real SyncBridge Ed25519 identities and encrypted channels.
"""
from __future__ import annotations

import threading
import time
from uuid import uuid4

import pytest

from syncbridge.network.operation_lock import (
    LeaseCoordinator,
    OperationBusy,
    OperationLeaseLost,
    OperationLockClient,
    OperationLockError,
    OperationLockService,
)
from syncbridge.network.security import DeviceIdentity, TrustStore


@pytest.fixture
def world(tmp_path):
    a, b = DeviceIdentity.generate(), DeviceIdentity.generate()
    leader, follower = sorted((a, b), key=lambda ident: ident.node_id)
    lt = TrustStore(tmp_path / "leader.json")
    ft = TrustStore(tmp_path / "follower.json")
    lt.add_verified(follower.public_key_hex, confirmed_fingerprint=follower.fingerprint, name="Follower")
    ft.add_verified(leader.public_key_hex, confirmed_fingerprint=leader.fingerprint, name="Leader")
    share = uuid4().hex
    service = OperationLockService(
        leader, lt, {share: follower.node_id},
        listen_port=0, lease_seconds=2.4, timeout=2.0,
    )
    service.start()
    client = OperationLockClient(follower, ft, timeout=2.0)
    coordinator_leader = LeaseCoordinator(
        leader, follower.node_id, share, local_service=service,
    )
    coordinator_follower = LeaseCoordinator(
        follower, leader.node_id, share, client=client, port=service.bound_port,
    )
    try:
        yield service, client, coordinator_leader, coordinator_follower, share, leader, follower, lt, ft
    finally:
        service.stop()


def test_remote_acquires_and_releases_authenticated_lease(world):
    service, client, _, _, share, leader, follower, *_ = world
    grant = client.acquire("127.0.0.1", service.bound_port, leader.node_id, share, "sync")
    assert len(grant.token) == 32
    assert service.status_local(share).owner == follower.node_id
    assert client.release("127.0.0.1", service.bound_port, leader.node_id, share, grant.token)
    assert service.status_local(share).owner is None


def test_remote_cannot_take_local_lease(world):
    service, client, _, _, share, leader, follower, *_ = world
    local = service.acquire_local(share, "sync")
    with pytest.raises(OperationBusy, match="SB-OPS-423") as exc:
        client.acquire("127.0.0.1", service.bound_port, leader.node_id, share, "deletion")
    assert exc.value.owner == leader.node_id
    assert service.release_local(share, local.token)


def test_local_cannot_take_remote_lease(world):
    service, client, _, _, share, leader, follower, *_ = world
    remote = client.acquire("127.0.0.1", service.bound_port, leader.node_id, share, "sync")
    with pytest.raises(OperationBusy) as exc:
        service.acquire_local(share, "recovery")
    assert exc.value.owner == follower.node_id
    assert client.release("127.0.0.1", service.bound_port, leader.node_id, share, remote.token)


def test_remote_status_does_not_expose_token(world):
    service, client, _, _, share, leader, follower, *_ = world
    local = service.acquire_local(share, "deletion")
    status = client.status("127.0.0.1", service.bound_port, leader.node_id, share)
    assert status.owner == leader.node_id and status.operation == "deletion"
    assert status.seconds_left > 0
    assert not hasattr(status, "token")
    service.release_local(share, local.token)


def test_wrong_token_cannot_release_or_renew(world):
    service, client, _, _, share, leader, follower, *_ = world
    grant = client.acquire("127.0.0.1", service.bound_port, leader.node_id, share, "sync")
    wrong = uuid4().hex
    assert not client.renew("127.0.0.1", service.bound_port, leader.node_id, share, wrong)
    assert not client.release("127.0.0.1", service.bound_port, leader.node_id, share, wrong)
    assert service.status_local(share).owner == follower.node_id
    assert client.release("127.0.0.1", service.bound_port, leader.node_id, share, grant.token)


def test_lease_expires_and_new_owner_can_start(world):
    service, client, _, _, share, leader, follower, *_ = world
    old = service.acquire_local(share, "sync")
    time.sleep(2.55)
    new = client.acquire("127.0.0.1", service.bound_port, leader.node_id, share, "sync")
    assert new.token != old.token
    assert not service.renew_local(share, old.token)
    assert not service.release_local(share, old.token)
    assert client.release("127.0.0.1", service.bound_port, leader.node_id, share, new.token)


def test_renewal_extends_lifetime(world):
    service, client, _, _, share, leader, follower, *_ = world
    grant = service.acquire_local(share, "sync")
    time.sleep(1.1)
    assert service.renew_local(share, grant.token)
    time.sleep(1.45)
    assert service.status_local(share).owner == leader.node_id
    assert service.release_local(share, grant.token)


def test_two_guards_prevent_concurrent_operations(world):
    service, client, alice, bob, share, leader, follower, *_ = world
    with alice.hold("sync") as guard:
        guard.check()
        with pytest.raises(OperationBusy):
            with bob.hold("sync"):
                pass
    with bob.hold("sync") as guard:
        guard.check()
    assert service.status_local(share).owner is None


def test_heartbeat_keeps_remote_lease_alive(world):
    service, client, alice, bob, share, leader, follower, *_ = world
    with bob.hold("sync") as guard:
        time.sleep(3.0)
        guard.check()
        assert service.status_local(share).owner == follower.node_id
    assert service.status_local(share).owner is None


def test_heartbeat_detects_revocation(world):
    service, client, alice, bob, share, leader, follower, *_ = world
    with pytest.raises(OperationLeaseLost, match="SB-OPS-409"):
        with bob.hold("sync") as guard:
            # Server deliberately expires the token. The heartbeat must fail.
            with service._lock:
                service._leases.pop(share)
            time.sleep(1.15)
            guard.check()


def test_authority_is_deterministic(world):
    service, client, alice, bob, share, leader, follower, *_ = world
    assert alice.authority == bob.authority == leader.node_id
    with pytest.raises(ValueError, match="lower node"):
        OperationLockService(follower, world[-1], {share: leader.node_id})


def test_unknown_share_is_not_authorized(world):
    service, client, alice, bob, share, leader, follower, *_ = world
    with pytest.raises(OperationLockError, match="SB-OPS-403"):
        client.acquire("127.0.0.1", service.bound_port, leader.node_id, uuid4().hex, "sync")
    assert service.status_local(share).owner is None


def test_unpaired_device_cannot_acquire(world, tmp_path):
    service, client, alice, bob, share, leader, follower, *_ = world
    stranger = DeviceIdentity.generate()
    trust = TrustStore(tmp_path / "stranger.json")
    trust.add_verified(leader.public_key_hex, confirmed_fingerprint=leader.fingerprint, name="Authority")
    stranger_client = OperationLockClient(stranger, trust, timeout=1)
    if stranger.node_id > leader.node_id:
        with pytest.raises(Exception):
            stranger_client.acquire("127.0.0.1", service.bound_port, leader.node_id, share, "sync")
    assert service.status_local(share).owner is None


def test_authority_offline_blocks_new_operation(world):
    service, client, alice, bob, share, leader, follower, *_ = world
    port = service.bound_port
    service.stop()
    with pytest.raises(OperationLockError, match="SB-OPS-503"):
        client.acquire("127.0.0.1", port, leader.node_id, share, "sync")


def test_forged_owner_cannot_release_other_lease(world):
    service, client, alice, bob, share, leader, follower, *_ = world
    grant = service.acquire_local(share, "sync")
    assert not client.release("127.0.0.1", service.bound_port, leader.node_id, share, grant.token)
    assert service.status_local(share).owner == leader.node_id
    assert service.release_local(share, grant.token)


def test_bad_operation_and_token_rejected(world):
    service, client, alice, bob, share, leader, follower, *_ = world
    with pytest.raises(ValueError):
        service.acquire_local(share, "erase_everything")
    with pytest.raises(ValueError):
        client.renew("127.0.0.1", service.bound_port, leader.node_id, share, "bad")
    assert service.status_local(share).owner is None


def test_two_threads_only_one_wins(world):
    service, client, alice, bob, share, leader, follower, *_ = world
    barrier = threading.Barrier(2)
    winners = []
    results = []
    guard = threading.Lock()

    def run(coordinator):
        barrier.wait(timeout=3)
        try:
            with coordinator.hold("sync"):
                with guard:
                    winners.append(coordinator.identity.node_id)
                time.sleep(0.25)
        except OperationBusy:
            with guard:
                results.append("busy")

    threads = [threading.Thread(target=run, args=(coordinator,)) for coordinator in (alice, bob)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert len(winners) == 1
    assert results == ["busy"]
