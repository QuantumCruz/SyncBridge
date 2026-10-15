
"""Phase 20B: real runtime sync with authenticated cooperative leases.

Tests use two distinct persisted identities, trust stores, SQLite databases,
and localhost TCP listeners. This is not receiver-side lease fencing.
"""
from __future__ import annotations

import socket
from unittest.mock import Mock
from uuid import uuid4

import pytest

from syncbridge.core.approved_deletion import ApprovedDeletionCoordinator
from syncbridge.core.coordinated_operations import (
    CoordinatedOperations,
    LocalOperationBusy,
)
from syncbridge.core.lifecycle import LifecycleStatus
from syncbridge.network.operation_lock import (
    LeaseCoordinator,
    OperationBusy,
    OperationLockClient,
    OperationLockError,
    OperationLockService,
)
from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.runtime import SyncBridgeRuntime
from syncbridge.storage.config import AppConfig, ConfigStore, ShareConfig


def available_ports(amount: int) -> tuple[int, ...]:
    """Allocate distinct local ports for the two live runtime processes."""
    ports = []
    while len(ports) < amount:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        if port not in ports:
            ports.append(port)
    return tuple(ports)


@pytest.fixture
def devices(tmp_path):
    share = uuid4().hex
    names = ("alice", "bob")
    folders = {}
    profiles = {}
    identities = {}
    trusts = {}
    allocation = available_ports(6)
    ports = {"alice": allocation[:3], "bob": allocation[3:]}
    runtimes = {}
    authority_service = None

    for name in names:
        directory = tmp_path / name
        profiles[name] = directory / "Profile"
        folders[name] = directory / "Shared"
        profiles[name].mkdir(parents=True)
        folders[name].mkdir()
        identities[name] = load_or_create_identity(profiles[name] / "identity.json")
        trusts[name] = TrustStore(profiles[name] / "trust.json")

    for name in names:
        other = "bob" if name == "alice" else "alice"
        peer = identities[other]
        trusts[name].add_verified(
            peer.public_key_hex,
            confirmed_fingerprint=peer.fingerprint,
            name=other.capitalize(),
        )
        store = ConfigStore(profiles[name] / "settings.json")
        remote_ports = ports[other]
        store.save(
            AppConfig(
                device_name=name.capitalize(),
                shares=(ShareConfig(
                    share_id=share,
                    peer_node_id=peer.node_id,
                    local_root=str(folders[name]),
                    display_name="Shared",
                    remote_host="127.0.0.1",
                    manifest_port=remote_ports[0],
                    transfer_port=remote_ports[1],
                    agreement_port=remote_ports[2],
                    enabled=True,
                    grant_manifest=True,
                    grant_read=True,
                    grant_write=True,
                    grant_agreement=True,
                ),),
            )
        )
        runtimes[name] = SyncBridgeRuntime(
            store, listen_ports=ports[name], bind_address="127.0.0.1"
        )

    leader = min(names, key=lambda name: identities[name].node_id)
    follower = "bob" if leader == "alice" else "alice"

    try:
        for name in names:
            runtimes[name].start(background=False)

        authority_service = OperationLockService(
            identities[leader], trusts[leader],
            {share: identities[follower].node_id},
            bind_address="127.0.0.1", listen_port=0,
            lease_seconds=3.0, timeout=2.0,
        )
        authority_service.start()

        leases = {}
        operations = {}
        for name in names:
            other = "bob" if name == "alice" else "alice"
            if name == leader:
                leases[name] = LeaseCoordinator(
                    identities[name], identities[other].node_id, share,
                    local_service=authority_service,
                )
            else:
                client = OperationLockClient(
                    identities[name], trusts[name], timeout=2.0
                )
                leases[name] = LeaseCoordinator(
                    identities[name], identities[other].node_id, share,
                    client=client, host="127.0.0.1",
                    port=authority_service.bound_port,
                )
            operations[name] = CoordinatedOperations(
                runtimes[name].lifecycle, leases[name]
            )

        yield {
            "operations": operations,
            "leases": leases,
            "folders": folders,
            "runtimes": runtimes,
            "service": authority_service,
            "leader": leader,
            "follower": follower,
            "share": share,
            "identities": identities,
        }
    finally:
        if authority_service is not None:
            authority_service.stop()
        for name in reversed(names):
            runtimes[name].stop()


def test_real_two_way_sync_from_either_device(devices):
    ops, folders = devices["operations"], devices["folders"]
    (folders["alice"] / "from_alice.txt").write_text("Hello from Alice")
    (folders["bob"] / "from_bob.txt").write_text("Hello from Bob")

    first = ops["alice"].sync_once()
    assert first.complete
    assert first.checkpoint.baseline.revision == 1
    assert (folders["bob"] / "from_alice.txt").read_text() == "Hello from Alice"
    assert (folders["alice"] / "from_bob.txt").read_text() == "Hello from Bob"

    (folders["bob"] / "from_bob.txt").write_text("Bob changed this")
    second = ops["bob"].sync_once()
    assert second.complete
    assert second.checkpoint.baseline.revision == 2
    assert (folders["alice"] / "from_bob.txt").read_text() == "Bob changed this"


def test_bob_waits_while_alice_has_permission(devices):
    ops, leases = devices["operations"], devices["leases"]
    with leases["alice"].hold("sync"):
        with pytest.raises(OperationBusy, match="SB-OPS-423"):
            ops["bob"].sync_once()

    assert ops["bob"].sync_once().status is LifecycleStatus.COMMITTED


def test_alice_waits_while_bob_has_permission(devices):
    ops, leases = devices["operations"], devices["leases"]
    with leases["bob"].hold("sync"):
        with pytest.raises(OperationBusy, match="SB-OPS-423"):
            ops["alice"].sync_once()
    assert ops["alice"].sync_once().complete


def test_preview_is_read_only_during_peer_lease(devices):
    ops, leases = devices["operations"], devices["leases"]
    with leases["bob"].hold("sync"):
        report = ops["alice"].preview()
        assert report.status is LifecycleStatus.PREVIEW
    assert devices["service"].status_local(devices["share"]).owner is None


def test_authority_offline_blocks_changes_before_sync(devices):
    follower = devices["follower"]
    folder = devices["folders"][follower]
    (folder / "untouched.txt").write_text("Only local")
    devices["service"].stop()

    with pytest.raises(OperationLockError, match="SB-OPS-503"):
        devices["operations"][follower].sync_once()
    assert (folder / "untouched.txt").read_text() == "Only local"


def test_same_runner_cannot_start_two_operations(devices):
    runner = devices["operations"]["alice"]
    runner._local_lock.acquire()
    try:
        with pytest.raises(LocalOperationBusy, match="SB-OPS-423"):
            runner.sync_once()
        with pytest.raises(LocalOperationBusy, match="SB-OPS-423"):
            runner.preview()
    finally:
        runner._local_lock.release()


def test_approved_delete_requires_explicit_local_confirmation(devices):
    runner = devices["operations"]["alice"]
    fake = Mock(spec=ApprovedDeletionCoordinator)
    fake.lifecycle = runner.lifecycle
    manager = CoordinatedOperations(
        runner.lifecycle, runner.leases, approved_deletion=fake
    )

    with pytest.raises(ValueError, match="SB-DEL-111"):
        manager.delete_approved(uuid4().hex)
    fake.apply.assert_not_called()

    with devices["leases"]["bob"].hold("sync"):
        with pytest.raises(OperationBusy, match="SB-OPS-423"):
            manager.delete_approved(uuid4().hex, confirmed=True)
    fake.apply.assert_not_called()

    outcome = object()
    fake.apply.return_value = outcome
    assert manager.delete_approved(uuid4().hex, confirmed=True) is outcome
    fake.apply.assert_called_once()


def test_rejects_lease_for_different_share(devices):
    runtime = devices["runtimes"]["alice"]
    original = devices["leases"]["alice"]
    mismatched = LeaseCoordinator(
        original.identity,
        original.peer_node_id,
        uuid4().hex,
        client=original.client,
        local_service=original.local_service,
        host=original.host,
        port=original.port,
    )
    with pytest.raises(ValueError, match="same share"):
        CoordinatedOperations(runtime.lifecycle, mismatched)
