
"""Real two-profile integration for the operation-bound SyncBridge runtime.

Both elected-authority arrangements are tested with disposable localhost peers.
The normal Qt launcher and user profiles are not involved.
"""
from __future__ import annotations

import hashlib
import socket
from uuid import uuid4

import pytest

from syncbridge.core.fenced_guarded_manual import FencedGuardedManualRuntime
from syncbridge.core.lifecycle import LifecycleStatus
from syncbridge.network.fenced_publish import PublishConflict
from syncbridge.network.fenced_lease_channel import LeaseChannelError
from syncbridge.network.lease_validation import LeaseProof, LeaseProofRejected
from syncbridge.network.operation_lock import OperationBusy
from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.network.transfer import TransferError, TransferService
from syncbridge.runtime import StartupError
from syncbridge.storage.config import AppConfig, ConfigStore, ShareConfig


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ports(amount: int) -> tuple[int, ...]:
    held = []

    try:
        for _ in range(amount):
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM,
            )
            sock.bind(("127.0.0.1", 0))
            held.append(sock)

        return tuple(
            sock.getsockname()[1]
            for sock in held
        )

    finally:
        for sock in held:
            sock.close()


def _configure(store, root, peer, share, ports):
    store.save(AppConfig(shares=(ShareConfig(
        share_id=share,
        peer_node_id=peer.node_id,
        local_root=str(root),
        display_name="Approved test folder",
        remote_host="127.0.0.1",
        manifest_port=ports[0],
        transfer_port=ports[1],
        agreement_port=ports[2],
        enabled=True,
        grant_read=True,
        grant_write=True,
        grant_manifest=True,
        grant_agreement=True,
    ),)))


@pytest.fixture(params=["alice_elected", "bob_elected"])
def pair(tmp_path, request):
    alice_profile = tmp_path / "AliceProfile"
    bob_profile = tmp_path / "BobProfile"

    alice_profile.mkdir()
    bob_profile.mkdir()

    sa = ConfigStore(alice_profile / "settings.json")
    sb = ConfigStore(bob_profile / "settings.json")

    real_alice = load_or_create_identity(
        alice_profile / "identity.json"
    )
    real_bob = load_or_create_identity(
        bob_profile / "identity.json"
    )

    # Both possible elected-authority arrangements.
    if (
        (real_alice.node_id < real_bob.node_id)
        != (request.param == "alice_elected")
    ):
        sa, sb = sb, sa
        real_alice, real_bob = real_bob, real_alice
        alice_profile, bob_profile = bob_profile, alice_profile

    ta = TrustStore(alice_profile / "trust.json")
    tb = TrustStore(bob_profile / "trust.json")

    ta.add_verified(
        real_bob.public_key_hex,
        confirmed_fingerprint=real_bob.fingerprint,
        name="Bob",
    )

    tb.add_verified(
        real_alice.public_key_hex,
        confirmed_fingerprint=real_alice.fingerprint,
        name="Alice",
    )

    a_root = tmp_path / "AliceFiles"
    b_root = tmp_path / "BobFiles"

    a_root.mkdir()
    b_root.mkdir()

    share = uuid4().hex
    ports = _ports(10)

    a_ports = ports[:3]
    b_ports = ports[3:6]

    a_lease, b_lease, lock_port, validation_port = ports[6:]

    _configure(
        sa, a_root, real_bob, share, b_ports
    )
    _configure(
        sb, b_root, real_alice, share, a_ports
    )

    alice = FencedGuardedManualRuntime(
        sa,
        bind_address="127.0.0.1",
        listen_ports=a_ports,
        lease_listen_port=a_lease,
        remote_lease_port=b_lease,
        lock_port=lock_port,
        validation_port=validation_port,
    )

    bob = FencedGuardedManualRuntime(
        sb,
        bind_address="127.0.0.1",
        listen_ports=b_ports,
        lease_listen_port=b_lease,
        remote_lease_port=a_lease,
        lock_port=lock_port,
        validation_port=validation_port,
    )

    try:
        bob.start()
        alice.start()

        yield {
            "a": alice,
            "b": bob,
            "a_root": a_root,
            "b_root": b_root,
            "share": share,
            "a_id": real_alice,
            "b_id": real_bob,
            "a_trust": ta,
        }

    finally:
        alice.stop()
        bob.stop()


def test_manual_lifecycle_syncs_both_directions_with_shared_history(pair):
    p = pair

    content_a = b"Alice's version" * 8192
    content_b = b"Bob's version" * 8192

    (p["a_root"] / "a.bin").write_bytes(content_a)
    (p["b_root"] / "b.bin").write_bytes(content_b)

    assert p["a"].preview().status is LifecycleStatus.PREVIEW
    assert not (p["b_root"] / "a.bin").exists()

    assert p["a"].sync_once().complete

    assert _digest(
        (p["b_root"] / "a.bin").read_bytes()
    ) == _digest(content_a)

    assert _digest(
        (p["a_root"] / "b.bin").read_bytes()
    ) == _digest(content_b)

    assert p["a"].shared_state.load(
        p["a_root"],
        p["b_id"].node_id,
        p["share"],
    ).revision == 1

    assert p["b"].shared_state.load(
        p["b_root"],
        p["a_id"].node_id,
        p["share"],
    ).revision == 1

    (
        p["b_root"] / "new.txt"
    ).write_text("second round", encoding="utf-8")

    assert p["b"].sync_once().complete

    assert (
        p["a_root"] / "new.txt"
    ).read_text(encoding="utf-8") == "second round"


def test_legacy_incoming_write_refused(pair):
    p = pair

    (
        p["a_root"] / "legacy.bin"
    ).write_bytes(b"not fenced")

    old_client = TransferService(
        p["a_id"],
        p["a_trust"],
        p["a_root"],
        share_id=p["share"],
        bind_address="127.0.0.1",
        listen_port=0,
    )

    with pytest.raises(TransferError):
        old_client.send_file(
            "127.0.0.1",
            p["b"].status.transfer_port,
            p["b_id"].node_id,
            p["a_root"],
            "legacy.bin",
            share_id=p["share"],
        )

    assert not (
        p["b_root"] / "legacy.bin"
    ).exists()


def test_elected_lock_rejects_competing_initiator(pair):
    p = pair

    (
        p["a_root"] / "file.txt"
    ).write_text("new", encoding="utf-8")

    with p["a"].leases.hold("sync"):
        with pytest.raises(OperationBusy):
            p["b"].sync_once()

    assert not (
        p["b_root"] / "file.txt"
    ).exists()

    assert p["a"].sync_once().complete


def test_unapproved_direct_coordinator_cannot_upload(pair):
    p = pair

    (
        p["a_root"] / "direct.txt"
    ).write_text("unauthorized", encoding="utf-8")

    preview = p["a"].coordinator.inspect()

    with pytest.raises(LeaseChannelError):
        p["a"].coordinator.execute_changes(preview)

    assert not (
        p["b_root"] / "direct.txt"
    ).exists()


def test_local_download_publisher_rejects_missing_operation_proof(pair):
    p = pair
    alice = p["a"]

    lease = alice.lease_authority.acquire(
        p["share"],
        alice.identity.node_id,
    )

    content = b"No local operation authority"
    name = "f" * 64 + ".part"

    stage = alice.transfer_client._staging / name
    stage.write_bytes(content)

    try:
        with pytest.raises(LeaseProofRejected):
            alice.transfer_client.publisher.publish(
                lease,
                authenticated_peer_id=alice.identity.node_id,
                relative_path="direct-local.bin",
                staging_name=name,
                expected_size=len(content),
                expected_sha256=_digest(content),
                expected_destination_sha256=None,
            )

        assert stage.exists()
        assert not (
            p["a_root"] / "direct-local.bin"
        ).exists()

    finally:
        alice.lease_authority.release(lease)


def test_revoked_elected_operation_blocks_remote_final_publication(pair):
    p = pair
    alice = p["a"]
    bob = p["b"]

    with alice.leases.hold("sync") as guard:
        proof = LeaseProof(
            p["share"],
            alice.identity.node_id,
            "sync",
            guard.token,
        )

        with alice.lease_client.use_operation(proof):
            lease = alice.lease_client.acquire(
                "127.0.0.1",
                bob.lease_server.bound_port,
                bob.identity.node_id,
                p["share"],
            )

    # The receiver's fencing grant still exists, but
    # the elected sync operation has ended.
    bob.lease_authority.assert_current(lease)

    content = b"stale elected sync operation"
    name = "e" * 64 + ".part"

    stage = bob.transfer_server._staging / name
    stage.write_bytes(content)

    try:
        with pytest.raises(
            PublishConflict,
            match="no longer authorized",
        ):
            bob.transfer_server.publisher.publish(
                lease,
                authenticated_peer_id=alice.identity.node_id,
                relative_path="stale.bin",
                staging_name=name,
                expected_size=len(content),
                expected_sha256=_digest(content),
                expected_destination_sha256=None,
            )

        assert stage.exists()
        assert not (
            p["b_root"] / "stale.bin"
        ).exists()

    finally:
        alice.lease_client.release(
            "127.0.0.1",
            bob.lease_server.bound_port,
            bob.identity.node_id,
            lease,
        )


def test_stopping_runtime_and_restarting_preserves_identity(pair):
    p = pair

    old_id = p["a"].identity.node_id

    p["a"].stop()
    assert not p["a"].status.running

    p["a"].start()

    assert p["a"].identity.node_id == old_id
    assert p["a"].transfer_server.is_running
    assert p["a"].lease_server.bound_port is not None


def test_default_is_manual_and_preview_does_not_copy(pair):
    p = pair

    (
        p["a_root"] / "pending.txt"
    ).write_text("not yet", encoding="utf-8")

    assert p["a"].preview().status is LifecycleStatus.PREVIEW

    assert not (
        p["b_root"] / "pending.txt"
    ).exists()

    with pytest.raises(
        StartupError,
        match="manual",
    ):
        p["a"].start(background=True)
