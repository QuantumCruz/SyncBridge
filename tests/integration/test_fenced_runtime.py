
"""End-to-end runtime tests: fenced upload/download through the real lifecycle.

Two independent, paired profiles run on localhost. The server exposes one
fenced transfer port for reads and writes; the client uses the existing
Preview -> Apply lifecycle, with no legacy publishing endpoint.
"""
from __future__ import annotations

import hashlib
from uuid import uuid4

import pytest

from syncbridge.network.fenced_lease_channel import LeaseChannelError
from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.network.transfer import TransferError, TransferService
from syncbridge.runtime_fenced import FencedSyncBridgeRuntime
from syncbridge.storage.config import AppConfig, ConfigStore, ShareConfig


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _profile(tmp_path, name):
    home = tmp_path / name
    home.mkdir()
    config = ConfigStore(home / "settings.json")
    identity = load_or_create_identity(home / "identity.json")
    trust = TrustStore(home / "trust.json")
    return config, identity, trust


def _configure(store, root, peer_id, share, ports=(45843, 45842, 45844)):
    store.save(AppConfig(shares=(ShareConfig(
        share_id=share,
        peer_node_id=peer_id,
        local_root=str(root),
        display_name="Approved folder",
        remote_host="127.0.0.1",
        manifest_port=ports[0],
        transfer_port=ports[1],
        agreement_port=ports[2],
        enabled=True,
        grant_manifest=True,
        grant_read=True,
        grant_write=True,
        grant_agreement=True,
    ),)))


@pytest.fixture
def paired_runtimes(tmp_path):
    alice_store, alice_id, alice_trust = _profile(tmp_path, "AliceProfile")
    bob_store, bob_id, bob_trust = _profile(tmp_path, "BobProfile")

    alice_trust.add_verified(
        bob_id.public_key_hex,
        confirmed_fingerprint=bob_id.fingerprint,
        name="Bob",
    )
    bob_trust.add_verified(
        alice_id.public_key_hex,
        confirmed_fingerprint=alice_id.fingerprint,
        name="Alice",
    )

    alice_root = tmp_path / "AliceFiles"
    bob_root = tmp_path / "BobFiles"
    alice_root.mkdir()
    bob_root.mkdir()
    share = uuid4().hex

    _configure(bob_store, bob_root, alice_id.node_id, share)
    bob = FencedSyncBridgeRuntime(
        bob_store,
        listen_ports=(0, 0, 0),
        lease_listen_port=0,
    )
    bob.start()

    alice = None
    try:
        ports = (
            bob.status.manifest_port,
            bob.status.transfer_port,
            bob.status.agreement_port,
        )
        _configure(alice_store, alice_root, bob_id.node_id, share, ports)
        alice = FencedSyncBridgeRuntime(
            alice_store,
            listen_ports=(0, 0, 0),
            lease_listen_port=0,
            remote_lease_port=bob.lease_server.bound_port,
        )
        alice.start()

        yield {
            "alice": alice,
            "bob": bob,
            "alice_root": alice_root,
            "bob_root": bob_root,
            "alice_store": alice_store,
            "bob_store": bob_store,
            "alice_id": alice_id,
            "bob_id": bob_id,
            "alice_trust": alice_trust,
            "share": share,
        }
    finally:
        if alice is not None:
            alice.stop()
        bob.stop()


def test_real_lifecycle_syncs_both_ways_under_fencing(paired_runtimes):
    p = paired_runtimes
    a = p["alice_root"] / "alice.bin"
    b = p["bob_root"] / "bob.bin"
    a.write_bytes(b"Alice's file" * 2048)
    b.write_bytes(b"Bob's file" * 2048)

    result = p["alice"].lifecycle.run_once(apply=True)

    assert result.complete
    assert _sha(a) == _sha(p["bob_root"] / "alice.bin")
    assert _sha(b) == _sha(p["alice_root"] / "bob.bin")
    assert p["alice"].shared_state.load(
        p["alice_root"], p["bob_id"].node_id, p["share"]
    ).revision == 1
    assert p["bob"].shared_state.load(
        p["bob_root"], p["alice_id"].node_id, p["share"]
    ).revision == 1


def test_legacy_upload_cannot_write_to_real_runtime(paired_runtimes):
    p = paired_runtimes
    source = p["alice_root"] / "legacy.txt"
    source.write_bytes(b"unfenced write must be rejected")

    legacy = TransferService(
        p["alice_id"],
        p["alice_trust"],
        p["alice_root"],
        share_id=p["share"],
        bind_address="127.0.0.1",
        listen_port=0,
    )
    with pytest.raises(TransferError):
        legacy.send_file(
            "127.0.0.1",
            p["bob"].status.transfer_port,
            p["bob_id"].node_id,
            p["alice_root"],
            "legacy.txt",
            share_id=p["share"],
        )
    assert not (p["bob_root"] / "legacy.txt").exists()


def test_create_only_mode_uses_fenced_upload(paired_runtimes):
    p = paired_runtimes
    (p["alice_root"] / "only-alice.txt").write_text("new")
    (p["bob_root"] / "only-bob.txt").write_text("keep")

    preview = p["alice"].coordinator.inspect()
    outcome = p["alice"].coordinator.execute_new_files(preview)
    assert outcome.uploaded
    assert (p["bob_root"] / "only-alice.txt").read_text() == "new"
    assert not (p["alice_root"] / "only-bob.txt").exists()


def test_lease_denial_leaves_both_folders_untouched(paired_runtimes):
    from dataclasses import replace

    p = paired_runtimes
    (p["alice_root"] / "a.txt").write_text("from Alice")
    (p["bob_root"] / "b.txt").write_text("from Bob")

    config = p["bob_store"].load()
    p["bob_store"].save(replace(
        config,
        shares=(replace(config.shares[0], grant_write=False),),
    ))

    with pytest.raises(LeaseChannelError):
        p["alice"].lifecycle.run_once(apply=True)

    assert not (p["bob_root"] / "a.txt").exists()
    assert not (p["alice_root"] / "b.txt").exists()
    assert p["alice"].transfer_server.is_running
    assert p["bob"].transfer_server.is_running


def test_stopping_fenced_runtime_releases_profile_lock(paired_runtimes):
    p = paired_runtimes
    alice = p["alice"]
    identity = alice.identity.node_id

    alice.stop()
    assert not alice.status.running
    assert alice.start().running
    assert alice.identity.node_id == identity
    assert alice.transfer_server.is_running
    assert alice.lease_server.bound_port is not None
