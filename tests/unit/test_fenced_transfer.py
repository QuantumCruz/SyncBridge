
"""Real encrypted localhost tests for an opt-in lease-fenced PUSH listener.

These tests do NOT turn fencing on in SyncBridgeRuntime. They confirm that a
separate, explicitly fenced receiver accepts no legacy write or pull pathway.
"""
from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from syncbridge.network.fenced_lease_channel import (
    FencedLeaseClient,
    FencedLeaseService,
)
from syncbridge.network.fenced_transfer import (
    FencedTransferClient,
    FencedTransferService,
)
from syncbridge.network.lease_fencing import LeaseAuthority
from syncbridge.network.security import DeviceIdentity, TrustStore
from syncbridge.network.transfer import TransferError, TransferService
from syncbridge.storage.config import AppConfig, ConfigStore, ShareConfig


SHARE = "a" * 32


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, delta):
        self.now += delta


def _trust(path, other):
    store = TrustStore(path)
    store.add_verified(
        other.public_key_hex,
        confirmed_fingerprint=other.fingerprint,
        name="Trusted test peer",
    )
    return store


@pytest.fixture
def peers(tmp_path):
    alice_identity = DeviceIdentity.generate()
    bob_identity = DeviceIdentity.generate()

    alice_trust = _trust(
        tmp_path / "alice_trust.json",
        bob_identity,
    )
    bob_trust = _trust(
        tmp_path / "bob_trust.json",
        alice_identity,
    )

    alice_root = tmp_path / "alice"
    bob_root = tmp_path / "bob"
    alice_root.mkdir()
    bob_root.mkdir()

    profile = tmp_path / "bob_profile"
    store = ConfigStore(
        profile / "settings.json"
    )

    store.save(
        AppConfig(
            device_name="Bob",
            shares=(
                ShareConfig(
                    share_id=SHARE,
                    peer_node_id=alice_identity.node_id,
                    local_root=str(bob_root),
                    display_name="Test share",
                    remote_host="127.0.0.1",
                    enabled=True,
                    grant_write=True,
                    grant_read=True,
                    grant_manifest=True,
                    grant_agreement=True,
                ),
            ),
        )
    )

    clock = Clock()
    authority = LeaseAuthority(
        profile / "fences.sqlite",
        clock=clock,
    )

    lease_server = FencedLeaseService(
        bob_identity,
        bob_trust,
        store,
        authority,
        bind_address="127.0.0.1",
        port=0,
    )

    receiver = FencedTransferService(
        bob_identity,
        bob_trust,
        bob_root,
        authority=authority,
        share_id=SHARE,
        allowed_senders=(alice_identity.node_id,),
        allowed_readers=(alice_identity.node_id,),
        allow_overwrite=True,
        bind_address="127.0.0.1",
        listen_port=0,
    )

    sender = FencedTransferClient(
        alice_identity,
        alice_trust,
        alice_root,
        share_id=SHARE,
        bind_address="127.0.0.1",
        listen_port=0,
    )

    lease_client = FencedLeaseClient(
        alice_identity,
        alice_trust,
    )

    lease_server.start()

    try:
        receiver.start()

        try:
            yield {
                "alice": alice_root,
                "bob": bob_root,
                "clock": clock,
                "lease_server": lease_server,
                "receiver": receiver,
                "sender": sender,
                "lease_client": lease_client,
                "alice_identity": alice_identity,
                "bob_identity": bob_identity,
                "alice_trust": alice_trust,
            }

        finally:
            receiver.stop()

    finally:
        lease_server.stop()


def _lease(peers, ttl=10):
    return peers["lease_client"].acquire(
        "127.0.0.1",
        peers["lease_server"].bound_port,
        peers["bob_identity"].node_id,
        SHARE,
        ttl_seconds=ttl,
    )


def _send(
    peers,
    grant,
    path="file.txt",
    expected=None,
):
    return peers["sender"].send_fenced_file(
        "127.0.0.1",
        peers["receiver"].bound_port,
        peers["bob_identity"].node_id,
        peers["alice"],
        path,
        lease=grant,
        expected_destination_sha256=expected,
    )


def test_authenticated_fenced_push_publishes_exact_bytes(peers):
    payload = b"hello secure fenced transfer" * 1024

    (peers["alice"] / "nested").mkdir()
    (
        peers["alice"] / "nested" / "file.txt"
    ).write_bytes(payload)

    grant = _lease(peers)

    result = _send(
        peers,
        grant,
        "nested/file.txt",
    )

    assert result.completed
    assert result.sha256 == hashlib.sha256(
        payload
    ).hexdigest()

    assert (
        peers["bob"] / "nested" / "file.txt"
    ).read_bytes() == payload

    # An idempotent retry still requires a valid lease.
    assert _send(
        peers,
        grant,
        "nested/file.txt",
    ).completed


def test_fenced_zero_byte_file(peers):
    (
        peers["alice"] / "empty.txt"
    ).write_bytes(b"")

    assert _send(
        peers,
        _lease(peers),
        "empty.txt",
    ).completed

    assert (
        peers["bob"] / "empty.txt"
    ).read_bytes() == b""


def test_fenced_conditional_update_preserves_old_version_contract(
    peers,
):
    (
        peers["alice"] / "document.txt"
    ).write_bytes(b"new")

    (
        peers["bob"] / "document.txt"
    ).write_bytes(b"old")

    grant = _lease(peers)
    old_hash = hashlib.sha256(
        b"old"
    ).hexdigest()

    assert _send(
        peers,
        grant,
        "document.txt",
        expected=old_hash,
    ).completed

    assert (
        peers["bob"] / "document.txt"
    ).read_bytes() == b"new"


def test_fenced_conditional_update_rejects_other_persons_edit(
    peers,
):
    (
        peers["alice"] / "document.txt"
    ).write_bytes(b"new")

    (
        peers["bob"] / "document.txt"
    ).write_bytes(
        b"someone else edited"
    )

    with pytest.raises(TransferError):
        _send(
            peers,
            _lease(peers),
            "document.txt",
            expected=hashlib.sha256(
                b"old"
            ).hexdigest(),
        )

    assert (
        peers["bob"] / "document.txt"
    ).read_bytes() == b"someone else edited"


def test_expired_grant_cannot_write_and_new_generation_can(peers):
    (
        peers["alice"] / "new.txt"
    ).write_bytes(b"new bytes")

    old = _lease(peers, ttl=5)
    peers["clock"].advance(6)
    new = _lease(peers)

    with pytest.raises(TransferError):
        _send(
            peers,
            old,
            "new.txt",
        )

    assert not (
        peers["bob"] / "new.txt"
    ).exists()

    assert new.generation == old.generation + 1

    assert _send(
        peers,
        new,
        "new.txt",
    ).completed

    assert (
        peers["bob"] / "new.txt"
    ).read_bytes() == b"new bytes"


def test_forged_session_token_cannot_publish(peers):
    (
        peers["alice"] / "new.txt"
    ).write_bytes(b"new bytes")

    lease = _lease(peers)

    fake = replace(
        lease,
        session_token="f" * 64,
    )

    with pytest.raises(TransferError):
        _send(
            peers,
            fake,
            "new.txt",
        )

    assert not (
        peers["bob"] / "new.txt"
    ).exists()

    assert _send(
        peers,
        lease,
        "new.txt",
    ).completed


@pytest.mark.parametrize(
    "request_kind",
    ["offer", "get"],
)
def test_legacy_protocol_cannot_bypass_fenced_listener(
    peers,
    request_kind,
):
    (
        peers["alice"] / "old.txt"
    ).write_bytes(b"old protocol")

    legacy = TransferService(
        peers["alice_identity"],
        peers["alice_trust"],
        peers["alice"],
        share_id=SHARE,
        bind_address="127.0.0.1",
        listen_port=0,
    )

    with pytest.raises(TransferError):
        if request_kind == "offer":
            legacy.send_file(
                "127.0.0.1",
                peers["receiver"].bound_port,
                peers["bob_identity"].node_id,
                peers["alice"],
                "old.txt",
                share_id=SHARE,
            )

        else:
            legacy.fetch_file(
                "127.0.0.1",
                peers["receiver"].bound_port,
                peers["bob_identity"].node_id,
                SHARE,
                "old.txt",
            )

    assert not (
        peers["bob"] / "old.txt"
    ).exists()


def test_expiry_at_final_publish_blocks_encrypted_transfer(
    peers,
    monkeypatch,
):
    (
        peers["alice"] / "late.txt"
    ).write_bytes(
        b"large transfer" * 8192
    )

    grant = _lease(peers, ttl=5)
    publisher = peers["receiver"].publisher
    original = publisher.publish

    def expire_before_publish(*args, **kwargs):
        peers["clock"].advance(6)
        return original(
            *args,
            **kwargs,
        )

    monkeypatch.setattr(
        publisher,
        "publish",
        expire_before_publish,
    )

    with pytest.raises(TransferError):
        _send(
            peers,
            grant,
            "late.txt",
        )

    assert not (
        peers["bob"] / "late.txt"
    ).exists()


def test_revoked_write_permission_blocks_fenced_push(peers):
    (
        peers["alice"] / "note.txt"
    ).write_bytes(
        b"no longer authorized"
    )

    grant = _lease(peers)

    peers["receiver"].revoke_sender(
        peers["alice_identity"].node_id
    )

    with pytest.raises(TransferError):
        _send(
            peers,
            grant,
            "note.txt",
        )

    assert not (
        peers["bob"] / "note.txt"
    ).exists()
