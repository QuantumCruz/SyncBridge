
"""End-to-end encrypted GET into a locally lease-fenced destination.

Only disposable localhost shares are used. Bob grants read access; Alice owns
and validates the lease for her local destination. Production runtime untouched.
"""
from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from syncbridge.network.fenced_download import FencedDownloadClient
from syncbridge.network.lease_fencing import FencedOut, LeaseAuthority
from syncbridge.network.security import DeviceIdentity, TrustStore
from syncbridge.network.transfer import TransferError, TransferService


SHARE = "a" * 32


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def _trust(path, other):
    store = TrustStore(path)
    store.add_verified(
        other.public_key_hex,
        confirmed_fingerprint=other.fingerprint,
        name="Trusted test device",
    )
    return store


@pytest.fixture
def peers(tmp_path):
    alice = DeviceIdentity.generate()
    bob = DeviceIdentity.generate()

    alice_trust = _trust(
        tmp_path / "alice-trust.json",
        bob,
    )

    bob_trust = _trust(
        tmp_path / "bob-trust.json",
        alice,
    )

    alice_root = tmp_path / "alice"
    bob_root = tmp_path / "bob"

    alice_root.mkdir()
    bob_root.mkdir()

    clock = Clock()

    authority = LeaseAuthority(
        tmp_path / "alice-profile" / "fences.sqlite",
        clock=clock,
    )

    client = FencedDownloadClient(
        alice,
        alice_trust,
        alice_root,
        share_id=SHARE,
        authority=authority,
        allow_overwrite=True,
        bind_address="127.0.0.1",
        listen_port=0,
    )

    source = TransferService(
        bob,
        bob_trust,
        bob_root,
        share_id=SHARE,
        allowed_readers=(alice.node_id,),
        bind_address="127.0.0.1",
        listen_port=0,
    )

    source.start()

    try:
        yield {
            "alice": alice,
            "bob": bob,
            "alice_root": alice_root,
            "bob_root": bob_root,
            "authority": authority,
            "clock": clock,
            "client": client,
            "source": source,
        }

    finally:
        source.stop()


def _grant(peers, ttl=30):
    return peers["authority"].acquire(
        SHARE,
        peers["alice"].node_id,
        ttl_seconds=ttl,
    )


def _fetch(
    peers,
    lease,
    *,
    path="file.txt",
    content=b"remote",
    expected=None,
    source_hash=None,
    **kwargs,
):
    return peers["client"].fetch_fenced_file(
        "127.0.0.1",
        peers["source"].bound_port,
        peers["bob"].node_id,
        SHARE,
        path,
        lease=lease,
        expected_source_sha256=(
            source_hash or hashlib.sha256(content).hexdigest()
        ),
        expected_destination_sha256=expected,
        **kwargs,
    )


def test_download_creates_verified_file_in_local_receiver(peers):
    content = b"from Bob" * 1024

    (peers["bob_root"] / "folder").mkdir()

    (
        peers["bob_root"] / "folder" / "file.txt"
    ).write_bytes(content)

    receipt = _fetch(
        peers,
        _grant(peers),
        path="folder/file.txt",
        content=content,
    )

    assert receipt.completed

    assert receipt.sha256 == hashlib.sha256(
        content
    ).hexdigest()

    assert (
        peers["alice_root"] / "folder" / "file.txt"
    ).read_bytes() == content


def test_fenced_zero_byte_download(peers):
    (
        peers["bob_root"] / "file.txt"
    ).write_bytes(b"")

    result = _fetch(
        peers,
        _grant(peers),
        content=b"",
    )

    assert result.completed

    assert (
        peers["alice_root"] / "file.txt"
    ).read_bytes() == b""


def test_conditional_update_and_idempotent_retry(peers):
    (
        peers["alice_root"] / "file.txt"
    ).write_bytes(b"old")

    (
        peers["bob_root"] / "file.txt"
    ).write_bytes(b"new")

    lease = _grant(peers)
    old_hash = hashlib.sha256(b"old").hexdigest()

    assert _fetch(
        peers,
        lease,
        content=b"new",
        expected=old_hash,
    ).completed

    assert (
        peers["alice_root"] / "file.txt"
    ).read_bytes() == b"new"

    assert _fetch(
        peers,
        lease,
        content=b"new",
        expected=old_hash,
    ).completed


def test_competing_local_writer_is_not_overwritten(peers):
    (
        peers["alice_root"] / "file.txt"
    ).write_bytes(b"local edit")

    (
        peers["bob_root"] / "file.txt"
    ).write_bytes(b"remote edit")

    with pytest.raises(TransferError):
        _fetch(
            peers,
            _grant(peers),
            content=b"remote edit",
            expected=hashlib.sha256(
                b"old"
            ).hexdigest(),
        )

    assert (
        peers["alice_root"] / "file.txt"
    ).read_bytes() == b"local edit"


def test_expired_and_replaced_local_lease_cannot_publish(peers):
    (
        peers["bob_root"] / "file.txt"
    ).write_bytes(b"remote")

    old = _grant(peers, ttl=5)

    peers["clock"].advance(6)

    new = _grant(peers)

    with pytest.raises(FencedOut):
        _fetch(peers, old)

    assert not (
        peers["alice_root"] / "file.txt"
    ).exists()

    assert _fetch(peers, new).completed


def test_forged_local_lease_does_not_publish(peers):
    (
        peers["bob_root"] / "file.txt"
    ).write_bytes(b"remote")

    good = _grant(peers)

    fake = replace(
        good,
        session_token="f" * 64,
    )

    with pytest.raises(FencedOut):
        _fetch(peers, fake)

    assert not (
        peers["alice_root"] / "file.txt"
    ).exists()

    assert _fetch(peers, good).completed


def test_remote_source_change_is_rejected(peers):
    (
        peers["bob_root"] / "file.txt"
    ).write_bytes(b"different")

    with pytest.raises(TransferError):
        _fetch(
            peers,
            _grant(peers),
            content=b"original",
        )

    assert not (
        peers["alice_root"] / "file.txt"
    ).exists()


def test_revoked_remote_read_permission_denies_download(peers):
    (
        peers["bob_root"] / "file.txt"
    ).write_bytes(b"remote")

    peers["source"].revoke_reader(
        peers["alice"].node_id
    )

    with pytest.raises(TransferError):
        _fetch(
            peers,
            _grant(peers),
        )

    assert not (
        peers["alice_root"] / "file.txt"
    ).exists()


def test_expiry_during_actual_download_blocks_final_publish(
    peers,
    monkeypatch,
):
    data = b"payload" * 8192

    (
        peers["bob_root"] / "file.txt"
    ).write_bytes(data)

    grant = _grant(peers, ttl=5)

    original = peers["client"].publisher.publish

    def expire_before_commit(*args, **kwargs):
        peers["clock"].advance(6)
        return original(*args, **kwargs)

    monkeypatch.setattr(
        peers["client"].publisher,
        "publish",
        expire_before_commit,
    )

    with pytest.raises(FencedOut):
        _fetch(
            peers,
            grant,
            content=data,
        )

    assert not (
        peers["alice_root"] / "file.txt"
    ).exists()


def test_client_has_no_legacy_unfenced_entry_point(peers):
    client = peers["client"]

    with pytest.raises(TransferError):
        client.start()

    with pytest.raises(TransferError):
        client.fetch_file(
            "127.0.0.1",
            1,
            peers["bob"].node_id,
            SHARE,
            "file.txt",
        )

    with pytest.raises(TransferError):
        client.send_file(
            "127.0.0.1",
            1,
            peers["bob"].node_id,
            peers["alice_root"],
            "file.txt",
        )

    assert not client.is_running
