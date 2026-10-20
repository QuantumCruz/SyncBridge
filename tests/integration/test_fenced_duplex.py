
"""Real encrypted single-port tests for fenced bidirectional transfers.

Two trusted identities use disposable folders and receiver-local SQLite
authorities. The same server port handles fenced uploads and approved GETs.

No normal desktop runtime is modified by this suite.
"""

from __future__ import annotations

import hashlib

import pytest

from syncbridge.network.fenced_download import FencedDownloadClient
from syncbridge.network.fenced_duplex import FencedDuplexService
from syncbridge.network.fenced_lease_channel import (
    FencedLeaseClient,
    FencedLeaseService,
)
from syncbridge.network.fenced_sync_session import FencedSyncSession
from syncbridge.network.fenced_transfer import FencedTransferClient
from syncbridge.network.lease_fencing import LeaseAuthority
from syncbridge.network.security import DeviceIdentity, TrustStore
from syncbridge.network.transfer import TransferError, TransferService
from syncbridge.storage.config import AppConfig, ConfigStore, ShareConfig


SHARE = "a" * 32


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
    alice = DeviceIdentity.generate()
    bob = DeviceIdentity.generate()

    alice_root = tmp_path / "Alice"
    bob_root = tmp_path / "Bob"

    alice_root.mkdir()
    bob_root.mkdir()

    alice_trust = _trust(
        tmp_path / "alice-trust.json",
        bob,
    )

    bob_trust = _trust(
        tmp_path / "bob-trust.json",
        alice,
    )

    bob_settings = ConfigStore(
        tmp_path / "BobProfile" / "settings.json"
    )

    bob_settings.save(
        AppConfig(
            device_name="Bob",
            shares=(
                ShareConfig(
                    share_id=SHARE,
                    peer_node_id=alice.node_id,
                    local_root=str(bob_root),
                    display_name="Shared folder",
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

    alice_authority = LeaseAuthority(
        tmp_path / "AliceProfile" / "leases.sqlite"
    )

    bob_authority = LeaseAuthority(
        tmp_path / "BobProfile" / "leases.sqlite"
    )

    lease_server = FencedLeaseService(
        bob,
        bob_trust,
        bob_settings,
        bob_authority,
        bind_address="127.0.0.1",
        port=0,
    )

    duplex = FencedDuplexService(
        bob,
        bob_trust,
        bob_root,
        authority=bob_authority,
        share_id=SHARE,
        allowed_senders=(alice.node_id,),
        allowed_readers=(alice.node_id,),
        allow_overwrite=True,
        bind_address="127.0.0.1",
        listen_port=0,
    )

    upload_client = FencedTransferClient(
        alice,
        alice_trust,
        alice_root,
        share_id=SHARE,
        bind_address="127.0.0.1",
        listen_port=0,
    )

    download_client = FencedDownloadClient(
        alice,
        alice_trust,
        alice_root,
        share_id=SHARE,
        authority=alice_authority,
        allow_overwrite=True,
        bind_address="127.0.0.1",
        listen_port=0,
    )

    lease_client = FencedLeaseClient(
        alice,
        alice_trust,
    )

    started = []

    try:
        for service in (lease_server, duplex):
            service.start()
            started.append(service)

        def make_session(
            *,
            need_upload=True,
            need_download=True,
        ):
            return FencedSyncSession(
                local_root=alice_root,
                share_id=SHARE,
                peer_node_id=bob.node_id,
                remote_host="127.0.0.1",
                remote_lease_port=lease_server.bound_port,
                remote_upload_port=duplex.bound_port,
                remote_read_port=duplex.bound_port,
                lease_client=lease_client,
                local_authority=alice_authority,
                upload_client=upload_client,
                download_client=download_client,
                need_upload=need_upload,
                need_download=need_download,
                ttl_seconds=30,
                renewal_interval_seconds=0.1,
            )

        yield {
            "alice": alice,
            "bob": bob,
            "alice_root": alice_root,
            "bob_root": bob_root,
            "alice_trust": alice_trust,
            "alice_authority": alice_authority,
            "bob_authority": bob_authority,
            "duplex": duplex,
            "upload_client": upload_client,
            "lease_client": lease_client,
            "lease_server": lease_server,
            "session": make_session,
        }

    finally:
        for service in reversed(started):
            service.stop()


def test_single_port_synchronizes_both_directions(peers):
    from_alice = b"Hello from Alice" * 2048
    from_bob = b"Hello from Bob" * 2048

    (peers["alice_root"] / "nested").mkdir()
    (
        peers["alice_root"] / "nested" / "alice.txt"
    ).write_bytes(from_alice)

    (
        peers["bob_root"] / "bob.txt"
    ).write_bytes(from_bob)

    session = peers["session"]()

    with session:
        upload = session.upload(
            "nested/alice.txt"
        )

        download = session.download(
            "bob.txt",
            expected_source_sha256=_sha(from_bob),
        )

        assert upload.completed
        assert download.completed

        assert upload.sha256 == _sha(from_alice)
        assert download.sha256 == _sha(from_bob)

    assert (
        peers["bob_root"] / "nested" / "alice.txt"
    ).read_bytes() == from_alice

    assert (
        peers["alice_root"] / "bob.txt"
    ).read_bytes() == from_bob

    assert not session.active
    assert session.cleanup_errors == []


def test_conditional_updates_work_both_ways(peers):
    (peers["alice_root"] / "upload.txt").write_bytes(
        b"new upload"
    )
    (peers["bob_root"] / "upload.txt").write_bytes(
        b"old upload"
    )

    (peers["alice_root"] / "download.txt").write_bytes(
        b"old download"
    )
    (peers["bob_root"] / "download.txt").write_bytes(
        b"new download"
    )

    with peers["session"]() as session:
        assert session.upload(
            "upload.txt",
            expected_destination_sha256=_sha(
                b"old upload"
            ),
        ).completed

        assert session.download(
            "download.txt",
            expected_source_sha256=_sha(
                b"new download"
            ),
            expected_destination_sha256=_sha(
                b"old download"
            ),
        ).completed

    assert (
        peers["bob_root"] / "upload.txt"
    ).read_bytes() == b"new upload"

    assert (
        peers["alice_root"] / "download.txt"
    ).read_bytes() == b"new download"


def test_legacy_upload_is_rejected_on_same_port(peers):
    content = b"Legacy protocol must not bypass fencing"

    (
        peers["alice_root"] / "legacy.txt"
    ).write_bytes(content)

    legacy = TransferService(
        peers["alice"],
        peers["alice_trust"],
        peers["alice_root"],
        share_id=SHARE,
        bind_address="127.0.0.1",
        listen_port=0,
    )

    with pytest.raises(TransferError):
        legacy.send_file(
            "127.0.0.1",
            peers["duplex"].bound_port,
            peers["bob"].node_id,
            peers["alice_root"],
            "legacy.txt",
            share_id=SHARE,
        )

    assert not (
        peers["bob_root"] / "legacy.txt"
    ).exists()


def test_revoking_read_does_not_grant_legacy_write(peers):
    content = b"Bob's private readable file"

    (
        peers["bob_root"] / "private.txt"
    ).write_bytes(content)

    peers["duplex"].revoke_reader(
        peers["alice"].node_id
    )

    with peers["session"](
        need_upload=False,
        need_download=True,
    ) as session:
        with pytest.raises(TransferError):
            session.download(
                "private.txt",
                expected_source_sha256=_sha(content),
            )

    assert not (
        peers["alice_root"] / "private.txt"
    ).exists()

    assert (
        peers["bob_root"] / "private.txt"
    ).read_bytes() == content


def test_revoking_write_stops_fenced_upload(peers):
    content = b"Should not arrive at Bob"

    (
        peers["alice_root"] / "denied.txt"
    ).write_bytes(content)

    peers["duplex"].revoke_sender(
        peers["alice"].node_id
    )

    with peers["session"](
        need_upload=True,
        need_download=False,
    ) as session:
        with pytest.raises(TransferError):
            session.upload("denied.txt")

    assert not (
        peers["bob_root"] / "denied.txt"
    ).exists()


def test_old_lease_cannot_publish_after_session_closes(peers):
    content = b"Stale session bytes"

    (
        peers["alice_root"] / "stale.txt"
    ).write_bytes(content)

    with peers["session"](
        need_upload=True,
        need_download=False,
    ) as session:
        old_lease = session.remote_grant

        assert old_lease is not None

    with pytest.raises(TransferError):
        peers["upload_client"].send_fenced_file(
            "127.0.0.1",
            peers["duplex"].bound_port,
            peers["bob"].node_id,
            peers["alice_root"],
            "stale.txt",
            lease=old_lease,
        )

    assert not (
        peers["bob_root"] / "stale.txt"
    ).exists()


def test_remote_source_mismatch_preserves_local_files(peers):
    (
        peers["bob_root"] / "document.txt"
    ).write_bytes(b"changed remotely")

    (
        peers["alice_root"] / "document.txt"
    ).write_bytes(b"my local content")

    with peers["session"](
        need_upload=False,
        need_download=True,
    ) as session:
        with pytest.raises(TransferError):
            session.download(
                "document.txt",
                expected_source_sha256=_sha(
                    b"outdated remote content"
                ),
                expected_destination_sha256=_sha(
                    b"my local content"
                ),
            )

    assert (
        peers["alice_root"] / "document.txt"
    ).read_bytes() == b"my local content"
