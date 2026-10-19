
"""Real authenticated integration tests for the fenced transfer lifecycle.

All tests use disposable file shares, real encrypted localhost services, and
receiver-local SQLite lease authorities. The read listener is explicitly
read-only, so it cannot bypass fenced publication with a legacy upload.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import replace

import pytest

from syncbridge.network.fenced_download import FencedDownloadClient
from syncbridge.network.fenced_lease_channel import (
    FencedLeaseClient,
    FencedLeaseService,
    LeaseChannelError,
)
from syncbridge.network.fenced_sync_session import (
    FencedSessionError,
    FencedSyncSession,
)
from syncbridge.network.fenced_transfer import (
    FencedTransferClient,
    FencedTransferService,
)
from syncbridge.network.lease_fencing import (
    FencedOut,
    LeaseAuthority,
    LeaseBusy,
)
from syncbridge.network.security import DeviceIdentity, TrustStore
from syncbridge.network.transfer import TransferError, TransferService
from syncbridge.storage.config import AppConfig, ConfigStore, ShareConfig


SHARE = "a" * 32


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, value):
        self.now += value


def _trust(path, other):
    store = TrustStore(path)
    store.add_verified(
        other.public_key_hex,
        confirmed_fingerprint=other.fingerprint,
        name="Test computer",
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

    alice_trust = _trust(tmp_path / "AliceTrust.json", bob)
    bob_trust = _trust(tmp_path / "BobTrust.json", alice)

    bob_store = ConfigStore(
        tmp_path / "BobProfile" / "settings.json"
    )

    bob_store.save(
        AppConfig(
            device_name="Bob",
            shares=(
                ShareConfig(
                    share_id=SHARE,
                    peer_node_id=alice.node_id,
                    local_root=str(bob_root),
                    remote_host="127.0.0.1",
                    display_name="Test folder",
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

    local_authority = LeaseAuthority(
        tmp_path / "AliceProfile" / "fences.sqlite",
        clock=clock,
    )

    remote_authority = LeaseAuthority(
        tmp_path / "BobProfile" / "fences.sqlite",
        clock=clock,
    )

    lease_server = FencedLeaseService(
        bob,
        bob_trust,
        bob_store,
        remote_authority,
        bind_address="127.0.0.1",
        port=0,
    )

    upload_receiver = FencedTransferService(
        bob,
        bob_trust,
        bob_root,
        authority=remote_authority,
        share_id=SHARE,
        allowed_senders=(alice.node_id,),
        allow_overwrite=True,
        bind_address="127.0.0.1",
        listen_port=0,
    )

    read_server = TransferService(
        bob,
        bob_trust,
        bob_root,
        share_id=SHARE,
        allowed_senders=(),
        allowed_readers=(alice.node_id,),
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
        authority=local_authority,
        share_id=SHARE,
        allow_overwrite=True,
        bind_address="127.0.0.1",
        listen_port=0,
    )

    lease_client = FencedLeaseClient(
        alice,
        alice_trust,
    )

    services = (
        lease_server,
        upload_receiver,
        read_server,
    )

    started = []

    try:
        for service in services:
            service.start()
            started.append(service)

        def session(
            *,
            need_upload=True,
            need_download=True,
            ttl_seconds=30,
            renewal_interval_seconds=5,
        ):
            return FencedSyncSession(
                local_root=alice_root,
                share_id=SHARE,
                peer_node_id=bob.node_id,
                remote_host="127.0.0.1",
                remote_lease_port=lease_server.bound_port,
                remote_upload_port=upload_receiver.bound_port,
                remote_read_port=read_server.bound_port,
                lease_client=lease_client,
                local_authority=local_authority,
                upload_client=upload_client,
                download_client=download_client,
                need_upload=need_upload,
                need_download=need_download,
                ttl_seconds=ttl_seconds,
                renewal_interval_seconds=renewal_interval_seconds,
            )

        yield {
            "alice": alice,
            "bob": bob,
            "alice_root": alice_root,
            "bob_root": bob_root,
            "clock": clock,
            "local_authority": local_authority,
            "remote_authority": remote_authority,
            "bob_store": bob_store,
            "lease_client": lease_client,
            "read_server": read_server,
            "session": session,
        }

    finally:
        for service in reversed(started):
            service.stop()


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_one_session_completes_both_transfer_directions(peers):
    alice_content = b"Written by Alice" * 1024
    bob_content = b"Written by Bob" * 1024

    (
        peers["alice_root"] / "alice.txt"
    ).write_bytes(alice_content)

    (
        peers["bob_root"] / "bob.txt"
    ).write_bytes(bob_content)

    session = peers["session"]()

    with session:
        assert session.active

        remote_grant = session.remote_grant
        local_grant = session.local_grant

        assert remote_grant is not None
        assert local_grant is not None

        upload = session.upload("alice.txt")

        download = session.download(
            "bob.txt",
            expected_source_sha256=_digest(bob_content),
        )

        assert upload.completed
        assert download.completed

    assert not session.active

    assert (
        peers["bob_root"] / "alice.txt"
    ).read_bytes() == alice_content

    assert (
        peers["alice_root"] / "bob.txt"
    ).read_bytes() == bob_content

    with pytest.raises(FencedOut):
        peers["remote_authority"].assert_current(remote_grant)

    with pytest.raises(FencedOut):
        peers["local_authority"].assert_current(local_grant)

    assert session.cleanup_errors == []


def test_read_only_source_cannot_accept_legacy_upload(peers):
    payload = b"Must not publish through read listener"

    (peers["alice_root"] / "legacy.txt").write_bytes(payload)

    legacy = TransferService(
        peers["alice"],
        _trust(
            peers["alice_root"].parent / "legacy_trust.json",
            peers["bob"],
        ),
        peers["alice_root"],
        share_id=SHARE,
        bind_address="127.0.0.1",
        listen_port=0,
    )

    with pytest.raises(TransferError):
        legacy.send_file(
            "127.0.0.1",
            peers["read_server"].bound_port,
            peers["bob"].node_id,
            peers["alice_root"],
            "legacy.txt",
            share_id=SHARE,
        )

    assert not (
        peers["bob_root"] / "legacy.txt"
    ).exists()


def test_download_only_works_without_remote_write_permission(peers):
    content = b"Read-only sharing"

    (peers["bob_root"] / "read.txt").write_bytes(content)

    settings = peers["bob_store"].load()
    disabled_write = replace(
        settings.shares[0],
        grant_write=False,
    )

    peers["bob_store"].save(
        replace(settings, shares=(disabled_write,))
    )

    with peers["session"](
        need_upload=False,
        need_download=True,
    ) as session:
        assert session.remote_grant is None

        assert session.download(
            "read.txt",
            expected_source_sha256=_digest(content),
        ).completed

    assert (
        peers["alice_root"] / "read.txt"
    ).read_bytes() == content


def test_remote_lease_denial_releases_local_lease(peers):
    settings = peers["bob_store"].load()

    peers["bob_store"].save(
        replace(
            settings,
            shares=(
                replace(
                    settings.shares[0],
                    grant_write=False,
                ),
            ),
        )
    )

    with pytest.raises(LeaseChannelError):
        with peers["session"]():
            pytest.fail("Session should not have started")

    replacement = peers["local_authority"].acquire(
        SHARE,
        peers["alice"].node_id,
    )

    assert replacement.generation == 2

    peers["local_authority"].release(replacement)


def test_concurrent_session_ownership_is_refused(peers):
    with peers["session"]() as session:
        with pytest.raises(LeaseBusy):
            peers["local_authority"].acquire(
                SHARE,
                peers["bob"].node_id,
            )

        with pytest.raises(LeaseBusy):
            peers["remote_authority"].acquire(
                SHARE,
                peers["bob"].node_id,
            )

        assert session.local_grant is not None
        assert session.remote_grant is not None


def test_error_still_releases_both_authorities(peers):
    session = peers["session"]()

    with pytest.raises(ValueError, match="Simulated work failure"):
        with session:
            raise ValueError("Simulated work failure")

    assert not session.active

    next_local = peers["local_authority"].acquire(
        SHARE,
        peers["alice"].node_id,
    )

    next_remote = peers["remote_authority"].acquire(
        SHARE,
        peers["alice"].node_id,
    )

    assert next_local.generation == 2
    assert next_remote.generation == 2

    peers["local_authority"].release(next_local)
    peers["remote_authority"].release(next_remote)


def test_renewal_survives_original_expiration_time(peers):
    payload = b"Legitimate long transfer" * 4096

    (peers["alice_root"] / "slow.bin").write_bytes(payload)

    session = peers["session"](
        need_upload=True,
        need_download=False,
        ttl_seconds=1,
        renewal_interval_seconds=0.025,
    )

    with session:
        original = session.remote_grant

        assert original is not None
        assert original.expires_at == 1001.0

        peers["clock"].advance(0.7)

        deadline = time.monotonic() + 4

        while (
            session.remote_grant.expires_at <= 1001.0
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)

        assert session.remote_grant.expires_at > 1001.0

        # Move beyond the originally granted expiration.
        peers["clock"].advance(0.5)

        assert peers["clock"].now > original.expires_at

        assert session.upload("slow.bin").completed

    assert (
        peers["bob_root"] / "slow.bin"
    ).read_bytes() == payload


def test_no_transfers_outside_active_session(peers):
    session = peers["session"]()

    with pytest.raises(FencedSessionError):
        session.upload("file.txt")

    with pytest.raises(FencedSessionError):
        session.download(
            "file.txt",
            expected_source_sha256=_digest(b"test"),
        )

    with session:
        pass

    with pytest.raises(FencedSessionError):
        session.upload("file.txt")

    with pytest.raises(FencedSessionError):
        with session:
            pass
