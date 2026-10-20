
"""Publication-bound elected-operation checks using real localhost peers.

Each test runs with both possible elected-authority arrangements.
All transferred files, settings and SQLite databases are disposable.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from syncbridge.network.fenced_publish import (
    PublishConflict,
)
from syncbridge.network.fenced_transfer import (
    FencedTransferClient,
)
from syncbridge.network.lease_fencing import (
    LeaseAuthority,
)
from syncbridge.network.lease_validation import (
    LeaseProof,
    LeaseValidationClient,
    LeaseValidationService,
    WriteAdmissionGate,
)
from syncbridge.network.operation_bound_duplex import (
    OperationBoundDuplexService,
)
from syncbridge.network.operation_bound_lease import (
    OperationBoundFencedLeaseClient,
    OperationBoundFencedLeaseService,
)
from syncbridge.network.operation_lock import (
    LeaseCoordinator,
    OperationLockClient,
    OperationLockService,
)
from syncbridge.network.security import (
    DeviceIdentity,
    TrustStore,
)
from syncbridge.network.transfer import (
    TransferError,
    TransferService,
)
from syncbridge.storage.config import (
    AppConfig,
    ConfigStore,
    ShareConfig,
)


SHARE = "a" * 32


def _sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _trust(path: Path, other):
    store = TrustStore(path)

    store.add_verified(
        other.public_key_hex,
        confirmed_fingerprint=other.fingerprint,
        name="Trusted peer",
    )

    return store


@pytest.fixture(
    params=[
        "receiver_is_authority",
        "sender_is_authority",
    ]
)
def peers(tmp_path, request):
    devices = sorted(
        (
            DeviceIdentity.generate(),
            DeviceIdentity.generate(),
        ),
        key=lambda device: device.node_id,
    )

    low, high = devices

    if request.param == "receiver_is_authority":
        receiver_id, sender_id = low, high
    else:
        sender_id, receiver_id = low, high

    sender_trust = _trust(
        tmp_path / "sender-trust.json",
        receiver_id,
    )

    receiver_trust = _trust(
        tmp_path / "receiver-trust.json",
        sender_id,
    )

    sender_root = tmp_path / "SenderFiles"
    receiver_root = tmp_path / "ReceiverFiles"

    sender_root.mkdir()
    receiver_root.mkdir()

    settings = ConfigStore(
        tmp_path / "ReceiverProfile" / "settings.json"
    )

    settings.save(
        AppConfig(
            shares=(
                ShareConfig(
                    share_id=SHARE,
                    peer_node_id=sender_id.node_id,
                    local_root=str(receiver_root),
                    remote_host="127.0.0.1",
                    display_name="Test share",
                    enabled=True,
                    grant_write=True,
                    grant_read=True,
                    grant_manifest=True,
                    grant_agreement=True,
                ),
            ),
        )
    )

    elected_id = low
    elected_trust = (
        receiver_trust
        if elected_id is receiver_id
        else sender_trust
    )
    other_id = (
        sender_id
        if elected_id is receiver_id
        else receiver_id
    )

    operation_authority = OperationLockService(
        elected_id,
        elected_trust,
        {SHARE: other_id.node_id},
        bind_address="127.0.0.1",
        listen_port=0,
    )

    operation_authority.start()
    started = []

    try:
        validation = LeaseValidationService(
            operation_authority,
            bind_address="127.0.0.1",
            listen_port=0,
        )

        validation.start()
        started.append(validation)

        if elected_id is receiver_id:
            admission = WriteAdmissionGate(
                SHARE,
                elected_id.node_id,
                sender_id.node_id,
                local_validation=validation,
            )

        else:
            admission = WriteAdmissionGate(
                SHARE,
                elected_id.node_id,
                receiver_id.node_id,
                remote_validation=LeaseValidationClient(
                    receiver_id,
                    receiver_trust,
                ),
                authority_host="127.0.0.1",
                authority_port=validation.bound_port,
            )

        fence_authority = LeaseAuthority(
            tmp_path / "ReceiverProfile" / "fences.sqlite"
        )

        lease_server = OperationBoundFencedLeaseService(
            receiver_id,
            receiver_trust,
            settings,
            fence_authority,
            admission=admission,
            bind_address="127.0.0.1",
            port=0,
        )

        duplex = OperationBoundDuplexService(
            receiver_id,
            receiver_trust,
            receiver_root,
            share_id=SHARE,
            authority=fence_authority,
            operation_leases=lease_server,
            allowed_senders=(sender_id.node_id,),
            allowed_readers=(sender_id.node_id,),
            allow_overwrite=True,
            bind_address="127.0.0.1",
            listen_port=0,
        )

        sender = FencedTransferClient(
            sender_id,
            sender_trust,
            sender_root,
            share_id=SHARE,
            bind_address="127.0.0.1",
            listen_port=0,
        )

        lease_client = OperationBoundFencedLeaseClient(
            sender_id,
            sender_trust,
        )

        if elected_id is sender_id:
            coordinator = LeaseCoordinator(
                sender_id,
                receiver_id.node_id,
                SHARE,
                local_service=operation_authority,
            )
        else:
            coordinator = LeaseCoordinator(
                sender_id,
                receiver_id.node_id,
                SHARE,
                client=OperationLockClient(
                    sender_id,
                    sender_trust,
                ),
                host="127.0.0.1",
                port=operation_authority.bound_port,
            )

        lease_server.start()
        started.append(lease_server)

        duplex.start()
        started.append(duplex)

        yield {
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "sender_trust": sender_trust,
            "sender_root": sender_root,
            "receiver_root": receiver_root,
            "coordinator": coordinator,
            "fence_authority": fence_authority,
            "lease_server": lease_server,
            "lease_client": lease_client,
            "duplex": duplex,
            "sender": sender,
        }

    finally:
        for service in reversed(started):
            service.stop()

        operation_authority.stop()


def _acquire(peers, proof):
    with peers["lease_client"].use_operation(proof):
        return peers["lease_client"].acquire(
            "127.0.0.1",
            peers["lease_server"].bound_port,
            peers["receiver_id"].node_id,
            SHARE,
        )


def _release(peers, lease):
    peers["lease_client"].release(
        "127.0.0.1",
        peers["lease_server"].bound_port,
        peers["receiver_id"].node_id,
        lease,
    )


def _send(peers, lease, path):
    return peers["sender"].send_fenced_file(
        "127.0.0.1",
        peers["duplex"].bound_port,
        peers["receiver_id"].node_id,
        peers["sender_root"],
        path,
        lease=lease,
    )


def _proof(peers, guard):
    return LeaseProof(
        SHARE,
        peers["sender_id"].node_id,
        "sync",
        guard.token,
    )


def test_valid_operation_publishes_verified_encrypted_upload(peers):
    content = b"Operation-authorized encrypted upload" * 2048

    (
        peers["sender_root"] / "approved.bin"
    ).write_bytes(content)

    with peers["coordinator"].hold("sync") as guard:
        lease = _acquire(
            peers,
            _proof(peers, guard),
        )

        result = _send(
            peers,
            lease,
            "approved.bin",
        )

        assert result.completed
        assert result.sha256 == _sha(content)

        _release(peers, lease)

    assert (
        peers["receiver_root"] / "approved.bin"
    ).read_bytes() == content


def test_lost_operation_blocks_final_publication(peers):
    content = b"Never publish after losing operation authority"

    lease = None

    with peers["coordinator"].hold("sync") as guard:
        lease = _acquire(
            peers,
            _proof(peers, guard),
        )

    # The receiver's fencing token still exists, but the elected
    # synchronization operation has already ended.
    peers["fence_authority"].assert_current(lease)

    staged_name = "b" * 64 + ".part"
    staged = peers["duplex"]._staging / staged_name
    staged.write_bytes(content)

    with pytest.raises(
        PublishConflict,
        match="no longer authorized",
    ):
        peers["duplex"].publisher.publish(
            lease,
            authenticated_peer_id=peers["sender_id"].node_id,
            relative_path="blocked.bin",
            staging_name=staged_name,
            expected_size=len(content),
            expected_sha256=_sha(content),
            expected_destination_sha256=None,
        )

    assert not (
        peers["receiver_root"] / "blocked.bin"
    ).exists()

    assert staged.read_bytes() == content

    _release(peers, lease)


def test_lost_operation_refuses_encrypted_upload(peers):
    content = b"Already revoked operation"
    (
        peers["sender_root"] / "expired.bin"
    ).write_bytes(content)

    with peers["coordinator"].hold("sync") as guard:
        lease = _acquire(
            peers,
            _proof(peers, guard),
        )

    with pytest.raises(TransferError):
        _send(
            peers,
            lease,
            "expired.bin",
        )

    assert not (
        peers["receiver_root"] / "expired.bin"
    ).exists()

    _release(peers, lease)


def test_legacy_write_still_cannot_bypass_receiver(peers):
    content = b"Unfenced offer"
    (
        peers["sender_root"] / "legacy.bin"
    ).write_bytes(content)

    legacy = TransferService(
        peers["sender_id"],
        peers["sender_trust"],
        peers["sender_root"],
        share_id=SHARE,
        bind_address="127.0.0.1",
        listen_port=0,
    )

    with pytest.raises(TransferError):
        legacy.send_file(
            "127.0.0.1",
            peers["duplex"].bound_port,
            peers["receiver_id"].node_id,
            peers["sender_root"],
            "legacy.bin",
            share_id=SHARE,
        )

    assert not (
        peers["receiver_root"] / "legacy.bin"
    ).exists()


def test_listener_restart_invalidates_old_operation_binding(peers):
    content = b"Not authorized across listener restart"

    with peers["coordinator"].hold("sync") as guard:
        lease = _acquire(
            peers,
            _proof(peers, guard),
        )

        peers["lease_server"].stop()
        peers["lease_server"].start()

        # The SQLite fencing grant may remain current, but the
        # previous listener's in-memory operation binding cannot
        # authorize publication after restart.
        peers["fence_authority"].assert_current(lease)

        with pytest.raises(Exception):
            peers["lease_server"].require_operation_bound(
                lease
            )

        staged_name = "c" * 64 + ".part"
        staged = peers["duplex"]._staging / staged_name
        staged.write_bytes(content)

        with pytest.raises(PublishConflict):
            peers["duplex"].publisher.publish(
                lease,
                authenticated_peer_id=peers["sender_id"].node_id,
                relative_path="restart.bin",
                staging_name=staged_name,
                expected_size=len(content),
                expected_sha256=_sha(content),
                expected_destination_sha256=None,
            )

    assert not (
        peers["receiver_root"] / "restart.bin"
    ).exists()

    _release(peers, lease)
