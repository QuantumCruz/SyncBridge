    
"""Opt-in lease-guarded encrypted transfer integration tests (real TCP/files)."""
from __future__ import annotations

import hashlib
from uuid import uuid4

import pytest

from syncbridge.network.guarded_transfer import GuardedTransferService
from syncbridge.network.lease_validation import (
    LeaseProof,
    LeaseValidationClient,
    LeaseValidationService,
    WriteAdmissionGate,
)
from syncbridge.network.operation_lock import (
    OperationLockClient,
    OperationLockService,
)
from syncbridge.network.security import DeviceIdentity, TrustStore
from syncbridge.network.transfer import TransferError, TransferService


@pytest.fixture
def peers(tmp_path):
    leader, follower = sorted(
        (
            DeviceIdentity.generate(),
            DeviceIdentity.generate(),
        ),
        key=lambda identity: identity.node_id,
    )

    lt = TrustStore(
        tmp_path / "leader-trust.json"
    )
    ft = TrustStore(
        tmp_path / "follower-trust.json"
    )

    lt.add_verified(
        follower.public_key_hex,
        confirmed_fingerprint=follower.fingerprint,
        name="Follower",
    )
    ft.add_verified(
        leader.public_key_hex,
        confirmed_fingerprint=leader.fingerprint,
        name="Leader",
    )

    share = uuid4().hex
    a = tmp_path / "leader-files"
    b = tmp_path / "follower-files"
    a.mkdir()
    b.mkdir()

    authority = OperationLockService(
        leader,
        lt,
        {share: follower.node_id},
        listen_port=0,
        lease_seconds=10.0,
        timeout=2.0,
    )

    validation = LeaseValidationService(
        authority,
        listen_port=0,
        timeout=2.0,
    )

    authority.start()
    validation.start()

    leader_gate = WriteAdmissionGate(
        share,
        leader.node_id,
        follower.node_id,
        local_validation=validation,
    )

    follower_gate = WriteAdmissionGate(
        share,
        leader.node_id,
        follower.node_id,
        remote_validation=LeaseValidationClient(
            follower,
            ft,
            timeout=2.0,
        ),
        authority_host="127.0.0.1",
        authority_port=validation.bound_port,
    )

    leader_transfers = GuardedTransferService(
        leader,
        lt,
        a,
        share_id=share,
        allowed_senders=[follower.node_id],
        allowed_readers=[follower.node_id],
        allow_overwrite=True,
        listen_port=0,
        admission=leader_gate,
    )

    follower_transfers = GuardedTransferService(
        follower,
        ft,
        b,
        share_id=share,
        allowed_senders=[leader.node_id],
        allowed_readers=[leader.node_id],
        allow_overwrite=True,
        listen_port=0,
        admission=follower_gate,
    )

    leader_transfers.start()
    follower_transfers.start()

    lease_client = OperationLockClient(
        follower,
        ft,
        timeout=2.0,
    )

    try:
        yield {
            "leader": leader,
            "follower": follower,
            "share": share,
            "a": a,
            "b": b,
            "authority": authority,
            "validation": validation,
            "lease_client": lease_client,
            "leader_transfers": leader_transfers,
            "follower_transfers": follower_transfers,
            "lt": lt,
            "ft": ft,
        }

    finally:
        follower_transfers.stop()
        leader_transfers.stop()
        validation.stop()
        authority.stop()


def follower_lease(d):
    grant = d["lease_client"].acquire(
        "127.0.0.1",
        d["authority"].bound_port,
        d["leader"].node_id,
        d["share"],
        "sync",
    )

    return LeaseProof(
        d["share"],
        d["follower"].node_id,
        "sync",
        grant.token,
    )


def leader_lease(d):
    grant = d["authority"].acquire_local(
        d["share"],
        "sync",
    )

    return LeaseProof(
        d["share"],
        d["leader"].node_id,
        "sync",
        grant.token,
    )


def test_authorized_push_publishes_real_file(peers):
    d = peers

    (d["b"] / "hello.txt").write_bytes(
        b"hello guarded transfer"
    )

    proof = follower_lease(d)

    try:
        result = d["follower_transfers"].send_file(
            "127.0.0.1",
            d["leader_transfers"].bound_port,
            d["leader"].node_id,
            d["b"],
            "hello.txt",
            share_id=d["share"],
            lease_proof=proof,
        )

        assert result.completed
        assert (
            d["a"] / "hello.txt"
        ).read_bytes() == b"hello guarded transfer"

    finally:
        d["lease_client"].release(
            "127.0.0.1",
            d["authority"].bound_port,
            d["leader"].node_id,
            d["share"],
            proof.token,
        )


def test_authorized_pull_publishes_real_file(peers):
    d = peers

    (d["a"] / "remote.txt").write_bytes(
        b"pulled over encrypted TCP"
    )

    proof = follower_lease(d)

    try:
        result = d["follower_transfers"].fetch_file(
            "127.0.0.1",
            d["leader_transfers"].bound_port,
            d["leader"].node_id,
            d["share"],
            "remote.txt",
            lease_proof=proof,
        )

        assert result.completed
        assert (
            d["b"] / "remote.txt"
        ).read_bytes() == b"pulled over encrypted TCP"

    finally:
        d["lease_client"].release(
            "127.0.0.1",
            d["authority"].bound_port,
            d["leader"].node_id,
            d["share"],
            proof.token,
        )


def test_authority_owner_can_push_to_follower(peers):
    d = peers

    (d["a"] / "authority.txt").write_bytes(
        b"leader initiated"
    )

    proof = leader_lease(d)

    try:
        result = d["leader_transfers"].send_file(
            "127.0.0.1",
            d["follower_transfers"].bound_port,
            d["follower"].node_id,
            d["a"],
            "authority.txt",
            share_id=d["share"],
            lease_proof=proof,
        )

        assert result.completed
        assert (
            d["b"] / "authority.txt"
        ).read_bytes() == b"leader initiated"

    finally:
        d["authority"].release_local(
            d["share"],
            proof.token,
        )


def test_expired_or_released_proof_cannot_create_file(peers):
    d = peers

    (d["b"] / "blocked.txt").write_bytes(
        b"should not appear"
    )

    proof = follower_lease(d)

    d["lease_client"].release(
        "127.0.0.1",
        d["authority"].bound_port,
        d["leader"].node_id,
        d["share"],
        proof.token,
    )

    with pytest.raises(
        TransferError,
        match="SB-OPS-409",
    ):
        d["follower_transfers"].send_file(
            "127.0.0.1",
            d["leader_transfers"].bound_port,
            d["leader"].node_id,
            d["b"],
            "blocked.txt",
            share_id=d["share"],
            lease_proof=proof,
        )

    assert not (
        d["a"] / "blocked.txt"
    ).exists()


def test_old_proof_cannot_write_after_replacement(peers):
    d = peers

    (d["b"] / "old.txt").write_bytes(
        b"not authorized"
    )

    old = follower_lease(d)

    d["lease_client"].release(
        "127.0.0.1",
        d["authority"].bound_port,
        d["leader"].node_id,
        d["share"],
        old.token,
    )

    current = follower_lease(d)

    try:
        with pytest.raises(
            TransferError,
            match="SB-OPS-409",
        ):
            d["follower_transfers"].send_file(
                "127.0.0.1",
                d["leader_transfers"].bound_port,
                d["leader"].node_id,
                d["b"],
                "old.txt",
                share_id=d["share"],
                lease_proof=old,
            )

        assert not (
            d["a"] / "old.txt"
        ).exists()

    finally:
        d["lease_client"].release(
            "127.0.0.1",
            d["authority"].bound_port,
            d["leader"].node_id,
            d["share"],
            current.token,
        )


def test_legacy_client_without_proof_rejected(peers):
    d = peers

    (d["b"] / "legacy.txt").write_bytes(
        b"legacy payload"
    )

    legacy = TransferService(
        d["follower"],
        d["ft"],
        d["b"],
        share_id=d["share"],
    )

    with pytest.raises(TransferError):
        legacy.send_file(
            "127.0.0.1",
            d["leader_transfers"].bound_port,
            d["leader"].node_id,
            d["b"],
            "legacy.txt",
            share_id=d["share"],
        )

    assert not (
        d["a"] / "legacy.txt"
    ).exists()


def test_cannot_write_with_wrong_share_or_wrong_owner(peers):
    d = peers

    (d["b"] / "file.txt").write_bytes(
        b"data"
    )

    proof = follower_lease(d)

    try:
        forged = LeaseProof(
            d["share"],
            d["leader"].node_id,
            "sync",
            proof.token,
        )

        with pytest.raises(
            TransferError,
            match="SB-OPS-403",
        ):
            d["follower_transfers"].send_file(
                "127.0.0.1",
                d["leader_transfers"].bound_port,
                d["leader"].node_id,
                d["b"],
                "file.txt",
                share_id=d["share"],
                lease_proof=forged,
            )

        with pytest.raises(
            TransferError,
            match="SB-OPS-403",
        ):
            d["follower_transfers"].send_file(
                "127.0.0.1",
                d["leader_transfers"].bound_port,
                d["leader"].node_id,
                d["b"],
                "file.txt",
                share_id=uuid4().hex,
                lease_proof=proof,
            )

    finally:
        d["lease_client"].release(
            "127.0.0.1",
            d["authority"].bound_port,
            d["leader"].node_id,
            d["share"],
            proof.token,
        )

    assert not (
        d["a"] / "file.txt"
    ).exists()


def test_lease_revoked_between_staging_and_publish_refused(
    peers,
    monkeypatch,
):
    d = peers

    (d["b"] / "late.txt").write_bytes(
        b"A" * (256 * 1024)
    )

    proof = follower_lease(d)
    receiver = d["leader_transfers"]

    original = receiver._precondition
    calls = []

    def check_then_revoke(*args, **kwargs):
        result = original(*args, **kwargs)
        calls.append(True)

        if len(calls) == 1:
            d["lease_client"].release(
                "127.0.0.1",
                d["authority"].bound_port,
                d["leader"].node_id,
                d["share"],
                proof.token,
            )

        return result

    monkeypatch.setattr(
        receiver,
        "_precondition",
        check_then_revoke,
    )

    with pytest.raises(
        TransferError,
        match="SB-OPS-409",
    ):
        d["follower_transfers"].send_file(
            "127.0.0.1",
            receiver.bound_port,
            d["leader"].node_id,
            d["b"],
            "late.txt",
            share_id=d["share"],
            lease_proof=proof,
        )

    assert calls
    assert not (
        d["a"] / "late.txt"
    ).exists()


def test_conditional_overwrite_uses_current_lease(peers):
    d = peers

    (d["a"] / "document.txt").write_bytes(
        b"original"
    )
    (d["b"] / "document.txt").write_bytes(
        b"revised"
    )

    proof = follower_lease(d)

    try:
        result = d["follower_transfers"].send_file(
            "127.0.0.1",
            d["leader_transfers"].bound_port,
            d["leader"].node_id,
            d["b"],
            "document.txt",
            share_id=d["share"],
            lease_proof=proof,
            expected_destination_sha256=(
                hashlib.sha256(
                    b"original"
                ).hexdigest()
            ),
        )

        assert result.completed
        assert (
            d["a"] / "document.txt"
        ).read_bytes() == b"revised"

    finally:
        d["lease_client"].release(
            "127.0.0.1",
            d["authority"].bound_port,
            d["leader"].node_id,
            d["share"],
            proof.token,
        )


def test_released_lease_cannot_pull_into_local_folder(peers):
    d = peers

    (d["a"] / "unavailable.txt").write_bytes(
        b"protected"
    )

    proof = follower_lease(d)

    d["lease_client"].release(
        "127.0.0.1",
        d["authority"].bound_port,
        d["leader"].node_id,
        d["share"],
        proof.token,
    )

    with pytest.raises(
        TransferError,
        match="SB-OPS-409",
    ):
        d["follower_transfers"].fetch_file(
            "127.0.0.1",
            d["leader_transfers"].bound_port,
            d["leader"].node_id,
            d["share"],
            "unavailable.txt",
            lease_proof=proof,
        )

    assert not (
        d["b"] / "unavailable.txt"
    ).exists()
