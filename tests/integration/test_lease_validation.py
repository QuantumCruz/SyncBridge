
"""Real encrypted lease-validation tests for Phase 20C.

Validation is deliberately read-only: these tests do not write shared files.
They establish the proof-verification boundary, NOT transfer fencing.
"""
from __future__ import annotations

import time
from uuid import uuid4

import pytest

from syncbridge.network.lease_validation import (
    LeaseProof,
    LeaseProofError,
    LeaseProofRejected,
    LeaseValidationClient,
    LeaseValidationService,
)
from syncbridge.network.operation_lock import (
    OperationLockClient,
    OperationLockService,
)
from syncbridge.network.security import DeviceIdentity, TrustStore


@pytest.fixture
def devices(tmp_path):
    identities = sorted(
        (DeviceIdentity.generate(), DeviceIdentity.generate()),
        key=lambda item: item.node_id,
    )
    leader, follower = identities
    lt = TrustStore(tmp_path / "leader-trust.json")
    ft = TrustStore(tmp_path / "follower-trust.json")
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
    authority = OperationLockService(
        leader, lt, {share: follower.node_id},
        bind_address="127.0.0.1", listen_port=0,
        lease_seconds=2.4, timeout=2.0,
    )
    validation = LeaseValidationService(
        authority, bind_address="127.0.0.1", listen_port=0, timeout=2.0,
    )
    remote_leases = OperationLockClient(follower, ft, timeout=2.0)
    remote_validation = LeaseValidationClient(follower, ft, timeout=2.0)
    authority.start()
    validation.start()
    try:
        yield {
            "leader": leader, "follower": follower,
            "lt": lt, "ft": ft, "share": share,
            "authority": authority, "validation": validation,
            "remote_leases": remote_leases,
            "remote_validation": remote_validation,
        }
    finally:
        validation.stop()
        authority.stop()


def query(d, proof):
    return d["remote_validation"].validate(
        "127.0.0.1", d["validation"].bound_port,
        d["leader"].node_id, proof,
    )


def test_remote_receiver_verifies_authority_local_lease(devices):
    d = devices
    grant = d["authority"].acquire_local(d["share"], "sync")
    proof = LeaseProof(d["share"], d["leader"].node_id, "sync", grant.token)
    try:
        assert d["validation"].validate_local(proof)
        assert query(d, proof)
    finally:
        d["authority"].release_local(d["share"], grant.token)


def test_remote_owner_proof_is_checked_against_current_token(devices):
    d = devices
    grant = d["remote_leases"].acquire(
        "127.0.0.1", d["authority"].bound_port,
        d["leader"].node_id, d["share"], "sync",
    )
    proof = LeaseProof(d["share"], d["follower"].node_id, "sync", grant.token)
    try:
        assert query(d, proof)
    finally:
        d["remote_leases"].release(
            "127.0.0.1", d["authority"].bound_port,
            d["leader"].node_id, d["share"], grant.token,
        )
    assert not query(d, proof)


def test_wrong_secret_is_rejected(devices):
    d = devices
    grant = d["authority"].acquire_local(d["share"], "sync")
    try:
        wrong = LeaseProof(d["share"], d["leader"].node_id, "sync", uuid4().hex)
        assert not query(d, wrong)
        with pytest.raises(LeaseProofRejected, match="SB-OPS-409"):
            d["remote_validation"].require_current(
                "127.0.0.1", d["validation"].bound_port,
                d["leader"].node_id, wrong,
            )
    finally:
        d["authority"].release_local(d["share"], grant.token)


def test_wrong_owner_is_rejected_even_with_right_token(devices):
    d = devices
    grant = d["authority"].acquire_local(d["share"], "sync")
    try:
        forged = LeaseProof(d["share"], d["follower"].node_id, "sync", grant.token)
        assert not query(d, forged)
    finally:
        d["authority"].release_local(d["share"], grant.token)


def test_wrong_operation_is_rejected_even_with_right_token(devices):
    d = devices
    grant = d["authority"].acquire_local(d["share"], "sync")
    try:
        wrong = LeaseProof(d["share"], d["leader"].node_id, "deletion", grant.token)
        assert not query(d, wrong)
    finally:
        d["authority"].release_local(d["share"], grant.token)


def test_wrong_share_is_rejected_even_with_right_token(devices):
    d = devices
    grant = d["authority"].acquire_local(d["share"], "sync")
    try:
        wrong = LeaseProof(uuid4().hex, d["leader"].node_id, "sync", grant.token)
        with pytest.raises(LeaseProofError, match="SB-OPS-403"):
            query(d, wrong)
    finally:
        d["authority"].release_local(d["share"], grant.token)


def test_expiry_invalidates_proof(devices):
    d = devices
    grant = d["authority"].acquire_local(d["share"], "sync")
    proof = LeaseProof(d["share"], d["leader"].node_id, "sync", grant.token)
    assert query(d, proof)
    time.sleep(2.55)
    assert not query(d, proof)


def test_old_proof_stays_invalid_after_new_grant(devices):
    d = devices
    first = d["authority"].acquire_local(d["share"], "sync")
    old = LeaseProof(d["share"], d["leader"].node_id, "sync", first.token)
    d["authority"].release_local(d["share"], first.token)
    second = d["authority"].acquire_local(d["share"], "sync")
    try:
        current = LeaseProof(d["share"], d["leader"].node_id, "sync", second.token)
        assert not query(d, old)
        assert query(d, current)
    finally:
        d["authority"].release_local(d["share"], second.token)


def test_stopped_authority_fails_closed(devices):
    d = devices
    grant = d["authority"].acquire_local(d["share"], "sync")
    proof = LeaseProof(d["share"], d["leader"].node_id, "sync", grant.token)
    assert query(d, proof)
    d["authority"].stop()
    assert not d["validation"].validate_local(proof)
    assert not query(d, proof)


def test_stopped_validation_listener_fails_closed(devices):
    d = devices
    grant = d["authority"].acquire_local(d["share"], "sync")
    proof = LeaseProof(d["share"], d["leader"].node_id, "sync", grant.token)
    port = d["validation"].bound_port
    d["validation"].stop()
    try:
        with pytest.raises(LeaseProofError, match="SB-OPS-503"):
            d["remote_validation"].validate(
                "127.0.0.1", port, d["leader"].node_id, proof,
            )
    finally:
        d["authority"].release_local(d["share"], grant.token)


def test_restarting_authority_rejects_old_token(devices):
    d = devices
    grant = d["authority"].acquire_local(d["share"], "sync")
    proof = LeaseProof(d["share"], d["leader"].node_id, "sync", grant.token)
    assert query(d, proof)
    d["validation"].stop()
    d["authority"].stop()
    assert not d["validation"].validate_local(proof)
    d["authority"].start()
    # Do not let a validator accept an old in-memory lease after restart.
    with pytest.raises(RuntimeError, match="before granting any leases"):
        d["validation"].start()
    assert not d["validation"].validate_local(proof)


def test_unpaired_receiver_cannot_query_validation(devices):
    d = devices
    grant = d["authority"].acquire_local(d["share"], "sync")
    proof = LeaseProof(d["share"], d["leader"].node_id, "sync", grant.token)
    try:
        d["ft"].remove(d["leader"].node_id)
        with pytest.raises(Exception):
            query(d, proof)
    finally:
        d["authority"].release_local(d["share"], grant.token)


def test_malformed_proofs_are_rejected_locally(devices):
    d = devices
    for args in (
        ("bad", d["leader"].node_id, "sync", uuid4().hex),
        (d["share"], "bad", "sync", uuid4().hex),
        (d["share"], d["leader"].node_id, "destroy", uuid4().hex),
        (d["share"], d["leader"].node_id, "sync", "bad"),
    ):
        with pytest.raises(ValueError):
            LeaseProof(*args)


def test_service_start_requires_active_authority(devices):
    d = devices
    d["validation"].stop()
    d["authority"].stop()
    with pytest.raises(RuntimeError, match="authority first"):
        d["validation"].start()


def test_admission_gate_allows_only_authenticated_current_writer(devices):
    from syncbridge.network.lease_validation import WriteAdmissionGate

    d = devices
    grant = d["authority"].acquire_local(d["share"], "sync")
    proof = LeaseProof(d["share"], d["leader"].node_id, "sync", grant.token)
    gate = WriteAdmissionGate(
        d["share"], d["leader"].node_id, d["follower"].node_id,
        remote_validation=d["remote_validation"],
        authority_port=d["validation"].bound_port,
    )
    try:
        gate.require(proof, authenticated_owner_id=d["leader"].node_id)
        with pytest.raises(LeaseProofRejected, match="SB-OPS-403"):
            gate.require(proof, authenticated_owner_id=d["follower"].node_id)
    finally:
        d["authority"].release_local(d["share"], grant.token)

    with pytest.raises(LeaseProofRejected, match="SB-OPS-409"):
        gate.require(proof, authenticated_owner_id=d["leader"].node_id)


def test_local_authority_admission_check(devices):
    from syncbridge.network.lease_validation import WriteAdmissionGate

    d = devices
    remote_grant = d["remote_leases"].acquire(
        "127.0.0.1", d["authority"].bound_port,
        d["leader"].node_id, d["share"], "sync",
    )
    proof = LeaseProof(d["share"], d["follower"].node_id, "sync", remote_grant.token)
    gate = WriteAdmissionGate(
        d["share"], d["leader"].node_id, d["follower"].node_id,
        local_validation=d["validation"],
    )
    try:
        gate.require(proof, authenticated_owner_id=d["follower"].node_id)
    finally:
        d["remote_leases"].release(
            "127.0.0.1", d["authority"].bound_port,
            d["leader"].node_id, d["share"], remote_grant.token,
        )
    with pytest.raises(LeaseProofRejected, match="SB-OPS-409"):
        gate.require(proof, authenticated_owner_id=d["follower"].node_id)


def test_admission_gate_requires_correct_roles(devices):
    from syncbridge.network.lease_validation import WriteAdmissionGate

    d = devices
    with pytest.raises(ValueError, match="exactly one"):
        WriteAdmissionGate(d["share"], d["leader"].node_id, d["follower"].node_id)
    with pytest.raises(ValueError, match="exactly one"):
        WriteAdmissionGate(
            d["share"], d["leader"].node_id, d["follower"].node_id,
            local_validation=d["validation"],
            remote_validation=d["remote_validation"],
        )
    with pytest.raises(ValueError, match="different authority"):
        WriteAdmissionGate(
            d["share"], d["follower"].node_id, d["leader"].node_id,
            local_validation=d["validation"],
        )
