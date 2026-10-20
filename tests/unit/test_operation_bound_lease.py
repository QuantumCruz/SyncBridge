
"""Authenticated operation-bound fencing grants on real localhost services."""
from __future__ import annotations

from dataclasses import replace

import pytest

from syncbridge.network.fenced_lease_channel import (
    FencedLeaseClient,
    LeaseChannelError,
)
from syncbridge.network.lease_fencing import LeaseAuthority
from syncbridge.network.lease_validation import (
    LeaseProof,
    LeaseValidationClient,
    LeaseValidationService,
    WriteAdmissionGate,
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
from syncbridge.network.security import DeviceIdentity, TrustStore
from syncbridge.storage.config import AppConfig, ConfigStore, ShareConfig

SHARE = "a" * 32


def _trust(path, other):
    trust = TrustStore(path)
    trust.add_verified(
        other.public_key_hex,
        confirmed_fingerprint=other.fingerprint,
        name="Verified peer",
    )
    return trust


@pytest.fixture(
    params=["receiver_is_authority", "sender_is_authority"]
)
def paired(tmp_path, request):
    identities = sorted(
        (DeviceIdentity.generate(), DeviceIdentity.generate()),
        key=lambda device: device.node_id,
    )
    authority_id, second_id = identities
    if request.param == "receiver_is_authority":
        receiver, sender = authority_id, second_id
    else:
        sender, receiver = authority_id, second_id

    sender_trust = _trust(
        tmp_path / "sender-trust.json", receiver
    )
    receiver_trust = _trust(
        tmp_path / "receiver-trust.json", sender
    )
    authority = (
        receiver
        if receiver.node_id == authority_id.node_id
        else sender
    )
    authority_trust = (
        receiver_trust if authority is receiver else sender_trust
    )
    other = sender if authority is receiver else receiver

    folder = tmp_path / "Shared"
    folder.mkdir()
    settings = ConfigStore(
        tmp_path / "ReceiverProfile" / "settings.json"
    )
    settings.save(AppConfig(shares=(ShareConfig(
        share_id=SHARE,
        peer_node_id=sender.node_id,
        local_root=str(folder),
        display_name="Secure share",
        remote_host="127.0.0.1",
        enabled=True,
        grant_write=True,
        grant_read=True,
        grant_manifest=True,
        grant_agreement=True,
    ),)))

    op = OperationLockService(
        authority,
        authority_trust,
        {SHARE: other.node_id},
        bind_address="127.0.0.1",
        listen_port=0,
    )
    op.start()
    validation = LeaseValidationService(
        op,
        bind_address="127.0.0.1",
        listen_port=0,
    )
    validation.start()

    if authority is receiver:
        gate = WriteAdmissionGate(
            SHARE,
            authority.node_id,
            sender.node_id,
            local_validation=validation,
        )
    else:
        gate = WriteAdmissionGate(
            SHARE,
            authority.node_id,
            receiver.node_id,
            remote_validation=LeaseValidationClient(
                receiver, receiver_trust
            ),
            authority_host="127.0.0.1",
            authority_port=validation.bound_port,
        )

    fence_authority = LeaseAuthority(
        tmp_path / "ReceiverProfile" / "fencing.sqlite"
    )
    listener = OperationBoundFencedLeaseService(
        receiver,
        receiver_trust,
        settings,
        fence_authority,
        admission=gate,
        bind_address="127.0.0.1",
        port=0,
    )
    lease_client = OperationBoundFencedLeaseClient(
        sender, sender_trust
    )
    ordinary_client = FencedLeaseClient(
        sender, sender_trust
    )

    if sender is authority:
        coordinator = LeaseCoordinator(
            sender,
            receiver.node_id,
            SHARE,
            local_service=op,
        )
    else:
        coordinator = LeaseCoordinator(
            sender,
            receiver.node_id,
            SHARE,
            client=OperationLockClient(
                sender, sender_trust
            ),
            host="127.0.0.1",
            port=op.bound_port,
        )

    try:
        listener.start()
        yield {
            "sender": sender,
            "receiver": receiver,
            "listener": listener,
            "client": lease_client,
            "ordinary": ordinary_client,
            "coordinator": coordinator,
            "fence": fence_authority,
            "args": (
                "127.0.0.1",
                listener.bound_port,
                receiver.node_id,
            ),
        }
    finally:
        listener.stop()
        validation.stop()
        op.stop()


def test_ordinary_authenticated_client_cannot_acquire(paired):
    p = paired
    with p["coordinator"].hold("sync"):
        with pytest.raises(
            LeaseChannelError, match="rejected"
        ):
            p["ordinary"].acquire(
                *p["args"], SHARE
            )


def test_bound_client_refuses_acquire_without_proof(paired):
    with pytest.raises(
        LeaseChannelError, match="requires"
    ):
        paired["client"].acquire(
            *paired["args"], SHARE
        )


def test_forged_operation_token_is_denied(paired):
    p = paired
    fake = LeaseProof(
        SHARE,
        p["sender"].node_id,
        "sync",
        "f" * 32,
    )
    with p["client"].use_operation(fake):
        with pytest.raises(
            LeaseChannelError, match="rejected"
        ):
            p["client"].acquire(
                *p["args"], SHARE
            )


def test_valid_operation_issues_renewable_fence(paired):
    p = paired
    with p["coordinator"].hold("sync") as op:
        proof = LeaseProof(
            SHARE,
            p["sender"].node_id,
            "sync",
            op.token,
        )
        with p["client"].use_operation(proof):
            lease = p["client"].acquire(
                *p["args"], SHARE, ttl_seconds=20
            )
        p["listener"].require_current_bound(lease)
        renewed = p["client"].renew(
            *p["args"], lease, ttl_seconds=20
        )
        assert renewed.session_token == lease.session_token
        assert renewed.generation == lease.generation
        p["client"].release(
            *p["args"], renewed
        )

    assert p["listener"]._bindings == {}


def test_operation_loss_blocks_renewal_and_bound_check(paired):
    p = paired
    with p["coordinator"].hold("sync") as op:
        proof = LeaseProof(
            SHARE,
            p["sender"].node_id,
            "sync",
            op.token,
        )
        with p["client"].use_operation(proof):
            lease = p["client"].acquire(
                *p["args"], SHARE
            )

    with pytest.raises(
        LeaseChannelError, match="rejected"
    ):
        p["client"].renew(
            *p["args"], lease
        )

    with pytest.raises(Exception):
        p["listener"].require_current_bound(lease)

    p["client"].release(
        *p["args"], lease
    )


def test_new_operation_cannot_revive_previous_fencing_session(
    paired,
):
    p = paired
    with p["coordinator"].hold("sync") as op:
        proof = LeaseProof(
            SHARE,
            p["sender"].node_id,
            "sync",
            op.token,
        )
        with p["client"].use_operation(proof):
            lease = p["client"].acquire(
                *p["args"], SHARE
            )

    with p["coordinator"].hold("sync") as fresh:
        assert fresh.token != proof.token

        with pytest.raises(
            LeaseChannelError, match="rejected"
        ):
            p["client"].renew(
                *p["args"], lease
            )

        p["client"].release(
            *p["args"], lease
        )

        current = LeaseProof(
            SHARE,
            p["sender"].node_id,
            "sync",
            fresh.token,
        )
        with p["client"].use_operation(current):
            new = p["client"].acquire(
                *p["args"], SHARE
            )

        assert new.generation == lease.generation + 1
        p["client"].release(
            *p["args"], new
        )


def test_forged_fencing_token_cannot_be_released(paired):
    p = paired
    with p["coordinator"].hold("sync") as op:
        proof = LeaseProof(
            SHARE,
            p["sender"].node_id,
            "sync",
            op.token,
        )
        with p["client"].use_operation(proof):
            lease = p["client"].acquire(
                *p["args"], SHARE
            )

        forged = replace(
            lease, session_token="e" * 64
        )

        with pytest.raises(
            LeaseChannelError, match="rejected"
        ):
            p["ordinary"].release(
                *p["args"], forged
            )

        p["listener"].require_current_bound(lease)
        p["client"].release(
            *p["args"], lease
        )
