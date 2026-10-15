
"""Hands-on encrypted transfer demo: current leases write; old ones cannot.

Run: python scripts/guarded_transfer_demo.py
All files are created in a temporary folder, not personal sync folders.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from uuid import uuid4

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


def main() -> None:
    with tempfile.TemporaryDirectory(
        prefix="syncbridge-guarded-transfer-"
    ) as temp:
        base = Path(temp)

        leader, follower = sorted(
            (
                DeviceIdentity.generate(),
                DeviceIdentity.generate(),
            ),
            key=lambda identity: identity.node_id,
        )

        leader_trust = TrustStore(
            base / "leader-trust.json"
        )
        follower_trust = TrustStore(
            base / "follower-trust.json"
        )

        leader_trust.add_verified(
            follower.public_key_hex,
            confirmed_fingerprint=follower.fingerprint,
            name="Peer",
        )
        follower_trust.add_verified(
            leader.public_key_hex,
            confirmed_fingerprint=leader.fingerprint,
            name="Coordinator",
        )

        leader_folder = base / "Leader"
        follower_folder = base / "Follower"

        leader_folder.mkdir()
        follower_folder.mkdir()

        (
            follower_folder / "report.txt"
        ).write_text(
            "This file requires current synchronization permission.\n",
            encoding="utf-8",
        )

        share = uuid4().hex

        authority = OperationLockService(
            leader,
            leader_trust,
            {share: follower.node_id},
            listen_port=0,
            lease_seconds=15,
        )

        validation = LeaseValidationService(
            authority,
            listen_port=0,
        )

        authority.start()

        try:
            validation.start()

            try:
                receiver_gate = WriteAdmissionGate(
                    share,
                    leader.node_id,
                    follower.node_id,
                    local_validation=validation,
                )

                sender_gate = WriteAdmissionGate(
                    share,
                    leader.node_id,
                    follower.node_id,
                    remote_validation=LeaseValidationClient(
                        follower,
                        follower_trust,
                    ),
                    authority_port=validation.bound_port,
                )

                receiver = GuardedTransferService(
                    leader,
                    leader_trust,
                    leader_folder,
                    share_id=share,
                    allowed_senders=[follower.node_id],
                    allowed_readers=[follower.node_id],
                    admission=receiver_gate,
                    listen_port=0,
                )

                sender = GuardedTransferService(
                    follower,
                    follower_trust,
                    follower_folder,
                    share_id=share,
                    allowed_senders=[leader.node_id],
                    allowed_readers=[leader.node_id],
                    admission=sender_gate,
                    listen_port=0,
                )

                receiver.start()
                sender.start()

                try:
                    client = OperationLockClient(
                        follower,
                        follower_trust,
                    )

                    grant = client.acquire(
                        "127.0.0.1",
                        authority.bound_port,
                        leader.node_id,
                        share,
                        "sync",
                    )

                    proof = LeaseProof(
                        share,
                        follower.node_id,
                        "sync",
                        grant.token,
                    )

                    print(
                        "\n=== GUARDED FILE TRANSFER DEMO ==="
                    )

                    result = sender.send_file(
                        "127.0.0.1",
                        receiver.bound_port,
                        leader.node_id,
                        follower_folder,
                        "report.txt",
                        share_id=share,
                        lease_proof=proof,
                    )

                    assert result.completed

                    assert (
                        leader_folder / "report.txt"
                    ).read_bytes() == (
                        follower_folder / "report.txt"
                    ).read_bytes()

                    print(
                        "PASS: A valid lease allowed a "
                        "real encrypted file upload."
                    )

                    client.release(
                        "127.0.0.1",
                        authority.bound_port,
                        leader.node_id,
                        share,
                        grant.token,
                    )

                    (
                        follower_folder / "new.txt"
                    ).write_text(
                        "should remain local"
                    )

                    try:
                        sender.send_file(
                            "127.0.0.1",
                            receiver.bound_port,
                            leader.node_id,
                            follower_folder,
                            "new.txt",
                            share_id=share,
                            lease_proof=proof,
                        )

                    except TransferError:
                        assert not (
                            leader_folder / "new.txt"
                        ).exists()

                        print(
                            "PASS: Released permission could "
                            "not publish a new file."
                        )

                    else:
                        raise RuntimeError(
                            "Expired permission unexpectedly succeeded"
                        )

                    legacy = TransferService(
                        follower,
                        follower_trust,
                        follower_folder,
                        share_id=share,
                    )

                    try:
                        legacy.send_file(
                            "127.0.0.1",
                            receiver.bound_port,
                            leader.node_id,
                            follower_folder,
                            "new.txt",
                            share_id=share,
                        )

                    except TransferError:
                        assert not (
                            leader_folder / "new.txt"
                        ).exists()

                        print(
                            "PASS: A legacy transfer "
                            "without proof was refused."
                        )

                    else:
                        raise RuntimeError(
                            "Unguarded transfer unexpectedly succeeded"
                        )

                    print(
                        "\nThis verifies an opt-in receiver, "
                        "not full runtime fencing."
                    )

                finally:
                    sender.stop()
                    receiver.stop()

            finally:
                validation.stop()

        finally:
            authority.stop()


if __name__ == "__main__":
    main()
