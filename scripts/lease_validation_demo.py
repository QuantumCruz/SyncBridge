
"""Hands-on Phase 20C: prove that expired/replaced write permissions fail.

Run: python scripts/lease_validation_demo.py

Uses real authenticated encrypted localhost TCP channels and temporary
identities. Does NOT change synced files or protect legacy receivers yet.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from uuid import uuid4

from syncbridge.network.lease_validation import (
    LeaseProof,
    LeaseValidationClient,
    LeaseValidationService,
    WriteAdmissionGate,
    LeaseProofRejected,
)
from syncbridge.network.operation_lock import OperationLockService
from syncbridge.network.security import DeviceIdentity, TrustStore


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="syncbridge-fence-demo-") as tmp:
        location = Path(tmp)
        left, right = sorted(
            (DeviceIdentity.generate(), DeviceIdentity.generate()),
            key=lambda item: item.node_id,
        )
        left_trust = TrustStore(location / "left-trust.json")
        right_trust = TrustStore(location / "right-trust.json")
        left_trust.add_verified(
            right.public_key_hex,
            confirmed_fingerprint=right.fingerprint,
            name="Peer",
        )
        right_trust.add_verified(
            left.public_key_hex,
            confirmed_fingerprint=left.fingerprint,
            name="Authority",
        )
        share = uuid4().hex
        authority = OperationLockService(
            left, left_trust, {share: right.node_id},
            bind_address="127.0.0.1", listen_port=0,
            lease_seconds=10,
        )
        validation = LeaseValidationService(
            authority, bind_address="127.0.0.1", listen_port=0,
        )
        authority.start()
        try:
            validation.start()
            try:
                remote = LeaseValidationClient(right, right_trust)
                gate = WriteAdmissionGate(
                    share, left.node_id, right.node_id,
                    remote_validation=remote,
                    authority_host="127.0.0.1",
                    authority_port=validation.bound_port,
                )
                print("\n=== SYNCBRIDGE LEASE VERIFICATION DEMO ===")
                print("A real encrypted channel is used for each check.")
                print("No synchronized files are modified.\n")

                first = authority.acquire_local(share, "sync")
                old = LeaseProof(share, left.node_id, "sync", first.token)
                print("1. Alice (authority) receives a sync lease.")
                gate.require(old, authenticated_owner_id=left.node_id)
                print("   PASS: Bob can verify Alice's valid permission.")

                authority.release_local(share, first.token)
                print("2. Alice releases that permission.")
                try:
                    gate.require(old, authenticated_owner_id=left.node_id)
                except LeaseProofRejected:
                    print("   PASS: Bob rejects the old permission. [SB-OPS-409]")
                else:
                    raise RuntimeError("Old permission was unexpectedly accepted")

                second = authority.acquire_local(share, "sync")
                current = LeaseProof(share, left.node_id, "sync", second.token)
                print("3. Alice receives a different lease.")
                gate.require(current, authenticated_owner_id=left.node_id)
                print("   PASS: Bob accepts the CURRENT token.")
                try:
                    gate.require(old, authenticated_owner_id=left.node_id)
                except LeaseProofRejected:
                    print("   PASS: Bob still rejects the replaced token.")
                else:
                    raise RuntimeError("Replaced permission was unexpectedly accepted")
                authority.release_local(share, second.token)

                print("\nVerification service works. Receiver integration is still required.")
            finally:
                validation.stop()
        finally:
            authority.stop()


if __name__ == "__main__":
    main()
