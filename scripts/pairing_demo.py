
"""Two-user pairing protocol demo on localhost with TEMPORARY identities.

This demonstration supplies consent programmatically ONLY because both test
identities are generated locally, under one developer's direct control. The
real GUI MUST ask two independent people to compare the code out-of-band.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from syncbridge.network.pairing import PairingClient, PairingService
from syncbridge.network.security import TrustStore, load_or_create_identity


def main():
    with tempfile.TemporaryDirectory(
        prefix="syncbridge-pair-test-"
    ) as location:
        base = Path(location)

        alice_identity = load_or_create_identity(
            base / "Alice" / "identity.json"
        )
        bob_identity = load_or_create_identity(
            base / "Bob" / "identity.json"
        )

        alice_trust = TrustStore(
            base / "Alice" / "trust.json"
        )
        bob_trust = TrustStore(
            base / "Bob" / "trust.json"
        )

        bob = PairingService(
            bob_identity,
            bob_trust,
            "Bob",
            bind_address="127.0.0.1",
            listen_port=0,
        )

        bob.start()

        try:
            alice = PairingClient(
                alice_identity,
                alice_trust,
                "Alice",
            )

            request = alice.request(
                "127.0.0.1",
                bob.bound_port,
                expected_node_id=bob_identity.node_id,
            )

            try:
                incoming = bob.pending()[0]

                print(
                    "\n=== TWO-PERSON PAIRING PROTOCOL DEMO ==="
                )
                print(
                    "Alice displays:",
                    request.details.code,
                )
                print(
                    "Bob displays:  ",
                    incoming.code,
                )

                assert (
                    request.details.code
                    == incoming.code
                )
                assert (
                    alice_trust.devices
                    == bob_trust.devices
                    == ()
                )

                print(
                    "PASS: Signed handshake produced the "
                    "same comparison code."
                )
                print(
                    "PASS: Neither device was trusted "
                    "before consent."
                )

                bob.approve(
                    incoming.request_id,
                    request.details.code,
                )
                request.approve(incoming.code)

                assert (
                    alice_trust.get(bob_identity.node_id)
                    is not None
                )
                assert (
                    bob_trust.get(alice_identity.node_id)
                    is not None
                )

                print(
                    "PASS: Both explicit approvals saved "
                    "the verified devices."
                )

                assert not list(
                    base.rglob("settings.json")
                )

                print(
                    "PASS: Pairing granted no folder "
                    "or file permissions."
                )

            finally:
                request.close()

        finally:
            bob.stop()

    print(
        "PASS: All temporary database and "
        "identity files were cleaned up."
    )


if __name__ == "__main__":
    main()
