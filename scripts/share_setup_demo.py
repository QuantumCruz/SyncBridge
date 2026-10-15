
"""Demo: two trusted computers negotiate a disabled folder relationship.

The receiver's folder selection is simulated here because this is a
developer demonstration. The next GUI phase will ask the real user.
"""
from __future__ import annotations

import tempfile
import time
from pathlib import Path

from syncbridge.network.security import (
    TrustStore,
    load_or_create_identity,
)
from syncbridge.network.share_setup import (
    ShareSetupClient,
    ShareSetupService,
)
from syncbridge.storage.config import ConfigStore


def main() -> None:
    with tempfile.TemporaryDirectory(
        prefix="syncbridge-share-setup-"
    ) as temp:
        base = Path(temp)
        profiles = {}

        for name in ("Alice", "Bob"):
            profile = base / name / "Profile"
            folder = base / name / "Shared"
            folder.mkdir(parents=True)

            profiles[name] = (
                load_or_create_identity(
                    profile / "identity.json"
                ),
                TrustStore(
                    profile / "trust.json"
                ),
                ConfigStore(
                    profile / "settings.json"
                ),
                folder,
            )

        for name, other in (
            ("Alice", "Bob"),
            ("Bob", "Alice"),
        ):
            identity = profiles[other][0]

            profiles[name][1].add_verified(
                identity.public_key_hex,
                confirmed_fingerprint=identity.fingerprint,
                name=other,
            )

        alice = profiles["Alice"]
        bob = profiles["Bob"]

        receiver = ShareSetupService(
            bob[0],
            bob[1],
            bob[2],
            port=0,
            bind_address="127.0.0.1",
        )
        receiver.start()

        try:
            sender = ShareSetupClient(
                alice[0],
                alice[1],
                alice[2],
            )

            session = sender.request(
                "127.0.0.1",
                bob[0].node_id,
                alice[3],
                "Shared documents",
                port=receiver.bound_port,
            )

            try:
                deadline = time.monotonic() + 3
                incoming = ()

                while (
                    time.monotonic() < deadline
                    and not incoming
                ):
                    incoming = receiver.pending()
                    time.sleep(0.01)

                assert incoming, (
                    "Incoming share proposal did not arrive"
                )

                print(
                    "\n=== ENCRYPTED FOLDER SETUP DEMO ==="
                )
                print(
                    "Alice requested a relationship:",
                    incoming[0].display_name,
                )

                assert not alice[2].load().shares
                assert not bob[2].load().shares

                print(
                    "PASS: No folder access was created before approval"
                )

                receiver.approve(
                    incoming[0].request_id,
                    bob[3],
                )

                result = session.wait()

                second = (
                    bob[2].load()
                    .get_share(result.share_id)
                )

                assert second is not None
                assert result.share_id == second.share_id
                assert result.peer_node_id == bob[0].node_id
                assert second.peer_node_id == alice[0].node_id

                print(
                    "PASS: Both profiles saved the SAME share identifier"
                )

                assert all(
                    not entry.enabled
                    and not entry.grant_write
                    and not entry.grant_read
                    and not entry.grant_manifest
                    and not entry.grant_agreement
                    for entry in (
                        result,
                        second,
                    )
                )

                print(
                    "PASS: Both shares are disabled with ZERO file grants"
                )

                assert (
                    result.local_root
                    != second.local_root
                )

                print(
                    "PASS: Each device independently selected its local folder"
                )

            finally:
                session.close()

        finally:
            receiver.stop()

    print(
        "PASS: Listener stopped and temporary files removed"
    )


if __name__ == "__main__":
    main()
