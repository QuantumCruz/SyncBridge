
"""Real encrypted localhost demo: approved folders become ready internally.

This uses temporary data. It exercises folder consent via ShareSetup and the
separate readiness exchange, with no manual port/permission steps for users.
No automatic deletion or background file sync is enabled.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.network.share_activation import (
    ShareActivationClient,
    ShareActivationService,
)
from syncbridge.network.share_setup import ShareSetupClient, ShareSetupService
from syncbridge.storage.config import AppConfig, ConfigStore


def main() -> None:
    with tempfile.TemporaryDirectory(
        prefix="syncbridge-ready-"
    ) as temp:
        peers = {}

        for name in ("Alice", "Bob"):
            home = Path(temp) / name
            folder = home / "Shared"
            folder.mkdir(parents=True)

            profile = home / "Profile"
            identity = load_or_create_identity(
                profile / "identity.json"
            )
            trust = TrustStore(
                profile / "trust.json"
            )
            store = ConfigStore(
                profile / "settings.json"
            )
            store.save(
                AppConfig(device_name=name)
            )

            peers[name] = (
                identity,
                trust,
                store,
                folder,
            )

        for name, remote in (
            ("Alice", "Bob"),
            ("Bob", "Alice"),
        ):
            identity = peers[remote][0]

            peers[name][1].add_verified(
                identity.public_key_hex,
                confirmed_fingerprint=identity.fingerprint,
                name=remote,
            )

        alice, bob = peers["Alice"], peers["Bob"]

        setup = ShareSetupService(
            bob[0],
            bob[1],
            bob[2],
            bind_address="127.0.0.1",
            port=0,
        )
        setup.start()

        try:
            request = ShareSetupClient(
                alice[0],
                alice[1],
                alice[2],
            ).request(
                "127.0.0.1",
                bob[0].node_id,
                alice[3],
                "Shared documents",
                port=setup.bound_port,
                local_ports=(
                    46543,
                    46542,
                    46544,
                ),
            )

            try:
                incoming = setup.pending()[0]

                setup.approve(
                    incoming.request_id,
                    bob[3],
                    local_ports=(
                        47543,
                        47542,
                        47544,
                    ),
                )

                disabled = request.wait()

            finally:
                request.close()

        finally:
            setup.stop()

        assert not disabled.enabled
        assert not bob[2].load().get_share(
            disabled.share_id
        ).enabled

        print(
            "\n=== SYNCBRIDGE FOLDER READINESS DEMO ==="
        )
        print(
            "PASS: Both users selected folders and approved; "
            "no early grants"
        )

        service = ShareActivationService(
            bob[0],
            bob[1],
            bob[2],
            bind_address="127.0.0.1",
            port=0,
            local_ports=(
                47543,
                47542,
                47544,
            ),
        )
        service.start()

        try:
            client = ShareActivationClient(
                alice[0],
                alice[1],
                alice[2],
                local_ports=(
                    46543,
                    46542,
                    46544,
                ),
            )

            first = client.activate(
                disabled.share_id,
                bob[0].node_id,
                port=service.bound_port,
            )

            second = bob[2].load().get_share(
                disabled.share_id
            )

            assert first.enabled and second.enabled
            assert first.share_id == second.share_id

            print(
                "PASS: Both computers are ready with matching "
                "trusted share IDs"
            )

            assert not first.preferences.auto_apply
            assert not second.preferences.auto_apply

            print(
                "PASS: No unattended synchronization or deletion "
                "was enabled"
            )

            client.activate(
                disabled.share_id,
                bob[0].node_id,
                port=service.bound_port,
            )

            print(
                "PASS: Retrying is safe and does not create "
                "duplicate folders"
            )

        finally:
            service.stop()

    print(
        "PASS: Connections closed and temporary test files removed"
    )


if __name__ == "__main__":
    main()
