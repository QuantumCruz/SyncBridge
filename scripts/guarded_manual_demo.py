
"""One-process, two-device manual sync using guarded transfer receivers.

Run from repository root:
    python scripts/guarded_manual_demo.py

Only temporary folders are touched. Both devices have different identities,
configuration profiles and SQLite histories. Real localhost encrypted network
connections carry the files. This is not a two-computer or crash-fencing test.
"""
from __future__ import annotations

import socket
import tempfile
from pathlib import Path
from uuid import uuid4

from syncbridge.core.guarded_manual import GuardedManualRuntime
from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.storage.config import AppConfig, ConfigStore, ShareConfig


def free_ports(count: int) -> list[int]:
    result = []

    while len(result) < count:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            number = listener.getsockname()[1]

        if number not in result:
            result.append(number)

    return result


def main() -> None:
    with tempfile.TemporaryDirectory(
        prefix="syncbridge-guarded-manual-"
    ) as temp:
        base = Path(temp)

        profiles = {
            name: base / name / "Profile"
            for name in ("Alice", "Bob")
        }
        folders = {
            name: base / name / "Shared"
            for name in ("Alice", "Bob")
        }
        identities = {}

        for name in profiles:
            profiles[name].mkdir(parents=True)
            folders[name].mkdir()

            identities[name] = load_or_create_identity(
                profiles[name] / "identity.json"
            )

        ports = free_ports(8)
        share = uuid4().hex
        runtimes = {}

        for name, other, offset, remote_offset in (
            ("Alice", "Bob", 0, 3),
            ("Bob", "Alice", 3, 0),
        ):
            peer = identities[other]

            TrustStore(
                profiles[name] / "trust.json"
            ).add_verified(
                peer.public_key_hex,
                confirmed_fingerprint=peer.fingerprint,
                name=other,
            )

            config = ConfigStore(
                profiles[name] / "settings.json"
            )

            config.save(
                AppConfig(
                    device_name=name,
                    shares=(
                        ShareConfig(
                            share_id=share,
                            peer_node_id=peer.node_id,
                            local_root=str(folders[name]),
                            display_name="Manual protected test",
                            remote_host="127.0.0.1",
                            manifest_port=ports[remote_offset],
                            transfer_port=ports[remote_offset + 1],
                            agreement_port=ports[remote_offset + 2],
                            enabled=True,
                            grant_manifest=True,
                            grant_read=True,
                            grant_write=True,
                            grant_agreement=True,
                        ),
                    ),
                )
            )

            runtimes[name] = GuardedManualRuntime(
                config,
                bind_address="127.0.0.1",
                listen_ports=tuple(
                    ports[offset:offset + 3]
                ),
                lock_port=ports[6],
                validation_port=ports[7],
            )

        leader = min(
            identities,
            key=lambda name: identities[name].node_id,
        )
        follower = "Bob" if leader == "Alice" else "Alice"

        print("\n=== PROTECTED MANUAL SYNC DEMO ===")
        print("Authority:", leader)

        (
            folders["Alice"] / "from_alice.txt"
        ).write_text(
            "Hello from Alice",
            encoding="utf-8",
        )

        (
            folders["Bob"] / "from_bob.txt"
        ).write_text(
            "Hello from Bob",
            encoding="utf-8",
        )

        try:
            runtimes[leader].start()
            runtimes[follower].start()

            first = runtimes["Alice"].sync_once()

            assert first.complete
            assert first.checkpoint.baseline.revision == 1

            assert (
                folders["Bob"] / "from_alice.txt"
            ).read_text(encoding="utf-8") == "Hello from Alice"

            assert (
                folders["Alice"] / "from_bob.txt"
            ).read_text(encoding="utf-8") == "Hello from Bob"

            print(
                "PASS: Alice's guarded Sync copied both files "
                "and committed revision 1"
            )

            (
                folders["Bob"] / "from_bob.txt"
            ).write_text(
                "Bob's updated version",
                encoding="utf-8",
            )

            second = runtimes["Bob"].sync_once()

            assert second.complete
            assert second.checkpoint.baseline.revision == 2

            assert (
                folders["Alice"] / "from_bob.txt"
            ).read_text(encoding="utf-8") == "Bob's updated version"

            print(
                "PASS: Bob's guarded Sync delivered an update "
                "and committed revision 2"
            )

            from syncbridge.network.operation_lock import (
                OperationBusy,
            )

            with runtimes["Alice"].leases.hold("sync"):
                try:
                    runtimes["Bob"].sync_once()
                except OperationBusy:
                    print(
                        "PASS: Bob was refused while Alice held "
                        "the shared operation lease"
                    )
                else:
                    raise RuntimeError(
                        "BUG: Concurrent operation was accepted"
                    )

            print(
                "\nGuarded real synchronization is working "
                "in the isolated demo."
            )
            print(
                "This does NOT prove crash-atomic fencing "
                "or secure baseline writes yet."
            )

        finally:
            runtimes[follower].stop()
            runtimes[leader].stop()


if __name__ == "__main__":
    main()
