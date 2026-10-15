
"""Hands-on SyncBridge demo: two independent peers on one Windows laptop.

Uses real encrypted localhost TCP services and separate persistent profiles.
No real user folders are touched. Never automatically resolves conflicts/deletions.
"""

from __future__ import annotations

import os
import tempfile
import traceback
from pathlib import Path
from uuid import uuid4

from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.runtime import SyncBridgeRuntime
from syncbridge.storage.config import AppConfig, ConfigStore, ShareConfig


def configure(
    profile: Path,
    folder: Path,
    peer_id: str,
    share_id: str,
    remote_ports: tuple[int, int, int],
    device_name: str,
) -> ConfigStore:
    store = ConfigStore(profile / "settings.json")
    store.save(
        AppConfig(
            device_name=device_name,
            shares=(
                ShareConfig(
                    share_id=share_id,
                    peer_node_id=peer_id,
                    local_root=str(folder),
                    display_name="Manual Test Folder",
                    remote_host="127.0.0.1",
                    manifest_port=remote_ports[0],
                    transfer_port=remote_ports[1],
                    agreement_port=remote_ports[2],
                    enabled=True,
                    grant_manifest=True,
                    grant_read=True,
                    grant_write=True,
                    grant_agreement=True,
                ),
            ),
        )
    )
    return store


def show_folders(alice_folder: Path, bob_folder: Path) -> None:
    print(f"\nALICE folder: {alice_folder}")
    print(f"BOB   folder: {bob_folder}")

    if os.name == "nt":
        os.startfile(str(alice_folder))
        os.startfile(str(bob_folder))


def instructions() -> None:
    print(
        "\nPRACTICAL TESTS\n"
        "  1. Press 2 to sync the starter files in BOTH directions.\n"
        "  2. Edit 'from_alice.txt' in Alice's Explorer window, save, press 2.\n"
        "     Bob should receive Alice's edited version.\n"
        "  3. Edit 'from_bob.txt' in Bob's window, save, press 2.\n"
        "     Alice should receive Bob's edited version.\n"
        "  4. Edit 'from_alice.txt' DIFFERENTLY on both sides, press 2.\n"
        "     Expect NEEDS_REVIEW: neither version is overwritten.\n"
        "  5. Optionally delete a synchronized file from ONE folder, press 2.\n"
        "     Expect NEEDS_REVIEW: no automatic deletion on the other side.\n"
        "  Note: For a fresh successful sync after a conflict, make the two\n"
        "        copies identical again, then press 2.\n"
    )


def show_plan(lifecycle) -> None:
    report = lifecycle.run_once()
    decisions = report.preview.plan.decisions

    print("\nDRY-RUN PLAN:")

    if not decisions:
        print("  No file transfers needed.")

    for decision in decisions:
        print(f"  {decision.action.value:24} {decision.path}")

    print("  Nothing was transferred or modified.")


def show_sync(lifecycle) -> None:
    report = lifecycle.run_once(apply=True)

    print(f"\nSYNC RESULT: {report.status.value.upper()}")

    for transfer in report.uploaded:
        print(
            f"  ALICE -> BOB  {transfer.path} "
            f"({transfer.total} bytes)"
        )

    for transfer in report.downloaded:
        print(
            f"  BOB -> ALICE  {transfer.path} "
            f"({transfer.total} bytes)"
        )

    if report.checkpoint is not None:
        print(
            "  Shared baseline revision: "
            f"{report.checkpoint.baseline.revision}"
        )

    if report.conflicts:
        print("  Conflicts retained for review:")
        for decision in report.conflicts:
            print(f"    {decision.path}")

    if report.pending_deletions:
        print("  Unapproved deletions:")
        for decision in report.pending_deletions:
            print(f"    {decision.path}")

    if report.unapproved_joint_deletions:
        print("  Unapproved deletions on both devices:")
        for path in report.unapproved_joint_deletions:
            print(f"    {path}")

    if report.status.value == "needs_review":
        print(
            "  Protection active: conflicting versions "
            "and deletions were not applied."
        )


def main() -> None:
    base = Path(
        tempfile.mkdtemp(prefix="syncbridge-hands-on-")
    ).resolve()

    alice_folder = base / "Alice" / "Shared"
    bob_folder = base / "Bob" / "Shared"

    alice_profile = base / "Alice" / "Profile"
    bob_profile = base / "Bob" / "Profile"

    for path in (
        alice_folder,
        bob_folder,
        alice_profile,
        bob_profile,
    ):
        path.mkdir(parents=True, exist_ok=True)

    alice_id = load_or_create_identity(
        alice_profile / "identity.json"
    )
    bob_id = load_or_create_identity(
        bob_profile / "identity.json"
    )

    alice_trust = TrustStore(
        alice_profile / "trust.json"
    )
    bob_trust = TrustStore(
        bob_profile / "trust.json"
    )

    # Test-only pairing of identities created by this script.
    # Real pairing must require user fingerprint confirmation.
    alice_trust.add_verified(
        bob_id.public_key_hex,
        confirmed_fingerprint=bob_id.fingerprint,
        name="Bob (demo)",
    )
    bob_trust.add_verified(
        alice_id.public_key_hex,
        confirmed_fingerprint=alice_id.fingerprint,
        name="Alice (demo)",
    )

    share_id = uuid4().hex

    # Bob serves requests; only Alice initiates synchronization.
    # Bob's outbound ports are unused in this demonstration.
    bob_store = configure(
        bob_profile,
        bob_folder,
        alice_id.node_id,
        share_id,
        (45843, 45842, 45844),
        "Bob (demo)",
    )

    server = SyncBridgeRuntime(
        bob_store,
        bind_address="127.0.0.1",
        listen_ports=(0, 0, 0),
    )

    client = None

    try:
        server.start()

        ports = (
            server.status.manifest_port,
            server.status.transfer_port,
            server.status.agreement_port,
        )

        if any(port is None for port in ports):
            raise RuntimeError(
                "Bob did not start all three listeners"
            )

        alice_store = configure(
            alice_profile,
            alice_folder,
            bob_id.node_id,
            share_id,
            ports,
            "Alice (demo)",
        )

        client = SyncBridgeRuntime(
            alice_store,
            bind_address="127.0.0.1",
            listen_ports=(0, 0, 0),
        )
        client.start()

        (alice_folder / "from_alice.txt").write_text(
            "Hello from Alice! Edit me and synchronize.\n",
            encoding="utf-8",
        )

        (bob_folder / "from_bob.txt").write_text(
            "Hello from Bob! Edit me and synchronize.\n",
            encoding="utf-8",
        )

        print("\n=== SYNCBRIDGE HANDS-ON TEST ===")
        print(f"Demo location: {base}")
        print(f"Alice node ID: {alice_id.node_id}")
        print(f"Bob node ID:   {bob_id.node_id}")
        print(
            "Two isolated device profiles, one approved share, "
            "encrypted TCP."
        )
        print(
            "No background automatic writes; "
            "you choose when to sync."
        )

        show_folders(alice_folder, bob_folder)
        instructions()

        while True:
            command = input(
                "\n[1] Preview  [2] Sync  "
                "[3] Open folders  [4] Instructions  "
                "[0] Exit > "
            ).strip()

            if command == "0":
                break

            try:
                if command == "1":
                    show_plan(client.lifecycle)

                elif command == "2":
                    show_sync(client.lifecycle)

                elif command == "3":
                    show_folders(
                        alice_folder,
                        bob_folder,
                    )

                elif command == "4":
                    instructions()

                else:
                    print("Unknown command.")

            except Exception:
                print(
                    "Operation failed; "
                    "full traceback for debugging:"
                )
                traceback.print_exc()

    finally:
        if client is not None:
            client.stop()

        server.stop()

        print(f"\nDemo files were kept at: {base}")
        print(
            "Delete that temporary demo directory "
            "when finished."
        )


if __name__ == "__main__":
    main()
