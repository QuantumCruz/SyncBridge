
"""Hands-on authorized deletion with two real localhost SyncBridge runtimes.

Run from the repository root with the virtual environment activated:
    python scripts/deletion_demo.py

This is an isolated demonstration. Profiles and folders are freshly created
under the temporary directory. Real encrypted network services are used, but
both runtimes share one launcher process. Unattended deletion is NEVER enabled.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from uuid import uuid4

from syncbridge.core.approved_deletion import (
    ApprovedDeletionCoordinator,
    RecoveryVault,
)
from syncbridge.network.deletion_approval import (
    DeletionApprovalClient,
    DeletionApprovalService,
    DeletionApprovalStore,
    describe_status,
)
from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.runtime import SyncBridgeRuntime
from syncbridge.storage.config import AppConfig, ConfigStore, ShareConfig


def configure(profile, root, peer_id, share, remote_ports):
    store = ConfigStore(profile / "settings.json")
    store.save(AppConfig(
        device_name=profile.parent.name,
        shares=(ShareConfig(
            share_id=share,
            peer_node_id=peer_id,
            local_root=str(root),
            display_name="Deletion test folder",
            remote_host="127.0.0.1",
            manifest_port=remote_ports[0],
            transfer_port=remote_ports[1],
            agreement_port=remote_ports[2],
            enabled=True,
            grant_manifest=True,
            grant_read=True,
            grant_write=True,
            grant_agreement=True,
        ),),
    ))
    return store


def main():
    session = Path(tempfile.mkdtemp(prefix="syncbridge-deletion-test-"))
    alice_profile = session / "Alice" / "Profile"
    bob_profile = session / "Bob" / "Profile"
    alice_folder = session / "Alice" / "Shared"
    bob_folder = session / "Bob" / "Shared"
    for item in (alice_profile, bob_profile, alice_folder, bob_folder):
        item.mkdir(parents=True)

    alice_id = load_or_create_identity(alice_profile / "identity.json")
    bob_id = load_or_create_identity(bob_profile / "identity.json")
    alice_trust = TrustStore(alice_profile / "trust.json")
    bob_trust = TrustStore(bob_profile / "trust.json")

    # Demo ONLY: both keys were generated inside this local script.
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

    share = uuid4().hex
    bob_runtime = SyncBridgeRuntime(
        configure(bob_profile, bob_folder, alice_id.node_id, share,
                  (45843, 45842, 45844)),
        listen_ports=(0, 0, 0),
    )
    alice_runtime = None
    approval_server = None

    try:
        bob_runtime.start()
        bob_ports = (
            bob_runtime.status.manifest_port,
            bob_runtime.status.transfer_port,
            bob_runtime.status.agreement_port,
        )

        alice_runtime = SyncBridgeRuntime(
            configure(alice_profile, alice_folder, bob_id.node_id,
                      share, bob_ports),
            listen_ports=(0, 0, 0),
        )
        alice_runtime.start()

        filename = "project.txt"
        (bob_folder / filename).write_text(
            "Important file: this will be protected in recovery.\n",
            encoding="utf-8",
        )
        first = alice_runtime.lifecycle.run_once(apply=True)

        if not first.complete:
            raise RuntimeError("Initial synchronization did not finish")

        print("\n=== SYNCBRIDGE: APPROVED DELETION DEMO ===")
        print("Initial sync complete. Shared revision:", first.checkpoint.baseline.revision)
        print("Alice's folder:", alice_folder)
        print("Bob's folder:  ", bob_folder)

        if os.name == "nt":
            os.startfile(str(alice_folder))
            os.startfile(str(bob_folder))

        input(
            "\nIn Bob's Explorer window, DELETE project.txt, "
            "then press Enter here... "
        )

        if (bob_folder / filename).exists():
            print("Bob still has project.txt. Nothing will be deleted.")
            return

        store = DeletionApprovalStore(alice_profile / "deletion_requests.sqlite")
        approval_server = DeletionApprovalService(
            alice_runtime.identity,
            alice_runtime.trust_store,
            alice_runtime.shared_state,
            store,
            {share: alice_folder},
            allowed_requesters={share: [bob_id.node_id]},
            bind_address="127.0.0.1",
            listen_port=0,
        )
        approval_server.start()

        client = DeletionApprovalClient(
            bob_runtime.identity,
            bob_runtime.trust_store,
        )
        baseline = bob_runtime.shared_state.load(
            bob_folder, alice_id.node_id, share,
        )
        original = baseline.snapshot.files[filename]

        request_id, state = client.request(
            "127.0.0.1",
            approval_server.bound_port,
            alice_id.node_id,
            share,
            filename,
            baseline_revision=baseline.revision,
            baseline_sha256=baseline.sha256,
            file_sha256=original.sha256,
            file_size=original.size,
        )

        print("\nBob requests deletion of project.txt everywhere.")
        print("Request status:", describe_status(state, "Alice").title)
        print("Request ID:", request_id)

        request = approval_server.incoming(share, bob_id.node_id)[0]
        print("\nAlice received this request:")
        print("  Bob wants to remove:", request.path)
        print("  Remaining copy is on: Alice")
        print("  Alice's file will be kept in recovery storage.")

        choice = input("\nAlice: type APPROVE or DECLINE: ").strip().upper()

        if choice not in {"APPROVE", "DECLINE"}:
            print("No decision made. Alice's file is unchanged.")
            return

        decision = approval_server.decide(
            share, bob_id.node_id, request_id,
            approve=(choice == "APPROVE"),
        )

        remote_status = client.status(
            "127.0.0.1", approval_server.bound_port,
            alice_id.node_id, share, request_id,
        )
        print("\n", describe_status(remote_status, "Alice").title)

        if decision.state != "approved":
            print("Alice declined. The remaining copy was not removed.")
            return

        execute = input(
            "\nAlice: type EXECUTE to move your copy into recovery "
            "and confirm deletion on both computers: "
        ).strip()

        if execute != "EXECUTE":
            print("Approval recorded, but no file was removed.")
            return

        vault = RecoveryVault(alice_folder, alice_profile / "Recovery")
        coordinator = ApprovedDeletionCoordinator(
            alice_runtime.lifecycle, approval_server, vault,
        )

        outcome = coordinator.apply(request_id)

        print(f"\n[{outcome.code}] {outcome.message}")
        print("Shared revision:", outcome.revision)
        print("Recoverable original:", outcome.recovery_path)
        print("Alice's folder has project.txt:", (alice_folder / filename).exists())
        print("Bob's folder has project.txt:  ", (bob_folder / filename).exists())
        print("\nThe recovery copy is retained. It has NOT been permanently erased.")

        if input("\nType RESTORE to restore Alice's copy, or Enter to exit: ").strip() == "RESTORE":
            restored = vault.restore(request)
            print("Restored:", restored)
            print("This restored copy is a NEW local change; sync it separately.")

    finally:
        if approval_server is not None:
            approval_server.stop()
        if alice_runtime is not None:
            alice_runtime.stop()
        bob_runtime.stop()
        print("\nTemporary demo files remain at:", session)


if __name__ == "__main__":
    main()
