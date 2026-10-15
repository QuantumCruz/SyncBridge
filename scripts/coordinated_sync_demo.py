
"""Two independent SyncBridge peers using real leased sync operations.

Run:
    python scripts/coordinated_sync_demo.py

Creates disposable localhost Alice/Bob profiles and consoles. Unlike the
older demo, NO shared lock file is used; permission comes from the elected
peer's authenticated operation-lock service. Existing network receivers are
not yet fenced: this is a manual, cooperative demonstration only.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import traceback
from pathlib import Path

from syncbridge.core.coordinated_operations import CoordinatedOperations
from syncbridge.core.review import ReviewManager, explain_error
from syncbridge.network.operation_lock import (
    LeaseCoordinator,
    OperationBusy,
    OperationLockClient,
    OperationLockError,
    OperationLockService,
)
from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.runtime import SyncBridgeRuntime
from syncbridge.storage.config import ConfigStore

# This file imports only the setup helpers from our already committed
# two-process demo. It does not use that demo's shared cycle lock.
from two_process_demo import folder, initialize, profile


def choose_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def create_session() -> Path:
    session = initialize()
    info_file = session / "demo.json"
    info = json.loads(info_file.read_text(encoding="utf-8"))
    identities = {
        role: load_or_create_identity(profile(session, role) / "identity.json")
        for role in ("alice", "bob")
    }
    info["leader"] = min(identities, key=lambda role: identities[role].node_id)
    info["lock_port"] = choose_free_port()

    # The older helper creates identities, trust, shared folders, and
    # two sets of distinct TCP ports before anything is started.
    info_file.write_text(json.dumps(info, indent=2), encoding="utf-8")
    print("Coordination authority:", info["leader"].capitalize())
    print("Demo session:", session)
    return session


def print_result(result, reviewer: ReviewManager) -> None:
    print("\n--- Synchronization result ---")
    for transfer in result.uploaded:
        print(f"  Sent '{transfer.path}' to the other computer.")
    for transfer in result.downloaded:
        print(f"  Received '{transfer.path}' from the other computer.")
    if result.complete:
        print("SUCCESS: Both devices agreed on the file contents.")
        print("Shared revision:", result.checkpoint.baseline.revision)
    elif result.status.value == "needs_review":
        issues = reviewer.list_issues()
        print("Some files require your decision; they were not overwritten.")
        for issue in issues:
            print(f"  [{issue.code}] {issue.title}")
            print("    Next:", issue.next_step)
    elif result.status.value == "paused":
        print("Synchronization paused. Review both folders before retrying.")
    else:
        print("Sync not committed:", result.status.value)


def peer_main(role: str, session: Path) -> None:
    other = "bob" if role == "alice" else "alice"
    info = json.loads((session / "demo.json").read_text(encoding="utf-8"))
    identity = load_or_create_identity(profile(session, role) / "identity.json")
    peer = load_or_create_identity(profile(session, other) / "identity.json")
    trust = TrustStore(profile(session, role) / "trust.json")
    runtime = SyncBridgeRuntime(
        ConfigStore(profile(session, role) / "settings.json"),
        bind_address="127.0.0.1",
        listen_ports=tuple(info["local_ports"][role]),
    )
    service = None

    try:
        runtime.start(background=False)
        share = runtime.coordinator.share_id

        if role == info["leader"]:
            service = OperationLockService(
                identity,
                trust,
                {share: peer.node_id},
                bind_address="127.0.0.1",
                listen_port=info["lock_port"],
                lease_seconds=15.0,
            )
            service.start()
            leases = LeaseCoordinator(
                identity, peer.node_id, share, local_service=service,
            )
        else:
            client = OperationLockClient(identity, trust)
            leases = LeaseCoordinator(
                identity, peer.node_id, share,
                client=client, host="127.0.0.1", port=info["lock_port"],
            )

        runner = CoordinatedOperations(runtime.lifecycle, leases)
        reviewer = ReviewManager(
            runtime.lifecycle, here=role.capitalize(), there=other.capitalize()
        )
        shared = folder(session, role)

        print(f"\n==== {role.upper()} | PID {os.getpid()} ====")
        print("Shared folder:", shared)
        print("Coordination authority:", info["leader"].capitalize())
        print("Automatic changes: OFF")
        print("The other device should also be open before synchronizing.")

        if os.name == "nt":
            os.startfile(str(shared))

        while True:
            try:
                option = input(
                    "\n[1] Preview  [2] Coordinated Sync  "
                    "[3] Hold permission  [4] Open folder  "
                    "[5] Who is working?  [0] Exit > "
                ).strip()
            except (EOFError, KeyboardInterrupt):
                break

            if option == "0":
                break
            try:
                if option == "1":
                    result = runner.preview()
                    decisions = result.preview.plan.decisions
                    if not decisions:
                        print("No file transfers needed.")
                    for decision in decisions:
                        print(f"  {decision.path} — {decision.action.value}")
                    print("Preview did not modify files.")

                elif option == "2":
                    print_result(runner.sync_once(), reviewer)

                elif option == "3":
                    with leases.hold("sync") as guard:
                        print("[SB-OPS-200] This computer has permission.")
                        print("Try [2] in the other device's terminal now.")
                        input("Press Enter to release permission... ")
                        guard.check()
                    print("Permission released. The other device can proceed.")

                elif option == "4":
                    print(shared)
                    if os.name == "nt":
                        os.startfile(str(shared))

                elif option == "5":
                    if service is not None:
                        status = service.status_local(share)
                    else:
                        status = leases.client.status(
                            "127.0.0.1", info["lock_port"], peer.node_id, share
                        )
                    if status.owner is None:
                        print("No device is currently working on this folder.")
                    else:
                        who = role if status.owner == identity.node_id else other
                        print(f"{who.capitalize()} is working on this folder.")

                else:
                    print("Choose 1, 2, 3, 4, 5, or 0.")

            except OperationBusy as exc:
                owner = role if exc.owner == identity.node_id else other
                print(f"[SB-OPS-423] {owner.capitalize()} is using this folder.")
                print("Wait until that device finishes, then try again.")
            except OperationLockError as exc:
                print(f"Coordination stopped: {exc}")
                print("Next: Check the other device and retry when it is available.")
            except Exception as exc:
                code, explanation, action = explain_error(exc)
                print(f"[{code}] {explanation}")
                print("Next step:", action)
                print("Details:", exc)
                traceback.print_exc()

    finally:
        if service is not None:
            service.stop()
        runtime.stop()
        print("Stopped. Demo files are still at:", session)


def main() -> None:
    if len(sys.argv) == 4 and sys.argv[1] == "peer":
        role = sys.argv[2].lower()
        if role not in ("alice", "bob"):
            raise SystemExit("Unknown device")
        try:
            peer_main(role, Path(sys.argv[3]).resolve(strict=True))
        except Exception:
            traceback.print_exc()
            input("Press Enter to close... ")
        return

    if len(sys.argv) != 1:
        raise SystemExit("Usage: python scripts/coordinated_sync_demo.py")

    session = create_session()
    info = json.loads((session / "demo.json").read_text(encoding="utf-8"))
    script = str(Path(__file__).resolve())
    leader = info["leader"]
    other = "bob" if leader == "alice" else "alice"
    commands = [
        [sys.executable, "-u", script, "peer", role, str(session)]
        for role in (leader, other)
    ]

    if os.name == "nt":
        for command in commands:
            subprocess.Popen(
                command,
                creationflags=subprocess.CREATE_NEW_CONSOLE,
                cwd=str(Path(__file__).resolve().parent.parent),
            )
        print("Two independent terminals are opening.")
    else:
        print("Open two terminals and run these commands:")
        for command in commands:
            print(" ".join(repr(part) for part in command))

    print("Start sync from either device. Hold permission in one to test contention.")


if __name__ == "__main__":
    main()
