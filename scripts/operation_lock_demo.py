
"""Practical Phase 20: encrypted cross-process operation coordination.

Run: python scripts/operation_lock_demo.py
Two independent console windows are created on Windows. Hold the lock in one
console, then attempt to acquire in the other. This does NOT modify synced files
or integrate with the older unguarded Sync/Deletion services yet.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from uuid import uuid4

from syncbridge.network.operation_lock import (
    LeaseCoordinator,
    OperationBusy,
    OperationLockClient,
    OperationLockError,
    OperationLockService,
)
from syncbridge.network.security import TrustStore, load_or_create_identity


def profile(base: Path, role: str) -> Path:
    return base / role.capitalize() / "Profile"


def prepare() -> Path:
    root = Path(tempfile.mkdtemp(prefix="syncbridge-operation-demo-")).resolve()
    identities = {}
    for role in ("alice", "bob"):
        directory = profile(root, role)
        directory.mkdir(parents=True)
        identities[role] = load_or_create_identity(directory / "identity.json")

    for role, other in (("alice", "bob"), ("bob", "alice")):
        remote = identities[other]
        TrustStore(profile(root, role) / "trust.json").add_verified(
            remote.public_key_hex,
            confirmed_fingerprint=remote.fingerprint,
            name=other.capitalize(),
        )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as temporary:
        temporary.bind(("127.0.0.1", 0))
        port = temporary.getsockname()[1]

    leader_role = min(identities, key=lambda role: identities[role].node_id)
    data = {
        "share": uuid4().hex,
        "port": port,
        "leader": leader_role,
    }
    (root / "demo.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Temporary test session: {root}")
    print(f"Coordination authority: {leader_role.capitalize()}")
    return root


def peer_main(role: str, root: Path) -> None:
    info = json.loads((root / "demo.json").read_text(encoding="utf-8"))
    other = "bob" if role == "alice" else "alice"
    from syncbridge.network.security import load_or_create_identity
    identity = load_or_create_identity(profile(root, role) / "identity.json")
    other_identity = load_or_create_identity(profile(root, other) / "identity.json")
    trusted = TrustStore(profile(root, role) / "trust.json")
    server = None

    try:
        if role == info["leader"]:
            server = OperationLockService(
                identity, trusted, {info["share"]: other_identity.node_id},
                listen_port=info["port"], lease_seconds=15,
            )
            server.start()
            coordinator = LeaseCoordinator(
                identity, other_identity.node_id, info["share"],
                local_service=server,
            )
        else:
            client = OperationLockClient(identity, trusted)
            coordinator = LeaseCoordinator(
                identity, other_identity.node_id, info["share"],
                client=client, host="127.0.0.1", port=info["port"],
            )

        print(f"\n=== {role.upper()} — independent process {os.getpid()} ===")
        print("Authority:", info["leader"].capitalize())
        print("Coordinated share:", info["share"])
        print("\n[1] Hold Sync permission [2] Check who is working [0] Exit")
        while True:
            try:
                answer = input("\nChoose: ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if answer == "0":
                break
            try:
                if answer == "1":
                    with coordinator.hold("sync") as lease:
                        print("[SB-OPS-200] You may start one coordinated operation.")
                        print("Leave this window open. Try option 1 on the OTHER computer.")
                        input("Press Enter to finish and release permission... ")
                        lease.check()
                    print("Finished: the other device may now start.")
                elif answer == "2":
                    if server is not None:
                        state = server.status_local(info["share"])
                    else:
                        state = coordinator.client.status(
                            "127.0.0.1", info["port"], other_identity.node_id, info["share"]
                        )
                    if state.owner is None:
                        print("Nobody is currently working on this folder.")
                    else:
                        who = role.capitalize() if state.owner == identity.node_id else other.capitalize()
                        print(f"{who} is working on this folder ({state.operation}).")
                        print(f"Lease expires in up to {state.seconds_left:.1f}s unless renewed.")
                else:
                    print("Choose 1, 2, or 0.")
            except OperationBusy as exc:
                who = role.capitalize() if exc.owner == identity.node_id else other.capitalize()
                print(f"[SB-OPS-423] {who} is already working on this folder. Try again afterward.")
            except OperationLockError as exc:
                print(f"Could not coordinate safely: {exc}")
    finally:
        if server is not None:
            server.stop()
        print("Process stopped. No synchronized files were modified.")


def main() -> None:
    if len(sys.argv) == 4 and sys.argv[1] == "peer":
        role = sys.argv[2].lower()
        if role not in ("alice", "bob"):
            raise SystemExit("Unknown demo role")
        peer_main(role, Path(sys.argv[3]).resolve(strict=True))
        return
    if len(sys.argv) != 1:
        raise SystemExit("Usage: python scripts/operation_lock_demo.py")
    root = prepare()
    script = str(Path(__file__).resolve())
    info = json.loads((root / "demo.json").read_text(encoding="utf-8"))
    commands = [
        [sys.executable, "-u", script, "peer", role, str(root)]
        for role in (info["leader"], "bob" if info["leader"] == "alice" else "alice")
    ]
    if os.name == "nt":
        for command in commands:
            subprocess.Popen(command, creationflags=subprocess.CREATE_NEW_CONSOLE,
                             cwd=str(Path(__file__).resolve().parent.parent))
        print("Two independent Windows console windows are opening.")
    else:
        print("Open two terminals and run:")
        for command in commands:
            print(" ".join(f'"{arg}"' for arg in command))
    print("Hold permission in one window, then try the other; release and retry.")


if __name__ == "__main__":
    main()
