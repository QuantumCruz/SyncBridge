
"""Run two independent SyncBridge windows on one Windows computer.

    python scripts/gui_demo.py --unpaired   # pair, select two folders, auto-ready
    python scripts/gui_demo.py              # preconfigured guarded manual sync

The printed temporary folder is preserved until you delete it after closing.
"""
from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from uuid import uuid4

from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.storage.config import AppConfig, ConfigStore, ShareConfig


def free_ports(count: int) -> list[int]:
    results: list[int] = []
    while len(results) < count:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("127.0.0.1", 0))
            number = server.getsockname()[1]
        if number not in results:
            results.append(number)
    return results


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--unpaired", action="store_true")
    options = parser.parse_args(argv)
    base = Path(tempfile.mkdtemp(prefix="syncbridge-desktop-demo-"))
    names = ("Alice", "Bob")
    profiles = {name: base / name / "Profile" for name in names}
    folders = {name: base / name / "Shared" for name in names}
    identities = {}
    for name in names:
        profiles[name].mkdir(parents=True)
        folders[name].mkdir()
        identities[name] = load_or_create_identity(
            profiles[name] / "identity.json"
        )

    ports = free_ports(16)
    local = {"Alice": tuple(ports[0:3]), "Bob": tuple(ports[3:6])}
    share_id = uuid4().hex
    for name, other in (("Alice", "Bob"), ("Bob", "Alice")):
        if options.unpaired:
            shares = ()
        else:
            peer = identities[other]
            TrustStore(profiles[name] / "trust.json").add_verified(
                peer.public_key_hex,
                confirmed_fingerprint=peer.fingerprint,
                name=other,
            )
            shares = (
                ShareConfig(
                    share_id=share_id,
                    peer_node_id=peer.node_id,
                    local_root=str(folders[name]),
                    display_name="Demo documents",
                    remote_host="127.0.0.1",
                    manifest_port=local[other][0],
                    transfer_port=local[other][1],
                    agreement_port=local[other][2],
                    enabled=True,
                    grant_manifest=True,
                    grant_read=True,
                    grant_write=True,
                    grant_agreement=True,
                ),
            )
        ConfigStore(profiles[name] / "settings.json").save(
            AppConfig(device_name=name, shares=shares)
        )

    (folders["Alice"] / "from_alice.txt").write_text(
        "Hello from Alice!", encoding="utf-8"
    )
    (folders["Bob"] / "from_bob.txt").write_text(
        "Hello from Bob!", encoding="utf-8"
    )
    leader = min(names, key=lambda name: identities[name].node_id)
    follower = "Bob" if leader == "Alice" else "Alice"
    launcher = Path(__file__).resolve().parent / "desktop_app.py"

    print("\n=== SYNCBRIDGE TWO-COMPUTER GUI DEMO ===", flush=True)
    print("Temporary test files:", base, flush=True)
    if options.unpaired:
        print("1. Pair Alice and Bob using Nearby Devices.", flush=True)
        print("2. Click Connect Folders on Alice and choose Alice/Shared.", flush=True)
        print("3. Bob chooses Bob/Shared and accepts.", flush=True)
        print("4. Both windows should say Folders ready automatically.", flush=True)
        print("5. Connections start automatically when folders are ready.", flush=True)
        print("6. Preview and Sync Now to test real encrypted transfers.", flush=True)
    else:
        print("Previously configured folders. Connections start automatically.", flush=True)
    print("Close both windows before removing the temporary files.", flush=True)

    processes = []
    try:
        for name in (leader, follower):
            alice = name == "Alice"
            discovery = ports[8] if alice else ports[9]
            target = ports[9] if alice else ports[8]
            pairing = ports[10] if alice else ports[11]
            setup = ports[12] if alice else ports[13]
            remote_setup = ports[13] if alice else ports[12]
            activation = ports[14] if alice else ports[15]
            remote_activation = ports[15] if alice else ports[14]
            command = [
                sys.executable, str(launcher),
                "--profile", str(profiles[name]),
                "--listen-ports", *(str(p) for p in local[name]),
                "--lock-port", str(ports[6]),
                "--validation-port", str(ports[7]),
                "--discovery-port", str(discovery),
                "--discovery-bind", "127.0.0.1",
                "--discovery-name", name,
                "--discovery-target", f"127.0.0.1:{target}",
                "--pairing-port", str(pairing),
                "--pairing-bind", "127.0.0.1",
                "--setup-port", str(setup),
                "--remote-setup-port", str(remote_setup),
                "--activation-port", str(activation),
                "--remote-activation-port", str(remote_activation),
            ]
            processes.append(subprocess.Popen(command, cwd=str(launcher.parent.parent)))
        print("Opened two independent SyncBridge windows.", flush=True)
    except Exception:
        for process in processes:
            process.terminate()
        raise


if __name__ == "__main__":
    main()
