
"""Open two independent local SyncBridge GUIs to test discovery and pairing.

Usage:
    python scripts/gui_demo.py --unpaired   # test two-person pairing from scratch
    python scripts/gui_demo.py              # previously trusted sync demonstration

Profiles and files are disposable test data kept in a printed temp directory.
The --unpaired mode gives neither peer any trust or shared-folder grant.
Pair first; folder setup is a separate future step.
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
    results = []
    while len(results) < count:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("127.0.0.1", 0))
            port = server.getsockname()[1]
        if port not in results:
            results.append(port)
    return results


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--unpaired", action="store_true",
        help="Start Alice/Bob without trust entries to test GUI pairing",
    )
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

    share = uuid4().hex
    ports = free_ports(12)
    local = {"Alice": tuple(ports[0:3]), "Bob": tuple(ports[3:6])}
    scripts = Path(__file__).resolve().parent
    desktop_script = scripts / "desktop_app.py"

    for name, other in (("Alice", "Bob"), ("Bob", "Alice")):
        peer = identities[other]
        if not options.unpaired:
            TrustStore(profiles[name] / "trust.json").add_verified(
                peer.public_key_hex,
                confirmed_fingerprint=peer.fingerprint,
                name=other,
            )
        shares = ()
        if not options.unpaired:
            shares = (
                ShareConfig(
                    share_id=share,
                    peer_node_id=peer.node_id,
                    local_root=str(folders[name]),
                    display_name="Demo Shared documents",
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

    authority = min(names, key=lambda name: identities[name].node_id)
    follower = "Bob" if authority == "Alice" else "Alice"
    print("\n=== SYNCBRIDGE TWO-WINDOW DESKTOP DEMO ===", flush=True)
    print("Temporary test data:", base, flush=True)
    if options.unpaired:
        print("Mode: UNPAIRED. Open Nearby Devices on ONE window and request pairing.", flush=True)
        print("Compare both codes and approve separately in Alice and Bob.", flush=True)
        print("No shares or folder permissions are configured; pairing cannot transfer files.", flush=True)
    else:
        print("Mode: ALREADY PAIRED. Test Preview and Sync Now as before.", flush=True)
    print("For synchronization, start connection on", authority, "then", follower, flush=True)
    print("Close both windows before deleting the temporary directory.", flush=True)

    processes = []
    try:
        for name in (authority, follower):
            is_alice = name == "Alice"
            discovery = ports[8] if is_alice else ports[9]
            target = ports[9] if is_alice else ports[8]
            pairing = ports[10] if is_alice else ports[11]
            command = [
                sys.executable, str(desktop_script),
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
            ]
            processes.append(subprocess.Popen(command, cwd=str(scripts.parent)))
        print("Opened two independent SyncBridge desktop processes.", flush=True)
    except Exception:
        for process in processes:
            process.terminate()
        raise


if __name__ == "__main__":
    main()
