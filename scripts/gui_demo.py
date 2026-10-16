
"""Open two SyncBridge desktops for discovery, pairing and folder setup.

    python scripts/gui_demo.py --unpaired  # pair, then set up folders via GUI
    python scripts/gui_demo.py             # legacy preconfigured manual sync

Both processes run on localhost. Test profiles persist in the printed temp
folder until manually deleted. New folder requests save DISABLED shares only.
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
        identities[name] = load_or_create_identity(profiles[name] / "identity.json")

    ports = free_ports(14)
    local = {"Alice": tuple(ports[0:3]), "Bob": tuple(ports[3:6])}
    share_id = uuid4().hex
    for name, other in (("Alice", "Bob"), ("Bob", "Alice")):
        if not options.unpaired:
            peer = identities[other]
            TrustStore(profiles[name] / "trust.json").add_verified(
                peer.public_key_hex,
                confirmed_fingerprint=peer.fingerprint,
                name=other,
            )
            shares = (
                ShareConfig(
                    share_id=share_id, peer_node_id=peer.node_id,
                    local_root=str(folders[name]), display_name="Demo documents",
                    remote_host="127.0.0.1",
                    manifest_port=local[other][0],
                    transfer_port=local[other][1],
                    agreement_port=local[other][2],
                    enabled=True,
                    grant_manifest=True, grant_read=True,
                    grant_write=True, grant_agreement=True,
                ),
            )
        else:
            shares = ()
        ConfigStore(profiles[name] / "settings.json").save(
            AppConfig(device_name=name, shares=shares)
        )

    (folders["Alice"] / "from_alice.txt").write_text("Hello from Alice!", encoding="utf-8")
    (folders["Bob"] / "from_bob.txt").write_text("Hello from Bob!", encoding="utf-8")
    leader = min(names, key=lambda name: identities[name].node_id)
    follower = "Bob" if leader == "Alice" else "Alice"
    scripts = Path(__file__).resolve().parent
    launcher = scripts / "desktop_app.py"
    print("\n=== SYNCBRIDGE DESKTOP DEMO ===", flush=True)
    print("Test data:", base, flush=True)
    if options.unpaired:
        print("Pair from Nearby Devices, then click Set Up Folder.", flush=True)
        print("Approve on the other window, choosing its OWN folder.", flush=True)
        print("The new relationship stays DISABLED; no syncing yet.", flush=True)
    else:
        print("Preconfigured demo: Start Connection on", leader, "first.", flush=True)
        print("Then Preview and Sync Now as before.", flush=True)
    print("Close both windows before deleting test data.", flush=True)

    processes = []
    try:
        for name in (leader, follower):
            alice = name == "Alice"
            discovery = ports[8] if alice else ports[9]
            target = ports[9] if alice else ports[8]
            pairing = ports[10] if alice else ports[11]
            setup = ports[12] if alice else ports[13]
            remote_setup = ports[13] if alice else ports[12]
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
            ]
            processes.append(subprocess.Popen(command, cwd=str(scripts.parent)))
        print("Opened two separate SyncBridge processes.", flush=True)
    except Exception:
        for process in processes:
            process.terminate()
        raise


if __name__ == "__main__":
    main()
