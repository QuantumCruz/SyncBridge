
"""Make two disposable, paired profiles and open two real desktop windows.

Run: python scripts/gui_demo.py

This is a LOCALHOST demonstration, not genuine multi-machine pairing.
The demo data is kept under a temporary folder so that GUI processes can use
it after this launcher exits; remove that folder yourself after closing both.
"""
from __future__ import annotations

import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from uuid import uuid4

from syncbridge.network.security import (
    TrustStore,
    load_or_create_identity,
)
from syncbridge.storage.config import (
    AppConfig,
    ConfigStore,
    ShareConfig,
)


def free_ports(count: int) -> list[int]:
    results: list[int] = []

    while len(results) < count:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        ) as server:
            server.bind(
                ("127.0.0.1", 0)
            )
            port = server.getsockname()[1]

        if port not in results:
            results.append(port)

    return results


def main() -> None:
    base = Path(
        tempfile.mkdtemp(
            prefix="syncbridge-desktop-demo-"
        )
    )

    names = ("Alice", "Bob")
    profiles = {
        name: base / name / "Profile"
        for name in names
    }
    folders = {
        name: base / name / "Shared"
        for name in names
    }
    identities = {}

    for name in names:
        profiles[name].mkdir(
            parents=True
        )
        folders[name].mkdir()

        identities[name] = load_or_create_identity(
            profiles[name] / "identity.json"
        )

    share = uuid4().hex
    ports = free_ports(8)

    local = {
        "Alice": tuple(ports[0:3]),
        "Bob": tuple(ports[3:6]),
    }

    scripts = Path(__file__).resolve().parent
    desktop_script = scripts / "desktop_app.py"

    for name, other in (
        ("Alice", "Bob"),
        ("Bob", "Alice"),
    ):
        peer = identities[other]

        TrustStore(
            profiles[name] / "trust.json"
        ).add_verified(
            peer.public_key_hex,
            confirmed_fingerprint=peer.fingerprint,
            name=f"{other} (local demo only)",
        )

        ConfigStore(
            profiles[name] / "settings.json"
        ).save(
            AppConfig(
                device_name=name,
                shares=(
                    ShareConfig(
                        share_id=share,
                        peer_node_id=peer.node_id,
                        local_root=str(folders[name]),
                        display_name="Shared documents",
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
                ),
            )
        )

    (
        folders["Alice"] / "from_alice.txt"
    ).write_text(
        "Hello from Alice!",
        encoding="utf-8",
    )

    (
        folders["Bob"] / "from_bob.txt"
    ).write_text(
        "Hello from Bob!",
        encoding="utf-8",
    )

    authority = min(
        names,
        key=lambda name: identities[name].node_id,
    )

    other = (
        "Bob"
        if authority == "Alice"
        else "Alice"
    )

    print(
        "\n=== SYNCBRIDGE TWO-WINDOW DESKTOP DEMO ==="
    )
    print("Temporary files:", base)
    print(
        "Start Connection on",
        authority,
        "FIRST, then",
        other,
    )
    print(
        "Next, press Preview then Sync Now "
        "in either window."
    )
    print(
        "Both windows must stay connected "
        "while synchronizing."
    )
    print(
        "This demo deliberately does not delete "
        "temporary files automatically."
    )

    processes = []

    try:
        for name in (
            authority,
            other,
        ):
            command = [
                sys.executable,
                str(desktop_script),
                "--profile",
                str(profiles[name]),
                "--listen-ports",
                *(str(p) for p in local[name]),
                "--lock-port",
                str(ports[6]),
                "--validation-port",
                str(ports[7]),
            ]

            processes.append(
                subprocess.Popen(
                    command,
                    cwd=str(scripts.parent),
                )
            )

        print(
            "Opened two independent SyncBridge "
            "desktop processes."
        )

    except Exception:
        for proc in processes:
            proc.terminate()

        raise


if __name__ == "__main__":
    main()
