
"""Real localhost integration for opt-in guarded manual SyncBridge runtime."""
from __future__ import annotations

import socket
from uuid import uuid4

import pytest

from syncbridge.core.guarded_manual import GuardedManualRuntime
from syncbridge.network.operation_lock import OperationBusy, OperationLockError
from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.network.transfer import TransferError, TransferService
from syncbridge.runtime import InstanceAlreadyRunning, StartupError
from syncbridge.storage.config import AppConfig, ConfigStore, ShareConfig


def free_ports(amount: int) -> list[int]:
    ports = []

    while len(ports) < amount:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            candidate = sock.getsockname()[1]

        if candidate not in ports:
            ports.append(candidate)

    return ports


@pytest.fixture
def pair(tmp_path):
    share = uuid4().hex
    ports = free_ports(8)

    profiles = {}
    folders = {}
    identities = {}
    runtimes = {}
    stores = {}

    for name in ("alice", "bob"):
        profiles[name] = tmp_path / name / "Profile"
        folders[name] = tmp_path / name / "Shared"

        profiles[name].mkdir(parents=True)
        folders[name].mkdir()

        identities[name] = load_or_create_identity(
            profiles[name] / "identity.json"
        )

        stores[name] = ConfigStore(
            profiles[name] / "settings.json"
        )

    for name, other, offset, remote_offset in (
        ("alice", "bob", 0, 3),
        ("bob", "alice", 3, 0),
    ):
        trust = TrustStore(profiles[name] / "trust.json")
        peer = identities[other]

        trust.add_verified(
            peer.public_key_hex,
            confirmed_fingerprint=peer.fingerprint,
            name=other.capitalize(),
        )

        stores[name].save(
            AppConfig(
                device_name=name.capitalize(),
                shares=(
                    ShareConfig(
                        share_id=share,
                        peer_node_id=peer.node_id,
                        local_root=str(folders[name]),
                        display_name="Test folder",
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
            stores[name],
            bind_address="127.0.0.1",
            listen_ports=tuple(ports[offset:offset + 3]),
            lock_port=ports[6],
            validation_port=ports[7],
        )

    leader = min(
        identities,
        key=lambda name: identities[name].node_id,
    )
    follower = "bob" if leader == "alice" else "alice"

    try:
        runtimes[leader].start()
        runtimes[follower].start()

        yield {
            "runtimes": runtimes,
            "folders": folders,
            "identities": identities,
            "stores": stores,
            "profiles": profiles,
            "share": share,
            "leader": leader,
            "follower": follower,
        }

    finally:
        for name in (follower, leader):
            runtimes[name].stop()


def test_actual_two_way_guarded_sync_and_checkpoint(pair):
    a = pair["folders"]["alice"]
    b = pair["folders"]["bob"]
    rt = pair["runtimes"]

    (a / "a.txt").write_text(
        "Alice's document",
        encoding="utf-8",
    )
    (b / "b.txt").write_text(
        "Bob's document",
        encoding="utf-8",
    )

    result = rt["alice"].sync_once()

    assert result.complete
    assert result.checkpoint.baseline.revision == 1

    assert (
        (a / "b.txt").read_text(encoding="utf-8")
        == "Bob's document"
    )
    assert (
        (b / "a.txt").read_text(encoding="utf-8")
        == "Alice's document"
    )

    (b / "b.txt").write_text(
        "Updated from Bob",
        encoding="utf-8",
    )

    again = rt["bob"].sync_once()

    assert again.complete
    assert again.checkpoint.baseline.revision == 2
    assert (
        (a / "b.txt").read_text(encoding="utf-8")
        == "Updated from Bob"
    )


def test_direct_lifecycle_write_without_lease_fails_closed(pair):
    folder = pair["folders"]["alice"]

    (folder / "bypass.txt").write_text(
        "Must not cross"
    )

    runtime = pair["runtimes"]["alice"]

    with pytest.raises(
        TransferError,
        match="SB-OPS-403",
    ):
        runtime.lifecycle.run_once(apply=True)

    assert not (
        pair["folders"]["bob"] / "bypass.txt"
    ).exists()


def test_concurrent_peer_permission_refused_before_writes(pair):
    rt = pair["runtimes"]

    (
        pair["folders"]["bob"] / "waiting.txt"
    ).write_text("Queued")

    with rt["alice"].leases.hold("sync"):
        with pytest.raises(
            OperationBusy,
            match="SB-OPS-423",
        ):
            rt["bob"].sync_once()

        assert not (
            pair["folders"]["alice"] / "waiting.txt"
        ).exists()

    assert rt["bob"].sync_once().complete

    assert (
        pair["folders"]["alice"] / "waiting.txt"
    ).exists()


def test_plain_legacy_sender_is_rejected(pair):
    name = "alice"
    other = "bob"

    (
        pair["folders"][name] / "legacy.txt"
    ).write_bytes(b"legacy")

    rt = pair["runtimes"]

    sender = TransferService(
        pair["identities"][name],
        rt[name].trust_store,
        pair["folders"][name],
        share_id=pair["share"],
    )

    with pytest.raises(TransferError):
        sender.send_file(
            "127.0.0.1",
            rt[other].transfer_server.bound_port,
            pair["identities"][other].node_id,
            pair["folders"][name],
            "legacy.txt",
            share_id=pair["share"],
        )

    assert not (
        pair["folders"][other] / "legacy.txt"
    ).exists()


def test_authority_offline_refuses_new_sync(pair):
    follower = pair["follower"]
    leader = pair["leader"]
    rt = pair["runtimes"]

    (
        pair["folders"][follower] / "offline.txt"
    ).write_text("Not copied")

    rt[leader].operation_authority.stop()

    with pytest.raises(
        OperationLockError,
        match="SB-OPS-503",
    ):
        rt[follower].sync_once()

    assert not (
        pair["folders"][leader] / "offline.txt"
    ).exists()


def test_profile_exclusivity_still_applies(pair):
    old = pair["runtimes"]["alice"]

    duplicate = GuardedManualRuntime(
        pair["stores"]["alice"],
        bind_address="127.0.0.1",
        listen_ports=(0, 0, 0),
    )

    with pytest.raises(InstanceAlreadyRunning):
        duplicate.start()

    assert old.status.running


def test_preview_does_not_require_authority_lease(pair):
    runtime = pair["runtimes"]["alice"]

    with pair["runtimes"]["bob"].leases.hold("sync"):
        assert runtime.preview().status.value == "preview"


def test_background_mode_is_refused(pair):
    runtime = pair["runtimes"]["alice"]

    with pytest.raises(
        StartupError,
        match="manual",
    ):
        runtime.start(background=True)
