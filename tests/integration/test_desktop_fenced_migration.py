
"""End-to-end acceptance tests for the operation-bound desktop controller.

Two independent paired desktop profiles use real authenticated localhost
services, separate folders and SQLite authorities.

Run both loopback-only and all-interfaces server bindings. No real user
profile, Qt event loop, discovery, or physical second computer is required.
"""
from __future__ import annotations

import hashlib
import socket
from uuid import uuid4

import pytest

from syncbridge.core.fenced_guarded_manual import (
    FencedGuardedManualRuntime,
)
from syncbridge.network.security import (
    TrustStore,
    load_or_create_identity,
)
from syncbridge.network.transfer import (
    TransferError,
    TransferService,
)
from syncbridge.storage.config import (
    AppConfig,
    ConfigStore,
    ShareConfig,
)
from syncbridge.ui.desktop_controller import DesktopController


def _sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _available_ports(amount: int) -> tuple[int, ...]:
    held = []

    try:
        for _ in range(amount):
            connection = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM,
            )
            connection.bind(("127.0.0.1", 0))
            held.append(connection)

        return tuple(
            connection.getsockname()[1]
            for connection in held
        )
    finally:
        for connection in held:
            connection.close()


def _profile(tmp_path, name):
    home = tmp_path / name
    home.mkdir()

    store = ConfigStore(
        home / "settings.json"
    )

    identity = load_or_create_identity(
        home / "identity.json"
    )

    trust = TrustStore(
        home / "trust.json"
    )

    return store, identity, trust


def _configure(store, root, peer, share, remote_ports):
    store.save(
        AppConfig(
            device_name="Test device",
            shares=(
                ShareConfig(
                    share_id=share,
                    peer_node_id=peer.node_id,
                    local_root=str(root),
                    display_name="Shared test folder",
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


@pytest.fixture(params=["127.0.0.1", "0.0.0.0"])
def desktops(tmp_path, request):
    a_store, alice, a_trust = _profile(
        tmp_path,
        "AliceProfile",
    )

    b_store, bob, b_trust = _profile(
        tmp_path,
        "BobProfile",
    )

    a_trust.add_verified(
        bob.public_key_hex,
        confirmed_fingerprint=bob.fingerprint,
        name="Bob",
    )

    b_trust.add_verified(
        alice.public_key_hex,
        confirmed_fingerprint=alice.fingerprint,
        name="Alice",
    )

    a_root = tmp_path / "AliceFiles"
    b_root = tmp_path / "BobFiles"

    a_root.mkdir()
    b_root.mkdir()

    share = uuid4().hex
    ports = _available_ports(10)

    a_ports = ports[0:3]
    b_ports = ports[3:6]

    a_lease = ports[6]
    b_lease = ports[7]
    operation_port = ports[8]
    validation_port = ports[9]

    _configure(
        a_store,
        a_root,
        bob,
        share,
        b_ports,
    )

    _configure(
        b_store,
        b_root,
        alice,
        share,
        a_ports,
    )

    options = {
        "bind_address": request.param,
        "lock_port": operation_port,
        "validation_port": validation_port,
    }

    a_desktop = DesktopController(
        a_store,
        listen_ports=a_ports,
        lease_listen_port=a_lease,
        remote_lease_port=b_lease,
        **options,
    )

    b_desktop = DesktopController(
        b_store,
        listen_ports=b_ports,
        lease_listen_port=b_lease,
        remote_lease_port=a_lease,
        **options,
    )

    try:
        b_desktop.start()
        a_desktop.start()

        yield {
            "a": a_desktop,
            "b": b_desktop,
            "a_root": a_root,
            "b_root": b_root,
            "alice": alice,
            "bob": bob,
            "a_trust": a_trust,
            "share": share,
            "bind_address": request.param,
        }

    finally:
        a_desktop.stop()
        b_desktop.stop()


def test_desktop_selects_fenced_runtime(desktops):
    p = desktops

    for controller in (p["a"], p["b"]):
        assert isinstance(
            controller.runtime,
            FencedGuardedManualRuntime,
        )

        assert controller.running

        assert controller.runtime.transfer_server.is_running
        assert controller.runtime.lease_server.bound_port is not None

        # The old unfenced write listener is not the active receiver.
        assert (
            type(controller.runtime.transfer_server).__name__
            == "OperationBoundDuplexService"
        )


def test_desktop_preview_then_sync_in_both_directions(desktops):
    p = desktops

    content_a = b"Created by Alice" * 4096
    content_b = b"Created by Bob" * 4096

    (
        p["a_root"] / "alice.bin"
    ).write_bytes(content_a)

    (
        p["b_root"] / "bob.bin"
    ).write_bytes(content_b)

    preview = p["a"].preview()

    assert {
        item.action
        for item in preview.items
    } == {"Send", "Receive"}

    assert not (
        p["b_root"] / "alice.bin"
    ).exists()

    assert not (
        p["a_root"] / "bob.bin"
    ).exists()

    result = p["a"].sync_once()

    assert result.complete

    assert _sha(
        (
            p["b_root"] / "alice.bin"
        ).read_bytes()
    ) == _sha(content_a)

    assert _sha(
        (
            p["a_root"] / "bob.bin"
        ).read_bytes()
    ) == _sha(content_b)

    assert p["a"].runtime.shared_state.load(
        p["a_root"],
        p["bob"].node_id,
        p["share"],
    ).revision == 1

    assert p["b"].runtime.shared_state.load(
        p["b_root"],
        p["alice"].node_id,
        p["share"],
    ).revision == 1

    (
        p["b_root"] / "second-round.txt"
    ).write_text("From Bob", encoding="utf-8")

    assert p["b"].sync_once().complete

    assert (
        p["a_root"] / "second-round.txt"
    ).read_text(encoding="utf-8") == "From Bob"


def test_desktop_rejects_legacy_incoming_upload(desktops):
    p = desktops

    (
        p["a_root"] / "legacy.txt"
    ).write_text(
        "Must never bypass fencing",
        encoding="utf-8",
    )

    legacy = TransferService(
        p["alice"],
        p["a_trust"],
        p["a_root"],
        share_id=p["share"],
        bind_address="127.0.0.1",
        listen_port=0,
    )

    with pytest.raises(TransferError):
        legacy.send_file(
            "127.0.0.1",
            p["b"].runtime.status.transfer_port,
            p["bob"].node_id,
            p["a_root"],
            "legacy.txt",
            share_id=p["share"],
        )

    assert not (
        p["b_root"] / "legacy.txt"
    ).exists()


def test_desktop_restarts_without_losing_pairing(desktops):
    p = desktops

    controller = p["a"]

    original_identity = controller.runtime.identity.node_id

    controller.stop()

    assert not controller.running

    controller.start()

    assert controller.running

    assert controller.runtime.identity.node_id == original_identity

    (
        p["a_root"] / "after-restart.txt"
    ).write_text(
        "Still trusted",
        encoding="utf-8",
    )

    assert controller.sync_once().complete

    assert (
        p["b_root"] / "after-restart.txt"
    ).read_text(encoding="utf-8") == "Still trusted"


def test_wildcard_authority_can_validate_sync_over_loopback(desktops):
    p = desktops

    authority = (
        p["a"].runtime
        if p["a"].runtime.operation_authority is not None
        else p["b"].runtime
    )

    assert authority.validation_service is not None

    assert (
        authority.validation_service.bind_address
        == p["bind_address"]
    )

    (
        p["a_root"] / "network-check.txt"
    ).write_text(
        "Reachable through authenticated validation",
        encoding="utf-8",
    )

    assert p["a"].sync_once().complete

    assert (
        p["b_root"] / "network-check.txt"
    ).read_text(encoding="utf-8") == (
        "Reachable through authenticated validation"
    )
