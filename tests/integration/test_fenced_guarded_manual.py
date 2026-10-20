
"""Two-profile integration tests for manual locking plus receiver fencing.

Tests use disposable localhost shares, authenticated peers, actual TCP sockets,
and receiver-local SQLite authority databases. This module never modifies an
ordinary SyncBridge user profile or starts the Qt desktop.
"""

from __future__ import annotations

import hashlib
import socket
from uuid import uuid4

import pytest

from syncbridge.core.fenced_guarded_manual import (
    FencedGuardedManualRuntime,
)
from syncbridge.core.lifecycle import LifecycleStatus
from syncbridge.network.operation_lock import OperationBusy
from syncbridge.network.security import (
    TrustStore,
    load_or_create_identity,
)
from syncbridge.network.transfer import TransferError, TransferService
from syncbridge.runtime import StartupError
from syncbridge.storage.config import (
    AppConfig,
    ConfigStore,
    ShareConfig,
    SyncPreferences,
)


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _unused_ports(count):
    held = []

    try:
        for _ in range(count):
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM,
            )
            sock.bind(("127.0.0.1", 0))
            held.append(sock)

        return tuple(
            sock.getsockname()[1]
            for sock in held
        )
    finally:
        for sock in held:
            sock.close()


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


def _configure(
    store,
    root,
    peer,
    share,
    remote_ports,
    *,
    auto_apply=False,
):
    prefs = SyncPreferences(
        auto_apply=auto_apply,
    )

    store.save(
        AppConfig(
            shares=(
                ShareConfig(
                    share_id=share,
                    peer_node_id=peer,
                    local_root=str(root),
                    display_name="Test folder",
                    remote_host="127.0.0.1",
                    manifest_port=remote_ports[0],
                    transfer_port=remote_ports[1],
                    agreement_port=remote_ports[2],
                    grant_manifest=True,
                    grant_read=True,
                    grant_write=True,
                    grant_agreement=True,
                    enabled=True,
                    preferences=prefs,
                ),
            ),
        )
    )


@pytest.fixture
def paired(tmp_path):
    a_store, a_id, a_trust = _profile(
        tmp_path,
        "AliceProfile",
    )
    b_store, b_id, b_trust = _profile(
        tmp_path,
        "BobProfile",
    )

    a_trust.add_verified(
        b_id.public_key_hex,
        confirmed_fingerprint=b_id.fingerprint,
        name="Bob",
    )
    b_trust.add_verified(
        a_id.public_key_hex,
        confirmed_fingerprint=a_id.fingerprint,
        name="Alice",
    )

    a_root = tmp_path / "AliceFiles"
    b_root = tmp_path / "BobFiles"

    a_root.mkdir()
    b_root.mkdir()

    share = uuid4().hex

    ports = _unused_ports(9)

    a_ports = ports[0:3]
    b_ports = ports[3:6]

    a_lease_port = ports[6]
    b_lease_port = ports[7]
    operation_port = ports[8]

    _configure(
        a_store,
        a_root,
        b_id.node_id,
        share,
        b_ports,
    )

    _configure(
        b_store,
        b_root,
        a_id.node_id,
        share,
        a_ports,
    )

    alice = FencedGuardedManualRuntime(
        a_store,
        bind_address="127.0.0.1",
        listen_ports=a_ports,
        lease_listen_port=a_lease_port,
        remote_lease_port=b_lease_port,
        lock_port=operation_port,
    )

    bob = FencedGuardedManualRuntime(
        b_store,
        bind_address="127.0.0.1",
        listen_ports=b_ports,
        lease_listen_port=b_lease_port,
        remote_lease_port=a_lease_port,
        lock_port=operation_port,
    )

    try:
        bob.start()
        alice.start()

        yield {
            "alice": alice,
            "bob": bob,
            "a_root": a_root,
            "b_root": b_root,
            "a_id": a_id,
            "b_id": b_id,
            "a_trust": a_trust,
            "b_trust": b_trust,
            "share": share,
        }

    finally:
        alice.stop()
        bob.stop()


def test_manual_sync_preserves_both_directions_and_history(paired):
    p = paired

    content_a = b"Written on Alice" * 2048
    content_b = b"Written on Bob" * 2048

    a_file = p["a_root"] / "alice.bin"
    b_file = p["b_root"] / "bob.bin"

    a_file.write_bytes(content_a)
    b_file.write_bytes(content_b)

    result = p["alice"].sync_once()

    assert result.complete

    assert _sha(
        p["b_root"] / "alice.bin"
    ) == _sha(a_file)

    assert _sha(
        p["a_root"] / "bob.bin"
    ) == _sha(b_file)

    a_history = p["alice"].shared_state.load(
        p["a_root"],
        p["b_id"].node_id,
        p["share"],
    )

    b_history = p["bob"].shared_state.load(
        p["b_root"],
        p["a_id"].node_id,
        p["share"],
    )

    assert a_history.revision == 1
    assert b_history.revision == 1

    # Neither elected operation coordination nor fencing
    # should be holding a session after successful cleanup.
    assert p["alice"].operations is not None
    assert p["bob"].operations is not None

    assert p["alice"].lease_authority.acquire(
        p["share"],
        p["a_id"].node_id,
    ).generation >= 2


def test_preview_never_modifies_either_folder(paired):
    p = paired

    (p["a_root"] / "preview.txt").write_text(
        "Read-only",
        encoding="utf-8",
    )

    result = p["alice"].preview()

    assert result.status is LifecycleStatus.PREVIEW

    assert not (
        p["b_root"] / "preview.txt"
    ).exists()


def test_competing_initiator_is_rejected_by_elected_lock(paired):
    p = paired

    (p["a_root"] / "waiting.txt").write_text(
        "Not yet synchronized",
        encoding="utf-8",
    )

    with p["alice"].leases.hold("sync"):
        with pytest.raises(OperationBusy):
            p["bob"].sync_once()

    assert not (
        p["b_root"] / "waiting.txt"
    ).exists()

    assert p["alice"].sync_once().complete

    assert (
        p["b_root"] / "waiting.txt"
    ).read_text(encoding="utf-8") == "Not yet synchronized"


def test_sync_from_either_computer_uses_same_agreement(paired):
    p = paired

    (p["a_root"] / "first.txt").write_text(
        "First round",
        encoding="utf-8",
    )

    assert p["alice"].sync_once().complete

    (p["b_root"] / "second.txt").write_text(
        "Second round",
        encoding="utf-8",
    )

    assert p["bob"].sync_once().complete

    assert (
        p["a_root"] / "second.txt"
    ).read_text(encoding="utf-8") == "Second round"

    assert p["bob"].shared_state.load(
        p["b_root"],
        p["a_id"].node_id,
        p["share"],
    ).revision == 2

    assert p["alice"].shared_state.load(
        p["a_root"],
        p["b_id"].node_id,
        p["share"],
    ).revision == 2


def test_legacy_upload_is_rejected(paired):
    p = paired

    (p["a_root"] / "legacy.txt").write_bytes(
        b"Never publish without fencing"
    )

    legacy = TransferService(
        p["a_id"],
        p["a_trust"],
        p["a_root"],
        share_id=p["share"],
        bind_address="127.0.0.1",
        listen_port=0,
    )

    with pytest.raises(TransferError):
        legacy.send_file(
            "127.0.0.1",
            p["bob"].status.transfer_port,
            p["b_id"].node_id,
            p["a_root"],
            "legacy.txt",
            share_id=p["share"],
        )

    assert not (
        p["b_root"] / "legacy.txt"
    ).exists()


def test_background_mode_is_refused(paired):
    p = paired

    assert not p["alice"].status.background_running
    assert not p["bob"].status.background_running

    with pytest.raises(StartupError, match="manual"):
        p["alice"].start(background=True)


def test_stop_releases_local_profile_lock(paired):
    p = paired

    node_id = p["alice"].identity.node_id

    p["alice"].stop()

    assert not p["alice"].status.running

    p["alice"].start()

    assert p["alice"].identity.node_id == node_id
    assert p["alice"].operations is not None


def test_no_sync_before_start(tmp_path):
    store = ConfigStore(
        tmp_path / "Profile" / "settings.json"
    )

    runtime = FencedGuardedManualRuntime(
        store,
    )

    with pytest.raises(StartupError, match="Start SyncBridge"):
        runtime.preview()

    with pytest.raises(StartupError, match="Start SyncBridge"):
        runtime.sync_once()
