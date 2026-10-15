
"""Application composition, fail-closed startup, and localhost end-to-end tests."""

from __future__ import annotations

import time
from pathlib import Path
from uuid import uuid4

import pytest

from syncbridge.runtime import (
    InstanceAlreadyRunning,
    StartupError,
    SyncBridgeRuntime,
)
from syncbridge.network.manifest import ManifestError, ManifestService
from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.storage.config import (
    AppConfig,
    ConfigStore,
    ShareConfig,
    SyncPreferences,
)


def profile(tmp_path: Path, name: str):
    home = tmp_path / name
    home.mkdir()
    store = ConfigStore(home / "settings.json")
    identity = load_or_create_identity(home / "identity.json")
    trust = TrustStore(home / "trust.json")
    return store, identity, trust


def configure(
    store,
    root,
    peer_id,
    share,
    *,
    ports=(45843, 45842, 45844),
    enabled=True,
    host="127.0.0.1",
    all_grants=True,
    prefs=None,
):
    folder = ShareConfig(
        share_id=share,
        peer_node_id=peer_id,
        local_root=str(root),
        display_name="Documents",
        remote_host=host,
        manifest_port=ports[0],
        transfer_port=ports[1],
        agreement_port=ports[2],
        enabled=enabled,
        grant_manifest=all_grants,
        grant_read=all_grants,
        grant_write=all_grants,
        grant_agreement=all_grants,
        preferences=prefs or SyncPreferences(),
    )
    store.save(AppConfig(shares=(folder,)))


def pair(tmp_path):
    sa, alice, ta = profile(tmp_path, "a-profile")
    sb, bob, tb = profile(tmp_path, "b-profile")

    ta.add_verified(
        bob.public_key_hex,
        confirmed_fingerprint=bob.fingerprint,
        name="Bob",
    )
    tb.add_verified(
        alice.public_key_hex,
        confirmed_fingerprint=alice.fingerprint,
        name="Alice",
    )

    ar = tmp_path / "a-folder"
    br = tmp_path / "b-folder"
    ar.mkdir()
    br.mkdir()

    share = uuid4().hex

    return sa, sb, alice, bob, ta, tb, ar, br, share


def test_empty_profile_starts_without_exposing_network(tmp_path):
    store = ConfigStore(tmp_path / "profile" / "settings.json")
    runtime = SyncBridgeRuntime(store)

    status = runtime.start()

    assert status.running
    assert status.node_id
    assert status.share_id is None
    assert status.manifest_port is None
    assert not status.background_running
    assert runtime.sync_service is None

    runtime.stop()

    assert not runtime.status.running
    assert runtime.start().node_id == status.node_id

    runtime.stop()


def test_disabled_share_does_not_open_listeners(tmp_path):
    store, _identity, _trust = profile(tmp_path, "profile")
    root = tmp_path / "files"
    root.mkdir()

    configure(
        store,
        root,
        uuid4().hex,
        uuid4().hex,
        enabled=False,
    )

    runtime = SyncBridgeRuntime(store)

    try:
        assert runtime.start(background=True).share_id is None
        assert runtime.manifest_server is None
        assert runtime.sync_service is None
    finally:
        runtime.stop()


def test_missing_folder_rejected_and_lock_released(tmp_path):
    store, _identity, _trust = profile(tmp_path, "profile")

    configure(
        store,
        tmp_path / "missing",
        uuid4().hex,
        uuid4().hex,
    )

    runtime = SyncBridgeRuntime(store)

    with pytest.raises(StartupError, match="missing"):
        runtime.start()

    with pytest.raises(StartupError, match="missing"):
        SyncBridgeRuntime(store).start()

    assert not runtime.status.running


def test_unpaired_peer_rejected_before_listeners(tmp_path):
    store, _identity, _trust = profile(tmp_path, "profile")
    folder = tmp_path / "folder"
    folder.mkdir()

    configure(
        store,
        folder,
        uuid4().hex,
        uuid4().hex,
    )

    runtime = SyncBridgeRuntime(
        store,
        listen_ports=(0, 0, 0),
    )

    with pytest.raises(StartupError, match="paired"):
        runtime.start()

    assert runtime.manifest_server is None
    assert not runtime.status.running


def test_missing_remote_address_rejected(tmp_path):
    store, _identity, _trust = profile(tmp_path, "profile")
    root = tmp_path / "folder"
    root.mkdir()

    configure(
        store,
        root,
        uuid4().hex,
        uuid4().hex,
        host=None,
    )

    with pytest.raises(StartupError, match="remote IPv4"):
        SyncBridgeRuntime(store).start()


def test_rejects_multiple_enabled_shares(tmp_path):
    store, alice, trust = profile(tmp_path, "profile")
    bob = load_or_create_identity(tmp_path / "bob.json")

    trust.add_verified(
        bob.public_key_hex,
        confirmed_fingerprint=bob.fingerprint,
        name="Bob",
    )

    roots = [tmp_path / "one", tmp_path / "two"]

    for root in roots:
        root.mkdir()

    one = ShareConfig(
        uuid4().hex,
        bob.node_id,
        str(roots[0]),
        "One",
        enabled=True,
        remote_host="127.0.0.1",
    )
    two = ShareConfig(
        uuid4().hex,
        bob.node_id,
        str(roots[1]),
        "Two",
        enabled=True,
        remote_host="127.0.0.1",
    )

    store.save(AppConfig(shares=(one, two)))

    with pytest.raises(StartupError, match="one enabled share"):
        SyncBridgeRuntime(store).start()


def test_second_runtime_cannot_own_same_profile(tmp_path):
    store = ConfigStore(tmp_path / "profile" / "settings.json")
    first = SyncBridgeRuntime(store)
    second = SyncBridgeRuntime(store)

    try:
        first.start()

        with pytest.raises(InstanceAlreadyRunning):
            second.start()
    finally:
        first.stop()

    assert second.start().running
    second.stop()


def test_stop_is_idempotent_and_context_manager(tmp_path):
    store = ConfigStore(tmp_path / "profile" / "settings.json")
    runtime = SyncBridgeRuntime(store)

    runtime.stop()

    with runtime as active:
        assert active.status.running

    assert not runtime.status.running

    runtime.stop()


def test_invalid_construction_and_arguments(tmp_path):
    with pytest.raises(TypeError):
        SyncBridgeRuntime(object())

    with pytest.raises(ValueError):
        SyncBridgeRuntime(listen_ports=(0, 1))

    with pytest.raises(ValueError):
        SyncBridgeRuntime(listen_ports=(0, True, 2))

    runtime = SyncBridgeRuntime(
        ConfigStore(tmp_path / "settings.json")
    )

    with pytest.raises(TypeError):
        runtime.start(background="yes")


def test_real_two_way_sync_and_persistence_across_restart(tmp_path):
    sa, sb, alice, bob, ta, tb, ar, br, share = pair(tmp_path)

    configure(sb, br, alice.node_id, share)

    server = SyncBridgeRuntime(
        sb,
        listen_ports=(0, 0, 0),
    )
    server.start()

    ports = (
        server.status.manifest_port,
        server.status.transfer_port,
        server.status.agreement_port,
    )

    configure(sa, ar, bob.node_id, share, ports=ports)

    client = SyncBridgeRuntime(
        sa,
        listen_ports=(0, 0, 0),
    )

    try:
        client.start()

        assert not client.status.background_running

        (ar / "from-a.txt").write_text("from A")
        (br / "from-b.txt").write_text("from B")

        result = client.lifecycle.run_once(apply=True)

        assert result.complete
        assert (ar / "from-b.txt").read_text() == "from B"
        assert (br / "from-a.txt").read_text() == "from A"

        assert client.shared_state.load(
            ar, bob.node_id, share
        ).revision == 1

        assert server.shared_state.load(
            br, alice.node_id, share
        ).revision == 1

        node_id = client.identity.node_id

        client.stop()
        client.start()

        assert client.identity.node_id == node_id
        assert client.lifecycle.run_once(apply=True).complete

        assert client.shared_state.load(
            ar, bob.node_id, share
        ).revision == 1

    finally:
        client.stop()
        server.stop()


def test_zero_grants_deny_remote_manifest(tmp_path):
    sa, sb, alice, bob, ta, tb, ar, br, share = pair(tmp_path)

    configure(
        sb,
        br,
        alice.node_id,
        share,
        all_grants=False,
    )

    server = SyncBridgeRuntime(
        sb,
        listen_ports=(0, 0, 0),
    )
    server.start()

    try:
        reader = ManifestService(alice, ta)

        with pytest.raises(ManifestError, match="not available"):
            reader.fetch(
                "127.0.0.1",
                server.status.manifest_port,
                bob.node_id,
                share,
            )

    finally:
        server.stop()


def test_start_background_preview_only_by_default(tmp_path):
    sa, sb, alice, bob, ta, tb, ar, br, share = pair(tmp_path)

    configure(sb, br, alice.node_id, share)

    server = SyncBridgeRuntime(
        sb,
        listen_ports=(0, 0, 0),
    )
    server.start()

    ports = (
        server.status.manifest_port,
        server.status.transfer_port,
        server.status.agreement_port,
    )

    configure(
        sa,
        ar,
        bob.node_id,
        share,
        ports=ports,
        prefs=SyncPreferences(
            poll_interval=0.2,
            watch_interval=0.1,
            settle_delay=0.1,
        ),
    )

    (ar / "new.txt").write_text("do not copy yet")

    client = SyncBridgeRuntime(
        sa,
        listen_ports=(0, 0, 0),
    )

    try:
        client.start(background=True)

        assert not client.sync_service.auto_apply
        assert client.status.background_running

        deadline = time.monotonic() + 3

        while (
            client.sync_service.status.last_result is None
            and time.monotonic() < deadline
        ):
            time.sleep(0.02)

        assert client.sync_service.status.last_result is not None
        assert not (br / "new.txt").exists()

    finally:
        client.stop()
        server.stop()


def test_start_with_invalid_bind_address_rolls_back(tmp_path):
    sa, sb, alice, bob, ta, tb, ar, br, share = pair(tmp_path)

    configure(sa, ar, bob.node_id, share)

    bad = SyncBridgeRuntime(
        sa,
        bind_address="not-ip",
        listen_ports=(0, 0, 0),
    )

    with pytest.raises(ValueError):
        bad.start()

    assert not bad.status.running

    good = SyncBridgeRuntime(
        sa,
        listen_ports=(0, 0, 0),
    )

    try:
        assert good.start().running
    finally:
        good.stop()
