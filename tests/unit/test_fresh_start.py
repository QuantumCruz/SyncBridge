
"""Reset stale setup safely without deleting any previously shared files."""
from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from syncbridge.network.security import (
    DeviceIdentity,
    TrustStore,
    load_or_create_identity,
)
from syncbridge.storage.config import ConfigStore, ShareConfig
from syncbridge.storage.folder_change_recovery import FolderChangeJournal
from syncbridge.ui.fresh_start import FreshStartError, start_fresh_locally
from syncbridge.ui.readiness_jobs import ReadinessJobs


@pytest.fixture
def old_setup(tmp_path):
    profile = tmp_path / "Profile"
    profile.mkdir()

    root = tmp_path / "MyFiles"
    root.mkdir()

    contents = root / "important.txt"
    contents.write_text("Do not delete this file", encoding="utf-8")

    local = load_or_create_identity(profile / "identity.json")
    remote = DeviceIdentity.generate()

    trust = TrustStore(profile / "trust.json")
    trust.add_verified(
        remote.public_key_hex,
        confirmed_fingerprint=remote.fingerprint,
        name="Previous computer",
    )

    store = ConfigStore(profile / "settings.json")
    share = ShareConfig(
        share_id="a" * 32,
        peer_node_id=remote.node_id,
        local_root=str(root),
        display_name="Old connection",
        remote_host="127.0.0.1",
        enabled=True,
        grant_manifest=True,
        grant_read=True,
        grant_write=True,
        grant_agreement=True,
    )

    store.save(replace(store.load(), shares=(share,)))
    ReadinessJobs(profile).add(share.share_id, share.peer_node_id)

    return store, share, root, local, remote


def test_start_fresh_removes_saved_setup_but_keeps_files_identity(old_setup):
    store, share, root, identity, peer = old_setup
    path = store.path.parent / "identity.json"

    initial_key_digest = hashlib.sha256(
        path.read_bytes()
    ).hexdigest()

    result = start_fresh_locally(store, running=False)

    assert result.removed_shares == 1
    assert result.removed_devices == 1
    assert store.load().shares == ()
    assert TrustStore(store.path.parent / "trust.json").devices == ()
    assert ReadinessJobs(store.path.parent).entries() == ()

    assert (
        root / "important.txt"
    ).read_text(encoding="utf-8") == "Do not delete this file"

    assert hashlib.sha256(
        path.read_bytes()
    ).hexdigest() == initial_key_digest

    assert load_or_create_identity(path).node_id == identity.node_id


def test_start_fresh_requires_disconnected_runtime(old_setup):
    store, share, root, identity, peer = old_setup

    with pytest.raises(FreshStartError, match="Disconnect"):
        start_fresh_locally(store, running=True)

    assert store.load().shares == (share,)
    assert TrustStore(
        store.path.parent / "trust.json"
    ).get(peer.node_id)


def test_start_fresh_never_erases_unresolved_recovery(old_setup):
    store, share, root, identity, peer = old_setup
    journal = FolderChangeJournal(store)

    journal.begin("c" * 32, share)

    with pytest.raises(FreshStartError, match="recovery"):
        start_fresh_locally(store, running=False)

    assert journal.load() is not None
    assert store.load().shares == (share,)
    assert TrustStore(
        store.path.parent / "trust.json"
    ).get(peer.node_id)

    assert (root / "important.txt").exists()


def test_repeated_start_fresh_is_safe(old_setup):
    store, share, root, identity, peer = old_setup

    start_fresh_locally(store, running=False)
    result = start_fresh_locally(store, running=False)

    assert result.removed_shares == 0
    assert result.removed_devices == 0
    assert (root / "important.txt").exists()
