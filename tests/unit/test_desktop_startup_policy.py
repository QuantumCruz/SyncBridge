
"""Verify desktop clean-start behavior without sacrificing recovery safety."""
from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from scripts.desktop_qt import _prepare_profile
from syncbridge.network.security import (
    DeviceIdentity,
    TrustStore,
    load_or_create_identity,
)
from syncbridge.storage.config import ConfigStore, ShareConfig
from syncbridge.storage.folder_change_recovery import (
    FolderChangeJournal,
    FolderRecoveryError,
)
from syncbridge.ui.readiness_jobs import ReadinessJobs


@pytest.fixture
def saved_setup(tmp_path):
    profile = tmp_path / "profile"
    profile.mkdir()

    folder = tmp_path / "files"
    folder.mkdir()

    original = folder / "important.txt"
    original.write_text(
        "Do not delete this",
        encoding="utf-8",
    )

    identity = load_or_create_identity(
        profile / "identity.json"
    )
    remote = DeviceIdentity.generate()

    trust = TrustStore(profile / "trust.json")
    trust.add_verified(
        remote.public_key_hex,
        confirmed_fingerprint=remote.fingerprint,
        name="Cruz",
    )

    store = ConfigStore(profile / "settings.json")

    share = ShareConfig(
        share_id="a" * 32,
        peer_node_id=remote.node_id,
        local_root=str(folder),
        display_name="My folder",
        remote_host="127.0.0.1",
        enabled=True,
        grant_manifest=True,
        grant_read=True,
        grant_write=True,
        grant_agreement=True,
    )

    store.save(
        replace(store.load(), shares=(share,))
    )

    ReadinessJobs(profile).add(
        share.share_id,
        share.peer_node_id,
    )

    return store, share, identity, original, remote


def test_default_launch_starts_without_previous_connection(saved_setup):
    store, share, identity, original, remote = saved_setup

    before = hashlib.sha256(original.read_bytes()).digest()
    private_key = (
        store.path.parent / "identity.json"
    ).read_bytes()

    assert _prepare_profile(
        store, persistent=False
    ) == "fresh"

    assert store.load().shares == ()
    assert TrustStore(
        store.path.parent / "trust.json"
    ).devices == ()

    assert ReadinessJobs(
        store.path.parent
    ).entries() == ()

    assert hashlib.sha256(
        original.read_bytes()
    ).digest() == before

    assert (
        store.path.parent / "identity.json"
    ).read_bytes() == private_key

    assert load_or_create_identity(
        store.path.parent / "identity.json"
    ).node_id == identity.node_id


def test_explicit_profile_retains_saved_connection(saved_setup):
    store, share, _, original, remote = saved_setup

    assert _prepare_profile(
        store, persistent=True
    ) == "persistent"

    assert store.load().shares == (share,)

    assert TrustStore(
        store.path.parent / "trust.json"
    ).get(remote.node_id) is not None

    assert original.is_file()


def test_crash_checkpoint_overrides_clean_start(saved_setup):
    store, share, _, original, remote = saved_setup

    journal = FolderChangeJournal(store)
    journal.begin("c" * 32, share)

    assert _prepare_profile(
        store, persistent=False
    ) == "recovery"

    assert journal.load() is not None
    assert store.load().shares == (share,)

    assert TrustStore(
        store.path.parent / "trust.json"
    ).get(remote.node_id) is not None

    assert original.is_file()


def test_invalid_recovery_record_blocks_clean_start(saved_setup):
    store, share, _, _, remote = saved_setup

    journal = FolderChangeJournal(store)
    journal.begin("c" * 32, share)

    journal.path.write_bytes(
        b"damaged recovery record"
    )

    with pytest.raises(FolderRecoveryError):
        _prepare_profile(
            store, persistent=False
        )

    assert store.load().shares == (share,)

    assert TrustStore(
        store.path.parent / "trust.json"
    ).get(remote.node_id) is not None


def test_clean_start_is_repeatable(saved_setup):
    store, _, _, original, _ = saved_setup

    assert _prepare_profile(
        store, persistent=False
    ) == "fresh"

    assert _prepare_profile(
        store, persistent=False
    ) == "fresh"

    assert store.load().shares == ()
    assert original.is_file()
