
"""Crash-survivable checkpoints protect saved folder relationships."""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import replace

import pytest

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
from syncbridge.ui.connection_switch import forget_local_folder_connection

SESSION = "c" * 32


@pytest.fixture
def profile(tmp_path):
    directory = tmp_path / "Profile"
    directory.mkdir()

    root = tmp_path / "Shared"
    root.mkdir()
    (root / "keep.txt").write_text(
        "important test data", encoding="utf-8"
    )

    local = load_or_create_identity(directory / "identity.json")
    other = DeviceIdentity.generate()
    TrustStore(directory / "trust.json").add_verified(
        other.public_key_hex,
        confirmed_fingerprint=other.fingerprint,
        name="Bob",
    )

    store = ConfigStore(directory / "settings.json")
    share = ShareConfig(
        share_id="a" * 32,
        peer_node_id=other.node_id,
        local_root=str(root),
        display_name="Old folder",
        remote_host="127.0.0.1",
        enabled=True,
        grant_manifest=True,
        grant_read=True,
        grant_write=True,
        grant_agreement=True,
    )
    store.save(replace(store.load(), shares=(share,)))
    return store, share, local, root


def test_checkpoint_before_change_preserves_original(profile):
    store, share, _, root = profile
    journal = FolderChangeJournal(store)
    original_revision = store.load().revision

    checkpoint = journal.begin(SESSION, share)

    assert checkpoint.stage == "preparing"
    assert journal.load() == checkpoint
    assert store.load().shares == (share,)
    assert store.load().revision == original_revision
    assert (
        root / "keep.txt"
    ).read_text(encoding="utf-8") == "important test data"


def test_restore_old_connection_after_local_share_was_cleared(profile):
    store, share, _, root = profile
    journal = FolderChangeJournal(store)

    journal.begin(SESSION, share)
    journal.mark_committing(SESSION)
    forget_local_folder_connection(
        store,
        expected_share_id=share.share_id,
        running=False,
    )

    assert store.load().shares == ()

    restored = journal.restore_previous(running=False)

    assert restored == share
    assert store.load().shares == (share,)
    assert journal.load() is None
    assert (
        root / "keep.txt"
    ).read_text(encoding="utf-8") == "important test data"


def test_never_recover_while_running(profile):
    store, share, _, _ = profile
    journal = FolderChangeJournal(store)
    journal.begin(SESSION, share)

    with pytest.raises(FolderRecoveryError):
        journal.restore_previous(running=True)

    assert journal.load() is not None


def test_refuses_to_overwrite_another_new_share(profile, tmp_path):
    store, share, _, _ = profile
    journal = FolderChangeJournal(store)
    journal.begin(SESSION, share)

    new_folder = tmp_path / "New"
    new_folder.mkdir()
    new_share = replace(
        share,
        share_id="d" * 32,
        local_root=str(new_folder),
    )
    store.save(replace(store.load(), shares=(new_share,)))

    with pytest.raises(FolderRecoveryError):
        journal.restore_previous(running=False)

    assert store.load().shares == (new_share,)
    assert journal.load() is not None

    journal.mark_committing(SESSION)
    selected = journal.keep_replacement(running=False)

    assert selected == new_share
    assert journal.load() is None
    assert store.load().shares == (new_share,)


def test_finish_only_after_different_approved_share_connected(
    profile, tmp_path
):
    store, share, _, _ = profile
    journal = FolderChangeJournal(store)
    journal.begin(SESSION, share)

    with pytest.raises(FolderRecoveryError):
        journal.finish_if_connected(share)

    new_folder = tmp_path / "Replacement"
    new_folder.mkdir()
    new_share = replace(
        share,
        share_id="d" * 32,
        local_root=str(new_folder),
    )

    journal.mark_committing(SESSION)
    store.save(replace(store.load(), shares=(new_share,)))

    assert journal.finish_if_connected(new_share)
    assert journal.load() is None


def test_tampered_checkpoint_fails_closed(profile):
    store, share, _, _ = profile
    journal = FolderChangeJournal(store)
    journal.begin(SESSION, share)

    record = json.loads(
        journal.path.read_text(encoding="utf-8")
    )
    record["payload"]["original"]["local_root"] = "C:\\SomethingElse"
    journal.path.write_text(
        json.dumps(record), encoding="utf-8"
    )

    with pytest.raises(FolderRecoveryError):
        journal.load()

    assert store.load().shares == (share,)


def test_abrupt_child_exit_keeps_recovery_record(profile):
    store, share, local, root = profile

    script = (
        "import os,sys; "
        "from syncbridge.storage.config import ConfigStore; "
        "from syncbridge.storage.folder_change_recovery "
        "import FolderChangeJournal; "
        "s=ConfigStore(sys.argv[1]); "
        "FolderChangeJournal(s).begin('c'*32,s.load().shares[0]); "
        "os._exit(73)"
    )

    result = subprocess.run(
        [sys.executable, "-c", script, str(store.path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 73, result.stderr

    recovered = FolderChangeJournal(store).load()
    assert recovered is not None
    assert recovered.original == share
    assert store.load().shares == (share,)
    assert (root / "keep.txt").exists()
