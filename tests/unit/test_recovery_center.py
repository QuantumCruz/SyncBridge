
"""Recovery Center tests with real Phase 18 vault records and local locks."""
from __future__ import annotations

import hashlib
import json
from uuid import uuid4

import pytest

from syncbridge.core.approved_deletion import RecoveryVault
from syncbridge.core.recovery_center import (
    RecoveryCenter,
    RecoveryCenterError,
)
from syncbridge.network.deletion_approval import DeletionRequest
from syncbridge.runtime import _ProfileLock


@pytest.fixture
def world(tmp_path):
    profile = tmp_path / "Alice" / "Profile"
    root = tmp_path / "Alice" / "Shared"

    profile.mkdir(parents=True)
    root.mkdir()

    contents = b"An important recoverable document\n"

    path = root / "work" / "report.txt"
    path.parent.mkdir()
    path.write_bytes(contents)

    request = DeletionRequest(
        uuid4().hex,
        uuid4().hex,
        uuid4().hex,
        "work/report.txt",
        1,
        "a" * 64,
        hashlib.sha256(contents).hexdigest(),
        len(contents),
        "approved",
    )

    vault = RecoveryVault(
        root,
        profile / "Recovery",
    )
    saved = vault.preserve(request)
    center = RecoveryCenter(profile, root)

    return (
        profile,
        root,
        request,
        contents,
        path,
        saved,
        center,
    )


def test_lists_verified_recoverable_file(world):
    *_, request, contents, original, saved, center = world

    item, = center.list_items()

    assert item.request_id == request.request_id
    assert item.path == "work/report.txt"
    assert item.size == len(contents)
    assert item.code == "SB-RCV-301"
    assert item.can_restore

    assert not original.exists()
    assert saved.read_bytes() == contents


def test_restore_keeps_original_backup(world):
    profile, root, request, contents, original, saved, center = world

    assert center.restore(request.request_id) == original
    assert original.read_bytes() == contents
    assert saved.read_bytes() == contents

    after, = center.list_items()

    assert after.code == "SB-RCV-302"
    assert not after.can_restore


def test_repeated_restore_never_overwrites_existing_file(world):
    *_, request, contents, original, saved, center = world

    center.restore(request.request_id)
    original.write_bytes(b"new user content")

    with pytest.raises(
        RecoveryCenterError,
        match="SB-RCV-302",
    ):
        center.restore(request.request_id)

    assert original.read_bytes() == b"new user content"
    assert saved.read_bytes() == contents


def test_detects_new_file_at_original_location(world):
    *_, request, contents, original, saved, center = world

    original.write_bytes(b"recreated by the user")

    issue, = center.list_items()

    assert issue.code == "SB-RCV-302"

    with pytest.raises(
        RecoveryCenterError,
        match="SB-RCV-302",
    ):
        center.restore(request.request_id)

    assert original.read_bytes() == b"recreated by the user"


def test_missing_recovery_blob_is_reported(world):
    *_, request, contents, original, saved, center = world

    saved.unlink()

    issue, = center.list_items()

    assert issue.code == "SB-RCV-303"
    assert not issue.can_restore

    with pytest.raises(
        RecoveryCenterError,
        match="SB-RCV-303",
    ):
        center.restore(request.request_id)


def test_corrupt_recovery_blob_is_not_restored(world):
    *_, request, contents, original, saved, center = world

    saved.write_bytes(b"tampered data")

    issue, = center.list_items()

    assert issue.code == "SB-RCV-304"

    with pytest.raises(
        RecoveryCenterError,
        match="SB-RCV-304",
    ):
        center.restore(request.request_id)

    assert not original.exists()


def test_missing_parent_directory_requires_review(world):
    *_, request, contents, original, saved, center = world

    original.parent.rmdir()

    issue, = center.list_items()

    assert issue.code == "SB-RCV-306"

    with pytest.raises(
        RecoveryCenterError,
        match="SB-RCV-306",
    ):
        center.restore(request.request_id)

    original.parent.mkdir()

    assert (
        center.restore(request.request_id).read_bytes()
        == contents
    )


def test_invalid_journal_path_is_never_followed(world):
    profile, root, request, contents, original, saved, center = world

    journal = (
        profile
        / "Recovery"
        / f"{request.request_id}.json"
    )

    data = json.loads(
        journal.read_text(encoding="utf-8")
    )
    data["path"] = "../outside.txt"

    journal.write_text(
        json.dumps(data),
        encoding="utf-8",
    )

    issue, = center.list_items()

    assert issue.code == "SB-RCV-304"

    with pytest.raises(
        RecoveryCenterError,
        match="SB-RCV-304",
    ):
        center.restore(request.request_id)

    assert saved.exists()


def test_invalid_journal_digest_is_never_restored(world):
    profile, root, request, contents, original, saved, center = world

    journal = (
        profile
        / "Recovery"
        / f"{request.request_id}.json"
    )

    data = json.loads(
        journal.read_text(encoding="utf-8")
    )
    data["file_sha256"] = "invalid"

    journal.write_text(
        json.dumps(data),
        encoding="utf-8",
    )

    assert (
        center.list_items()[0].code
        == "SB-RCV-304"
    )


def test_orphaned_blob_is_reported_without_restore(world):
    profile, root, request, contents, original, saved, center = world

    journal = (
        profile
        / "Recovery"
        / f"{request.request_id}.json"
    )
    journal.unlink()

    issue, = center.list_items()

    assert issue.code == "SB-RCV-305"
    assert not issue.can_restore

    with pytest.raises(
        RecoveryCenterError,
        match="No recovery record",
    ):
        center.restore(request.request_id)


def test_running_runtime_profile_blocks_restore(world):
    profile, root, request, contents, original, saved, center = world

    lock = _ProfileLock(
        profile / "instance.lock"
    )
    lock.acquire()

    try:
        with pytest.raises(
            RecoveryCenterError,
            match="SB-RCV-409",
        ):
            center.restore(request.request_id)

        assert not original.exists()

    finally:
        lock.release()

    assert center.restore(request.request_id) == original


def test_invalid_recovery_id_rejected(world):
    *_, center = world

    for value in (
        "",
        "../escape",
        "A" * 32,
        "q" * 32,
    ):
        with pytest.raises(
            ValueError,
            match="Recovery ID",
        ):
            center.restore(value)


def test_missing_id_refused_and_lock_released(world):
    profile, root, request, contents, original, saved, center = world

    with pytest.raises(
        RecoveryCenterError,
        match="No recovery record",
    ):
        center.restore(uuid4().hex)

    assert center.restore(request.request_id) == original


def test_profile_cannot_be_inside_shared_folder(tmp_path):
    root = tmp_path / "Shared"
    profile = root / "Profile"
    profile.mkdir(parents=True)

    with pytest.raises(ValueError):
        RecoveryCenter(profile, root)


def test_empty_vault_has_no_recovery_items(tmp_path):
    profile = tmp_path / "Profile"
    root = tmp_path / "Shared"

    profile.mkdir()
    root.mkdir()

    assert (
        RecoveryCenter(profile, root).list_items()
        == ()
    )
