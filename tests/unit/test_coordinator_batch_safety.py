
"""Safety contracts for future SyncBridge sync batching.

These tests exercise real authenticated loopback manifest and transfer
services using disposable folders. They protect against stale file states,
unexpected baseline changes, and conditional-overwrite races.

The first four tests verify the current full-inventory validation boundaries.
Any future batching optimization must retain equivalent protection, even if
the implementation no longer uses the same number of inventory requests.
"""
from __future__ import annotations

import pytest

from syncbridge.core.conflicts import SyncAction
from syncbridge.core.coordinator import (
    CoordinationError,
    StaleSyncState,
)
from syncbridge.core.scanner import FileScanner
from syncbridge.network.transfer import TransferError

from test_coordinator_v2 import baseline, pair


def _prepare_two_uploads(pair):
    """Create two independent uploads with a deterministic order."""
    local, remote, coordinator, *_ = pair

    (local / "a-first.txt").write_text(
        "Alice's first file",
        encoding="utf-8",
    )
    (local / "z-second.txt").write_text(
        "Alice's second file",
        encoding="utf-8",
    )

    preview = coordinator.inspect()

    assert [
        (decision.path, decision.action)
        for decision in preview.plan.decisions
    ] == [
        ("a-first.txt", SyncAction.UPLOAD),
        ("z-second.txt", SyncAction.UPLOAD),
    ]

    return local, remote, coordinator, preview


def _after_first_verified_transfer(
    monkeypatch,
    coordinator,
    change,
):
    """Inject a concurrent change immediately after the first post-check.

    This is the exact gap a naive optimization could leave unprotected:
    one file has been transferred and verified, but the next file has
    not yet been transferred.

    The injection is synchronous and deterministic; no timing sleeps or
    background races are needed.
    """
    original_validate = coordinator._validate_current
    attempts = []

    def validate_with_interleaving(*args, **kwargs):
        attempts.append(len(attempts) + 1)

        # Preserve the complete original validation.
        original_validate(*args, **kwargs)

        # Call 1: validation before first transfer.
        # Call 2: validation after first transfer.
        # The modification happens after Call 2 has succeeded.
        if len(attempts) == 2:
            change()

    monkeypatch.setattr(
        coordinator,
        "_validate_current",
        validate_with_interleaving,
    )

    return attempts


def test_remote_edit_between_transfers_blocks_next_upload(
    pair,
    monkeypatch,
):
    local, remote, coordinator, preview = _prepare_two_uploads(
        pair
    )

    def concurrent_change():
        (remote / "unexpected.txt").write_text(
            "Changed by another remote application",
            encoding="utf-8",
        )

    attempts = _after_first_verified_transfer(
        monkeypatch,
        coordinator,
        concurrent_change,
    )

    with pytest.raises(
        StaleSyncState,
        match="Remote files changed",
    ):
        coordinator.execute_changes(preview)

    assert len(attempts) == 3

    # The first completed transfer remains valid.
    assert (
        remote / "a-first.txt"
    ).read_text(encoding="utf-8") == "Alice's first file"

    # The coordinator must not initiate the next planned transfer.
    assert not (remote / "z-second.txt").exists()

    # Never discard the third-party writer's content.
    assert (
        remote / "unexpected.txt"
    ).read_text(encoding="utf-8") == (
        "Changed by another remote application"
    )

    assert (local / "z-second.txt").exists()


def test_local_edit_between_transfers_blocks_next_upload(
    pair,
    monkeypatch,
):
    local, remote, coordinator, preview = _prepare_two_uploads(
        pair
    )

    def concurrent_change():
        (local / "unexpected-local.txt").write_text(
            "Unsynchronized local modification",
            encoding="utf-8",
        )

    attempts = _after_first_verified_transfer(
        monkeypatch,
        coordinator,
        concurrent_change,
    )

    with pytest.raises(
        StaleSyncState,
        match="Local files changed",
    ):
        coordinator.execute_changes(preview)

    assert len(attempts) == 3

    assert (remote / "a-first.txt").exists()
    assert not (remote / "z-second.txt").exists()

    assert (
        local / "unexpected-local.txt"
    ).read_text(encoding="utf-8") == (
        "Unsynchronized local modification"
    )


def test_remote_deletion_between_transfers_is_not_silently_ignored(
    pair,
    monkeypatch,
):
    local, remote, coordinator, *_ = pair

    # An unchanged shared file must also be protected, even though it
    # is not one of the files scheduled for transfer.
    (local / "keep.txt").write_text(
        "Important existing data",
        encoding="utf-8",
    )
    (remote / "keep.txt").write_text(
        "Important existing data",
        encoding="utf-8",
    )

    (local / "a-first.txt").write_text(
        "First upload",
        encoding="utf-8",
    )
    (local / "z-second.txt").write_text(
        "Second upload",
        encoding="utf-8",
    )

    preview = coordinator.inspect()

    assert [
        decision.path
        for decision in preview.plan.decisions
    ] == [
        "a-first.txt",
        "z-second.txt",
    ]

    def concurrent_deletion():
        (remote / "keep.txt").unlink()

    attempts = _after_first_verified_transfer(
        monkeypatch,
        coordinator,
        concurrent_deletion,
    )

    with pytest.raises(
        StaleSyncState,
        match="Remote files changed",
    ):
        coordinator.execute_changes(preview)

    assert len(attempts) == 3

    assert (remote / "a-first.txt").exists()
    assert not (remote / "z-second.txt").exists()

    # Sync must neither restore nor propagate this deletion
    # without a separate, reviewed decision.
    assert not (remote / "keep.txt").exists()
    assert (
        local / "keep.txt"
    ).read_text(encoding="utf-8") == (
        "Important existing data"
    )


def test_new_baseline_proposal_between_transfers_blocks_sync(
    pair,
    monkeypatch,
):
    local, remote, coordinator, ad, _, _, bob, share, *_ = pair

    _, _, _, preview = _prepare_two_uploads(pair)

    def concurrent_proposal():
        snapshot = FileScanner(local).scan()
        assert snapshot.complete

        ad.stage(
            local,
            bob.node_id,
            share,
            snapshot,
            expected_revision=0,
        )

    attempts = _after_first_verified_transfer(
        monkeypatch,
        coordinator,
        concurrent_proposal,
    )

    with pytest.raises(
        CoordinationError,
        match="Unresolved shared-baseline proposal",
    ):
        coordinator.execute_changes(preview)

    assert len(attempts) == 3

    assert ad.pending(
        local,
        bob.node_id,
        share,
    ) is not None

    assert (remote / "a-first.txt").exists()
    assert not (remote / "z-second.txt").exists()


def test_remote_destination_edit_immediately_before_upload_is_rejected(
    pair,
    monkeypatch,
):
    local, remote, coordinator, *_ = pair

    (local / "document.txt").write_text(
        "Original",
        encoding="utf-8",
    )
    (remote / "document.txt").write_text(
        "Original",
        encoding="utf-8",
    )

    baseline(pair)

    (local / "document.txt").write_text(
        "Alice's updated version",
        encoding="utf-8",
    )

    preview = coordinator.inspect()

    assert len(preview.plan.uploads) == 1

    original_send = coordinator.transfer_sender.send_file

    def concurrent_destination_edit(*args, **kwargs):
        # The coordinator's inventory validation already succeeded.
        # Another application changes the remote destination just
        # before the actual encrypted transfer begins.
        (remote / "document.txt").write_text(
            "Bob's unexpected new version",
            encoding="utf-8",
        )

        return original_send(*args, **kwargs)

    monkeypatch.setattr(
        coordinator.transfer_sender,
        "send_file",
        concurrent_destination_edit,
    )

    with pytest.raises(
        TransferError,
        match="Destination changed",
    ):
        coordinator.execute_changes(preview)

    assert (
        remote / "document.txt"
    ).read_text(encoding="utf-8") == (
        "Bob's unexpected new version"
    )

    assert (
        local / "document.txt"
    ).read_text(encoding="utf-8") == (
        "Alice's updated version"
    )


def test_local_destination_edit_immediately_before_download_is_rejected(
    pair,
    monkeypatch,
):
    local, remote, coordinator, *_ = pair

    (local / "document.txt").write_text(
        "Original",
        encoding="utf-8",
    )
    (remote / "document.txt").write_text(
        "Original",
        encoding="utf-8",
    )

    baseline(pair)

    (remote / "document.txt").write_text(
        "Bob's updated version",
        encoding="utf-8",
    )

    preview = coordinator.inspect()

    assert len(preview.plan.downloads) == 1

    original_fetch = coordinator.transfer_sender.fetch_file

    def concurrent_local_edit(*args, **kwargs):
        # Another local application modifies the destination after
        # planning but before the authenticated download writes it.
        (local / "document.txt").write_text(
            "Alice's unexpected new version",
            encoding="utf-8",
        )

        return original_fetch(*args, **kwargs)

    monkeypatch.setattr(
        coordinator.transfer_sender,
        "fetch_file",
        concurrent_local_edit,
    )

    with pytest.raises(
        TransferError,
        match="Destination changed",
    ):
        coordinator.execute_changes(preview)

    assert (
        local / "document.txt"
    ).read_text(encoding="utf-8") == (
        "Alice's unexpected new version"
    )

    assert (
        remote / "document.txt"
    ).read_text(encoding="utf-8") == (
        "Bob's updated version"
    )
