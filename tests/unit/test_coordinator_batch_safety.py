
"""Safety contracts for consolidated full-inventory validation.

All tests use the existing authenticated loopback peer fixture, real files,
and conditional transfers. Changes are injected *after a completed transfer*,
not at a particular private validation call number. This makes these checks
meaningful even when the coordinator's validation schedule changes.
"""
from __future__ import annotations

import threading

import pytest

from syncbridge.core.conflicts import SyncAction
from syncbridge.core.coordinator import CoordinationError, StaleSyncState
from syncbridge.core.scanner import FileScanner
from syncbridge.network.transfer import TransferError

from test_coordinator_v2 import baseline, pair


def _two_uploads(pair):
    local, remote, coordinator, *_ = pair
    (local / "a-first.txt").write_text("First upload", encoding="utf-8")
    (local / "z-second.txt").write_text("Second upload", encoding="utf-8")
    preview = coordinator.inspect()
    assert [(d.path, d.action) for d in preview.plan.decisions] == [
        ("a-first.txt", SyncAction.UPLOAD),
        ("z-second.txt", SyncAction.UPLOAD),
    ]
    return local, remote, coordinator, preview


def _after_first_upload(monkeypatch, coordinator, change):
    """Perform the first real transfer, then run a competing writer."""
    original = coordinator.transfer_sender.send_file
    calls = []

    def send_with_interleaving(*args, **kwargs):
        result = original(*args, **kwargs)
        calls.append(result.path)
        if len(calls) == 1 and result.completed:
            change()
        return result

    monkeypatch.setattr(coordinator.transfer_sender, "send_file", send_with_interleaving)
    return calls


def test_remote_edit_between_transfers_blocks_next_upload(pair, monkeypatch):
    local, remote, coordinator, preview = _two_uploads(pair)
    calls = _after_first_upload(
        monkeypatch,
        coordinator,
        lambda: (remote / "unexpected.txt").write_text(
            "Another application's edit", encoding="utf-8"
        ),
    )
    with pytest.raises(StaleSyncState, match="Remote files changed"):
        coordinator.execute_changes(preview)
    assert calls == ["a-first.txt"]
    assert (remote / "a-first.txt").read_text(encoding="utf-8") == "First upload"
    assert not (remote / "z-second.txt").exists()
    assert (remote / "unexpected.txt").read_text(encoding="utf-8") == (
        "Another application's edit"
    )
    assert (local / "z-second.txt").exists()


def test_local_edit_between_transfers_blocks_next_upload(pair, monkeypatch):
    local, remote, coordinator, preview = _two_uploads(pair)
    calls = _after_first_upload(
        monkeypatch,
        coordinator,
        lambda: (local / "unexpected-local.txt").write_text(
            "Another local edit", encoding="utf-8"
        ),
    )
    with pytest.raises(StaleSyncState, match="Local files changed"):
        coordinator.execute_changes(preview)
    assert calls == ["a-first.txt"]
    assert (remote / "a-first.txt").exists()
    assert not (remote / "z-second.txt").exists()
    assert (local / "unexpected-local.txt").read_text(encoding="utf-8") == (
        "Another local edit"
    )


def test_remote_deletion_between_transfers_is_not_silently_ignored(pair, monkeypatch):
    local, remote, coordinator, *_ = pair
    for root in (local, remote):
        (root / "keep.txt").write_text("Important existing data", encoding="utf-8")
    _, _, _, preview = _two_uploads(pair)
    assert [d.path for d in preview.plan.decisions] == [
        "a-first.txt", "z-second.txt"
    ]
    calls = _after_first_upload(
        monkeypatch,
        coordinator,
        lambda: (remote / "keep.txt").unlink(),
    )
    with pytest.raises(StaleSyncState, match="Remote files changed"):
        coordinator.execute_changes(preview)
    assert calls == ["a-first.txt"]
    assert (remote / "a-first.txt").exists()
    assert not (remote / "z-second.txt").exists()
    assert not (remote / "keep.txt").exists()
    assert (local / "keep.txt").read_text(encoding="utf-8") == (
        "Important existing data"
    )


def test_new_baseline_proposal_between_transfers_blocks_sync(pair, monkeypatch):
    local, remote, coordinator, ad, _, _, bob, share, *_ = pair
    _, _, _, preview = _two_uploads(pair)

    def create_pending_proposal():
        snapshot = FileScanner(local).scan()
        assert snapshot.complete
        ad.stage(local, bob.node_id, share, snapshot, expected_revision=0)

    calls = _after_first_upload(monkeypatch, coordinator, create_pending_proposal)
    with pytest.raises(CoordinationError, match="Unresolved shared-baseline proposal"):
        coordinator.execute_changes(preview)
    assert calls == ["a-first.txt"]
    assert ad.pending(local, bob.node_id, share) is not None
    assert (remote / "a-first.txt").exists()
    assert not (remote / "z-second.txt").exists()


def test_remote_destination_edit_immediately_before_upload_is_rejected(pair, monkeypatch):
    local, remote, coordinator, *_ = pair
    for root in (local, remote):
        (root / "document.txt").write_text("Original", encoding="utf-8")
    baseline(pair)
    (local / "document.txt").write_text("Alice's updated version", encoding="utf-8")
    preview = coordinator.inspect()
    assert len(preview.plan.uploads) == 1
    original = coordinator.transfer_sender.send_file

    def change_destination(*args, **kwargs):
        (remote / "document.txt").write_text(
            "Bob's unexpected new version", encoding="utf-8"
        )
        return original(*args, **kwargs)

    monkeypatch.setattr(coordinator.transfer_sender, "send_file", change_destination)
    with pytest.raises(TransferError, match="Destination changed"):
        coordinator.execute_changes(preview)
    assert (remote / "document.txt").read_text(encoding="utf-8") == (
        "Bob's unexpected new version"
    )
    assert (local / "document.txt").read_text(encoding="utf-8") == (
        "Alice's updated version"
    )


def test_local_destination_edit_immediately_before_download_is_rejected(pair, monkeypatch):
    local, remote, coordinator, *_ = pair
    for root in (local, remote):
        (root / "document.txt").write_text("Original", encoding="utf-8")
    baseline(pair)
    (remote / "document.txt").write_text("Bob's updated version", encoding="utf-8")
    preview = coordinator.inspect()
    assert len(preview.plan.downloads) == 1
    original = coordinator.transfer_sender.fetch_file

    def change_destination(*args, **kwargs):
        (local / "document.txt").write_text(
            "Alice's unexpected new version", encoding="utf-8"
        )
        return original(*args, **kwargs)

    monkeypatch.setattr(coordinator.transfer_sender, "fetch_file", change_destination)
    with pytest.raises(TransferError, match="Destination changed"):
        coordinator.execute_changes(preview)
    assert (local / "document.txt").read_text(encoding="utf-8") == (
        "Alice's unexpected new version"
    )
    assert (remote / "document.txt").read_text(encoding="utf-8") == (
        "Bob's updated version"
    )


def test_two_file_cycle_uses_three_full_validations(pair, monkeypatch):
    local, remote, coordinator, preview = _two_uploads(pair)
    original = coordinator._validate_current
    calls = []

    def measured(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(coordinator, "_validate_current", measured)
    result = coordinator.execute_changes(preview)
    assert len(result.uploaded) == 2
    assert len(calls) == 3  # before first, between transfers, and final
    for filename in ("a-first.txt", "z-second.txt"):
        assert (remote / filename).read_bytes() == (local / filename).read_bytes()


def test_final_validation_detects_change_after_last_transfer(pair, monkeypatch):
    local, remote, coordinator, *_ = pair
    (local / "only.txt").write_text("planned", encoding="utf-8")
    preview = coordinator.inspect()
    original = coordinator.transfer_sender.send_file

    def mutate_after_upload(*args, **kwargs):
        result = original(*args, **kwargs)
        if result.completed:
            (remote / "concurrent.txt").write_text("late edit", encoding="utf-8")
        return result

    monkeypatch.setattr(coordinator.transfer_sender, "send_file", mutate_after_upload)
    with pytest.raises(StaleSyncState, match="Remote files changed"):
        coordinator.execute_changes(preview)
    assert (remote / "only.txt").read_text(encoding="utf-8") == "planned"
    assert (remote / "concurrent.txt").read_text(encoding="utf-8") == "late edit"


def test_cancel_after_completed_file_still_validates_final_state(pair, monkeypatch):
    local, remote, coordinator, preview = _two_uploads(pair)
    cancellation = threading.Event()
    original = coordinator.transfer_sender.send_file
    calls = []

    def cancel_after_first(*args, **kwargs):
        result = original(*args, **kwargs)
        calls.append(result.path)
        if len(calls) == 1 and result.completed:
            (remote / "concurrent.txt").write_text("unexpected", encoding="utf-8")
            cancellation.set()
        return result

    monkeypatch.setattr(coordinator.transfer_sender, "send_file", cancel_after_first)
    with pytest.raises(StaleSyncState, match="Remote files changed"):
        coordinator.execute_changes(preview, cancel_event=cancellation)
    assert calls == ["a-first.txt"]
    assert cancellation.is_set()
    assert (remote / "a-first.txt").exists()
    assert not (remote / "z-second.txt").exists()
    assert (remote / "concurrent.txt").read_text(encoding="utf-8") == "unexpected"
