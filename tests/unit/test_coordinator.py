
"""Real localhost tests for conservative SyncBridge coordination."""

from __future__ import annotations

import os
import threading
from uuid import uuid4

import pytest

from syncbridge.core.coordinator import (
    CoordinationError,
    StaleSyncState,
    SyncCoordinator,
)
from syncbridge.core.conflicts import SyncAction
from syncbridge.core.scanner import FileScanner
from syncbridge.network.manifest import ManifestService
from syncbridge.network.security import DeviceIdentity, TrustStore
from syncbridge.network.transfer import TransferService
from syncbridge.storage.shared_state import SharedStateDatabase


@pytest.fixture
def pair(tmp_path):
    local = tmp_path / "alice"
    remote = tmp_path / "bob"

    local.mkdir()
    remote.mkdir()

    alice = DeviceIdentity.generate()
    bob = DeviceIdentity.generate()

    at = TrustStore(
        tmp_path / "alice-trust.json"
    )
    bt = TrustStore(
        tmp_path / "bob-trust.json"
    )

    at.add_verified(
        bob.public_key_hex,
        confirmed_fingerprint=bob.fingerprint,
        name="Bob",
    )
    bt.add_verified(
        alice.public_key_hex,
        confirmed_fingerprint=alice.fingerprint,
        name="Alice",
    )

    share_id = uuid4().hex

    ad = SharedStateDatabase(
        tmp_path / "alice-state.db"
    )
    bd = SharedStateDatabase(
        tmp_path / "bob-state.db"
    )

    opts = dict(
        bind_address="127.0.0.1",
        listen_port=0,
        handshake_timeout=2.0,
        io_timeout=5.0,
    )

    manifest_server = ManifestService(
        bob,
        bt,
        {share_id: remote},
        allowed_readers={
            share_id: [alice.node_id],
        },
        shared_state=bd,
        **opts,
    )

    transfer_server = TransferService(
        bob,
        bt,
        remote,
        allowed_senders=[alice.node_id],
        allow_overwrite=False,
        **opts,
    )

    manifest_client = ManifestService(
        alice,
        at,
        **opts,
    )

    sender = TransferService(
        alice,
        at,
        tmp_path / "unused-inbox",
        **opts,
    )

    manifest_server.start()
    transfer_server.start()

    coordinator = SyncCoordinator(
        local,
        bob.node_id,
        share_id,
        "127.0.0.1",
        manifest_server.bound_port,
        transfer_server.bound_port,
        manifest_client=manifest_client,
        transfer_sender=sender,
        shared_state=ad,
    )

    try:
        yield (
            local,
            remote,
            coordinator,
            ad,
            bd,
            alice,
            bob,
            share_id,
        )
    finally:
        transfer_server.stop()
        manifest_server.stop()


def _agree_on_existing(pair):
    local, remote, _, ad, bd, alice, bob, share = pair

    for database, root, peer_id in (
        (ad, local, bob.node_id),
        (bd, remote, alice.node_id),
    ):
        snapshot = FileScanner(root).scan()

        proposal = database.stage(
            root,
            peer_id,
            share,
            snapshot,
            expected_revision=0,
        )

        database.confirm_local(
            root,
            peer_id,
            share,
            proposal.proposal_id,
            snapshot,
        )

        database.confirm_remote(
            root,
            peer_id,
            share,
            proposal.proposal_id,
            authenticated_peer_id=peer_id,
            acknowledged_sha256=proposal.sha256,
        )

        database.finalize(
            root,
            peer_id,
            share,
            proposal.proposal_id,
            snapshot,
        )


def test_empty_folders_have_no_actions(pair):
    _, _, coordinator, *_ = pair

    report = coordinator.run_once()

    assert not report.preview.plan.decisions
    assert not report.uploaded
    assert not report.paused


def test_dry_run_does_not_transfer(pair):
    local, remote, coordinator, *_ = pair

    (local / "new.txt").write_text("new")

    result = coordinator.run_once()

    assert [
        item.path
        for item in result.preview.new_uploads
    ] == ["new.txt"]

    assert result.uploaded == ()
    assert not (remote / "new.txt").exists()


def test_push_one_new_file_then_noop(pair):
    local, remote, coordinator, ad, _, _, bob, share = pair

    (local / "new.txt").write_text(
        "hello world"
    )

    report = coordinator.run_once(
        push_new=True
    )

    assert len(report.uploaded) == 1
    assert report.uploaded[0].completed

    assert (
        remote / "new.txt"
    ).read_text() == "hello world"

    assert ad.load(
        local,
        bob.node_id,
        share,
    ) is None

    assert not coordinator.run_once(
        push_new=True
    ).uploaded


def test_nested_large_file_and_multiple_files(pair):
    local, remote, coordinator, *_ = pair

    (local / "inside").mkdir()

    data = os.urandom(350_000)

    (
        local / "inside" / "binary.bin"
    ).write_bytes(data)

    (
        local / "a.txt"
    ).write_text("A")

    (
        local / "z.txt"
    ).write_text("Z")

    report = coordinator.run_once(
        push_new=True
    )

    assert len(report.uploaded) == 3

    assert (
        remote / "inside" / "binary.bin"
    ).read_bytes() == data

    assert (
        remote / "a.txt"
    ).read_text() == "A"

    assert not report.paused


def test_remote_only_file_is_not_deleted_or_downloaded(pair):
    local, remote, coordinator, *_ = pair

    (
        remote / "only-remote.txt"
    ).write_text("remote")

    report = coordinator.run_once(
        push_new=True
    )

    assert len(report.pending_downloads) == 1
    assert (
        report.pending_downloads[0].action
        is SyncAction.DOWNLOAD
    )

    assert report.uploaded == ()

    assert not (
        local / "only-remote.txt"
    ).exists()

    assert (
        remote / "only-remote.txt"
    ).read_text() == "remote"


def test_divergent_new_files_are_conflicts_not_overwrites(pair):
    local, remote, coordinator, *_ = pair

    (
        local / "same.txt"
    ).write_text("alice")

    (
        remote / "same.txt"
    ).write_text("bob")

    report = coordinator.run_once(
        push_new=True
    )

    assert len(report.pending_conflicts) == 1
    assert report.uploaded == ()

    assert (
        local / "same.txt"
    ).read_text() == "alice"

    assert (
        remote / "same.txt"
    ).read_text() == "bob"


def test_modified_existing_file_is_deferred(pair):
    local, remote, coordinator, *_ = pair

    (
        local / "existing.txt"
    ).write_text("original")

    (
        remote / "existing.txt"
    ).write_text("original")

    _agree_on_existing(pair)

    (
        local / "existing.txt"
    ).write_text("changed")

    report = coordinator.run_once(
        push_new=True
    )

    assert [
        item.path
        for item in report.pending_updates
    ] == ["existing.txt"]

    assert report.uploaded == ()

    assert (
        remote / "existing.txt"
    ).read_text() == "original"


def test_deletion_requires_review(pair):
    local, remote, coordinator, *_ = pair

    (
        local / "existing.txt"
    ).write_text("original")

    (
        remote / "existing.txt"
    ).write_text("original")

    _agree_on_existing(pair)

    (
        local / "existing.txt"
    ).unlink()

    report = coordinator.run_once(
        push_new=True
    )

    assert len(report.pending_deletions) == 1
    assert (
        remote / "existing.txt"
    ).exists()


def test_remote_baseline_revision_mismatch_blocks_planning(pair):
    local, remote, coordinator, ad, bd, alice, _, share = pair

    snapshot = FileScanner(remote).scan()

    proposal = bd.stage(
        remote,
        alice.node_id,
        share,
        snapshot,
        expected_revision=0,
    )

    bd.confirm_local(
        remote,
        alice.node_id,
        share,
        proposal.proposal_id,
        snapshot,
    )

    bd.confirm_remote(
        remote,
        alice.node_id,
        share,
        proposal.proposal_id,
        authenticated_peer_id=alice.node_id,
        acknowledged_sha256=proposal.sha256,
    )

    bd.finalize(
        remote,
        alice.node_id,
        share,
        proposal.proposal_id,
        snapshot,
    )

    with pytest.raises(
        StaleSyncState,
        match="baseline differs",
    ):
        coordinator.inspect()


def test_local_edit_after_preview_blocks_upload(pair):
    local, remote, coordinator, *_ = pair

    (
        local / "new.txt"
    ).write_text("one")

    preview = coordinator.inspect()

    (
        local / "new.txt"
    ).write_text("two")

    with pytest.raises(
        StaleSyncState,
        match="Local files changed",
    ):
        coordinator.execute_new_files(
            preview
        )

    assert not (
        remote / "new.txt"
    ).exists()


def test_remote_edit_after_preview_blocks_upload(pair):
    local, remote, coordinator, *_ = pair

    (
        local / "new.txt"
    ).write_text("one")

    preview = coordinator.inspect()

    (
        remote / "different.txt"
    ).write_text("another update")

    with pytest.raises(
        StaleSyncState,
        match="Remote files changed",
    ):
        coordinator.execute_new_files(
            preview
        )

    assert not (
        remote / "new.txt"
    ).exists()


def test_pending_proposal_blocks_execution(pair):
    local, remote, coordinator, ad, _, _, bob, share = pair

    (
        local / "file.txt"
    ).write_text("one")

    preview = coordinator.inspect()

    ad.stage(
        local,
        bob.node_id,
        share,
        FileScanner(local).scan(),
        expected_revision=0,
    )

    with pytest.raises(
        CoordinationError,
        match="Unresolved",
    ):
        coordinator.execute_new_files(
            preview
        )

    assert not (
        remote / "file.txt"
    ).exists()


def test_cancellation_before_transfer(pair):
    local, remote, coordinator, *_ = pair

    (
        local / "file.txt"
    ).write_text("data")

    cancel = threading.Event()
    cancel.set()

    result = coordinator.run_once(
        push_new=True,
        cancel_event=cancel,
    )

    assert result.paused
    assert result.uploaded == ()

    assert not (
        remote / "file.txt"
    ).exists()


def test_cancel_during_transfer_then_retry(pair):
    local, remote, coordinator, *_ = pair

    content = os.urandom(350_000)

    (
        local / "binary.bin"
    ).write_bytes(content)

    cancelled = threading.Event()

    def progress(update):
        if update.transferred >= 65_536:
            cancelled.set()

    report = coordinator.run_once(
        push_new=True,
        cancel_event=cancelled,
        on_progress=progress,
    )

    assert report.paused
    assert report.uploaded == ()

    assert not (
        remote / "binary.bin"
    ).exists()

    retry = coordinator.run_once(
        push_new=True
    )

    assert len(retry.uploaded) == 1

    assert (
        remote / "binary.bin"
    ).read_bytes() == content


def test_upload_does_not_advance_agreed_baseline(pair):
    local, _, coordinator, ad, _, _, bob, share = pair

    (
        local / "new.txt"
    ).write_text("new")

    coordinator.run_once(
        push_new=True
    )

    assert ad.load(
        local,
        bob.node_id,
        share,
    ) is None

    assert ad.pending(
        local,
        bob.node_id,
        share,
    ) is None


def test_previews_can_be_reviewed_without_mutation(pair):
    local, remote, coordinator, *_ = pair

    (
        local / "a.txt"
    ).write_text("one")

    (
        remote / "b.txt"
    ).write_text("two")

    first = coordinator.inspect()
    second = coordinator.inspect()

    assert [
        d.path
        for d in first.plan.decisions
    ] == ["a.txt", "b.txt"]

    assert (
        first.plan.decisions
        == second.plan.decisions
    )

    assert not (
        remote / "a.txt"
    ).exists()

    assert not (
        local / "b.txt"
    ).exists()


def test_bad_inputs_rejected(pair):
    local, _, coordinator, _, _, _, bob, share = pair

    kwargs = dict(
        manifest_client=coordinator.manifest_client,
        transfer_sender=coordinator.transfer_sender,
        shared_state=coordinator.shared_state,
    )

    with pytest.raises(ValueError):
        SyncCoordinator(
            local,
            "bad",
            share,
            "127.0.0.1",
            1,
            2,
            **kwargs,
        )

    with pytest.raises(ValueError):
        SyncCoordinator(
            local,
            bob.node_id,
            "bad",
            "127.0.0.1",
            1,
            2,
            **kwargs,
        )

    with pytest.raises(ValueError):
        SyncCoordinator(
            local,
            bob.node_id,
            share,
            "invalid-host",
            1,
            2,
            **kwargs,
        )

    with pytest.raises(ValueError):
        SyncCoordinator(
            local,
            bob.node_id,
            share,
            "127.0.0.1",
            True,
            2,
            **kwargs,
        )

    with pytest.raises(TypeError):
        coordinator.run_once(
            push_new="yes"
        )

    with pytest.raises(TypeError):
        coordinator.execute_new_files(
            coordinator.inspect(),
            cancel_event="no",
        )
