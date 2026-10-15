
"""Real localhost integration tests for opt-in, share-bound two-way coordination."""

from __future__ import annotations

import os
import threading
from uuid import uuid4

import pytest

from syncbridge.core.coordinator import CoordinationError, StaleSyncState, SyncCoordinator
from syncbridge.core.scanner import FileScanner
from syncbridge.network.manifest import ManifestService
from syncbridge.network.security import DeviceIdentity, TrustStore
from syncbridge.network.transfer import TransferError, TransferService
from syncbridge.storage.shared_state import SharedStateDatabase


@pytest.fixture
def pair(tmp_path):
    local, remote = tmp_path / "alice", tmp_path / "bob"
    local.mkdir()
    remote.mkdir()
    alice, bob = DeviceIdentity.generate(), DeviceIdentity.generate()
    at, bt = TrustStore(tmp_path / "at.json"), TrustStore(tmp_path / "bt.json")
    at.add_verified(bob.public_key_hex, confirmed_fingerprint=bob.fingerprint, name="B")
    bt.add_verified(alice.public_key_hex, confirmed_fingerprint=alice.fingerprint, name="A")
    share = uuid4().hex
    ad = SharedStateDatabase(tmp_path / "ad.db")
    bd = SharedStateDatabase(tmp_path / "bd.db")
    opts = dict(bind_address="127.0.0.1", listen_port=0, handshake_timeout=2, io_timeout=4)
    server = ManifestService(bob, bt, {share: remote},
                             allowed_readers={share: [alice.node_id]}, shared_state=bd, **opts)
    client = ManifestService(alice, at, **opts)
    outbound = TransferService(alice, at, local, share_id=share, allow_overwrite=True,
                               allowed_senders=[bob.node_id], allowed_readers=[bob.node_id], **opts)
    inbound = TransferService(bob, bt, remote, share_id=share, allow_overwrite=True,
                              allowed_senders=[alice.node_id], allowed_readers=[alice.node_id], **opts)
    server.start()
    inbound.start()
    coordinator = SyncCoordinator(local, bob.node_id, share, "127.0.0.1",
                                  server.bound_port, inbound.bound_port,
                                  manifest_client=client, transfer_sender=outbound, shared_state=ad)
    try:
        yield local, remote, coordinator, ad, bd, alice, bob, share, outbound, inbound, server
    finally:
        inbound.stop()
        server.stop()


def baseline(pair):
    local, remote, _, ad, bd, alice, bob, share, *_ = pair
    for db, root, peer in ((ad, local, bob.node_id), (bd, remote, alice.node_id)):
        scan = FileScanner(root).scan()
        p = db.stage(root, peer, share, scan, expected_revision=0)
        db.confirm_local(root, peer, share, p.proposal_id, scan)
        db.confirm_remote(root, peer, share, p.proposal_id,
                          authenticated_peer_id=peer, acknowledged_sha256=p.sha256)
        db.finalize(root, peer, share, p.proposal_id, scan)


def test_dry_run_no_changes(pair):
    local, remote, coordinator, *_ = pair
    (local / "new.txt").write_text("A")
    (remote / "other.txt").write_text("B")
    result = coordinator.run_once()
    assert len(result.preview.plan.decisions) == 2
    assert not result.uploaded and not result.downloaded
    assert not (local / "other.txt").exists() and not (remote / "new.txt").exists()


def test_new_files_sync_in_both_directions(pair):
    local, remote, coordinator, *_ = pair
    (local / "one.txt").write_text("one")
    (remote / "two.txt").write_text("two")
    result = coordinator.run_once(sync=True)
    assert [x.path for x in result.uploaded] == ["one.txt"]
    assert [x.path for x in result.downloaded] == ["two.txt"]
    assert (remote / "one.txt").read_text() == "one"
    assert (local / "two.txt").read_text() == "two"
    assert not result.pending_downloads and not result.pending_uploads
    assert not result.pending_updates
    assert coordinator.run_once(sync=True).uploaded == ()
    assert coordinator.run_once(sync=True).downloaded == ()


def test_binary_nested_sync(pair):
    local, remote, coordinator, *_ = pair
    (local / "folder").mkdir()
    (remote / "files").mkdir()
    data1, data2 = os.urandom(230_000), os.urandom(250_000)
    (local / "folder" / "a.bin").write_bytes(data1)
    (remote / "files" / "b.bin").write_bytes(data2)
    result = coordinator.run_once(sync=True)
    assert len(result.uploaded) == len(result.downloaded) == 1
    assert (remote / "folder" / "a.bin").read_bytes() == data1
    assert (local / "files" / "b.bin").read_bytes() == data2


def test_existing_local_edit_conditional_upload(pair):
    local, remote, coordinator, *_ = pair
    (local / "doc").write_text("original")
    (remote / "doc").write_text("original")
    baseline(pair)
    (local / "doc").write_text("local update")
    result = coordinator.run_once(sync=True)
    assert len(result.uploaded) == 1
    assert result.downloaded == ()
    assert not result.pending_updates
    assert (remote / "doc").read_text() == "local update"


def test_existing_remote_edit_conditional_download(pair):
    local, remote, coordinator, *_ = pair
    (local / "doc").write_text("original")
    (remote / "doc").write_text("original")
    baseline(pair)
    (remote / "doc").write_text("remote update")
    result = coordinator.run_once(sync=True)
    assert len(result.downloaded) == 1
    assert not result.pending_updates
    assert (local / "doc").read_text() == "remote update"


def test_conflicting_changes_are_untouched(pair):
    local, remote, coordinator, *_ = pair
    (local / "doc").write_text("original")
    (remote / "doc").write_text("original")
    baseline(pair)
    (local / "doc").write_text("Alice version")
    (remote / "doc").write_text("Bob version")
    result = coordinator.run_once(sync=True)
    assert len(result.pending_conflicts) == 1
    assert result.pending_deletions == ()
    assert not result.uploaded and not result.downloaded
    assert (local / "doc").read_text() == "Alice version"
    assert (remote / "doc").read_text() == "Bob version"


def test_deletion_never_applied_even_with_other_new_files(pair):
    local, remote, coordinator, *_ = pair
    (local / "keep").write_text("x")
    (remote / "keep").write_text("x")
    baseline(pair)
    (local / "keep").unlink()
    (local / "new").write_text("new")
    result = coordinator.run_once(sync=True)
    assert len(result.pending_deletions) == 1
    assert len(result.uploaded) == 1
    assert (remote / "keep").read_text() == "x"
    assert not (local / "keep").exists()


def test_share_binding_required_for_full_sync(pair):
    local, remote, coordinator, _, _, _, _, share, sender, *_ = pair
    (remote / "download.txt").write_text("download")
    sender.share_id = None
    with pytest.raises(CoordinationError, match="share-bound"):
        coordinator.run_once(sync=True)
    assert not (local / "download.txt").exists()


def test_local_transfer_destination_must_match(pair, tmp_path):
    local, remote, coordinator, _, _, _, _, _, sender, *_ = pair
    (remote / "download.txt").write_text("download")
    sender.destination_root = tmp_path / "another"
    sender.destination_root.mkdir()
    with pytest.raises(CoordinationError, match="local folder"):
        coordinator.run_once(sync=True)
    assert not (sender.destination_root / "download.txt").exists()


def test_remote_share_mismatch_rejected(pair):
    local, remote, coordinator, _, _, _, _, share, _, receiver, *_ = pair
    (local / "out.txt").write_text("A")
    receiver.share_id = uuid4().hex
    with pytest.raises(TransferError, match="share"):
        coordinator.run_once(sync=True)
    assert not (remote / "out.txt").exists()


def test_no_remote_permission_is_not_silent(pair):
    local, remote, coordinator, _, _, _, _, _, _, receiver, *_ = pair
    (local / "new.txt").write_text("new")
    receiver.revoke_sender(coordinator.manifest_client.identity.node_id)
    with pytest.raises(TransferError, match="authorized"):
        coordinator.run_once(sync=True)
    assert not (remote / "new.txt").exists()


def test_no_remote_read_permission_is_not_silent(pair):
    local, remote, coordinator, _, _, _, _, _, _, receiver, *_ = pair
    (remote / "download.txt").write_text("content")
    receiver.revoke_reader(coordinator.manifest_client.identity.node_id)
    with pytest.raises(TransferError, match="permission"):
        coordinator.run_once(sync=True)
    assert not (local / "download.txt").exists()


def test_local_conditional_updates_need_permission(pair):
    local, remote, coordinator, _, _, _, _, _, sender, *_ = pair
    (local / "doc").write_text("same")
    (remote / "doc").write_text("same")
    baseline(pair)
    (remote / "doc").write_text("new")
    sender.allow_overwrite = False
    with pytest.raises(CoordinationError, match="conditional updates"):
        coordinator.run_once(sync=True)
    assert (local / "doc").read_text() == "same"


def test_pending_baseline_proposal_blocks_two_way(pair):
    local, remote, coordinator, ad, _, _, bob, share, *_ = pair
    (local / "one").write_text("1")
    ad.stage(local, bob.node_id, share, FileScanner(local).scan(), expected_revision=0)
    with pytest.raises(CoordinationError, match="Unresolved"):
        coordinator.run_once(sync=True)
    assert not (remote / "one").exists()


def test_stale_local_after_preview_blocks_two_way(pair):
    local, remote, coordinator, *_ = pair
    (local / "file").write_text("old")
    preview = coordinator.inspect()
    (local / "file").write_text("new")
    with pytest.raises(StaleSyncState, match="Local files changed"):
        coordinator.execute_changes(preview)
    assert not (remote / "file").exists()


def test_stale_remote_after_preview_blocks_two_way(pair):
    local, remote, coordinator, *_ = pair
    (remote / "file").write_text("old")
    preview = coordinator.inspect()
    (remote / "file").write_text("new")
    with pytest.raises(StaleSyncState, match="Remote files changed"):
        coordinator.execute_changes(preview)
    assert not (local / "file").exists()


def test_cancel_before_two_way_work(pair):
    local, remote, coordinator, *_ = pair
    (remote / "file").write_text("x")
    cancelled = threading.Event()
    cancelled.set()
    result = coordinator.run_once(sync=True, cancel_event=cancelled)
    assert result.paused and not result.uploaded and not result.downloaded
    assert len(result.pending_downloads) == 1
    assert not (local / "file").exists()


def test_cancel_download_then_resume(pair):
    local, remote, coordinator, *_ = pair
    payload = os.urandom(400_000)
    (remote / "big.bin").write_bytes(payload)
    cancelled = threading.Event()
    def progress(e):
        if e.direction == "receive" and e.transferred >= 65536:
            cancelled.set()
    paused = coordinator.run_once(sync=True, cancel_event=cancelled, on_progress=progress)
    assert paused.paused and not paused.downloaded
    assert len(paused.pending_downloads) == 1
    assert not (local / "big.bin").exists()
    complete = coordinator.run_once(sync=True)
    assert len(complete.downloaded) == 1
    assert (local / "big.bin").read_bytes() == payload


def test_old_push_new_mode_remains_create_only(pair):
    local, remote, coordinator, *_ = pair
    (local / "out.txt").write_text("out")
    (remote / "in.txt").write_text("in")
    # A share-bound server should reject old, unscoped offers instead of accepting them.
    with pytest.raises(TransferError):
        coordinator.run_once(push_new=True)
    assert not (remote / "out.txt").exists()
    assert not (local / "in.txt").exists()


def test_modes_are_explicit_and_exclusive(pair):
    coordinator = pair[2]
    with pytest.raises(ValueError, match="either"):
        coordinator.run_once(push_new=True, sync=True)
    with pytest.raises(TypeError):
        coordinator.run_once(sync="yes")


def test_no_baseline_auto_committed(pair):
    local, remote, coordinator, ad, bd, alice, bob, share, *_ = pair
    (local / "one").write_text("1")
    (remote / "two").write_text("2")
    coordinator.run_once(sync=True)
    assert ad.load(local, bob.node_id, share) is None
    assert bd.load(remote, alice.node_id, share) is None
    assert ad.pending(local, bob.node_id, share) is None


def test_result_keeps_unexecuted_updates_visible(pair):
    local, remote, coordinator, *_ = pair
    (local / "x").write_text("base")
    (remote / "x").write_text("base")
    baseline(pair)
    (remote / "x").write_text("new")
    preview = coordinator.inspect()
    assert len(preview.deferred_updates) == 1
    report = coordinator.run_once()
    assert len(report.pending_updates) == 1
    assert len(report.pending_downloads) == 1


def test_file_change_in_progress_rejected_or_detected(pair):
    local, remote, coordinator, *_ = pair
    (local / "doc").write_text("initial")
    (remote / "doc").write_text("initial")
    baseline(pair)
    (local / "doc").write_text("new")
    preview = coordinator.inspect()
    (remote / "doc").write_text("another writer")
    with pytest.raises(StaleSyncState):
        coordinator.execute_changes(preview)
    assert (remote / "doc").read_text() == "another writer"
