
"""Phase 18: local-owner approved deletion, backup and checkpoint regression tests.

Orchestration uses mocked authenticated inventory and checkpoint endpoints here;
Phase 17 separately tests encrypted request delivery and local consent. These
cases test the real RecoveryVault and ApprovedDeletionCoordinator implementations.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest

from syncbridge.core.approved_deletion import (
    ApprovedDeletionCoordinator,
    ApprovedDeletionError,
    RecoveryVault,
)
from syncbridge.core.lifecycle import SyncLifecycle
from syncbridge.core.coordinator import SyncCoordinator
from syncbridge.core.scanner import FileRecord, FileScanner
from syncbridge.network.deletion_approval import (
    DeletionApprovalService,
    DeletionRequest,
)


def file_entry(data: bytes) -> FileRecord:
    return FileRecord("docs/report.txt", len(data), 1, hashlib.sha256(data).hexdigest())


@pytest.fixture
def world(tmp_path):
    root = tmp_path / "Alice" / "Shared"
    root.mkdir(parents=True)
    target = root / "docs" / "report.txt"
    target.parent.mkdir()
    payload = b"Our approved report\n"
    target.write_bytes(payload)
    record = file_entry(payload)
    share, peer, rid = uuid4().hex, uuid4().hex, uuid4().hex
    baseline = SimpleNamespace(
        revision=1, sha256="a" * 64,
        snapshot=SimpleNamespace(files={"docs/report.txt": record}),
    )
    request = DeletionRequest(
        rid, share, peer, "docs/report.txt", 1,
        baseline.sha256, record.sha256, record.size, "approved",
    )
    vault = RecoveryVault(root, tmp_path / "Alice" / "Recovery")
    state = Mock()
    state.path = tmp_path / "Alice" / "baseline.sqlite"
    state.load.return_value = baseline
    state.pending.return_value = None

    coordinator = Mock(spec=SyncCoordinator)
    coordinator.root = root
    coordinator.peer_node_id = peer
    coordinator.share_id = share
    coordinator.shared_state = state

    # Remote peer has already deleted the report. Other files are unchanged.
    def inspect():
        return SimpleNamespace(
            local=FileScanner(root).scan(),
            remote=SimpleNamespace(snapshot=SimpleNamespace(files={})),
            baseline_revision=1,
        )
    coordinator.inspect.side_effect = inspect

    approvals = Mock(spec=DeletionApprovalService)
    approvals.shared_state = state
    approvals._shares = {share: root}
    approvals.incoming.return_value = (request,)

    lifecycle = Mock(spec=SyncLifecycle)
    lifecycle.coordinator = coordinator
    checkpoint = Mock()
    lifecycle.baseline = checkpoint

    def commit():
        next_baseline = SimpleNamespace(
            revision=2, sha256="b" * 64,
            snapshot=SimpleNamespace(files={}),
        )
        state.load.return_value = next_baseline
        return SimpleNamespace(baseline=next_baseline)
    checkpoint.checkpoint.side_effect = commit

    runner = ApprovedDeletionCoordinator(lifecycle, approvals, vault)
    return SimpleNamespace(
        root=root, target=target, payload=payload, record=record,
        request=request, state=state, approvals=approvals,
        lifecycle=lifecycle, runner=runner, vault=vault,
    )


def test_approved_removal_keeps_recovery_copy_and_commits(world):
    result = world.runner.apply(world.request.request_id)
    assert result.completed
    assert result.code == "SB-DEL-109"
    assert result.revision == 2
    assert not world.target.exists()
    assert result.recovery_path.read_bytes() == world.payload
    assert world.vault.stored(world.request) == result.recovery_path
    world.lifecycle.baseline.checkpoint.assert_called_once()


def test_unapproved_request_never_removes_file(world):
    world.approvals.incoming.return_value = (
        __import__("dataclasses").replace(world.request, state="pending"),
    )
    with pytest.raises(ApprovedDeletionError, match="not been approved"):
        world.runner.apply(world.request.request_id)
    assert world.target.read_bytes() == world.payload
    world.lifecycle.baseline.checkpoint.assert_not_called()


def test_unknown_request_never_removes_file(world):
    with pytest.raises(ApprovedDeletionError, match="not found"):
        world.runner.apply(uuid4().hex)
    assert world.target.exists()


def test_changed_file_after_approval_never_removed(world):
    world.target.write_bytes(b"Important edit after approval!")
    with pytest.raises(ApprovedDeletionError, match="Other files changed"):
        world.runner.apply(world.request.request_id)
    assert world.target.read_bytes() == b"Important edit after approval!"
    assert world.vault.stored(world.request) is None


def test_remote_file_restored_refuses_deletion(world):
    world.runner.lifecycle.coordinator.inspect.side_effect = lambda: SimpleNamespace(
        local=FileScanner(world.root).scan(),
        remote=SimpleNamespace(snapshot=SimpleNamespace(files={"docs/report.txt": world.record})),
        baseline_revision=1,
    )
    with pytest.raises(ApprovedDeletionError, match="requesting device restored"):
        world.runner.apply(world.request.request_id)
    assert world.target.exists()


def test_unrelated_local_edit_blocks_approved_removal(world):
    (world.root / "other.txt").write_text("new")
    with pytest.raises(ApprovedDeletionError, match="Other files changed"):
        world.runner.apply(world.request.request_id)
    assert world.target.exists()


def test_baseline_changes_block_request(world):
    world.state.load.return_value.sha256 = "d" * 64
    with pytest.raises(ApprovedDeletionError, match="Shared history changed"):
        world.runner.apply(world.request.request_id)
    assert world.target.exists()


def test_incomplete_checkpoint_preserves_data_and_retry_recovers(world):
    world.lifecycle.baseline.checkpoint.side_effect = RuntimeError("Disconnected")
    with pytest.raises(ApprovedDeletionError, match="safely stored in recovery"):
        world.runner.apply(world.request.request_id)
    assert not world.target.exists()
    assert world.vault.stored(world.request).read_bytes() == world.payload

    next_baseline = SimpleNamespace(
        revision=2, sha256="b" * 64,
        snapshot=SimpleNamespace(files={}),
    )
    def success():
        world.state.load.return_value = next_baseline
        return SimpleNamespace(baseline=next_baseline)
    world.lifecycle.baseline.checkpoint.side_effect = success
    result = world.runner.apply(world.request.request_id)
    assert result.completed and result.revision == 2
    assert world.vault.stored(world.request).read_bytes() == world.payload


def test_repeated_completed_request_is_idempotent(world):
    first = world.runner.apply(world.request.request_id)
    second = world.runner.apply(world.request.request_id)
    assert second.completed and second.revision == first.revision
    world.lifecycle.baseline.checkpoint.assert_called_once()


def test_completed_request_detects_recreated_file(world):
    world.runner.apply(world.request.request_id)
    world.target.write_bytes(b"new edit after successful deletion")
    with pytest.raises(ApprovedDeletionError, match="reappeared"):
        world.runner.apply(world.request.request_id)


def test_explicit_restore_does_not_destroy_backup(world):
    world.runner.apply(world.request.request_id)
    restored = world.vault.restore(world.request)
    assert restored == world.target
    assert restored.read_bytes() == world.payload
    assert world.vault.stored(world.request).read_bytes() == world.payload
    with pytest.raises(ApprovedDeletionError, match="already exists"):
        world.vault.restore(world.request)


def test_recovery_directory_cannot_be_inside_share(world):
    with pytest.raises(ValueError, match="separate"):
        RecoveryVault(world.root, world.root / ".syncbridge" / "recovery")


def test_recovery_detects_tampered_backup(world):
    world.runner.apply(world.request.request_id)
    blob = world.vault.stored(world.request)
    blob.write_bytes(b"CORRUPTED")
    with pytest.raises(ApprovedDeletionError, match="integrity"):
        world.vault.stored(world.request)


def test_recovery_rejects_a_recreated_original(world):
    world.runner.apply(world.request.request_id)
    world.target.write_bytes(b"NEW")
    with pytest.raises(ApprovedDeletionError, match="reappeared"):
        world.vault.preserve(world.request)
    assert world.target.read_bytes() == b"NEW"


def test_recovery_survives_new_vault_object(world):
    world.runner.apply(world.request.request_id)
    other = RecoveryVault(world.root, world.vault.directory)
    assert other.stored(world.request).read_bytes() == world.payload


def test_refuse_missing_approval_folder_link(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    vault = RecoveryVault(root, tmp_path / "vault")
    with pytest.raises(ValueError):
        vault._paths("bad")
