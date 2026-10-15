
"""Tests for actionable human-facing reviews and non-destructive repairs."""
from __future__ import annotations

import hashlib
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from syncbridge.core.conflicts import SyncAction, SyncDecision
from syncbridge.core.lifecycle import SyncLifecycle
from syncbridge.core.review import (
    HELP,
    ReviewError,
    ReviewManager,
    explain_error,
    help_for,
)
from syncbridge.core.scanner import FileRecord, ScanResult
from syncbridge.network.transfer import TransferResult


def record(path, content):
    return FileRecord(
        path,
        len(content),
        1,
        hashlib.sha256(content).hexdigest(),
    )


def fixture(
    tmp_path,
    decision,
    *,
    base=None,
    local=None,
    remote=None,
):
    root = tmp_path / "alice"
    root.mkdir()

    local = dict(local or {})
    remote = dict(remote or {})

    snapshot = ScanResult(root, local, [])
    remote_scan = ScanResult(
        tmp_path / "bob", remote, []
    )

    preview = SimpleNamespace(
        baseline_revision=1,
        plan=SimpleNamespace(
            decisions=(decision,) if decision else ()
        ),
        local=snapshot,
        remote=SimpleNamespace(snapshot=remote_scan),
    )

    baseline = (
        None
        if base is None
        else SimpleNamespace(
            snapshot=ScanResult(root, base, [])
        )
    )

    shared_state = SimpleNamespace(
        load=Mock(return_value=baseline)
    )

    transfer = SimpleNamespace(
        share_id="a" * 32,
        destination_root=root,
        allow_overwrite=True,
        send_file=(
            Mock(
                return_value=TransferResult(
                    decision.path,
                    "c" * 64,
                    3,
                    3,
                    True,
                )
            )
            if decision
            else Mock()
        ),
        fetch_file=Mock(),
    )

    coordinator = SimpleNamespace(
        inspect=Mock(return_value=preview),
        shared_state=shared_state,
        root=root,
        peer_node_id="b" * 32,
        share_id="a" * 32,
        host="127.0.0.1",
        transfer_port=45842,
        transfer_sender=transfer,
    )

    lifecycle = Mock(spec=SyncLifecycle)
    lifecycle.coordinator = coordinator

    return (
        ReviewManager(
            lifecycle,
            here="Alice",
            there="Bob",
        ),
        transfer,
        coordinator,
        root,
    )


def test_bob_deleted_after_commit_displayed_from_alice(
    tmp_path,
):
    old = record("report.txt", b"old")
    dec = SyncDecision(
        "report.txt",
        SyncAction.REVIEW_DELETE_LOCAL,
        old, old, None, "internal",
    )

    manager, *_ = fixture(
        tmp_path, dec,
        base={"report.txt": old},
        local={"report.txt": old},
    )

    issue, = manager.list_issues()

    assert issue.code == "SB-DEL-102"
    assert "Bob no longer has" in issue.title
    assert "Restore" in issue.next_step
    assert "review_delete" not in (
        issue.title + issue.explanation
    )
    assert issue.options == ("restore",)


def test_alice_deleted_after_commit_displayed_from_alice(
    tmp_path,
):
    old = record("report.txt", b"old")
    dec = SyncDecision(
        "report.txt",
        SyncAction.REVIEW_DELETE_REMOTE,
        old, None, old, "internal",
    )

    manager, *_ = fixture(
        tmp_path, dec,
        base={"report.txt": old},
        remote={"report.txt": old},
    )

    issue, = manager.list_issues()

    assert issue.code == "SB-DEL-101"
    assert "Alice no longer has" in issue.title
    assert "Bob still has" in issue.explanation


def test_both_edited_explained_without_cryptic_action(
    tmp_path,
):
    old = record("x.txt", b"old")
    local = record("x.txt", b"Alice")
    remote = record("x.txt", b"Bob")

    dec = SyncDecision(
        "x.txt",
        SyncAction.CONFLICT,
        old, local, remote, "internal",
    )

    manager, *_ = fixture(
        tmp_path, dec,
        base={"x.txt": old},
        local={"x.txt": local},
        remote={"x.txt": remote},
    )

    issue, = manager.list_issues()

    assert issue.code == "SB-CFL-201"
    assert issue.options == ("keep_both",)
    assert "both changed" in issue.title


def test_initial_name_collision_reported_separately(
    tmp_path,
):
    local = record("x", b"local")
    remote = record("x", b"remote")

    dec = SyncDecision(
        "x",
        SyncAction.CONFLICT,
        None, local, remote, "internal",
    )

    manager, *_ = fixture(
        tmp_path, dec,
        local={"x": local},
        remote={"x": remote},
    )

    issue, = manager.list_issues()

    assert issue.code == "SB-CFL-202"
    assert "different files" in issue.title


@pytest.mark.parametrize(
    "local_absent,missing_name",
    [
        (True, "Alice"),
        (False, "Bob"),
    ],
)
def test_edit_versus_delete_requires_manual_resolution(
    tmp_path,
    local_absent,
    missing_name,
):
    old = record("x", b"old")
    changed = record("x", b"changed")

    a, b = (
        (None, changed)
        if local_absent
        else (changed, None)
    )

    dec = SyncDecision(
        "x",
        SyncAction.CONFLICT,
        old, a, b, "internal",
    )

    manager, *_ = fixture(
        tmp_path, dec,
        base={"x": old},
        local={} if a is None else {"x": a},
        remote={} if b is None else {"x": b},
    )

    issue, = manager.list_issues()

    assert issue.code == "SB-CFL-203"
    assert missing_name in issue.title
    assert issue.options == ()


def test_both_deleted_missing_from_planner_is_still_visible(
    tmp_path,
):
    old = record("x", b"old")
    manager, *_ = fixture(
        tmp_path,
        None,
        base={"x": old},
    )

    issue, = manager.list_issues()

    assert issue.code == "SB-DEL-103"
    assert "both Alice and Bob" in issue.title
    assert issue.options == ()


def test_help_catalog_has_stable_explanations():
    assert all(
        value and "_" not in code
        for code, value in HELP.items()
    )

    assert "not yet supported" in help_for(
        "SB-DEL-103"
    )

    assert "Unknown" in help_for(
        "SB-WRONG-999"
    )


def test_errors_have_readable_codes():
    assert explain_error(
        ConnectionError("refused")
    )[0] == "SB-CON-401"

    assert explain_error(
        ReviewError("Unsafe target")
    )[0] == "SB-RSL-410"

    assert explain_error(
        RuntimeError("not authorized")
    )[0] == "SB-AUT-403"

    assert explain_error(
        RuntimeError("baseline revision is stale")
    )[0] == "SB-SYN-500"

    assert explain_error(
        ValueError("unknown")
    )[0] == "SB-ERR-900"


def test_restore_local_missing_uses_authenticated_hash_precondition(
    tmp_path,
):
    old = record("nested/file.txt", b"old")

    dec = SyncDecision(
        "nested/file.txt",
        SyncAction.REVIEW_DELETE_REMOTE,
        old, None, old, "internal",
    )

    manager, transfer, _, root = fixture(
        tmp_path, dec,
        base={dec.path: old},
        remote={dec.path: old},
    )

    transfer.fetch_file.return_value = TransferResult(
        dec.path,
        old.sha256,
        old.size,
        old.size,
        True,
    )

    issue, = manager.list_issues()
    outcome = manager.restore(issue)

    assert "Alice" in outcome.message

    assert (
        transfer.fetch_file.call_args.kwargs[
            "expected_source_sha256"
        ]
        == old.sha256
    )

    assert not transfer.send_file.called


def test_restore_remote_missing_never_asks_for_overwrite(
    tmp_path,
):
    old = record("x", b"old")

    dec = SyncDecision(
        "x",
        SyncAction.REVIEW_DELETE_LOCAL,
        old, old, None, "internal",
    )

    manager, transfer, _, root = fixture(
        tmp_path, dec,
        base={"x": old},
        local={"x": old},
    )

    transfer.send_file.return_value = TransferResult(
        "x",
        old.sha256,
        old.size,
        old.size,
        True,
    )

    issue, = manager.list_issues()
    manager.restore(issue)

    assert (
        transfer.send_file.call_args.kwargs
        == {"share_id": "a" * 32}
    )

    assert not transfer.fetch_file.called


def test_stale_issue_refuses_to_restore(tmp_path):
    old = record("x", b"old")

    dec = SyncDecision(
        "x",
        SyncAction.REVIEW_DELETE_LOCAL,
        old, old, None, "internal",
    )

    manager, transfer, coordinator, _ = fixture(
        tmp_path, dec,
        base={"x": old},
        local={"x": old},
    )

    issue, = manager.list_issues()

    coordinator.inspect.return_value.baseline_revision = 2

    with pytest.raises(
        Exception,
        match="Baseline changed",
    ):
        manager.restore(issue)

    assert not transfer.send_file.called


def test_keep_both_preserves_original_copy_and_fetches_remote(
    tmp_path,
):
    old = record("file.txt", b"old")
    mine = b"Alice's different version"
    theirs = b"Bob's different version"

    local = record("file.txt", mine)
    remote = record("file.txt", theirs)

    dec = SyncDecision(
        "file.txt",
        SyncAction.CONFLICT,
        old, local, remote, "internal",
    )

    manager, transfer, _, root = fixture(
        tmp_path, dec,
        base={"file.txt": old},
        local={"file.txt": local},
        remote={"file.txt": remote},
    )

    (root / "file.txt").write_bytes(mine)

    def fetch(*args, **kwargs):
        assert (
            kwargs["expected_source_sha256"]
            == remote.sha256
        )
        assert (
            kwargs["expected_destination_sha256"]
            == local.sha256
        )

        (root / "file.txt").write_bytes(theirs)

        return TransferResult(
            dec.path,
            remote.sha256,
            remote.size,
            remote.size,
            True,
        )

    transfer.fetch_file.side_effect = fetch

    issue, = manager.list_issues()
    result = manager.keep_both(issue)

    assert result.preserved_copy
    assert (
        root / result.preserved_copy
    ).read_bytes() == mine

    assert (
        root / "file.txt"
    ).read_bytes() == theirs

    assert (
        "Both versions preserved"
        in result.message
    )


def test_keep_both_does_not_overwrite_existing_backup(
    tmp_path,
):
    mine = b"local"
    theirs = b"remote"

    local = record("file.txt", mine)
    remote = record("file.txt", theirs)

    dec = SyncDecision(
        "file.txt",
        SyncAction.CONFLICT,
        None, local, remote, "internal",
    )

    manager, transfer, _, root = fixture(
        tmp_path, dec,
        local={"file.txt": local},
        remote={"file.txt": remote},
    )

    (root / "file.txt").write_bytes(mine)

    candidate = root / (
        f"file (conflict copy "
        f"{local.sha256[:8]}).txt"
    )
    candidate.write_bytes(b"precious")

    issue, = manager.list_issues()

    with pytest.raises(
        ReviewError,
        match="already exists",
    ):
        manager.keep_both(issue)

    assert candidate.read_bytes() == b"precious"
    assert (
        root / "file.txt"
    ).read_bytes() == mine

    assert not transfer.fetch_file.called


def test_keep_both_detects_local_file_modified_after_review(
    tmp_path,
):
    mine = b"local"
    theirs = b"remote"

    local = record("file.txt", mine)
    remote = record("file.txt", theirs)

    dec = SyncDecision(
        "file.txt",
        SyncAction.CONFLICT,
        None, local, remote, "internal",
    )

    manager, transfer, _, root = fixture(
        tmp_path, dec,
        local={"file.txt": local},
        remote={"file.txt": remote},
    )

    (root / "file.txt").write_bytes(b"modified")

    issue, = manager.list_issues()

    with pytest.raises(
        Exception,
        match="Local file changed",
    ):
        manager.keep_both(issue)

    assert not transfer.fetch_file.called


def test_restoring_conflict_as_deletion_forbidden(
    tmp_path,
):
    mine = record("x", b"a")
    theirs = record("x", b"b")

    dec = SyncDecision(
        "x",
        SyncAction.CONFLICT,
        None, mine, theirs, "internal",
    )

    manager, *_ = fixture(
        tmp_path, dec,
        local={"x": mine},
        remote={"x": theirs},
    )

    with pytest.raises(
        ReviewError,
        match="only for",
    ):
        manager.restore(
            manager.list_issues()[0]
        )
