
"""Shared-baseline persistence and acknowledgement tests; no file changes."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest

from syncbridge.core.scanner import FileRecord, ScanError, ScanResult
from syncbridge.storage.shared_state import (
    BaselineNotReady,
    RevisionConflict,
    SharedStateDatabase,
    SharedStateError,
)


def scan(root: Path, **contents: str) -> ScanResult:
    return ScanResult(root=root, files={
        name: FileRecord(name, len(text.encode()), 321,
                         hashlib.sha256(text.encode()).hexdigest())
        for name, text in contents.items()
    })


@pytest.fixture
def setup(tmp_path):
    root = tmp_path / "shared"
    root.mkdir()
    db = SharedStateDatabase(tmp_path / "state" / "shared.db")
    return db, root, uuid4().hex, uuid4().hex


def prepared(db, root, peer, share, snap, *, rev=0):
    proposal = db.stage(root, peer, share, snap, expected_revision=rev)
    db.confirm_local(root, peer, share, proposal.proposal_id, snap)
    db.confirm_remote(root, peer, share, proposal.proposal_id,
                      authenticated_peer_id=peer, acknowledged_sha256=proposal.sha256)
    return proposal


def test_missing_differs_from_committed_empty(setup):
    db, root, peer, share = setup
    assert db.load(root, peer, share) is None
    empty = scan(root)
    p = prepared(db, root, peer, share, empty)
    committed = db.finalize(root, peer, share, p.proposal_id, empty)
    assert committed.revision == 1
    assert committed.snapshot.files == {}
    assert db.load(root, peer, share).revision == 1
    assert db.pending(root, peer, share) is None


def test_staging_does_not_change_existing_baseline(setup):
    db, root, peer, share = setup
    first = scan(root, **{"x.txt": "old"})
    p = prepared(db, root, peer, share, first)
    db.finalize(root, peer, share, p.proposal_id, first)
    second = scan(root, **{"x.txt": "new"})
    db.stage(root, peer, share, second, expected_revision=1)
    assert db.load(root, peer, share).snapshot.files["x.txt"].sha256 == first.files["x.txt"].sha256


def test_persistent_and_canonical_digest_across_metadata_changes(setup):
    db, root, peer, share = setup
    original = scan(root, **{"nested/é.txt": "bonjour", "A.txt": "data"})
    p = prepared(db, root, peer, share, original)
    snapshot = db.finalize(root, peer, share, p.proposal_id, original)
    reloaded = SharedStateDatabase(db.path).load(root, peer, share)
    assert reloaded.sha256 == snapshot.sha256
    assert reloaded.snapshot.files["A.txt"].modified_ns == 0
    changed_timestamp = scan(root, **{"nested/é.txt": "bonjour", "A.txt": "data"})
    changed_timestamp.files["A.txt"] = FileRecord("A.txt", 4, 999999,
                                                   original.files["A.txt"].sha256)
    p2 = prepared(db, root, peer, share, changed_timestamp, rev=1)
    assert p2.sha256 == snapshot.sha256


def test_local_confirmation_requires_same_contents(setup):
    db, root, peer, share = setup
    proposed = scan(root, **{"x": "alpha"})
    pending = db.stage(root, peer, share, proposed, expected_revision=0)
    with pytest.raises(BaselineNotReady):
        db.confirm_local(root, peer, share, pending.proposal_id, scan(root, **{"x": "beta"}))
    assert not db.pending(root, peer, share).local_confirmed


def test_remote_confirmation_requires_authenticated_correct_peer_and_digest(setup):
    db, root, peer, share = setup
    original = scan(root, **{"x": "alpha"})
    p = db.stage(root, peer, share, original, expected_revision=0)
    with pytest.raises(SharedStateError, match="wrong peer"):
        db.confirm_remote(root, peer, share, p.proposal_id,
                          authenticated_peer_id=uuid4().hex, acknowledged_sha256=p.sha256)
    with pytest.raises(BaselineNotReady):
        db.confirm_remote(root, peer, share, p.proposal_id,
                          authenticated_peer_id=peer, acknowledged_sha256="0" * 64)
    assert not db.pending(root, peer, share).remote_confirmed


def test_finalize_requires_two_confirmations(setup):
    db, root, peer, share = setup
    original = scan(root, **{"x": "alpha"})
    p = db.stage(root, peer, share, original, expected_revision=0)
    db.confirm_local(root, peer, share, p.proposal_id, original)
    with pytest.raises(BaselineNotReady):
        db.finalize(root, peer, share, p.proposal_id, original)
    assert db.load(root, peer, share) is None
    assert db.pending(root, peer, share).local_confirmed


def test_finalize_requires_current_matching_scan(setup):
    db, root, peer, share = setup
    original = scan(root, **{"x": "alpha"})
    p = prepared(db, root, peer, share, original)
    with pytest.raises(BaselineNotReady):
        db.finalize(root, peer, share, p.proposal_id, scan(root, **{"x": "new"}))
    assert db.load(root, peer, share) is None
    assert db.pending(root, peer, share) is not None


def test_stale_revision_rejected_without_overwrite(setup):
    db, root, peer, share = setup
    snap = scan(root)
    p = prepared(db, root, peer, share, snap)
    db.finalize(root, peer, share, p.proposal_id, snap)
    with pytest.raises(RevisionConflict):
        db.stage(root, peer, share, snap, expected_revision=0)
    assert db.load(root, peer, share).revision == 1


def test_pending_survives_restart_and_idempotent_stage(setup):
    db, root, peer, share = setup
    proposed = scan(root, **{"a": "a"})
    p = db.stage(root, peer, share, proposed, expected_revision=0)
    second = SharedStateDatabase(db.path)
    second.confirm_local(root, peer, share, p.proposal_id, proposed)
    identical = db.stage(root, peer, share, proposed,
                         expected_revision=0, proposal_id=p.proposal_id)
    assert identical.local_confirmed
    assert not identical.remote_confirmed
    assert second.pending(root, peer, share).proposal_id == p.proposal_id


def test_staged_change_must_explicitly_abort(setup):
    db, root, peer, share = setup
    a = scan(root, **{"a": "one"})
    b = scan(root, **{"a": "two"})
    old = db.stage(root, peer, share, a, expected_revision=0)
    with pytest.raises(SharedStateError, match="Another proposal"):
        db.stage(root, peer, share, b, expected_revision=0)
    assert db.abort(root, peer, share, old.proposal_id)
    assert not db.abort(root, peer, share, old.proposal_id)
    assert db.pending(root, peer, share) is None
    assert db.stage(root, peer, share, b, expected_revision=0).sha256 != old.sha256


def test_pair_and_share_isolation(setup):
    db, root, peer, share = setup
    other_peer, other_share = uuid4().hex, uuid4().hex
    for p, s in ((peer, share), (other_peer, share), (peer, other_share)):
        snap = scan(root, **{"shared.txt": p + s})
        prop = prepared(db, root, p, s, snap)
        db.finalize(root, p, s, prop.proposal_id, snap)
    assert len({db.load(root, p, s).sha256 for p, s in (
        (peer, share), (other_peer, share), (peer, other_share))}) == 3


def test_incomplete_and_bad_paths_cannot_be_staged(setup):
    db, root, peer, share = setup
    incomplete = scan(root)
    incomplete.errors.append(ScanError("file", "unreadable"))
    with pytest.raises(SharedStateError, match="Incomplete"):
        db.stage(root, peer, share, incomplete, expected_revision=0)
    for name in ("../escape", "/absolute", "CON.txt", "a\\b", ".git/index", "x."):
        with pytest.raises(SharedStateError):
            db.stage(root, peer, share, scan(root, **{name: "x"}), expected_revision=0)
    assert db.pending(root, peer, share) is None


def test_collisions_rejected(setup):
    db, root, peer, share = setup
    for paths in ({"A.txt": "x", "a.txt": "y"}, {"folder": "x", "folder/file": "y"}):
        with pytest.raises(SharedStateError):
            db.stage(root, peer, share, scan(root, **paths), expected_revision=0)


def test_different_root_rejected(setup, tmp_path):
    db, root, peer, share = setup
    with pytest.raises(SharedStateError, match="does not belong"):
        db.stage(root, peer, share, scan(tmp_path / "other"), expected_revision=0)


def test_refuses_database_inside_synced_root_except_excluded_directory(tmp_path):
    root = tmp_path / "sync"
    root.mkdir()
    db_inside = SharedStateDatabase(root / "unsafe.db")
    with pytest.raises(SharedStateError, match="must not be synchronized"):
        db_inside.load(root, uuid4().hex, uuid4().hex)
    db_excluded = SharedStateDatabase(root / ".syncbridge" / "state.db")
    assert db_excluded.load(root, uuid4().hex, uuid4().hex) is None


def test_integrity_check_catches_corrupted_committed_rows(setup):
    db, root, peer, share = setup
    snap = scan(root, **{"file": "contents"})
    p = prepared(db, root, peer, share, snap)
    db.finalize(root, peer, share, p.proposal_id, snap)
    with sqlite3.connect(db.path) as conn:
        conn.execute("UPDATE shared_files SET size = size + 1")
    with pytest.raises(SharedStateError, match="integrity"):
        db.load(root, peer, share)


def test_multi_instance_confirms_and_commits(setup):
    a, root, peer, share = setup
    b = SharedStateDatabase(a.path)
    snap = scan(root, **{"file": "contents"})
    p = a.stage(root, peer, share, snap, expected_revision=0)
    b.confirm_local(root, peer, share, p.proposal_id, snap)
    a.confirm_remote(root, peer, share, p.proposal_id,
                     authenticated_peer_id=peer, acknowledged_sha256=p.sha256)
    assert b.finalize(root, peer, share, p.proposal_id, snap).revision == 1
    assert a.load(root, peer, share).revision == 1


def test_persistent_revision_advances(setup):
    db, root, peer, share = setup
    for index in range(3):
        snap = scan(root, **{"file": f"version-{index}"})
        p = prepared(db, root, peer, share, snap, rev=index)
        db.finalize(root, peer, share, p.proposal_id, snap)
    assert db.load(root, peer, share).revision == 3


def test_proposal_rejects_invalid_ids_and_versions(setup):
    db, root, peer, share = setup
    with pytest.raises(SharedStateError):
        db.stage(root, "BAD", share, scan(root), expected_revision=0)
    with pytest.raises(SharedStateError):
        db.stage(root, peer, share, scan(root), expected_revision=True)
    with pytest.raises(SharedStateError):
        db.stage(root, peer, share, scan(root), expected_revision=0, proposal_id="bad")
