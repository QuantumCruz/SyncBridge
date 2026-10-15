
"""Regression tests for deterministic SQLite connection cleanup.

These checks retain strong references to all opened connections, preventing
garbage collection from disguising leaked handles. In particular, Windows
must be able to remove a stopped profile directory immediately.
"""
from __future__ import annotations

import shutil
import sqlite3
from contextlib import closing
from pathlib import Path
from uuid import uuid4

import pytest

from syncbridge.core.scanner import ScanResult
from syncbridge.storage.shared_state import (
    RevisionConflict,
    SharedStateDatabase,
    SharedStateError,
)


class TrackedConnection(sqlite3.Connection):
    """A genuine SQLite connection held alive by its test fixture."""


@pytest.fixture
def observed_connections(monkeypatch):
    original_connect = sqlite3.connect
    opened = []

    def connect_spy(*args, **kwargs):
        if "factory" in kwargs:
            raise AssertionError(
                "Unexpected SQLite connection factory"
            )

        connection = original_connect(
            *args,
            factory=TrackedConnection,
            **kwargs,
        )
        opened.append(connection)
        return connection

    monkeypatch.setattr(
        sqlite3,
        "connect",
        connect_spy,
    )

    return opened, original_connect


def assert_all_closed(opened):
    assert opened, "Expected at least one SQLite connection"

    for connection in opened:
        with pytest.raises(
            sqlite3.ProgrammingError,
            match="closed",
        ):
            connection.execute("SELECT 1")


def create_database(tmp_path):
    root = tmp_path / "Shared"
    root.mkdir()

    db = SharedStateDatabase(
        tmp_path / "Profile" / "shared_state.sqlite"
    )

    return db, root, uuid4().hex, uuid4().hex


def empty_snapshot(root: Path):
    return ScanResult(
        root=root,
        files={},
    )


def commit_empty_baseline(db, root, peer, share):
    snapshot = empty_snapshot(root)

    proposal = db.stage(
        root,
        peer,
        share,
        snapshot,
        expected_revision=0,
    )

    db.confirm_local(
        root,
        peer,
        share,
        proposal.proposal_id,
        snapshot,
    )

    db.confirm_remote(
        root,
        peer,
        share,
        proposal.proposal_id,
        authenticated_peer_id=peer,
        acknowledged_sha256=proposal.sha256,
    )

    return db.finalize(
        root,
        peer,
        share,
        proposal.proposal_id,
        snapshot,
    )


def test_constructor_closes_schema_connection(
    tmp_path,
    observed_connections,
):
    opened, _ = observed_connections

    db = SharedStateDatabase(
        tmp_path / "Profile" / "shared_state.sqlite"
    )

    assert db.path.exists()
    assert_all_closed(opened)


def test_empty_read_paths_close_connections(
    tmp_path,
    observed_connections,
):
    opened, _ = observed_connections
    db, root, peer, share = create_database(tmp_path)

    assert db.load(root, peer, share) is None
    assert db.pending(root, peer, share) is None

    assert_all_closed(opened)


def test_successful_staging_and_commit_close_connections(
    tmp_path,
    observed_connections,
):
    opened, _ = observed_connections
    db, root, peer, share = create_database(tmp_path)

    baseline = commit_empty_baseline(
        db,
        root,
        peer,
        share,
    )

    assert baseline.revision == 1
    assert db.load(root, peer, share).revision == 1
    assert db.pending(root, peer, share) is None

    second = db.stage(
        root,
        peer,
        share,
        empty_snapshot(root),
        expected_revision=1,
    )

    assert db.abort(
        root,
        peer,
        share,
        second.proposal_id,
    )

    assert db.pending(root, peer, share) is None
    assert_all_closed(opened)


def test_failed_transaction_rolls_back_and_closes(
    tmp_path,
    observed_connections,
):
    opened, _ = observed_connections
    db, root, peer, share = create_database(tmp_path)

    first = db.stage(
        root,
        peer,
        share,
        empty_snapshot(root),
        expected_revision=0,
    )

    with pytest.raises(
        RevisionConflict,
        match="revision",
    ):
        db.stage(
            root,
            peer,
            share,
            empty_snapshot(root),
            expected_revision=1,
        )

    assert (
        db.pending(root, peer, share).proposal_id
        == first.proposal_id
    )

    assert_all_closed(opened)


def test_integrity_failure_also_closes_connection(
    tmp_path,
    observed_connections,
):
    opened, original_connect = observed_connections
    db, root, peer, share = create_database(tmp_path)

    commit_empty_baseline(
        db,
        root,
        peer,
        share,
    )

    # Deliberately corrupt committed metadata using a separate,
    # explicitly closed database connection.
    with closing(original_connect(db.path)) as connection:
        connection.execute(
            "UPDATE shared_baselines SET sha256=?",
            ("0" * 64,),
        )
        connection.commit()

    with pytest.raises(
        SharedStateError,
        match="integrity",
    ):
        db.load(root, peer, share)

    assert_all_closed(opened)


def test_profile_directory_can_be_removed_without_gc(
    tmp_path,
    observed_connections,
):
    opened, _ = observed_connections
    db, root, peer, share = create_database(tmp_path)

    commit_empty_baseline(
        db,
        root,
        peer,
        share,
    )

    assert db.load(root, peer, share) is not None
    assert_all_closed(opened)

    profile = db.path.parent
    assert profile.exists()

    # Keep the database object AND every SQLite connection object
    # alive here. Windows must still allow immediate removal.
    shutil.rmtree(profile)

    assert not profile.exists()
    assert_all_closed(opened)
