
"""Tests for conflict-safe two-way planning; no files are modified."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from syncbridge.core.conflicts import (
    ConflictResolver,
    SyncAction,
    SyncPlanError,
)
from syncbridge.core.scanner import (
    FileRecord,
    ScanError,
    ScanResult,
)


def record(
    path: str,
    content: str,
    *,
    timestamp: int = 1,
) -> FileRecord:
    raw = content.encode()

    return FileRecord(
        path,
        len(raw),
        timestamp,
        hashlib.sha256(raw).hexdigest(),
    )


def inventory(
    name: str,
    **files: str,
) -> ScanResult:
    return ScanResult(
        root=Path(name),
        files={
            path: record(path, content)
            for path, content in files.items()
        },
    )


def one(local, remote, *, base=None):
    plan = ConflictResolver.plan(
        local,
        remote,
        base=base,
    )

    assert len(plan.decisions) == 1
    return plan.decisions[0]


def test_two_empty_folders_need_no_actions():
    plan = ConflictResolver.plan(
        inventory("A"),
        inventory("B"),
    )

    assert plan.decisions == ()
    assert not plan.requires_review
    assert not plan.has_shared_baseline


def test_equal_contents_ignore_timestamps():
    a = inventory(
        "A",
        **{"a.txt": "same"},
    )

    b = inventory(
        "B",
        **{"a.txt": "same"},
    )

    b.files["a.txt"] = record(
        "a.txt",
        "same",
        timestamp=999,
    )

    assert ConflictResolver.plan(
        a, b
    ).decisions == ()


@pytest.mark.parametrize(
    "local,remote,action",
    [
        (
            {"new.txt": "hello"},
            {},
            SyncAction.UPLOAD,
        ),
        (
            {},
            {"new.txt": "hello"},
            SyncAction.DOWNLOAD,
        ),
        (
            {"new.txt": "hello"},
            {"new.txt": "different"},
            SyncAction.CONFLICT,
        ),
    ],
)
def test_initial_merge_is_nondestructive(
    local,
    remote,
    action,
):
    item = one(
        inventory("A", **local),
        inventory("B", **remote),
    )

    assert item.action is action
    assert item.base is None


def test_one_sided_modification_upload():
    base = inventory(
        "shared",
        **{"x": "original"},
    )

    local = inventory(
        "A",
        **{"x": "updated"},
    )

    remote = inventory(
        "B",
        **{"x": "original"},
    )

    assert one(
        local, remote, base=base
    ).action is SyncAction.UPLOAD


def test_one_sided_modification_download():
    base = inventory(
        "shared",
        **{"x": "original"},
    )

    local = inventory(
        "A",
        **{"x": "original"},
    )

    remote = inventory(
        "B",
        **{"x": "updated"},
    )

    assert one(
        local, remote, base=base
    ).action is SyncAction.DOWNLOAD


def test_simultaneous_identical_edit_is_not_a_conflict():
    base = inventory(
        "shared",
        **{"x": "original"},
    )

    local = inventory(
        "A",
        **{"x": "same new content"},
    )

    remote = inventory(
        "B",
        **{"x": "same new content"},
    )

    assert ConflictResolver.plan(
        local,
        remote,
        base=base,
    ).decisions == ()


def test_divergent_edits_are_conflicts():
    base = inventory(
        "shared",
        **{"x": "original"},
    )

    local = inventory(
        "A",
        **{"x": "local edit"},
    )

    remote = inventory(
        "B",
        **{"x": "remote edit"},
    )

    item = one(
        local,
        remote,
        base=base,
    )

    assert item.action is SyncAction.CONFLICT
    assert (
        item.base.sha256
        == base.files["x"].sha256
    )


@pytest.mark.parametrize(
    "local,remote,action",
    [
        (
            {},
            {"x": "original"},
            SyncAction.REVIEW_DELETE_REMOTE,
        ),
        (
            {"x": "original"},
            {},
            SyncAction.REVIEW_DELETE_LOCAL,
        ),
        (
            {},
            {"x": "remote edit"},
            SyncAction.CONFLICT,
        ),
        (
            {"x": "local edit"},
            {},
            SyncAction.CONFLICT,
        ),
    ],
)
def test_deletions_are_never_automatically_executed(
    local,
    remote,
    action,
):
    base = inventory(
        "shared",
        **{"x": "original"},
    )

    decision = one(
        inventory("A", **local),
        inventory("B", **remote),
        base=base,
    )

    assert decision.action is action


def test_both_sides_delete_is_not_an_action():
    plan = ConflictResolver.plan(
        inventory("A"),
        inventory("B"),
        base=inventory(
            "shared",
            **{"x": "original"},
        ),
    )

    assert plan.decisions == ()


def test_independent_new_files_and_order():
    local = inventory(
        "A",
        **{
            "z": "z",
            "common": "yes",
        },
    )

    remote = inventory(
        "B",
        **{
            "a": "a",
            "common": "yes",
        },
    )

    plan = ConflictResolver.plan(
        local,
        remote,
    )

    assert [
        (item.path, item.action)
        for item in plan.decisions
    ] == [
        ("a", SyncAction.DOWNLOAD),
        ("z", SyncAction.UPLOAD),
    ]

    assert len(plan.downloads) == 1
    assert len(plan.uploads) == 1
    assert not plan.requires_review


def test_mix_including_pending_deletion_needs_review():
    base = inventory(
        "base",
        **{
            "gone": "old",
            "changed": "old",
        },
    )

    local = inventory(
        "local",
        **{"changed": "new"},
    )

    remote = inventory(
        "remote",
        **{
            "gone": "old",
            "changed": "old",
        },
    )

    plan = ConflictResolver.plan(
        local,
        remote,
        base=base,
    )

    assert len(plan.uploads) == 1
    assert len(plan.pending_deletions) == 1
    assert plan.requires_review
    assert plan.has_shared_baseline


def test_incomplete_local_or_remote_or_base_rejected():
    for index in range(3):
        snapshots = [
            inventory("a"),
            inventory("b"),
            inventory("base"),
        ]

        snapshots[index].errors.append(
            ScanError(
                "foo",
                "access denied",
            )
        )

        with pytest.raises(
            SyncPlanError,
            match="incomplete",
        ):
            ConflictResolver.plan(
                snapshots[0],
                snapshots[1],
                base=snapshots[2],
            )


def test_case_insensitive_cross_platform_collisions_rejected():
    with pytest.raises(
        SyncPlanError,
        match="Ambiguous",
    ):
        ConflictResolver.plan(
            inventory(
                "A",
                **{"Résumé.txt": "A"},
            ),
            inventory(
                "B",
                **{"résumé.txt": "B"},
            ),
        )


def test_file_directory_collision_rejected():
    with pytest.raises(
        SyncPlanError,
        match="parent directory",
    ):
        ConflictResolver.plan(
            inventory(
                "A",
                **{"dir": "file"},
            ),
            inventory(
                "B",
                **{"dir/sub.txt": "nested"},
            ),
        )


@pytest.mark.parametrize(
    "bad",
    [
        "../x",
        "x\\y",
        "CON.txt",
        "a//b",
        "a/./b",
        "a/../b",
        "a.",
        "/abs",
        "C:/foo",
        "a\x00b",
    ],
)
def test_unsafe_manifest_path_rejected(bad):
    with pytest.raises(SyncPlanError):
        ConflictResolver.plan(
            inventory(
                "A",
                **{bad: "x"},
            ),
            inventory("B"),
        )


def test_modified_ns_and_metadata_validation():
    first = inventory(
        "A",
        **{"x": "hello"},
    )

    value = first.files["x"]

    first.files["x"] = FileRecord(
        "x",
        value.size,
        1,
        "z" * 64,
    )

    with pytest.raises(
        SyncPlanError,
        match="record",
    ):
        ConflictResolver.plan(
            first,
            inventory("B"),
        )


def test_input_snapshots_are_not_mutated():
    local = inventory(
        "A",
        **{"a.txt": "hello"},
    )

    remote = inventory("B")
    before = dict(local.files)

    ConflictResolver.plan(
        local,
        remote,
    )

    assert local.files == before
    assert remote.files == {}


def test_case_different_file_directory_collision_rejected():
    with pytest.raises(
        SyncPlanError,
        match="parent directory",
    ):
        ConflictResolver.plan(
            inventory(
                "A",
                **{"Folder": "file"},
            ),
            inventory(
                "B",
                **{"folder/child.txt": "nested"},
            ),
        )


def test_internal_state_and_git_paths_rejected():
    for path in (
        ".syncbridge/state.db",
        ".git/config",
        ".venv/cache",
        "__pycache__/x.pyc",
    ):
        with pytest.raises(
            SyncPlanError,
            match="Unsafe",
        ):
            ConflictResolver.plan(
                inventory(
                    "A",
                    **{path: "x"},
                ),
                inventory("B"),
            )
