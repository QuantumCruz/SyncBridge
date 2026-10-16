
"""Read-only transfer estimates must not exaggerate synchronization success."""
from __future__ import annotations

from types import SimpleNamespace

from syncbridge.ui.transfer_overview import TransferOverview


def plan(path, action, size=None):
    return SimpleNamespace(
        path=path,
        action=action,
        size=size,
    )


def event(path, direction, transferred, total):
    return SimpleNamespace(
        path=path,
        direction=direction,
        transferred=transferred,
        total=total,
    )


def test_overall_bytes_use_actual_preview_sizes():
    meter = TransferOverview([
        plan("a.txt", "Send", 100),
        plan("b.bin", "Receive", 300),
    ])

    state = meter.update(
        event("a.txt", "send", 40, 100),
        now=0,
    )

    assert state.planned_bytes == 400
    assert state.reported_bytes == 40
    assert state.overall_percent == 10
    assert state.file_percent == 40
    assert state.file_number == 1
    assert state.planned_files == 2


def test_speed_uses_new_bytes_not_resumed_offset():
    meter = TransferOverview([
        plan("a.bin", "Send", 1000)
    ])

    first = meter.update(
        event("a.bin", "send", 700, 1000),
        now=10,
    )
    later = meter.update(
        event("a.bin", "send", 800, 1000),
        now=12,
    )

    assert first.speed_bps is None
    assert later.speed_bps == 50
    assert later.data_eta_seconds == 4


def test_repeated_progress_does_not_decrease_percentage():
    meter = TransferOverview([
        plan("a.bin", "Send", 100)
    ])

    meter.update(
        event("a.bin", "send", 80, 100),
        now=0,
    )

    state = meter.update(
        event("a.bin", "send", 30, 100),
        now=1,
    )

    assert state.reported_bytes == 80
    assert state.overall_percent == 80


def test_missing_size_disables_misleading_job_percentage():
    meter = TransferOverview([
        plan("a.txt", "Send")
    ])

    state = meter.update(
        event("a.txt", "send", 50, 100),
        now=0,
    )

    assert state.planned_bytes is None
    assert state.overall_percent is None
    assert state.file_percent == 50


def test_changed_remote_manifest_size_disables_old_estimate():
    meter = TransferOverview([
        plan("a.txt", "Receive", 100)
    ])

    state = meter.update(
        event("a.txt", "receive", 40, 120),
        now=0,
    )

    assert state.planned_bytes is None
    assert state.overall_percent is None


def test_unplanned_transfer_does_not_show_false_job_percentage():
    meter = TransferOverview([
        plan("a.txt", "Send", 100)
    ])

    state = meter.update(
        event("b.txt", "send", 20, 20),
        now=0,
    )

    assert state.planned_bytes is None
    assert not state.verifying


def test_verified_state_not_claimed_by_one_finished_file():
    meter = TransferOverview([
        plan("a", "Send", 100),
        plan("b", "Receive", 300),
    ])

    first = meter.update(
        event("a", "send", 100, 100),
        now=0,
    )
    assert not first.verifying

    last = meter.update(
        event("b", "receive", 300, 300),
        now=2,
    )

    assert last.verifying
    assert last.overall_percent == 100


def test_zero_length_file_does_not_divide_by_zero():
    meter = TransferOverview([
        plan("empty.txt", "Send", 0)
    ])

    state = meter.update(
        event("empty.txt", "send", 0, 0),
        now=0,
    )

    assert state.file_percent == 100
    assert state.verifying


def test_unreviewed_conflicts_do_not_inflate_transfer_count():
    meter = TransferOverview([
        plan("a", "Send", 100),
        plan("conflict", "Conflict"),
        plan("deleted", "Deletion review"),
    ])

    state = meter.update(
        event("a", "send", 50, 100),
        now=0,
    )

    assert state.planned_files == 1
    assert state.planned_bytes == 100


def test_headless_preview_exposes_source_file_size():
    from syncbridge.core.conflicts import SyncAction
    from syncbridge.ui.desktop_controller import describe_preview

    decision = SimpleNamespace(
        path="video.mp4",
        action=SyncAction.UPLOAD,
        local=SimpleNamespace(size=4096),
        remote=None,
    )

    result = SimpleNamespace(
        preview=SimpleNamespace(
            plan=SimpleNamespace(
                decisions=(decision,)
            ),
            baseline_revision=1,
        )
    )

    display = describe_preview(result)

    assert display.items[0].size == 4096
