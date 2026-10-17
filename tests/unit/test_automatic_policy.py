
"""Real filesystem snapshot tests for the read-only automatic-plan gate.

These tests do not create network services or write to a synchronized peer.
They prove that a stable candidate cannot itself authorize a file mutation.
"""
from __future__ import annotations

from dataclasses import replace
from uuid import NAMESPACE_URL, uuid5

import pytest

from syncbridge.core.automatic_policy import (
    AutomaticPlanGate,
    AutoPlanState,
)
from syncbridge.core.conflicts import ConflictResolver
from syncbridge.core.coordinator import SyncPreview
from syncbridge.core.scanner import FileScanner, ScanError
from syncbridge.network.manifest import RemoteManifest
from syncbridge.storage.shared_state import _canonical_rows, _digest


def _folders(tmp_path):
    alice = tmp_path / "Alice"
    bob = tmp_path / "Bob"
    alice.mkdir()
    bob.mkdir()
    return alice, bob


def _preview(alice, bob, *, baseline=None):
    local = FileScanner(alice).scan()
    remote = FileScanner(bob).scan()
    revision = 1 if baseline is not None else 0

    manifest = RemoteManifest(
        peer_node_id=uuid5(
            NAMESPACE_URL, str(bob.resolve())
        ).hex,
        share_id=uuid5(
            NAMESPACE_URL,
            str(alice.resolve()) + "|" + str(bob.resolve()),
        ).hex,
        snapshot=remote,
        inventory_sha256=_digest(
            _canonical_rows(remote, remote.root)
        ),
        baseline_revision=revision,
        baseline_sha256=(
            _digest(_canonical_rows(baseline, baseline.root))
            if baseline is not None
            else None
        ),
    )

    plan = ConflictResolver.plan(local, remote, base=baseline)
    return SyncPreview(plan, local, manifest, revision)


def test_only_a_stable_read_only_candidate_is_reported(tmp_path):
    alice, bob = _folders(tmp_path)
    (alice / "photo.jpg").write_bytes(b"verified photo contents")
    preview = _preview(alice, bob)
    gate = AutomaticPlanGate(settle_seconds=2)

    first = gate.observe(preview, observed_at=10)
    second = gate.observe(preview, observed_at=11)
    stable = gate.observe(preview, observed_at=12)

    assert first.state is AutoPlanState.SETTLING
    assert second.state is AutoPlanState.SETTLING
    assert stable.state is AutoPlanState.STABLE_CANDIDATE
    assert stable.change_count == 1
    assert not first.can_write_without_confirmation
    assert not stable.can_write_without_confirmation
    assert not (bob / "photo.jpg").exists()


def test_changed_contents_restart_the_settling_window(tmp_path):
    alice, bob = _folders(tmp_path)
    path = alice / "notes.txt"
    path.write_text("First edit", encoding="utf-8")

    gate = AutomaticPlanGate(settle_seconds=1)
    first = _preview(alice, bob)

    assert gate.observe(
        first, observed_at=1
    ).state is AutoPlanState.SETTLING
    assert gate.observe(
        first, observed_at=2
    ).state is AutoPlanState.STABLE_CANDIDATE

    path.write_text("Another edit", encoding="utf-8")
    changed = _preview(alice, bob)

    assert gate.observe(
        changed, observed_at=2.1
    ).state is AutoPlanState.SETTLING
    assert gate.observe(
        changed, observed_at=3.2
    ).state is AutoPlanState.STABLE_CANDIDATE

    assert not (bob / "notes.txt").exists()


def test_conflicting_first_merge_requires_review(tmp_path):
    alice, bob = _folders(tmp_path)
    (alice / "report.txt").write_text("Alice", encoding="utf-8")
    (bob / "report.txt").write_text("Bob", encoding="utf-8")

    gate = AutomaticPlanGate(settle_seconds=1)

    result = gate.observe(_preview(alice, bob), observed_at=5)

    assert result.state is AutoPlanState.REVIEW_REQUIRED
    assert not result.can_write_without_confirmation
    assert gate.observe(
        _preview(alice, bob), observed_at=100
    ).state is AutoPlanState.REVIEW_REQUIRED


def test_single_sided_deletion_requires_review(tmp_path):
    alice, bob = _folders(tmp_path)
    (alice / "shared.txt").write_bytes(b"shared initial content")
    (bob / "shared.txt").write_bytes(b"shared initial content")

    baseline = FileScanner(alice).scan()
    (alice / "shared.txt").unlink()

    preview = _preview(alice, bob, baseline=baseline)
    gate = AutomaticPlanGate()

    result = gate.observe(preview, baseline=baseline)

    assert result.state is AutoPlanState.REVIEW_REQUIRED
    assert not result.can_write_without_confirmation
    assert (bob / "shared.txt").exists()


def test_deletion_on_both_computers_cannot_be_treated_as_no_changes(
    tmp_path,
):
    alice, bob = _folders(tmp_path)

    for root in (alice, bob):
        (root / "shared.txt").write_bytes(b"shared original data")

    baseline = FileScanner(alice).scan()

    (alice / "shared.txt").unlink()
    (bob / "shared.txt").unlink()

    preview = _preview(alice, bob, baseline=baseline)
    assert preview.plan.decisions == ()

    result = AutomaticPlanGate().observe(
        preview, baseline=baseline
    )

    assert result.state is AutoPlanState.REVIEW_REQUIRED
    assert result.change_count == 1
    assert not result.can_write_without_confirmation


def test_missing_baseline_prevents_false_safe_decision(tmp_path):
    alice, bob = _folders(tmp_path)

    for root in (alice, bob):
        (root / "shared.txt").write_bytes(b"shared content")

    baseline = FileScanner(alice).scan()
    preview = _preview(alice, bob, baseline=baseline)

    result = AutomaticPlanGate().observe(preview)

    assert result.state is AutoPlanState.NOT_READY
    assert not result.can_write_without_confirmation


def test_plan_tampering_or_incomplete_scan_is_rejected(tmp_path):
    alice, bob = _folders(tmp_path)
    (alice / "new.txt").write_bytes(b"new data")

    preview = _preview(alice, bob)
    bad_plan = replace(preview.plan, decisions=())
    bad_preview = replace(preview, plan=bad_plan)
    gate = AutomaticPlanGate()

    assert gate.observe(
        bad_preview
    ).state is AutoPlanState.NOT_READY

    preview.local.errors.append(
        ScanError("unreadable.txt", "access denied")
    )
    assert gate.observe(
        preview
    ).state is AutoPlanState.NOT_READY


def test_up_to_date_and_reset_behavior(tmp_path):
    alice, bob = _folders(tmp_path)
    gate = AutomaticPlanGate(settle_seconds=1)
    clean = _preview(alice, bob)

    result = gate.observe(clean)

    assert result.state is AutoPlanState.UP_TO_DATE
    assert not result.can_write_without_confirmation

    (alice / "new.txt").write_bytes(b"ready")
    preview = _preview(alice, bob)

    assert gate.observe(
        preview, observed_at=1
    ).state is AutoPlanState.SETTLING

    gate.reset()

    assert gate.observe(
        preview, observed_at=100
    ).state is AutoPlanState.SETTLING


@pytest.mark.parametrize(
    "value",
    [0, -1, float("nan"), float("inf"), True, "2"],
)
def test_invalid_settle_intervals_are_rejected(value):
    with pytest.raises(ValueError):
        AutomaticPlanGate(settle_seconds=value)
