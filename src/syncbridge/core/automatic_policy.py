
"""Read-only stability and review gate for future unattended synchronization.

This component NEVER grants permission to modify files. A stable plan is only
an input to a future, fully fenced guarded writer. In particular, this module
must not call SyncLifecycle.run_once(apply=True), GuardedManualRuntime.sync_once,
or any transfer API.
"""
from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import dataclass
from enum import Enum

from syncbridge.core.conflicts import ConflictResolver, SyncAction
from syncbridge.core.coordinator import SyncPreview
from syncbridge.core.scanner import ScanResult
from syncbridge.storage.shared_state import _canonical_rows, _digest


class AutoPlanState(str, Enum):
    NOT_READY = "not_ready"
    UP_TO_DATE = "up_to_date"
    SETTLING = "settling"
    REVIEW_REQUIRED = "review_required"
    STABLE_CANDIDATE = "stable_candidate"


@dataclass(frozen=True, slots=True)
class AutoPlanAssessment:
    state: AutoPlanState
    message: str
    change_count: int = 0

    @property
    def can_write_without_confirmation(self) -> bool:
        """Remain false until the actual write protocol is fully fenced."""
        return False


class AutomaticPlanGate:
    """Evaluate consecutive read-only plans without running any transfers.

    A baseline snapshot is compulsory for an established relationship, because
    the conflict planner omits deletions performed on both computers.
    A plan must stay content-identical for settle_seconds before it is a
    stable candidate, which is NOT write authorization.
    """

    def __init__(self, *, settle_seconds: float = 2.0) -> None:
        if (
            type(settle_seconds) not in (int, float)
            or not math.isfinite(settle_seconds)
            or settle_seconds <= 0
        ):
            raise ValueError("settle_seconds must be finite and positive")

        self.settle_seconds = float(settle_seconds)
        self._fingerprint: str | None = None
        self._first_seen: float | None = None

    def reset(self) -> None:
        """Forget observations after disconnect, failed scan, or peer change."""
        self._fingerprint = None
        self._first_seen = None

    @staticmethod
    def _record(record) -> tuple[int, str] | None:
        if record is None:
            return None
        return record.size, record.sha256

    @classmethod
    def _snapshot(cls, scan: ScanResult) -> list[tuple[str, int, str]]:
        return [
            (path, record.size, record.sha256)
            for path, record in sorted(scan.files.items())
        ]

    @classmethod
    def _signature(cls, preview: SyncPreview) -> str:
        document = [
            preview.remote.peer_node_id,
            preview.remote.share_id,
            preview.baseline_revision,
            preview.remote.baseline_sha256,
            cls._snapshot(preview.local),
            cls._snapshot(preview.remote.snapshot),
            [
                (
                    item.path,
                    item.action.value,
                    cls._record(item.base),
                    cls._record(item.local),
                    cls._record(item.remote),
                )
                for item in preview.plan.decisions
            ],
        ]

        payload = json.dumps(
            document,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def _inspect(
        cls,
        preview: SyncPreview,
        baseline: ScanResult | None,
    ) -> AutoPlanAssessment | None:
        if not isinstance(preview, SyncPreview):
            return AutoPlanAssessment(
                AutoPlanState.NOT_READY,
                "A fresh folder inspection is required.",
            )

        if (
            not isinstance(preview.local, ScanResult)
            or not isinstance(preview.remote.snapshot, ScanResult)
            or (
                baseline is not None
                and not isinstance(baseline, ScanResult)
            )
        ):
            return AutoPlanAssessment(
                AutoPlanState.NOT_READY,
                "The folder inventory could not be verified.",
            )

        if (
            not preview.local.complete
            or not preview.remote.snapshot.complete
            or (baseline is not None and not baseline.complete)
        ):
            return AutoPlanAssessment(
                AutoPlanState.NOT_READY,
                "File inventory is incomplete.",
            )

        if preview.baseline_revision != preview.remote.baseline_revision:
            return AutoPlanAssessment(
                AutoPlanState.NOT_READY,
                "The two computers disagree about their shared history.",
            )

        if (preview.baseline_revision > 0) != (baseline is not None):
            return AutoPlanAssessment(
                AutoPlanState.NOT_READY,
                "Shared history must be verified before automatic synchronization.",
            )

        if preview.plan.has_shared_baseline != (baseline is not None):
            return AutoPlanAssessment(
                AutoPlanState.NOT_READY,
                "The plan does not match its shared history.",
            )

        try:
            remote_digest = _digest(
                _canonical_rows(
                    preview.remote.snapshot,
                    preview.remote.snapshot.root,
                )
            )
            expected_baseline_digest = (
                _digest(
                    _canonical_rows(
                        baseline,
                        baseline.root,
                    )
                )
                if baseline is not None
                else None
            )
        except (ValueError, TypeError, OSError):
            return AutoPlanAssessment(
                AutoPlanState.NOT_READY,
                "Folder hashes could not be verified.",
            )

        if (
            preview.remote.inventory_sha256 != remote_digest
            or preview.remote.baseline_sha256 != expected_baseline_digest
        ):
            return AutoPlanAssessment(
                AutoPlanState.NOT_READY,
                "Folder history or inventory checksum is inconsistent.",
            )

        if (
            preview.plan.local_root != preview.local.root
            or preview.plan.remote_root != preview.remote.snapshot.root
        ):
            return AutoPlanAssessment(
                AutoPlanState.NOT_READY,
                "The plan belongs to different folders.",
            )

        try:
            expected = ConflictResolver.plan(
                preview.local,
                preview.remote.snapshot,
                base=baseline,
            )
        except (ValueError, TypeError):
            return AutoPlanAssessment(
                AutoPlanState.NOT_READY,
                "The current folder inventories could not be verified.",
            )

        def decisions(plan):
            return [
                (
                    item.path,
                    item.action,
                    cls._record(item.base),
                    cls._record(item.local),
                    cls._record(item.remote),
                )
                for item in plan.decisions
            ]

        if decisions(preview.plan) != decisions(expected):
            return AutoPlanAssessment(
                AutoPlanState.NOT_READY,
                "Folder differences changed during inspection.",
            )

        if baseline is not None:
            missing_on_both = set(baseline.files) - (
                set(preview.local.files)
                | set(preview.remote.snapshot.files)
            )

            if missing_on_both:
                return AutoPlanAssessment(
                    AutoPlanState.REVIEW_REQUIRED,
                    "A previously shared file is missing from both "
                    "computers. Review before continuing.",
                    len(missing_on_both),
                )

        if any(
            item.action not in (SyncAction.UPLOAD, SyncAction.DOWNLOAD)
            for item in preview.plan.decisions
        ):
            return AutoPlanAssessment(
                AutoPlanState.REVIEW_REQUIRED,
                "Conflicting changes or deletions require your decision.",
                len(preview.plan.decisions),
            )

        if not preview.plan.decisions:
            return AutoPlanAssessment(
                AutoPlanState.UP_TO_DATE,
                "Both folders are up to date.",
            )

        return None

    def observe(
        self,
        preview: SyncPreview,
        *,
        baseline: ScanResult | None = None,
        observed_at: float | None = None,
    ) -> AutoPlanAssessment:
        """Return only a read-only assessment, never permission to publish."""
        now = time.monotonic() if observed_at is None else observed_at

        if type(now) not in (int, float) or not math.isfinite(now):
            raise ValueError("observed_at must be finite")

        assessment = self._inspect(preview, baseline)

        if assessment is not None:
            self.reset()
            return assessment

        signature = self._signature(preview)

        if (
            signature != self._fingerprint
            or self._first_seen is None
            or now < self._first_seen
        ):
            self._fingerprint = signature
            self._first_seen = float(now)

            return AutoPlanAssessment(
                AutoPlanState.SETTLING,
                "Checking that changes have finished saving.",
                len(preview.plan.decisions),
            )

        if now - self._first_seen < self.settle_seconds:
            return AutoPlanAssessment(
                AutoPlanState.SETTLING,
                "Checking that changes have finished saving.",
                len(preview.plan.decisions),
            )

        return AutoPlanAssessment(
            AutoPlanState.STABLE_CANDIDATE,
            "Changes are stable. Secure write fencing is still "
            "required before unattended syncing.",
            len(preview.plan.decisions),
        )
