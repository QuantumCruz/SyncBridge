
"""Compare two filesystem scans without modifying any files.

This module detects local changes between scans. It does not decide how to
resolve differences between two peers or authorize file deletion. Two-way
conflict handling belongs to the synchronization engine/conflicts module.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .scanner import FileRecord, ScanResult


class ChangeType(str, Enum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"


@dataclass(frozen=True, slots=True)
class FileChange:
    """A difference in one relative file path between two scans."""

    path: str
    kind: ChangeType
    before: FileRecord | None
    after: FileRecord | None


@dataclass(frozen=True, slots=True)
class ReconcileResult:
    """Immutable summary of the differences between two complete scans."""

    root: Path
    changes: tuple[FileChange, ...]
    unchanged_count: int
    previous_count: int
    current_count: int

    @property
    def added(self) -> tuple[FileChange, ...]:
        return tuple(
            change
            for change in self.changes
            if change.kind is ChangeType.ADDED
        )

    @property
    def modified(self) -> tuple[FileChange, ...]:
        return tuple(
            change
            for change in self.changes
            if change.kind is ChangeType.MODIFIED
        )

    @property
    def deleted(self) -> tuple[FileChange, ...]:
        return tuple(
            change
            for change in self.changes
            if change.kind is ChangeType.DELETED
        )

    @property
    def has_changes(self) -> bool:
        return bool(self.changes)


class IncompleteScanError(ValueError):
    """An incomplete scan cannot safely establish whether files disappeared."""


class FileReconciler:
    """Produce a deterministic, read-only diff between inventories of one root."""

    @staticmethod
    def compare(
        previous: ScanResult,
        current: ScanResult,
    ) -> ReconcileResult:
        if previous.root != current.root:
            raise ValueError(
                "Cannot compare scans from different folders: "
                f"{previous.root} != {current.root}"
            )

        if not previous.complete or not current.complete:
            raise IncompleteScanError(
                "Cannot reconcile incomplete scans. Resolve scan errors before "
                "interpreting missing files as deletions. "
                f"Previous errors: {len(previous.errors)}; "
                f"current errors: {len(current.errors)}."
            )

        changes: list[FileChange] = []
        unchanged = 0

        for path in sorted(previous.files.keys() | current.files.keys()):
            before = previous.files.get(path)
            after = current.files.get(path)

            if before is None:
                kind = ChangeType.ADDED

            elif after is None:
                kind = ChangeType.DELETED

            elif (
                before.size != after.size
                or before.sha256 != after.sha256
            ):
                kind = ChangeType.MODIFIED

            else:
                unchanged += 1
                continue

            changes.append(
                FileChange(
                    path=path,
                    kind=kind,
                    before=before,
                    after=after,
                )
            )

        return ReconcileResult(
            root=current.root,
            changes=tuple(changes),
            unchanged_count=unchanged,
            previous_count=len(previous.files),
            current_count=len(current.files),
        )
