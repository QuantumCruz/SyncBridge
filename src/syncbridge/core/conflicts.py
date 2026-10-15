
"""Read-only, three-way reconciliation plan for a synchronized folder pair.

The base inventory MUST be the last snapshot acknowledged by BOTH devices.
The ordinary SyncEngine SQLite snapshot is only local history, not this base.
If no common baseline exists, pass base=None for an initial merge.

Planning never accesses the filesystem, transfers files, or performs deletions.
Deletions are review-only until a separate authorization workflow exists.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .scanner import FileRecord, ScanResult

_MAX_FILES = 250_000
_MAX_FILE_SIZE = 2**63 - 1
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_RESERVED = re.compile(
    r"(?i)(con|prn|aux|nul|conin\$|conout\$|com[1-9]|lpt[1-9])(?:\..*)?\Z"
)
_FORBIDDEN = frozenset('<>:"\\|?*')


class SyncPlanError(ValueError):
    """Inventory is incomplete or unsafe to use for synchronization."""


class SyncAction(str, Enum):
    UPLOAD = "upload"
    DOWNLOAD = "download"
    CONFLICT = "conflict"
    REVIEW_DELETE_LOCAL = "review_delete_local"
    REVIEW_DELETE_REMOTE = "review_delete_remote"


@dataclass(frozen=True, slots=True)
class SyncDecision:
    path: str
    action: SyncAction
    base: FileRecord | None
    local: FileRecord | None
    remote: FileRecord | None
    reason: str


@dataclass(frozen=True, slots=True)
class SyncPlan:
    local_root: Path
    remote_root: Path
    has_shared_baseline: bool
    decisions: tuple[SyncDecision, ...]

    @property
    def uploads(self) -> tuple[SyncDecision, ...]:
        return tuple(
            item for item in self.decisions
            if item.action is SyncAction.UPLOAD
        )

    @property
    def downloads(self) -> tuple[SyncDecision, ...]:
        return tuple(
            item for item in self.decisions
            if item.action is SyncAction.DOWNLOAD
        )

    @property
    def conflicts(self) -> tuple[SyncDecision, ...]:
        return tuple(
            item for item in self.decisions
            if item.action is SyncAction.CONFLICT
        )

    @property
    def pending_deletions(self) -> tuple[SyncDecision, ...]:
        return tuple(
            item for item in self.decisions
            if item.action in (
                SyncAction.REVIEW_DELETE_LOCAL,
                SyncAction.REVIEW_DELETE_REMOTE,
            )
        )

    @property
    def requires_review(self) -> bool:
        return bool(
            self.conflicts or self.pending_deletions
        )


def _validate_path(path: str) -> None:
    if (
        not isinstance(path, str)
        or not path
        or path.startswith("/")
        or "//" in path
    ):
        raise SyncPlanError(
            "Invalid relative file path"
        )

    try:
        encoded = path.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SyncPlanError(
            "Invalid Unicode file path"
        ) from exc

    if len(encoded) > 1024:
        raise SyncPlanError(
            "Relative path exceeds 1024 UTF-8 bytes"
        )

    for part in path.split("/"):
        if (
            not part
            or part in (".", "..")
            or part.endswith((" ", "."))
            or part.casefold() in {
                ".syncbridge",
                ".git",
                ".venv",
                "__pycache__",
            }
            or len(part.encode("utf-8")) > 255
            or _RESERVED.fullmatch(part) is not None
            or any(
                ord(c) < 32
                or ord(c) == 127
                or c in _FORBIDDEN
                for c in part
            )
        ):
            raise SyncPlanError(
                f"Unsafe portable file path: {path!r}"
            )


def _validate_inventory(
    label: str,
    snapshot: ScanResult,
) -> None:
    if not isinstance(snapshot, ScanResult):
        raise TypeError(
            f"{label} must be a ScanResult"
        )

    if not snapshot.complete:
        raise SyncPlanError(
            f"{label} inventory is incomplete; refusing to plan"
        )

    if len(snapshot.files) > _MAX_FILES:
        raise SyncPlanError(
            f"{label} inventory exceeds file limit"
        )

    for path, record in snapshot.files.items():
        _validate_path(path)

        if (
            not isinstance(record, FileRecord)
            or record.relative_path != path
            or type(record.size) is not int
            or not 0 <= record.size <= _MAX_FILE_SIZE
            or type(record.modified_ns) is not int
            or not isinstance(record.sha256, str)
            or _HASH.fullmatch(record.sha256) is None
        ):
            raise SyncPlanError(
                f"Invalid {label} inventory record: {path!r}"
            )


def _check_cross_platform_collisions(
    paths: set[str],
) -> None:
    folded: dict[str, str] = {}

    for path in sorted(paths):
        normalized = unicodedata.normalize(
            "NFC", path
        ).casefold()

        other = folded.setdefault(
            normalized, path
        )

        if other != path:
            raise SyncPlanError(
                "Ambiguous case/Unicode paths across devices: "
                f"{other!r}, {path!r}"
            )

    for path in paths:
        parts = path.split("/")

        for end in range(1, len(parts)):
            parent = "/".join(parts[:end])

            normalized_parent = unicodedata.normalize(
                "NFC", parent
            ).casefold()

            if normalized_parent in folded:
                raise SyncPlanError(
                    "A file is also a parent directory: "
                    f"{folded[normalized_parent]!r}, {path!r}"
                )


def _same(
    left: FileRecord | None,
    right: FileRecord | None,
) -> bool:
    """Content equality, not timestamps; None means absent."""
    if left is None or right is None:
        return left is None and right is None

    return (
        left.size == right.size
        and left.sha256 == right.sha256
    )


class ConflictResolver:
    """Plan conservative two-way updates without side effects."""

    @staticmethod
    def plan(
        local: ScanResult,
        remote: ScanResult,
        *,
        base: ScanResult | None = None,
    ) -> SyncPlan:
        _validate_inventory("local", local)
        _validate_inventory("remote", remote)

        if base is not None:
            _validate_inventory("base", base)

        all_paths = (
            set(local.files)
            | set(remote.files)
        )

        if base is not None:
            all_paths.update(base.files)

        _check_cross_platform_collisions(all_paths)

        result: list[SyncDecision] = []

        for path in sorted(all_paths):
            ancestor = (
                base.files.get(path)
                if base is not None
                else None
            )

            current_local = local.files.get(path)
            current_remote = remote.files.get(path)

            if _same(
                current_local,
                current_remote,
            ):
                # Identical contents require no action.
                # Both sides may also have deleted the same file.
                continue

            if base is None or ancestor is None:
                if current_local is None:
                    action = SyncAction.DOWNLOAD
                    reason = "File exists only remotely"

                elif current_remote is None:
                    action = SyncAction.UPLOAD
                    reason = "File exists only locally"

                else:
                    action = SyncAction.CONFLICT
                    reason = (
                        "Different files without a common ancestor"
                    )

            elif _same(ancestor, current_local):
                if current_remote is None:
                    action = SyncAction.REVIEW_DELETE_LOCAL
                    reason = (
                        "Remote deletion requires explicit approval"
                    )
                else:
                    action = SyncAction.DOWNLOAD
                    reason = "Only remote contents changed"

            elif _same(ancestor, current_remote):
                if current_local is None:
                    action = SyncAction.REVIEW_DELETE_REMOTE
                    reason = (
                        "Local deletion requires explicit approval"
                    )
                else:
                    action = SyncAction.UPLOAD
                    reason = "Only local contents changed"

            else:
                action = SyncAction.CONFLICT
                reason = (
                    "Both sides diverged from their common ancestor"
                )

            result.append(
                SyncDecision(
                    path,
                    action,
                    ancestor,
                    current_local,
                    current_remote,
                    reason,
                )
            )

        return SyncPlan(
            local_root=local.root,
            remote_root=remote.root,
            has_shared_baseline=base is not None,
            decisions=tuple(result),
        )
