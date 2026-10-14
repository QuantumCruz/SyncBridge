
"""Persistent snapshot metadata for SyncBridge.

File contents and hashes use the shared FileRecord model from core.scanner.
This module contains only metadata specific to persistent snapshots.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass(frozen=True, slots=True)
class SnapshotInfo:
    """Metadata describing one saved, complete inventory of a folder."""

    root: Path
    saved_at: datetime
    file_count: int
