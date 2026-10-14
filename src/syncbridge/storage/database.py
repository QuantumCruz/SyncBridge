
"""SQLite persistence for complete SyncBridge filesystem snapshots.

Saves are transactional: incomplete scans are rejected, and a failed write
keeps the previously committed snapshot intact. No filesystem changes occur.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from syncbridge.core.scanner import FileRecord, ScanResult
from .models import SnapshotInfo


class SnapshotDatabase:
    """Keep the last successfully saved file inventory for each local folder.

    The database path should be outside watched folders or inside a directory
    excluded by the scanner, such as ``.syncbridge``.
    """

    def __init__(self, database_path: str | Path) -> None:
        self.path = Path(database_path).expanduser().resolve()
        if self.path.is_dir():
            raise IsADirectoryError(f"Database path is a directory: {self.path}")

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS snapshots (
                    root TEXT PRIMARY KEY,
                    saved_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS snapshot_files (
                    root TEXT NOT NULL,
                    relative_path TEXT NOT NULL,
                    size INTEGER NOT NULL CHECK (size >= 0),
                    modified_ns INTEGER NOT NULL,
                    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
                    PRIMARY KEY (root, relative_path),
                    FOREIGN KEY (root) REFERENCES snapshots(root) ON DELETE CASCADE
                );
                """
            )
            connection.commit()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10.0)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            yield connection
        finally:
            connection.close()

    @staticmethod
    def _canonical_root(root: str | Path) -> Path:
        return Path(root).expanduser().resolve()

    @staticmethod
    def _validate_record(path: str, record: FileRecord) -> None:
        """Reject malformed paths/records before touching persistent state."""
        if (
            not isinstance(path, str)
            or not path
            or "\\" in path
            or any(part in ("", ".", "..") for part in path.split("/"))
            or path != record.relative_path
        ):
            raise ValueError(f"Invalid file path in snapshot: {path!r}")

        if record.size < 0 or not isinstance(record.modified_ns, int):
            raise ValueError(f"Invalid file metadata for {path!r}")

        if (
            len(record.sha256) != 64
            or any(character not in "0123456789abcdef" for character in record.sha256)
        ):
            raise ValueError(f"Invalid SHA-256 hash for {path!r}")

    def save_snapshot(self, scan: ScanResult) -> SnapshotInfo:
        """Atomically replace one root's snapshot with a complete scan."""
        if not scan.complete:
            raise ValueError("Refusing to save an incomplete filesystem scan")

        root = self._canonical_root(scan.root)
        records = tuple(sorted(scan.files.items()))
        for path, record in records:
            self._validate_record(path, record)

        saved_at = datetime.now(timezone.utc)

        with self._connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT INTO snapshots (root, saved_at) VALUES (?, ?)
                    ON CONFLICT(root) DO UPDATE SET saved_at = excluded.saved_at
                    """,
                    (str(root), saved_at.isoformat()),
                )
                connection.execute(
                    "DELETE FROM snapshot_files WHERE root = ?", (str(root),)
                )
                connection.executemany(
                    """
                    INSERT INTO snapshot_files
                        (root, relative_path, size, modified_ns, sha256)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        (str(root), path, record.size, record.modified_ns, record.sha256)
                        for path, record in records
                    ),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

        return SnapshotInfo(root=root, saved_at=saved_at, file_count=len(records))

    def load_snapshot(self, root: str | Path) -> ScanResult | None:
        """Load a root's last committed scan, or None if never saved."""
        resolved_root = self._canonical_root(root)

        with self._connect() as connection:
            try:
                connection.execute("BEGIN")
                saved = connection.execute(
                    "SELECT root FROM snapshots WHERE root = ?", (str(resolved_root),)
                ).fetchone()
                if saved is None:
                    connection.commit()
                    return None

                rows = connection.execute(
                    """
                    SELECT relative_path, size, modified_ns, sha256
                    FROM snapshot_files
                    WHERE root = ?
                    ORDER BY relative_path
                    """,
                    (str(resolved_root),),
                ).fetchall()
                connection.commit()
            except Exception:
                connection.rollback()
                raise

        return ScanResult(
            root=resolved_root,
            files={
                row["relative_path"]: FileRecord(
                    relative_path=row["relative_path"],
                    size=row["size"],
                    modified_ns=row["modified_ns"],
                    sha256=row["sha256"],
                )
                for row in rows
            },
        )

    def list_snapshots(self) -> tuple[SnapshotInfo, ...]:
        """List saved folder roots and summary metadata."""
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT snapshots.root, snapshots.saved_at,
                       COUNT(snapshot_files.relative_path) AS file_count
                FROM snapshots
                LEFT JOIN snapshot_files
                    ON snapshot_files.root = snapshots.root
                GROUP BY snapshots.root, snapshots.saved_at
                ORDER BY snapshots.root
                """
            ).fetchall()

        return tuple(
            SnapshotInfo(
                root=Path(row["root"]),
                saved_at=datetime.fromisoformat(row["saved_at"]),
                file_count=row["file_count"],
            )
            for row in rows
        )
