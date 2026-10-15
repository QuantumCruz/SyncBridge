
"""Durable, conservative shared baselines for one SyncBridge folder pair.

A shared baseline is NOT the local scanner cache. Only a coordinator using
mutually authenticated peer messages may mark the remote acknowledgement.
The coordinator must ensure both peers confirm the same proposal and revision;
SQLite alone cannot atomically commit a transaction on two computers.

No file contents are transferred or filesystem files changed by this module.
Use a database outside shared folders or under their excluded .syncbridge
subdirectory. Baselines compare SHA-256 + size, never timestamps.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
import struct
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from syncbridge.core.scanner import FileRecord, ScanResult

_ID = re.compile(r"[0-9a-f]{32}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_RESERVED = re.compile(
    r"(?i)(con|prn|aux|nul|conin\$|conout\$|com[0-9]|lpt[0-9])(?:\..*)?\Z"
)
_EXCLUDED = frozenset({".syncbridge", ".git", ".venv", "__pycache__"})
_MAX_FILES = 250_000
_MAX_SIZE = 2**63 - 1


class SharedStateError(ValueError):
    """A proposed shared state is unsafe, stale, or inconsistent."""


class RevisionConflict(SharedStateError):
    """A baseline was advanced by another synchronization operation."""


class BaselineNotReady(SharedStateError):
    """A proposal needs both confirmations and a matching local rescan."""


@dataclass(frozen=True, slots=True)
class SharedBaseline:
    local_root: Path
    peer_node_id: str
    share_id: str
    revision: int
    sha256: str
    committed_at: datetime
    snapshot: ScanResult


@dataclass(frozen=True, slots=True)
class BaselineProposal:
    proposal_id: str
    expected_revision: int
    sha256: str
    file_count: int
    local_confirmed: bool
    remote_confirmed: bool


def _identity(value: str, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise SharedStateError(f"{label} must be 32 lowercase hex characters")
    return value


def _validate_path(path: str) -> str:
    if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path:
        raise SharedStateError("Invalid portable relative path")
    try:
        encoded = path.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SharedStateError("Invalid Unicode path") from exc
    if len(encoded) > 1024:
        raise SharedStateError("File path exceeds 1024 UTF-8 bytes")
    for part in path.split("/"):
        if (
            not part or part in (".", "..") or part.endswith((" ", "."))
            or part.casefold() in _EXCLUDED
            or len(part.encode("utf-8")) > 255
            or _RESERVED.fullmatch(part)
            or any(ord(c) < 32 or ord(c) == 127 or c in '<>:"|?*' for c in part)
        ):
            raise SharedStateError(f"Unsafe portable file path: {path!r}")
    return path


def _canonical_rows(snapshot: ScanResult, root: Path) -> tuple[tuple[str, int, str], ...]:
    if not isinstance(snapshot, ScanResult):
        raise TypeError("snapshot must be a ScanResult")
    if Path(snapshot.root).expanduser().resolve() != root:
        raise SharedStateError("Snapshot does not belong to this local folder")
    if not snapshot.complete:
        raise SharedStateError("Incomplete inventory cannot become a shared baseline")
    if len(snapshot.files) > _MAX_FILES:
        raise SharedStateError("Shared inventory exceeds file limit")

    rows = []
    normalized: dict[str, str] = {}
    for path, record in sorted(snapshot.files.items()):
        _validate_path(path)
        if (
            not isinstance(record, FileRecord) or record.relative_path != path
            or type(record.size) is not int or not 0 <= record.size <= _MAX_SIZE
            or type(record.modified_ns) is not int
            or not isinstance(record.sha256, str) or _HASH.fullmatch(record.sha256) is None
        ):
            raise SharedStateError(f"Invalid file record: {path!r}")
        norm = unicodedata.normalize("NFC", path).casefold()
        if norm in normalized and normalized[norm] != path:
            raise SharedStateError("Case/Unicode filename collision")
        normalized[norm] = path
        rows.append((path, record.size, record.sha256))
    for path, _, _ in rows:
        parts = path.split("/")
        for i in range(1, len(parts)):
            parent = unicodedata.normalize("NFC", "/".join(parts[:i])).casefold()
            if parent in normalized:
                raise SharedStateError("A file collides with a parent directory")
    return tuple(rows)


def _digest(rows: tuple[tuple[str, int, str], ...]) -> str:
    digest = hashlib.sha256(b"SyncBridge shared baseline v1\x00")
    digest.update(struct.pack("!I", len(rows)))
    for path, size, sha256 in rows:
        raw = path.encode("utf-8")
        digest.update(struct.pack("!I", len(raw)))
        digest.update(raw)
        digest.update(struct.pack("!Q", size))
        digest.update(bytes.fromhex(sha256))
    return digest.hexdigest()


def _scan_from_rows(root: Path, rows: tuple[tuple[str, int, str], ...]) -> ScanResult:
    return ScanResult(root=root, files={
        path: FileRecord(path, size, 0, sha256)
        for path, size, sha256 in rows
    })


class SharedStateDatabase:
    """SQLite two-confirmation staging for a per-device, per-share baseline.

    A remote acknowledgement may ONLY be recorded after an authenticated
    encrypted response has identified the expected peer and matched SHA-256.
    Actual cross-device two-phase orchestration is implemented separately.
    """

    def __init__(self, database_path: str | Path) -> None:
        self.path = Path(database_path).expanduser().resolve()
        if self.path.is_dir():
            raise IsADirectoryError(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS shared_baselines (
                    root TEXT NOT NULL,
                    peer_id TEXT NOT NULL,
                    share_id TEXT NOT NULL,
                    revision INTEGER NOT NULL CHECK(revision >= 1),
                    sha256 TEXT NOT NULL,
                    committed_at TEXT NOT NULL,
                    PRIMARY KEY(root, peer_id, share_id)
                );
                CREATE TABLE IF NOT EXISTS shared_files (
                    root TEXT NOT NULL, peer_id TEXT NOT NULL, share_id TEXT NOT NULL,
                    path TEXT NOT NULL, size INTEGER NOT NULL CHECK(size >= 0),
                    sha256 TEXT NOT NULL,
                    PRIMARY KEY(root, peer_id, share_id, path),
                    FOREIGN KEY(root, peer_id, share_id)
                        REFERENCES shared_baselines(root, peer_id, share_id)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS baseline_proposals (
                    root TEXT NOT NULL, peer_id TEXT NOT NULL, share_id TEXT NOT NULL,
                    proposal_id TEXT NOT NULL,
                    expected_revision INTEGER NOT NULL CHECK(expected_revision >= 0),
                    sha256 TEXT NOT NULL,
                    local_ok INTEGER NOT NULL DEFAULT 0 CHECK(local_ok IN (0,1)),
                    remote_ok INTEGER NOT NULL DEFAULT 0 CHECK(remote_ok IN (0,1)),
                    PRIMARY KEY(root, peer_id, share_id)
                );
                CREATE TABLE IF NOT EXISTS proposal_files (
                    root TEXT NOT NULL, peer_id TEXT NOT NULL, share_id TEXT NOT NULL,
                    path TEXT NOT NULL, size INTEGER NOT NULL CHECK(size >= 0),
                    sha256 TEXT NOT NULL,
                    PRIMARY KEY(root, peer_id, share_id, path),
                    FOREIGN KEY(root, peer_id, share_id)
                        REFERENCES baseline_proposals(root, peer_id, share_id)
                        ON DELETE CASCADE
                );
            """)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=10000")
        return db

    def _key(self, local_root: str | Path, peer_node_id: str, share_id: str) -> tuple[str, str, str]:
        root = Path(local_root).expanduser().resolve()
        if root == self.path.parent or self.path == root or root in self.path.parents:
            # An excluded .syncbridge directory is the only allowed in-tree location.
            try:
                relative = self.path.relative_to(root)
            except ValueError:
                pass
            else:
                if not relative.parts or relative.parts[0].casefold() != ".syncbridge":
                    raise SharedStateError("State database must not be synchronized")
        return str(root), _identity(peer_node_id, "peer_node_id"), _identity(share_id, "share_id")

    @staticmethod
    def _revision(db: sqlite3.Connection, key: tuple[str, str, str]) -> int:
        row = db.execute(
            "SELECT revision FROM shared_baselines WHERE root=? AND peer_id=? AND share_id=?", key
        ).fetchone()
        return int(row["revision"]) if row else 0

    @staticmethod
    def _rows(db: sqlite3.Connection, table: str, key: tuple[str, str, str]) -> tuple[tuple[str, int, str], ...]:
        if table not in ("shared_files", "proposal_files"):
            raise ValueError("Invalid table")
        data = db.execute(
            f"SELECT path,size,sha256 FROM {table} WHERE root=? AND peer_id=? AND share_id=? ORDER BY path", key
        ).fetchall()
        rows = tuple((row["path"], row["size"], row["sha256"]) for row in data)
        _canonical_rows(_scan_from_rows(Path(key[0]), rows), Path(key[0]))
        return rows

    @staticmethod
    def _proposal(row: sqlite3.Row, count: int) -> BaselineProposal:
        return BaselineProposal(
            row["proposal_id"], row["expected_revision"], row["sha256"],
            count, bool(row["local_ok"]), bool(row["remote_ok"])
        )

    def load(self, local_root: str | Path, peer_node_id: str, share_id: str) -> SharedBaseline | None:
        """None means never agreed; an empty baseline is a real saved state."""
        key = self._key(local_root, peer_node_id, share_id)
        with self._connect() as db:
            db.execute("BEGIN")
            row = db.execute(
                "SELECT revision,sha256,committed_at FROM shared_baselines "
                "WHERE root=? AND peer_id=? AND share_id=?", key
            ).fetchone()
            if row is None:
                return None
            rows = self._rows(db, "shared_files", key)
        if _digest(rows) != row["sha256"]:
            raise SharedStateError("Committed baseline contents failed integrity check")
        return SharedBaseline(
            Path(key[0]), key[1], key[2], row["revision"], row["sha256"],
            datetime.fromisoformat(row["committed_at"]),
            _scan_from_rows(Path(key[0]), rows),
        )

    def pending(self, local_root: str | Path, peer_node_id: str, share_id: str) -> BaselineProposal | None:
        key = self._key(local_root, peer_node_id, share_id)
        with self._connect() as db:
            db.execute("BEGIN")
            row = db.execute(
                "SELECT * FROM baseline_proposals WHERE root=? AND peer_id=? AND share_id=?", key
            ).fetchone()
            if row is None:
                return None
            rows = self._rows(db, "proposal_files", key)
        if _digest(rows) != row["sha256"]:
            raise SharedStateError("Staged baseline contents failed integrity check")
        return self._proposal(row, len(rows))

    def stage(
        self, local_root: str | Path, peer_node_id: str, share_id: str,
        snapshot: ScanResult, *, expected_revision: int,
        proposal_id: str | None = None,
    ) -> BaselineProposal:
        """Persist a proposed COMMON state without changing the active baseline."""
        key = self._key(local_root, peer_node_id, share_id)
        rows = _canonical_rows(snapshot, Path(key[0]))
        if type(expected_revision) is not int or expected_revision < 0:
            raise SharedStateError("expected_revision must be nonnegative")
        identifier = _identity(proposal_id or uuid4().hex, "proposal_id")
        sha256 = _digest(rows)
        with self._connect() as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                if self._revision(db, key) != expected_revision:
                    raise RevisionConflict("Shared baseline revision changed")
                previous = db.execute(
                    "SELECT * FROM baseline_proposals WHERE root=? AND peer_id=? AND share_id=?", key
                ).fetchone()
                if previous is not None:
                    if (previous["proposal_id"], previous["expected_revision"], previous["sha256"]) != (identifier, expected_revision, sha256):
                        raise SharedStateError("Another proposal is pending; abort it explicitly first")
                    staged_rows = self._rows(db, "proposal_files", key)
                    if staged_rows != rows:
                        raise SharedStateError("Staged proposal contents differ")
                    result = self._proposal(previous, len(rows))
                else:
                    db.execute(
                        "INSERT INTO baseline_proposals(root,peer_id,share_id,proposal_id,expected_revision,sha256) "
                        "VALUES(?,?,?,?,?,?)", (*key, identifier, expected_revision, sha256)
                    )
                    db.executemany(
                        "INSERT INTO proposal_files(root,peer_id,share_id,path,size,sha256) VALUES(?,?,?,?,?,?)",
                        ((*key, path, size, digest) for path, size, digest in rows),
                    )
                    result = BaselineProposal(identifier, expected_revision, sha256, len(rows), False, False)
                db.commit()
                return result
            except Exception:
                db.rollback()
                raise

    def confirm_local(
        self, local_root: str | Path, peer_node_id: str, share_id: str,
        proposal_id: str, current_scan: ScanResult,
    ) -> BaselineProposal:
        """Confirm that a fresh, complete LOCAL inventory matches the proposal."""
        key = self._key(local_root, peer_node_id, share_id)
        identifier = _identity(proposal_id, "proposal_id")
        actual = _digest(_canonical_rows(current_scan, Path(key[0])))
        return self._confirm(key, identifier, "local_ok", actual)

    def confirm_remote(
        self, local_root: str | Path, peer_node_id: str, share_id: str,
        proposal_id: str, *, authenticated_peer_id: str, acknowledged_sha256: str,
    ) -> BaselineProposal:
        """Record a matching remote receipt ONLY from a verified secure peer.

        This storage API cannot itself authenticate the network connection.
        The coordinator MUST supply the identity obtained from the secure
        channel, NOT an untrusted field inside a received JSON message.
        """
        key = self._key(local_root, peer_node_id, share_id)
        identifier = _identity(proposal_id, "proposal_id")
        if _identity(authenticated_peer_id, "authenticated_peer_id") != key[1]:
            raise SharedStateError("Acknowledgement came from the wrong peer")
        if not isinstance(acknowledged_sha256, str) or _HASH.fullmatch(acknowledged_sha256) is None:
            raise SharedStateError("Invalid remote baseline digest")
        return self._confirm(key, identifier, "remote_ok", acknowledged_sha256)

    def _confirm(
        self, key: tuple[str, str, str], identifier: str, column: str, digest: str,
    ) -> BaselineProposal:
        if column not in ("local_ok", "remote_ok"):
            raise ValueError("Invalid acknowledgement type")
        with self._connect() as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT * FROM baseline_proposals WHERE root=? AND peer_id=? AND share_id=?", key
                ).fetchone()
                if row is None or row["proposal_id"] != identifier:
                    raise SharedStateError("Unknown baseline proposal")
                if row["expected_revision"] != self._revision(db, key):
                    raise RevisionConflict("Shared baseline advanced while proposal was pending")
                rows = self._rows(db, "proposal_files", key)
                if _digest(rows) != row["sha256"]:
                    raise SharedStateError("Staged proposal is corrupted")
                if digest != row["sha256"]:
                    raise BaselineNotReady("Acknowledged inventory does not match proposal")
                db.execute(
                    f"UPDATE baseline_proposals SET {column}=1 WHERE root=? AND peer_id=? AND share_id=?", key
                )
                updated = db.execute(
                    "SELECT * FROM baseline_proposals WHERE root=? AND peer_id=? AND share_id=?", key
                ).fetchone()
                db.commit()
                return self._proposal(updated, len(rows))
            except Exception:
                db.rollback()
                raise

    def finalize(
        self, local_root: str | Path, peer_node_id: str, share_id: str,
        proposal_id: str, current_scan: ScanResult,
    ) -> SharedBaseline:
        """Atomically promote a double-confirmed proposal after local recheck."""
        key = self._key(local_root, peer_node_id, share_id)
        identifier = _identity(proposal_id, "proposal_id")
        actual = _digest(_canonical_rows(current_scan, Path(key[0])))
        with self._connect() as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                pending = db.execute(
                    "SELECT * FROM baseline_proposals WHERE root=? AND peer_id=? AND share_id=?", key
                ).fetchone()
                if pending is None or pending["proposal_id"] != identifier:
                    raise SharedStateError("Unknown baseline proposal")
                if pending["expected_revision"] != self._revision(db, key):
                    raise RevisionConflict("Shared baseline revision changed")
                if not pending["local_ok"] or not pending["remote_ok"]:
                    raise BaselineNotReady("Both local and remote confirmations are required")
                rows = self._rows(db, "proposal_files", key)
                if _digest(rows) != pending["sha256"]:
                    raise SharedStateError("Staged baseline failed integrity check")
                if actual != pending["sha256"]:
                    raise BaselineNotReady("Local files changed since their acknowledgement")

                revision = pending["expected_revision"] + 1
                committed_at = datetime.now(timezone.utc)
                db.execute(
                    "INSERT INTO shared_baselines(root,peer_id,share_id,revision,sha256,committed_at) "
                    "VALUES(?,?,?,?,?,?) ON CONFLICT(root,peer_id,share_id) DO UPDATE SET "
                    "revision=excluded.revision,sha256=excluded.sha256,committed_at=excluded.committed_at",
                    (*key, revision, pending["sha256"], committed_at.isoformat()),
                )
                db.execute(
                    "DELETE FROM shared_files WHERE root=? AND peer_id=? AND share_id=?", key
                )
                db.executemany(
                    "INSERT INTO shared_files(root,peer_id,share_id,path,size,sha256) VALUES(?,?,?,?,?,?)",
                    ((*key, path, size, digest) for path, size, digest in rows),
                )
                db.execute(
                    "DELETE FROM baseline_proposals WHERE root=? AND peer_id=? AND share_id=?", key
                )
                db.commit()
            except Exception:
                db.rollback()
                raise
        return SharedBaseline(
            Path(key[0]), key[1], key[2], revision, pending["sha256"],
            committed_at, _scan_from_rows(Path(key[0]), rows),
        )

    def abort(
        self, local_root: str | Path, peer_node_id: str, share_id: str,
        proposal_id: str,
    ) -> bool:
        """Cancel a pending proposal without altering the committed baseline."""
        key = self._key(local_root, peer_node_id, share_id)
        identifier = _identity(proposal_id, "proposal_id")
        with self._connect() as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                deleted = db.execute(
                    "DELETE FROM baseline_proposals WHERE root=? AND peer_id=? AND share_id=? AND proposal_id=?",
                    (*key, identifier),
                ).rowcount
                db.commit()
                return bool(deleted)
            except Exception:
                db.rollback()
                raise
