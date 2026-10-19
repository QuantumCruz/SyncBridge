
"""Persistent, receiver-local fencing leases for future guarded SyncBridge writes.

This module is a foundation, NOT yet an enforced transfer protocol. It has no
network endpoints and does not authorize file writes. The eventual receiver must
validate a grant at the same atomic boundary as each protected mutation;
checking a grant in advance is not sufficient to prevent a stale writer.

An authority must reside in the local application profile, never in a synced
folder. All contenders for a given receiver/share must use the same database.
"""

from __future__ import annotations

import math
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator


class LeaseError(RuntimeError):
    """A local lease operation was refused."""


class LeaseBusy(LeaseError):
    """Another unexpired session holds the share lease."""


class FencedOut(LeaseError):
    """A lease expired, was released, or was superseded."""


class LeaseClockError(LeaseError):
    """The local clock moved backwards; fail closed until corrected."""


@dataclass(frozen=True, slots=True)
class LeaseGrant:
    share_id: str
    owner_node_id: str
    session_token: str = field(repr=False)
    generation: int
    expires_at: float


_MAX_GENERATION = (1 << 63) - 1


def _hex_id(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 32
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ValueError(f"{label} must be 32 lowercase hex characters")
    return value


def _ttl(value: float) -> float:
    if (
        type(value) not in (int, float)
        or not math.isfinite(value)
        or not 0.1 <= value <= 3600.0
    ):
        raise ValueError(
            "ttl_seconds must be a finite number from 0.1 to 3600"
        )
    return float(value)


class LeaseAuthority:
    """Serialize receiver-local lease generations using durable SQLite state.

    This class is intentionally independent of transport, identities, and the
    transfer service. In particular, its ``assert_current`` method is only a
    diagnostic/precondition check, NOT an atomic filesystem write barrier.
    """

    def __init__(
        self,
        database_path: str | Path,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not callable(clock):
            raise TypeError("clock must be callable")

        self.path = Path(database_path).expanduser()

        if self.path.exists() and not self.path.is_file():
            raise ValueError(
                "lease database path must be a regular file"
            )

        if self.path.is_symlink():
            raise ValueError(
                "lease database path cannot be a symbolic link"
            )

        self._clock = clock
        self.path.parent.mkdir(parents=True, exist_ok=True)

        with self._connect() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS lease_fences (
                    share_id TEXT PRIMARY KEY,
                    generation INTEGER NOT NULL CHECK(generation > 0),
                    owner_node_id TEXT,
                    session_token TEXT,
                    expires_at REAL,
                    observed_at REAL NOT NULL
                )"""
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
            self.path,
            timeout=5.0,
            isolation_level=None,
        )

        try:
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA synchronous=FULL")
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")

            try:
                yield connection
                connection.execute("COMMIT")

            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def _now(self) -> float:
        now = self._clock()

        if (
            type(now) not in (int, float)
            or not math.isfinite(now)
        ):
            raise LeaseClockError(
                "local clock returned an invalid timestamp"
            )

        return float(now)

    @staticmethod
    def _row(
        connection: sqlite3.Connection,
        share_id: str,
    ):
        return connection.execute(
            """SELECT generation, owner_node_id, session_token,
                      expires_at, observed_at
               FROM lease_fences WHERE share_id = ?""",
            (share_id,),
        ).fetchone()

    @staticmethod
    def _check_clock(row, now: float) -> None:
        if row is not None and now < row[4]:
            raise LeaseClockError(
                "local clock moved backwards; refusing lease operation"
            )

    @staticmethod
    def _current(
        row,
        lease: LeaseGrant,
        now: float,
    ) -> None:
        if (
            row is None
            or row[0] != lease.generation
            or row[1] != lease.owner_node_id
            or row[2] != lease.session_token
            or row[3] is None
            or now >= row[3]
        ):
            raise FencedOut(
                "lease expired or belongs to another session"
            )

    @staticmethod
    def _valid_grant(lease: LeaseGrant) -> None:
        if not isinstance(lease, LeaseGrant):
            raise TypeError(
                "lease must be a LeaseGrant"
            )

        _hex_id(lease.share_id, "share_id")
        _hex_id(lease.owner_node_id, "owner_node_id")

        if (
            type(lease.generation) is not int
            or not 1 <= lease.generation <= _MAX_GENERATION
            or not isinstance(lease.session_token, str)
            or len(lease.session_token) != 64
            or any(
                char not in "0123456789abcdef"
                for char in lease.session_token
            )
        ):
            raise ValueError(
                "invalid lease generation or session token"
            )

    def acquire(
        self,
        share_id: str,
        owner_node_id: str,
        *,
        ttl_seconds: float = 30.0,
    ) -> LeaseGrant:
        """Allocate a new, strictly increasing generation for this share."""
        _hex_id(share_id, "share_id")
        _hex_id(owner_node_id, "owner_node_id")
        ttl = _ttl(ttl_seconds)

        with self._write() as connection:
            now = self._now()
            row = self._row(connection, share_id)
            self._check_clock(row, now)

            if (
                row is not None
                and row[3] is not None
                and now < row[3]
            ):
                raise LeaseBusy(
                    "another session currently holds this share"
                )

            generation = (
                1 if row is None else row[0] + 1
            )

            if generation > _MAX_GENERATION:
                raise LeaseError(
                    "lease generation counter exhausted"
                )

            token = secrets.token_hex(32)
            expires_at = now + ttl

            if row is None:
                connection.execute(
                    """INSERT INTO lease_fences
                       (share_id, generation, owner_node_id, session_token,
                        expires_at, observed_at) VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        share_id,
                        generation,
                        owner_node_id,
                        token,
                        expires_at,
                        now,
                    ),
                )

            else:
                connection.execute(
                    """UPDATE lease_fences SET generation = ?,
                       owner_node_id = ?, session_token = ?, expires_at = ?,
                       observed_at = ? WHERE share_id = ?""",
                    (
                        generation,
                        owner_node_id,
                        token,
                        expires_at,
                        now,
                        share_id,
                    ),
                )

            return LeaseGrant(
                share_id,
                owner_node_id,
                token,
                generation,
                expires_at,
            )

    def renew(
        self,
        lease: LeaseGrant,
        *,
        ttl_seconds: float = 30.0,
    ) -> LeaseGrant:
        """Extend only the current session; never revive an expired one."""
        self._valid_grant(lease)
        ttl = _ttl(ttl_seconds)

        with self._write() as connection:
            now = self._now()
            row = self._row(connection, lease.share_id)
            self._check_clock(row, now)
            self._current(row, lease, now)

            expires_at = now + ttl

            connection.execute(
                """UPDATE lease_fences SET expires_at = ?, observed_at = ?
                   WHERE share_id = ?""",
                (expires_at, now, lease.share_id),
            )

            return LeaseGrant(
                lease.share_id,
                lease.owner_node_id,
                lease.session_token,
                lease.generation,
                expires_at,
            )

    def assert_current(
        self,
        lease: LeaseGrant,
    ) -> LeaseGrant:
        """Check current authority; NOT atomic with later filesystem writes."""
        self._valid_grant(lease)

        with self._write() as connection:
            now = self._now()
            row = self._row(connection, lease.share_id)
            self._check_clock(row, now)
            self._current(row, lease, now)

            connection.execute(
                """UPDATE lease_fences SET observed_at = ?
                   WHERE share_id = ?""",
                (now, lease.share_id),
            )

            return LeaseGrant(
                lease.share_id,
                lease.owner_node_id,
                lease.session_token,
                lease.generation,
                row[3],
            )

    def release(
        self,
        lease: LeaseGrant,
    ) -> None:
        """Revoke the current session, retaining its generation permanently."""
        self._valid_grant(lease)

        with self._write() as connection:
            now = self._now()
            row = self._row(connection, lease.share_id)
            self._check_clock(row, now)
            self._current(row, lease, now)

            connection.execute(
                """UPDATE lease_fences SET owner_node_id = NULL,
                   session_token = NULL, expires_at = NULL, observed_at = ?
                   WHERE share_id = ?""",
                (now, lease.share_id),
            )
