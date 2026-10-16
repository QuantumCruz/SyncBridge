
"""Durable, opt-in completion jobs for previously approved folder setup.

Only the initiating device records a job after the secure setup exchange has
saved an approved folder. A disabled share on its own is NEVER activation
consent. Jobs are scoped to a share ID and a verified peer identity; the
activation protocol checks folder configuration and trust again before writes.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path

from syncbridge.network.share_setup import _id


class ReadinessJobs:
    """Small, crash-persistent queue. Does not grant any permissions itself."""

    def __init__(self, profile: str | Path):
        self.path = Path(profile).expanduser().resolve() / "pending_readiness.json"
        self._lock = threading.RLock()

    def _read(self) -> dict[str, str]:
        if self.path.is_symlink():
            raise ValueError("Refusing linked readiness journal")
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return {}
        if len(raw) > 16384:
            raise ValueError("Readiness journal is too large")

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate readiness journal key")
                result[key] = value
            return result

        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
        if not isinstance(data, dict) or len(data) > 64:
            raise ValueError("Invalid readiness journal")
        for share_id, peer_id in data.items():
            _id(share_id)
            _id(peer_id)
        return data

    def entries(self) -> tuple[tuple[str, str], ...]:
        with self._lock:
            return tuple(self._read().items())

    def _write(self, records: dict[str, str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(
            prefix=".pending_readiness.", suffix=".tmp", dir=self.path.parent
        )
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(json.dumps(records, sort_keys=True).encode("utf-8"))
                stream.flush()
                os.fsync(stream.fileno())
            if self.path.is_symlink():
                raise ValueError("Refusing linked readiness journal")
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def add(self, share_id: str, peer_id: str) -> None:
        _id(share_id)
        _id(peer_id)
        with self._lock:
            records = self._read()
            if share_id in records and records[share_id] != peer_id:
                raise ValueError("Readiness job has a different peer identity")
            records[share_id] = peer_id
            self._write(records)

    def remove(self, share_id: str, peer_id: str) -> None:
        with self._lock:
            records = self._read()
            if records.get(share_id) == peer_id:
                del records[share_id]
                self._write(records)
