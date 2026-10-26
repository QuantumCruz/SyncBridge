
"""Durable, locally recoverable checkpoints for coordinated folder changes.

The journal is written BEFORE stopping the original synchronization runtime.
It records only the previously approved share and a session identifier; it
contains no device private keys. Its contents are signed by the local device
identity to detect accidental modification or substitution.

A journal is retained until a DIFFERENT, approved share reaches Connected.
After interruption, the UI must not open network listeners or synchronize
until the user explicitly resolves the previous relationship.
This is fail-closed recovery, not a distributed atomic transaction.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.storage.config import ConfigStore, ShareConfig, SyncPreferences

_VERSION = 1
_MAX_BYTES = 32_768
_ID = re.compile(r"[0-9a-f]{32}\Z")
_STAGES = {"preparing", "committing"}


class FolderRecoveryError(RuntimeError):
    """The previous relationship cannot safely be recovered or finalized."""


@dataclass(frozen=True)
class FolderCheckpoint:
    session_id: str
    original: ShareConfig
    stage: str
    created_at: int


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate recovery field")
        result[key] = value
    return result


def _file_check(path: Path) -> None:
    if path.is_symlink() or (
        hasattr(os.path, "isjunction") and os.path.isjunction(path)
    ):
        raise FolderRecoveryError("Recovery record is a link")
    if path.exists() and not path.is_file():
        raise FolderRecoveryError("Recovery record is not a regular file")


class FolderChangeJournal:
    """One durable, signed checkpoint belonging to one local ConfigStore."""

    def __init__(self, store: ConfigStore) -> None:
        if not isinstance(store, ConfigStore):
            raise TypeError("store must be ConfigStore")
        self.store = store
        self.path = store.path.parent / "folder-change-recovery.json"
        self.identity_path = store.path.parent / "identity.json"
        self.trust_path = store.path.parent / "trust.json"

    def _identity(self):
        if not self.identity_path.is_file() or self.identity_path.is_symlink():
            raise FolderRecoveryError("The computer identity is unavailable")
        return load_or_create_identity(self.identity_path)

    def load(self) -> FolderCheckpoint | None:
        _file_check(self.path)
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return None

        if not raw or len(raw) > _MAX_BYTES:
            raise FolderRecoveryError("Recovery record has an invalid size")

        try:
            record = json.loads(
                raw.decode("utf-8"), object_pairs_hook=_pairs
            )
            if not isinstance(record, dict) or set(record) != {
                "payload", "signature"
            }:
                raise ValueError("Invalid recovery envelope")

            data = record["payload"]
            if not isinstance(data, dict) or set(data) != {
                "version", "session_id", "original", "stage", "created_at"
            }:
                raise ValueError("Invalid recovery fields")

            if type(data["version"]) is not int or data["version"] != _VERSION:
                raise ValueError("Unsupported recovery version")
            if (
                not isinstance(data["session_id"], str)
                or _ID.fullmatch(data["session_id"]) is None
            ):
                raise ValueError("Invalid recovery session")
            if data["stage"] not in _STAGES:
                raise ValueError("Invalid recovery stage")
            if (
                type(data["created_at"]) is not int
                or not 1 <= data["created_at"] <= 10**12
            ):
                raise ValueError("Invalid recovery creation time")

            original_data = data["original"]
            if not isinstance(original_data, dict):
                raise ValueError("Invalid saved folder")

            preferences = original_data.get("preferences")
            if not isinstance(preferences, dict):
                raise ValueError("Invalid saved preferences")

            original = ShareConfig(
                **{
                    **original_data,
                    "preferences": SyncPreferences(**preferences),
                }
            )
            if not original.enabled:
                raise ValueError("Only approved shares can be recovered")

            signature = bytes.fromhex(record["signature"])
            if len(signature) != 64:
                raise ValueError("Invalid recovery signature")

            identity = self._identity()
            Ed25519PublicKey.from_public_bytes(identity.public_key).verify(
                signature, _canonical(data)
            )

            return FolderCheckpoint(
                data["session_id"],
                original,
                data["stage"],
                data["created_at"],
            )

        except (
            ValueError,
            TypeError,
            KeyError,
            UnicodeError,
            InvalidSignature,
        ) as exc:
            raise FolderRecoveryError(
                "Recovery record is invalid or its signature does not match"
            ) from exc

    def _write(self, checkpoint: FolderCheckpoint) -> None:
        identity = self._identity()
        data = {
            "version": _VERSION,
            "session_id": checkpoint.session_id,
            "original": asdict(checkpoint.original),
            "stage": checkpoint.stage,
            "created_at": checkpoint.created_at,
        }
        envelope = {
            "payload": data,
            "signature": identity.sign(_canonical(data)).hex(),
        }
        raw = _canonical(envelope) + b"\n"
        if len(raw) > _MAX_BYTES:
            raise FolderRecoveryError("Recovery record is too large")

        self.path.parent.mkdir(parents=True, exist_ok=True)
        _file_check(self.path)
        fd, temporary = tempfile.mkstemp(
            prefix=".folder-change-",
            suffix=".tmp",
            dir=self.path.parent,
        )
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)

            if os.name != "nt":
                directory = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def begin(
        self, session_id: str, original: ShareConfig
    ) -> FolderCheckpoint:
        if (
            not isinstance(session_id, str)
            or _ID.fullmatch(session_id) is None
        ):
            raise FolderRecoveryError("Invalid session identifier")
        if not isinstance(original, ShareConfig) or not original.enabled:
            raise FolderRecoveryError(
                "An approved folder relationship is required"
            )
        if self.load() is not None:
            raise FolderRecoveryError(
                "An earlier folder change needs recovery"
            )

        settings = self.store.load()
        if settings.shares != (original,):
            raise FolderRecoveryError(
                "The saved folder changed before preparation"
            )

        checkpoint = FolderCheckpoint(
            session_id,
            original,
            "preparing",
            int(time.time()),
        )
        self._write(checkpoint)
        return checkpoint

    def mark_committing(self, session_id: str) -> None:
        checkpoint = self.load()
        if checkpoint is None or checkpoint.session_id != session_id:
            raise FolderRecoveryError(
                "Missing matching folder-change checkpoint"
            )
        if checkpoint.stage != "committing":
            self._write(replace(checkpoint, stage="committing"))

    def finish_if_connected(self, new_share: ShareConfig) -> bool:
        """Resolve only after connecting a NEW, approved folder relationship."""
        checkpoint = self.load()
        if checkpoint is None:
            return False
        if (
            not isinstance(new_share, ShareConfig)
            or not new_share.enabled
            or checkpoint.stage != "committing"
            or new_share.share_id == checkpoint.original.share_id
            or new_share.peer_node_id != checkpoint.original.peer_node_id
            or self.store.load().shares != (new_share,)
        ):
            raise FolderRecoveryError(
                "The replacement folder is not ready"
            )
        self._remove()
        return True

    def restore_previous(self, *, running: bool) -> ShareConfig:
        """Explicit local recovery; never overwrite an unrelated new share."""
        if type(running) is not bool or running:
            raise FolderRecoveryError(
                "Stop the active connection before recovery"
            )
        checkpoint = self.load()
        if checkpoint is None:
            raise FolderRecoveryError(
                "There is no interrupted folder change"
            )

        original = checkpoint.original
        if TrustStore(self.trust_path).get(original.peer_node_id) is None:
            raise FolderRecoveryError(
                "The old computer is no longer trusted"
            )

        current = self.store.load()
        if current.shares == ():
            self.store.save(replace(current, shares=(original,)))
        elif current.shares != (original,):
            raise FolderRecoveryError(
                "Another folder is already configured; "
                "recovery will not overwrite it"
            )

        self._remove()
        return original

    def keep_replacement(self, *, running: bool) -> ShareConfig:
        """Explicitly retain a newer approved share without auto-connecting.

        The other laptop must hold the same new relationship and still
        approve a fresh live connection.
        """
        if type(running) is not bool or running:
            raise FolderRecoveryError(
                "Stop the active connection before recovery"
            )
        checkpoint = self.load()
        if checkpoint is None:
            raise FolderRecoveryError(
                "There is no interrupted folder change"
            )

        current = self.store.load()
        if len(current.shares) != 1:
            raise FolderRecoveryError(
                "No new approved folder has been saved"
            )
        replacement = current.shares[0]

        if (
            not replacement.enabled
            or checkpoint.stage != "committing"
            or replacement.share_id == checkpoint.original.share_id
            or replacement.peer_node_id != checkpoint.original.peer_node_id
            or TrustStore(self.trust_path).get(replacement.peer_node_id) is None
        ):
            raise FolderRecoveryError(
                "The new folder is not a matching approved share"
            )

        self._remove()
        return replacement

    def _remove(self) -> None:
        _file_check(self.path)
        self.path.unlink()
        if os.name != "nt":
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
