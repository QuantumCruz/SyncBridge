
"""Owner-controlled, read-only recovery inventory and explicit restoration.

Recovery records come from Phase 18's RecoveryVault. The Recovery Center
never deletes a backup and never silently replaces an existing file.

Restoring acquires the SAME profile lock as SyncBridgeRuntime. This excludes a
concurrent runtime using that local profile. It does NOT lock other devices or
unrelated filesystem programs. Keep the other device idle during restoration.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from syncbridge.core.approved_deletion import (
    ApprovedDeletionError,
    RecoveryVault,
)
from syncbridge.network.deletion_approval import DeletionRequest
from syncbridge.runtime import InstanceAlreadyRunning, _ProfileLock
from syncbridge.storage.shared_state import _validate_path


class RecoveryCenterError(RuntimeError):
    """A recovery record cannot safely be viewed or restored."""


@dataclass(frozen=True, slots=True)
class RecoveryItem:
    request_id: str
    path: str
    size: int | None
    code: str
    message: str
    can_restore: bool


_HEX = frozenset("0123456789abcdef")
_KEYS = frozenset({
    "request_id",
    "share_id",
    "peer_node_id",
    "path",
    "baseline_revision",
    "baseline_sha256",
    "file_sha256",
    "file_size",
})


def _hex_string(value: object, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in _HEX for character in value)
    )


def _linked(path: Path) -> bool:
    return path.is_symlink() or (
        hasattr(os.path, "isjunction")
        and os.path.isjunction(path)
    )


class RecoveryCenter:
    """Inspect and restore copies saved by a single SyncBridge profile.

    `profile` contains settings and runtime's instance.lock.
    `shared_root` is this device's synchronized folder, not the peer's.
    """

    def __init__(
        self,
        profile: str | Path,
        shared_root: str | Path,
    ) -> None:
        profile_path = Path(profile).expanduser()

        if _linked(profile_path):
            raise ValueError(
                "Profile directory cannot be a link"
            )

        self.profile = profile_path.resolve(strict=True)

        if not self.profile.is_dir():
            raise NotADirectoryError(self.profile)

        self.vault = RecoveryVault(
            shared_root,
            self.profile / "Recovery",
        )
        self.root = self.vault.root

        if (
            self.profile == self.root
            or self.profile in self.root.parents
            or self.root in self.profile.parents
        ):
            raise ValueError(
                "Profile and shared folder must be separate"
            )

    def _request(self, path: Path) -> DeletionRequest:
        if _linked(path) or not path.is_file():
            raise RecoveryCenterError(
                "Recovery journal is not a regular file"
            )

        if path.stat().st_size > 16_384:
            raise RecoveryCenterError(
                "Recovery journal is too large"
            )

        try:
            details = json.loads(
                path.read_text(encoding="utf-8")
            )
        except (ValueError, UnicodeError, OSError) as exc:
            raise RecoveryCenterError(
                "Recovery journal cannot be read"
            ) from exc

        if (
            not isinstance(details, dict)
            or set(details) != _KEYS
        ):
            raise RecoveryCenterError(
                "Recovery journal has invalid fields"
            )

        if (
            not _hex_string(details["request_id"], 32)
            or details["request_id"] != path.stem
            or not _hex_string(details["share_id"], 32)
            or not _hex_string(details["peer_node_id"], 32)
            or not _hex_string(
                details["baseline_sha256"], 64
            )
            or not _hex_string(
                details["file_sha256"], 64
            )
            or type(details["baseline_revision"]) is not int
            or not 1 <= details["baseline_revision"] < 2**63 - 1
            or type(details["file_size"]) is not int
            or not 0 <= details["file_size"] <= 2**63 - 1
        ):
            raise RecoveryCenterError(
                "Recovery journal has invalid values"
            )

        try:
            _validate_path(details["path"])
        except (ValueError, TypeError) as exc:
            raise RecoveryCenterError(
                "Recovery journal has an unsafe file path"
            ) from exc

        return DeletionRequest(
            details["request_id"],
            details["share_id"],
            details["peer_node_id"],
            details["path"],
            details["baseline_revision"],
            details["baseline_sha256"],
            details["file_sha256"],
            details["file_size"],
            "approved",
        )

    def _destination(
        self,
        relative: str,
    ) -> tuple[bool, bool]:
        """Return (already_present, unsafe_or_missing_parent)."""
        current = self.root
        parts = relative.split("/")

        for part in parts[:-1]:
            current = current / part

            if _linked(current) or not current.is_dir():
                return False, True

        destination = current / parts[-1]

        if _linked(destination):
            return False, True

        return destination.exists(), False

    def _inspect(self, path: Path) -> RecoveryItem:
        request_id = path.stem

        try:
            request = self._request(path)
            blob = self.vault.stored(request)

            if blob is None:
                return RecoveryItem(
                    request_id,
                    request.path,
                    request.file_size,
                    "SB-RCV-303",
                    "The recovery record exists, but its saved "
                    "file is missing. Do not delete the journal; "
                    "investigate the interrupted operation.",
                    False,
                )

            present, unsafe = self._destination(
                request.path
            )

            if unsafe:
                return RecoveryItem(
                    request_id,
                    request.path,
                    request.file_size,
                    "SB-RCV-306",
                    "The original folder is missing or contains "
                    "a link. Restore its folder structure safely, "
                    "then check again.",
                    False,
                )

            if present:
                return RecoveryItem(
                    request_id,
                    request.path,
                    request.file_size,
                    "SB-RCV-302",
                    "A file already exists at this location. "
                    "SyncBridge will not replace it; your "
                    "recovery copy is still protected.",
                    False,
                )

            return RecoveryItem(
                request_id,
                request.path,
                request.file_size,
                "SB-RCV-301",
                "A verified recovery copy is ready. "
                "Restoring it adds the file back to this device; "
                "a later sync may copy it to the other device.",
                True,
            )

        except (
            RecoveryCenterError,
            ApprovedDeletionError,
            OSError,
            ValueError,
        ) as exc:
            return RecoveryItem(
                request_id,
                "(unavailable)",
                None,
                "SB-RCV-304",
                f"The recovery record cannot be verified: {exc}. "
                "No file has been changed. Seek help before "
                "attempting recovery.",
                False,
            )

    def list_items(self) -> tuple[RecoveryItem, ...]:
        """List verified, incomplete, or damaged recovery records."""
        directory = self.vault.directory

        entries = [
            self._inspect(path)
            for path in sorted(directory.glob("*.json"))
        ]

        journals = {
            path.stem
            for path in directory.glob("*.json")
        }

        for path in sorted(directory.glob("*.recovery")):
            if path.stem not in journals:
                entries.append(
                    RecoveryItem(
                        path.stem,
                        "(unknown)",
                        None,
                        "SB-RCV-305",
                        "A saved file has no matching journal. "
                        "It will not be restored automatically. "
                        "Keep it for manual investigation.",
                        False,
                    )
                )

        return tuple(
            sorted(
                entries,
                key=lambda item: (
                    item.path,
                    item.request_id,
                ),
            )
        )

    def restore(self, request_id: str) -> Path:
        """Restore explicitly, without overwriting an existing file.

        Do not call with a running SyncBridgeRuntime for this profile.
        """
        if not _hex_string(request_id, 32):
            raise ValueError(
                "Recovery ID must be 32 lowercase "
                "hexadecimal characters"
            )

        lock = _ProfileLock(
            self.profile / "instance.lock"
        )

        try:
            lock.acquire()

        except InstanceAlreadyRunning as exc:
            raise RecoveryCenterError(
                "SyncBridge is using this profile. "
                "Close the application before restoring a file. "
                "[SB-RCV-409]"
            ) from exc

        try:
            journal = (
                self.vault.directory
                / f"{request_id}.json"
            )

            if (
                not journal.exists()
                and not journal.is_symlink()
            ):
                raise RecoveryCenterError(
                    "No recovery record has that ID"
                )

            item = self._inspect(journal)

            if not item.can_restore:
                raise RecoveryCenterError(
                    f"[{item.code}] {item.message}"
                )

            request = self._request(journal)

            try:
                return self.vault.restore(request)

            except (
                ApprovedDeletionError,
                OSError,
            ) as exc:
                raise RecoveryCenterError(
                    "Restore stopped to protect existing files. "
                    "Nothing was overwritten. "
                    f"Details: {exc}"
                ) from exc

        finally:
            lock.release()
