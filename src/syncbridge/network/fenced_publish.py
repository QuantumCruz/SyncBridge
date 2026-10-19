
"""Receiver-local fenced publication of fully verified staged files.

This is an enforcement building block, not a network endpoint. The authenticated
transfer receiver must supply the actual peer node ID and the lease returned by
the receiver's own authority; never trust an owner ID asserted in an offer.

A SQLite BEGIN IMMEDIATE transaction is held across the final lease check,
destination precondition, and filesystem publish. Therefore other clients of
the SAME authority database cannot revoke/supersede the lease mid-publication.
This does not make SQLite + filesystem one crash-atomic transaction, prevent
unrelated programs from editing files, or enforce leases in the existing
TransferService until that service is explicitly integrated.
"""
from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from syncbridge.network.lease_fencing import FencedOut, LeaseAuthority, LeaseGrant
from syncbridge.network.transfer import (
    _child,
    _hash_file,
    _linked,
    _path,
    _same_stat,
)

_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_STAGE = re.compile(r"[0-9a-f]{64}\.part\Z")


class PublishConflict(RuntimeError):
    """The target or staged bytes do not match the approved preconditions."""


@dataclass(frozen=True, slots=True)
class FencedPublishResult:
    path: str
    sha256: str
    size: int
    already_present: bool


def _id(value: str) -> str:
    if not isinstance(value, str) or _HEX32.fullmatch(value) is None:
        raise ValueError("Expected 32 lowercase hexadecimal characters")
    return value


def _digest(value: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise ValueError("Expected 64 lowercase hexadecimal characters")
    return value


def _regular_fingerprint(path: Path) -> tuple[int, str, os.stat_result]:
    if _linked(path):
        raise PublishConflict("Linked files are not eligible for publication")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )

    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise PublishConflict("Cannot read the file for verification") from exc

    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())

        if not stat.S_ISREG(before.st_mode):
            raise PublishConflict("Publication requires a regular file")

        actual = _hash_file(stream)
        after = os.fstat(stream.fileno())

        if not _same_stat(before, after):
            raise PublishConflict("File changed during verification")

    try:
        named = path.stat()
    except OSError as exc:
        raise PublishConflict("File disappeared during verification") from exc

    if not _same_stat(before, named) or _linked(path):
        raise PublishConflict("File changed during verification")

    return before.st_size, actual, before


class FencedFilePublisher:
    """Publish receiver-controlled staging bytes under a receiver-owned fence.

    A staging filename must be a direct '<64 hex>.part' child of staging_root,
    matching TransferService's existing resume slot naming convention.
    The staging directory must be on the same filesystem as the destination.
    """

    def __init__(
        self,
        authority: LeaseAuthority,
        share_id: str,
        destination_root: str | Path,
        staging_root: str | Path,
    ) -> None:
        if not isinstance(authority, LeaseAuthority):
            raise TypeError("authority must be LeaseAuthority")

        self.share_id = _id(share_id)
        self.authority = authority
        self.destination_root = Path(destination_root).absolute()
        self.staging_root = Path(staging_root).absolute()

        for root in (self.destination_root, self.staging_root):
            if _linked(root) or not root.is_dir():
                raise ValueError(
                    "Publisher roots must be real existing directories"
                )

        if self.destination_root == self.staging_root:
            raise ValueError("Staging and destination must differ")

        if (
            self.destination_root in self.staging_root.parents
            or self.staging_root in self.destination_root.parents
        ):
            raise ValueError(
                "Staging and destination roots must not overlap"
            )

    @staticmethod
    def _publish_file(stage: Path, target: Path, exists: bool) -> None:
        if exists:
            os.replace(stage, target)
        else:
            # Creates only if still absent, even against an unrelated writer.
            os.link(stage, target)
            stage.unlink()

    def publish(
        self,
        lease: LeaseGrant,
        *,
        authenticated_peer_id: str,
        relative_path: str,
        staging_name: str,
        expected_size: int,
        expected_sha256: str,
        expected_destination_sha256: str | None,
    ) -> FencedPublishResult:
        """Verify and publish under an exclusive receiver-local lease lock.

        Caller must already have authenticated the network peer, received and
        fsynced the full staging file, and verified the approved share binding.
        Existing transfer behavior remains unchanged until explicitly wired.
        """
        self.authority._valid_grant(lease)
        peer = _id(authenticated_peer_id)

        if (
            lease.share_id != self.share_id
            or peer != lease.owner_node_id
        ):
            raise FencedOut(
                "Lease is not assigned to this peer and share"
            )

        parts = _path(relative_path)

        if (
            not isinstance(staging_name, str)
            or _STAGE.fullmatch(staging_name) is None
        ):
            raise ValueError("Invalid receiver staging filename")

        if (
            type(expected_size) is not int
            or not 0 <= expected_size <= (1 << 63) - 1
        ):
            raise ValueError("Invalid expected file size")

        digest = _digest(expected_sha256)

        if expected_destination_sha256 is not None:
            _digest(expected_destination_sha256)

        stage = self.staging_root / staging_name
        size, stage_digest, stage_stat = _regular_fingerprint(stage)

        if size != expected_size or stage_digest != digest:
            raise PublishConflict(
                "Staged file does not match approved content"
            )

        # Every lease holder, including one in another process, must use
        # this same database. BEGIN IMMEDIATE excludes simultaneous lease
        # acquisition/release while this publication is in progress.
        with self.authority._write() as connection:
            now = self.authority._now()
            row = self.authority._row(connection, self.share_id)

            self.authority._check_clock(row, now)
            self.authority._current(row, lease, now)

            target = _child(self.destination_root, parts)
            exists = target.exists()

            if exists:
                current_size, current_digest, _ = (
                    _regular_fingerprint(target)
                )

                if (
                    current_size == size
                    and current_digest == digest
                ):
                    # Idempotent completion, but only for the current holder.
                    if (
                        not _same_stat(stage.stat(), stage_stat)
                        or _linked(stage)
                    ):
                        raise PublishConflict(
                            "Staged file changed before publication"
                        )

                    stage.unlink()
                    return FencedPublishResult(
                        relative_path, digest, size, True
                    )

                if (
                    expected_destination_sha256 is None
                    or current_digest != expected_destination_sha256
                ):
                    raise PublishConflict(
                        "Destination changed; refusing overwrite"
                    )

            elif expected_destination_sha256 is not None:
                raise PublishConflict(
                    "Expected destination file disappeared"
                )

            target = _child(
                self.destination_root,
                parts,
                create=True,
            )

            if (
                not _same_stat(stage.stat(), stage_stat)
                or _linked(stage)
            ):
                raise PublishConflict(
                    "Staged file changed before publication"
                )

            # Recheck expiration immediately before publishing, still
            # holding the transaction lock.
            self.authority._current(
                row,
                lease,
                self.authority._now(),
            )

            self._publish_file(stage, target, exists)

        return FencedPublishResult(
            relative_path, digest, size, False
        )
