
"""Operation-bound, single-port fenced receiver with safe partial recovery.

The elected operation is revalidated before transfer acceptance and inside
the receiver's final publication transaction.

A new fencing generation may adopt staged bytes from an older generation
ONLY when the authenticated sender, approved share, relative path, full-file
digest, file size, and destination precondition match exactly.

Adoption copies bytes into an independent staging file. The new session never
reuses the previous session's fencing token or publication authority.

A recovered prefix is NOT automatically trusted as correct source content:
the existing fenced receiver verifies the complete SHA-256 before publishing.
If the prefix is corrupt, publication fails closed.

This implementation intentionally leaves the normal fenced transfer protocol
and its final filesystem-publication checks unchanged.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
from pathlib import Path

from syncbridge.network.fenced_duplex import FencedDuplexService
from syncbridge.network.fenced_publish import (
    FencedFilePublisher,
    PublishConflict,
)
from syncbridge.network.operation_bound_lease import (
    OperationBoundFencedLeaseService,
)
from syncbridge.network.transfer import (
    TransferError,
    _MAX_SIZE,
    _HASH,
    _linked,
    _path,
    _regular,
    _same_stat,
    _sha,
)


_STAGE_ID = re.compile(r"[0-9a-f]{64}\Z")
_COPY_CHUNK = 1024 * 1024
_MAX_CANDIDATES = 128


def _strict_json(raw: str):
    """Reject duplicate metadata keys and nonstandard JSON numbers."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate recovery metadata field")
            result[key] = value
        return result

    def constant(value):
        raise ValueError("Invalid recovery metadata number")

    return json.loads(
        raw,
        object_pairs_hook=unique,
        parse_constant=constant,
    )


class OperationBoundDuplexService(FencedDuplexService):
    """Enforce operation authorization and recover verified transfer state."""

    def __init__(
        self,
        *args,
        operation_leases: OperationBoundFencedLeaseService,
        **kwargs,
    ) -> None:
        if not isinstance(
            operation_leases,
            OperationBoundFencedLeaseService,
        ):
            raise TypeError(
                "operation_leases must be an operation-bound lease service"
            )

        super().__init__(*args, **kwargs)

        if (
            operation_leases.authority is not self.authority
            or operation_leases.identity.node_id
            != self.identity.node_id
            or operation_leases.admission.share_id
            != self.share_id
        ):
            raise ValueError(
                "Operation binding does not match this receiver and share"
            )

        self.operation_leases = operation_leases
        self._resume_lock = threading.Lock()

        self.publisher = FencedFilePublisher(
            self.authority,
            self.share_id,
            self.destination_root,
            self._staging,
            before_publish=self._require_elected_operation,
        )

    def _require_elected_operation(self, lease) -> None:
        try:
            self.operation_leases.require_operation_bound(
                lease
            )
        except Exception as exc:
            raise PublishConflict(
                "The elected synchronization operation is no longer authorized"
            ) from exc

    def _slot(self, sender_id: str, offer: dict, lease) -> str:
        """Use exactly the slot formula of FencedTransferService."""
        relative = offer["path"]
        size = offer["size"]
        digest = offer["sha256"]
        expected = _sha(offer["expected_destination_sha256"])

        return hashlib.sha256(
            (
                f"{sender_id}\0{self.share_id}\0"
                f"{relative}\0{size}\0{digest}\0"
                f"{expected}\0{lease.generation}\0"
                f"{lease.session_token}"
            ).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _metadata_matches(
        data,
        required: dict,
        current_generation: int,
    ) -> bool:
        if not isinstance(data, dict):
            return False

        if set(data) != set(required):
            return False

        if (
            type(data["generation"]) is not int
            or type(data["size"]) is not int
            or not 1 <= data["generation"] < current_generation
        ):
            return False

        return all(
            data[key] == value
            for key, value in required.items()
            if key != "generation"
        )

    def _older_partial(
        self,
        required: dict,
        generation: int,
    ) -> tuple[Path, Path] | None:
        """Select one unambiguous, matching older fenced staging pair."""
        matches = []
        examined = 0

        for info in self._staging.glob("*.json"):
            examined += 1

            if examined > _MAX_CANDIDATES:
                # Do not scan unbounded amounts of stale state.
                return None

            if _STAGE_ID.fullmatch(info.stem) is None:
                continue

            partial = self._staging / (info.stem + ".part")

            if _linked(info) or _linked(partial):
                continue

            try:
                _regular(info)
                _regular(partial)

                if not partial.is_file():
                    continue

                if info.stat().st_size > 4096:
                    continue

                data = _strict_json(
                    info.read_text(encoding="utf-8")
                )

                if not self._metadata_matches(
                    data,
                    required,
                    generation,
                ):
                    continue

                file_stat = partial.stat()

                if (
                    not stat.S_ISREG(file_stat.st_mode)
                    or file_stat.st_nlink != 1
                    or not 0 < file_stat.st_size <= required["size"]
                ):
                    continue

                matches.append((partial, info))

                # With multiple matching candidates, no reliable
                # origin is established. Restart rather than guess.
                if len(matches) > 1:
                    return None

            except (OSError, ValueError, TypeError, TransferError):
                continue

        return matches[0] if len(matches) == 1 else None

    @staticmethod
    def _copy_stable_partial(source: Path, destination: Path) -> None:
        """Create an independent durable copy, rejecting unstable source data."""
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )

        fd = os.open(source, flags)

        with os.fdopen(fd, "rb") as input_file:
            before = os.fstat(input_file.fileno())

            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
            ):
                raise TransferError(
                    "Recovery source is not a private regular file"
                )

            copied = 0

            with destination.open("xb") as output:
                while True:
                    data = input_file.read(_COPY_CHUNK)

                    if not data:
                        break

                    output.write(data)
                    copied += len(data)

                output.flush()
                os.fsync(output.fileno())

            after = os.fstat(input_file.fileno())

            if (
                copied != before.st_size
                or not _same_stat(before, after)
                or _linked(source)
                or not _same_stat(before, source.stat())
            ):
                raise TransferError(
                    "Partial transfer changed during recovery"
                )

    def _adopt_partial(
        self,
        sender_id: str,
        offer: dict,
        lease,
    ) -> None:
        """Rebase old bytes into the currently authorized fencing generation.

        This does not authorize publication and does not accept file bytes
        over the network. The original receiver still owns all final checks.
        """
        _path(offer["path"])

        if (
            type(offer["size"]) is not int
            or not 0 <= offer["size"] <= _MAX_SIZE
            or not isinstance(offer["sha256"], str)
            or _HASH.fullmatch(offer["sha256"]) is None
        ):
            raise TransferError(
                "Invalid fenced transfer offer"
            )

        expected = _sha(
            offer["expected_destination_sha256"]
        )

        self.authority.assert_current(lease)
        self._require_elected_operation(lease)

        slot = self._slot(sender_id, offer, lease)
        current_part = self._staging / (slot + ".part")
        current_info = self._staging / (slot + ".json")

        _regular(current_part)
        _regular(current_info)

        # Already-staged current-generation bytes are handled by
        # the original fenced receiver, including its strict metadata
        # checks. Never overwrite such a staging pair.
        if current_part.exists() and current_info.exists():
            return

        required = {
            "sender": sender_id,
            "share_id": self.share_id,
            "path": offer["path"],
            "size": offer["size"],
            "sha256": offer["sha256"],
            "expected": expected,
            "generation": lease.generation,
        }

        candidate = self._older_partial(
            required,
            lease.generation,
        )

        if candidate is None:
            return

        old_part, old_info = candidate

        # These can be left after interruption during an earlier
        # attempted adoption. Without both files they are not a
        # valid current-generation resume pair.
        current_part.unlink(missing_ok=True)
        current_info.unlink(missing_ok=True)

        created_part = False
        created_info = False

        try:
            self._copy_stable_partial(
                old_part,
                current_part,
            )
            created_part = True

            self.authority.assert_current(lease)
            self._require_elected_operation(lease)

            with current_info.open(
                "x",
                encoding="utf-8",
            ) as output:
                created_info = True
                json.dump(
                    required,
                    output,
                    sort_keys=True,
                )
                output.flush()
                os.fsync(output.fileno())

        except BaseException:
            # The original staged bytes remain available if
            # adoption did not finish.
            if created_info:
                current_info.unlink(missing_ok=True)

            # Even if copying failed before the method returned,
            # the partial destination may have been created.
            current_part.unlink(missing_ok=True)
            raise

        # The new pair is durable and independently owned.
        # Retire the older pair so successful completion leaves
        # no obsolete .part files behind.
        old_part.unlink(missing_ok=True)
        old_info.unlink(missing_ok=True)

    def _receive_fenced(
        self,
        secure,
        sender_id: str,
        offer: dict,
        lease,
    ):
        self._require_elected_operation(lease)

        # Prevent simultaneous adoption attempts from racing
        # to create or replace staging files. Normal encrypted
        # transfer processing retains the parent receiver's
        # existing per-path active-transfer protection.
        with self._resume_lock:
            with self._lock:
                if offer["path"] in self._active_paths:
                    raise TransferError(
                        "Transfer for path already active"
                    )

            self._adopt_partial(
                sender_id,
                offer,
                lease,
            )

        # The parent verifies the selected staging metadata,
        # streams the remaining bytes, validates full SHA-256,
        # and publishes only under the NEW current fencing
        # generation and elected-operation check.
        return super()._receive_fenced(
            secure,
            sender_id,
            offer,
            lease,
        )
