
"""Opt-in, lease-fenced downloads from a trusted SyncBridge share.

The remote side supplies bytes using its existing authenticated GET operation.
The local destination uses FencedFilePublisher. The lease must be issued by the
LOCAL receiver's authority and owned by the local identity.

This class cannot start a legacy write listener, send unfenced uploads, or use
the inherited unfenced download method.

It is not wired into SyncBridgeRuntime yet. Until legacy write listeners are
retired, the entire application is not globally fenced.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import threading
from pathlib import Path
from typing import Callable

from syncbridge.network.fenced_publish import FencedFilePublisher
from syncbridge.network.lease_fencing import LeaseAuthority, LeaseGrant
from syncbridge.network.security import SecurityError
from syncbridge.network.transfer import (
    TransferError,
    TransferProgress,
    TransferResult,
    TransferService,
    _CHUNK_SIZE,
    _HASH,
    _MAX_SIZE,
    _child,
    _close,
    _exact,
    _expect,
    _hash_file,
    _path,
    _read,
    _regular,
    _reply,
    _send,
    _sha,
)


class FencedDownloadClient(TransferService):
    """A client-only receiver; every completed local download is fenced."""

    def __init__(
        self,
        *args,
        authority: LeaseAuthority,
        **kwargs,
    ) -> None:
        if not isinstance(authority, LeaseAuthority):
            raise TypeError("authority must be a LeaseAuthority")

        super().__init__(*args, **kwargs)

        if self.share_id is None:
            raise ValueError(
                "Fenced downloads require a share-bound client"
            )

        self.authority = authority
        self.publisher = FencedFilePublisher(
            authority,
            self.share_id,
            self.destination_root,
            self._staging,
        )

    def start(self) -> None:
        raise TransferError(
            "Fenced download client cannot accept incoming transfers"
        )

    def send_file(self, *args, **kwargs):
        raise TransferError(
            "Use a separately authorized fenced upload sender"
        )

    def fetch_file(self, *args, **kwargs):
        raise TransferError(
            "Use fetch_fenced_file with a receiver-local lease"
        )

    def fetch_fenced_file(
        self,
        host: str,
        port: int,
        expected_node_id: str,
        share_id: str,
        relative_path: str,
        *,
        lease: LeaseGrant,
        expected_source_sha256: str,
        expected_destination_sha256: str | None = None,
        cancel_event: threading.Event | None = None,
        on_progress: Callable[[TransferProgress], None] | None = None,
    ) -> TransferResult:
        """Read remote bytes, then publish under a receiver-owned fence.

        The remote peer's read service need not implement fencing because
        that service does not write the local destination. It must still
        authenticate the requester and authorize the share read.

        A planned source digest is mandatory.
        """
        LeaseAuthority._valid_grant(lease)

        if (
            lease.share_id != self.share_id
            or share_id != self.share_id
            or lease.owner_node_id != self.identity.node_id
        ):
            raise TransferError(
                "Lease belongs to a different receiver or share"
            )

        if (
            not isinstance(expected_source_sha256, str)
            or _HASH.fullmatch(expected_source_sha256) is None
        ):
            raise TransferError(
                "Fenced downloads require the planned source SHA-256"
            )

        _sha(expected_destination_sha256)
        _path(relative_path)

        if (
            cancel_event is not None
            and not isinstance(cancel_event, threading.Event)
        ):
            raise TypeError(
                "cancel_event must be threading.Event or None"
            )

        if on_progress is not None and not callable(on_progress):
            raise TypeError(
                "on_progress must be callable or None"
            )

        # Fail before connecting if our own receiver has lost authority.
        self.authority.assert_current(lease)

        try:
            sock, secure, peer = self._connect(
                host,
                port,
                expected_node_id,
            )
        except SecurityError as exc:
            raise TransferError(
                "Secure fenced download failed"
            ) from exc

        try:
            _send(
                secure,
                "get",
                share_id=share_id,
                path=relative_path,
                expected_source_sha256=expected_source_sha256,
                expected_destination_sha256=expected_destination_sha256,
            )

            offer = _reply(
                _read(secure, {"offer", "error"}),
                "offer",
            )

            _expect(
                offer,
                "offer",
                {
                    "share_id",
                    "path",
                    "size",
                    "sha256",
                    "expected_destination_sha256",
                },
            )

            if (
                offer["share_id"] != self.share_id
                or offer["path"] != relative_path
                or offer["sha256"] != expected_source_sha256
                or offer["expected_destination_sha256"]
                != expected_destination_sha256
            ):
                raise TransferError(
                    "Remote offer differs from approved download"
                )

            return self._receive_fenced(
                secure,
                peer.node_id,
                relative_path,
                offer,
                lease,
                cancel_event=cancel_event,
                on_progress=on_progress,
            )

        except (OSError, SecurityError) as exc:
            raise TransferError(
                "Secure fenced download interrupted"
            ) from exc

        finally:
            _close(sock)

    def _receive_fenced(
        self,
        secure,
        peer_id: str,
        relative: str,
        offer: dict,
        lease: LeaseGrant,
        *,
        cancel_event: threading.Event | None,
        on_progress: Callable[[TransferProgress], None] | None,
    ) -> TransferResult:
        size = offer["size"]
        digest = offer["sha256"]
        expected = _sha(
            offer["expected_destination_sha256"]
        )

        if (
            type(size) is not int
            or not 0 <= size <= _MAX_SIZE
        ):
            raise TransferError(
                "Invalid fenced download size"
            )

        if (
            not isinstance(digest, str)
            or _HASH.fullmatch(digest) is None
        ):
            raise TransferError(
                "Invalid fenced download digest"
            )

        with self._lock:
            if relative in self._active_paths:
                raise TransferError(
                    "Another download for this path is active"
                )

            self._active_paths.add(relative)

        try:
            self.authority.assert_current(lease)

            target = _child(
                self.destination_root,
                _path(relative),
            )

            if self._precondition(
                target,
                size,
                digest,
                expected,
                strict=True,
            ):
                self.authority.assert_current(lease)

                _send(
                    secure,
                    "already_complete",
                    size=size,
                    sha256=digest,
                )

                return TransferResult(
                    relative,
                    digest,
                    size,
                    size,
                    True,
                )

            # Separate resume states for different lease generations.
            slot = hashlib.sha256(
                (
                    f"fenced-download\0{peer_id}\0{self.share_id}\0"
                    f"{relative}\0{size}\0{digest}\0{expected}\0"
                    f"{lease.generation}\0{lease.session_token}"
                ).encode("utf-8")
            ).hexdigest()

            part_name = slot + ".part"
            partial = self._staging / part_name
            metadata = self._staging / (slot + ".json")

            _regular(partial)
            _regular(metadata)

            manifest = {
                "remote": peer_id,
                "share_id": self.share_id,
                "path": relative,
                "size": size,
                "sha256": digest,
                "expected": expected,
                "generation": lease.generation,
            }

            if partial.exists() and metadata.exists():
                try:
                    previous = json.loads(
                        metadata.read_text(encoding="utf-8")
                    )
                except (ValueError, UnicodeError) as exc:
                    raise TransferError(
                        "Invalid download resume metadata"
                    ) from exc

                if previous != manifest:
                    raise TransferError(
                        "Resume metadata does not match the offered file"
                    )

                offset = partial.stat().st_size

                if offset > size:
                    raise TransferError(
                        "Resume data exceeds expected file size"
                    )

            else:
                partial.unlink(missing_ok=True)
                metadata.unlink(missing_ok=True)

                with metadata.open(
                    "x",
                    encoding="utf-8",
                ) as output:
                    json.dump(
                        manifest,
                        output,
                        sort_keys=True,
                    )
                    output.flush()
                    os.fsync(output.fileno())

                with partial.open("xb"):
                    pass

                offset = 0

            _send(secure, "ready", offset=offset)

            received = offset

            self._progress(
                "receive",
                peer_id,
                relative,
                received,
                size,
                on_progress,
            )

            with partial.open("ab", buffering=0) as output:
                while received < size:
                    # Cancellation preserves an uncommitted partial.
                    # Resume requires the same lease and manifest.
                    if (
                        cancel_event is not None
                        and cancel_event.is_set()
                    ):
                        os.fsync(output.fileno())

                        return TransferResult(
                            relative,
                            digest,
                            size,
                            received,
                            False,
                        )

                    self.authority.assert_current(lease)

                    length = struct.unpack(
                        "!I",
                        _exact(secure, 4),
                    )[0]

                    if (
                        length == 0
                        or length > _CHUNK_SIZE
                        or length > size - received
                    ):
                        raise TransferError(
                            "Invalid encrypted file-chunk length"
                        )

                    output.write(
                        _exact(secure, length)
                    )

                    received += length

                    self._progress(
                        "receive",
                        peer_id,
                        relative,
                        received,
                        size,
                        on_progress,
                    )

                os.fsync(output.fileno())

            if struct.unpack(
                "!I",
                _exact(secure, 4),
            )[0] != 0:
                raise TransferError(
                    "Missing encrypted end-of-file marker"
                )

            _expect(
                _read(secure, {"finish"}),
                "finish",
                set(),
            )

            self.authority.assert_current(lease)

            with partial.open("rb") as stream:
                actual = _hash_file(stream)

            if (
                actual != digest
                or partial.stat().st_size != size
            ):
                partial.unlink(missing_ok=True)
                metadata.unlink(missing_ok=True)

                raise TransferError(
                    "Corrupt download rejected before publication"
                )

            # The lease owner is this local receiver's authenticated
            # device identity. The remote source was authenticated
            # separately when the encrypted channel was opened.
            result = self.publisher.publish(
                lease,
                authenticated_peer_id=self.identity.node_id,
                relative_path=relative,
                staging_name=part_name,
                expected_size=size,
                expected_sha256=digest,
                expected_destination_sha256=expected,
            )

            metadata.unlink(missing_ok=True)

            _send(
                secure,
                "complete",
                size=size,
                sha256=digest,
            )

            return TransferResult(
                relative,
                result.sha256,
                result.size,
                size,
                True,
            )

        finally:
            with self._lock:
                self._active_paths.discard(relative)
