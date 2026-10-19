
"""Opt-in authenticated, lease-fenced PUSH transfers.

A fenced listener accepts only ``fenced_offer`` messages. No legacy ``offer``
or ``get`` can reach its publication path. The normal SyncBridge runtime does
not enable this service yet; migrating pulls and ordinary writes requires a
separate, coordinated protocol upgrade.

Every final publish goes through FencedFilePublisher with a receiver-owned
SQLite transaction lock. Unrelated filesystem writers are not covered by the
lock, and SQLite + the filesystem are not a crash-atomic transaction.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import stat
import struct
import threading
from pathlib import Path

from syncbridge.network.fenced_publish import (
    FencedFilePublisher,
    PublishConflict,
)
from syncbridge.network.lease_fencing import (
    LeaseAuthority,
    LeaseError,
    LeaseGrant,
)
from syncbridge.network.secure_channel import accept_secure_channel
from syncbridge.network.security import SecurityError
from syncbridge.network.transfer import (
    TransferError,
    TransferResult,
    TransferService,
    _CHUNK_SIZE,
    _MAX_SIZE,
    _HASH,
    _child,
    _close,
    _exact,
    _expect,
    _hash_file,
    _linked,
    _path,
    _read,
    _regular,
    _same_stat,
    _send,
    _sha,
)


_FENCED_FIELDS = {
    "path",
    "size",
    "sha256",
    "share_id",
    "expected_destination_sha256",
    "lease_generation",
    "lease_token",
}


class FencedTransferClient(TransferService):
    """Sender of fenced offers; does not require a local lease database."""

    def send_file(self, *args, **kwargs):
        raise TransferError(
            "Fenced service requires send_fenced_file and a lease"
        )

    def fetch_file(self, *args, **kwargs):
        raise TransferError(
            "Fenced pull protocol is not implemented"
        )

    def send_fenced_file(
        self,
        host: str,
        port: int,
        expected_node_id: str,
        source_root: str | Path,
        relative_path: str,
        *,
        lease: LeaseGrant,
        expected_destination_sha256: str | None = None,
        cancel_event: threading.Event | None = None,
        on_progress=None,
    ) -> TransferResult:
        """Send a file with a receiver-issued lease over an authenticated channel."""
        LeaseAuthority._valid_grant(lease)

        if (
            lease.owner_node_id != self.identity.node_id
            or lease.share_id != self.share_id
        ):
            raise TransferError(
                "Lease does not belong to the sending peer/share"
            )

        _sha(expected_destination_sha256)
        _path(relative_path)

        if (
            cancel_event is not None
            and not isinstance(cancel_event, threading.Event)
        ):
            raise TypeError(
                "cancel_event must be threading.Event"
            )

        if on_progress is not None and not callable(on_progress):
            raise TypeError("on_progress must be callable")

        root = Path(source_root).expanduser().absolute()

        if _linked(root) or not root.is_dir():
            raise TransferError("Invalid source directory")

        sock, secure, peer = self._connect(
            host, port, expected_node_id
        )

        try:
            source = _child(root, _path(relative_path))
            flags = (
                os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )

            with os.fdopen(os.open(source, flags), "rb") as stream:
                before = os.fstat(stream.fileno())

                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_size > _MAX_SIZE
                ):
                    raise TransferError("Invalid source file")

                digest = _hash_file(stream)

                if not _same_stat(
                    before,
                    os.fstat(stream.fileno()),
                ):
                    raise TransferError(
                        "Source changed while hashing"
                    )

                stream.seek(0)

                _send(
                    secure,
                    "fenced_offer",
                    share_id=self.share_id,
                    path=relative_path,
                    size=before.st_size,
                    sha256=digest,
                    expected_destination_sha256=expected_destination_sha256,
                    lease_generation=lease.generation,
                    lease_token=lease.session_token,
                )

                return self._transmit(
                    secure,
                    peer.node_id,
                    stream,
                    before,
                    digest,
                    relative_path,
                    cancel_event=cancel_event,
                    on_progress=on_progress,
                    outbound=True,
                )

        except (OSError, SecurityError) as exc:
            raise TransferError(
                "Secure fenced transfer failed"
            ) from exc

        finally:
            _close(sock)


class FencedTransferService(FencedTransferClient):
    """Isolated receiver with no unfenced incoming write path.

    Not automatically started by SyncBridgeRuntime. It supports PUSH only.
    The authenticated node_id, not an offer field, identifies the lease owner.
    """

    def __init__(
        self,
        *args,
        authority: LeaseAuthority,
        **kwargs,
    ) -> None:
        if not isinstance(authority, LeaseAuthority):
            raise TypeError(
                "authority must be a LeaseAuthority"
            )

        super().__init__(*args, **kwargs)

        if self.share_id is None:
            raise ValueError(
                "Fenced transfer service requires a share_id"
            )

        self.authority = authority

        self.publisher = FencedFilePublisher(
            authority,
            self.share_id,
            self.destination_root,
            self._staging,
        )

    def _serve(self, sock: socket.socket) -> None:
        secure = None

        try:
            secure, peer = accept_secure_channel(
                sock,
                self.identity,
                self.trust_store,
                timeout=self.handshake_timeout,
            )

            secure.settimeout(self.io_timeout)

            request = _read(
                secure,
                {"fenced_offer", "offer", "get"},
            )

            if request["type"] != "fenced_offer":
                raise TransferError(
                    "This receiver requires fenced transfers; "
                    "legacy requests denied"
                )

            _expect(
                request,
                "fenced_offer",
                _FENCED_FIELDS,
            )

            self._verify_share(request["share_id"])

            self._check_permission(
                peer.node_id,
                secure.remote_public_key,
            )

            lease = LeaseGrant(
                share_id=self.share_id,
                owner_node_id=peer.node_id,
                session_token=request["lease_token"],
                generation=request["lease_generation"],
                expires_at=0.0,
            )

            # Only the receiver's durable database determines expiry.
            self.authority.assert_current(lease)

            self._receive_fenced(
                secure,
                peer.node_id,
                request,
                lease,
            )

        except (
            OSError,
            ValueError,
            TransferError,
            SecurityError,
            LeaseError,
            PublishConflict,
        ) as exc:
            if secure is not None and not self._stop.is_set():
                try:
                    _send(
                        secure,
                        "error",
                        reason="Fenced transfer refused",
                    )
                except (OSError, TransferError):
                    pass

            if not self._stop.is_set():
                self._report(exc)

        finally:
            _close(sock)

            with self._lock:
                self._connections.discard(sock)

    def _receive_fenced(
        self,
        secure,
        sender_id: str,
        offer: dict,
        lease: LeaseGrant,
    ) -> TransferResult:
        segments = _path(offer["path"])
        relative = offer["path"]
        size = offer["size"]
        digest = offer["sha256"]
        expected = _sha(
            offer["expected_destination_sha256"]
        )

        if (
            type(size) is not int
            or not 0 <= size <= _MAX_SIZE
        ):
            raise TransferError("Invalid file size")

        if (
            not isinstance(digest, str)
            or _HASH.fullmatch(digest) is None
        ):
            raise TransferError("Invalid file digest")

        with self._lock:
            if relative in self._active_paths:
                raise TransferError(
                    "Transfer for path already active"
                )

            self._active_paths.add(relative)

        try:
            self._check_permission(
                sender_id,
                secure.remote_public_key,
            )

            self.authority.assert_current(lease)

            target = _child(
                self.destination_root,
                segments,
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

            # A superseded holder cannot reuse its successor's
            # partial transfer or resume metadata.
            slot = hashlib.sha256(
                (
                    f"{sender_id}\0{self.share_id}\0"
                    f"{relative}\0{size}\0{digest}\0"
                    f"{expected}\0{lease.generation}\0"
                    f"{lease.session_token}"
                ).encode("utf-8")
            ).hexdigest()

            part_name = slot + ".part"
            partial = self._staging / part_name
            metadata = self._staging / (slot + ".json")

            _regular(partial)
            _regular(metadata)

            manifest = {
                "sender": sender_id,
                "share_id": self.share_id,
                "path": relative,
                "size": size,
                "sha256": digest,
                "expected": expected,
                "generation": lease.generation,
            }

            if partial.exists() and metadata.exists():
                try:
                    old = json.loads(
                        metadata.read_text("utf-8")
                    )
                except (ValueError, UnicodeError) as exc:
                    raise TransferError(
                        "Corrupt resume metadata"
                    ) from exc

                if old != manifest:
                    raise TransferError(
                        "Resume metadata mismatch"
                    )

                offset = partial.stat().st_size

                if offset > size:
                    raise TransferError(
                        "Partial exceeds offered size"
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

            with partial.open(
                "ab",
                buffering=0,
            ) as output:
                while received < size:
                    self._check_permission(
                        sender_id,
                        secure.remote_public_key,
                    )
                    self.authority.assert_current(lease)

                    length = struct.unpack(
                        "!I",
                        _exact(secure, 4),
                    )[0]

                    if length == 0:
                        paused = _read(
                            secure,
                            {"pause"},
                        )
                        _expect(
                            paused,
                            "pause",
                            set(),
                        )

                        os.fsync(output.fileno())

                        _send(
                            secure,
                            "paused",
                            offset=received,
                        )

                        return TransferResult(
                            relative,
                            digest,
                            size,
                            received,
                            False,
                        )

                    if (
                        length > _CHUNK_SIZE
                        or length > size - received
                    ):
                        raise TransferError(
                            "Invalid file chunk length"
                        )

                    output.write(
                        _exact(secure, length)
                    )

                    received += length

                    self._progress(
                        "receive",
                        sender_id,
                        relative,
                        received,
                        size,
                    )

                os.fsync(output.fileno())

            if struct.unpack(
                "!I",
                _exact(secure, 4),
            )[0] != 0:
                raise TransferError(
                    "Missing end-of-file marker"
                )

            _expect(
                _read(secure, {"finish"}),
                "finish",
                set(),
            )

            self._check_permission(
                sender_id,
                secure.remote_public_key,
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
                    "File hash mismatch; corrupt partial discarded"
                )

            self._check_permission(
                sender_id,
                secure.remote_public_key,
            )

            # This is the actual receiver-enforced commit boundary.
            result = self.publisher.publish(
                lease,
                authenticated_peer_id=sender_id,
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
