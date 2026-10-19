
"""One guarded lifecycle for authenticated, lease-fenced file transfers.

This composes existing SyncBridge components. It is NOT an alternative transfer
protocol and is not yet selected by the desktop runtime.

Uploads: the destination computer issues the lease and enforces publication.
Downloads: this computer issues its own local lease and enforces publication.

The authenticated remote read listener must have NO legacy write permission.
A completed operation is reported only after the transfer method and its lease
renewal guard have both succeeded.

A pause or process restart ends this session. Since current fenced partials
are bound to lease identity, a new generation currently starts a new partial;
cross-generation resume is a separate migration/recovery requirement.
"""
from __future__ import annotations

import ipaddress
import math
from contextlib import ExitStack
from pathlib import Path
from threading import Event

from syncbridge.network.fenced_download import FencedDownloadClient
from syncbridge.network.fenced_lease_channel import FencedLeaseClient
from syncbridge.network.fenced_transfer import FencedTransferClient
from syncbridge.network.lease_fencing import LeaseAuthority, LeaseGrant
from syncbridge.network.lease_keepalive import LeaseKeepAlive
from syncbridge.network.transfer import TransferProgress, TransferResult


class FencedSessionError(RuntimeError):
    """The guarded transfer session was used incorrectly."""


class FencedSyncSession:
    """Coordinate both fenced transfer directions under one session.

    The session is single-use. Create another instance for a later sync cycle.
    No listener is started here, and the normal runtime remains unchanged.
    """

    def __init__(
        self,
        *,
        local_root: str | Path,
        share_id: str,
        peer_node_id: str,
        remote_host: str,
        remote_lease_port: int,
        remote_upload_port: int,
        remote_read_port: int,
        lease_client: FencedLeaseClient,
        local_authority: LeaseAuthority,
        upload_client: FencedTransferClient,
        download_client: FencedDownloadClient,
        need_upload: bool = True,
        need_download: bool = True,
        ttl_seconds: float = 30.0,
        renewal_interval_seconds: float = 5.0,
    ) -> None:
        if not isinstance(lease_client, FencedLeaseClient):
            raise TypeError("lease_client must be FencedLeaseClient")
        if not isinstance(local_authority, LeaseAuthority):
            raise TypeError("local_authority must be LeaseAuthority")
        if not isinstance(upload_client, FencedTransferClient):
            raise TypeError("upload_client must be FencedTransferClient")
        if not isinstance(download_client, FencedDownloadClient):
            raise TypeError("download_client must be FencedDownloadClient")

        for label, value in (
            ("share_id", share_id),
            ("peer_node_id", peer_node_id),
        ):
            if (
                not isinstance(value, str)
                or len(value) != 32
                or any(c not in "0123456789abcdef" for c in value)
            ):
                raise ValueError(
                    f"{label} must be 32 lowercase hexadecimal characters"
                )

        try:
            address = ipaddress.IPv4Address(remote_host)
        except (ValueError, ipaddress.AddressValueError) as exc:
            raise ValueError("remote_host must be numeric IPv4") from exc

        if (
            address.is_unspecified
            or address.is_multicast
            or address.is_loopback and False
            or str(address) == "255.255.255.255"
        ):
            raise ValueError("remote_host must be a unicast IPv4 address")

        for label, port in (
            ("remote_lease_port", remote_lease_port),
            ("remote_upload_port", remote_upload_port),
            ("remote_read_port", remote_read_port),
        ):
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError(f"{label} must be a valid TCP port")

        if type(need_upload) is not bool or type(need_download) is not bool:
            raise TypeError("Transfer direction flags must be bool")

        if not (need_upload or need_download):
            raise ValueError("At least one transfer direction is required")

        if (
            type(ttl_seconds) not in (int, float)
            or not math.isfinite(ttl_seconds)
            or not 0.1 <= ttl_seconds <= 3600.0
        ):
            raise ValueError("Invalid lease lifetime")

        if (
            type(renewal_interval_seconds) not in (int, float)
            or not math.isfinite(renewal_interval_seconds)
            or not 0.01 <= renewal_interval_seconds < ttl_seconds / 2
        ):
            raise ValueError(
                "Renewal interval must be shorter than half the lease lifetime"
            )

        root = Path(local_root).expanduser().resolve(strict=True)

        if not root.is_dir():
            raise NotADirectoryError(root)

        identity = lease_client.identity.node_id

        if (
            upload_client.identity.node_id != identity
            or download_client.identity.node_id != identity
        ):
            raise ValueError(
                "All session clients must use the same local device identity"
            )

        if (
            upload_client.share_id != share_id
            or download_client.share_id != share_id
        ):
            raise ValueError("Transfer clients belong to another share")

        if download_client.authority is not local_authority:
            raise ValueError(
                "Download client must use the session's local lease authority"
            )

        if (
            upload_client.destination_root.resolve() != root
            or download_client.destination_root.resolve() != root
        ):
            raise ValueError(
                "Transfer clients must use the selected local folder"
            )

        self.local_root = root
        self.share_id = share_id
        self.peer_node_id = peer_node_id
        self.remote_host = str(address)

        self.remote_lease_port = remote_lease_port
        self.remote_upload_port = remote_upload_port
        self.remote_read_port = remote_read_port

        self.lease_client = lease_client
        self.local_authority = local_authority
        self.upload_client = upload_client
        self.download_client = download_client

        self.need_upload = need_upload
        self.need_download = need_download

        self.ttl_seconds = float(ttl_seconds)
        self.renewal_interval_seconds = float(renewal_interval_seconds)

        self._used = False
        self._active = False
        self._stack: ExitStack | None = None

        self._local_renewal: LeaseKeepAlive | None = None
        self._remote_renewal: LeaseKeepAlive | None = None

        # Cleanup is best effort because the receiver must enforce expiration
        # independently. Keep only exception type names, never lease tokens.
        self.cleanup_errors: list[str] = []

    @property
    def active(self) -> bool:
        return self._active

    @property
    def local_grant(self) -> LeaseGrant | None:
        if not self._active or self._local_renewal is None:
            return None
        return self._local_renewal.check()

    @property
    def remote_grant(self) -> LeaseGrant | None:
        if not self._active or self._remote_renewal is None:
            return None
        return self._remote_renewal.check()

    def _release_local(self, grant: LeaseGrant) -> None:
        try:
            self.local_authority.release(grant)
        except Exception as exc:
            self.cleanup_errors.append(type(exc).__name__)

    def _release_remote(self, grant: LeaseGrant) -> None:
        try:
            self.lease_client.release(
                self.remote_host,
                self.remote_lease_port,
                self.peer_node_id,
                grant,
            )
        except Exception as exc:
            self.cleanup_errors.append(type(exc).__name__)

    def __enter__(self) -> FencedSyncSession:
        if self._used:
            raise FencedSessionError("A fenced session cannot be restarted")

        self._used = True
        stack = ExitStack()

        try:
            local = None
            remote = None

            if self.need_download:
                local = self.local_authority.acquire(
                    self.share_id,
                    self.lease_client.identity.node_id,
                    ttl_seconds=self.ttl_seconds,
                )
                stack.callback(self._release_local, local)

            if self.need_upload:
                remote = self.lease_client.acquire(
                    self.remote_host,
                    self.remote_lease_port,
                    self.peer_node_id,
                    self.share_id,
                    ttl_seconds=self.ttl_seconds,
                )
                stack.callback(self._release_remote, remote)

            if local is not None:
                self._local_renewal = stack.enter_context(
                    LeaseKeepAlive(
                        local,
                        lambda grant: self.local_authority.renew(
                            grant,
                            ttl_seconds=self.ttl_seconds,
                        ),
                        interval_seconds=self.renewal_interval_seconds,
                    )
                )

            if remote is not None:
                self._remote_renewal = stack.enter_context(
                    LeaseKeepAlive(
                        remote,
                        lambda grant: self.lease_client.renew(
                            self.remote_host,
                            self.remote_lease_port,
                            self.peer_node_id,
                            grant,
                            ttl_seconds=self.ttl_seconds,
                        ),
                        interval_seconds=self.renewal_interval_seconds,
                    )
                )

            self._stack = stack
            self._active = True
            return self

        except BaseException:
            stack.close()
            raise

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        if not self._active or self._stack is None:
            raise FencedSessionError("Session is not active")

        stack = self._stack
        self._active = False
        self._stack = None

        return bool(stack.__exit__(exc_type, exc_value, traceback))

    def upload(
        self,
        relative_path: str,
        *,
        expected_destination_sha256: str | None = None,
        cancel_event: Event | None = None,
        on_progress=None,
    ) -> TransferResult:
        """Send bytes only with the destination's current authorization."""
        if not self._active or self._remote_renewal is None:
            raise FencedSessionError(
                "Upload requires an active remote fenced lease"
            )

        grant = self._remote_renewal.check()

        result = self.upload_client.send_fenced_file(
            self.remote_host,
            self.remote_upload_port,
            self.peer_node_id,
            self.local_root,
            relative_path,
            lease=grant,
            expected_destination_sha256=expected_destination_sha256,
            cancel_event=cancel_event,
            on_progress=on_progress,
        )

        self._remote_renewal.check()
        return result

    def download(
        self,
        relative_path: str,
        *,
        expected_source_sha256: str,
        expected_destination_sha256: str | None = None,
        cancel_event: Event | None = None,
        on_progress=None,
    ) -> TransferResult:
        """Receive bytes only with the local receiver's current authority."""
        if not self._active or self._local_renewal is None:
            raise FencedSessionError(
                "Download requires an active local fenced lease"
            )

        grant = self._local_renewal.check()

        result = self.download_client.fetch_fenced_file(
            self.remote_host,
            self.remote_read_port,
            self.peer_node_id,
            self.share_id,
            relative_path,
            lease=grant,
            expected_source_sha256=expected_source_sha256,
            expected_destination_sha256=expected_destination_sha256,
            cancel_event=cancel_event,
            on_progress=on_progress,
        )

        self._local_renewal.check()
        return result
