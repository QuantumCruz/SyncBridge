
"""Internal completion of a user-approved SyncBridge folder relationship.

The user has already approved the folder on each computer during share setup.
Activation checks matching identities, share IDs, names, and reciprocal TCP
ports over an authenticated, encrypted channel. It grants only manual sync:
auto_apply stays off and deletion still requires the existing review flow.

Settings on two machines cannot be updated in one atomic transaction. If a
connection fails after one side saves, retry activation for the same share ID;
no second user approval or duplicate share is required. Until both are ready,
a peer lacking matching grants refuses sync. Not production crash fencing.
"""
from __future__ import annotations

import socket
import threading
from dataclasses import replace
from pathlib import Path

from syncbridge.network.secure_channel import (
    accept_secure_channel, open_secure_channel,
)
from syncbridge.network.security import DeviceIdentity, TrustStore
from syncbridge.network.share_setup import (
    ShareSetupError, ShareSetupService, _DEFAULT_PORTS, _folder, _host,
    _id, _ports, _recv, _send,
)
from syncbridge.storage.config import ConfigStore, ShareConfig

ACTIVATION_PORT = 45848


class ShareActivationError(ShareSetupError):
    """Approved folders could not yet be made ready on both devices."""


def _assigned_ports(share: ShareConfig) -> tuple[int, int, int]:
    return (
        share.manifest_port,
        share.transfer_port,
        share.agreement_port,
    )


def _validate_share(
    store: ConfigStore,
    share_id: str,
    peer_id: str,
) -> ShareConfig:
    share = store.load().get_share(_id(share_id))

    if share is None or share.peer_node_id != _id(peer_id):
        raise ShareActivationError(
            "No approved folder relationship for this device"
        )

    if share.remote_host is None:
        raise ShareActivationError(
            "Paired device has no network address"
        )

    _folder(Path(share.local_root), store.path)

    if share.preferences.auto_apply:
        raise ShareActivationError(
            "Unattended synchronization is not authorized"
        )

    grants = (
        share.grant_manifest,
        share.grant_read,
        share.grant_write,
        share.grant_agreement,
    )

    if any(grants) != all(grants) or share.enabled != all(grants):
        raise ShareActivationError(
            "Folder has inconsistent access permissions"
        )

    others = store.load().shares

    if any(
        item.enabled
        for item in others
        if item.share_id != share_id
    ):
        raise ShareActivationError(
            "Another folder is already active in this beta"
        )

    return share


def _enabled(share: ShareConfig) -> ShareConfig:
    return replace(
        share,
        enabled=True,
        grant_manifest=True,
        grant_read=True,
        grant_write=True,
        grant_agreement=True,
    )


def _save_ready(
    store: ConfigStore,
    expected: ShareConfig,
) -> ShareConfig:
    """Idempotent compare-and-swap; never overwrite intervening edits."""
    current = store.load()
    found = current.get_share(expected.share_id)

    if found != expected:
        raise ShareActivationError(
            "Folder settings changed during connection setup"
        )

    if found.enabled:
        return found

    ready = _enabled(found)

    store.save(
        replace(
            current,
            shares=tuple(
                ready if item.share_id == found.share_id else item
                for item in current.shares
            ),
        )
    )

    return ready


class ShareActivationClient:
    """Complete setup; normally called by the GUI, not directly by a person."""

    def __init__(
        self,
        identity: DeviceIdentity,
        trust: TrustStore,
        store: ConfigStore,
        *,
        local_ports: tuple[int, int, int] = _DEFAULT_PORTS,
    ) -> None:
        self.identity = identity
        self.trust = trust
        self.store = store
        self.local_ports = _ports(local_ports)

    def activate(
        self,
        share_id: str,
        peer_id: str,
        *,
        port: int = ACTIVATION_PORT,
        timeout: float = 6.0,
    ) -> ShareConfig:
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("Invalid activation port")

        share = _validate_share(
            self.store, share_id, peer_id
        )

        if self.trust.get(peer_id) is None:
            raise ShareActivationError(
                "Device is no longer trusted"
            )

        try:
            with socket.create_connection(
                (_host(share.remote_host), port),
                timeout=timeout,
            ) as sock:
                secure, authenticated = open_secure_channel(
                    sock,
                    self.identity,
                    self.trust,
                    peer_id,
                    timeout=timeout,
                )

                if authenticated.node_id != peer_id:
                    raise ShareActivationError(
                        "Remote device identity changed"
                    )

                secure.settimeout(timeout)

                _send(
                    secure,
                    "prepare",
                    share_id=share.share_id,
                    name=share.display_name,
                    local_ports=list(self.local_ports),
                    remote_ports=list(_assigned_ports(share)),
                )

                kind, response = _recv(
                    secure,
                    {
                        "ready": {
                            "share_id",
                            "local_ports",
                            "remote_ports",
                        },
                        "rejected": set(),
                    },
                )

                if kind == "rejected":
                    raise ShareActivationError(
                        "Other device is not ready for this folder"
                    )

                if (
                    _id(response["share_id"]) != share.share_id
                    or _ports(response["local_ports"])
                    != _assigned_ports(share)
                    or _ports(response["remote_ports"])
                    != self.local_ports
                ):
                    raise ShareActivationError(
                        "Folder connection details disagree"
                    )

                if self.trust.get(peer_id) is None:
                    raise ShareActivationError(
                        "Device trust was revoked"
                    )

                # The two settings files are not atomically updated.
                # If the connection is interrupted after this save,
                # retrying reconciles the same share ID.
                ready = _save_ready(self.store, share)

                _send(
                    secure,
                    "activate",
                    share_id=share.share_id,
                )

                kind, acknowledgement = _recv(
                    secure,
                    {
                        "active": {"share_id"},
                        "rejected": set(),
                    },
                )

                if (
                    kind != "active"
                    or _id(acknowledgement["share_id"])
                    != share.share_id
                ):
                    raise ShareActivationError(
                        "Other device did not confirm readiness"
                    )

                return ready

        except (OSError, TimeoutError) as exc:
            raise ShareActivationError(
                "Connection interrupted. SyncBridge can retry "
                "this folder automatically"
            ) from exc


class ShareActivationService(ShareSetupService):
    """Authenticated receiver reusing the bounded TCP listener lifecycle."""

    def __init__(
        self,
        identity: DeviceIdentity,
        trust: TrustStore,
        store: ConfigStore,
        *,
        bind_address: str = "127.0.0.1",
        port: int = ACTIVATION_PORT,
        local_ports: tuple[int, int, int] = _DEFAULT_PORTS,
    ) -> None:
        super().__init__(
            identity,
            trust,
            store,
            bind_address=bind_address,
            port=port,
            approval_timeout=10.0,
        )
        self.local_ports = _ports(local_ports)

    def _handle(
        self,
        sock: socket.socket,
        observed_host: str,
    ) -> None:
        secure = None

        try:
            sock.settimeout(6)

            secure, authenticated = accept_secure_channel(
                sock,
                self.identity,
                self.trust,
                timeout=6,
            )

            secure.settimeout(6)

            _, request = _recv(
                secure,
                {
                    "prepare": {
                        "share_id",
                        "name",
                        "local_ports",
                        "remote_ports",
                    }
                },
            )

            share = _validate_share(
                self.store,
                _id(request["share_id"]),
                authenticated.node_id,
            )

            if (
                share.remote_host != _host(observed_host)
                or share.display_name != request["name"]
                or _assigned_ports(share)
                != _ports(request["local_ports"])
                or self.local_ports
                != _ports(request["remote_ports"])
                or self.trust.get(authenticated.node_id) is None
                or self._stop.is_set()
            ):
                raise ShareActivationError(
                    "Folder connection details disagree"
                )

            _send(
                secure,
                "ready",
                share_id=share.share_id,
                local_ports=list(self.local_ports),
                remote_ports=list(_assigned_ports(share)),
            )

            _, confirmation = _recv(
                secure,
                {
                    "activate": {"share_id"}
                },
            )

            if _id(confirmation["share_id"]) != share.share_id:
                raise ShareActivationError(
                    "Wrong folder activation receipt"
                )

            if (
                self._stop.is_set()
                or self.trust.get(authenticated.node_id) is None
            ):
                raise ShareActivationError(
                    "Activation stopped or device is no longer trusted"
                )

            # Recheck consent and settings before saving.
            latest = _validate_share(
                self.store,
                share.share_id,
                authenticated.node_id,
            )

            if latest != share:
                raise ShareActivationError(
                    "Folder configuration changed"
                )

            _save_ready(self.store, latest)

            _send(
                secure,
                "active",
                share_id=share.share_id,
            )

        except Exception:
            # Failed exchanges must not terminate the listener
            # or silently approve an invalid request.
            if secure is not None:
                try:
                    _send(secure, "rejected")
                except Exception:
                    pass

        finally:
            with self._lock:
                self._sockets.discard(sock)
                self._workers.discard(
                    threading.current_thread()
                )

            if secure is not None:
                secure.close()

            sock.close()
