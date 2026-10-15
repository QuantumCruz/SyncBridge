
"""Fail-closed application composition for one explicitly configured folder pair.

Identity and trust live outside synchronized roots. No pairing is inferred from
settings. Start is transactional: listeners/workers are rolled back on failure.

Until the transfer service is multiplexed by share ID, ONE enabled folder pair
is supported. The lock prevents two runtimes using the same local profile; it
is not a distributed or filesystem-writer lock.
"""

from __future__ import annotations

import os
import stat
import threading
from dataclasses import dataclass
from pathlib import Path

from syncbridge.core.baseline import BaselineCoordinator
from syncbridge.core.coordinator import SyncCoordinator
from syncbridge.core.lifecycle import SyncLifecycle
from syncbridge.core.sync_service import AutoSyncService, ServiceState
from syncbridge.network.agreement import AgreementClient, AgreementService
from syncbridge.network.manifest import ManifestService
from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.network.transfer import TransferService
from syncbridge.storage.config import AppConfig, ConfigStore, ShareConfig
from syncbridge.storage.shared_state import SharedStateDatabase


class StartupError(RuntimeError):
    """Configuration or current process state makes startup unsafe."""


class InstanceAlreadyRunning(StartupError):
    """Another process currently owns the local SyncBridge profile."""


@dataclass(frozen=True, slots=True)
class RuntimeStatus:
    running: bool
    node_id: str | None
    share_id: str | None
    manifest_port: int | None
    transfer_port: int | None
    agreement_port: int | None
    background_running: bool


class _ProfileLock:
    """Lifetime OS advisory lock. Never unlink the lock file while running."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._stream = None

    def acquire(self) -> None:
        if self._stream is not None:
            raise RuntimeError("Profile lock already held")

        if self.path.is_symlink() or (
            hasattr(os.path, "isjunction")
            and os.path.isjunction(self.path)
        ):
            raise StartupError("Profile lock cannot be a link or junction")

        self.path.parent.mkdir(parents=True, exist_ok=True)

        flags = (
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )

        fd = os.open(self.path, flags, 0o600)
        stream = os.fdopen(fd, "r+b", buffering=0)

        try:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise StartupError("Profile lock must be a regular file")

            if os.fstat(stream.fileno()).st_size == 0:
                stream.write(b"\0")

            stream.seek(0)

            try:
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(
                        stream.fileno(),
                        msvcrt.LK_NBLCK,
                        1,
                    )
                else:
                    import fcntl

                    fcntl.flock(
                        stream.fileno(),
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )

            except (OSError, BlockingIOError) as exc:
                raise InstanceAlreadyRunning(
                    "SyncBridge profile is already in use"
                ) from exc

            self._stream = stream

        except BaseException:
            stream.close()
            raise

    def release(self) -> None:
        stream, self._stream = self._stream, None

        if stream is None:
            return

        try:
            stream.seek(0)

            if os.name == "nt":
                import msvcrt

                msvcrt.locking(
                    stream.fileno(),
                    msvcrt.LK_UNLCK,
                    1,
                )
            else:
                import fcntl

                fcntl.flock(
                    stream.fileno(),
                    fcntl.LOCK_UN,
                )
        finally:
            stream.close()


class SyncBridgeRuntime:
    """Build and own all services for a single user-approved folder pair.

    start(background=False) opens authorized listeners but runs NO sync cycle.
    start(background=True) also starts monitoring; file writes still require
    the saved preferences.auto_apply flag.

    The profile must be outside the synchronized folder. Local listening ports
    normally use the three configured ports. listen_ports=(0,0,0) may be used
    for loopback integration tests only; the remote ports in configuration are
    always the other device's actual ports.
    """

    def __init__(
        self,
        config_store: ConfigStore | None = None,
        *,
        bind_address: str = "127.0.0.1",
        listen_ports: tuple[int, int, int] | None = None,
    ) -> None:
        self.config_store = (
            config_store
            if config_store is not None
            else ConfigStore()
        )

        if not isinstance(self.config_store, ConfigStore):
            raise TypeError("config_store must be ConfigStore")

        if listen_ports is not None and (
            not isinstance(listen_ports, tuple)
            or len(listen_ports) != 3
            or any(
                type(port) is not int or not 0 <= port <= 65535
                for port in listen_ports
            )
        ):
            raise ValueError(
                "listen_ports must contain three valid TCP ports"
            )

        self.bind_address = bind_address
        self.listen_ports = listen_ports

        self._guard = threading.RLock()

        self._profile_lock = _ProfileLock(
            self.config_store.path.parent / "instance.lock"
        )

        self.config: AppConfig | None = None
        self.identity = None
        self.trust_store: TrustStore | None = None
        self.shared_state: SharedStateDatabase | None = None

        self.manifest_server: ManifestService | None = None
        self.transfer_server: TransferService | None = None
        self.agreement_server: AgreementService | None = None

        self.manifest_client: ManifestService | None = None
        self.transfer_client: TransferService | None = None
        self.agreement_client: AgreementClient | None = None

        self.coordinator: SyncCoordinator | None = None
        self.baseline: BaselineCoordinator | None = None
        self.lifecycle: SyncLifecycle | None = None
        self.sync_service: AutoSyncService | None = None

        self._running = False

    def _clear(self) -> None:
        for field in (
            "config",
            "identity",
            "trust_store",
            "shared_state",
            "manifest_server",
            "transfer_server",
            "agreement_server",
            "manifest_client",
            "transfer_client",
            "agreement_client",
            "coordinator",
            "baseline",
            "lifecycle",
            "sync_service",
        ):
            setattr(self, field, None)

        self._running = False

    @property
    def status(self) -> RuntimeStatus:
        with self._guard:
            share = (
                next(
                    (
                        item
                        for item in self.config.shares
                        if item.enabled
                    ),
                    None,
                )
                if self.config
                else None
            )

            return RuntimeStatus(
                self._running,
                (
                    self.identity.node_id
                    if self.identity is not None
                    else None
                ),
                share.share_id if share else None,
                (
                    self.manifest_server.bound_port
                    if self.manifest_server
                    else None
                ),
                (
                    self.transfer_server.bound_port
                    if self.transfer_server
                    else None
                ),
                (
                    self.agreement_server.bound_port
                    if self.agreement_server
                    else None
                ),
                (
                    self.sync_service.is_running
                    if self.sync_service
                    else False
                ),
            )

    def _selected(
        self,
        settings: AppConfig,
    ) -> ShareConfig | None:
        shares = [
            share
            for share in settings.shares
            if share.enabled
        ]

        if len(shares) > 1:
            raise StartupError(
                "Only one enabled share is supported until "
                "transfer multiplexing is implemented"
            )

        if not shares:
            return None

        share = shares[0]
        root = Path(share.local_root)

        if (
            root.is_symlink()
            or (
                hasattr(os.path, "isjunction")
                and os.path.isjunction(root)
            )
            or not root.is_dir()
        ):
            raise StartupError(
                "Enabled share folder is missing or is a link"
            )

        resolved = root.resolve(strict=True)
        profile = self.config_store.path.parent.resolve(
            strict=False
        )

        if (
            resolved == profile
            or resolved in profile.parents
            or profile in resolved.parents
        ):
            raise StartupError(
                "Profile and synchronized folder must not overlap"
            )

        if share.remote_host is None:
            raise StartupError(
                "Enabled share has no remote IPv4 address"
            )

        return share

    def start(
        self,
        *,
        background: bool = False,
    ) -> RuntimeStatus:
        if type(background) is not bool:
            raise TypeError("background must be bool")

        with self._guard:
            if self._running:
                return self.status

            self._profile_lock.acquire()
            started = []

            try:
                config = self.config_store.load()
                selected = self._selected(config)
                profile = self.config_store.path.parent

                self.identity = load_or_create_identity(
                    profile / "identity.json"
                )
                self.trust_store = TrustStore(
                    profile / "trust.json"
                )

                self.config = config

                if selected is not None:
                    if (
                        self.trust_store.get(
                            selected.peer_node_id
                        ) is None
                    ):
                        raise StartupError(
                            "Configured peer has not been explicitly paired"
                        )

                    root = Path(
                        selected.local_root
                    ).resolve(strict=True)

                    share = selected.share_id
                    peer = selected.peer_node_id
                    remote = selected.remote_host

                    self.shared_state = SharedStateDatabase(
                        profile / "shared_state.sqlite"
                    )

                    ports = self.listen_ports or (
                        selected.manifest_port,
                        selected.transfer_port,
                        selected.agreement_port,
                    )

                    opts = {
                        "bind_address": self.bind_address
                    }

                    self.manifest_server = ManifestService(
                        self.identity,
                        self.trust_store,
                        {share: root},
                        allowed_readers={
                            share: (
                                [peer]
                                if selected.grant_manifest
                                else []
                            )
                        },
                        shared_state=self.shared_state,
                        listen_port=ports[0],
                        **opts,
                    )

                    self.transfer_server = TransferService(
                        self.identity,
                        self.trust_store,
                        root,
                        share_id=share,
                        allowed_senders=(
                            [peer]
                            if selected.grant_write
                            else []
                        ),
                        allowed_readers=(
                            [peer]
                            if selected.grant_read
                            else []
                        ),
                        allow_overwrite=selected.grant_write,
                        listen_port=ports[1],
                        **opts,
                    )

                    self.agreement_server = AgreementService(
                        self.identity,
                        self.trust_store,
                        self.shared_state,
                        {share: root},
                        allowed_peers={
                            share: (
                                [peer]
                                if selected.grant_agreement
                                else []
                            )
                        },
                        listen_port=ports[2],
                        **opts,
                    )

                    self.manifest_client = ManifestService(
                        self.identity,
                        self.trust_store,
                        bind_address="127.0.0.1",
                        listen_port=0,
                    )

                    self.transfer_client = self.transfer_server

                    self.agreement_client = AgreementClient(
                        self.identity,
                        self.trust_store,
                    )

                    self.coordinator = SyncCoordinator(
                        root,
                        peer,
                        share,
                        remote,
                        selected.manifest_port,
                        selected.transfer_port,
                        manifest_client=self.manifest_client,
                        transfer_sender=self.transfer_client,
                        shared_state=self.shared_state,
                    )

                    self.baseline = BaselineCoordinator(
                        root,
                        peer,
                        share,
                        remote,
                        selected.agreement_port,
                        agreement_client=self.agreement_client,
                        shared_state=self.shared_state,
                    )

                    self.lifecycle = SyncLifecycle(
                        self.coordinator,
                        self.baseline,
                    )

                    prefs = selected.preferences

                    self.sync_service = AutoSyncService(
                        self.lifecycle,
                        auto_apply=prefs.auto_apply,
                        poll_interval=prefs.poll_interval,
                        watch_interval=prefs.watch_interval,
                        settle_delay=prefs.settle_delay,
                        retry_initial=prefs.retry_initial,
                        retry_max=prefs.retry_max,
                    )

                    for listener in (
                        self.manifest_server,
                        self.transfer_server,
                        self.agreement_server,
                    ):
                        listener.start()
                        started.append(listener)

                    if background:
                        self.sync_service.start()
                        started.append(self.sync_service)

                self._running = True
                return self.status

            except BaseException:
                for service in reversed(started):
                    try:
                        service.stop()
                    except Exception:
                        pass

                self._clear()
                self._profile_lock.release()
                raise

    def stop(self) -> None:
        with self._guard:
            if not self._running:
                return

            if self.sync_service is not None:
                self.sync_service.stop(timeout=10)

                # Do not release the profile lock or tear down listeners
                # while a live synchronization worker is still stopping.
                if (
                    self.sync_service.status.state
                    is ServiceState.STOPPING
                ):
                    raise StartupError(
                        "Background synchronization has not stopped; "
                        "retry stop"
                    )

            for service in (
                self.agreement_server,
                self.transfer_server,
                self.manifest_server,
            ):
                if service is not None:
                    service.stop()

            self._clear()
            self._profile_lock.release()

    def __enter__(self) -> "SyncBridgeRuntime":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()
