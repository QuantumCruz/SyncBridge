
"""Headless adapter for SyncBridge's manual desktop synchronization UI.

Uses operation-bound, receiver-fenced transfers by default.

DesktopLifecycle defines the allowed desktop states and button permissions.
The Qt desktop will own one instance and use it as its sole UI-state authority.

For separate desktop profiles sharing one machine, lease-control ports are
derived from the configured transfer ports. Port overrides take precedence.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable

from syncbridge.core.conflicts import SyncAction
from syncbridge.core.fenced_guarded_manual import (
    FencedGuardedManualRuntime,
)
from syncbridge.storage.config import ConfigStore


class DesktopConfigurationError(RuntimeError):
    """The selected desktop profile cannot start synchronization."""


class DesktopLifecycleError(RuntimeError):
    """The desktop attempted an invalid state transition."""


class DesktopPhase(str, Enum):
    """The one authoritative phase of a desktop connection."""

    DISCONNECTED = "disconnected"
    PAIRING = "pairing"
    CHOOSING_FOLDER = "choosing_folder"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    SYNCHRONIZING = "synchronizing"
    CHANGING_FOLDERS = "changing_folders"
    DISCONNECTING = "disconnecting"


_TRANSITIONS = {
    DesktopPhase.DISCONNECTED: frozenset({
        DesktopPhase.PAIRING,
        DesktopPhase.CONNECTING,
    }),
    DesktopPhase.PAIRING: frozenset({
        DesktopPhase.CHOOSING_FOLDER,
        DesktopPhase.DISCONNECTING,
    }),
    DesktopPhase.CHOOSING_FOLDER: frozenset({
        DesktopPhase.CONNECTING,
        DesktopPhase.DISCONNECTING,
    }),
    DesktopPhase.CONNECTING: frozenset({
        DesktopPhase.CONNECTED,
        DesktopPhase.DISCONNECTING,
    }),
    DesktopPhase.CONNECTED: frozenset({
        DesktopPhase.SYNCHRONIZING,
        DesktopPhase.CHANGING_FOLDERS,
        DesktopPhase.DISCONNECTING,
    }),
    DesktopPhase.SYNCHRONIZING: frozenset({
        DesktopPhase.CONNECTED,
        DesktopPhase.DISCONNECTING,
    }),
    DesktopPhase.CHANGING_FOLDERS: frozenset({
        DesktopPhase.CHOOSING_FOLDER,
        DesktopPhase.DISCONNECTING,
    }),
    DesktopPhase.DISCONNECTING: frozenset({
        DesktopPhase.DISCONNECTED,
    }),
}


def desktop_buttons(
    phase: DesktopPhase,
    *,
    saved_peer: bool = False,
    preview_ready: bool = False,
) -> frozenset[str]:
    """One place to decide which main-window actions are permitted.

    The returning-user shortcut requires a saved relationship.
    Sync requires a fresh, safe Preview from the current connection.

    Network listeners must independently enforce session authorization.
    A disabled Qt button is never considered a security boundary.
    """
    if not isinstance(phase, DesktopPhase):
        raise TypeError("phase must be DesktopPhase")

    if type(saved_peer) is not bool:
        raise TypeError("saved_peer must be bool")

    if type(preview_ready) is not bool:
        raise TypeError("preview_ready must be bool")

    if phase is DesktopPhase.DISCONNECTED:
        actions = {"find"}
        if saved_peer:
            actions.add("reconnect")
        return frozenset(actions)

    if phase is DesktopPhase.CHOOSING_FOLDER:
        return frozenset({"choose_folder"})

    if phase is DesktopPhase.CONNECTED:
        actions = {
            "change_folder",
            "open_folder",
            "preview",
            "disconnect",
        }
        if preview_ready:
            actions.add("sync")
        return frozenset(actions)

    # Pairing, connecting, synchronizing, changing folders and
    # disconnecting do not permit conflicting main-window actions.
    return frozenset()


class DesktopLifecycle:
    """Small in-memory state machine; never stores network credentials.

    Transitions must be applied by the owner of the desktop event loop.
    Background workers return results to that owner instead of changing
    desktop state or widgets directly.

    The generation changes on each actual state transition, allowing the
    desktop to discard results produced for an obsolete operation.
    """

    def __init__(self) -> None:
        self._phase = DesktopPhase.DISCONNECTED
        self._generation = 0

    @property
    def phase(self) -> DesktopPhase:
        return self._phase

    @property
    def generation(self) -> int:
        return self._generation

    def transition(self, next_phase: DesktopPhase) -> int:
        if not isinstance(next_phase, DesktopPhase):
            raise TypeError("next_phase must be DesktopPhase")

        if next_phase is self._phase:
            return self._generation

        if next_phase not in _TRANSITIONS[self._phase]:
            raise DesktopLifecycleError(
                f"Invalid desktop transition: "
                f"{self._phase.value} -> {next_phase.value}"
            )

        self._phase = next_phase
        self._generation += 1
        return self._generation

    def allowed_buttons(
        self,
        *,
        saved_peer: bool = False,
        preview_ready: bool = False,
    ) -> frozenset[str]:
        return desktop_buttons(
            self._phase,
            saved_peer=saved_peer,
            preview_ready=preview_ready,
        )


@dataclass(frozen=True, slots=True)
class DesktopProfile:
    device_name: str
    folder_name: str
    local_root: Path
    peer_node_id: str
    remote_host: str


@dataclass(frozen=True, slots=True)
class DesktopPlanItem:
    path: str
    action: str
    description: str
    needs_review: bool
    size: int | None = None


@dataclass(frozen=True, slots=True)
class DesktopPreview:
    revision: int
    items: tuple[DesktopPlanItem, ...]
    requires_review: bool


_ACTIONS = {
    SyncAction.UPLOAD: (
        "Send",
        "Copy this version to the paired computer",
        False,
    ),
    SyncAction.DOWNLOAD: (
        "Receive",
        "Copy the paired computer's version here",
        False,
    ),
    SyncAction.CONFLICT: (
        "Conflict",
        "Both versions need your attention",
        True,
    ),
    SyncAction.REVIEW_DELETE_LOCAL: (
        "Deletion review",
        "The other computer is missing a previously synchronized file",
        True,
    ),
    SyncAction.REVIEW_DELETE_REMOTE: (
        "Deletion review",
        "This computer is missing a previously synchronized file",
        True,
    ),
}


_DEFAULT_TRANSFER_PORT = 45842
_DEFAULT_LEASE_PORT = 45849

_MIN_CUSTOM_PORT = 1025
_PORT_SPAN = 65535 - _MIN_CUSTOM_PORT + 1
_PORT_SHIFT = 20000


def _lease_port_for_transfer(transfer_port: int) -> int:
    """Compute the same lease port on both ends of a configured connection.

    Preserve the production port and derive independent ports for local
    multi-profile testing. Explicit overrides always take precedence.
    """
    if (
        type(transfer_port) is not int
        or not _MIN_CUSTOM_PORT <= transfer_port <= 65535
    ):
        raise ValueError(
            "A fixed transfer port between 1025 and 65535 is required"
        )

    def rotated(port: int) -> int:
        return _MIN_CUSTOM_PORT + (
            (port - _MIN_CUSTOM_PORT + _PORT_SHIFT)
            % _PORT_SPAN
        )

    if transfer_port == _DEFAULT_TRANSFER_PORT:
        return _DEFAULT_LEASE_PORT

    ordinary = rotated(transfer_port)

    if ordinary == _DEFAULT_LEASE_PORT:
        return rotated(_DEFAULT_TRANSFER_PORT)

    return ordinary


def describe_preview(result) -> DesktopPreview:
    """Convert lifecycle decisions into safe, read-only UI data."""
    preview = result.preview
    items = []

    for decision in preview.plan.decisions:
        title, explanation, blocked = _ACTIONS[
            decision.action
        ]

        source = (
            getattr(decision, "local", None)
            if decision.action is SyncAction.UPLOAD
            else getattr(decision, "remote", None)
            if decision.action is SyncAction.DOWNLOAD
            else None
        )

        items.append(
            DesktopPlanItem(
                decision.path,
                title,
                explanation,
                blocked,
                size=getattr(
                    source,
                    "size",
                    None,
                ),
            )
        )

    return DesktopPreview(
        revision=preview.baseline_revision,
        items=tuple(items),
        requires_review=any(
            item.needs_review
            for item in items
        ),
    )


class DesktopController:
    """Own exactly one manually controlled fenced runtime per profile."""

    def __init__(
        self,
        store: ConfigStore | None = None,
        *,
        bind_address: str = "127.0.0.1",
        listen_ports: tuple[int, int, int] | None = None,
        lock_port: int = 45846,
        validation_port: int = 45847,
        lease_listen_port: int | None = None,
        remote_lease_port: int | None = None,
        runtime_factory: Callable[..., object] = FencedGuardedManualRuntime,
    ) -> None:
        self.store = (
            store
            if store is not None
            else ConfigStore()
        )

        if not isinstance(self.store, ConfigStore):
            raise TypeError(
                "store must be a ConfigStore"
            )

        for label, port in (
            ("lease_listen_port", lease_listen_port),
            ("remote_lease_port", remote_lease_port),
        ):
            if port is not None and (
                type(port) is not int
                or not 1 <= port <= 65535
            ):
                raise ValueError(
                    f"{label} must be a valid TCP port"
                )

        self._started = False

        self._listen_ports = listen_ports
        self._lease_listen_override = lease_listen_port
        self._remote_lease_override = remote_lease_port

        # The existing onboarding layer reads runtime.listen_ports
        # before the user has chosen a folder. Keep runtime creation
        # independent of the future desktop UI lifecycle.
        self.runtime = runtime_factory(
            self.store,
            bind_address=bind_address,
            listen_ports=listen_ports,
            lock_port=lock_port,
            validation_port=validation_port,
            lease_listen_port=(
                lease_listen_port
                if lease_listen_port is not None
                else _DEFAULT_LEASE_PORT
            ),
            remote_lease_port=(
                remote_lease_port
                if remote_lease_port is not None
                else _DEFAULT_LEASE_PORT
            ),
        )

    @property
    def running(self) -> bool:
        # Runtime status may block on a synchronization lock.
        # Avoid holding the Qt event loop while waiting for it.
        return self._started

    def profile(self) -> DesktopProfile:
        settings = self.store.load()

        enabled = [
            share
            for share in settings.shares
            if share.enabled
        ]

        if len(enabled) != 1:
            raise DesktopConfigurationError(
                "Set up exactly one enabled folder pair in this profile. "
                "Pair your computers and choose your folders first."
            )

        share = enabled[0]

        if share.remote_host is None:
            raise DesktopConfigurationError(
                "The paired computer has no network address configured"
            )

        if share.preferences.auto_apply:
            raise DesktopConfigurationError(
                "Automatic changes are enabled in this profile. "
                "Turn off auto_apply before starting manual synchronization."
            )

        return DesktopProfile(
            settings.device_name,
            share.display_name,
            Path(share.local_root),
            share.peer_node_id,
            share.remote_host,
        )

    def _configure_lease_ports(self) -> None:
        """Match lease endpoints to the configured transfer endpoints."""
        if not isinstance(
            self.runtime,
            FencedGuardedManualRuntime,
        ):
            # Preserve test injection and alternative controllers.
            return

        enabled = [
            share
            for share in self.store.load().shares
            if share.enabled
        ]

        if len(enabled) != 1:
            raise DesktopConfigurationError(
                "Choose one approved folder before connecting"
            )

        share = enabled[0]

        if self._listen_ports is None:
            local_transfer_port = share.transfer_port
        else:
            local_transfer_port = self._listen_ports[1]

        remote_transfer_port = share.transfer_port

        try:
            if self._lease_listen_override is None:
                self.runtime.lease_listen_port = (
                    _lease_port_for_transfer(
                        local_transfer_port
                    )
                )

            if self._remote_lease_override is None:
                self.runtime.remote_lease_port = (
                    _lease_port_for_transfer(
                        remote_transfer_port
                    )
                )

        except ValueError as exc:
            raise DesktopConfigurationError(
                "Unable to configure secure transfer ports. "
                "Choose valid fixed network ports for this profile."
            ) from exc

    def start(self) -> None:
        if self._started:
            return

        self.profile()
        self._configure_lease_ports()

        self.runtime.start(
            background=False
        )
        self._started = True

    def stop(self) -> None:
        if not self._started:
            return

        self.runtime.stop()
        self._started = False

    def preview(self) -> DesktopPreview:
        if not self.running:
            raise RuntimeError(
                "Start the connection before previewing changes"
            )

        return describe_preview(
            self.runtime.preview()
        )

    def sync_once(self, *, on_progress=None):
        if not self.running:
            raise RuntimeError(
                "Start the connection before synchronizing"
            )

        return self.runtime.sync_once(
            on_progress=on_progress
        )
