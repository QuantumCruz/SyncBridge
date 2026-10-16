
"""Headless adapter for SyncBridge's manual desktop synchronization UI.

The selected profile must contain one trusted enabled share. This controller
never pairs devices or silently enables file changes. GuardedManualRuntime
remains the only authority permitted to modify files.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from syncbridge.core.conflicts import SyncAction
from syncbridge.core.guarded_manual import GuardedManualRuntime
from syncbridge.storage.config import ConfigStore


class DesktopConfigurationError(RuntimeError):
    """The chosen profile cannot start guarded synchronization yet."""


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

    # Optional for compatibility with existing tests and callers.
    # This is a read-only estimate from the preview inventory.
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


def describe_preview(result) -> DesktopPreview:
    """Convert real lifecycle decisions to safe, read-only UI data."""
    preview = result.preview
    items = []

    for decision in preview.plan.decisions:
        title, explanation, blocked = _ACTIONS[decision.action]

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
                size=getattr(source, "size", None),
            )
        )

    return DesktopPreview(
        revision=preview.baseline_revision,
        items=tuple(items),
        requires_review=any(
            item.needs_review for item in items
        ),
    )


class DesktopController:
    """Own exactly one guarded runtime for exactly one local profile."""

    def __init__(
        self,
        store: ConfigStore | None = None,
        *,
        bind_address: str = "127.0.0.1",
        listen_ports: tuple[int, int, int] | None = None,
        lock_port: int = 45846,
        validation_port: int = 45847,
        runtime_factory: Callable[..., object] = GuardedManualRuntime,
    ) -> None:
        self.store = (
            store if store is not None else ConfigStore()
        )

        if not isinstance(self.store, ConfigStore):
            raise TypeError(
                "store must be a ConfigStore"
            )

        self._started = False

        self.runtime = runtime_factory(
            self.store,
            bind_address=bind_address,
            listen_ports=listen_ports,
            lock_port=lock_port,
            validation_port=validation_port,
        )

    @property
    def running(self) -> bool:
        # runtime.status holds a lock for the whole sync cycle.
        # Accessing it on the UI thread can freeze the desktop.
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
                "Device pairing and folder setup will be added to the GUI next."
            )

        share = enabled[0]

        if share.remote_host is None:
            raise DesktopConfigurationError(
                "The paired computer has no network address configured"
            )

        if share.preferences.auto_apply:
            raise DesktopConfigurationError(
                "Automatic changes are enabled in this profile. "
                "Turn off auto_apply before starting the manual desktop beta."
            )

        return DesktopProfile(
            settings.device_name,
            share.display_name,
            Path(share.local_root),
            share.peer_node_id,
            share.remote_host,
        )

    def start(self) -> None:
        if self._started:
            return

        self.profile()
        self.runtime.start(background=False)
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
