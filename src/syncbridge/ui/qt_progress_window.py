
"""Qt progress presentation layered over the existing SyncBridge window.

The existing desktop behavior is unchanged. This subclass only improves the
visible reporting of a transfer started by the local user. The remote receiver
continues using its independent file-list refresh.
"""
from __future__ import annotations

import time

from PySide6.QtCore import Signal, Slot

from syncbridge.ui.qt_window import SyncBridgeQtWindow
from syncbridge.ui.transfer_overview import (
    TransferOverview,
    TransferSnapshot,
)


class SyncBridgeProgressWindow(SyncBridgeQtWindow):
    transfer_update = Signal(int, object, float)

    def __init__(self, *args, **kwargs) -> None:
        self._overview: TransferOverview | None = None
        self._transfer_generation = 0
        self._last_emitted_at = 0.0
        self._last_emitted_key: tuple[str, str] | None = None

        super().__init__(*args, **kwargs)

        self.transfer_update.connect(
            self._display_transfer_update
        )

    def _sync_files(self) -> None:
        plan = self._preview

        if (
            plan is None
            or plan.requires_review
            or not plan.items
        ):
            return

        # The backend securely replans before executing.
        # These sizes are UI estimates, not permission to modify files.
        self._overview = TransferOverview(plan.items)
        self._transfer_generation += 1
        self._last_emitted_at = 0.0
        self._last_emitted_key = None

        super()._sync_files()

        # User declined the confirmation dialog.
        if not self._busy:
            self._overview = None

    def _on_progress(self, event: object) -> None:
        """Called on the worker; limit frequent transfer updates."""
        now = time.monotonic()
        key = (
            str(event.direction),
            str(event.path),
        )
        final = event.transferred >= event.total

        if (
            key == self._last_emitted_key
            and not final
            and now - self._last_emitted_at < 0.15
        ):
            return

        self._last_emitted_key = key
        self._last_emitted_at = now

        self.transfer_update.emit(
            self._transfer_generation,
            event,
            now,
        )

    @staticmethod
    def _duration(seconds: float) -> str:
        n = max(0, int(round(seconds)))

        if n < 60:
            return f"{n}s"

        if n < 3600:
            return f"{n // 60}m {n % 60}s"

        return f"{n // 3600}h {(n % 3600) // 60}m"

    def _show_transfer(
        self,
        state: TransferSnapshot,
    ) -> None:
        current = (
            f"File {state.file_number} of {state.planned_files}"
            if (
                state.planned_files
                and state.file_number <= state.planned_files
            )
            else "Current file"
        )

        speed = (
            f"{self._size(state.speed_bps)}/s"
            if state.speed_bps is not None
            else "Calculating speed..."
        )

        summary = (
            f"{current}: {state.path} "
            f"({state.file_percent}% of this file)"
            f"  ·  {speed}"
        )

        if (
            state.data_eta_seconds is not None
            and not state.verifying
        ):
            summary += (
                "  ·  Data transfer ETA "
                f"~{self._duration(state.data_eta_seconds)}"
            )

        self.progress.setText(summary)

        if state.verifying:
            self._show_activity(
                "Transfer bytes received. "
                "Verifying files and saving the sync state..."
            )

        elif (
            state.planned_bytes is not None
            and state.planned_bytes > 0
        ):
            self._show_activity(
                f"Transfer data: "
                f"{self._size(state.reported_bytes)} of "
                f"{self._size(state.planned_bytes)} "
                "(verification follows)",
                done=state.reported_bytes,
                total=state.planned_bytes,
            )

        else:
            self._show_activity(
                f"Transferring: {state.path} (current file)",
                done=state.file_bytes,
                total=state.file_size,
            )

    @Slot(int, object, float)
    def _display_transfer_update(
        self,
        generation: int,
        event: object,
        timestamp: float,
    ) -> None:
        if (
            self._closing
            or not self._busy
            or self._overview is None
            or generation != self._transfer_generation
        ):
            return

        state = self._overview.update(
            event,
            now=timestamp,
        )
        self._show_transfer(state)

    def _finish(
        self,
        kind: str,
        result: object,
    ) -> None:
        if kind == "sync":
            self._overview = None
            self._transfer_generation += 1

        super()._finish(kind, result)
