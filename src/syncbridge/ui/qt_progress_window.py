
"""Qt desktop progress reporting and passive change detection.

The desktop periodically checks paired folders for differences without
modifying files. Explicit user approval is still required to initiate a
transfer. This does not enable the unfenced legacy background auto-sync path.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from PySide6.QtCore import QTimer, Signal, Slot
from syncbridge.ui.desktop_controller import DesktopPreview
from syncbridge.ui.qt_window import SyncBridgeQtWindow
from syncbridge.ui.transfer_overview import TransferOverview, TransferSnapshot


@dataclass(frozen=True, slots=True)
class _PassiveCheck:
    """Result of a read-only poll; errors must not create modal dialogs."""

    preview: DesktopPreview | None = None
    error: str | None = None


class SyncBridgeProgressWindow(SyncBridgeQtWindow):
    transfer_update = Signal(int, object, float)

    def __init__(self, *args, **kwargs) -> None:
        self._overview: TransferOverview | None = None
        self._transfer_generation = 0
        self._last_emitted_at = 0.0
        self._last_emitted_key: tuple[str, str] | None = None
        super().__init__(*args, **kwargs)

        self.transfer_update.connect(self._display_transfer_update)

        # The timer runs on the GUI thread and never directly scans files.
        # Actual preview work uses the window's existing one-worker queue.
        self._passive_check_timer = QTimer(self)
        self._passive_check_timer.setInterval(15_000)
        self._passive_check_timer.timeout.connect(self._check_in_background)
        self._passive_check_timer.start()

    def _check_in_background(self) -> None:
        """Schedule at most one read-only preview, never a file write."""
        if (
            self._closing
            or self._shutting_down
            or self._paused
            or self._busy
            or not self.controller.running
        ):
            return
        if self.onboarding and (
            self.onboarding._pair_busy or self.onboarding._folder_busy
        ):
            return
        self._work("preview", self._read_only_check)

    def _read_only_check(self) -> _PassiveCheck:
        """Return network errors as data so reconnection needs no popup."""
        try:
            return _PassiveCheck(preview=self.controller.preview())
        except Exception as exc:
            return _PassiveCheck(error=str(exc))

    @staticmethod
    def _preview_signature(preview: DesktopPreview | None):
        if preview is None:
            return None
        return (
            preview.revision,
            preview.requires_review,
            tuple(
                (item.path, item.action, item.needs_review, item.size)
                for item in preview.items
            ),
        )

    def _finish_passive_check(self, result: _PassiveCheck) -> None:
        if result.error is not None:
            # A disconnected peer is an ordinary temporary state. Retrying
            # must never flood the user with modal warning boxes.
            self._preview = None
            self.table.setRowCount(0)
            self.status.setText("Waiting for other computer")
            self.summary.setText(
                "Cannot check the other computer right now. "
                "SyncBridge will check again automatically."
            )
            return

        plan = result.preview
        if plan is None:
            self._preview = None
            self.status.setText("Waiting for other computer")
            return

        if not plan.items:
            if self._preview is not None and self._preview.items:
                self.table.setRowCount(0)
            self._preview = plan
            self.status.setText("Connected")
            self.summary.setText("Everything is up to date.")
            return

        if self._preview_signature(self._preview) != self._preview_signature(plan):
            self._display_plan(plan)
        else:
            self._preview = plan
            self.status.setText("Needs attention" if plan.requires_review else "Changes ready")

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
        key = (str(event.direction), str(event.path))
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

    def _show_transfer(self, state: TransferSnapshot) -> None:
        current = (
            f"File {state.file_number} of {state.planned_files}"
            if state.planned_files and state.file_number <= state.planned_files
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

        if state.data_eta_seconds is not None and not state.verifying:
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
        elif state.planned_bytes is not None and state.planned_bytes > 0:
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

        state = self._overview.update(event, now=timestamp)
        self._show_transfer(state)

    def _finish(self, kind: str, result: object) -> None:
        if kind == "preview" and isinstance(result, _PassiveCheck):
            self._finish_passive_check(result)
            return

        if kind == "sync":
            self._overview = None
            self._transfer_generation += 1

        super()._finish(kind, result)

    def closeEvent(self, event) -> None:
        if hasattr(self, "_passive_check_timer"):
            self._passive_check_timer.stop()
        super().closeEvent(event)
