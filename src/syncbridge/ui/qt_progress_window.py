
"""Qt desktop progress reporting with user-priority change detection.

Manual previews take priority over passive checks. Background checks are
read-only, less frequent, and never replace an actionable completed plan.
Slow previews display elapsed time instead of appearing frozen.

Unattended file writes remain disabled.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from PySide6.QtCore import QTimer, Signal, Slot

from syncbridge.ui.desktop_controller import DesktopPreview
from syncbridge.ui.qt_window import SyncBridgeQtWindow
from syncbridge.ui.transfer_overview import (
    TransferOverview,
    TransferSnapshot,
)


@dataclass(frozen=True, slots=True)
class _PassiveCheck:
    """A passive preview outcome; errors do not open modal dialogs."""

    preview: DesktopPreview | None = None
    error: str | None = None


class SyncBridgeProgressWindow(SyncBridgeQtWindow):
    transfer_update = Signal(int, object, float)

    PASSIVE_INTERVAL_MS = 90_000
    PREVIEW_PROGRESS_INTERVAL_MS = 1_000

    def __init__(self, *args, **kwargs) -> None:
        self._overview: TransferOverview | None = None
        self._transfer_generation = 0
        self._last_emitted_at = 0.0
        self._last_emitted_key: tuple[str, str] | None = None

        self._passive_working = False
        self._manual_preview_running = False
        self._manual_preview_queued = False
        self._preview_started_at: float | None = None

        super().__init__(*args, **kwargs)

        self.transfer_update.connect(
            self._display_transfer_update
        )

        # Expensive folder comparisons should not repeat every 15 seconds.
        # This is a GUI timer, not a second synchronization worker.
        self._passive_check_timer = QTimer(self)
        self._passive_check_timer.setInterval(
            self.PASSIVE_INTERVAL_MS
        )
        self._passive_check_timer.timeout.connect(
            self._check_in_background
        )
        self._passive_check_timer.start()

        self._preview_progress_timer = QTimer(self)
        self._preview_progress_timer.setInterval(
            self.PREVIEW_PROGRESS_INTERVAL_MS
        )
        self._preview_progress_timer.timeout.connect(
            self._report_preview_progress
        )
        self._preview_progress_timer.start()

    def _update_buttons(self) -> None:
        super()._update_buttons()

        # Allow a user to request a manual preview even if a passive
        # preview is already running. The existing worker will finish
        # first, after which the manual request will be processed.
        if (
            self._passive_working
            and not self._manual_preview_queued
            and not self._closing
            and not self._shutting_down
            and not self._paused
            and self.controller.running
            and not (
                self.onboarding
                and (
                    self.onboarding._pair_busy
                    or self.onboarding._folder_busy
                )
            )
        ):
            self.preview_button.setEnabled(True)

    def _check_changes(self) -> None:
        """Give manual Preview priority without overlapping workers."""
        if self._closing or self._shutting_down or self._paused:
            return

        if not self.controller.running:
            return

        if self._busy:
            if self._passive_working:
                self._manual_preview_queued = True
                self.summary.setText(
                    "Finishing the current check. "
                    "Your requested preview will run next."
                )
                self._update_buttons()
            return

        self._manual_preview_queued = False
        self._manual_preview_running = True
        self._preview_started_at = time.monotonic()

        # A previous result is no longer current once the user explicitly
        # requests a new preview. The guarded backend will recheck again
        # before any actual synchronization.
        self.table.setRowCount(0)

        super()._check_changes()

    def _check_in_background(self) -> None:
        """Run an idle read-only check without hiding pending changes."""
        if (
            self._closing
            or self._shutting_down
            or self._paused
            or self._busy
            or self._passive_working
            or self._manual_preview_running
            or self._manual_preview_queued
            or not self.controller.running
        ):
            return

        if self.onboarding and (
            self.onboarding._pair_busy
            or self.onboarding._folder_busy
        ):
            return

        # Once differences need attention, leave them alone. Do not
        # continually disable Sync or replace the visible result.
        # The user can always request a fresh manual preview.
        if self._preview is not None and self._preview.items:
            return

        self._passive_working = True
        self._preview_started_at = time.monotonic()

        self._work("preview", self._read_only_check)

    def _read_only_check(self) -> _PassiveCheck:
        try:
            return _PassiveCheck(
                preview=self.controller.preview()
            )
        except Exception as exc:
            return _PassiveCheck(
                error=f"{type(exc).__name__}: {exc}"
            )

    def _report_preview_progress(self) -> None:
        """Show truthful elapsed time for long-running preview work."""
        if (
            self._closing
            or not self._busy
            or self._preview_started_at is None
            or not (
                self._passive_working
                or self._manual_preview_running
            )
        ):
            return

        elapsed = max(
            0,
            int(time.monotonic() - self._preview_started_at),
        )

        if elapsed < 4:
            return

        if self._manual_preview_queued:
            message = (
                "The current check is still running "
                f"({elapsed}s). Your manual preview is next."
            )
        elif elapsed >= 60:
            message = (
                "Still checking folders "
                f"({elapsed}s). Large files or a slow connection "
                "may take longer. No files are being changed."
            )
        else:
            message = (
                f"Checking folder differences... {elapsed}s elapsed. "
                "You can leave SyncBridge open while this finishes."
            )

        self.summary.setText(message)

    @staticmethod
    def _preview_signature(
        preview: DesktopPreview | None,
    ):
        if preview is None:
            return None

        return (
            preview.revision,
            preview.requires_review,
            tuple(
                (
                    item.path,
                    item.action,
                    item.needs_review,
                    item.size,
                )
                for item in preview.items
            ),
        )

    def _finish_passive_check(
        self,
        result: _PassiveCheck,
    ) -> None:
        if result.error is not None:
            self._preview = None
            self.table.setRowCount(0)
            self.status.setText("Waiting for other computer")
            self.summary.setText(
                "Could not finish checking folder differences. "
                f"{result.error[:400]} "
                "SyncBridge will try again automatically."
            )
            return

        plan = result.preview

        if plan is None:
            self._preview = None
            self.table.setRowCount(0)
            self.status.setText("Waiting for other computer")
            self.summary.setText(
                "The folder comparison did not return a result. "
                "SyncBridge will try again."
            )
            return

        if not plan.items:
            self._preview = plan
            self.table.setRowCount(0)
            self.status.setText("Connected")
            self.summary.setText("Everything is up to date.")
            return

        # A completed actionable result is displayed once and remains
        # visible until the user explicitly previews or synchronizes.
        self._display_plan(plan)

    def _sync_files(self) -> None:
        plan = self._preview

        if (
            self._busy
            or plan is None
            or plan.requires_review
            or not plan.items
        ):
            return

        # This is a UI estimate only. The backend independently
        # validates and replans before making filesystem changes.
        self._overview = TransferOverview(plan.items)
        self._transfer_generation += 1
        self._last_emitted_at = 0.0
        self._last_emitted_key = None

        super()._sync_files()

        # The user declined the confirmation dialog.
        if not self._busy:
            self._overview = None

    def _on_progress(self, event: object) -> None:
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

    def _finish(self, kind: str, result: object) -> None:
        if (
            kind == "preview"
            and isinstance(result, _PassiveCheck)
        ):
            self._passive_working = False
            self._preview_started_at = None

            if self._manual_preview_queued:
                # Ignore the automatic result and process the user's
                # explicit request using the existing single worker.
                self._manual_preview_queued = False
                self._check_changes()
                return

            self._finish_passive_check(result)
            return

        if kind == "preview":
            self._manual_preview_running = False
            self._preview_started_at = None

        if kind == "sync":
            self._overview = None
            self._transfer_generation += 1

        super()._finish(kind, result)

    def _drain(self) -> None:
        super()._drain()

        # Base window error handling consumes errors independently of
        # _finish(). Reset progress tracking if a manual preview fails.
        if (
            self._manual_preview_running
            and not self._busy
        ):
            self._manual_preview_running = False
            self._preview_started_at = None

    def closeEvent(self, event) -> None:
        if hasattr(self, "_passive_check_timer"):
            self._passive_check_timer.stop()

        if hasattr(self, "_preview_progress_timer"):
            self._preview_progress_timer.stop()

        super().closeEvent(event)
