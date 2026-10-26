
"""Fail-closed restart recovery for coordinated Qt folder replacement.

Save a durable checkpoint before the old runtime stops. Never start network
services on a profile with unresolved recovery. A new approved share must
pass recovery validation BEFORE the desktop is allowed to become Connected.

No recovery command changes the peer's configuration or user file contents.
"""
from __future__ import annotations

import threading

from PySide6.QtWidgets import QMessageBox, QPushButton

from syncbridge.storage.folder_change_recovery import FolderChangeJournal
from syncbridge.ui.desktop_controller import DesktopPhase
from syncbridge.ui.qt_release_window import SyncBridgeReleaseWindow


class SyncBridgeCrashRecoveryWindow(SyncBridgeReleaseWindow):
    """Block network access when a coordinated folder change was interrupted."""

    def __init__(self, controller, *, network_options):
        self._change_journal = FolderChangeJournal(controller.store)
        self._recovery_required = False
        self._recovery_fault = ""
        super().__init__(controller, network_options=network_options)

    def _make_ui(self) -> None:
        super()._make_ui()
        heading = self.centralWidget().layout().itemAt(0).layout()
        self.restore_button = QPushButton("Restore previous connection", self)
        self.restore_button.clicked.connect(self._restore_previous)
        heading.insertWidget(3, self.restore_button)
        self.restore_button.hide()

    def _apply_state(self) -> None:
        super()._apply_state()
        if not hasattr(self, "restore_button"):
            return

        self.restore_button.setVisible(self._recovery_required)
        self.restore_button.setEnabled(
            self._recovery_required
            and not self._closing
            and not self._busy
            and not self.controller.running
            and not self._network_started
            and not self._recovery_fault
        )
        if self._recovery_required:
            for button in (
                self.find_button,
                self.reconnect_button,
                self.folder_select_button,
                self.open_folder_button,
                self.preview_button,
                self.sync_button,
                self.disconnect_button,
                self.rename_button,
            ):
                button.setEnabled(False)
            self.folder_select_button.hide()

    def _start_network(self) -> None:
        """Unresolved recovery prevents all discovery and pairing listeners."""
        if self._closing:
            return
        try:
            checkpoint = self._change_journal.load()
        except Exception as exc:
            self._recovery_required = True
            self._recovery_fault = str(exc)
            self.status.setText("Recovery needs attention")
            self.summary.setText(
                "The interrupted folder-change record cannot be verified. "
                "No network services were started. Preserve this profile "
                f"and its files. Details: {exc}"
            )
            self._apply_state()
            return

        if checkpoint is not None:
            self._recovery_required = True
            current = self.controller.store.load().shares
            new_share = (
                len(current) == 1
                and current[0].enabled
                and current[0].share_id != checkpoint.original.share_id
                and current[0].peer_node_id == checkpoint.original.peer_node_id
            )
            self.restore_button.setText(
                "Keep new folder connection"
                if new_share else "Restore previous connection"
            )
            self.status.setText("Folder recovery needed")
            self.summary.setText(
                "A folder change was interrupted. SyncBridge has not "
                "connected or synchronized. Both people must agree which "
                "folder relationship to keep before reconnecting. "
                "Neither computer's files were deleted by this screen."
            )
            self._apply_state()
            return

        super()._start_network()

    def _ensure_session_service(self) -> None:
        if not self._recovery_required:
            super()._ensure_session_service()

    def _restore_previous(self) -> None:
        if (
            not self._recovery_required
            or self._recovery_fault
            or self._network_started
            or self.controller.running
            or self._busy
            or self._closing
        ):
            return

        try:
            checkpoint = self._change_journal.load()
            if checkpoint is None:
                return
            shares = self.controller.store.load().shares
            keeping_new = (
                len(shares) == 1
                and shares[0].enabled
                and shares[0].share_id != checkpoint.original.share_id
                and shares[0].peer_node_id == checkpoint.original.peer_node_id
            )
        except Exception as exc:
            QMessageBox.warning(self, "Recovery needs attention", str(exc))
            return

        if keeping_new:
            title = "Keep the replacement folder?"
            explanation = (
                "Keep the NEW folder already approved on this laptop?\n\n"
                "The other laptop must have the SAME newly approved "
                "folder relationship. A new two-person connection will "
                "still be required. No files are moved or deleted.\n\n"
                "Do not continue unless both people have agreed."
            )
        else:
            title = "Restore previous folder connection?"
            explanation = (
                "Restore this laptop's previous folder selection?\n\n"
                "Ask the other person to restore the previous relationship "
                "on THEIR laptop too. Both must then restart and reconnect.\n\n"
                "This does not change or delete files."
            )

        answer = QMessageBox.question(
            self, title, explanation,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        try:
            if keeping_new:
                selected = self._change_journal.keep_replacement(
                    running=self.controller.running
                )
            else:
                selected = self._change_journal.restore_previous(
                    running=self.controller.running
                )
        except Exception as exc:
            self.status.setText("Recovery needs attention")
            QMessageBox.warning(
                self, "Could not resolve previous folders", str(exc)
            )
            return

        self.restore_button.setEnabled(False)
        self.status.setText("Folder selection recovered")
        self.summary.setText(
            f"This laptop's selected folder ({selected.display_name}) is saved. "
            "No connection has started. Confirm the other laptop has the "
            "matching relationship, then restart SyncBridge on both."
        )

    def _checkpoint_before_stopping(self, sid: str, role: str) -> bool:
        if (
            self._folder_role != role
            or self._folder_sid != sid
            or self.lifecycle.phase is not DesktopPhase.CONNECTED
            or not self.controller.running
            or self._folder_original is None
        ):
            return False

        try:
            self._change_journal.begin(sid, self._folder_original)
            return True
        except Exception as exc:
            self.summary.setText(
                "Cannot start the folder change safely. "
                f"Your existing folders are unchanged: {exc}"
            )
            if role == "receiver" and self._session_service is not None:
                self._session_service.reject_folder_change(sid)
            elif role == "initiator":
                client = self._session_client
                try:
                    target = self._target()
                except Exception:
                    target = None
                if client is not None and target is not None:
                    threading.Thread(
                        target=self._cancel_pending_change,
                        args=(client, target, sid),
                        name="SyncBridgeCancelUncheckpointedChange",
                        daemon=True,
                    ).start()

            self._folder_busy = False
            self._folder_role = None
            self._folder_sid = None
            self._folder_original = None
            self._apply_state()
            return False

    @staticmethod
    def _cancel_pending_change(client, target, sid) -> None:
        try:
            client.request(*target, sid, "folder_change_cancel")
        except Exception:
            pass

    def _prepare_receiver(self, sid: str) -> None:
        if self._checkpoint_before_stopping(sid, "receiver"):
            super()._prepare_receiver(sid)

    def _prepare_initiator(self, sid: str) -> None:
        if self._checkpoint_before_stopping(sid, "initiator"):
            super()._prepare_initiator(sid)

    def _replace_saved_folder(self, sid: str) -> None:
        try:
            self._change_journal.mark_committing(sid)
        except Exception as exc:
            self._end_folder_change(
                "Cannot safely finish the folder change. Existing files "
                f"were not deleted. Restart to recover: {exc}",
                replaced=False,
            )
            return
        super()._replace_saved_folder(sid)

    def _end_folder_change(self, message: str, *, replaced: bool) -> None:
        if not replaced:
            try:
                pending = self._change_journal.load() is not None
            except Exception:
                pending = True
            if pending:
                self._recovery_required = True

        super()._end_folder_change(message, replaced=replaced)

        if self._recovery_required and not replaced:
            # An interrupted checkpoint is never treated as a successful
            # return to ordinary Connected or allowed to continue syncing.
            if (
                not self._closing
                and self.controller.running
                and self.lifecycle.phase is DesktopPhase.CONNECTED
                and not self._busy
            ):
                self._begin_disconnect(notify_peer=True)

            self.summary.setText(
                "The folder change was interrupted. Close SyncBridge "
                "and reopen it on both computers to resolve the saved "
                "folder relationship. No user files were deleted. " + message
            )
            self._apply_state()

    def _connected(self, sid: str) -> None:
        """Validate the checkpoint before enabling previews or synchronization."""
        try:
            checkpoint = self._change_journal.load()
            if checkpoint is not None:
                share = self._saved_share()
                if share is None:
                    raise RuntimeError("No approved replacement folder is configured")
                self._change_journal.finish_if_connected(share)
        except Exception as exc:
            self._recovery_required = True
            self._recovery_fault = str(exc)
            self._after_disconnect_message = (
                "The new connection could not safely complete folder recovery. "
                "No synchronization is permitted. Restart SyncBridge to "
                f"resolve the folder selection. Details: {exc}"
            )
            self._finish_connect_attempt()
            if self._session_service is not None:
                self._session_service.clear(sid)
            self._move(DesktopPhase.DISCONNECTING)
            self._run(
                "disconnect",
                lambda: self._end_session(None, False),
            )
            self._apply_state()
            return

        super()._connected(sid)
