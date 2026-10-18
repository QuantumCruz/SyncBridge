
"""Safe, user-initiated folder changes for the SyncBridge Qt desktop.

Changing folders is not the same as disconnecting: the guarded runtime must
stop before its local share is forgotten. Pairing credentials and file contents
are never modified by this workflow. Each computer must consent separately.
"""
from __future__ import annotations

from PySide6.QtWidgets import QMessageBox

from syncbridge.ui.connection_switch import forget_local_folder_connection
from syncbridge.ui.qt_progress_window import SyncBridgeProgressWindow


class SyncBridgeFolderWindow(SyncBridgeProgressWindow):
    """The release desktop with an explicit, fail-closed Change folders action."""

    def __init__(self, *args, **kwargs) -> None:
        self._changing_folders = False
        self._folder_approval_guard_installed = False
        super().__init__(*args, **kwargs)
        self._update_buttons()

    def _update_buttons(self) -> None:
        super()._update_buttons()
        if not hasattr(self, "folder_select_button"):
            return

        if self._configured:
            self.folder_select_button.setText("Change folders")
            self.folder_select_button.setToolTip(
                "Stop this folder connection safely and choose new folders "
                "without losing files or device pairing."
            )
            onboarding_busy = bool(
                self.onboarding
                and (self.onboarding._pair_busy or self.onboarding._folder_busy)
            )
            self.folder_select_button.setEnabled(
                not self._busy
                and not self._changing_folders
                and not self._closing
                and not self._shutting_down
                and not onboarding_busy
            )
        else:
            self.folder_select_button.setText("Choose my folder")
            if self._changing_folders:
                self.folder_select_button.setEnabled(False)

    def _start_network(self) -> None:
        super()._start_network()
        if (
            not self.onboarding
            or not self.onboarding.started
            or self.onboarding.folders is None
            or self._folder_approval_guard_installed
        ):
            return

        # The headless setup layer supports multiple shares, but this GUI owns
        # exactly one. Reject an incoming second relationship until its owner
        # explicitly chooses Change folders on this machine too.
        folders = self.onboarding.folders
        approve_original = folders.approve

        def approve_single_share(request_id: str, folder: str) -> None:
            self._approve_new_folder(approve_original, request_id, folder)

        folders.approve = approve_single_share
        self._folder_approval_guard_installed = True

    def _approve_new_folder(self, approve, request_id: str, folder: str) -> None:
        """Require local consent to end the previous share before any new one."""
        if (
            self._changing_folders
            or self.controller.store.load().shares
            or (
                self.onboarding is not None
                and self.onboarding._folder_busy
            )
        ):
            raise RuntimeError(
                "This computer already has a folder connection or is changing "
                "one. Select Change folders here first, then ask the other "
                "person to send a fresh folder request."
            )
        approve(request_id, folder)

    def _choose_folder(self) -> None:
        if not self._configured:
            if self.controller.store.load().shares:
                QMessageBox.information(
                    self,
                    "Folder setup is unfinished",
                    "A folder relationship is already saved, but is not ready. "
                    "Finish or resolve that connection before choosing another."
                )
                return
            if (
                self.onboarding is not None
                and self.onboarding.folders is not None
                and self.onboarding.folders.pending()
            ):
                QMessageBox.information(
                    self,
                    "Folder request waiting",
                    "Your friend has already requested a folder connection. "
                    "Approve or decline that request first."
                )
                return
            super()._choose_folder()
            return

        if (
            self._busy
            or self._changing_folders
            or self._closing
            or self._shutting_down
            or (
                self.onboarding
                and (self.onboarding._pair_busy or self.onboarding._folder_busy)
            )
        ):
            return

        saved = self.controller.store.load().shares
        if len(saved) != 1:
            QMessageBox.warning(
                self,
                "Cannot change folders",
                "This profile has an unexpected number of folder connections. "
                "SyncBridge will not change them automatically.",
            )
            return

        share = saved[0]
        answer = QMessageBox.question(
            self,
            "Change folders?",
            "Stop synchronizing the current folders and set up a new pair?\n\n"
            "Your existing files stay exactly where they are. Device pairing "
            "is preserved.\n\n"
            "The other person must also choose Change folders on their "
            "computer before either person selects the replacement folders.\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        self._changing_folders = True
        self._preview = None
        self._work(
            "stop",
            lambda: self._stop_and_forget(share.share_id),
        )

    def _stop_and_forget(self, share_id: str) -> tuple[bool, str]:
        """Worker-only; never alter Qt widgets or user files here."""
        try:
            self.controller.stop()
            if self.controller.running:
                raise RuntimeError("The previous synchronization has not stopped")
            forget_local_folder_connection(
                self.controller.store,
                expected_share_id=share_id,
                running=self.controller.running,
            )
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"
        return True, ""

    def _finish(self, kind: str, result: object) -> None:
        if kind != "stop" or not self._changing_folders:
            super()._finish(kind, result)
            return

        success, error = result
        self._changing_folders = False
        self._preview = None
        self._loaded.clear()
        self.table.setRowCount(0)
        self.local_table.setRowCount(0)
        self.remote_table.setRowCount(0)
        self.progress.setText("")

        if not success:
            # If stop succeeded but the config write failed, remain disconnected.
            # Do not claim that it is safe to sync the old folder.
            if not self.controller.running:
                self._paused = True
            self._load_profile()
            self.status.setText("Folder change needs attention")
            self.summary.setText(
                "The old connection was not replaced. No files were deleted. "
                "Check the error before trying again."
            )
            QMessageBox.warning(self, "Could not change folders", error)
            return

        self._paused = False
        self._configured = False
        self._load_profile()
        self.status.setText("Choose new folders")
        self.summary.setText(
            "Previous files are untouched and the computers remain paired. "
            "Ask your friend to select Change folders too. Once both are ready, "
            "choose your new folder to send a fresh request."
        )
        self._update_buttons()
