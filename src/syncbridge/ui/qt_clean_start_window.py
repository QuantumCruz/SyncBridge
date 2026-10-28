
"""Fresh two-person pairing and safe, explicit local setup reset.

Known computers still need two-person consent. Start fresh changes connection
configuration only; actual files, device identity, and recovery records remain.
"""
from __future__ import annotations

import queue
import threading

from PySide6.QtCore import Qt
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QListWidgetItem, QMessageBox, QPushButton

from syncbridge.storage.folder_change_recovery import FolderChangeJournal
from syncbridge.ui.desktop_controller import DesktopPhase
from syncbridge.ui.fresh_start import start_fresh_locally
from syncbridge.ui.qt_crash_recovery_window import SyncBridgeCrashRecoveryWindow
from syncbridge.ui.qt_onboarding import DevicesDialog, QtOnboarding


class ApprovalDevicesDialog(DevicesDialog):
    """Show known devices without implying new approval is optional."""

    def refresh(self) -> None:
        snapshot = tuple(
            (peer, self.bridge.pairing.trusted(peer.node_id))
            for peer in self.bridge.devices()
        )
        if snapshot == self._previous:
            return

        self._previous = snapshot
        previous = self.selected()
        selected_id = previous.node_id if previous is not None else None
        self.listing.clear()

        for peer, known in snapshot:
            label = (
                "Known computer — approval required"
                if known else "New computer — approval required"
            )
            item = QListWidgetItem(f"{peer.name}    ·    {label}")
            item.setData(Qt.ItemDataRole.UserRole, peer.node_id)
            self.listing.addItem(item)
            if selected_id == peer.node_id:
                self.listing.setCurrentItem(item)

        if self.listing.count() == 1 and not selected_id:
            self.listing.setCurrentRow(0)

        self.refresh_buttons()
        self.message.setText(
            f"{len(snapshot)} computer(s) found. "
            "Both people must approve a connection."
        )


class ReapprovingOnboarding(QtOnboarding):
    """Require fresh two-person approval even for a previously trusted peer."""

    def show_devices(self) -> None:
        if self.devices_dialog is None and self.started:
            self.devices_dialog = ApprovalDevicesDialog(self.window, self)
        super().show_devices()

    def select_device(self, peer) -> None:
        self.current_peer = peer
        self._request_pair(peer)

    def _request_pair(self, peer) -> None:
        if self.pairing is None:
            return
        if not self.pairing.trusted(peer.node_id):
            super()._request_pair(peer)
            return
        if self._pair_busy or self.stopping:
            return

        self._pair_busy = True

        def request_again():
            try:
                session = self.pairing.client.request(
                    peer.address,
                    peer.pairing_port,
                    expected_node_id=peer.node_id,
                    approval_timeout=self.pairing.approval_timeout,
                )
                if self.stopping:
                    session.close()
                else:
                    self.events.put(("pair_session", session))
            except Exception as exc:
                self.events.put(("pair_error", str(exc)))

        self._spawn("QtReapproveKnownComputer", request_again)


class SyncBridgeCleanStartWindow(SyncBridgeCrashRecoveryWindow):
    """Connect with fresh approval and safely clear an obsolete local setup."""

    def __init__(self, controller, *, network_options):
        self._fresh_busy = False
        self._fresh_results: queue.SimpleQueue = queue.SimpleQueue()
        super().__init__(controller, network_options=network_options)

        # The parent's network startup runs on the next Qt event-loop turn.
        self.onboarding = ReapprovingOnboarding(
            self, controller, network_options, self._paired, self._folders_ready
        )

    def _make_ui(self) -> None:
        super()._make_ui()
        heading = self.centralWidget().layout().itemAt(0).layout()
        self.fresh_button = QPushButton("Start fresh", self)
        self.fresh_button.setToolTip(
            "Clear saved devices and folder connections on THIS computer. "
            "The contents of synchronized folders are never deleted."
        )
        self.fresh_button.clicked.connect(self._start_fresh)
        heading.insertWidget(4, self.fresh_button)

    def _apply_state(self) -> None:
        super()._apply_state()
        if not hasattr(self, "fresh_button"):
            return

        phase = self.lifecycle.phase
        available = (
            not self._closing
            and not self._busy
            and not self._folder_busy
            and not self._fresh_busy
            and not self._recovery_required
            and not self.controller.running
            and self._live_session is None
            and phase is DesktopPhase.DISCONNECTED
        )
        self.fresh_button.setVisible(
            phase is DesktopPhase.DISCONNECTED and not self._recovery_required
        )
        self.fresh_button.setEnabled(available)

        if self._fresh_busy:
            for button in (
                self.find_button,
                self.reconnect_button,
                self.cancel_button,
                self.change_button,
                self.folder_select_button,
                self.open_folder_button,
                self.preview_button,
                self.sync_button,
                self.disconnect_button,
                self.rename_button,
            ):
                button.setEnabled(False)

        # The base window incorrectly treats SYNCHRONIZING as 'not connected'.
        # Keep the connection banner truthful while an approved live sync runs.
        if (
            phase in (DesktopPhase.CONNECTED, DesktopPhase.SYNCHRONIZING)
            and self._live_session is not None
            and self.controller.running
            and not self._recovery_required
        ):
            self.connection.setText(f"Connected to {self._peer_name()}")
            self.hint.setText(
                "Synchronizing files..."
                if phase is DesktopPhase.SYNCHRONIZING
                else "Preview differences before synchronizing."
            )

    def _start_fresh(self) -> None:
        if (
            self._fresh_busy
            or self._busy
            or self._closing
            or self._folder_busy
            or self._recovery_required
            or self.controller.running
            or self._live_session is not None
            or self.lifecycle.phase is not DesktopPhase.DISCONNECTED
            or self._connect_cancel is not None
        ):
            return

        try:
            if FolderChangeJournal(self.controller.store).load() is not None:
                QMessageBox.warning(
                    self, "Recovery required",
                    "Resolve the interrupted folder change before starting fresh.",
                )
                return
        except Exception as exc:
            QMessageBox.warning(
                self, "Recovery needs attention",
                f"SyncBridge cannot safely reset this setup: {exc}",
            )
            return

        answer = QMessageBox.question(
            self,
            "Start a new connection setup?",
            "Remove previously saved paired devices and folder connections "
            "from THIS SyncBridge installation?\n\n"
            "All files in your folders, your device identity, and recovery "
            "history will be kept. No file will be deleted.\n\n"
            "Ask the other person to choose Start fresh on THEIR computer "
            "too, then use Find computer to connect and approve on both.\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        self._fresh_busy = True
        self._network_started = False
        self.status.setText("Starting fresh...")
        self.summary.setText("Closing old network setup safely...")
        self._apply_state()

        service = self._session_service
        onboarding = self.onboarding

        def reset_worker():
            try:
                if service is not None:
                    service.stop()
                onboarding.stop()
                result = start_fresh_locally(
                    self.controller.store, running=self.controller.running
                )
                self._fresh_results.put((True, result))
            except Exception as exc:
                self._fresh_results.put((False, str(exc)))

        threading.Thread(
            target=reset_worker,
            name="SyncBridgeStartFresh",
            daemon=False,
        ).start()

    def _drain(self) -> None:
        super()._drain()
        try:
            success, outcome = self._fresh_results.get_nowait()
        except queue.Empty:
            return

        self._fresh_busy = False
        if not success:
            self._network_started = False
            self.status.setText("Setup needs attention")
            self.summary.setText(
                "Could not safely start a new setup. No user files were "
                "deleted. Close and reopen SyncBridge before retrying. "
                f"Details: {outcome}"
            )
            self._apply_state()
            return

        self._session_service = None
        self._session_client = None
        self._session_identity = None
        self._live_session = None
        self._pending_session_id = None
        self._connect_cancel = None
        self._connect_deadline = None
        self._connect_stage = None
        self._fresh_folder_consent = False
        self._initiated_folder_setup = False
        self._folder_busy = False
        self._folder_role = None
        self._folder_sid = None
        self._folder_original = None
        self._clear_preview()

        options = self.onboarding.options
        self.onboarding = ReapprovingOnboarding(
            self, self.controller, options, self._paired, self._folders_ready
        )
        self._network_started = False
        self._start_network()

        if self._network_started:
            self.summary.setText(
                "Clean setup ready. Ask the other person to select "
                "Start fresh too. Then click Find computer; both people "
                "will receive approval prompts and choose their folders."
            )
        self._apply_state()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._fresh_busy:
            event.ignore()
            self.summary.setText(
                "Finishing the safe setup reset before closing..."
            )
            return
        super().closeEvent(event)
