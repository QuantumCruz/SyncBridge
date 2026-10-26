
"""Friendly device names and two-person, fail-closed folder changes.

Folder replacement is offered only while a mutually approved live connection
exists. Both users consent before either original share is replaced. All
filesystem data, identity keys, and trust records remain untouched.
"""
from __future__ import annotations

import queue
import threading
import time
from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QInputDialog, QLabel, QMessageBox, QPushButton

from syncbridge.network.folder_change_session import (
    FolderChangeSessionClient, FolderChangeSessionService,
)
from syncbridge.network.session_control import session_port_for_transfer
from syncbridge.ui.connection_switch import forget_local_folder_connection
from syncbridge.ui.desktop_controller import DesktopPhase
from syncbridge.ui.device_names import change_device_name
from syncbridge.ui.nearby_devices import NearbyDevice
from syncbridge.ui.qt_mutual_session_window import SyncBridgeMutualSessionWindow


class SyncBridgeReleaseWindow(SyncBridgeMutualSessionWindow):
    """Restore folder changes without bypassing mutual session approval."""

    CHANGE_APPROVAL_SECONDS = 60.0
    CHANGE_PREPARE_SECONDS = 25.0

    def __init__(self, *args, **kwargs) -> None:
        self._folder_events: queue.SimpleQueue = queue.SimpleQueue()
        self._folder_busy = False
        self._folder_role: str | None = None
        self._folder_sid: str | None = None
        self._folder_original = None
        self._folder_peer_name = "the other computer"
        self._folder_cancel_after_stop = False
        self._folder_receiver_ready = False
        super().__init__(*args, **kwargs)

    def _make_ui(self) -> None:
        super()._make_ui()
        heading = self.centralWidget().layout().itemAt(0).layout()
        self.my_name_label = QLabel(self)
        self.rename_button = QPushButton("Rename my computer", self)
        self.rename_button.clicked.connect(self._rename_my_computer)
        heading.insertWidget(1, self.my_name_label)
        heading.insertWidget(2, self.rename_button)
        self.folder_select_button.setToolTip(
            "Both people must approve changing the connected folders. "
            "Files and saved pairing are preserved."
        )

    def _ensure_session_service(self) -> None:
        """Use the same authenticated port with folder-change consent added."""
        share = self._saved_share()
        if share is None or not self.onboarding.started:
            return
        local_ports = self.controller.runtime.listen_ports
        transfer_port = local_ports[1] if local_ports else share.transfer_port
        signature = (share.share_id, share.peer_node_id, transfer_port)
        if signature == self._session_identity and self._session_service is not None:
            return
        if self._session_service is not None:
            self._session_service.stop()
            self._session_service = None
        pairing = self.onboarding.pairing
        if pairing is None:
            raise RuntimeError("Pairing service is unavailable")

        def on_event(kind, sid):
            if kind.startswith("folder-change-"):
                self._folder_events.put(("network", (kind, sid)))
            else:
                self._events.put(("session", (kind, sid)))

        service = FolderChangeSessionService(
            pairing.identity, pairing.trust, share.share_id, share.peer_node_id,
            bind_address=self.onboarding.options.pairing_bind,
            port=session_port_for_transfer(transfer_port),
            on_event=on_event,
        )
        service.start()
        self._session_service = service
        self._session_client = FolderChangeSessionClient(
            pairing.identity, pairing.trust
        )
        self._session_identity = signature

    def _apply_state(self) -> None:
        super()._apply_state()
        if not hasattr(self, "my_name_label"):
            return
        phase = self.lifecycle.phase
        idle = (
            self._network_started and not self._busy
            and not self._closing and not self._folder_busy
        )
        override = self.onboarding.options.name
        name = override or self.controller.store.load().device_name
        self.my_name_label.setText(f"This computer: {name}")
        self.rename_button.setEnabled(
            idle and override is None
            and phase in (DesktopPhase.DISCONNECTED, DesktopPhase.CONNECTED)
        )
        if override is not None:
            self.rename_button.setToolTip(
                "The --discovery-name option controls this test session."
            )

        # A saved connection alone is NOT permission to replace folders.
        # Only a live session qualifies.
        connected = (
            phase is DesktopPhase.CONNECTED
            and self._live_session is not None
            and self.controller.running
            and self._saved_share() is not None
        )
        if connected:
            self.folder_select_button.setText("Change folders")
            self.folder_select_button.setVisible(True)
            self.folder_select_button.setEnabled(idle)
        elif phase is DesktopPhase.CHOOSING_FOLDER:
            self.folder_select_button.setText("Choose my folder")
            self.folder_select_button.setVisible(True)
            self.folder_select_button.setEnabled(
                idle and not self.controller.store.load().shares
            )
        else:
            self.folder_select_button.setVisible(False)
            self.folder_select_button.setEnabled(False)

        if phase is DesktopPhase.DISCONNECTED and self._saved_share():
            self.open_folder_button.setEnabled(idle)

        if self._folder_busy:
            for button in (
                self.find_button, self.reconnect_button, self.folder_select_button,
                self.open_folder_button, self.preview_button, self.sync_button,
                self.disconnect_button,
            ):
                button.setEnabled(False)

    def _rename_my_computer(self) -> None:
        if (self._busy or self._closing or self._folder_busy
                or self.lifecycle.phase not in (
                    DesktopPhase.DISCONNECTED, DesktopPhase.CONNECTED
                )):
            return
        if self.onboarding.options.name is not None:
            return
        current = self.controller.store.load().device_name
        requested, accepted = QInputDialog.getText(
            self, "Computer name",
            "How should other people recognize this laptop?", text=current,
        )
        if not accepted:
            return
        try:
            name = change_device_name(self.controller.store, requested)
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Cannot rename computer", str(exc))
            return
        if self.onboarding.presence is not None:
            directory = self.onboarding.presence.directory
            directory.discovery.name = name
            if directory.running:
                try:
                    directory.refresh()
                except OSError:
                    pass
        if self.onboarding.pairing is not None:
            self.onboarding.pairing.client.name = name
            self.onboarding.pairing.service.name = name
        self._apply_state()
        self.summary.setText(f"This computer is now named '{name}'.")

    def _open_folder(self) -> None:
        if (self._busy or self._closing or self._folder_busy
                or self.lifecycle.phase not in (
                    DesktopPhase.CONNECTED, DesktopPhase.DISCONNECTED
                )):
            return
        share = self._saved_share()
        if share is None:
            return
        folder = Path(share.local_root)
        if not folder.is_dir():
            QMessageBox.warning(
                self, "Folder unavailable",
                "The saved folder is missing. Your settings were not changed.",
            )
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))

    def _choose_folder(self) -> None:
        if self.lifecycle.phase is DesktopPhase.CHOOSING_FOLDER:
            super()._choose_folder()
        elif self.lifecycle.phase is DesktopPhase.CONNECTED:
            self._request_folder_change()

    def _request_folder_change(self) -> None:
        if (self._busy or self._closing or self._folder_busy
                or self.lifecycle.phase is not DesktopPhase.CONNECTED
                or not self.controller.running or self._live_session is None):
            return
        settings = self.controller.store.load()
        if len(settings.shares) != 1 or self._saved_share() is None:
            return
        if self._session_client is None or self._session_service is None:
            return
        sid = self._live_session
        if self._session_service.active_session != sid:
            return
        answer = QMessageBox.question(
            self, "Change connected folders?",
            f"Ask {self._peer_name()} to replace the folders you synchronize?\n\n"
            "They must approve on their own laptop before anything changes. "
            "Both existing folders and their files will remain untouched.\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._folder_busy = True
        self._folder_role = "initiator"
        self._folder_sid = sid
        self._folder_original = settings.shares[0]
        self._folder_peer_name = self._peer_name()
        self.summary.setText(f"Asking {self._peer_name()} to approve changing folders...")
        self._apply_state()
        target = self._target()
        client = self._session_client

        def worker():
            prepared = False
            try:
                state = client.request(*target, sid, "folder_change_invite")
                if state != "waiting":
                    raise RuntimeError("The other computer is not ready for a folder change")
                deadline = time.monotonic() + self.CHANGE_APPROVAL_SECONDS
                while time.monotonic() < deadline:
                    state = client.request(*target, sid, "folder_change_status")
                    if state == "approved":
                        break
                    if state != "waiting":
                        raise RuntimeError("The other person declined or left the session")
                    time.sleep(0.25)
                else:
                    raise RuntimeError("The other person did not approve in time")
                state = client.request(*target, sid, "folder_change_prepare")
                if state != "preparing":
                    raise RuntimeError("The other computer could not prepare the change")
                prepared = True
                deadline = time.monotonic() + self.CHANGE_PREPARE_SECONDS
                while time.monotonic() < deadline:
                    state = client.request(*target, sid, "folder_change_status")
                    if state == "ready":
                        self._folder_events.put(("initiator-ready", sid))
                        return
                    if state not in ("preparing", "approved"):
                        raise RuntimeError("The other computer cancelled the folder change")
                    time.sleep(0.25)
                raise RuntimeError("The other computer did not finish preparing")
            except Exception as exc:
                try:
                    client.request(*target, sid, "folder_change_cancel")
                except Exception:
                    pass
                self._folder_events.put(("failed", (sid, str(exc), prepared)))

        threading.Thread(
            target=worker, name="SyncBridgeFolderChangeRequest", daemon=True
        ).start()

    def _incoming_folder_change(self, sid: str) -> None:
        service = self._session_service
        if not isinstance(service, FolderChangeSessionService):
            return
        if (self._closing or self._folder_busy or self._busy
                or self.lifecycle.phase is not DesktopPhase.CONNECTED
                or not self.controller.running
                or sid != self._live_session
                or sid != service.active_session):
            service.reject_folder_change(sid)
            return
        answer = QMessageBox.question(
            self, "Folder change request",
            f"{self._peer_name()} wants to change the synchronized folders.\n\n"
            "Allow both computers to stop the current synchronization and "
            "choose replacement folders?\n\n"
            "Existing files and saved device pairing will not be deleted.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            service.reject_folder_change(sid)
            self.summary.setText("Folder change declined. Your current folder is unchanged.")
            return
        if not service.approve_folder_change(sid):
            self.summary.setText("The folder change request expired. Nothing changed.")
            return
        self._folder_busy = True
        self._folder_role = "receiver"
        self._folder_sid = sid
        self._folder_original = self._saved_share()
        self._folder_peer_name = self._peer_name()
        self.summary.setText("Folder change approved. Waiting for both laptops to prepare...")
        self._apply_state()

    def _prepare_receiver(self, sid: str) -> None:
        if (self._folder_role != "receiver" or self._folder_sid != sid
                or self.lifecycle.phase is not DesktopPhase.CONNECTED):
            service = self._session_service
            if isinstance(service, FolderChangeSessionService):
                service.reject_folder_change(sid)
            return
        self._busy = True
        self._live_session = None
        self._move(DesktopPhase.CHANGING_FOLDERS)
        self.summary.setText("Safely stopping synchronization on this laptop...")
        self._apply_state()

        def worker():
            try:
                self.controller.stop()
                if self.controller.running:
                    raise RuntimeError("Synchronization is still running")
                self._folder_events.put(("receiver-stopped", (sid, None)))
            except Exception as exc:
                self._folder_events.put(("receiver-stopped", (sid, str(exc))))

        threading.Thread(
            target=worker, name="SyncBridgeFolderChangeReceiver", daemon=True
        ).start()

    def _prepare_initiator(self, sid: str) -> None:
        if (self._folder_role != "initiator" or self._folder_sid != sid
                or self.lifecycle.phase is not DesktopPhase.CONNECTED):
            return
        target = self._target()
        client = self._session_client
        self._busy = True
        self._live_session = None
        self._move(DesktopPhase.CHANGING_FOLDERS)
        self.summary.setText("Both approved. Finishing the secure folder change...")
        self._apply_state()

        def worker():
            try:
                self.controller.stop()
                if self.controller.running:
                    raise RuntimeError("Synchronization is still running")
                response = client.request(*target, sid, "folder_change_commit")
                if response != "committed":
                    raise RuntimeError("The other laptop could not confirm the change")
                self._folder_events.put(("commit", (sid, None)))
            except Exception as exc:
                try:
                    client.request(*target, sid, "folder_change_cancel")
                except Exception:
                    pass
                self._folder_events.put(("commit", (sid, str(exc))))

        threading.Thread(
            target=worker, name="SyncBridgeFolderChangeCommit", daemon=True
        ).start()

    def _replace_saved_folder(self, sid: str) -> None:
        share = self._folder_original
        service = self._session_service

        def worker():
            try:
                if share is None or sid != self._folder_sid:
                    raise RuntimeError("The original folder relationship changed")
                if self.controller.running:
                    raise RuntimeError("Cannot change folders while synchronization runs")
                if service is not None:
                    service.stop()
                if self.onboarding.folders is not None:
                    self.onboarding.folders.stop()
                forget_local_folder_connection(
                    self.controller.store, expected_share_id=share.share_id,
                    running=self.controller.running,
                )
                self.onboarding.folders.start()
                self._folder_events.put(("replaced", (sid, None)))
            except Exception as exc:
                self._folder_events.put(("replaced", (sid, str(exc))))

        threading.Thread(
            target=worker, name="SyncBridgeFolderChangeFinish", daemon=True
        ).start()

    def _end_folder_change(self, message: str, *, replaced: bool) -> None:
        share = self._folder_original
        if replaced and share is not None:
            # Discovery may expire during the transition, especially over a
            # virtual LAN. Keep the authenticated peer identity for setup.
            self.onboarding.current_peer = NearbyDevice(
                share.peer_node_id, self._folder_peer_name, share.remote_host,
                self.onboarding.options.discovery_port,
                self.onboarding.options.pairing_port,
            )
        self._folder_busy = False
        self._folder_role = None
        self._folder_sid = None
        self._folder_original = None
        self._folder_peer_name = "the other computer"
        self._folder_cancel_after_stop = False
        self._folder_receiver_ready = False
        self._busy = False
        self._session_service = None if replaced else self._session_service
        self._session_client = None if replaced else self._session_client
        self._session_identity = None if replaced else self._session_identity
        self._clear_preview()
        if self.lifecycle.phase is DesktopPhase.CHANGING_FOLDERS:
            if not replaced and self._session_service is not None:
                self._session_service.clear()
            if replaced:
                self._move(DesktopPhase.CHOOSING_FOLDER)
            else:
                self._move(DesktopPhase.DISCONNECTING)
                self._move(DesktopPhase.DISCONNECTED)
        if not replaced and not self._closing and self.lifecycle.phase is DesktopPhase.DISCONNECTED:
            # A failed commit may have stopped the authenticated listener.
            # Keep the saved share, but restore ordinary reconnect support.
            if self._session_service is not None:
                try:
                    self._session_service.stop()
                except Exception:
                    pass
            self._session_service = None
            self._session_client = None
            self._session_identity = None
            try:
                self._ensure_session_service()
            except Exception as exc:
                message += f" Reconnection needs attention: {exc}"
        if not self._closing:
            self.summary.setText(message)
            self._apply_state()

    def _drain(self) -> None:
        super()._drain()
        for _ in range(30):
            try:
                kind, value = self._folder_events.get_nowait()
            except queue.Empty:
                break
            if kind == "network":
                event, sid = value
                if event == "folder-change-invite":
                    self._incoming_folder_change(sid)
                elif event == "folder-change-prepare":
                    self._prepare_receiver(sid)
                elif event == "folder-change-committed":
                    if self._folder_role == "receiver" and sid == self._folder_sid:
                        self._replace_saved_folder(sid)
                elif event == "folder-change-cancelled":
                    if self._folder_role == "receiver" and sid == self._folder_sid:
                        if (self.lifecycle.phase is DesktopPhase.CHANGING_FOLDERS
                                and not self._folder_receiver_ready):
                            self._folder_cancel_after_stop = True
                        else:
                            self._end_folder_change(
                                "Folder change cancelled. Your original folders are unchanged.",
                                replaced=False,
                            )
            elif kind == "initiator-ready":
                if self._folder_role == "initiator" and value == self._folder_sid:
                    self._prepare_initiator(value)
            elif kind == "receiver-stopped":
                sid, error = value
                if self._folder_role != "receiver" or sid != self._folder_sid:
                    continue
                service = self._session_service
                if error or self._folder_cancel_after_stop or not service.ready_folder_change(sid):
                    service.reject_folder_change(sid)
                    self._end_folder_change(
                        "Could not finish the folder change. Your saved folders are intact. "
                        + (error or "The request was cancelled."), replaced=False,
                    )
                else:
                    self._folder_receiver_ready = True
                    self.summary.setText("Waiting for the other laptop to confirm the change...")
            elif kind == "commit":
                sid, error = value
                if self._folder_role != "initiator" or sid != self._folder_sid:
                    continue
                if error:
                    self._end_folder_change(
                        "Folder change could not be confirmed. Saved folders were not removed. "
                        + error, replaced=False,
                    )
                else:
                    self._replace_saved_folder(sid)
            elif kind == "replaced":
                sid, error = value
                if sid != self._folder_sid:
                    continue
                if error:
                    self._end_folder_change(
                        "Folder change needs attention. Original files remain untouched. "
                        "The computers may need to reconnect to finish setup. " + error,
                        replaced=False,
                    )
                else:
                    self._end_folder_change(
                        "Both approved. The previous files are untouched. "
                        "Choose the new folder on one laptop; the other person "
                        "will be asked to choose theirs.",
                        replaced=True,
                    )
            elif kind == "failed":
                sid, error, prepared = value
                if sid != self._folder_sid or self._folder_role != "initiator":
                    continue
                if prepared:
                    # One runtime may already be stopped. End the old live
                    # session rather than pretending both are still connected.
                    self._end_folder_change(
                        "The other laptop could not prepare the folder change. "
                        "Saved folders are intact. Reconnect before retrying. " + error,
                        replaced=False,
                    )
                    if self.controller.running:
                        self._begin_disconnect(notify_peer=True)
                else:
                    self._folder_busy = False
                    self._folder_role = None
                    self._folder_sid = None
                    self._folder_original = None
                    self.summary.setText(
                        "Folder change cancelled. No folder settings were changed. " + error
                    )
                    self._apply_state()
