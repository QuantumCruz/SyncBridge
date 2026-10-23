
"""SyncBridge Qt desktop with bounded, mutually approved live sessions.

Saved device trust, synchronization history, recovery data, and selected
folders survive disconnection. Live sessions never survive a restart.

Connection attempts have a bounded reachability stage and a separate
approval stage. Cancellation completes network cleanup before the desktop
permits another connection or a change of computer.

The synchronization engine, transfer permissions, and fencing remain
unchanged.
"""
from __future__ import annotations

import ipaddress
import math
import os
import queue
import socket
import threading
import time
from pathlib import Path

from PySide6.QtCore import QTimer, QUrl
from PySide6.QtGui import QCloseEvent, QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from syncbridge.network.session_control import (
    PeerSessionClient,
    PeerSessionService,
    SessionControlError,
    new_session_id,
    session_port_for_transfer,
)
from syncbridge.ui.connection_switch import (
    forget_local_folder_connection,
)
from syncbridge.ui.desktop_controller import (
    DesktopController,
    DesktopLifecycle,
    DesktopPhase,
)
from syncbridge.ui.qt_onboarding import (
    NetworkOptions,
    QtOnboarding,
)


STYLE = """
QWidget, QMainWindow {
    background: #f3f6fb;
    color: #17263c;
    font: 10pt 'Segoe UI';
}
QFrame#card {
    background: white;
    border-radius: 12px;
}
QPushButton {
    padding: 8px 12px;
    background: white;
    border: 1px solid #ccd5e1;
    border-radius: 6px;
}
QPushButton:disabled {
    color: #8792a2;
    background: #f1f2f5;
}
QPushButton#primary {
    background: #1565c0;
    color: white;
}
QPushButton#primary:disabled {
    background: #91b0d0;
}
QTableWidget {
    background: white;
}
"""


class ConnectionCancelled(SessionControlError):
    """The current connection attempt was cancelled by its owner."""


def _local_address_for(host: str) -> str:
    target = ipaddress.IPv4Address(host)

    if target.is_loopback:
        return "127.0.0.1"

    if target.is_unspecified or target.is_multicast:
        raise ValueError("Invalid peer address")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((str(target), 9))
        address = probe.getsockname()[0]

    actual = ipaddress.IPv4Address(address)

    if (
        actual.is_unspecified
        or actual.is_loopback
        or actual.is_multicast
    ):
        raise OSError(
            "No usable local address for the other computer"
        )

    return address


class SyncBridgeMutualSessionWindow(QMainWindow):
    """Own the application lifecycle, workers, and button permissions."""

    OFFLINE_TIMEOUT_SECONDS = 20.0
    APPROVAL_TIMEOUT_SECONDS = 55.0
    INCOMING_TIMEOUT_SECONDS = 65.0

    def __init__(
        self,
        controller: DesktopController,
        *,
        network_options: NetworkOptions | None = None,
    ) -> None:
        super().__init__()

        if network_options is None:
            raise ValueError(
                "Desktop networking options are required"
            )

        self.controller = controller
        self.lifecycle = DesktopLifecycle()

        self._events: queue.Queue = queue.Queue()

        self._busy = False
        self._closing = False
        self._close_allowed = False
        self._shutdown_started = False

        self._worker: threading.Thread | None = None

        self._live_session: str | None = None

        self._session_service: PeerSessionService | None = None
        self._session_client: PeerSessionClient | None = None
        self._session_identity = None

        self._peer_checks_pending = False
        self._missed_checks = 0
        self._disconnect_after_work = False

        self._initiated_folder_setup = False
        self._fresh_folder_consent = False

        self._preview = None
        self._network_started = False
        self._folder_stop_lock = threading.Lock()

        # A connection attempt owns its own cancellation event.
        # Another attempt cannot begin until the previous worker
        # and its cleanup have completed.
        self._connect_cancel: threading.Event | None = None
        self._pending_session_id: str | None = None

        self._connect_stage: str | None = None
        self._connect_deadline: float | None = None
        self._connecting_name = ""

        self._choose_after_cancel = False
        self._after_disconnect_message: str | None = None

        self.onboarding = QtOnboarding(
            self,
            controller,
            network_options,
            self._paired,
            self._folders_ready,
        )

        self._make_ui()
        self._apply_state()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._drain)
        self._timer.start(100)

        self._heartbeat = QTimer(self)
        self._heartbeat.timeout.connect(
            self._check_live_peer
        )
        self._heartbeat.start(3000)

        QTimer.singleShot(0, self._start_network)

    @staticmethod
    def _table(columns):
        table = QTableWidget(0, len(columns))
        table.setHorizontalHeaderLabels(columns)
        table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        table.horizontalHeader().setStretchLastSection(True)
        return table

    def _make_ui(self):
        self.setWindowTitle("SyncBridge")
        self.resize(1050, 700)
        self.setMinimumSize(780, 500)

        QApplication.instance().setStyleSheet(STYLE)

        root = QWidget()
        self.setCentralWidget(root)

        layout = QVBoxLayout(root)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        heading = QHBoxLayout()
        heading.addWidget(QLabel("SyncBridge"))
        heading.addStretch()

        self.status = QLabel()
        heading.addWidget(self.status)
        layout.addLayout(heading)

        connection_card = QFrame()
        connection_card.setObjectName("card")

        connection_layout = QVBoxLayout(connection_card)

        self.connection = QLabel()
        self.connection.setWordWrap(True)

        self.hint = QLabel()
        self.hint.setWordWrap(True)

        connection_layout.addWidget(self.connection)
        connection_layout.addWidget(self.hint)

        actions = QHBoxLayout()

        self.find_button = QPushButton("Find computer")
        self.find_button.clicked.connect(
            self._find_computers
        )
        actions.addWidget(self.find_button)

        self.reconnect_button = QPushButton(
            "Reconnect to last computer"
        )
        self.reconnect_button.setObjectName("primary")
        self.reconnect_button.clicked.connect(
            self._begin_outgoing
        )
        actions.addWidget(self.reconnect_button)

        self.cancel_button = QPushButton(
            "Cancel connection"
        )
        self.cancel_button.clicked.connect(
            self._cancel_connection
        )
        actions.addWidget(self.cancel_button)

        self.change_button = QPushButton(
            "Choose another computer"
        )
        self.change_button.clicked.connect(
            self._cancel_and_find
        )
        actions.addWidget(self.change_button)

        self.folder_select_button = QPushButton(
            "Choose my folder"
        )
        self.folder_select_button.clicked.connect(
            self._choose_folder
        )
        actions.addWidget(self.folder_select_button)

        self.open_folder_button = QPushButton(
            "Open my folder"
        )
        self.open_folder_button.clicked.connect(
            self._open_folder
        )
        actions.addWidget(self.open_folder_button)

        actions.addStretch()

        self.disconnect_button = QPushButton(
            "Disconnect"
        )
        self.disconnect_button.clicked.connect(
            self._disconnect
        )
        actions.addWidget(self.disconnect_button)

        connection_layout.addLayout(actions)
        layout.addWidget(connection_card)

        files_card = QFrame()
        files_card.setObjectName("card")

        files_layout = QVBoxLayout(files_card)

        file_actions = QHBoxLayout()
        file_actions.addWidget(QLabel("YOUR FILES"))
        file_actions.addStretch()

        self.preview_button = QPushButton(
            "Preview differences"
        )
        self.preview_button.clicked.connect(
            self._preview_files
        )
        file_actions.addWidget(self.preview_button)

        self.sync_button = QPushButton("Sync files")
        self.sync_button.setObjectName("primary")
        self.sync_button.clicked.connect(
            self._sync_files
        )
        file_actions.addWidget(self.sync_button)

        files_layout.addLayout(file_actions)

        self.summary = QLabel(
            "Find a computer to get started."
        )
        self.summary.setWordWrap(True)
        files_layout.addWidget(self.summary)

        self.tabs = QTabWidget()

        self.local_table = self._table(
            ["My file", "Size"]
        )
        self.remote_table = self._table(
            ["Other computer's file", "Size"]
        )
        self.table = self._table(
            ["Action", "File", "Explanation"]
        )

        self.tabs.addTab(
            self.local_table,
            "My files",
        )
        self.tabs.addTab(
            self.remote_table,
            "Other computer's files",
        )
        self.tabs.addTab(
            self.table,
            "Differences",
        )

        self.tabs.currentChanged.connect(
            self._tab_changed
        )

        files_layout.addWidget(self.tabs)
        layout.addWidget(files_card, 1)

        self.activity_label = QLabel("")
        layout.addWidget(self.activity_label)

        self.activity_bar = QProgressBar()
        layout.addWidget(self.activity_bar)

        self.progress = QLabel("")
        layout.addWidget(self.progress)

        self.activity_label.hide()
        self.activity_bar.hide()

    def _saved_share(self):
        enabled = [
            share
            for share in self.controller.store.load().shares
            if share.enabled
        ]

        return enabled[0] if len(enabled) == 1 else None

    def _peer_name(self):
        share = self._saved_share()

        if share is None:
            return "the other computer"

        pairing = self.onboarding.pairing

        if pairing is not None:
            trusted = pairing.trust.get(
                share.peer_node_id
            )

            if trusted is not None:
                return trusted.name

        return share.remote_host or "the other computer"

    def _apply_state(self):
        phase = self.lifecycle.phase
        saved = self._saved_share() is not None

        ready = bool(
            self._preview is not None
            and self._preview.items
            and not self._preview.requires_review
        )

        available = self.lifecycle.allowed_buttons(
            saved_peer=saved,
            preview_ready=ready,
        )

        idle = (
            not self._busy
            and not self._closing
            and self._network_started
        )

        self.find_button.setEnabled(
            idle and "find" in available
        )

        self.reconnect_button.setVisible(
            saved and phase is DesktopPhase.DISCONNECTED
        )
        self.reconnect_button.setEnabled(
            idle
            and "reconnect" in available
            and self._session_service is not None
        )
        self.reconnect_button.setText(
            f"Reconnect to {self._peer_name()}"
        )

        connecting = (
            phase is DesktopPhase.CONNECTING
            and self._busy
            and self._connect_cancel is not None
            and not self._closing
        )

        cancellation_available = (
            connecting
            and not self._connect_cancel.is_set()
        )

        self.cancel_button.setVisible(connecting)
        self.cancel_button.setEnabled(
            cancellation_available
        )

        self.change_button.setVisible(connecting)
        self.change_button.setEnabled(
            cancellation_available
        )

        folder_allowed = (
            "choose_folder" in available
        )

        self.folder_select_button.setText(
            "Choose my folder"
            if folder_allowed
            else "Change folders"
        )

        self.folder_select_button.setVisible(
            folder_allowed
        )
        self.folder_select_button.setEnabled(
            idle and folder_allowed
        )

        self.open_folder_button.setEnabled(
            idle and "open_folder" in available
        )

        self.preview_button.setEnabled(
            idle
            and self.controller.running
            and "preview" in available
        )

        self.sync_button.setEnabled(
            idle
            and self.controller.running
            and "sync" in available
        )

        self.disconnect_button.setVisible(
            phase is DesktopPhase.CONNECTED
        )
        self.disconnect_button.setEnabled(
            idle
            and self.controller.running
            and "disconnect" in available
        )

        self.status.setText(
            phase.value.replace("_", " ").capitalize()
        )

        if (
            phase is DesktopPhase.CONNECTED
            and self.controller.running
        ):
            self.connection.setText(
                f"Connected to {self._peer_name()}"
            )
            self.hint.setText(
                "Preview differences before synchronizing."
            )

        elif saved:
            self.connection.setText(
                f"Saved connection: {self._peer_name()}"
            )
            self.hint.setText(
                "This computer is not connected. "
                "Saved files and trust are intact."
            )

        else:
            self.connection.setText(
                "No active connection"
            )
            self.hint.setText(
                "Use Find computer to pair and "
                "choose your folders."
            )

    def _move(self, phase):
        self.lifecycle.transition(phase)
        self._apply_state()

    def _start_network(self):
        if self._closing:
            return

        try:
            self.onboarding.start()
            self._network_started = True

            # Folder setup requests cannot be accepted simply
            # because the application was opened.
            self._stop_folder_listener()

            self._ensure_session_service()
            self._apply_state()

        except Exception as exc:
            self.summary.setText(
                f"Could not start discovery: {exc}"
            )

    def _ensure_session_service(self):
        share = self._saved_share()

        if not share or not self.onboarding.started:
            return

        local_ports = self.controller.runtime.listen_ports

        transfer_port = (
            local_ports[1]
            if local_ports
            else share.transfer_port
        )

        signature = (
            share.share_id,
            share.peer_node_id,
            transfer_port,
        )

        if (
            signature == self._session_identity
            and self._session_service is not None
        ):
            return

        if self._session_service is not None:
            self._session_service.stop()
            self._session_service = None

        pairing = self.onboarding.pairing

        service = PeerSessionService(
            pairing.identity,
            pairing.trust,
            share.share_id,
            share.peer_node_id,
            bind_address=self.onboarding.options.pairing_bind,
            port=session_port_for_transfer(
                transfer_port
            ),
            on_event=lambda kind, sid: self._events.put(
                ("session", (kind, sid))
            ),
        )

        service.start()

        self._session_service = service
        self._session_client = PeerSessionClient(
            pairing.identity,
            pairing.trust,
        )
        self._session_identity = signature

    def _target(self):
        share = self._saved_share()

        if share is None or share.remote_host is None:
            raise SessionControlError(
                "Choose folders on both computers first"
            )

        return (
            share.remote_host,
            session_port_for_transfer(
                share.transfer_port
            ),
            share.peer_node_id,
            share.share_id,
        )

    def _find_computers(self):
        if (
            self.lifecycle.phase
            is not DesktopPhase.DISCONNECTED
            or self._busy
            or self._closing
        ):
            return

        self._move(DesktopPhase.PAIRING)

        self.onboarding.show_devices()
        self._attach_direct_discovery()

    def _attach_direct_discovery(self):
        from syncbridge.ui.qt_direct_discovery_window import (
            DirectDiscoveryControls,
        )

        dialog = self.onboarding.devices_dialog

        if (
            dialog is not None
            and not hasattr(dialog, "_direct_controls")
        ):
            controls = DirectDiscoveryControls(
                self.onboarding.presence.directory,
                dialog.message,
                dialog,
            )

            dialog.layout().insertWidget(
                2,
                controls,
            )
            dialog._direct_controls = controls

    def _cancel_pairing_selection(self, message):
        if self.lifecycle.phase is DesktopPhase.PAIRING:
            self._move(DesktopPhase.DISCONNECTING)
            self._move(DesktopPhase.DISCONNECTED)

        self.summary.setText(message)

    def _switch_saved_computer(self, share, name):
        """Replace only the local saved folder relationship.

        This method must run on the Qt thread with no active
        connection worker or synchronization runtime.
        """
        if (
            self._busy
            or self._closing
            or self.controller.running
            or self.lifecycle.phase
            is not DesktopPhase.PAIRING
        ):
            self._cancel_pairing_selection(
                "Disconnect from the current computer "
                "before switching to another."
            )
            return False

        answer = QMessageBox.question(
            self,
            "Connect to another computer?",
            f"You currently have a saved folder connection "
            f"with {self._peer_name()}.\n\n"
            f"To connect folders with {name}, SyncBridge "
            "needs to replace that saved folder relationship "
            "on THIS computer.\n\n"
            "Your files, device identity, previous trust, "
            "synchronization history, and recovery data "
            "will not be deleted.\n\n"
            "The old computer keeps its own saved relationship "
            "until its owner changes it.\n\n"
            f"Continue with {name}?",
            QMessageBox.StandardButton.Yes
            | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if answer != QMessageBox.StandardButton.Yes:
            self._cancel_pairing_selection(
                "Computer change cancelled. "
                "Your previous connection is still saved."
            )
            return False

        old_service = self._session_service

        try:
            # Prevent any more control requests for the previous
            # relationship before changing its configuration.
            if old_service is not None:
                old_service.stop()

            self._session_service = None
            self._session_client = None
            self._session_identity = None

            forget_local_folder_connection(
                self.controller.store,
                expected_share_id=share.share_id,
                running=self.controller.running,
            )

            self._live_session = None
            self._pending_session_id = None
            self._connect_cancel = None
            self._connect_deadline = None
            self._connect_stage = None
            self._connecting_name = ""

            self._fresh_folder_consent = False
            self._initiated_folder_setup = False
            self._after_disconnect_message = None
            self._choose_after_cancel = False

            self._clear_preview()

            # Allow the already authenticated new device
            # to negotiate its own folder relationship.
            self.onboarding.folders.start()

        except Exception as exc:
            # The saved configuration is not intentionally cleared
            # unless the safe local-switch operation succeeds.
            try:
                self._ensure_session_service()
            except Exception:
                pass

            self._cancel_pairing_selection(
                f"Could not change computers safely: {exc}"
            )
            return False

        self._move(DesktopPhase.CHOOSING_FOLDER)
        self.summary.setText(
            f"Paired with {name}. "
            "Choose the folder you want to synchronize. "
            "The other person must choose their own folder."
        )
        return True

    def _paired(self, name: str):
        share = self._saved_share()
        selected = self.onboarding.current_peer

        if share is not None:
            if (
                selected is None
                or selected.node_id == share.peer_node_id
            ):
                if self.lifecycle.phase is DesktopPhase.PAIRING:
                    self._move(
                        DesktopPhase.DISCONNECTING
                    )
                    self._move(
                        DesktopPhase.DISCONNECTED
                    )

                self._begin_outgoing()
                return

            self._switch_saved_computer(
                share,
                name,
            )
            return

        if self.lifecycle.phase is DesktopPhase.DISCONNECTED:
            self._move(DesktopPhase.PAIRING)

        if self.lifecycle.phase is DesktopPhase.PAIRING:
            self._move(DesktopPhase.CHOOSING_FOLDER)

            self.onboarding.folders.start()

            self.summary.setText(
                f"Paired with {name}. "
                "Choose your folder when ready."
            )

    def _choose_folder(self):
        if (
            self.lifecycle.phase
            is not DesktopPhase.CHOOSING_FOLDER
            or self._busy
        ):
            return

        self._initiated_folder_setup = True
        self.onboarding.choose_folder()

    def _folders_ready(self):
        if self._saved_share() is None:
            return

        try:
            self._ensure_session_service()

        except Exception as exc:
            self.summary.setText(
                f"Connection listener unavailable: {exc}"
            )
            return

        if (
            self.lifecycle.phase
            is DesktopPhase.CHOOSING_FOLDER
        ):
            self._fresh_folder_consent = True

            self._move(DesktopPhase.CONNECTING)

            if self._initiated_folder_setup:
                self._begin_outgoing(
                    first_time=True
                )

        self._apply_state()

    def _new_connection_attempt(
        self,
        sid,
        *,
        stage,
        seconds,
    ):
        if self._connect_cancel is not None:
            raise RuntimeError(
                "A previous connection is still finishing"
            )

        cancel = threading.Event()

        self._connect_cancel = cancel
        self._pending_session_id = sid
        self._connect_stage = stage
        self._connect_deadline = (
            time.monotonic() + seconds
        )
        self._connecting_name = self._peer_name()

        self._after_disconnect_message = None
        self._choose_after_cancel = False

        return cancel

    def _begin_outgoing(self, *, first_time=False):
        phase = self.lifecycle.phase

        if first_time:
            if phase is not DesktopPhase.CONNECTING:
                return

        elif phase is not DesktopPhase.DISCONNECTED:
            return

        if (
            self._busy
            or self._closing
            or self.controller.running
            or self._connect_cancel is not None
        ):
            return

        if self._session_service is None:
            self.summary.setText(
                "No saved connection is ready yet."
            )
            return

        sid = new_session_id()

        cancel = self._new_connection_attempt(
            sid,
            stage="finding",
            seconds=self.OFFLINE_TIMEOUT_SECONDS,
        )

        if not first_time:
            self._move(DesktopPhase.CONNECTING)

        self._run(
            "connect",
            lambda: self._connect_outgoing(
                sid,
                cancel,
            ),
        )

        self.summary.setText(
            f"Trying to reach {self._connecting_name}. "
            "Make sure SyncBridge is open on that computer."
        )

        self._apply_state()
        self._render_connection_progress()

    @staticmethod
    def _check_cancelled(cancel):
        if cancel.is_set():
            raise ConnectionCancelled(
                "Connection attempt cancelled"
            )

    def _check_attempt(self, cancel):
        self._check_cancelled(cancel)

        if self._closing:
            raise ConnectionCancelled(
                "The application is closing"
            )

    def _connection_stage_event(
        self,
        sid,
        stage,
        deadline,
    ):
        self._events.put(
            (
                "connection-stage",
                (sid, stage, deadline),
            )
        )

    def _prepare_listener(self):
        self.controller.runtime.bind_address = (
            _local_address_for(
                self.controller.profile().remote_host
            )
        )

    def _connect_outgoing(self, sid, cancel):
        client = self._session_client
        service = self._session_service
        target = self._target()

        started = False
        complete = False
        invitation_acknowledged = False

        offline_deadline = (
            time.monotonic()
            + self.OFFLINE_TIMEOUT_SECONDS
        )

        try:
            while True:
                self._check_attempt(cancel)

                if time.monotonic() >= offline_deadline:
                    raise SessionControlError(
                        f"Could not reach {self._connecting_name} "
                        f"within {int(self.OFFLINE_TIMEOUT_SECONDS)} "
                        "seconds. Make sure SyncBridge is open "
                        "on that computer, then try again."
                    )

                try:
                    response = client.request(
                        *target,
                        sid,
                        "session_invite",
                    )

                except SessionControlError as exc:
                    self._check_attempt(cancel)

                    # An authentication or identity failure is not
                    # a transient offline condition. Never keep
                    # retrying a security failure.
                    if str(exc) != (
                        "The other computer is unavailable"
                    ):
                        raise

                    remaining = (
                        offline_deadline - time.monotonic()
                    )

                    if remaining <= 0:
                        continue

                    cancel.wait(
                        min(0.4, remaining)
                    )
                    continue

                invitation_acknowledged = True
                self._check_attempt(cancel)
                break

            if response != "waiting":
                raise SessionControlError(
                    "The other computer is not accepting "
                    "connections right now."
                )

            approval_deadline = (
                time.monotonic()
                + self.APPROVAL_TIMEOUT_SECONDS
            )

            self._connection_stage_event(
                sid,
                "approval",
                approval_deadline,
            )

            while True:
                self._check_attempt(cancel)

                if (
                    time.monotonic()
                    >= approval_deadline
                ):
                    raise SessionControlError(
                        "The other computer did not approve "
                        "the connection in time."
                    )

                state = client.request(
                    *target,
                    sid,
                    "session_status",
                )

                self._check_attempt(cancel)

                if state == "approved":
                    break

                if state != "waiting":
                    raise SessionControlError(
                        "The connection request was declined "
                        "or has expired."
                    )

                remaining = (
                    approval_deadline - time.monotonic()
                )

                if remaining > 0:
                    cancel.wait(
                        min(0.25, remaining)
                    )

            self._connection_stage_event(
                sid,
                "establishing",
                approval_deadline,
            )

            self._check_attempt(cancel)
            self._prepare_listener()

            self._check_attempt(cancel)
            self.controller.start()
            started = True

            self._check_attempt(cancel)
            service.activate_outgoing(sid)

            self._check_attempt(cancel)

            if client.request(
                *target,
                sid,
                "session_commit",
            ) != "active":
                raise SessionControlError(
                    "Could not complete the mutual connection."
                )

            self._check_attempt(cancel)

            if client.request(
                *target,
                sid,
                "session_ping",
            ) != "active":
                raise SessionControlError(
                    "The other computer did not confirm "
                    "the connection."
                )

            self._check_attempt(cancel)

            complete = True
            return sid

        finally:
            if not complete:
                # All resource cleanup is completed by this worker
                # before another attempt can become available.
                service.clear(sid)

                if started:
                    self.controller.stop()

                if invitation_acknowledged:
                    try:
                        client.request(
                            *target,
                            sid,
                            "session_leave",
                        )
                    except Exception:
                        pass

    def _connect_incoming(self, sid, cancel):
        client = self._session_client
        service = self._session_service
        target = self._target()

        started = False
        complete = False

        try:
            self._check_attempt(cancel)
            self._prepare_listener()

            self._check_attempt(cancel)
            self.controller.start()
            started = True

            self._check_attempt(cancel)

            if not service.approve(sid):
                raise SessionControlError(
                    "Connection request expired."
                )

            deadline = (
                time.monotonic()
                + self.INCOMING_TIMEOUT_SECONDS
            )

            self._connection_stage_event(
                sid,
                "establishing",
                deadline,
            )

            while time.monotonic() < deadline:
                self._check_attempt(cancel)

                if service.active_session == sid:
                    state = client.request(
                        *target,
                        sid,
                        "session_ping",
                    )

                    self._check_attempt(cancel)

                    if state == "active":
                        complete = True
                        return sid

                cancel.wait(0.2)

            raise SessionControlError(
                "The other computer did not finish connecting."
            )

        finally:
            if not complete:
                service.clear(sid)

                if started:
                    self.controller.stop()

    def _on_invite(self, sid):
        service = self._session_service

        if (
            service is None
            or service.pending_invitation != sid
            or self._closing
        ):
            return

        if (
            self.lifecycle.phase
            is DesktopPhase.CONNECTING
            and self._fresh_folder_consent
            and not self._busy
        ):
            approved = True

        elif (
            self.lifecycle.phase
            is DesktopPhase.DISCONNECTED
            and not self._busy
        ):
            approved = (
                QMessageBox.question(
                    self,
                    "Connection request",
                    f"{self._peer_name()} wants "
                    "to reconnect. Accept?",
                    QMessageBox.StandardButton.Yes
                    | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                == QMessageBox.StandardButton.Yes
            )

            if approved:
                self._move(DesktopPhase.CONNECTING)

        else:
            approved = False

        if not approved or self._busy:
            service.reject(sid)
            return

        self._fresh_folder_consent = False

        cancel = self._new_connection_attempt(
            sid,
            stage="establishing",
            seconds=self.INCOMING_TIMEOUT_SECONDS,
        )

        self._run(
            "connect",
            lambda: self._connect_incoming(
                sid,
                cancel,
            ),
        )

        self.summary.setText(
            f"Establishing a secure connection "
            f"with {self._connecting_name}..."
        )

        self._apply_state()
        self._render_connection_progress()

    def _render_connection_progress(self):
        if (
            self.lifecycle.phase
            is not DesktopPhase.CONNECTING
            or self._connect_cancel is None
            or self._closing
        ):
            return

        if self._connect_cancel.is_set():
            self.activity_label.setText(
                "Cancelling connection and "
                "closing network resources..."
            )
            return

        deadline = self._connect_deadline

        if deadline is None:
            return

        remaining = max(
            0,
            math.ceil(
                deadline - time.monotonic()
            ),
        )

        if self._connect_stage == "finding":
            message = (
                f"Looking for {self._connecting_name} "
                f"({remaining}s remaining)..."
            )

        elif self._connect_stage == "approval":
            message = (
                f"Waiting for {self._connecting_name} "
                f"to approve ({remaining}s remaining)..."
            )

        else:
            message = (
                "Completing the secure connection..."
            )

        self.activity_label.setText(message)

    def _cancel_connection(self):
        self._request_connection_cancel(
            choose_other=False
        )

    def _cancel_and_find(self):
        self._request_connection_cancel(
            choose_other=True
        )

    def _request_connection_cancel(
        self,
        *,
        choose_other,
    ):
        if (
            self.lifecycle.phase
            is not DesktopPhase.CONNECTING
            or self._connect_cancel is None
            or self._closing
        ):
            return

        if choose_other:
            self._choose_after_cancel = True

        self._after_disconnect_message = (
            "Connection cancelled. "
            "Your files and saved pairing are unchanged."
        )

        self._connect_cancel.set()

        self.summary.setText(
            "Cancelling the current connection safely..."
        )

        self._apply_state()
        self._render_connection_progress()

    def _run(self, kind, func):
        if self._busy or self._closing:
            return

        self._busy = True
        self._apply_state()

        self.activity_label.setText(
            f"Working: {kind}..."
        )
        self.activity_label.show()

        self.activity_bar.setRange(0, 0)
        self.activity_bar.show()

        generation = self.lifecycle.generation

        def worker():
            try:
                result = func()
                self._events.put(
                    (
                        "done",
                        (kind, generation, result),
                    )
                )

            except Exception as exc:
                self._events.put(
                    (
                        "error",
                        (kind, generation, exc),
                    )
                )

        self._worker = threading.Thread(
            target=worker,
            name=f"SyncBridge-{kind}",
            daemon=False,
        )
        self._worker.start()

    def _finish_connect_attempt(self):
        self._connect_cancel = None
        self._pending_session_id = None
        self._connect_stage = None
        self._connect_deadline = None
        self._connecting_name = ""

    def _connected(self, sid):
        self._finish_connect_attempt()

        self._live_session = sid
        self._missed_checks = 0
        self._peer_checks_pending = False

        self._fresh_folder_consent = False
        self._initiated_folder_setup = False

        self._after_disconnect_message = None
        self._choose_after_cancel = False

        self._move(DesktopPhase.CONNECTED)

        self.summary.setText(
            "Connected. Preview differences "
            "before synchronizing."
        )

        self._load_files()

        # No further unsolicited folder-replacement requests.
        threading.Thread(
            target=self._stop_folder_listener,
            daemon=True,
        ).start()

    def _stop_folder_listener(self):
        try:
            with self._folder_stop_lock:
                if self.onboarding.folders is not None:
                    self.onboarding.folders.stop()

        except Exception as exc:
            self._events.put(
                ("listener-error", str(exc))
            )

    def _clear_preview(self):
        self._preview = None

        for table in (
            self.table,
            self.local_table,
            self.remote_table,
        ):
            table.setRowCount(0)

    def _disconnect(self):
        if (
            self.lifecycle.phase
            is not DesktopPhase.CONNECTED
            or self._busy
        ):
            return

        self._begin_disconnect(
            notify_peer=True
        )

    def _begin_disconnect(self, *, notify_peer):
        if self.lifecycle.phase in (
            DesktopPhase.DISCONNECTING,
            DesktopPhase.DISCONNECTED,
        ):
            return

        sid = self._live_session
        self._live_session = None

        self._clear_preview()
        self._move(DesktopPhase.DISCONNECTING)

        if self._session_service is not None:
            self._session_service.clear(sid)

        if self._busy:
            self._disconnect_after_work = True
            return

        self._run(
            "disconnect",
            lambda: self._end_session(
                sid,
                notify_peer,
            ),
        )

    def _end_session(self, sid, notify_peer):
        try:
            if (
                notify_peer
                and sid
                and self._session_client is not None
            ):
                try:
                    self._session_client.request(
                        *self._target(),
                        sid,
                        "session_leave",
                    )
                except Exception:
                    pass

        finally:
            self.controller.stop()
            self._stop_folder_listener()

    def _check_live_peer(self):
        if (
            self.lifecycle.phase
            is not DesktopPhase.CONNECTED
            or self._live_session is None
            or self._peer_checks_pending
            or self._closing
        ):
            return

        sid = self._live_session
        self._peer_checks_pending = True

        def worker():
            try:
                success = (
                    self._session_client.request(
                        *self._target(),
                        sid,
                        "session_ping",
                    )
                    == "active"
                )

            except Exception:
                success = False

            self._events.put(
                (
                    "heartbeat",
                    (sid, success),
                )
            )

        threading.Thread(
            target=worker,
            daemon=True,
        ).start()

    def _block_unexpected_folder_requests(self):
        folders = self.onboarding.folders

        if folders is None:
            return False

        pending = folders.pending()
        selected = self.onboarding.current_peer

        if (
            self.lifecycle.phase
            is DesktopPhase.CHOOSING_FOLDER
            and selected is not None
        ):
            unexpected = [
                request
                for request in pending
                if request.peer_node_id
                != selected.node_id
            ]

        elif (
            self.lifecycle.phase
            is DesktopPhase.CHOOSING_FOLDER
        ):
            # Direct virtual-network connections remain subject
            # to cryptographic authentication.
            unexpected = []

        else:
            unexpected = pending

        for request in unexpected:
            folders.reject(
                request.request_id
            )

        return bool(unexpected)

    def _handle_connect_result(
        self,
        *,
        kind,
        payload,
    ):
        cancel = self._connect_cancel

        was_cancelled = bool(
            cancel is not None
            and cancel.is_set()
        )

        if kind == "done" and not was_cancelled:
            self._connected(payload)
            return

        if kind == "done" and was_cancelled:
            # The remote side might have committed a session
            # immediately before the local Cancel click.
            # Explicitly notify it and stop the local runtime.
            self._finish_connect_attempt()
            self._fresh_folder_consent = False

            self._move(
                DesktopPhase.DISCONNECTING
            )

            self._run(
                "disconnect",
                lambda: self._end_session(
                    payload,
                    True,
                ),
            )
            return

        if was_cancelled or isinstance(
            payload,
            ConnectionCancelled,
        ):
            if self._after_disconnect_message is None:
                self._after_disconnect_message = (
                    "Connection cancelled. "
                    "Saved files and pairing are unchanged."
                )

        else:
            self._after_disconnect_message = str(
                payload
            )

        self._finish_connect_attempt()
        self._fresh_folder_consent = False

        self._move(DesktopPhase.DISCONNECTING)

        self._run(
            "disconnect",
            lambda: self._end_session(
                None,
                False,
            ),
        )

    def _finish_disconnection(self):
        if self.controller.running:
            self.status.setText(
                "Disconnect needs attention"
            )
            self.summary.setText(
                "Could not finish disconnecting safely. "
                "Please close SyncBridge before trying again."
            )
            return

        self._live_session = None
        self._finish_connect_attempt()

        self._move(DesktopPhase.DISCONNECTED)

        message = self._after_disconnect_message
        self._after_disconnect_message = None

        self.summary.setText(
            message
            or "Disconnected. Saved pairing "
            "and folders are retained."
        )

        if self._choose_after_cancel:
            self._choose_after_cancel = False

            if not self._closing:
                self._find_computers()

    def _drain(self):
        if (
            not self._closing
            and self.onboarding.started
        ):
            try:
                if not self._block_unexpected_folder_requests():
                    self.onboarding.poll()

            except Exception as exc:
                self.summary.setText(
                    f"Network event issue: {exc}"
                )

        for _ in range(100):
            try:
                kind, value = (
                    self._events.get_nowait()
                )

            except queue.Empty:
                break

            if kind == "shutdown":
                if value:
                    self.summary.setText(
                        "Could not close safely: "
                        + "; ".join(value)
                    )
                    self.status.setText(
                        "Shutdown needs attention"
                    )

                else:
                    self._close_allowed = True
                    self._timer.stop()
                    self.close()

                return

            if kind == "transfer":
                self.progress.setText(
                    f"{value.direction}: "
                    f"{value.path} "
                    f"({self._size(value.transferred)} "
                    f"/ {self._size(value.total)})"
                )
                continue

            if kind == "session":
                event, sid = value

                if event == "invite" and not self._closing:
                    self._on_invite(sid)

                elif (
                    event == "left"
                    and sid == self._live_session
                ):
                    self._begin_disconnect(
                        notify_peer=False
                    )

                continue

            if kind == "connection-stage":
                sid, stage, deadline = value

                if (
                    sid == self._pending_session_id
                    and self._connect_cancel is not None
                    and not self._connect_cancel.is_set()
                    and self.lifecycle.phase
                    is DesktopPhase.CONNECTING
                ):
                    self._connect_stage = stage
                    self._connect_deadline = deadline

                    if stage == "approval":
                        self.summary.setText(
                            f"{self._connecting_name} "
                            "has been reached. Waiting "
                            "for connection approval..."
                        )

                    elif stage == "establishing":
                        self.summary.setText(
                            "Completing the secure "
                            "connection between both computers..."
                        )

                continue

            if kind == "heartbeat":
                sid, success = value

                if sid != self._live_session:
                    continue

                self._peer_checks_pending = False

                self._missed_checks = (
                    0
                    if success
                    else self._missed_checks + 1
                )

                if self._missed_checks >= 3:
                    self._after_disconnect_message = (
                        "The other computer is offline "
                        "or unreachable. Your saved files "
                        "and pairing are intact."
                    )

                    self._begin_disconnect(
                        notify_peer=False
                    )

                continue

            if kind == "listener-error":
                self.summary.setText(
                    "Folder listener needs attention: "
                    f"{value}"
                )
                continue

            action, generation, payload = value

            self._busy = False
            self.activity_label.hide()
            self.activity_bar.hide()

            if self._closing:
                continue

            if generation != self.lifecycle.generation:
                # This result belongs to a superseded operation.
                # Do not allow an obsolete operation to bring the
                # desktop back to Connected.
                if (
                    self._disconnect_after_work
                    and not self._closing
                ):
                    self._disconnect_after_work = False

                    self._run(
                        "disconnect",
                        lambda: self._end_session(
                            None,
                            False,
                        ),
                    )

                continue

            if action == "connect":
                self._handle_connect_result(
                    kind=kind,
                    payload=payload,
                )
                self._apply_state()
                continue

            if kind == "error":
                self.summary.setText(
                    f"{action.capitalize()} failed: "
                    f"{payload}"
                )

                if action == "disconnect":
                    # Never report a safe disconnection when
                    # runtime cleanup did not finish.
                    self.status.setText(
                        "Shutdown needs attention"
                    )

                    self._choose_after_cancel = False

                elif action in ("preview", "sync"):
                    self._move(
                        DesktopPhase.CONNECTED
                    )

            elif action == "disconnect":
                self._finish_disconnection()

            elif action == "preview":
                self._preview = payload
                self._display_preview(payload)

                self._move(
                    DesktopPhase.CONNECTED
                )

            elif action == "sync":
                self._move(
                    DesktopPhase.CONNECTED
                )

                self.summary.setText(
                    "Synchronization finished. "
                    "Preview again to check changes."
                    if payload.complete
                    else
                    "Some changes need attention. "
                    "Preview again before retrying."
                )

                self._preview = None
                self.table.setRowCount(0)
                self._load_files()

            elif action in ("local", "remote"):
                table = (
                    self.local_table
                    if action == "local"
                    else self.remote_table
                )

                self._show_files(
                    table,
                    payload,
                )

            self._apply_state()

        if (
            self.lifecycle.phase
            is DesktopPhase.PAIRING
            and not self._closing
        ):
            dialog = self.onboarding.devices_dialog

            if (
                dialog is not None
                and not dialog.isVisible()
                and not self.onboarding._pair_busy
                and not self.onboarding.pair_dialogs
                and not self.onboarding._incoming_pairs
            ):
                self._move(
                    DesktopPhase.DISCONNECTING
                )
                self._move(
                    DesktopPhase.DISCONNECTED
                )

        if (
            self.lifecycle.phase
            is DesktopPhase.CONNECTING
        ):
            self._render_connection_progress()

        if (
            self._closing
            and not self._busy
            and not self._shutdown_started
        ):
            self._shutdown()

    def _preview_files(self):
        if (
            self.lifecycle.phase
            is not DesktopPhase.CONNECTED
            or self._busy
        ):
            return

        self._preview = None

        self._move(
            DesktopPhase.SYNCHRONIZING
        )

        self._run(
            "preview",
            self.controller.preview,
        )

    def _display_preview(self, preview):
        self.table.setRowCount(
            len(preview.items)
        )

        for row, item in enumerate(preview.items):
            for col, value in enumerate(
                (
                    item.action,
                    item.path,
                    item.description,
                )
            ):
                self.table.setItem(
                    row,
                    col,
                    QTableWidgetItem(
                        str(value)
                    ),
                )

        self.tabs.setCurrentIndex(2)

        if preview.requires_review:
            self.summary.setText(
                "Conflicts or deletions require review; "
                "no changes were applied."
            )

        elif not preview.items:
            self.summary.setText(
                "Everything is up to date."
            )

        else:
            self.summary.setText(
                f"{len(preview.items)} difference(s). "
                "Choose Sync to apply safe changes."
            )

    def _sync_files(self):
        if (
            self.lifecycle.phase
            is not DesktopPhase.CONNECTED
            or self._busy
        ):
            return

        plan = self._preview

        if (
            plan is None
            or plan.requires_review
            or not plan.items
        ):
            return

        answer = QMessageBox.question(
            self,
            "Synchronize?",
            f"Synchronize {len(plan.items)} "
            "planned file change(s)?",
            QMessageBox.StandardButton.Yes
            | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if answer != QMessageBox.StandardButton.Yes:
            return

        self._preview = None

        self._move(
            DesktopPhase.SYNCHRONIZING
        )

        self._run(
            "sync",
            lambda: self.controller.sync_once(
                on_progress=self._transfer_progress
            ),
        )

    def _transfer_progress(self, event):
        self._events.put(
            ("transfer", event)
        )

    def _list_local(self):
        root = self.controller.profile().local_root
        rows = []

        for base, dirs, files in os.walk(
            root,
            followlinks=False,
        ):
            dirs[:] = [
                directory
                for directory in dirs
                if directory not in {
                    ".git",
                    ".venv",
                    ".syncbridge",
                    "__pycache__",
                }
                and not (
                    Path(base) / directory
                ).is_symlink()
            ]

            for name in files:
                path = Path(base) / name

                if path.is_symlink():
                    continue

                try:
                    rows.append(
                        (
                            path.relative_to(root).as_posix(),
                            path.stat().st_size,
                        )
                    )

                except OSError:
                    continue

                if len(rows) >= 3000:
                    return rows

        return rows

    def _list_remote(self):
        share = self._saved_share()
        client = self.controller.runtime.manifest_client

        if share is None or client is None:
            return []

        manifest = client.fetch(
            share.remote_host,
            share.manifest_port,
            share.peer_node_id,
            share.share_id,
        )

        return [
            (
                file.relative_path,
                file.size,
            )
            for file in manifest.snapshot.files.values()
        ][:3000]

    def _tab_changed(self, index):
        if (
            self.lifecycle.phase
            is not DesktopPhase.CONNECTED
            or self._busy
        ):
            return

        if index == 0:
            self._run(
                "local",
                self._list_local,
            )

        elif index == 1:
            self._run(
                "remote",
                self._list_remote,
            )

    def _load_files(self):
        if (
            self.lifecycle.phase
            is DesktopPhase.CONNECTED
            and not self._busy
        ):
            self._run(
                "local",
                self._list_local,
            )

    @staticmethod
    def _size(n):
        n = float(n)

        for unit in (
            "B",
            "KB",
            "MB",
            "GB",
            "TB",
        ):
            if n < 1024 or unit == "TB":
                return (
                    f"{n:.0f} {unit}"
                    if unit == "B"
                    else f"{n:.1f} {unit}"
                )

            n /= 1024

    def _show_files(self, table, rows):
        table.setRowCount(len(rows))

        for index, (name, size) in enumerate(rows):
            table.setItem(
                index,
                0,
                QTableWidgetItem(str(name)),
            )
            table.setItem(
                index,
                1,
                QTableWidgetItem(
                    self._size(size)
                ),
            )

    def _open_folder(self):
        if (
            self.lifecycle.phase
            is not DesktopPhase.CONNECTED
        ):
            return

        folder = self.controller.profile().local_root

        QDesktopServices.openUrl(
            QUrl.fromLocalFile(str(folder))
        )

    def _shutdown(self):
        self._shutdown_started = True

        sid = self._live_session
        self._live_session = None

        service = self._session_service
        client = self._session_client

        try:
            target = (
                self._target()
                if sid
                else None
            )

        except Exception:
            target = None

        def worker():
            problems = []

            if sid and target and client:
                try:
                    client.request(
                        *target,
                        sid,
                        "session_leave",
                    )
                except Exception:
                    pass

            if service is not None:
                try:
                    service.stop()
                except Exception as exc:
                    problems.append(
                        str(exc)
                    )

            try:
                self.controller.stop()
            except Exception as exc:
                problems.append(
                    str(exc)
                )

            try:
                self._stop_folder_listener()
                self.onboarding.stop()

            except Exception as exc:
                problems.append(
                    str(exc)
                )

            self._events.put(
                ("shutdown", problems)
            )

        threading.Thread(
            target=worker,
            name="SyncBridgeShutdown",
            daemon=False,
        ).start()

    def closeEvent(self, event: QCloseEvent):
        if self._close_allowed:
            event.accept()
            return

        event.ignore()

        if self._closing:
            return

        self._closing = True

        if self._connect_cancel is not None:
            self._connect_cancel.set()

        self._heartbeat.stop()

        self.onboarding.close_ui()

        self._apply_state()

        self.summary.setText(
            "Closing network connections safely..."
        )

        if not self._busy:
            self._shutdown()
