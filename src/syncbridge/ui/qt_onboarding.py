
"""Simple Qt onboarding over SyncBridge's existing signed pairing and folder services.

Pairing is trust-on-first-use: both people approve, but no out-of-band fingerprint
comparison occurs. This is convenient on a private LAN but weaker against an
active impersonator than independently checking a verification code.
"""
from __future__ import annotations

import queue
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QFileDialog, QHBoxLayout, QLabel, QListWidget, QListWidgetItem,
    QMessageBox, QPushButton, QVBoxLayout,
)

from syncbridge.network.discovery import DISCOVERY_PORT
from syncbridge.network.pairing import PAIRING_PORT, PairingDetails, PairingSession
from syncbridge.network.share_activation import ACTIVATION_PORT
from syncbridge.network.share_setup import SETUP_PORT, IncomingShareRequest
from syncbridge.ui.folder_setup_desktop import FolderSetupController
from syncbridge.ui.nearby_devices import DesktopPresence, NearbyDevice
from syncbridge.ui.pairing_desktop import PairingController


@dataclass(frozen=True)
class NetworkOptions:
    discovery_port: int = DISCOVERY_PORT
    discovery_bind: str = "0.0.0.0"
    discovery_targets: tuple[tuple[str, int], ...] | None = None
    name: str | None = None
    pairing_port: int = PAIRING_PORT
    pairing_bind: str = "0.0.0.0"
    setup_port: int = SETUP_PORT
    remote_setup_port: int = SETUP_PORT
    activation_port: int = ACTIVATION_PORT
    remote_activation_port: int = ACTIVATION_PORT


class ConnectDialog(QDialog):
    """Each person approves a connection once. No code-entry UI."""

    def __init__(self, parent, details: PairingDetails, approve, reject):
        super().__init__(parent)
        self.details = details
        self._approve = approve
        self._reject = reject
        self.decided = False
        self.setWindowTitle("Connect computers")
        self.setMinimumWidth(420)

        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        title = QLabel(f"Connect with {details.remote_name}?")
        title.setObjectName("heading")
        layout.addWidget(title)

        info = QLabel(
            f"Computer: {details.remote_name}\n"
            f"Network address: {details.address}\n\n"
            "Both people must approve. You'll choose folders separately."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        self.message = QLabel("Waiting for your decision")
        layout.addWidget(self.message)

        buttons = QHBoxLayout()

        self.yes = QPushButton("Connect")
        self.yes.setObjectName("primary")
        self.yes.clicked.connect(self.accept_connection)
        buttons.addWidget(self.yes)

        self.no = QPushButton("Decline")
        self.no.clicked.connect(self.reject_connection)
        buttons.addWidget(self.no)

        layout.addLayout(buttons)

    def accept_connection(self):
        if self.decided:
            return

        self.decided = True
        self.yes.setEnabled(False)
        self.no.setEnabled(False)
        self.message.setText("Waiting for the other computer to approve...")

        # The protocol still verifies signed messages; the protocol's code
        # comparison is intentionally satisfied locally, not by the user.
        self._approve(self.details.code)

    def reject_connection(self):
        if not self.decided:
            self.decided = True
            self._reject()
        self.close()

    def closeEvent(self, event):
        if not self.decided:
            self.decided = True
            self._reject()
        event.accept()


class FolderRequestDialog(QDialog):
    """The only folder permission prompt is choosing a local folder."""

    def __init__(self, parent, request: IncomingShareRequest, approve, reject):
        super().__init__(parent)
        self.request = request
        self._approve = approve
        self._reject = reject
        self.decided = False
        self.setWindowTitle("Choose a folder")
        self.setMinimumWidth(445)

        layout = QVBoxLayout(self)

        title = QLabel(f"{request.peer_name} wants to sync folders")
        title.setObjectName("heading")
        layout.addWidget(title)

        info = QLabel(
            "Choose the folder on THIS computer to synchronize. "
            "The paired computer can read and update it. "
            "Conflicts and deletions still require review."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        self.message = QLabel("Waiting for your folder selection")
        layout.addWidget(self.message)

        buttons = QHBoxLayout()

        self.yes = QPushButton("Choose folder")
        self.yes.setObjectName("primary")
        self.yes.clicked.connect(self.choose)
        buttons.addWidget(self.yes)

        self.no = QPushButton("Decline")
        self.no.clicked.connect(self.reject_request)
        buttons.addWidget(self.no)

        layout.addLayout(buttons)

    def choose(self):
        if self.decided:
            return

        folder = QFileDialog.getExistingDirectory(
            self, "Folder to synchronize"
        )
        if not folder:
            return

        try:
            self._approve(self.request.request_id, folder)
        except Exception as exc:
            self.message.setText(f"Cannot use that folder: {exc}")
            return

        self.decided = True
        self.yes.setEnabled(False)
        self.no.setEnabled(False)
        self.message.setText("Folder chosen. Connecting...")

    def reject_request(self):
        if not self.decided:
            self.decided = True
            try:
                self._reject(self.request.request_id)
            except Exception:
                pass
        self.close()

    def closeEvent(self, event):
        if not self.decided:
            self.decided = True
            try:
                self._reject(self.request.request_id)
            except Exception:
                pass
        event.accept()


class DevicesDialog(QDialog):
    """Click a device, then connect. No separate advanced setup actions."""

    def __init__(self, parent, bridge: QtOnboarding):
        super().__init__(parent)
        self.bridge = bridge
        self.setWindowTitle("Nearby computers")
        self.resize(550, 370)

        layout = QVBoxLayout(self)

        title = QLabel("Choose a computer")
        title.setObjectName("heading")
        layout.addWidget(title)

        hint = QLabel(
            "Computers running SyncBridge appear here automatically."
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self.listing = QListWidget()
        self.listing.currentItemChanged.connect(
            lambda *_: self.refresh_buttons()
        )
        self.listing.itemDoubleClicked.connect(
            lambda *_: self.connect_selected()
        )
        layout.addWidget(self.listing)

        actions = QHBoxLayout()
        self.connect_button = QPushButton("Connect")
        self.connect_button.setObjectName("primary")
        self.connect_button.clicked.connect(self.connect_selected)
        actions.addWidget(self.connect_button)
        layout.addLayout(actions)

        self.message = QLabel("")
        layout.addWidget(self.message)

        self._previous = None
        self.refresh()

    def selected(self) -> NearbyDevice | None:
        item = self.listing.currentItem()
        return (
            self.bridge.device(
                item.data(Qt.ItemDataRole.UserRole)
            )
            if item else None
        )

    def refresh_buttons(self):
        self.connect_button.setEnabled(
            self.selected() is not None
            and not self.bridge.stopping
        )

    def force_refresh(self):
        try:
            self.bridge.presence.directory.refresh()
        except Exception as exc:
            self.message.setText(f"Cannot refresh: {exc}")
        self._previous = None
        self.refresh()

    def refresh(self):
        snapshot = tuple(
            (peer, self.bridge.pairing.trusted(peer.node_id))
            for peer in self.bridge.devices()
        )
        if snapshot == self._previous:
            return

        self._previous = snapshot
        selected = self.selected()
        selected_id = selected.node_id if selected else None

        self.listing.clear()
        for peer, paired in snapshot:
            item = QListWidgetItem(
                f"{peer.name}    ·    {'Paired' if paired else 'Available'}"
            )
            item.setData(Qt.ItemDataRole.UserRole, peer.node_id)
            self.listing.addItem(item)
            if selected_id == peer.node_id:
                self.listing.setCurrentItem(item)

        if self.listing.count() == 1 and not selected_id:
            self.listing.setCurrentRow(0)

        self.refresh_buttons()
        self.message.setText(f"{len(snapshot)} computer(s) found")

    def connect_selected(self):
        peer = self.selected()
        if peer is not None:
            self.bridge.select_device(peer)


class QtOnboarding:
    """Own existing networking services and bridge their events to Qt."""

    def __init__(
        self,
        window,
        controller,
        options: NetworkOptions,
        on_paired: Callable[[str], None],
        on_ready: Callable[[], None],
    ):
        self.window = window
        self.controller = controller
        self.options = options
        self.on_paired = on_paired
        self.on_ready = on_ready
        self.events: queue.SimpleQueue[tuple[str, object]] = queue.SimpleQueue()

        self.pairing: PairingController | None = None
        self.presence: DesktopPresence | None = None
        self.folders: FolderSetupController | None = None

        self.devices_dialog: DevicesDialog | None = None
        self.pair_dialogs: dict[str, ConnectDialog] = {}
        self.folder_dialogs: dict[str, FolderRequestDialog] = {}

        self._incoming_pairs: set[str] = set()
        self._incoming_folders: set[str] = set()
        self._outgoing_pairs: dict[str, PairingSession] = {}
        self._outgoing_folder = None
        self._pair_busy = False
        self._folder_busy = False

        self._threads: set[threading.Thread] = set()
        self._threads_lock = threading.Lock()
        self.stopping = False
        self.started = False
        self.current_peer: NearbyDevice | None = None
        self._known_ready: set[str] = set()

    def start(self):
        if self.started:
            return

        profile = self.controller.store.path.parent
        name = self.options.name or self.controller.store.load().device_name

        pairing = PairingController(
            profile,
            name,
            bind_address=self.options.pairing_bind,
            port=self.options.pairing_port,
        )

        presence = folders = None
        try:
            pairing.start()

            presence = DesktopPresence(
                profile,
                device_name=name,
                listen_port=self.options.discovery_port,
                bind_address=self.options.discovery_bind,
                targets=self.options.discovery_targets,
                pairing_port=pairing.port,
            )
            presence.start()

            folders = FolderSetupController(
                self.controller.store,
                bind_address=self.options.pairing_bind,
                listen_port=self.options.setup_port,
                remote_port=self.options.remote_setup_port,
                sync_ports=(
                    self.controller.runtime.listen_ports
                    or (45843, 45842, 45844)
                ),
                activation_port=self.options.activation_port,
                remote_activation_port=self.options.remote_activation_port,
            )
            folders.start()

        except BaseException:
            if folders is not None:
                folders.stop()
            if presence is not None:
                presence.stop()
            pairing.stop()
            raise

        self.pairing = pairing
        self.presence = presence
        self.folders = folders
        self._known_ready = self._ready_ids()
        self.started = True

    def devices(self) -> tuple[NearbyDevice, ...]:
        return self.presence.directory.devices() if self.presence else ()

    def device(self, peer_id: str) -> NearbyDevice | None:
        return next(
            (p for p in self.devices() if p.node_id == peer_id),
            None,
        )

    def paired_device(self) -> NearbyDevice | None:
        if (
            self.current_peer
            and self.pairing
            and self.pairing.trusted(self.current_peer.node_id)
        ):
            return self.current_peer

        if self.pairing:
            return next(
                (
                    p for p in self.devices()
                    if self.pairing.trusted(p.node_id)
                ),
                None,
            )
        return None

    def show_devices(self):
        if not self.started:
            QMessageBox.warning(
                self.window,
                "Not ready",
                "Nearby connections are not running.",
            )
            return

        if self.devices_dialog is None:
            self.devices_dialog = DevicesDialog(self.window, self)

        self.devices_dialog.refresh()
        self.devices_dialog.show()
        self.devices_dialog.raise_()
        self.devices_dialog.activateWindow()

    def select_device(self, peer: NearbyDevice):
        self.current_peer = peer

        if self.pairing.trusted(peer.node_id):
            if self.devices_dialog:
                self.devices_dialog.hide()
            self.on_paired(peer.name)
            return

        self._request_pair(peer)

    def _spawn(self, name: str, task):
        def run():
            try:
                task()
            finally:
                with self._threads_lock:
                    self._threads.discard(threading.current_thread())

        worker = threading.Thread(
            target=run, name=name, daemon=False
        )

        with self._threads_lock:
            if self.stopping:
                return
            self._threads.add(worker)
            try:
                worker.start()
            except BaseException:
                self._threads.discard(worker)
                raise

    def _request_pair(self, peer: NearbyDevice):
        if self._pair_busy or self.stopping:
            return

        self._pair_busy = True

        def task():
            try:
                session = self.pairing.request(peer)
                if self.stopping:
                    session.close()
                else:
                    self.events.put(("pair_session", session))
            except Exception as exc:
                self.events.put(("pair_error", str(exc)))

        self._spawn("QtPairRequest", task)

    def _approve_pair(self, session: PairingSession, code: str):
        def task():
            try:
                session.approve(code)
                self.events.put(
                    ("pair_success", session.details.request_id)
                )
            except Exception as exc:
                self.events.put(
                    (
                        "pair_failure",
                        (session.details.request_id, str(exc)),
                    )
                )

        self._spawn("QtPairApprove", task)

    def _reject_pair(self, session: PairingSession):
        session.reject()
        self._outgoing_pairs.pop(
            session.details.request_id, None
        )
        self._pair_busy = False

    def _approve_incoming(self, details: PairingDetails, code: str):
        try:
            self.pairing.approve_incoming(details, code)
        except Exception as exc:
            QMessageBox.warning(
                self.window, "Connection failed", str(exc)
            )

    def _reject_incoming(self, request_id: str):
        try:
            self.pairing.reject_incoming(request_id)
        except Exception:
            pass

    def choose_folder(self):
        if (
            self.stopping
            or self._folder_busy
            or self.controller.store.load().shares
        ):
            return

        peer = self.paired_device()
        if peer is None:
            self.show_devices()
            return

        folder = QFileDialog.getExistingDirectory(
            self.window, "Folder to synchronize"
        )
        if not folder:
            return

        self._folder_busy = True

        def task():
            session = None
            try:
                session = self.folders.request(
                    peer, folder, Path(folder).name
                )
                self._outgoing_folder = session

                if self.stopping:
                    session.cancel()
                    return

                share = session.wait()
                if not self.stopping:
                    self.folders.finish_outgoing(share)
                    self.events.put(("folder_sent", None))

            except Exception as exc:
                self.events.put(("folder_error", str(exc)))

            finally:
                if session is not None:
                    session.close()
                self._outgoing_folder = None

        self._spawn("QtChooseFolder", task)
        self.window.status.setText(
            "Waiting for the other computer to choose a folder..."
        )

    def _ready_ids(self) -> set[str]:
        return {
            s.share_id
            for s in self.controller.store.load().shares
            if s.enabled
        }

    def poll(self):
        if not self.started or self.stopping:
            return

        while True:
            try:
                kind, value = self.events.get_nowait()
            except queue.Empty:
                break

            if kind == "pair_session":
                session = value
                key = session.details.request_id
                self._outgoing_pairs[key] = session

                dialog = ConnectDialog(
                    self.window,
                    session.details,
                    lambda code, s=session: self._approve_pair(s, code),
                    lambda s=session: self._reject_pair(s),
                )
                self.pair_dialogs[key] = dialog
                dialog.show()

            elif kind in ("pair_success", "pair_failure"):
                key = (
                    value if kind == "pair_success"
                    else value[0]
                )

                dialog = self.pair_dialogs.pop(key, None)
                if dialog:
                    dialog.close()

                self._outgoing_pairs.pop(key, None)
                self._pair_busy = False

                if kind == "pair_success":
                    if self.devices_dialog:
                        self.devices_dialog.hide()
                    self.on_paired(
                        self.current_peer.name
                        if self.current_peer else "Computer"
                    )
                else:
                    QMessageBox.warning(
                        self.window, "Connection failed", value[1]
                    )

            elif kind == "pair_error":
                self._pair_busy = False
                QMessageBox.warning(
                    self.window, "Connection failed", value
                )

            elif kind == "folder_sent":
                self._folder_busy = False
                self.window.status.setText("Connecting folders...")

            elif kind == "folder_error":
                self._folder_busy = False
                QMessageBox.warning(
                    self.window, "Folder connection failed", value
                )

        incoming = {
            p.request_id: p
            for p in self.pairing.pending()
        }

        for key, details in incoming.items():
            if key not in self._incoming_pairs:
                self._incoming_pairs.add(key)

                dialog = ConnectDialog(
                    self.window,
                    details,
                    lambda code, d=details: self._approve_incoming(d, code),
                    lambda k=key: self._reject_incoming(k),
                )
                self.pair_dialogs[key] = dialog
                dialog.show()

        for key in tuple(self._incoming_pairs):
            if key not in incoming:
                dialog = self.pair_dialogs.pop(key, None)

                if dialog:
                    success = self.pairing.trusted(
                        dialog.details.remote_node_id
                    )
                    dialog.close()

                    if success:
                        peer = self.device(
                            dialog.details.remote_node_id
                        )
                        if peer:
                            self.current_peer = peer

                        if self.devices_dialog:
                            self.devices_dialog.hide()

                        self.on_paired(dialog.details.remote_name)

                self._incoming_pairs.discard(key)

        pending = {
            p.request_id: p
            for p in self.folders.pending()
        }

        for key, request in pending.items():
            if key not in self._incoming_folders:
                self._incoming_folders.add(key)

                dialog = FolderRequestDialog(
                    self.window,
                    request,
                    self.folders.approve,
                    self.folders.reject,
                )
                self.folder_dialogs[key] = dialog
                dialog.show()

        for key in tuple(self._incoming_folders):
            if key not in pending:
                dialog = self.folder_dialogs.pop(key, None)
                if dialog:
                    dialog.close()
                self._incoming_folders.discard(key)

        if (
            self.devices_dialog
            and self.devices_dialog.isVisible()
        ):
            self.devices_dialog.refresh()

        ready = self._ready_ids()
        if ready != self._known_ready:
            self._known_ready = ready
            self.on_ready()

    def close_ui(self):
        if self.devices_dialog:
            self.devices_dialog.close()

        for dialog in (
            *self.pair_dialogs.values(),
            *self.folder_dialogs.values(),
        ):
            dialog.close()

    def stop(self):
        self.stopping = True

        while True:
            try:
                kind, value = self.events.get_nowait()
            except queue.Empty:
                break

            if kind == "pair_session":
                value.close()

        for session in tuple(self._outgoing_pairs.values()):
            session.close()

        if self._outgoing_folder is not None:
            self._outgoing_folder.cancel()

        problems = []

        for service in (
            self.folders,
            self.presence,
            self.pairing,
        ):
            if service:
                try:
                    service.stop()
                except Exception as exc:
                    problems.append(str(exc))

        with self._threads_lock:
            workers = tuple(self._threads)

        for worker in workers:
            if worker is not threading.current_thread():
                worker.join(timeout=7)
                if worker.is_alive():
                    problems.append(
                        f"Still closing {worker.name}"
                    )

        if problems:
            raise RuntimeError("; ".join(problems))
