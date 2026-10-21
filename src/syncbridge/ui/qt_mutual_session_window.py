
"""Explicit, mutually approved live sessions for the SyncBridge Qt desktop.

Saved device trust, chosen folders, synchronization history and recovery data
survive restarts. A live connection does not.

The desktop starts disconnected. Both devices must agree on a fresh session
before manual Preview or Sync is enabled. A normal departure notifies the
peer. Unexpected loss is detected through authenticated periodic checks.

The synchronization engine, permissions and fencing remain unchanged.
"""
from __future__ import annotations

import queue
import threading
import time

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QMessageBox, QPushButton

from syncbridge.network.session_control import (
    PeerSessionClient,
    PeerSessionService,
    SessionControlError,
    new_session_id,
    session_port_for_transfer,
)
from syncbridge.ui.qt_direct_discovery_window import (
    SyncBridgeDiscoveryWindow,
)


class SyncBridgeMutualSessionWindow(SyncBridgeDiscoveryWindow):
    """A saved relationship is never treated as an active connection."""

    CHECK_INTERVAL_MS = 3000
    MISSED_CHECKS = 3
    APPROVAL_TIMEOUT_SECONDS = 65.0

    def __init__(self, *args, **kwargs):
        self._live_session = None
        self._session_online = False
        self._session_pending = False
        self._session_service = None
        self._session_client = None
        self._service_signature = None
        self._control_events = queue.SimpleQueue()
        self._check_inflight = False
        self._missed_checks = 0
        self._stop_when_idle = False
        self._disconnection_message = ""
        super().__init__(*args, **kwargs)

        self.reconnect_button = QPushButton(
            "Connect to saved computer",
            self,
        )
        self.reconnect_button.setObjectName("primary")
        self.reconnect_button.clicked.connect(
            self._begin_outgoing,
        )
        self.centralWidget().layout().insertWidget(
            3,
            self.reconnect_button,
        )

        self._session_timer = QTimer(self)
        self._session_timer.setInterval(
            self.CHECK_INTERVAL_MS
        )
        self._session_timer.timeout.connect(
            self._check_live_peer,
        )
        self._session_timer.start()
        self._update_buttons()

    def _auto_connect(self):
        """Do not restore live sessions on application startup."""
        return

    def _saved_share(self):
        shares = [
            share
            for share in self.controller.store.load().shares
            if share.enabled
        ]
        return shares[0] if len(shares) == 1 else None

    def _peer_name(self):
        share = self._saved_share()
        if share is None:
            return "the other computer"

        onboarding = self.onboarding
        if onboarding is not None and onboarding.pairing is not None:
            trusted = onboarding.pairing.trust.get(
                share.peer_node_id
            )
            if trusted is not None:
                return trusted.name

        return share.remote_host or "the other computer"

    def _load_profile(self):
        super()._load_profile()

        if not self._configured:
            return

        try:
            profile = self.controller.profile()
        except Exception:
            return

        name = self._peer_name()

        if self._session_online and self.controller.running:
            self.connection.setText(
                f"Connected with {name} · {profile.folder_name}\n"
                f"My folder: {profile.local_root}"
            )
            self.hint.setText(
                "Both computers have confirmed the current connection."
            )
            if self.status.text() in (
                "Not connected",
                "Connecting...",
                "Waiting for approval",
                "Other computer offline",
            ):
                self.status.setText("Connected")
            return

        self.connection.setText(
            f"Previously paired with {name} · {profile.folder_name}\n"
            f"My folder: {profile.local_root}"
        )
        self.hint.setText(
            "Your previous pairing and folders are saved. "
            "Choose Connect when both computers are ready."
        )
        self.status.setText(
            "Connecting..."
            if self._session_pending
            else "Not connected"
        )

    def _update_buttons(self):
        super()._update_buttons()

        if hasattr(self, "preview_button") and not self._session_online:
            self.preview_button.setEnabled(False)
            self.sync_button.setEnabled(False)

        if hasattr(self, "reconnect_button"):
            share = self._saved_share()
            visible = bool(share) and not self._session_online
            self.reconnect_button.setVisible(visible)
            self.reconnect_button.setText(
                f"Connect to {self._peer_name()}"
            )
            self.reconnect_button.setEnabled(
                visible
                and self.onboarding is not None
                and self.onboarding.started
                and self._session_service is not None
                and not self._busy
                and not self._session_pending
                and not self._closing
                and not self._shutting_down
                and not self.controller.running
            )

        if hasattr(self, "disconnect_button"):
            self.disconnect_button.setVisible(
                self._session_online
                and self.controller.running
                and not self._closing
            )
            self.disconnect_button.setEnabled(
                self._session_online
                and self.controller.running
                and not self._busy
                and not self._closing
            )

    def _start_network(self):
        super()._start_network()
        self._ensure_session_service()
        self._load_profile()
        self._update_buttons()

    def _folders_ready(self):
        super()._folders_ready()
        self._ensure_session_service()

        if self._configured and not self._session_online:
            self.summary.setText(
                "Folders are ready. Choose Connect when "
                "you want to start a session."
            )

        self._load_profile()
        self._update_buttons()

    def _ensure_session_service(self):
        onboarding = self.onboarding
        share = self._saved_share()

        if (
            onboarding is None
            or not onboarding.started
            or onboarding.pairing is None
            or share is None
            or self._closing
        ):
            if self._session_service is not None and share is None:
                old = self._session_service
                self._session_service = None
                self._session_client = None
                self._service_signature = None
                old.stop()
            return

        runtime = self.controller.runtime
        local_ports = runtime.listen_ports
        transfer_port = (
            local_ports[1]
            if local_ports is not None
            else share.transfer_port
        )

        port = session_port_for_transfer(transfer_port)
        address = onboarding.options.pairing_bind
        signature = (
            share.share_id,
            share.peer_node_id,
            address,
            port,
        )

        if (
            signature == self._service_signature
            and self._session_service is not None
        ):
            return

        if self._session_service is not None:
            self._session_service.stop()
            self._session_service = None

        pairing = onboarding.pairing
        service = PeerSessionService(
            pairing.identity,
            pairing.trust,
            share.share_id,
            share.peer_node_id,
            bind_address=address,
            port=port,
            on_event=lambda kind, session: (
                self._control_events.put((kind, session))
            ),
        )

        try:
            service.start()
        except Exception as exc:
            self._service_signature = None
            self._session_client = None
            self.summary.setText(
                f"Could not start connection requests: {exc}"
            )
            return

        self._session_service = service
        self._session_client = PeerSessionClient(
            pairing.identity,
            pairing.trust,
        )
        self._service_signature = signature
        self._update_buttons()

    def _target(self):
        share = self._saved_share()
        if share is None or share.remote_host is None:
            raise SessionControlError(
                "No approved folder relationship is available"
            )

        return (
            share.remote_host,
            session_port_for_transfer(
                share.transfer_port
            ),
            share.peer_node_id,
            share.share_id,
        )

    def _paired(self, name):
        super()._paired(name)

        # Clicking an already trusted computer is an explicit user action.
        # Selecting a newly paired computer still proceeds to folder setup.
        selected = (
            self.onboarding.current_peer
            if self.onboarding is not None
            else None
        )
        share = self._saved_share()

        if (
            selected is not None
            and share is not None
            and selected.node_id == share.peer_node_id
            and not self._session_online
            and not self._busy
        ):
            self._begin_outgoing()

    def _begin_outgoing(self):
        if (
            self._session_online
            or self._session_pending
            or self._busy
            or self._closing
            or self.controller.running
        ):
            return

        self._ensure_session_service()

        if (
            self._session_service is None
            or self._session_client is None
            or self._saved_share() is None
        ):
            self.summary.setText(
                "Choose a paired computer and finish folder setup first."
            )
            return

        session_id = new_session_id()
        self._session_pending = True

        self._work(
            "connect",
            lambda: self._connect_outgoing(session_id),
        )
        self.status.setText("Waiting for approval")
        self.summary.setText(
            f"Waiting for {self._peer_name()} to accept "
            "your connection request..."
        )

    def _connect_outgoing(self, session_id):
        service = self._session_service
        client = self._session_client
        target = self._target()
        started = False
        succeeded = False

        try:
            state = client.request(
                *target, session_id, "session_invite"
            )

            if state != "waiting":
                raise SessionControlError(
                    "The other computer could not accept an invitation"
                )

            deadline = (
                time.monotonic()
                + self.APPROVAL_TIMEOUT_SECONDS
            )

            while time.monotonic() < deadline:
                if self._closing:
                    raise SessionControlError(
                        "The application is closing"
                    )

                state = client.request(
                    *target, session_id, "session_status"
                )

                if state == "approved":
                    break

                if state != "waiting":
                    raise SessionControlError(
                        "The invitation was declined or expired"
                    )

                time.sleep(0.35)
            else:
                raise SessionControlError(
                    "The other computer did not respond in time"
                )

            self._prepare_listener()
            self.controller.start()
            started = True
            service.activate_outgoing(session_id)

            if client.request(
                *target, session_id, "session_commit"
            ) != "active":
                raise SessionControlError(
                    "Both computers could not agree on the connection"
                )

            if client.request(
                *target, session_id, "session_ping"
            ) != "active":
                raise SessionControlError(
                    "The other computer did not confirm the session"
                )

            succeeded = True
            return session_id

        finally:
            if not succeeded:
                if started:
                    self.controller.stop()

                service.clear(session_id)

                try:
                    client.request(
                        *target,
                        session_id,
                        "session_leave",
                    )
                except Exception:
                    pass

    def _accept_incoming(self, session_id):
        service = self._session_service
        client = self._session_client
        target = self._target()
        started = False
        succeeded = False

        try:
            self._prepare_listener()
            self.controller.start()
            started = True

            if not service.approve(session_id):
                raise SessionControlError(
                    "The incoming invitation is no longer available"
                )

            deadline = (
                time.monotonic()
                + self.APPROVAL_TIMEOUT_SECONDS
            )

            while time.monotonic() < deadline:
                if self._closing:
                    raise SessionControlError(
                        "The application is closing"
                    )

                if service.active_session == session_id:
                    state = client.request(
                        *target,
                        session_id,
                        "session_ping",
                    )

                    if state == "active":
                        succeeded = True
                        return session_id

                time.sleep(0.2)

            raise SessionControlError(
                "The other computer did not finish connecting"
            )

        finally:
            if not succeeded:
                if started:
                    self.controller.stop()

                service.clear(session_id)

    def _handle_invitation(self, session_id):
        service = self._session_service

        if (
            service is None
            or service.pending_invitation != session_id
        ):
            return

        if (
            self._closing
            or self._busy
            or self._session_pending
            or self._session_online
            or self.controller.running
        ):
            service.reject(session_id)
            return

        answer = QMessageBox.question(
            self,
            "Connection request",
            f"{self._peer_name()} wants to connect to you.\n\n"
            "Your previously approved folders will be used. "
            "Both computers must confirm a fresh connection.\n\n"
            "Accept this connection?",
            QMessageBox.StandardButton.Yes
            | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if answer != QMessageBox.StandardButton.Yes:
            service.reject(session_id)
            return

        self._session_pending = True
        self._work(
            "connect",
            lambda: self._accept_incoming(session_id),
        )
        self.summary.setText(
            "Establishing a secure connection with "
            f"{self._peer_name()}..."
        )

    def _discard_session_preview(self):
        self._preview = None
        self._loaded.clear()
        self.table.setRowCount(0)
        self.remote_table.setRowCount(0)

    def _mark_disconnected(self, message):
        old_session = self._live_session
        self._live_session = None
        self._session_online = False
        self._session_pending = False
        self._check_inflight = False
        self._missed_checks = 0
        self._disconnection_message = message

        if self._session_service is not None:
            self._session_service.clear(old_session)

        self._discard_session_preview()
        self._load_profile()
        self.summary.setText(message)
        self._update_buttons()

    def _check_live_peer(self):
        if (
            not self._session_online
            or self._live_session is None
            or self._check_inflight
            or self._closing
            or self._session_client is None
        ):
            return

        session_id = self._live_session
        client = self._session_client
        target = self._target()
        self._check_inflight = True

        def worker():
            try:
                state = client.request(
                    *target,
                    session_id,
                    "session_ping",
                )
                success = state == "active"
            except Exception:
                success = False

            self._control_events.put((
                "check-ok" if success else "check-failed",
                session_id,
            ))

        threading.Thread(
            target=worker,
            name="SyncBridgeSessionHeartbeat",
            daemon=True,
        ).start()

    def _remote_disconnected(self, message):
        if not self._session_online:
            return

        self._mark_disconnected(message)
        self._stop_when_idle = True

    def _drain(self):
        super()._drain()

        for _ in range(32):
            try:
                kind, session_id = (
                    self._control_events.get_nowait()
                )
            except queue.Empty:
                break

            if self._closing:
                continue

            if kind == "invite":
                self._handle_invitation(session_id)

            elif kind == "left":
                if self._live_session == session_id:
                    self._remote_disconnected(
                        "The other computer disconnected. "
                        "Your pairing and files are preserved."
                    )

            elif (
                kind == "check-ok"
                and self._live_session == session_id
            ):
                self._check_inflight = False
                self._missed_checks = 0

            elif (
                kind == "check-failed"
                and self._live_session == session_id
            ):
                self._check_inflight = False
                self._missed_checks += 1

                if self._missed_checks >= self.MISSED_CHECKS:
                    self._remote_disconnected(
                        "The other computer is offline or unreachable. "
                        "Your pairing and files are preserved."
                    )

        # Error events for connect are handled by the existing
        # Qt base window, which also resets its worker busy flag.
        if (
            self._session_pending
            and not self._busy
            and not self._session_online
        ):
            self._session_pending = False
            self._load_profile()
            self._update_buttons()

        if (
            self._stop_when_idle
            and not self._busy
            and self.controller.running
            and not self._closing
        ):
            self._stop_when_idle = False
            self._work("stop", self.controller.stop)

    def _check_changes(self):
        if not self._session_online:
            self.summary.setText(
                "Connect to the other computer before Preview."
            )
            return

        super()._check_changes()

    def _check_in_background(self):
        if self._session_online:
            super()._check_in_background()

    def _sync_files(self):
        if not self._session_online:
            self.summary.setText(
                "Connect to the other computer before Sync."
            )
            return

        super()._sync_files()

    def _leave_and_stop(self, session_id, target):
        try:
            if (
                session_id is not None
                and target is not None
                and self._session_client is not None
            ):
                self._session_client.request(
                    *target,
                    session_id,
                    "session_leave",
                )
        except Exception:
            # The other computer can independently detect loss
            # through authenticated health checks.
            pass
        finally:
            self.controller.stop()

    def _toggle_connection(self):
        if (
            not self._session_online
            or self._busy
            or self._closing
        ):
            return

        session_id = self._live_session
        target = self._target()

        self._mark_disconnected(
            "Disconnected. You can connect again when ready."
        )
        self._work(
            "stop",
            lambda: self._leave_and_stop(
                session_id, target
            ),
        )

    def _stop_and_forget(self, share_id):
        # The existing Change folders workflow is preserved,
        # including consent from both computers.
        session_id = self._live_session
        target = None

        if session_id is not None:
            try:
                target = self._target()
            except Exception:
                pass

        self._mark_disconnected(
            "Changing the shared folders..."
        )
        self._leave_and_stop(session_id, target)
        return super()._stop_and_forget(share_id)

    def _finish(self, kind, result):
        if kind == "connect":
            self._session_pending = False
            self._session_online = True
            self._live_session = result
            self._missed_checks = 0
            self._check_inflight = False
            self._disconnection_message = ""
            self._discard_session_preview()
            self._load_profile()
            self.summary.setText(
                "Connected securely. Preview the latest "
                "differences before synchronizing."
            )
            self._update_buttons()
            return

        super()._finish(kind, result)

        if kind == "stop":
            if not self.controller.running:
                self._live_session = None
                self._session_online = False
                self._session_pending = False
                self._ensure_session_service()
                self._load_profile()
                self._update_buttons()

    def _shutdown(self):
        self._shutting_down = True
        self.status.setText("Closing...")
        self._show_activity(
            "Closing network connections..."
        )

        session_id = self._live_session
        try:
            target = (
                self._target()
                if session_id is not None
                else None
            )
        except Exception:
            target = None

        service = self._session_service

        def worker():
            problems = []

            try:
                if (
                    session_id is not None
                    and target is not None
                    and self._session_client is not None
                ):
                    self._session_client.request(
                        *target,
                        session_id,
                        "session_leave",
                    )
            except Exception:
                pass

            if service is not None:
                try:
                    service.stop()
                except Exception as exc:
                    problems.append(str(exc))

            if self.onboarding is not None:
                try:
                    self.onboarding.stop()
                except Exception as exc:
                    problems.append(str(exc))

            try:
                self.controller.stop()
            except Exception as exc:
                problems.append(str(exc))

            self._events.put((
                "shutdown-error" if problems else "shutdown-ok",
                "; ".join(problems) if problems else None,
            ))

        self._worker = threading.Thread(
            target=worker,
            name="SyncBridgeSessionShutdown",
            daemon=False,
        )
        self._worker.start()

    def closeEvent(self, event):
        if hasattr(self, "_session_timer"):
            self._session_timer.stop()

        super().closeEvent(event)
