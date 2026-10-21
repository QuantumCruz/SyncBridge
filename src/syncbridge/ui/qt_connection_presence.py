
"""Live authenticated peer state for the standard SyncBridge Qt desktop.

A saved pairing/share is not a live connection. The sync runtime may listen
for incoming authenticated requests while its peer is temporarily offline,
but Preview and Sync are disabled until a fresh presence proof succeeds.

No file, pairing record, or synchronization history is erased on disconnect.
"""
from __future__ import annotations

import queue
import threading

from PySide6.QtCore import QTimer

from syncbridge.network.peer_presence import (
    PeerPresenceClient,
    PeerPresenceService,
    presence_port_for_transfer,
)
from syncbridge.ui.qt_direct_discovery_window import (
    SyncBridgeDiscoveryWindow,
)


class SyncBridgePresenceWindow(SyncBridgeDiscoveryWindow):
    """Desktop window with two-way live connection status."""

    PROBE_INTERVAL_MS = 3000
    MISSED_PROBES_OFFLINE = 3

    def __init__(self, *args, **kwargs) -> None:
        # The inherited constructor calls _load_profile
        # and _update_buttons, so initialize state first.
        self._presence_online = False
        self._presence_seen = False
        self._presence_epoch = None
        self._goodbye_epoch = None
        self._presence_failures = 0
        self._presence_generation = 0
        self._presence_inflight = False
        self._presence_events = queue.SimpleQueue()
        self._presence_service = None
        self._presence_client = None
        self._presence_target = None
        self._presence_reason = (
            "Checking whether the other computer is online..."
        )

        super().__init__(*args, **kwargs)

        self._presence_timer = QTimer(self)
        self._presence_timer.setInterval(
            self.PROBE_INTERVAL_MS
        )
        self._presence_timer.timeout.connect(
            self._probe_peer
        )
        self._presence_timer.start()

    def _load_profile(self) -> None:
        super()._load_profile()

        if (
            not self._configured
            or not self.controller.running
            or self._paused
            or self._closing
            or self._presence_online
        ):
            return

        profile = self.controller.profile()

        self.connection.setText(
            f"Saved pairing · {profile.folder_name}\n"
            f"My folder: {profile.local_root}"
        )

        self.hint.setText(
            "Pairing and folders are saved. "
            "A live connection is required to sync."
        )

        self.status.setText(
            "Computer offline"
            if self._presence_seen
            else "Checking connection..."
        )

    def _update_buttons(self) -> None:
        super()._update_buttons()

        if (
            not self._presence_online
            and hasattr(self, "preview_button")
        ):
            self.preview_button.setEnabled(False)
            self.sync_button.setEnabled(False)

    def _discard_preview(self) -> None:
        self._preview = None
        self._loaded.discard("remote")
        self._loaded.discard("preview")
        self.remote_table.setRowCount(0)
        self.table.setRowCount(0)

    def _online(self, epoch: str) -> None:
        # A goodbye may arrive just before an older probe reply.
        # The previous session must stay disconnected.
        if epoch == self._goodbye_epoch:
            return

        self._goodbye_epoch = None

        previously_live = self._presence_online
        changed_session = (
            self._presence_epoch is not None
            and self._presence_epoch != epoch
        )

        self._presence_online = True
        self._presence_seen = True
        self._presence_failures = 0
        self._presence_epoch = epoch

        if not previously_live or changed_session:
            self._discard_preview()
            self._load_profile()
            self.summary.setText(
                "Connected securely. Preview both folders "
                "for the latest differences."
            )

        self._update_buttons()

    def _offline(self, message: str) -> None:
        was_live = self._presence_online

        self._presence_online = False
        self._presence_seen = True
        self._presence_reason = message

        if was_live:
            self._discard_preview()

        if (
            self.controller.running
            and not self._paused
            and not self._closing
        ):
            self._load_profile()
            self.summary.setText(
                message + " Your pairing and folders are saved."
            )

        self._update_buttons()

    def _start_presence(self) -> None:
        self._stop_presence()

        runtime = self.controller.runtime
        if not self.controller.running:
            return

        profile = self.controller.profile()

        selected = next(
            share
            for share in self.controller.store.load().shares
            if share.enabled
        )

        transfer_port = (
            runtime.transfer_server.bound_port
        )

        if transfer_port is None:
            self._offline(
                "The local transfer listener isn't ready."
            )
            return

        self._presence_generation += 1
        generation = self._presence_generation

        service = PeerPresenceService(
            runtime.identity,
            runtime.trust_store,
            selected.share_id,
            profile.peer_node_id,
            bind_address=runtime.bind_address,
            port=presence_port_for_transfer(
                transfer_port
            ),
            on_goodbye=lambda: self._presence_events.put(
                ("goodbye", generation, None)
            ),
        )

        try:
            service.start()
        except Exception:
            self._offline(
                "Live connection checks are unavailable "
                "on this computer."
            )
            return

        self._presence_service = service
        self._presence_client = PeerPresenceClient(
            runtime.identity,
            runtime.trust_store,
        )

        self._presence_target = (
            profile.remote_host,
            presence_port_for_transfer(
                selected.transfer_port
            ),
            profile.peer_node_id,
            selected.share_id,
        )

        self._presence_online = False
        self._goodbye_epoch = None
        self._presence_failures = 0
        self._presence_inflight = False
        self._presence_seen = False

        self._load_profile()
        self._update_buttons()
        self._probe_peer()

    def _stop_presence(self) -> None:
        self._presence_generation += 1

        service, self._presence_service = (
            self._presence_service,
            None,
        )

        self._presence_client = None
        self._presence_target = None
        self._presence_inflight = False
        self._presence_online = False

        if service is not None:
            service.stop()

    def _probe_peer(self) -> None:
        if (
            self._closing
            or self._paused
            or not self.controller.running
            or self._presence_service is None
            or self._presence_inflight
            or self._presence_client is None
            or self._presence_target is None
        ):
            return

        self._presence_inflight = True
        generation = self._presence_generation
        client = self._presence_client
        target = self._presence_target

        def worker():
            try:
                epoch = client.probe(*target)
            except Exception:
                self._presence_events.put(
                    ("miss", generation, None)
                )
            else:
                self._presence_events.put(
                    ("live", generation, epoch)
                )

        threading.Thread(
            target=worker,
            name="SyncBridgePresenceCheck",
            daemon=True,
        ).start()

    def _drain(self) -> None:
        super()._drain()

        for _ in range(32):
            try:
                kind, generation, value = (
                    self._presence_events.get_nowait()
                )
            except queue.Empty:
                break

            if (
                generation != self._presence_generation
                or self._closing
            ):
                continue

            if kind == "goodbye":
                self._goodbye_epoch = (
                    self._presence_epoch
                )
                self._presence_failures = (
                    self.MISSED_PROBES_OFFLINE
                )
                self._offline(
                    "The other computer disconnected."
                )

            elif kind == "miss":
                self._presence_inflight = False
                self._presence_failures += 1

                if (
                    self._presence_failures
                    >= self.MISSED_PROBES_OFFLINE
                ):
                    self._offline(
                        "The other computer is offline "
                        "or unreachable."
                    )

            elif kind == "live":
                self._presence_inflight = False
                self._online(value)

    def _check_in_background(self) -> None:
        if self._presence_online:
            super()._check_in_background()

    def _check_changes(self) -> None:
        if not self._presence_online:
            self.summary.setText(
                "Wait until the other computer reconnects "
                "before Preview."
            )
            return

        super()._check_changes()

    def _sync_files(self) -> None:
        if not self._presence_online:
            self.summary.setText(
                "Cannot synchronize while the other "
                "computer is offline."
            )
            return

        super()._sync_files()

    def _announce_goodbye(self) -> None:
        client = self._presence_client
        target = self._presence_target
        epoch = self._presence_epoch

        if (
            client is None
            or target is None
            or epoch is None
        ):
            return

        try:
            client.goodbye(*target, epoch)
        except Exception:
            # Heartbeats handle an unreachable peer.
            pass

    def _stop_and_announce(self) -> None:
        self._announce_goodbye()
        self.controller.stop()

    def _toggle_connection(self) -> None:
        if not self.controller.running or self._busy:
            return

        self._paused = True
        self._paired_name = ""
        self._discard_preview()
        self._loaded.clear()

        self.table.setRowCount(0)
        self.local_table.setRowCount(0)
        self.remote_table.setRowCount(0)

        self._work(
            "stop",
            self._stop_and_announce,
        )

    def _finish(self, kind: str, result: object) -> None:
        super()._finish(kind, result)

        if kind == "connect":
            self._start_presence()
        elif kind == "stop":
            self._stop_presence()

        self._update_buttons()

    def _shutdown(self) -> None:
        # Goodbye precedes stopping local authenticated listeners.
        self._shutting_down = True
        self.status.setText("Closing...")
        self._show_activity(
            "Closing network connections..."
        )

        def worker():
            problems = []

            self._announce_goodbye()

            try:
                if self._presence_service is not None:
                    self._presence_service.stop()
            except Exception as exc:
                problems.append(str(exc))

            if self.onboarding:
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
            name="SyncBridgePresenceShutdown",
            daemon=False,
        )
        self._worker.start()

    def closeEvent(self, event) -> None:
        if hasattr(self, "_presence_timer"):
            self._presence_timer.stop()

        super().closeEvent(event)
