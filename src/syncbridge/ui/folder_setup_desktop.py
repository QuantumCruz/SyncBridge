
"""Two-folder consent with automatic, retryable connection readiness.

People choose folders only. All activation and network checks happen behind the
scenes. A disabled folder not created by this approved outgoing setup flow is
never automatically activated. Tk calls are restricted to the UI thread.
"""
from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Callable

from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.network.share_activation import (
    ACTIVATION_PORT, ShareActivationClient, ShareActivationService,
)
from syncbridge.network.share_setup import (
    SETUP_PORT, IncomingShareRequest, ShareSetupClient, ShareSetupError,
    ShareSetupService, ShareSetupSession,
)
from syncbridge.storage.config import ConfigStore, ShareConfig
from syncbridge.ui.nearby_devices import NearbyDevice
from syncbridge.ui.readiness_jobs import ReadinessJobs

DEFAULT_SYNC_PORTS = (45843, 45842, 45844)


class FolderSetupController:
    """Owns share negotiation, readiness receiver, and scoped retry worker."""

    def __init__(
        self, store: ConfigStore, *, bind_address: str = "0.0.0.0",
        listen_port: int = SETUP_PORT, remote_port: int = SETUP_PORT,
        sync_ports: tuple[int, int, int] = DEFAULT_SYNC_PORTS,
        activation_port: int | None = None,
        remote_activation_port: int = ACTIVATION_PORT,
        approval_timeout: float = 120.0,
        retry_interval: float = 2.0,
    ) -> None:
        if retry_interval <= 0:
            raise ValueError("retry_interval must be positive")
        self.store = store
        profile = store.path.parent
        self.identity = load_or_create_identity(profile / "identity.json")
        self.trust = TrustStore(profile / "trust.json")
        self.client = ShareSetupClient(self.identity, self.trust, store)
        self.service = ShareSetupService(
            self.identity, self.trust, store,
            bind_address=bind_address, port=listen_port,
            approval_timeout=approval_timeout,
        )
        # Ephemeral setup listeners (unit tests) get an ephemeral activation port.
        # Production devices use the same fixed service ports on distinct hosts.
        if activation_port is None:
            activation_port = ACTIVATION_PORT if listen_port == SETUP_PORT else 0
        self.activation_service = ShareActivationService(
            self.identity, self.trust, store,
            bind_address=bind_address, port=activation_port,
            local_ports=sync_ports,
        )
        self.activation_client = ShareActivationClient(
            self.identity, self.trust, store, local_ports=sync_ports,
        )
        self.remote_port = remote_port
        self.remote_activation_port = remote_activation_port
        self.sync_ports = sync_ports
        self.approval_timeout = approval_timeout
        self.retry_interval = retry_interval
        self.jobs = ReadinessJobs(profile)
        self.on_ready: Callable[[ShareConfig], None] | None = None
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._worker: threading.Thread | None = None
        self._started = False
        self._failures: dict[str, str] = {}

    def start(self) -> None:
        if self._started:
            return
        self.activation_service.start()
        try:
            self.service.start()
        except BaseException:
            self.activation_service.stop()
            raise
        self._stop.clear()
        self._started = True
        self._worker = threading.Thread(
            target=self._retry_loop, name="SyncBridgeFolderReadiness", daemon=False
        )
        self._worker.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        # Stop network services before joining the worker: outgoing connections
        # still have finite timeouts, so shutdown is bounded.
        self.service.stop()
        self.activation_service.stop()
        if self._worker is not None and self._worker is not threading.current_thread():
            self._worker.join(timeout=12)
            if self._worker.is_alive():
                raise RuntimeError("Folder readiness worker did not stop")
        self._worker = None
        self._started = False

    def pending(self) -> tuple[IncomingShareRequest, ...]:
        return self.service.pending()

    def trusted(self, peer_id: str) -> bool:
        return self.trust.get(peer_id) is not None

    def request(self, peer: NearbyDevice, folder: str | Path, name: str) -> ShareSetupSession:
        if not self.trusted(peer.node_id):
            raise ShareSetupError("Pair with this device before requesting a folder")
        return self.client.request(
            peer.address, peer.node_id, folder, name,
            port=self.remote_port, local_ports=self.sync_ports,
            approval_timeout=self.approval_timeout,
        )

    def approve(self, request_id: str, folder: str | Path) -> None:
        self.service.approve(request_id, folder, local_ports=self.sync_ports)

    def reject(self, request_id: str) -> None:
        self.service.reject(request_id)

    def finish_outgoing(self, saved: ShareConfig) -> None:
        """Record actual prior approval; then readiness proceeds without a click."""
        current = self.store.load().get_share(saved.share_id)
        if current != saved or not self.trusted(saved.peer_node_id):
            raise ShareSetupError("Approved folder changed before readiness")
        if saved.enabled or any((
            saved.grant_manifest, saved.grant_read,
            saved.grant_write, saved.grant_agreement,
        )):
            raise ShareSetupError("New folder unexpectedly has active permissions")
        self.jobs.add(saved.share_id, saved.peer_node_id)
        self._wake.set()

    def _retry_loop(self) -> None:
        while not self._stop.is_set():
            try:
                for share_id, peer_id in self.jobs.entries():
                    if self._stop.is_set():
                        return
                    share = self.store.load().get_share(share_id)
                    if share is None or share.peer_node_id != peer_id:
                        self.jobs.remove(share_id, peer_id)
                        continue
                    if not self.trusted(peer_id):
                        # Never enable access to an identity that lost trust.
                        continue
                    try:
                        ready = self.activation_client.activate(
                            share_id, peer_id,
                            port=self.remote_activation_port, timeout=3.0,
                        )
                    except Exception as exc:
                        self._failures[share_id] = str(exc)
                        continue
                    self.jobs.remove(share_id, peer_id)
                    self._failures.pop(share_id, None)
                    if self.on_ready is not None:
                        self.on_ready(ready)
            except Exception as exc:
                # A corrupt journal or settings file must fail closed. No
                # automatic repair, reset, or permission grant is attempted.
                self._failures["journal"] = str(exc)
            self._wake.wait(self.retry_interval)
            self._wake.clear()


class IncomingFolderDialog:
    """One explicit folder choice also approves the pending relationship."""

    def __init__(
        self, parent: tk.Misc, request: IncomingShareRequest,
        approve: Callable[[str, str], None], reject: Callable[[str], None],
    ) -> None:
        self.request = request
        self.approve_callback = approve
        self.reject_callback = reject
        self.decided = False
        self.window = tk.Toplevel(parent)
        self.window.title("SyncBridge — Folder Request")
        self.window.geometry("570x300")
        self.window.protocol("WM_DELETE_WINDOW", self.reject)
        content = ttk.Frame(self.window, padding=18)
        content.pack(fill="both", expand=True)
        ttk.Label(content, text="Choose your folder", font=("Segoe UI", 15, "bold")).pack(anchor="w")
        ttk.Label(
            content,
            text=(f"{request.peer_name} wants to synchronize '{request.display_name}' "
                  "with you. Choose which folder on THIS computer they may sync."),
            wraplength=520, justify="left",
        ).pack(anchor="w", pady=(10, 12))
        ttk.Label(
            content,
            text="The paired computer will be able to read and update files in the folder you choose. "
                 "Conflicts and deletions remain protected.",
            wraplength=520,
        ).pack(anchor="w", pady=(0, 12))
        self.status = tk.StringVar(value="Waiting for your folder choice")
        ttk.Label(content, textvariable=self.status, wraplength=520).pack(anchor="w")
        row = ttk.Frame(content)
        row.pack(side="bottom", fill="x", pady=(14, 0))
        self.yes = ttk.Button(row, text="Choose Folder and Connect", command=self.approve)
        self.yes.pack(side="left")
        self.no = ttk.Button(row, text="Decline", command=self.reject)
        self.no.pack(side="right")

    def approve(self) -> None:
        if self.decided:
            return
        folder = filedialog.askdirectory(parent=self.window, title="Folder to synchronize")
        if not folder:
            return
        if not messagebox.askyesno(
            "Connect folders",
            f"Allow your paired computer to synchronize files in:\n{folder}\n\n"
            "Files may be added or updated. Conflicts and deletions are reviewed separately.\n\nContinue?",
            parent=self.window,
        ):
            return
        try:
            self.approve_callback(self.request.request_id, folder)
        except Exception as exc:
            self.status.set(f"Could not connect: {exc}")
            return
        self.decided = True
        self.yes.configure(state="disabled")
        self.no.configure(state="disabled")
        self.status.set("Waiting for the other computer to finish connecting...")

    def reject(self) -> None:
        if self.decided:
            return
        try:
            self.reject_callback(self.request.request_id)
        except ShareSetupError:
            pass
        self.decided = True
        self.window.destroy()

    def finish(self, saved: bool) -> None:
        self.decided = True
        self.status.set(
            "Folder accepted. SyncBridge is finishing the connection."
            if saved else "The request was cancelled or expired."
        )
        self.yes.configure(state="disabled")
        self.no.configure(text="Close", state="normal", command=self.window.destroy)
        self.window.protocol("WM_DELETE_WINDOW", self.window.destroy)

    def destroy(self) -> None:
        self.decided = True
        try:
            self.window.destroy()
        except tk.TclError:
            pass


class FolderSetupUI:
    """Tk bridge; readiness retries occur off the UI thread."""

    def __init__(
        self, parent: tk.Misc, controller: FolderSetupController,
        visible_devices: Callable[[], tuple[NearbyDevice, ...]],
        on_saved: Callable[[], None],
    ) -> None:
        self.parent = parent
        self.controller = controller
        self.visible_devices = visible_devices
        self.on_saved = on_saved
        self._events: queue.SimpleQueue[tuple[str, object]] = queue.SimpleQueue()
        self._dialogs: dict[str, IncomingFolderDialog] = {}
        self._outgoing: ShareSetupSession | None = None
        self._worker: threading.Thread | None = None
        self._busy = False
        self._closed = False
        self._timer: str | None = None
        self._last_ready: tuple[str, ...] = ()

    def start(self) -> None:
        self.controller.on_ready = lambda item: self._events.put(("ready", item))
        self.controller.start()
        self._last_ready = self._ready_shares()
        self._tick()

    def _ready_shares(self) -> tuple[str, ...]:
        return tuple(sorted(
            item.share_id for item in self.controller.store.load().shares if item.enabled
        ))

    def request(self) -> None:
        if self._closed or self._busy:
            return
        peers = tuple(d for d in self.visible_devices() if self.controller.trusted(d.node_id))
        if not peers:
            messagebox.showinfo(
                "No paired computer online",
                "Pair with a computer in Nearby Devices first.", parent=self.parent,
            )
            return
        if len(peers) == 1:
            peer = peers[0]
        else:
            selection = simpledialog.askinteger(
                "Choose paired computer",
                "Choose a device number:\n" + "\n".join(
                    f"{i}. {dev.name} ({dev.address})" for i, dev in enumerate(peers, 1)
                ), minvalue=1, maxvalue=len(peers), parent=self.parent,
            )
            if selection is None:
                return
            peer = peers[selection - 1]
        folder = filedialog.askdirectory(title="Choose your folder", parent=self.parent)
        if not folder:
            return
        name = Path(folder).name
        if not messagebox.askyesno(
            "Connect folders",
            f"Ask {peer.name} to connect their folder with:\n{folder}\n\n"
            "Both computers will be able to read and update their selected folders. "
            "Conflicts and deletions remain protected.\n\nContinue?",
            parent=self.parent,
        ):
            return
        self._busy = True

        def worker() -> None:
            session = None
            try:
                session = self.controller.request(peer, folder, name)
                self._outgoing = session
                saved = session.wait()
                self.controller.finish_outgoing(saved)
                self._events.put(("saved", saved))
            except Exception as exc:
                self._events.put(("error", str(exc)))
            finally:
                if session is not None:
                    session.close()
                self._outgoing = None
                self._events.put(("finished", None))

        self._worker = threading.Thread(
            target=worker, name="SyncBridgeFolderSetup", daemon=False,
        )
        self._worker.start()

    def _tick(self) -> None:
        if self._closed:
            return
        while True:
            try:
                kind, value = self._events.get_nowait()
            except queue.Empty:
                break
            if kind == "finished":
                self._busy = False
            elif kind == "saved":
                self.on_saved()
                messagebox.showinfo(
                    "Folder accepted",
                    "Both folders have been chosen. SyncBridge is completing the connection.",
                    parent=self.parent,
                )
            elif kind == "ready":
                self.on_saved()
                messagebox.showinfo(
                    "Folders connected",
                    f"'{value.display_name}' is ready to synchronize.",
                    parent=self.parent,
                )
            elif kind == "error":
                messagebox.showerror("Could not connect folders", str(value), parent=self.parent)

        current = {item.request_id: item for item in self.controller.pending()}
        for request_id, request in current.items():
            if request_id not in self._dialogs:
                self._dialogs[request_id] = IncomingFolderDialog(
                    self.parent, request, self.controller.approve, self.controller.reject,
                )
        for request_id, dialog in tuple(self._dialogs.items()):
            if request_id not in current:
                share = self.controller.store.load().get_share(dialog.request.share_id)
                dialog.finish(share is not None)
                if share is not None:
                    self.on_saved()
                del self._dialogs[request_id]

        ready = self._ready_shares()
        if ready != self._last_ready:
            self._last_ready = ready
            self.on_saved()
        self._timer = self.parent.after(250, self._tick)

    def stop(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._timer is not None:
            try:
                self.parent.after_cancel(self._timer)
            except tk.TclError:
                pass
        if self._outgoing is not None:
            self._outgoing.cancel()
        self.controller.stop()
        for dialog in self._dialogs.values():
            dialog.destroy()
        self._dialogs.clear()
        if self._worker is not None and self._worker is not threading.current_thread():
            self._worker.join(timeout=8)
