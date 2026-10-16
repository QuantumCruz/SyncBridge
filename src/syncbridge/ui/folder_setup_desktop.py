
"""Manual folder-relationship setup, separate from file access activation.

Uses the authenticated encrypted ShareSetup protocol. A saved share is disabled
with no grants, until a distinct activation phase. Only the GUI thread uses Tk.
"""
from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Callable

from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.network.share_setup import (
    SETUP_PORT, IncomingShareRequest, ShareSetupClient, ShareSetupError,
    ShareSetupService, ShareSetupSession,
)
from syncbridge.storage.config import ConfigStore
from syncbridge.ui.nearby_devices import NearbyDevice


DEFAULT_SYNC_PORTS = (45843, 45842, 45844)


class FolderSetupController:
    """Headless controller: never enables a share or grants a file permission."""

    def __init__(
        self, store: ConfigStore, *, bind_address: str = "0.0.0.0",
        listen_port: int = SETUP_PORT, remote_port: int = SETUP_PORT,
        sync_ports: tuple[int, int, int] = DEFAULT_SYNC_PORTS,
        approval_timeout: float = 120.0,
    ) -> None:
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
        self.remote_port = remote_port
        self.sync_ports = sync_ports
        self.approval_timeout = approval_timeout

    def start(self) -> None:
        self.service.start()

    def stop(self) -> None:
        self.service.stop()

    def pending(self) -> tuple[IncomingShareRequest, ...]:
        return self.service.pending()

    def trusted(self, peer_id: str) -> bool:
        return self.trust.get(peer_id) is not None

    def request(
        self, peer: NearbyDevice, folder: str | Path, name: str,
    ) -> ShareSetupSession:
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


class IncomingFolderDialog:
    """Approves a trusted peer's request only after local folder selection."""

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
        self.window.geometry("580x310")
        self.window.protocol("WM_DELETE_WINDOW", self.reject)
        content = ttk.Frame(self.window, padding=18)
        content.pack(fill="both", expand=True)
        ttk.Label(content, text="Incoming folder request", font=("Segoe UI", 15, "bold")).pack(anchor="w")
        ttk.Label(
            content,
            text=f"{request.peer_name} wants to set up: {request.display_name}\n"
                 f"Verified device ID: {request.peer_node_id[:16]}…\n"
                 f"Observed address: {request.peer_address}",
            wraplength=535, justify="left",
        ).pack(anchor="w", pady=(10, 12))
        ttk.Label(
            content,
            text="Choose YOUR local folder. No files will be shared or transferred yet.",
            wraplength=530,
        ).pack(anchor="w", pady=(0, 12))
        self.status = tk.StringVar(value="Waiting for your decision...")
        ttk.Label(content, textvariable=self.status, wraplength=530).pack(anchor="w")
        row = ttk.Frame(content)
        row.pack(side="bottom", fill="x", pady=(14, 0))
        self.yes = ttk.Button(row, text="Choose Folder and Approve", command=self.approve)
        self.yes.pack(side="left")
        self.no = ttk.Button(row, text="Decline", command=self.reject)
        self.no.pack(side="right")

    def approve(self) -> None:
        if self.decided:
            return
        folder = filedialog.askdirectory(
            parent=self.window, title="Choose your own SyncBridge folder"
        )
        if not folder:
            return
        if not messagebox.askyesno(
            "Approve disabled folder relationship",
            f"Save a folder relationship for:\n{folder}\n\n"
            "It will remain DISABLED. No remote file access is granted.",
            parent=self.window,
        ):
            return
        try:
            self.approve_callback(self.request.request_id, folder)
        except Exception as exc:
            self.status.set(f"Could not approve: {exc}")
            return
        self.decided = True
        self.yes.configure(state="disabled")
        self.no.configure(state="disabled")
        self.status.set("Approved. Waiting for the encrypted setup to finish...")

    def reject(self) -> None:
        if self.decided:
            return
        try:
            self.reject_callback(self.request.request_id)
        except ShareSetupError:
            pass
        self.decided = True
        self.window.destroy()

    def finish(self, success: bool) -> None:
        self.decided = True
        self.status.set(
            "Folder relationship saved safely (disabled)." if success
            else "Request cancelled, expired, or interrupted."
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
    """Tk bridge for local selections, incoming consent, and worker-thread I/O."""

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

    def start(self) -> None:
        self.controller.start()
        self._tick()

    def request(self) -> None:
        if self._closed or self._busy:
            return
        peers = tuple(
            item for item in self.visible_devices()
            if self.controller.trusted(item.node_id)
        )
        if not peers:
            messagebox.showinfo(
                "No paired devices online",
                "First pair with a visible computer in Nearby Devices.", parent=self.parent,
            )
            return
        if len(peers) == 1:
            peer = peers[0]
        else:
            # Pick from a proper selection dialog, not an unverified typed ID.
            chosen: list[NearbyDevice] = []
            dialog = tk.Toplevel(self.parent)
            dialog.title("Choose paired computer")
            dialog.transient(self.parent)
            dialog.grab_set()
            box = ttk.Frame(dialog, padding=16)
            box.pack(fill="both", expand=True)
            listing = tk.Listbox(box, width=55, height=min(8, len(peers)))
            listing.pack(fill="both", expand=True)
            for item in peers:
                listing.insert("end", f"{item.name} — {item.address} ({item.node_id[:12]})")
            listing.selection_set(0)

            def pick():
                selection = listing.curselection()
                if selection:
                    chosen.append(peers[selection[0]])
                dialog.destroy()

            ttk.Button(box, text="Select", command=pick).pack(pady=(8, 0))
            dialog.wait_window()
            if not chosen:
                return
            peer = chosen[0]
        folder = filedialog.askdirectory(
            title="Choose YOUR local folder to synchronize", parent=self.parent,
        )
        if not folder:
            return
        name = simpledialog.askstring(
            "Name the folder relationship", "Share name:",
            initialvalue=Path(folder).name, parent=self.parent,
        )
        if name is None:
            return
        if not messagebox.askyesno(
            "Request folder setup",
            f"Send {peer.name} a request for '{name}'?\n\n"
            "They must choose their own folder and approve. "
            "Both configurations remain disabled until a later activation step.",
            parent=self.parent,
        ):
            return
        self._busy = True

        def worker() -> None:
            try:
                session = self.controller.request(peer, folder, name)
                self._outgoing = session
                saved = session.wait()
                self._events.put(("saved", saved))
            except Exception as exc:
                self._events.put(("error", str(exc)))
            finally:
                self._outgoing = None
                self._events.put(("finished", None))

        self._worker = threading.Thread(
            target=worker, name="SyncBridgeFolderSetup", daemon=False,
        )
        self._worker.start()
        messagebox.showinfo(
            "Request sent",
            "The encrypted request is being sent. The other person must approve.\n"
            "Keep both applications open while the request is pending.",
            parent=self.parent,
        )

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
                    "Folder relationship saved",
                    f"Saved '{value.display_name}'. It is DISABLED, with no file grants.\n"
                    "Activation will be implemented in the next stage.",
                    parent=self.parent,
                )
            elif kind == "error":
                messagebox.showerror("Folder request failed", str(value), parent=self.parent)
        current = {request.request_id: request for request in self.controller.pending()}
        for request_id, request in current.items():
            if request_id not in self._dialogs:
                self._dialogs[request_id] = IncomingFolderDialog(
                    self.parent, request, self.controller.approve, self.controller.reject,
                )
        for request_id, dialog in tuple(self._dialogs.items()):
            if request_id not in current:
                share = self.controller.store.load().get_share(dialog.request.share_id)
                success = share is not None and not share.enabled
                dialog.finish(success)
                if success:
                    self.on_saved()
                del self._dialogs[request_id]
        self._timer = self.parent.after(150, self._tick)

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
