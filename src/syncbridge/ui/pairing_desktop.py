
"""Two-person pairing UI; all socket operations stay off the Tk thread.

Discovery data is untrusted. Approval requires checking the comparison code
through a separate human communication channel. Trust never grants shares.
"""
from __future__ import annotations

import hmac
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Callable

from syncbridge.network.pairing import (
    PAIRING_PORT, PairingClient, PairingDetails, PairingService, PairingSession,
)
from syncbridge.network.security import PairingError, TrustStore, load_or_create_identity
from syncbridge.ui.nearby_devices import NearbyDevice


class PairingController:
    """Headless pairing endpoint owned by one desktop profile."""

    def __init__(self, profile: str | Path, name: str, *,
                 bind_address: str = "0.0.0.0", port: int = PAIRING_PORT,
                 approval_timeout: float = 120.0):
        profile = Path(profile).expanduser().resolve()
        self.identity = load_or_create_identity(profile / "identity.json")
        self.trust = TrustStore(profile / "trust.json")
        self.client = PairingClient(self.identity, self.trust, name)
        self.service = PairingService(
            self.identity, self.trust, name, bind_address=bind_address,
            listen_port=port, approval_timeout=approval_timeout,
        )
        self.approval_timeout = approval_timeout

    @property
    def port(self) -> int:
        if not self.service.running or self.service.bound_port is None:
            raise RuntimeError("Pairing service is not running")
        return self.service.bound_port

    def start(self) -> None:
        self.service.start()

    def stop(self) -> None:
        self.service.stop()

    def trusted(self, node_id: str) -> bool:
        return self.trust.get(node_id) is not None

    def pending(self) -> tuple[PairingDetails, ...]:
        return self.service.pending()

    def request(self, peer: NearbyDevice) -> PairingSession:
        if self.trusted(peer.node_id):
            raise PairingError("Device is already paired")
        return self.client.request(
            peer.address, peer.pairing_port,
            expected_node_id=peer.node_id,
            approval_timeout=self.approval_timeout,
        )

    def approve_incoming(self, details: PairingDetails, code: str) -> None:
        self.service.approve(details.request_id, code)

    def reject_incoming(self, request_id: str) -> None:
        self.service.reject(request_id)


class PairingDialog:
    """Nonmodal consent dialog. Never interprets discovery as verification."""

    def __init__(self, parent: tk.Misc, details: PairingDetails, *,
                 incoming: bool, approve: Callable[[str], None],
                 reject: Callable[[], None]):
        self.details = details
        self.approve_callback = approve
        self.reject_callback = reject
        self.waiting = False
        self.closed = False
        self.window = tk.Toplevel(parent)
        self.window.title("SyncBridge — Verify Device")
        self.window.geometry("575x385")
        self.window.resizable(False, False)
        self.window.protocol("WM_DELETE_WINDOW", self.cancel)
        box = ttk.Frame(self.window, padding=18)
        box.pack(fill="both", expand=True)
        ttk.Label(box, text=("Incoming pairing request" if incoming else "Pairing request"),
                  font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(box, text=f"Device: {details.remote_name}  ·  {details.address}",
                  wraplength=530).pack(anchor="w", pady=(10, 4))
        ttk.Label(box, text="This device claims the following fingerprint:").pack(anchor="w")
        ttk.Label(box, text=details.remote_fingerprint, wraplength=530,
                  font=("Consolas", 10)).pack(anchor="w", pady=(3, 10))
        ttk.Label(box, text="Compare this code with the code on the OTHER person's screen:",
                  wraplength=530).pack(anchor="w")
        ttk.Label(box, text=details.code, font=("Consolas", 16, "bold")).pack(
            anchor="w", pady=(4, 12))
        ttk.Label(box, text="Enter the code they independently tell you:").pack(anchor="w")
        self.code = tk.StringVar()
        self.entry = ttk.Entry(box, textvariable=self.code, width=30)
        self.entry.pack(anchor="w", pady=(3, 7))
        self.confirmed = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            box, variable=self.confirmed,
            text="I compared the code with the other person via a separate channel",
        ).pack(anchor="w", pady=(3, 9))
        self.status = tk.StringVar(value="No trust is saved until BOTH people approve.")
        ttk.Label(box, textvariable=self.status, wraplength=530).pack(anchor="w")
        actions = ttk.Frame(box)
        actions.pack(side="bottom", fill="x", pady=(14, 0))
        self.yes = ttk.Button(actions, text="Approve Pairing", command=self.approve)
        self.yes.pack(side="left")
        self.no = ttk.Button(actions, text="Reject / Cancel", command=self.cancel)
        self.no.pack(side="right")
        self.entry.focus_set()

    def approve(self) -> None:
        if self.waiting or self.closed:
            return
        if not self.confirmed.get():
            self.status.set("Verify the code with the other person first.")
            return
        if not hmac.compare_digest(self.code.get().strip().upper(), self.details.code):
            self.status.set("Codes do not match. Pairing has NOT been approved.")
            return
        # The controller performs the protocol's independent code check too.
        self.waiting = True
        self.yes.configure(state="disabled")
        self.no.configure(state="disabled")
        self.entry.configure(state="disabled")
        self.status.set("Approval submitted. Waiting for the other device...")
        self.approve_callback(self.code.get().strip().upper())

    def finish(self, message: str) -> None:
        if self.closed:
            return
        self.waiting = False
        self.status.set(message)
        self.no.configure(text="Close", state="normal")
        self.yes.configure(state="disabled")

    def cancel(self) -> None:
        if self.closed or self.waiting:
            return
        self.closed = True
        try:
            self.reject_callback()
        finally:
            self.window.destroy()

    def destroy(self) -> None:
        if not self.closed:
            self.closed = True
            self.window.destroy()


class DesktopPairingUI:
    """Tk event-loop bridge for a listener and one outgoing pairing at a time."""

    def __init__(self, parent: tk.Misc, controller: PairingController):
        self.parent = parent
        self.controller = controller
        self._events: queue.SimpleQueue[tuple[str, object]] = queue.SimpleQueue()
        self._closed = False
        self._timer: str | None = None
        self._incoming: dict[str, PairingDialog] = {}
        self._outgoing: PairingDialog | None = None
        self._outgoing_session: PairingSession | None = None
        self._requesting = False

    def start(self) -> None:
        self.controller.start()
        self._tick()

    def trusted(self, node_id: str) -> bool:
        return self.controller.trusted(node_id)

    def request(self, device: NearbyDevice) -> None:
        if self._closed or self._requesting or self._outgoing is not None:
            return
        if self.trusted(device.node_id):
            return
        self._requesting = True

        def worker():
            try:
                session = self.controller.request(device)
                if self._closed:
                    session.reject()
                    return
                self._events.put(("session", session))
            except Exception as exc:
                self._events.put(("request_error", str(exc)))

        threading.Thread(target=worker, daemon=True, name="SyncBridgePairDial").start()

    def _incoming_approve(self, details: PairingDetails, code: str) -> None:
        try:
            self.controller.approve_incoming(details, code)
        except Exception as exc:
            dialog = self._incoming.get(details.request_id)
            if dialog is not None:
                dialog.finish(f"Approval failed: {exc}")

    def _incoming_reject(self, request_id: str) -> None:
        try:
            self.controller.reject_incoming(request_id)
        except PairingError:
            pass
        self._incoming.pop(request_id, None)

    def _outgoing_reject(self) -> None:
        if self._outgoing_session is not None:
            self._outgoing_session.reject()
        self._outgoing = None
        self._outgoing_session = None

    def _outgoing_approve(self, code: str) -> None:
        session = self._outgoing_session
        if session is None:
            return

        def worker():
            try:
                session.approve(code)
                self._events.put(("paired", session.details.remote_name))
            except Exception as exc:
                self._events.put(("pair_error", str(exc)))

        threading.Thread(target=worker, daemon=True, name="SyncBridgePairApprove").start()

    def _tick(self) -> None:
        if self._closed:
            return
        while True:
            try:
                kind, payload = self._events.get_nowait()
            except queue.Empty:
                break
            if kind == "session":
                self._requesting = False
                session = payload
                self._outgoing_session = session
                self._outgoing = PairingDialog(
                    self.parent, session.details, incoming=False,
                    approve=self._outgoing_approve, reject=self._outgoing_reject,
                )
            elif kind == "request_error":
                self._requesting = False
                from tkinter import messagebox
                messagebox.showerror("Pairing request failed", str(payload), parent=self.parent)
            elif kind in ("paired", "pair_error"):
                if self._outgoing is not None:
                    self._outgoing.finish(
                        "Both devices paired successfully." if kind == "paired"
                        else f"Pairing failed: {payload}"
                    )
                self._outgoing_session = None

        requests = {item.request_id: item for item in self.controller.pending()}
        for request_id, details in requests.items():
            if request_id not in self._incoming:
                self._incoming[request_id] = PairingDialog(
                    self.parent, details, incoming=True,
                    approve=lambda code, d=details: self._incoming_approve(d, code),
                    reject=lambda rid=request_id: self._incoming_reject(rid),
                )
        for request_id, dialog in tuple(self._incoming.items()):
            if request_id not in requests:
                success = self.trusted(dialog.details.remote_node_id)
                if dialog.waiting:
                    dialog.finish(
                        "Both devices paired successfully." if success
                        else "Pairing expired or was cancelled; no trust was saved here."
                    )
                elif not dialog.closed:
                    dialog.finish("Pairing request expired or was cancelled.")
                del self._incoming[request_id]

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
        if self._outgoing_session is not None:
            self._outgoing_session.reject()
        self.controller.stop()
        for dialog in list(self._incoming.values()):
            dialog.destroy()
        self._incoming.clear()
        if self._outgoing is not None:
            self._outgoing.destroy()
        self._outgoing = None
        self._outgoing_session = None
