
"""Nearby SyncBridge devices: untrusted UDP discovery plus a Tkinter viewer.

Discovery beacons are NOT authenticated, verified identities, pairing requests,
or permission to read files. The advertised TCP port is reserved for a future
pairing endpoint; this phase does not open that endpoint or connect to peers.
"""
from __future__ import annotations

import queue
import socket
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import ttk
from typing import Iterable

from syncbridge.network.discovery import (
    DISCOVERY_PORT,
    PeerDiscovery,
)
from syncbridge.network.security import load_or_create_identity


@dataclass(frozen=True, slots=True)
class NearbyDevice:
    node_id: str
    name: str
    address: str
    discovery_port: int


class NearbyDirectory:
    """Headless discovery controller. No trust-store writes or sync operations."""

    def __init__(
        self,
        node_id: str,
        device_name: str,
        *,
        listen_port: int = DISCOVERY_PORT,
        bind_address: str = "0.0.0.0",
        targets: Iterable[tuple[str, int]] | None = None,
        announce_interval: float = 2.0,
        peer_timeout: float = 8.0,
    ) -> None:
        self._errors: queue.SimpleQueue[str] = queue.SimpleQueue()
        options = {} if targets is None else {"targets": tuple(targets)}
        self.discovery = PeerDiscovery(
            node_id,
            device_name,
            45840,  # Future pairing endpoint: not opened or trusted in this phase.
            listen_port=listen_port,
            bind_address=bind_address,
            announce_interval=announce_interval,
            peer_timeout=peer_timeout,
            on_error=self._error,
            **options,
        )

    def _error(self, exc: Exception) -> None:
        self._errors.put(f"{type(exc).__name__}: {exc}")

    @property
    def running(self) -> bool:
        return self.discovery.is_running

    @property
    def bound_port(self) -> int | None:
        return self.discovery.bound_port

    def start(self) -> None:
        self.discovery.start()

    def stop(self) -> None:
        self.discovery.stop()

    def refresh(self) -> None:
        self.discovery.announce()

    def add_target(self, address: str, port: int) -> None:
        self.discovery.add_target(address, port)

    def devices(self) -> tuple[NearbyDevice, ...]:
        return tuple(
            NearbyDevice(peer.node_id, peer.name, peer.address, peer.discovery_port)
            for peer in self.discovery.peers
        )

    def errors(self) -> tuple[str, ...]:
        results = []
        while True:
            try:
                results.append(self._errors.get_nowait())
            except queue.Empty:
                return tuple(results)


class NearbyDevicesWindow:
    """A read-only device browser. All Tk calls run on the GUI thread."""

    def __init__(
        self,
        parent: tk.Misc,
        profile: str | Path,
        *,
        device_name: str | None = None,
        listen_port: int = DISCOVERY_PORT,
        bind_address: str = "0.0.0.0",
        targets: Iterable[tuple[str, int]] | None = None,
    ) -> None:
        profile_path = Path(profile).expanduser().resolve()
        profile_path.mkdir(parents=True, exist_ok=True)
        identity = load_or_create_identity(profile_path / "identity.json")
        name = device_name or socket.gethostname() or "SyncBridge Device"
        self.directory = NearbyDirectory(
            identity.node_id,
            name,
            listen_port=listen_port,
            bind_address=bind_address,
            targets=targets,
        )
        self.window = tk.Toplevel(parent)
        self.window.title("SyncBridge — Nearby Devices")
        self.window.geometry("680x430")
        self.window.minsize(560, 360)
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self._closed = False
        self._after_id: str | None = None
        self._previous: tuple[NearbyDevice, ...] = ()
        self._by_id: dict[str, NearbyDevice] = {}

        outer = ttk.Frame(self.window, padding=16)
        outer.pack(fill="both", expand=True)
        ttk.Label(
            outer, text="Devices on your local network", font=("Segoe UI", 16, "bold")
        ).pack(anchor="w")
        ttk.Label(
            outer,
            text=(
                "Devices listed here are unverified announcements. "
                "Discovery does not pair devices or grant file access."
            ),
            wraplength=640,
        ).pack(anchor="w", pady=(6, 12))

        frame = ttk.Frame(outer)
        frame.pack(fill="both", expand=True)
        self.table = ttk.Treeview(
            frame, columns=("name", "ip", "trust"), show="headings", selectmode="browse"
        )
        for key, title, width in (
            ("name", "Device name (unverified)", 220),
            ("ip", "Network address", 140),
            ("trust", "Pairing status", 180),
        ):
            self.table.heading(key, text=title)
            self.table.column(key, width=width, stretch=True)
        scroll = ttk.Scrollbar(frame, command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        self.table.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        buttons = ttk.Frame(outer)
        buttons.pack(fill="x", pady=(12, 6))
        ttk.Button(buttons, text="Scan Now", command=self._refresh).pack(side="left")
        ttk.Button(buttons, text="Copy Selected Details", command=self._copy).pack(
            side="left", padx=8
        )
        ttk.Button(buttons, text="Close", command=self.close).pack(side="right")
        self.message = tk.StringVar(value="Starting discovery...")
        ttk.Label(outer, textvariable=self.message, wraplength=640).pack(anchor="w")
        ttk.Label(
            outer,
            text="Pair / Connect will be enabled after secure pairing is implemented.",
        ).pack(anchor="w", pady=(6, 0))

        try:
            self.directory.start()
        except BaseException:
            self.window.destroy()
            raise
        self._tick()

    def focus(self) -> None:
        self.window.lift()
        self.window.focus_force()

    def _refresh(self) -> None:
        try:
            self.directory.refresh()
            self.message.set("Searching the network for SyncBridge devices...")
        except Exception as exc:
            self.message.set(f"Discovery could not send an announcement: {exc}")

    def _copy(self) -> None:
        selected = self.table.selection()
        if not selected:
            self.message.set("Select a device first.")
            return
        device = self._by_id.get(selected[0])
        if device is None:
            self.message.set("That device is no longer visible. Refresh and try again.")
            return
        details = (
            f"Name (unverified): {device.name}\n"
            f"Address (observed): {device.address}\n"
            f"Advertised device ID (unverified): {device.node_id}\n"
            f"UDP discovery port: {device.discovery_port}\n"
        )
        self.window.clipboard_clear()
        self.window.clipboard_append(details)
        self.message.set("Unverified discovery details copied. Do not treat these as trusted identity.")

    def _tick(self) -> None:
        if self._closed:
            return
        devices = self.directory.devices()
        if devices != self._previous:
            selection = self.table.selection()
            selected_id = selection[0] if selection else None
            for item in self.table.get_children():
                self.table.delete(item)
            self._by_id = {device.node_id: device for device in devices}
            for device in devices:
                self.table.insert(
                    "", "end", iid=device.node_id,
                    values=(device.name, device.address, "Not paired / unverified"),
                )
            if selected_id in self._by_id:
                self.table.selection_set(selected_id)
            self._previous = devices
        problems = self.directory.errors()
        if problems:
            self.message.set(f"Discovery issue: {problems[-1]}")
        elif self.message.get().startswith(("Starting", "Searching", "Found", "No devices")):
            self.message.set(
                f"Found {len(devices)} other device(s). "
                "Keep both apps open; devices disappear after a short timeout."
                if devices else "No devices yet. Keep SyncBridge open on another computer on the same LAN."
            )
        self._after_id = self.window.after(350, self._tick)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._after_id is not None:
            try:
                self.window.after_cancel(self._after_id)
            except tk.TclError:
                pass
        self.directory.stop()
        try:
            self.window.destroy()
        except tk.TclError:
            pass
