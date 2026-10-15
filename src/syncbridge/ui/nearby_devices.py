
"""Application-owned LAN discovery and a read-only Tkinter peer browser.

Opening SyncBridge starts advertisements. Opening or closing Nearby Devices does
not start or stop advertisements. Beacons are untrusted and never pair devices,
open shared files, or grant file permissions. The advertised pairing port is
reserved for a future listener and is not yet a working pairing endpoint.
"""
from __future__ import annotations

import queue
import socket
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import ttk
from typing import Iterable

from syncbridge.network.discovery import DISCOVERY_PORT, PeerDiscovery
from syncbridge.network.security import load_or_create_identity


@dataclass(frozen=True, slots=True)
class NearbyDevice:
    node_id: str
    name: str
    address: str
    discovery_port: int


class NearbyDirectory:
    """Headless UDP discovery without trust or sync side effects."""

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
            45840,  # Reserved future pairing endpoint; NOT active yet.
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


class DesktopPresence:
    """One identity and one background discovery service per open app profile.

    It is deliberately independent of GuardedManualRuntime: a device can be
    discoverable before a share is configured or a Sync connection is started.
    Close it with the app, not with the device browser.
    """

    def __init__(
        self,
        profile: str | Path,
        *,
        device_name: str | None = None,
        listen_port: int = DISCOVERY_PORT,
        bind_address: str = "0.0.0.0",
        targets: Iterable[tuple[str, int]] | None = None,
        announce_interval: float = 2.0,
        peer_timeout: float = 8.0,
    ) -> None:
        self.profile = Path(profile).expanduser().resolve()
        self.profile.mkdir(parents=True, exist_ok=True)
        identity = load_or_create_identity(self.profile / "identity.json")
        self.node_id = identity.node_id
        self.directory = NearbyDirectory(
            identity.node_id,
            device_name or socket.gethostname() or "SyncBridge Device",
            listen_port=listen_port,
            bind_address=bind_address,
            targets=targets,
            announce_interval=announce_interval,
            peer_timeout=peer_timeout,
        )

    @property
    def running(self) -> bool:
        return self.directory.running

    def start(self) -> None:
        self.directory.start()

    def stop(self) -> None:
        self.directory.stop()


class NearbyDevicesWindow:
    """Read-only UI for the application's ALREADY RUNNING discovery service.

    Closing this window has no effect on whether this computer is visible to
    peers. The owner (SyncBridgeWindow) stops discovery when the app exits.
    """

    def __init__(self, parent: tk.Misc, directory: NearbyDirectory) -> None:
        if not isinstance(directory, NearbyDirectory):
            raise TypeError("An application-owned NearbyDirectory is required")
        if not directory.running:
            raise RuntimeError("Nearby discovery is not running")
        self.directory = directory
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
            outer, text="Devices on your network", font=("Segoe UI", 16, "bold")
        ).pack(anchor="w")
        ttk.Label(
            outer,
            text=(
                "SyncBridge is already discoverable while the app is open. "
                "These announcements are unverified and do not grant file access."
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
            ("ip", "Observed address", 140),
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
        ttk.Button(buttons, text="Refresh List", command=self._refresh).pack(side="left")
        ttk.Button(buttons, text="Copy Selected Details", command=self._copy).pack(
            side="left", padx=8
        )
        ttk.Button(buttons, text="Close", command=self.close).pack(side="right")
        self.message = tk.StringVar(value="Checking for nearby SyncBridge devices...")
        ttk.Label(outer, textvariable=self.message, wraplength=640).pack(anchor="w")
        ttk.Label(
            outer,
            text="Connect / Pair will be added in the secure pairing phase.",
        ).pack(anchor="w", pady=(6, 0))
        self._tick()

    def focus(self) -> None:
        self.window.lift()
        self.window.focus_set()

    def _refresh(self) -> None:
        try:
            self.directory.refresh()
            self.message.set("Refreshing visible devices...")
        except Exception as exc:
            self.message.set(f"Cannot refresh discovery: {exc}")

    def _copy(self) -> None:
        selected = self.table.selection()
        if not selected:
            self.message.set("Select a device first.")
            return
        device = self._by_id.get(selected[0])
        if device is None:
            self.message.set("This device is no longer visible.")
            return
        details = (
            f"Name (unverified): {device.name}\n"
            f"Address (observed): {device.address}\n"
            f"Advertised device ID (unverified): {device.node_id}\n"
            f"UDP discovery port: {device.discovery_port}\n"
        )
        self.window.clipboard_clear()
        self.window.clipboard_append(details)
        self.message.set("Unverified device details copied. Pairing is not established.")

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
        else:
            self.message.set(
                f"Found {len(devices)} other device(s). "
                "Close this window any time; SyncBridge stays discoverable."
                if devices
                else "No devices visible yet. Keep SyncBridge open on the other computer."
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
        # The main app owns discovery. DO NOT call directory.stop() here.
        try:
            self.window.destroy()
        except tk.TclError:
            pass
