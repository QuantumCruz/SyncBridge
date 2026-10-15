
"""Application-owned LAN discovery and a read-only device browser.

UDP beacons are UNTRUSTED. Pairing requests must still check the signed
handshake and receive independent approval from BOTH users.
"""
from __future__ import annotations

import queue
import socket
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import ttk
from typing import Callable, Iterable

from syncbridge.network.discovery import DISCOVERY_PORT, PeerDiscovery
from syncbridge.network.pairing import PAIRING_PORT
from syncbridge.network.security import load_or_create_identity


@dataclass(frozen=True, slots=True)
class NearbyDevice:
    node_id: str
    name: str
    address: str
    discovery_port: int
    pairing_port: int = PAIRING_PORT


class NearbyDirectory:
    """Headless discovery. No peer is trusted just by appearing here."""

    def __init__(
        self, node_id: str, device_name: str, *,
        listen_port: int = DISCOVERY_PORT,
        bind_address: str = "0.0.0.0",
        targets: Iterable[tuple[str, int]] | None = None,
        announce_interval: float = 2.0,
        peer_timeout: float = 8.0,
        pairing_port: int = PAIRING_PORT,
    ) -> None:
        self._errors: queue.SimpleQueue[str] = queue.SimpleQueue()
        options = {} if targets is None else {"targets": tuple(targets)}
        self.discovery = PeerDiscovery(
            node_id, device_name, pairing_port,
            listen_port=listen_port,
            bind_address=bind_address,
            announce_interval=announce_interval,
            peer_timeout=peer_timeout,
            on_error=self._error, **options,
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
            NearbyDevice(peer.node_id, peer.name, peer.address,
                         peer.discovery_port, peer.port)
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
    """One discovery advertiser per open profile, independent of sync."""

    def __init__(
        self, profile: str | Path, *, device_name: str | None = None,
        listen_port: int = DISCOVERY_PORT,
        bind_address: str = "0.0.0.0",
        targets: Iterable[tuple[str, int]] | None = None,
        announce_interval: float = 2.0,
        peer_timeout: float = 8.0,
        pairing_port: int = PAIRING_PORT,
    ) -> None:
        self.profile = Path(profile).expanduser().resolve()
        self.profile.mkdir(parents=True, exist_ok=True)
        identity = load_or_create_identity(self.profile / "identity.json")
        self.node_id = identity.node_id
        self.directory = NearbyDirectory(
            identity.node_id,
            device_name or socket.gethostname() or "SyncBridge Device",
            listen_port=listen_port, bind_address=bind_address,
            targets=targets, announce_interval=announce_interval,
            peer_timeout=peer_timeout, pairing_port=pairing_port,
        )

    @property
    def running(self) -> bool:
        return self.directory.running

    def start(self) -> None:
        self.directory.start()

    def stop(self) -> None:
        self.directory.stop()


class NearbyDevicesWindow:
    """Read-only discovery list with explicit secure-pairing action."""

    def __init__(
        self, parent: tk.Misc, directory: NearbyDirectory, *,
        on_pair: Callable[[NearbyDevice], None] | None = None,
        is_trusted: Callable[[str], bool] | None = None,
    ) -> None:
        if not isinstance(directory, NearbyDirectory):
            raise TypeError("An application-owned NearbyDirectory is required")
        if not directory.running:
            raise RuntimeError("Nearby discovery is not running")
        self.directory = directory
        self._on_pair = on_pair
        self._is_trusted = is_trusted or (lambda _node_id: False)
        self.window = tk.Toplevel(parent)
        self.window.title("SyncBridge — Nearby Devices")
        self.window.geometry("700x440")
        self.window.minsize(560, 360)
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self._closed = False
        self._after_id: str | None = None
        self._previous = None
        self._by_id: dict[str, NearbyDevice] = {}

        outer = ttk.Frame(self.window, padding=16)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="Devices on your network",
                  font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(
            outer,
            text=("SyncBridge advertises automatically while open. "
                  "Device names and addresses are unverified until pairing."),
            wraplength=640,
        ).pack(anchor="w", pady=(6, 12))
        frame = ttk.Frame(outer)
        frame.pack(fill="both", expand=True)
        self.table = ttk.Treeview(
            frame, columns=("name", "ip", "trust"), show="headings",
            selectmode="browse",
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
        self.table.bind("<<TreeviewSelect>>", self._selected)

        buttons = ttk.Frame(outer)
        buttons.pack(fill="x", pady=(12, 6))
        ttk.Button(buttons, text="Refresh List", command=self._refresh).pack(side="left")
        self.pair_button = ttk.Button(
            buttons, text="Request Pairing", command=self._request_pair, state="disabled"
        )
        self.pair_button.pack(side="left", padx=8)
        ttk.Button(buttons, text="Copy Details", command=self._copy).pack(side="left")
        ttk.Button(buttons, text="Close", command=self.close).pack(side="right")
        self.message = tk.StringVar(value="Checking for nearby devices...")
        ttk.Label(outer, textvariable=self.message, wraplength=640).pack(anchor="w")
        ttk.Label(
            outer, text="Pairing confirms device identity only; it grants no folder permissions."
        ).pack(anchor="w", pady=(6, 0))
        self._tick()

    def focus(self) -> None:
        self.window.lift()
        self.window.focus_set()

    def _selected_device(self) -> NearbyDevice | None:
        selection = self.table.selection()
        return self._by_id.get(selection[0]) if selection else None

    def _selected(self, _event=None) -> None:
        device = self._selected_device()
        can_pair = (device is not None and self._on_pair is not None
                    and not self._is_trusted(device.node_id))
        self.pair_button.configure(state="normal" if can_pair else "disabled")

    def _request_pair(self) -> None:
        device = self._selected_device()
        if device is None or self._on_pair is None or self._is_trusted(device.node_id):
            return
        self._on_pair(device)
        self.message.set(f"Pairing request sent to {device.name}. Wait for verification.")

    def _refresh(self) -> None:
        try:
            self.directory.refresh()
            self.message.set("Refreshing visible devices...")
        except Exception as exc:
            self.message.set(f"Cannot refresh discovery: {exc}")

    def _copy(self) -> None:
        device = self._selected_device()
        if device is None:
            self.message.set("Select a device first.")
            return
        details = (
            f"Name (unverified): {device.name}\n"
            f"Address (observed): {device.address}\n"
            f"Advertised device ID (unverified): {device.node_id}\n"
            f"TCP pairing port: {device.pairing_port}\n"
            f"UDP discovery port: {device.discovery_port}\n"
        )
        self.window.clipboard_clear()
        self.window.clipboard_append(details)
        self.message.set("Details copied. Trust requires a separate verified pairing.")

    def _tick(self) -> None:
        if self._closed:
            return
        devices = self.directory.devices()
        statuses = tuple((d.node_id, self._is_trusted(d.node_id)) for d in devices)
        snapshot = (devices, statuses)
        if snapshot != self._previous:
            selected = self._selected_device()
            selected_id = selected.node_id if selected else None
            for item in self.table.get_children():
                self.table.delete(item)
            self._by_id = {device.node_id: device for device in devices}
            for device in devices:
                self.table.insert(
                    "", "end", iid=device.node_id,
                    values=(
                        device.name, device.address,
                        "Paired (identity verified)" if self._is_trusted(device.node_id)
                        else "Not paired / unverified",
                    ),
                )
            if selected_id in self._by_id:
                self.table.selection_set(selected_id)
            self._previous = snapshot
            self._selected()
        problems = self.directory.errors()
        self.message.set(
            f"Discovery issue: {problems[-1]}" if problems else
            f"Found {len(devices)} other device(s). Close this list any time; discovery stays on."
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
        # Main application owns the advertiser; never stop it here.
        try:
            self.window.destroy()
        except tk.TclError:
            pass
