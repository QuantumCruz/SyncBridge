
"""SyncBridge desktop: auto-discovery, verified pairing, folder setup, manual sync.

The setup service creates DISABLED shares without file grants. Only a separate
explicit activation step can enable a share for guarded synchronization.
All blocking file sync and folder-request work occurs off the Tk event loop.
"""
from __future__ import annotations

import argparse
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from syncbridge.core.review import explain_error
from syncbridge.network.discovery import DISCOVERY_PORT
from syncbridge.network.pairing import PAIRING_PORT
from syncbridge.network.share_setup import SETUP_PORT
from syncbridge.storage.config import ConfigStore
from syncbridge.ui.desktop_controller import DesktopController, DesktopPreview
from syncbridge.ui.folder_setup_desktop import FolderSetupController, FolderSetupUI
from syncbridge.ui.nearby_devices import DesktopPresence, NearbyDevicesWindow
from syncbridge.ui.pairing_desktop import DesktopPairingUI, PairingController


class SyncBridgeWindow:
    def __init__(
        self, root: tk.Tk, controller: DesktopController, *,
        discovery_port: int = DISCOVERY_PORT,
        discovery_bind: str = "0.0.0.0",
        discovery_targets: tuple[tuple[str, int], ...] | None = None,
        discovery_name: str | None = None,
        pairing_port: int = PAIRING_PORT,
        pairing_bind: str = "0.0.0.0",
        setup_port: int = SETUP_PORT,
        remote_setup_port: int = SETUP_PORT,
    ) -> None:
        self.root = root
        self.controller = controller
        self._events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._busy = False
        self._closing = False
        self._preview: DesktopPreview | None = None
        self._worker: threading.Thread | None = None
        self._nearby: NearbyDevicesWindow | None = None
        self._presence: DesktopPresence | None = None
        self._pairing: DesktopPairingUI | None = None
        self._folders: FolderSetupUI | None = None
        self._discovery_problem: str | None = None
        self._discovery_port = discovery_port
        self._discovery_bind = discovery_bind
        self._discovery_targets = discovery_targets
        self._discovery_name = discovery_name
        self._pairing_port = pairing_port
        self._pairing_bind = pairing_bind
        self._setup_port = setup_port
        self._remote_setup_port = remote_setup_port

        root.title("SyncBridge — Manual Sync Beta")
        root.geometry("930x630")
        root.minsize(750, 510)
        root.protocol("WM_DELETE_WINDOW", self._close)
        self.state = tk.StringVar(value="Not connected")
        self.profile_path = tk.StringVar(value=str(controller.store.path.parent))
        self.details = tk.StringVar(value="Loading profile...")
        self.summary = tk.StringVar(value="Pair with a device, then set up folders.")
        self.progress = tk.StringVar(value="")
        self.presence_status = tk.StringVar(value="Starting discovery, pairing and folder setup...")

        outer = ttk.Frame(root, padding=18)
        outer.pack(fill="both", expand=True)
        heading = ttk.Frame(outer)
        heading.pack(fill="x", pady=(0, 12))
        ttk.Label(heading, text="SyncBridge", font=("Segoe UI", 22, "bold")).pack(side="left")
        ttk.Label(heading, textvariable=self.state).pack(side="right")
        profile_row = ttk.Frame(outer)
        profile_row.pack(fill="x", pady=(0, 8))
        ttk.Label(profile_row, text="Profile:").pack(side="left")
        ttk.Entry(profile_row, textvariable=self.profile_path, state="readonly").pack(
            side="left", fill="x", expand=True, padx=8,
        )
        self.choose_button = ttk.Button(
            profile_row, text="Choose Profile", command=self._choose_profile,
        )
        self.choose_button.pack(side="right")
        ttk.Label(outer, textvariable=self.details, wraplength=860, justify="left").pack(
            fill="x", pady=(0, 12),
        )
        controls = ttk.Frame(outer)
        controls.pack(fill="x", pady=(0, 12))
        self.start_button = ttk.Button(controls, text="Start Connection", command=self._start)
        self.start_button.pack(side="left", padx=(0, 6))
        self.stop_button = ttk.Button(controls, text="Stop", command=self._stop)
        self.stop_button.pack(side="left", padx=(0, 6))
        self.preview_button = ttk.Button(controls, text="Preview", command=self._request_preview)
        self.preview_button.pack(side="left", padx=(0, 6))
        self.sync_button = ttk.Button(controls, text="Sync Now", command=self._request_sync)
        self.sync_button.pack(side="left", padx=(0, 6))
        self.folder_button = ttk.Button(controls, text="Open Folder", command=self._open_folder)
        self.folder_button.pack(side="right")
        self.nearby_button = ttk.Button(controls, text="Nearby Devices", command=self._open_nearby)
        self.nearby_button.pack(side="right", padx=(0, 8))
        self.setup_button = ttk.Button(controls, text="Set Up Folder", command=self._setup_folder)
        self.setup_button.pack(side="right", padx=(0, 8))
        ttk.Label(outer, textvariable=self.presence_status, wraplength=860).pack(
            fill="x", pady=(0, 8),
        )
        ttk.Label(outer, textvariable=self.summary, wraplength=860).pack(
            fill="x", pady=(0, 8),
        )
        frame = ttk.Frame(outer)
        frame.pack(fill="both", expand=True)
        self.table = ttk.Treeview(
            frame, columns=("action", "path", "note"), show="headings", selectmode="browse",
        )
        for name, label, width in (
            ("action", "Action", 125), ("path", "File", 260), ("note", "Meaning", 350),
        ):
            self.table.heading(name, text=label)
            self.table.column(name, width=width, stretch=(name != "action"))
        scroll = ttk.Scrollbar(frame, command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        self.table.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        footer = ttk.Frame(root, padding=(18, 5, 18, 14))
        footer.pack(side="bottom", fill="x")
        ttk.Label(footer, textvariable=self.progress, wraplength=860).pack(anchor="w")
        ttk.Label(
            footer,
            text="Manual operations only · Newly configured folders stay disabled · No automatic deletion",
        ).pack(anchor="w")
        self._refresh_profile()
        self._start_presence()
        self._buttons()
        root.after(80, self._drain)

    def _display_name(self) -> str | None:
        if self._discovery_name:
            return self._discovery_name
        try:
            return self.controller.store.load().device_name
        except Exception:
            return None

    def _start_presence(self) -> None:
        if self._presence is not None:
            return
        pairing = presence = folders = None
        try:
            profile = self.controller.store.path.parent
            pairing = DesktopPairingUI(
                self.root,
                PairingController(
                    profile, self._display_name() or "SyncBridge Device",
                    bind_address=self._pairing_bind, port=self._pairing_port,
                ),
            )
            pairing.start()
            presence = DesktopPresence(
                profile, device_name=self._display_name(),
                listen_port=self._discovery_port, bind_address=self._discovery_bind,
                targets=self._discovery_targets, pairing_port=pairing.controller.port,
            )
            presence.start()
            sync_ports = self.controller.runtime.listen_ports or (45843, 45842, 45844)
            folders = FolderSetupUI(
                self.root,
                FolderSetupController(
                    self.controller.store, bind_address=self._pairing_bind,
                    listen_port=self._setup_port, remote_port=self._remote_setup_port,
                    sync_ports=tuple(sync_ports),
                ),
                visible_devices=presence.directory.devices,
                on_saved=self._folder_saved,
            )
            folders.start()
            self._pairing, self._presence, self._folders = pairing, presence, folders
            self._discovery_problem = None
            self.presence_status.set(
                "Discoverable · Device pairing and folder requests require approval"
            )
        except Exception as exc:
            if folders is not None:
                folders.stop()
            if presence is not None:
                presence.stop()
            if pairing is not None:
                pairing.stop()
            self._pairing = self._presence = self._folders = None
            self._discovery_problem = str(exc)
            self.presence_status.set("Discovery/setup unavailable; existing synced profiles may still work.")

    def _stop_presence(self) -> None:
        if self._nearby is not None:
            self._nearby.close()
            self._nearby = None
        if self._folders is not None:
            self._folders.stop()
            self._folders = None
        if self._presence is not None:
            self._presence.stop()
            self._presence = None
        if self._pairing is not None:
            self._pairing.stop()
            self._pairing = None
        self.presence_status.set("Discovery, pairing and folder setup stopped")

    def _folder_saved(self) -> None:
        self._refresh_profile()
        self._buttons()

    def _refresh_profile(self) -> None:
        settings = self.controller.store.load()
        try:
            profile = self.controller.profile()
        except Exception:
            disabled = [share for share in settings.shares if not share.enabled]
            self.details.set(
                f"Device: {settings.device_name} · {len(disabled)} inactive folder relationship(s).\n"
                "Pair with a computer and select Set Up Folder. "
                "A separate activation step will enable synchronization."
            )
            self.state.set("Setup required")
        else:
            self.details.set(
                f"{profile.device_name} · {profile.folder_name}\n"
                f"Local folder: {profile.local_root}\n"
                f"Paired computer: {profile.remote_host} · ID {profile.peer_node_id[:12]}…"
            )
            self.state.set("Connected" if self.controller.running else "Ready to connect")

    def _buttons(self) -> None:
        ready = not (self._busy or self._closing)
        running = self.controller.running
        try:
            self.controller.profile()
            configured = True
        except Exception:
            configured = False
        self.choose_button.configure(state="normal" if ready and not running else "disabled")
        self.start_button.configure(state="normal" if ready and not running and configured else "disabled")
        self.stop_button.configure(state="normal" if ready and running else "disabled")
        self.preview_button.configure(state="normal" if ready and running else "disabled")
        self.sync_button.configure(
            state="normal" if ready and running and self._preview is not None
            and not self._preview.requires_review else "disabled"
        )
        self.folder_button.configure(state="normal" if ready and configured else "disabled")
        self.nearby_button.configure(state="normal" if not self._closing else "disabled")
        self.setup_button.configure(state="normal" if ready and not running and self._folders else "disabled")

    def _choose_profile(self) -> None:
        chosen = filedialog.askdirectory(title="Choose a SyncBridge profile folder")
        if not chosen:
            return
        current = self.controller
        replacement = DesktopController(
            ConfigStore(Path(chosen) / "settings.json"),
            bind_address=current.runtime.bind_address,
            listen_ports=current.runtime.listen_ports,
            lock_port=current.runtime.lock_port,
            validation_port=current.runtime.validation_port,
        )
        self._stop_presence()
        self.controller = replacement
        self.profile_path.set(chosen)
        self._preview = None
        self._show_rows(())
        self._refresh_profile()
        self._start_presence()
        self._buttons()

    def _open_nearby(self) -> None:
        if self._nearby is not None and not self._nearby._closed:
            self._nearby.focus()
            return
        if self._presence is None or not self._presence.running:
            self._start_presence()
        if self._presence is None or self._pairing is None:
            messagebox.showerror(
                "Discovery unavailable",
                f"Could not start discovery and pairing:\n{self._discovery_problem}",
                parent=self.root,
            )
            return
        self._nearby = NearbyDevicesWindow(
            self.root, self._presence.directory,
            on_pair=self._pairing.request,
            is_trusted=self._pairing.trusted,
        )

    def _setup_folder(self) -> None:
        if self._folders is not None and not self.controller.running:
            self._folders.request()

    def _run(self, label: str, task) -> None:
        if self._busy or self._closing:
            return
        self._busy = True
        self.state.set(label)
        self.progress.set("")
        self._buttons()

        def worker():
            try:
                result = task()
            except Exception as exc:
                self._events.put(("error", exc))
            else:
                self._events.put(("done", (label, result)))

        self._worker = threading.Thread(
            target=worker, name="SyncBridgeDesktopTask", daemon=False,
        )
        self._worker.start()

    def _start(self) -> None:
        self._run("Connecting...", self.controller.start)

    def _stop(self) -> None:
        self._preview = None
        self._show_rows(())
        self._run("Stopping...", self.controller.stop)

    def _request_preview(self) -> None:
        self._preview = None
        self._buttons()
        self._run("Checking both folders...", self.controller.preview)

    def _request_sync(self) -> None:
        if self._preview is None or self._preview.requires_review:
            return
        if not messagebox.askyesno(
            "Confirm synchronization",
            "SyncBridge will rescan both folders before transferring files.\n\n"
            "Additions and updates may be copied in either direction. "
            "Conflicts and deletions will not be resolved automatically.\n\nContinue?",
            parent=self.root,
        ):
            return
        self._preview = None
        self._show_rows(())
        self._run(
            "Synchronizing...",
            lambda: self.controller.sync_once(
                on_progress=lambda event: self._events.put(("progress", event))
            ),
        )

    def _open_folder(self) -> None:
        try:
            folder = self.controller.profile().local_root.resolve(strict=True)
            if not folder.is_dir():
                raise NotADirectoryError(folder)
            if sys.platform == "win32":
                os.startfile(str(folder))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(folder)])
            else:
                subprocess.Popen(["xdg-open", str(folder)])
        except Exception as exc:
            messagebox.showerror("Cannot open folder", str(exc), parent=self.root)

    def _show_rows(self, rows) -> None:
        for item in self.table.get_children():
            self.table.delete(item)
        for item in rows:
            self.table.insert("", "end", values=(item.action, item.path, item.description))

    def _display_result(self, label: str, result) -> None:
        if label == "Connecting...":
            self.state.set("Connected — manual mode")
            self.summary.set("Connection started. Preview both folders before synchronizing.")
        elif label == "Stopping...":
            self.state.set("Disconnected")
            self.summary.set("Connection stopped safely.")
        elif label == "Checking both folders...":
            self._preview = result
            self._show_rows(result.items)
            self.summary.set(
                f"Shared revision {result.revision}: {len(result.items)} planned change(s). "
                + ("Conflicts/deletions need review; Sync is disabled."
                   if result.requires_review else "You can synchronize after confirming.")
            )
            self.state.set("Preview ready")
        elif label == "Synchronizing...":
            if result.complete:
                self.summary.set(
                    f"Success. Sent {len(result.uploaded)} and received "
                    f"{len(result.downloaded)} file(s). "
                    f"Shared revision: {result.checkpoint.baseline.revision}."
                )
                self.state.set("Synchronized")
            else:
                self.summary.set(
                    f"Synchronization stopped at '{result.status.value}'. "
                    "Review changes before trying again."
                )
                self.state.set("Attention needed")
            self.progress.set("Run Preview again to see the current state.")

    def _drain(self) -> None:
        try:
            while True:
                kind, payload = self._events.get_nowait()
                if kind == "shutdown_done":
                    self._busy = False
                    self.root.destroy()
                    return
                if kind == "shutdown_error":
                    self._busy = False
                    self._closing = False
                    self.state.set("Could not close connections")
                    messagebox.showerror(
                        "Shutdown incomplete",
                        f"SyncBridge could not stop cleanly: {payload}\n\nRetry closing.",
                        parent=self.root,
                    )
                elif kind == "progress":
                    self.progress.set(
                        f"{payload.direction}: {payload.path} "
                        f"({payload.transferred:,} / {payload.total:,} bytes)"
                    )
                elif kind == "error":
                    self._busy = False
                    code, message, next_step = explain_error(payload)
                    self.state.set("Operation stopped")
                    self.summary.set(f"[{code}] {message} {next_step}")
                    self.progress.set(str(payload))
                    messagebox.showerror(
                        "SyncBridge stopped safely",
                        f"[{code}] {message}\n\n{next_step}\n\nDetails: {payload}",
                        parent=self.root,
                    )
                else:
                    self._busy = False
                    label, value = payload
                    self._display_result(label, value)
                self._buttons()
        except queue.Empty:
            pass
        if self._closing and not self._busy:
            if self.controller.running:
                self._run_shutdown()
            else:
                self.root.destroy()
            return
        self.root.after(80, self._drain)

    def _run_shutdown(self) -> None:
        self._busy = True
        self.state.set("Closing connections...")
        self._buttons()

        def stop():
            try:
                self.controller.stop()
            except Exception as exc:
                self._events.put(("shutdown_error", exc))
            else:
                self._events.put(("shutdown_done", None))

        self._worker = threading.Thread(
            target=stop, name="SyncBridgeDesktopShutdown", daemon=False,
        )
        self._worker.start()

    def _close(self) -> None:
        if self._closing:
            return
        self._closing = True
        self._stop_presence()
        self.state.set("Waiting for current operation to finish...")
        self._buttons()
        if not self._busy:
            if self.controller.running:
                self._run_shutdown()
            else:
                self.root.destroy()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SyncBridge manual desktop beta")
    parser.add_argument("--profile", type=Path, help="Existing local profile directory")
    parser.add_argument("--bind-address", default="127.0.0.1")
    parser.add_argument("--listen-ports", nargs=3, type=int,
                        metavar=("MANIFEST", "TRANSFER", "AGREEMENT"))
    parser.add_argument("--lock-port", type=int, default=45846)
    parser.add_argument("--validation-port", type=int, default=45847)
    parser.add_argument("--discovery-port", type=int, default=DISCOVERY_PORT)
    parser.add_argument("--discovery-bind", default="0.0.0.0")
    parser.add_argument("--discovery-name", default=None)
    parser.add_argument("--pairing-port", type=int, default=PAIRING_PORT)
    parser.add_argument("--pairing-bind", default="0.0.0.0")
    parser.add_argument("--setup-port", type=int, default=SETUP_PORT)
    parser.add_argument("--remote-setup-port", type=int, default=SETUP_PORT)
    parser.add_argument("--discovery-target", action="append", metavar="IP:PORT")
    args = parser.parse_args(argv)
    store = ConfigStore(args.profile / "settings.json" if args.profile else None)
    controller = DesktopController(
        store, bind_address=args.bind_address,
        listen_ports=tuple(args.listen_ports) if args.listen_ports else None,
        lock_port=args.lock_port, validation_port=args.validation_port,
    )
    targets = None
    if args.discovery_target:
        try:
            targets = tuple(
                (host, int(port))
                for host, port in (value.rsplit(":", 1) for value in args.discovery_target)
            )
        except (ValueError, TypeError) as exc:
            parser.error(f"Invalid --discovery-target: {exc}")
    root = tk.Tk()
    SyncBridgeWindow(
        root, controller, discovery_port=args.discovery_port,
        discovery_bind=args.discovery_bind, discovery_targets=targets,
        discovery_name=args.discovery_name, pairing_port=args.pairing_port,
        pairing_bind=args.pairing_bind, setup_port=args.setup_port,
        remote_setup_port=args.remote_setup_port,
    )
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
