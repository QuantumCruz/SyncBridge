
"""SyncBridge desktop: discover, pair, choose folders, then synchronize.

Users do not manage protocol activation, ports or permission flags. Incoming
folder consent launches an internal retryable readiness exchange. Only manual
sync is supported; deletion and conflict resolution are never automatic.
"""
from __future__ import annotations

import argparse
import os
import logging
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
from syncbridge.network.share_activation import ACTIVATION_PORT
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
        activation_port: int = ACTIVATION_PORT,
        remote_activation_port: int = ACTIVATION_PORT,
    ) -> None:
        self.root = root
        self.controller = controller
        self._events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._busy = False
        self._closing = False
        self._shutdown_started = False
        self._preview: DesktopPreview | None = None
        self._auto_started_shares: set[str] = set()
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
        self._activation_port = activation_port
        self._remote_activation_port = remote_activation_port

        root.title("SyncBridge")
        root.geometry("1000x700")
        root.minsize(800, 570)
        root.protocol("WM_DELETE_WINDOW", self._close)
        self.state = tk.StringVar(value="Not connected")
        self.profile_path = tk.StringVar(value=str(controller.store.path.parent))
        self.details = tk.StringVar(value="Loading profile...")
        self.summary = tk.StringVar(
            value="Pair with a computer, then choose your folders."
        )
        self.progress = tk.StringVar(value="")
        self.presence_status = tk.StringVar(
            value="Starting discovery and pairing..."
        )

        self._apply_style()
        self._advanced_visible = False
        outer = ttk.Frame(root, padding=20)
        outer.pack(fill="both", expand=True)

        heading = ttk.Frame(outer)
        heading.pack(fill="x", pady=(0, 18))
        brand = ttk.Frame(heading)
        brand.pack(side="left")
        ttk.Label(
            brand, text="SyncBridge", style="Brand.TLabel"
        ).pack(anchor="w")
        ttk.Label(
            brand, text="Your files, together. No cloud account needed.",
            style="Subtle.TLabel",
        ).pack(anchor="w", pady=(2, 0))
        ttk.Label(
            heading, textvariable=self.state, style="Status.TLabel"
        ).pack(side="right", padx=8)

        connection = ttk.Frame(outer, style="Card.TFrame", padding=16)
        connection.pack(fill="x", pady=(0, 12))
        ttk.Label(
            connection, text="YOUR CONNECTION",
            style="Eyebrow.Card.TLabel",
        ).pack(anchor="w")
        ttk.Label(
            connection, textvariable=self.details, style="Card.TLabel",
            wraplength=875, justify="left",
        ).pack(fill="x", pady=(8, 11))

        setup_row = ttk.Frame(connection, style="Card.TFrame")
        setup_row.pack(fill="x")
        self.nearby_button = ttk.Button(
            setup_row, text="1  Find Computer",
            command=self._open_nearby, style="Accent.TButton",
        )
        self.nearby_button.pack(side="left", padx=(0, 8))
        self.setup_button = ttk.Button(
            setup_row, text="2  Connect Folders",
            command=self._setup_folder,
        )
        self.setup_button.pack(side="left", padx=(0, 8))
        self.folder_button = ttk.Button(
            setup_row, text="Open My Folder",
            command=self._open_folder,
        )
        self.folder_button.pack(side="right")
        ttk.Label(
            connection, textvariable=self.presence_status,
            style="Subtle.Card.TLabel", wraplength=875,
        ).pack(anchor="w", pady=(12, 0))

        # Reserve footer space before the expanding file list.
        footer = ttk.Frame(outer)
        footer.pack(side="bottom", fill="x", pady=(12, 0))

        changes = ttk.Frame(outer, style="Card.TFrame", padding=16)
        self._changes_card = changes
        changes.pack(fill="both", expand=True)
        action_row = ttk.Frame(changes, style="Card.TFrame")
        action_row.pack(fill="x", pady=(0, 10))
        change_heading = ttk.Frame(action_row, style="Card.TFrame")
        change_heading.pack(side="left")
        ttk.Label(
            change_heading, text="FILE CHANGES",
            style="Eyebrow.Card.TLabel",
        ).pack(anchor="w")
        ttk.Label(
            change_heading, text="Check what will change before syncing.",
            style="Subtle.Card.TLabel",
        ).pack(anchor="w", pady=(3, 0))

        self.sync_button = ttk.Button(
            action_row, text="Sync Changes", command=self._request_sync,
            style="Accent.TButton",
        )
        self.sync_button.pack(side="right", padx=(8, 0))
        self.preview_button = ttk.Button(
            action_row, text="Check Changes", command=self._request_preview,
        )
        self.preview_button.pack(side="right")
        ttk.Label(
            changes, textvariable=self.summary, style="Card.TLabel",
            wraplength=875, justify="left",
        ).pack(fill="x", pady=(0, 10))

        table_area = ttk.Frame(changes, style="Card.TFrame")
        table_area.pack(fill="both", expand=True)
        self.table = ttk.Treeview(
            table_area, columns=("action", "path", "note"),
            show="headings", selectmode="browse",
            style="Changes.Treeview",
        )
        for name, label, width in (
            ("action", "Action", 115),
            ("path", "File", 375),
            ("note", "Meaning", 325),
        ):
            self.table.heading(name, text=label)
            self.table.column(
                name, width=width, stretch=name != "action"
            )
        scroll = ttk.Scrollbar(table_area, command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        self.table.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        ttk.Label(
            footer, textvariable=self.progress,
            style="Subtle.TLabel", wraplength=920,
        ).pack(anchor="w", pady=(0, 6))
        advanced_row = ttk.Frame(footer)
        advanced_row.pack(fill="x")
        self.advanced_button = ttk.Button(
            advanced_row, text="Connection options  ▾",
            command=self._toggle_advanced,
        )
        self.advanced_button.pack(side="left")
        ttk.Label(
            advanced_row,
            text="Conflicts and deletions always need review",
            style="Subtle.TLabel",
        ).pack(side="right")

        self.advanced_controls = ttk.Frame(
            outer, padding=(0, 10, 0, 0)
        )
        action_options = ttk.Frame(self.advanced_controls)
        action_options.pack(fill="x", pady=(0, 8))
        self.start_button = ttk.Button(
            action_options, text="Reconnect", command=self._start,
        )
        self.start_button.pack(side="left", padx=(0, 8))
        self.stop_button = ttk.Button(
            action_options, text="Disconnect", command=self._stop,
        )
        self.stop_button.pack(side="left")

        profile_row = ttk.Frame(self.advanced_controls)
        profile_row.pack(fill="x")
        ttk.Label(
            profile_row, text="Profile", style="Subtle.TLabel"
        ).pack(side="left")
        ttk.Entry(
            profile_row, textvariable=self.profile_path,
            state="readonly",
        ).pack(side="left", fill="x", expand=True, padx=10)
        self.choose_button = ttk.Button(
            profile_row, text="Choose Profile",
            command=self._choose_profile,
        )
        self.choose_button.pack(side="right")

        self._refresh_profile()
        self._start_presence()
        self._buttons()
        root.after(80, self._drain)
        root.after(350, self._auto_connect)

    def _apply_style(self) -> None:
        """Style the temporary Tk GUI without additional dependencies."""
        bg = "#f4f6fb"
        fg = "#172438"
        muted = "#5d6b7e"
        accent = "#1769dd"

        self.root.configure(bg=bg)
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TFrame", background=bg)
        style.configure(
            "TLabel", background=bg, foreground=fg,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Brand.TLabel", background=bg, foreground=fg,
            font=("Segoe UI", 25, "bold"),
        )
        style.configure(
            "Subtle.TLabel", background=bg, foreground=muted,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Status.TLabel", background="#e5efff",
            foreground="#1453a1", padding=(12, 8),
            font=("Segoe UI", 10, "bold"),
        )
        style.configure(
            "Card.TFrame", background="white", relief="flat",
        )
        style.configure(
            "Card.TLabel", background="white", foreground=fg,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Subtle.Card.TLabel", background="white",
            foreground=muted, font=("Segoe UI", 9),
        )
        style.configure(
            "Eyebrow.Card.TLabel", background="white",
            foreground="#45617f",
            font=("Segoe UI", 10, "bold"),
        )
        style.configure(
            "TButton", font=("Segoe UI", 10), padding=(12, 9),
        )
        style.configure(
            "Accent.TButton", background=accent,
            foreground="white", font=("Segoe UI", 10, "bold"),
            padding=(13, 9), borderwidth=0,
        )
        style.map(
            "Accent.TButton",
            background=[
                ("disabled", "#cad4e0"),
                ("active", "#1354b5"),
            ],
            foreground=[("disabled", "#536273")],
        )
        style.configure(
            "Changes.Treeview", background="white",
            fieldbackground="white", foreground=fg,
            rowheight=27, font=("Segoe UI", 9),
        )
        style.configure(
            "Changes.Treeview.Heading",
            font=("Segoe UI", 9, "bold"), padding=7,
        )

    def _toggle_advanced(self) -> None:
        """Keep networking/profile controls out of the ordinary workflow."""
        self._advanced_visible = not self._advanced_visible
        if self._advanced_visible:
            self.advanced_controls.pack(
                fill="x", before=self._changes_card
            )
            self.advanced_button.configure(
                text="Connection options  ▴"
            )
        else:
            self.advanced_controls.pack_forget()
            self.advanced_button.configure(
                text="Connection options  ▾"
            )

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
                    profile,
                    self._display_name() or "SyncBridge Device",
                    bind_address=self._pairing_bind,
                    port=self._pairing_port,
                ),
            )
            pairing.start()
            presence = DesktopPresence(
                profile, device_name=self._display_name(),
                listen_port=self._discovery_port,
                bind_address=self._discovery_bind,
                targets=self._discovery_targets,
                pairing_port=pairing.controller.port,
            )
            presence.start()
            sync_ports = (
                self.controller.runtime.listen_ports
                or (45843, 45842, 45844)
            )
            folders = FolderSetupUI(
                self.root,
                FolderSetupController(
                    self.controller.store,
                    bind_address=self._pairing_bind,
                    listen_port=self._setup_port,
                    remote_port=self._remote_setup_port,
                    sync_ports=tuple(sync_ports),
                    activation_port=self._activation_port,
                    remote_activation_port=self._remote_activation_port,
                ),
                visible_devices=presence.directory.devices,
                on_saved=self._folder_saved,
            )
            folders.start()
            self._pairing = pairing
            self._presence = presence
            self._folders = folders
            self._discovery_problem = None
            self.presence_status.set(
                "Discoverable · Pairing and folder requests require your approval"
            )
        except Exception as exc:
            if folders is not None:
                folders.stop()
            if presence is not None:
                presence.stop()
            if pairing is not None:
                pairing.stop()
            self._pairing = None
            self._presence = None
            self._folders = None
            self._discovery_problem = str(exc)
            self.presence_status.set(
                "Nearby connections unavailable; check your network settings."
            )

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
        self.presence_status.set("Nearby connections stopped")

    def _folder_saved(self) -> None:
        self._refresh_profile()
        self._buttons()
        self._auto_connect()

    def _auto_connect(self) -> None:
        """Start listeners after approved folders become ready, without a click.

        This never starts unattended sync; file changes still need the guarded
        manual synchronization workflow until its crash guarantees are finished.
        A failed start can be retried using Reconnect.
        """
        if self._busy or self._closing or self.controller.running:
            return
        try:
            share = next(
                item for item in self.controller.store.load().shares
                if item.enabled
            )
            self.controller.profile()
        except Exception:
            return
        if share.share_id in self._auto_started_shares:
            return
        self._auto_started_shares.add(share.share_id)
        self._run("Connecting...", self.controller.start)

    def _refresh_profile(self) -> None:
        settings = self.controller.store.load()
        try:
            profile = self.controller.profile()
        except Exception:
            waiting = sum(
                not item.enabled for item in settings.shares
            )
            self.details.set(
                f"Device: {settings.device_name}\n"
                + (
                    "Waiting for folder connection to finish..."
                    if waiting else
                    "Pair with a computer, then choose the folders to connect."
                )
            )
            self.state.set(
                "Connecting folders..." if waiting else "Setup required"
            )
        else:
            self.details.set(
                f"{profile.device_name} · {profile.folder_name}\n"
                f"Local folder: {profile.local_root}\n"
                f"Paired computer: {profile.remote_host} "
                f"· ID {profile.peer_node_id[:12]}…"
            )
            self.state.set(
                "Connected" if self.controller.running else "Folders ready"
            )
            self.summary.set(
                "Folders connected. SyncBridge connects automatically; "
                "preview before syncing."
            )

    def _buttons(self) -> None:
        ready = not (self._busy or self._closing)
        running = self.controller.running
        try:
            self.controller.profile()
            configured = True
        except Exception:
            configured = False
        self.choose_button.configure(
            state="normal" if ready and not running else "disabled"
        )
        self.start_button.configure(
            state="normal" if ready and not running
            and configured else "disabled"
        )
        self.stop_button.configure(
            state="normal" if ready and running else "disabled"
        )
        self.preview_button.configure(
            state="normal" if ready and running else "disabled"
        )
        self.sync_button.configure(
            state="normal"
            if ready and running and self._preview is not None
            and not self._preview.requires_review
            else "disabled"
        )
        self.folder_button.configure(
            state="normal" if ready and configured else "disabled"
        )
        self.nearby_button.configure(
            state="normal" if not self._closing else "disabled"
        )
        self.setup_button.configure(
            state="normal"
            if ready and not running and self._folders is not None
            else "disabled"
        )

    def _choose_profile(self) -> None:
        chosen = filedialog.askdirectory(
            title="Choose a SyncBridge profile folder"
        )
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
        self._auto_started_shares.clear()
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
                f"Could not start discovery and pairing:\n"
                f"{self._discovery_problem}",
                parent=self.root,
            )
            return
        self._nearby = NearbyDevicesWindow(
            self.root,
            self._presence.directory,
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
            target=worker,
            name="SyncBridgeDesktopTask",
            daemon=False,
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

        count = len(self._preview.items)
        folder_name = self.controller.profile().folder_name
        warning = (
            "\n\nThis is a large change list. Transfers may take a while."
            if count >= 50 else ""
        )
        if not messagebox.askyesno(
            "Sync these changes?",
            f"Folder: {folder_name}\n"
            f"Files to update: {count}\n\n"
            "Both computers may send and receive files. File sizes vary; "
            "please check the list before proceeding."
            f"{warning}\n\n"
            "Conflicts and deletions will not be applied automatically."
            "\n\nContinue?",
            parent=self.root,
        ):
            return
        self._preview = None
        self._show_rows(())
        self._run(
            "Synchronizing...",
            lambda: self.controller.sync_once(
                on_progress=lambda event: self._events.put(
                    ("progress", event)
                )
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
            messagebox.showerror(
                "Cannot open folder", str(exc), parent=self.root
            )

    def _show_rows(self, rows) -> None:
        for item in self.table.get_children():
            self.table.delete(item)
        for item in rows:
            self.table.insert(
                "", "end",
                values=(item.action, item.path, item.description),
            )

    def _display_result(self, label: str, result) -> None:
        if label == "Connecting...":
            self.state.set("Connected — manual mode")
            self.summary.set(
                "Connected. Preview the folder changes before synchronizing."
            )
        elif label == "Stopping...":
            self.state.set("Disconnected")
            self.summary.set("Connection stopped safely.")
        elif label == "Checking both folders...":
            self._preview = result
            self._show_rows(result.items)
            self.summary.set(
                f"Shared revision {result.revision}: "
                f"{len(result.items)} planned change(s). "
                + (
                    "Conflicts/deletions need review; Sync is disabled."
                    if result.requires_review
                    else "You can synchronize after confirming."
                )
            )
            self.state.set("Preview ready")
        elif label == "Synchronizing...":
            if result.complete:
                self.summary.set(
                    f"Success. Sent {len(result.uploaded)} and received "
                    f"{len(result.downloaded)} file(s). "
                    f"Shared revision: "
                    f"{result.checkpoint.baseline.revision}."
                )
                self.state.set("Synchronized")
            else:
                self.summary.set(
                    f"Synchronization stopped at '{result.status.value}'. "
                    "Review changes before trying again."
                )
                self.state.set("Attention needed")
            self.progress.set(
                "Run Preview again to see the current state."
            )

    def _report_ui_error(
        self, exc: Exception, *, recover_busy: bool = True
    ) -> None:
        """Keep Tk's event pump alive even if rendering a result fails."""
        logging.exception(
            "SyncBridge desktop failed to display a result"
        )
        if recover_busy:
            self._busy = False
            self._preview = None
        self.state.set("Needs attention")
        self.summary.set(
            "Couldn't display the last result. Try Preview again."
        )
        self.progress.set(f"Interface error: {exc}")
        try:
            messagebox.showerror(
                "SyncBridge interface error",
                "The last operation finished, but its result "
                "couldn't be displayed.\n"
                "You can try Preview again or close the application.\n\n"
                f"Details: {exc}",
                parent=self.root,
            )
        except Exception:
            logging.exception(
                "Could not display desktop error dialog"
            )

    def _handle_event(self, kind: str, payload: object) -> bool:
        """Return True if the window was destroyed by this event."""
        if kind == "shutdown_done":
            self._busy = False
            self.root.destroy()
            return True
        if kind == "shutdown_error":
            self._busy = False
            self._closing = False
            self._shutdown_started = False
            self.state.set("Could not close connections")
            messagebox.showerror(
                "Shutdown incomplete",
                f"SyncBridge could not stop cleanly: {payload}"
                "\n\nRetry closing.",
                parent=self.root,
            )
        elif kind == "progress":
            if not self._closing:
                self.progress.set(
                    f"{payload.direction}: {payload.path} "
                    f"({payload.transferred:,} / "
                    f"{payload.total:,} bytes)"
                )
        elif kind == "error":
            self._busy = False
            if not self._closing:
                code, message, next_step = explain_error(payload)
                self.state.set("Operation stopped")
                self.summary.set(
                    f"[{code}] {message} {next_step}"
                )
                self.progress.set(str(payload))
                messagebox.showerror(
                    "SyncBridge stopped safely",
                    f"[{code}] {message}\n\n"
                    f"{next_step}\n\nDetails: {payload}",
                    parent=self.root,
                )
        elif kind == "done":
            self._busy = False
            if not self._closing:
                label, value = payload
                self._display_result(label, value)
        else:
            raise ValueError(
                f"Unexpected desktop event: {kind}"
            )
        self._buttons()
        return False

    def _drain(self) -> None:
        """Never lose the event pump because result rendering raised."""
        destroyed = False
        try:
            for _ in range(100):
                try:
                    kind, payload = self._events.get_nowait()
                except queue.Empty:
                    break
                try:
                    if self._handle_event(kind, payload):
                        destroyed = True
                        return
                except Exception as exc:
                    self._report_ui_error(
                        exc, recover_busy=kind != "progress"
                    )
            if (
                self._closing and not self._busy
                and not self._shutdown_started
            ):
                self._run_shutdown()
        except Exception as exc:
            self._report_ui_error(exc)
        finally:
            if not destroyed:
                try:
                    self.root.after(80, self._drain)
                except tk.TclError:
                    pass

    def _run_shutdown(self) -> None:
        """Stop blocking services on a worker; never wait on Tk's thread."""
        if self._shutdown_started:
            return
        self._shutdown_started = True
        self._busy = True
        self.state.set("Closing connections...")
        self._buttons()

        def stop() -> None:
            problems = []

            def cancel_outgoing_folder_request() -> None:
                if self._folders is None:
                    return
                session = self._folders._outgoing
                if session is not None:
                    session.cancel()
                worker = self._folders._worker
                if (
                    worker is not None
                    and worker is not threading.current_thread()
                ):
                    worker.join(timeout=8)
                    if worker.is_alive():
                        raise RuntimeError(
                            "Folder request is still closing"
                        )

            operations = (
                (
                    "Pending folder request",
                    cancel_outgoing_folder_request,
                ),
                ("Synchronization", self.controller.stop),
                (
                    "Folder setup",
                    self._folders.controller.stop
                    if self._folders else None,
                ),
                (
                    "Discovery",
                    self._presence.stop
                    if self._presence else None,
                ),
                (
                    "Pairing",
                    self._pairing.controller.stop
                    if self._pairing else None,
                ),
            )
            for name, callback in operations:
                if callback is None:
                    continue
                try:
                    callback()
                except Exception as exc:
                    logging.exception(
                        "Could not stop %s", name
                    )
                    problems.append(f"{name}: {exc}")
            self._events.put((
                "shutdown_error" if problems else "shutdown_done",
                "; ".join(problems) if problems else None,
            ))

        self._worker = threading.Thread(
            target=stop,
            name="SyncBridgeDesktopShutdown",
            daemon=True,
        )
        self._worker.start()

    def _close(self) -> None:
        """Stop accepting new actions; keep Tk responsive during shutdown."""
        if self._closing:
            return
        self._closing = True
        self.state.set("Closing SyncBridge...")
        self.summary.set(
            "Finishing the current operation and closing connections."
        )
        self._buttons()

        if self._nearby is not None:
            try:
                self._nearby.close()
            except tk.TclError:
                pass
            self._nearby = None

        if not self._busy:
            self._run_shutdown()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="SyncBridge manual desktop beta"
    )
    parser.add_argument(
        "--profile", type=Path,
        help="Existing local profile directory",
    )
    parser.add_argument(
        "--bind-address", default="127.0.0.1"
    )
    parser.add_argument(
        "--listen-ports", nargs=3, type=int,
        metavar=("MANIFEST", "TRANSFER", "AGREEMENT"),
    )
    parser.add_argument(
        "--lock-port", type=int, default=45846
    )
    parser.add_argument(
        "--validation-port", type=int, default=45847
    )
    parser.add_argument(
        "--discovery-port", type=int, default=DISCOVERY_PORT
    )
    parser.add_argument(
        "--discovery-bind", default="0.0.0.0"
    )
    parser.add_argument(
        "--discovery-name", default=None
    )
    parser.add_argument(
        "--pairing-port", type=int, default=PAIRING_PORT
    )
    parser.add_argument(
        "--pairing-bind", default="0.0.0.0"
    )
    parser.add_argument(
        "--setup-port", type=int, default=SETUP_PORT
    )
    parser.add_argument(
        "--remote-setup-port", type=int, default=SETUP_PORT
    )
    parser.add_argument(
        "--activation-port", type=int, default=ACTIVATION_PORT
    )
    parser.add_argument(
        "--remote-activation-port", type=int,
        default=ACTIVATION_PORT,
    )
    parser.add_argument(
        "--discovery-target", action="append",
        metavar="IP:PORT",
    )
    args = parser.parse_args(argv)
    store = ConfigStore(
        args.profile / "settings.json" if args.profile else None
    )
    controller = DesktopController(
        store,
        bind_address=args.bind_address,
        listen_ports=tuple(args.listen_ports)
        if args.listen_ports else None,
        lock_port=args.lock_port,
        validation_port=args.validation_port,
    )
    targets = None
    if args.discovery_target:
        try:
            targets = tuple(
                (host, int(port))
                for host, port in (
                    value.rsplit(":", 1)
                    for value in args.discovery_target
                )
            )
        except (ValueError, TypeError) as exc:
            parser.error(
                f"Invalid --discovery-target: {exc}"
            )

    root = tk.Tk()
    SyncBridgeWindow(
        root, controller,
        discovery_port=args.discovery_port,
        discovery_bind=args.discovery_bind,
        discovery_targets=targets,
        discovery_name=args.discovery_name,
        pairing_port=args.pairing_port,
        pairing_bind=args.pairing_bind,
        setup_port=args.setup_port,
        remote_setup_port=args.remote_setup_port,
        activation_port=args.activation_port,
        remote_activation_port=args.remote_activation_port,
    )
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
