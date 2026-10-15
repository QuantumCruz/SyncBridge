
"""Tkinter desktop for explicitly configured, lease-guarded manual sync.

Run using `python -m syncbridge.ui.main_window --profile PATH` or the launcher.
Tk owns the main thread; all potentially blocking network work uses a worker
thread and a Queue. Closing waits for work to finish and stops every listener.
No pairing, background sync, silent deletion or automated conflict resolution.
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
from syncbridge.storage.config import ConfigStore
from syncbridge.ui.desktop_controller import DesktopController, DesktopPreview


class SyncBridgeWindow:
    def __init__(self, root: tk.Tk, controller: DesktopController) -> None:
        self.root = root
        self.controller = controller
        self._events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._busy = False
        self._closing = False
        self._preview: DesktopPreview | None = None
        self._worker: threading.Thread | None = None

        root.title("SyncBridge — Manual Sync Beta")
        root.geometry("850x600")
        root.minsize(680, 480)
        root.protocol("WM_DELETE_WINDOW", self._close)

        self.state = tk.StringVar(value="Not connected")
        self.profile_path = tk.StringVar(
            value=str(self.controller.store.path.parent)
        )
        self.details = tk.StringVar(value="Loading profile...")
        self.summary = tk.StringVar(
            value="Start the connection to preview changes."
        )
        self.progress = tk.StringVar(value="")

        outer = ttk.Frame(root, padding=18)
        outer.pack(fill="both", expand=True)

        heading = ttk.Frame(outer)
        heading.pack(fill="x", pady=(0, 12))

        ttk.Label(
            heading,
            text="SyncBridge",
            font=("Segoe UI", 22, "bold"),
        ).pack(side="left")

        ttk.Label(
            heading,
            textvariable=self.state,
        ).pack(side="right")

        profile_row = ttk.Frame(outer)
        profile_row.pack(fill="x", pady=(0, 8))

        ttk.Label(
            profile_row,
            text="Profile:",
        ).pack(side="left")

        ttk.Entry(
            profile_row,
            textvariable=self.profile_path,
            state="readonly",
        ).pack(
            side="left",
            fill="x",
            expand=True,
            padx=8,
        )

        self.choose_button = ttk.Button(
            profile_row,
            text="Choose Profile",
            command=self._choose_profile,
        )
        self.choose_button.pack(side="right")

        ttk.Label(
            outer,
            textvariable=self.details,
            wraplength=770,
            justify="left",
        ).pack(fill="x", pady=(0, 12))

        controls = ttk.Frame(outer)
        controls.pack(fill="x", pady=(0, 12))

        self.start_button = ttk.Button(
            controls,
            text="Start Connection",
            command=self._start,
        )
        self.start_button.pack(side="left", padx=(0, 6))

        self.stop_button = ttk.Button(
            controls,
            text="Stop",
            command=self._stop,
        )
        self.stop_button.pack(side="left", padx=(0, 6))

        self.preview_button = ttk.Button(
            controls,
            text="Preview",
            command=self._request_preview,
        )
        self.preview_button.pack(side="left", padx=(0, 6))

        self.sync_button = ttk.Button(
            controls,
            text="Sync Now",
            command=self._request_sync,
        )
        self.sync_button.pack(side="left", padx=(0, 6))

        self.folder_button = ttk.Button(
            controls,
            text="Open Folder",
            command=self._open_folder,
        )
        self.folder_button.pack(side="right")

        ttk.Label(
            outer,
            textvariable=self.summary,
            wraplength=770,
        ).pack(fill="x", pady=(0, 8))

        columns = ("action", "path", "note")
        self.table = ttk.Treeview(
            outer,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        self.table.heading("action", text="Action")
        self.table.heading("path", text="File")
        self.table.heading("note", text="Meaning")

        self.table.column(
            "action",
            width=125,
            stretch=False,
        )
        self.table.column(
            "path",
            width=260,
            stretch=True,
        )
        self.table.column(
            "note",
            width=350,
            stretch=True,
        )

        self.table.pack(
            side="left",
            fill="both",
            expand=True,
        )

        scrollbar = ttk.Scrollbar(
            outer,
            command=self.table.yview,
        )
        scrollbar.pack(side="right", fill="y")
        self.table.configure(
            yscrollcommand=scrollbar.set
        )

        footer = ttk.Frame(
            root,
            padding=(18, 5, 18, 14),
        )
        footer.pack(
            side="bottom",
            fill="x",
        )

        ttk.Label(
            footer,
            textvariable=self.progress,
            wraplength=790,
        ).pack(anchor="w")

        ttk.Label(
            footer,
            text=(
                "Manual operations only · File deletion and automatic "
                "conflict resolution are disabled"
            ),
        ).pack(anchor="w")

        self._refresh_profile()
        self._buttons()
        self.root.after(80, self._drain)

    def _refresh_profile(self) -> None:
        try:
            profile = self.controller.profile()

        except Exception as exc:
            self.details.set(
                f"This profile is not ready: {exc}"
            )
            self.state.set("Setup required")

        else:
            self.details.set(
                f"{profile.device_name}  ·  {profile.folder_name}\n"
                f"Local folder: {profile.local_root}\n"
                f"Paired computer: {profile.remote_host}  ·  "
                f"ID {profile.peer_node_id[:12]}…"
            )
            self.state.set(
                "Connected"
                if self.controller.running
                else "Ready to connect"
            )

    def _buttons(self) -> None:
        ready = not (self._busy or self._closing)
        running = self.controller.running

        self.choose_button.configure(
            state=(
                "normal"
                if ready and not running
                else "disabled"
            )
        )
        self.start_button.configure(
            state=(
                "normal"
                if ready and not running
                else "disabled"
            )
        )
        self.stop_button.configure(
            state=(
                "normal"
                if ready and running
                else "disabled"
            )
        )
        self.preview_button.configure(
            state=(
                "normal"
                if ready and running
                else "disabled"
            )
        )
        self.sync_button.configure(
            state=(
                "normal"
                if (
                    ready
                    and running
                    and self._preview is not None
                    and not self._preview.requires_review
                )
                else "disabled"
            )
        )
        self.folder_button.configure(
            state="normal" if ready else "disabled"
        )

    def _choose_profile(self) -> None:
        chosen = filedialog.askdirectory(
            title="Choose a SyncBridge profile folder"
        )
        if not chosen:
            return

        current = self.controller

        self.controller = DesktopController(
            ConfigStore(Path(chosen) / "settings.json"),
            bind_address=current.runtime.bind_address,
            listen_ports=current.runtime.listen_ports,
            lock_port=current.runtime.lock_port,
            validation_port=current.runtime.validation_port,
        )

        self.profile_path.set(chosen)
        self._preview = None
        self._show_rows(())
        self._refresh_profile()
        self._buttons()

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
        self._run(
            "Connecting...",
            self.controller.start,
        )

    def _stop(self) -> None:
        self._preview = None
        self._show_rows(())

        self._run(
            "Stopping...",
            self.controller.stop,
        )

    def _request_preview(self) -> None:
        self._preview = None
        self._buttons()

        self._run(
            "Checking both folders...",
            self.controller.preview,
        )

    def _request_sync(self) -> None:
        current = self._preview

        if current is None or current.requires_review:
            return

        confirmed = messagebox.askyesno(
            "Confirm synchronization",
            (
                "SyncBridge will check both folders again "
                "before transferring files.\n\n"
                "File additions and updates may be copied in either "
                "direction. Conflicts and deletions will not be "
                "resolved automatically.\n\nContinue?"
            ),
            parent=self.root,
        )

        if not confirmed:
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
            folder = (
                self.controller.profile()
                .local_root.resolve(strict=True)
            )

            if not folder.is_dir():
                raise NotADirectoryError(folder)

            if sys.platform == "win32":
                os.startfile(str(folder))

            elif sys.platform == "darwin":
                subprocess.Popen(
                    ["open", str(folder)]
                )

            else:
                subprocess.Popen(
                    ["xdg-open", str(folder)]
                )

        except Exception as exc:
            messagebox.showerror(
                "Cannot open folder",
                str(exc),
                parent=self.root,
            )

    def _show_rows(self, rows) -> None:
        for item in self.table.get_children():
            self.table.delete(item)

        for item in rows:
            self.table.insert(
                "",
                "end",
                values=(
                    item.action,
                    item.path,
                    item.description,
                ),
            )

    def _display_result(self, label: str, result) -> None:
        if label == "Connecting...":
            self.state.set(
                "Connected — manual mode"
            )
            self.summary.set(
                "Connection started. Preview both folders "
                "before synchronizing."
            )

        elif label == "Stopping...":
            self.state.set("Disconnected")
            self.summary.set(
                "Connection stopped safely."
            )

        elif label == "Checking both folders...":
            self._preview = result
            self._show_rows(result.items)

            if result.requires_review:
                self.summary.set(
                    f"Shared revision {result.revision}: "
                    f"{len(result.items)} change(s). "
                    "Conflicts or deletions need review; "
                    "Sync is disabled."
                )

            else:
                self.summary.set(
                    f"Shared revision {result.revision}: "
                    f"{len(result.items)} planned change(s). "
                    "You can synchronize after confirming."
                )

            self.state.set("Preview ready")

        elif label == "Synchronizing...":
            uploaded = len(result.uploaded)
            downloaded = len(result.downloaded)

            if result.complete:
                revision = (
                    result.checkpoint.baseline.revision
                )
                self.summary.set(
                    f"Success. Sent {uploaded} and received "
                    f"{downloaded} file(s). "
                    f"Shared revision: {revision}."
                )
                self.state.set("Synchronized")

            else:
                self.summary.set(
                    "Synchronization stopped at "
                    f"'{result.status.value}'. "
                    "Review changes before trying again."
                )
                self.state.set("Attention needed")

            self.progress.set(
                "Run Preview again to see the current state."
            )

    def _drain(self) -> None:
        try:
            while True:
                kind, payload = self._events.get_nowait()

                if kind == "shutdown_done":
                    self._busy = False
                    self.root.destroy()
                    return

                elif kind == "shutdown_error":
                    self._busy = False
                    self._closing = False
                    self.state.set(
                        "Could not close connections"
                    )

                    messagebox.showerror(
                        "Shutdown incomplete",
                        (
                            "SyncBridge could not stop cleanly: "
                            f"{payload}\n\n"
                            "Keep this window open and "
                            "retry closing."
                        ),
                        parent=self.root,
                    )

                elif kind == "progress":
                    self.progress.set(
                        f"{payload.direction}: "
                        f"{payload.path} "
                        f"({payload.transferred:,} / "
                        f"{payload.total:,} bytes)"
                    )

                elif kind == "error":
                    self._busy = False

                    code, message, next_step = (
                        explain_error(payload)
                    )

                    self.state.set(
                        "Operation stopped"
                    )
                    self.summary.set(
                        f"[{code}] {message} {next_step}"
                    )
                    self.progress.set(str(payload))

                    messagebox.showerror(
                        "SyncBridge stopped safely",
                        (
                            f"[{code}] {message}\n\n"
                            f"{next_step}\n\n"
                            f"Details: {payload}"
                        ),
                        parent=self.root,
                    )

                else:
                    self._busy = False
                    label, value = payload
                    self._display_result(
                        label,
                        value,
                    )

                self._buttons()

        except queue.Empty:
            pass

        if self._closing and not self._busy:
            if self.controller.running:
                self._run_shutdown()
            else:
                self.root.destroy()
            return

        self.root.after(
            80,
            self._drain,
        )

    def _run_shutdown(self) -> None:
        self._busy = True
        self.state.set(
            "Closing connections..."
        )
        self._buttons()

        def stop():
            try:
                self.controller.stop()

            except Exception as exc:
                self._events.put(
                    ("shutdown_error", exc)
                )

            else:
                self._events.put(
                    ("shutdown_done", None)
                )

        self._worker = threading.Thread(
            target=stop,
            name="SyncBridgeDesktopShutdown",
            daemon=False,
        )
        self._worker.start()

    def _close(self) -> None:
        if self._closing:
            return

        self._closing = True
        self.state.set(
            "Waiting for current operation to finish..."
        )
        self._buttons()

        if not self._busy:
            if self.controller.running:
                self._run_shutdown()
            else:
                self.root.destroy()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="SyncBridge guarded manual desktop beta"
    )

    parser.add_argument(
        "--profile",
        type=Path,
        help="Existing local profile directory",
    )
    parser.add_argument(
        "--bind-address",
        default="127.0.0.1",
    )
    parser.add_argument(
        "--listen-ports",
        nargs=3,
        type=int,
        metavar=(
            "MANIFEST",
            "TRANSFER",
            "AGREEMENT",
        ),
    )
    parser.add_argument(
        "--lock-port",
        type=int,
        default=45846,
    )
    parser.add_argument(
        "--validation-port",
        type=int,
        default=45847,
    )

    options = parser.parse_args(argv)

    store = ConfigStore(
        options.profile / "settings.json"
        if options.profile
        else None
    )

    controller = DesktopController(
        store,
        bind_address=options.bind_address,
        listen_ports=(
            tuple(options.listen_ports)
            if options.listen_ports
            else None
        ),
        lock_port=options.lock_port,
        validation_port=options.validation_port,
    )

    root = tk.Tk()
    SyncBridgeWindow(root, controller)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
