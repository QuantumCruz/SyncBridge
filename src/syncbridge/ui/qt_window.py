
"""Simple SyncBridge Qt desktop using the tested guarded synchronization engine.

Background file operations never touch Qt widgets. Unknown-duration operations
show an indeterminate bar; transfer callbacks show progress for ONE file only.
Disconnect stops the current runtime and requires selecting a computer again.
It does not erase either computer's share or grant permissions to a new peer.
"""
from __future__ import annotations

import ipaddress
import os
import queue
import socket
import threading
from pathlib import Path

from PySide6.QtCore import QTimer, Qt, QUrl
from PySide6.QtGui import QCloseEvent, QDesktopServices, QFont
from PySide6.QtWidgets import (
    QApplication, QFrame, QHBoxLayout, QHeaderView, QLabel, QMainWindow,
    QMessageBox, QProgressBar, QPushButton, QTabWidget, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from syncbridge.ui.desktop_controller import DesktopController, DesktopPreview
from syncbridge.ui.qt_onboarding import NetworkOptions, QtOnboarding

STYLE = """
QWidget, QMainWindow { background: #f3f6fb; color: #17263c; font: 10pt 'Segoe UI'; }
QLabel { background: transparent; color: #17263c; }
QLabel#brand { font-size: 22pt; font-weight: bold; }
QLabel#heading { font-size: 12pt; font-weight: bold; }
QLabel#muted { color: #586b83; }
QLabel#status { color: #1753a8; background: #e7f0ff;
    padding: 8px 12px; border-radius: 9px; }
QFrame#card { background: white; border: 1px solid #dfe7f1; border-radius: 12px; }
QFrame#card QLabel { background: transparent; }
QPushButton { background: white; color: #17263c; border: 1px solid #cbd8e8;
    border-radius: 8px; padding: 9px 14px; }
QPushButton:hover { background: #eaf2ff; color: #124d9c; }
QPushButton:disabled { background: #f2f4f8; color: #677992;
    border-color: #e0e4eb; }
QPushButton#primary { background: #236de0; color: white;
    border-color: #236de0; font-weight: bold; }
QPushButton#primary:hover { background: #155bc3; color: white; }
QPushButton#primary:disabled { background: #afc5e7;
    border-color: #afc5e7; color: white; }
QTabWidget::pane { background: white; border: 1px solid #dde6f0; }
QTabBar::tab { background: #e9eef7; color: #17263c; padding: 10px 18px; }
QTabBar::tab:selected { background: white; color: #145cbd; font-weight: bold; }
QTableWidget { background: white; alternate-background-color: #f8faff;
    color: #17263c; gridline-color: #ebeff6;
    selection-background-color: #dceafa; selection-color: #17263c; }
QHeaderView::section { background: #f5f7fb; color: #344a64;
    padding: 8px; border: none; }
QProgressBar { background: #e7ecf4; color: #17263c; border: 1px solid #cbd8e8;
    border-radius: 5px; text-align: center; min-height: 13px; }
QProgressBar::chunk { background: #236de0; border-radius: 4px; }
QDialog, QMessageBox { background: white; color: #17263c; }
QDialog QLabel, QMessageBox QLabel, QDialog QCheckBox {
    color: #17263c; background: transparent; }
QMessageBox QPushButton { background: #f5f8ff; color: #17263c; min-width: 60px; }
QListWidget, QLineEdit { background: white; color: #17263c;
    border: 1px solid #cbd8e8; }
QListWidget::item:selected { background: #dceafa; color: #17263c; }
"""


def local_address_for_peer(host: str) -> str:
    """Choose a unicast local address for the route to the other computer."""
    target = ipaddress.IPv4Address(host)
    if target.is_loopback:
        return "127.0.0.1"
    if target.is_unspecified or target.is_multicast:
        raise ValueError("The other computer has an invalid network address")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((str(target), 9))
        address = probe.getsockname()[0]
    actual = ipaddress.IPv4Address(address)
    if actual.is_unspecified or actual.is_loopback or actual.is_multicast:
        raise OSError("No usable local network address was found")
    return address


class SyncBridgeQtWindow(QMainWindow):
    def __init__(
        self, controller: DesktopController,
        *, network_options: NetworkOptions | None = None,
    ) -> None:
        super().__init__()
        self.setFont(QFont("Segoe UI", 10))
        self.controller = controller
        self._events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._busy = False
        self._closing = False
        self._shutting_down = False
        self._allow_close = False
        self._configured = False
        self._paused = False
        self._preview: DesktopPreview | None = None
        self._worker: threading.Thread | None = None
        self._paired_name = ""
        self._loaded: set[str] = set()
        self._render_kind: str | None = None
        self._render_rows: list[tuple[str, int]] = []
        self._render_offset = 0
        self._render_truncated = False

        self.onboarding = (
            QtOnboarding(self, controller, network_options, self._paired, self._folders_ready)
            if network_options is not None else None
        )
        self._make_ui()
        self._load_profile()
        self._update_buttons()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._drain)
        self._timer.start(80)
        QTimer.singleShot(150, self._auto_connect)
        if self.onboarding is not None:
            QTimer.singleShot(50, self._start_network)

    @staticmethod
    def _label(text: str, kind: str = "") -> QLabel:
        label = QLabel(text)
        if kind:
            label.setObjectName(kind)
        label.setWordWrap(True)
        return label

    @staticmethod
    def _table(headers: list[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.verticalHeader().hide()
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        return table

    def _make_ui(self) -> None:
        self.setWindowTitle("SyncBridge")
        self.resize(1060, 720)
        self.setMinimumSize(800, 560)
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(STYLE)
        self.setStyleSheet(STYLE)
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(22, 18, 22, 18)
        layout.setSpacing(12)

        title_row = QHBoxLayout()
        title_row.addWidget(self._label("SyncBridge", "brand"))
        title_row.addStretch()
        self.status = self._label("Getting ready", "status")
        title_row.addWidget(self.status)
        layout.addLayout(title_row)
        layout.addWidget(self._label(
            "Pair, choose folders, and keep your files together.", "muted"
        ))

        card = QFrame()
        card.setObjectName("card")
        box = QVBoxLayout(card)
        box.setContentsMargins(18, 14, 18, 14)
        box.addWidget(self._label("YOUR CONNECTION", "heading"))
        self.connection = self._label("Find a computer to get started.")
        box.addWidget(self.connection)
        self.hint = self._label("", "muted")
        box.addWidget(self.hint)
        controls = QHBoxLayout()
        self.find_button = QPushButton("Find computer")
        self.find_button.clicked.connect(self._find_computers)
        controls.addWidget(self.find_button)
        self.folder_select_button = QPushButton("Choose my folder")
        self.folder_select_button.clicked.connect(self._choose_folder)
        controls.addWidget(self.folder_select_button)
        self.open_folder_button = QPushButton("Open my folder")
        self.open_folder_button.clicked.connect(self._open_folder)
        controls.addWidget(self.open_folder_button)
        controls.addStretch()
        self.disconnect_button = QPushButton("Disconnect")
        self.disconnect_button.clicked.connect(self._toggle_connection)
        controls.addWidget(self.disconnect_button)
        box.addLayout(controls)
        layout.addWidget(card)

        changes_card = QFrame()
        changes_card.setObjectName("card")
        changes = QVBoxLayout(changes_card)
        changes.setContentsMargins(18, 14, 18, 14)

        action_row = QHBoxLayout()
        action_row.addWidget(self._label("YOUR FILES", "heading"))
        action_row.addStretch()
        self.preview_button = QPushButton("Preview differences")
        self.preview_button.clicked.connect(self._check_changes)
        action_row.addWidget(self.preview_button)
        self.sync_button = QPushButton("Sync files")
        self.sync_button.setObjectName("primary")
        self.sync_button.clicked.connect(self._sync_files)
        action_row.addWidget(self.sync_button)
        changes.addLayout(action_row)
        self.summary = self._label("Connect folders to see your files.")
        changes.addWidget(self.summary)

        self.tabs = QTabWidget()
        self.local_table = self._table(["File on my computer", "Size"])
        self.remote_table = self._table(["File on paired computer", "Size"])
        self.table = self._table(["Action", "File", "What happens"])
        self.tabs.addTab(self.local_table, "My files")
        self.tabs.addTab(self.remote_table, "Other computer's files")
        self.tabs.addTab(self.table, "Differences")
        self.tabs.currentChanged.connect(self._tab_changed)
        changes.addWidget(self.tabs, stretch=1)
        layout.addWidget(changes_card, stretch=1)

        self.activity_label = self._label("", "muted")
        layout.addWidget(self.activity_label)
        self.activity_bar = QProgressBar()
        self.activity_bar.setTextVisible(True)
        layout.addWidget(self.activity_bar)
        self.activity_label.hide()
        self.activity_bar.hide()
        self.progress = self._label("", "muted")
        layout.addWidget(self.progress)
        layout.addWidget(self._label(
            "Conflicts and deletions need review before changes are applied.", "muted"
        ))

    def _show_activity(self, message: str, *, done: int | None = None,
                       total: int | None = None) -> None:
        """Unknown total => moving bar; known total => percentage of this stage."""
        self.activity_label.setText(message)
        self.activity_label.show()
        if total is None or total <= 0 or done is None:
            self.activity_bar.setRange(0, 0)
            self.activity_bar.setFormat("")
        else:
            self.activity_bar.setRange(0, 100)
            self.activity_bar.setValue(max(0, min(100, int(done * 100 / total))))
            self.activity_bar.setFormat("%p%")
        self.activity_bar.show()

    def _hide_activity(self) -> None:
        self.activity_bar.hide()
        self.activity_label.hide()

    def _onboarding_activity(self) -> None:
        """Reflect slow approval stages without blocking any window controls."""
        if self._busy or self._closing or self.onboarding is None or not self.onboarding.started:
            return
        if self.onboarding._pair_busy:
            self._show_activity("Waiting for both computers to approve pairing...")
        elif self.onboarding._folder_busy:
            self._show_activity("Waiting for the other computer to choose a folder...")
        elif self.onboarding.folders and self.onboarding.folders.pending():
            self._show_activity("Waiting for your folder choice...")
        elif any(not item.enabled for item in self.controller.store.load().shares):
            self._show_activity("Finishing folder setup securely...")
        else:
            self._hide_activity()

    def _load_profile(self) -> None:
        try:
            profile = self.controller.profile()
        except Exception:
            self._configured = False
            peer = (
                self.onboarding.paired_device()
                if self.onboarding and self.onboarding.started else None
            )
            name = self._paired_name or (peer.name if peer else "")
            self.connection.setText(
                f"Paired with {name}. Choose my folder to continue." if name
                else "No paired computer yet. Select Find computer."
            )
            self.hint.setText("Both people choose a folder on their own computer.")
            self.status.setText("Choose a folder" if name else "Not connected")
            return
        self._configured = True
        if self._paused:
            self.connection.setText(
                f"Disconnected from {profile.remote_host} · {profile.folder_name}\n"
                "Select Find computer to reconnect to this saved folder."
            )
            self.hint.setText("Files and pairing have been kept; no files were deleted.")
            self.status.setText("Disconnected")
            return
        peer = (
            self.onboarding.paired_device()
            if self.onboarding and self.onboarding.started else None
        )
        name = self._paired_name or (peer.name if peer else profile.remote_host)
        self.connection.setText(
            f"Connected with {name}  ·  {profile.folder_name}\n"
            f"My folder: {profile.local_root}"
        )
        self.hint.setText("Browse either folder, or preview the differences.")
        self.status.setText("Connected" if self.controller.running else "Connecting...")

    def _paired(self, name: str) -> None:
        """A saved relationship resumes only after choosing that computer again."""
        if self._configured and self._paused:
            selected = self.onboarding.current_peer if self.onboarding else None
            saved = next((s for s in self.controller.store.load().shares if s.enabled), None)
            if selected is None or saved is None or selected.node_id != saved.peer_node_id:
                QMessageBox.information(
                    self, "Different computer",
                    "This folder is still linked to another computer. "
                    "Switching folder partners isn't supported safely yet. "
                    "Your files and saved connection have not changed.",
                )
                return
            self._paused = False
            self._paired_name = name
            self._load_profile()
            self._update_buttons()
            self._auto_connect()
            return
        self._paired_name = name
        self._load_profile()
        self._update_buttons()

    def _start_network(self) -> None:
        if self._closing:
            return
        try:
            self.onboarding.start()
        except Exception as exc:
            QMessageBox.warning(self, "Nearby computers unavailable", str(exc))
        self._load_profile()
        self._update_buttons()

    def _find_computers(self) -> None:
        if self.onboarding:
            self.onboarding.show_devices()

    def _choose_folder(self) -> None:
        if self.onboarding:
            self.onboarding.choose_folder()

    def _folders_ready(self) -> None:
        self._loaded.clear()
        self._load_profile()
        self._update_buttons()
        self._auto_connect()

    def _prepare_listener(self) -> None:
        profile = self.controller.profile()
        runtime = getattr(self.controller, "runtime", None)
        if runtime is not None:
            runtime.bind_address = local_address_for_peer(profile.remote_host)

    def _auto_connect(self) -> None:
        if self._configured and not self._paused and not self.controller.running and not self._closing:
            self._connect()

    def _update_buttons(self) -> None:
        available = not self._busy and not self._closing
        running = self.controller.running
        paired = bool(
            self._paired_name or (
                self.onboarding and self.onboarding.started
                and self.onboarding.paired_device()
            )
        )
        self.find_button.setEnabled(
            available and self.onboarding is not None and self.onboarding.started
        )
        self.folder_select_button.setEnabled(
            available and not self._paused and paired and not self._configured
        )
        self.open_folder_button.setEnabled(available and self._configured)
        self.preview_button.setEnabled(available and running)
        self.sync_button.setEnabled(
            available and running and self._preview is not None
            and not self._preview.requires_review and bool(self._preview.items)
        )
        self.disconnect_button.setText("Disconnect")
        self.disconnect_button.setVisible(not self._paused and (running or self._busy))
        self.disconnect_button.setEnabled(available and running)

    def _work(self, kind: str, action) -> None:
        if self._busy or self._closing:
            return
        self._busy = True
        self._update_buttons()
        descriptions = {
            "connect": "Connecting to computer...",
            "stop": "Disconnecting safely...",
            "preview": "Checking differences (scanning files)...",
            "sync": "Synchronizing files...",
            "local": "Loading my file list...",
            "remote": "Loading the other computer's file list...",
        }
        self.status.setText(descriptions[kind])
        self._show_activity(descriptions[kind])

        def runner():
            try:
                result = action()
            except Exception as exc:
                self._events.put(("error", (kind, exc)))
            else:
                self._events.put(("done", (kind, result)))

        self._worker = threading.Thread(
            target=runner, name=f"SyncBridgeQt-{kind}", daemon=False
        )
        self._worker.start()

    def _connect(self) -> None:
        if self._configured and not self._paused:
            def connect():
                self._prepare_listener()
                return self.controller.start()
            self._work("connect", connect)

    def _toggle_connection(self) -> None:
        """Stop sync and return to computer picker; do not erase folder grants."""
        if not self.controller.running or self._busy:
            return
        self._paused = True
        self._paired_name = ""
        self._preview = None
        self._loaded.clear()
        self.table.setRowCount(0)
        self.local_table.setRowCount(0)
        self.remote_table.setRowCount(0)
        self._work("stop", self.controller.stop)

    def _check_changes(self) -> None:
        self._preview = None
        self._update_buttons()
        self._work("preview", self.controller.preview)

    def _sync_files(self) -> None:
        plan = self._preview
        if plan is None or plan.requires_review or not plan.items:
            return
        answer = QMessageBox.question(
            self, "Sync these files?",
            f"{len(plan.items)} planned change(s). Files may be sent or received.\n\n"
            "Conflicts and deletions are not automatically applied.\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._preview = None
        self.table.setRowCount(0)
        self._work("sync", lambda: self.controller.sync_once(on_progress=self._on_progress))

    def _on_progress(self, item) -> None:
        self._events.put(("progress", item))

    def _open_folder(self) -> None:
        try:
            root = Path(self.controller.profile().local_root).resolve(strict=True)
            if not root.is_dir() or not QDesktopServices.openUrl(QUrl.fromLocalFile(str(root))):
                raise OSError("Could not open folder")
        except Exception as exc:
            QMessageBox.warning(self, "Cannot open folder", str(exc))

    @staticmethod
    def _list_local(root: Path):
        rows = []
        for parent, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [
                d for d in dirs if d not in {".git", ".venv", "__pycache__", ".syncbridge"}
                and not (Path(parent) / d).is_symlink()
            ]
            for filename in files:
                path = Path(parent) / filename
                if filename in {".git", ".venv", "__pycache__", ".syncbridge"} or path.is_symlink():
                    continue
                try:
                    rows.append((path.relative_to(root).as_posix(), path.stat().st_size))
                except (OSError, ValueError):
                    continue
                if len(rows) >= 3000:
                    return rows, True
        return rows, False

    def _list_remote(self):
        share = next(s for s in self.controller.store.load().shares if s.enabled)
        client = self.controller.runtime.manifest_client
        if client is None:
            raise RuntimeError("The connection is not ready")
        manifest = client.fetch(
            share.remote_host, share.manifest_port, share.peer_node_id, share.share_id
        )
        records = manifest.snapshot.files
        rows = [(item.relative_path, item.size) for item in records.values()]
        return rows[:3000], len(rows) > 3000

    def _tab_changed(self, index: int) -> None:
        if not self.controller.running or self._busy or self._closing:
            return
        kind = "local" if index == 0 else "remote" if index == 1 else None
        if kind is None or kind in self._loaded:
            return
        if kind == "local":
            root = Path(self.controller.profile().local_root)
            self._work("local", lambda: self._list_local(root))
        else:
            self._work("remote", self._list_remote)

    @staticmethod
    def _size(value: int) -> str:
        if value < 1024:
            return f"{value} B"
        for unit in ("KB", "MB", "GB", "TB"):
            value /= 1024
            if value < 1024:
                return f"{value:.1f} {unit}"
        return f"{value:.1f} PB"

    def _display_files(self, kind: str, result) -> None:
        """Render large listings in batches to keep the event loop responsive."""
        rows, truncated = result
        self._render_kind = kind
        self._render_rows = list(rows)
        self._render_truncated = bool(truncated)
        self._render_offset = 0
        target = self.local_table if kind == "local" else self.remote_table
        target.setRowCount(0)
        self._busy = True
        self._update_buttons()
        self._show_activity(f"Displaying {kind} files...", done=0, total=max(1, len(rows)))
        QTimer.singleShot(0, self._render_batch)

    def _render_batch(self) -> None:
        if self._closing or self._render_kind is None:
            return
        kind = self._render_kind
        target = self.local_table if kind == "local" else self.remote_table
        end = min(self._render_offset + 100, len(self._render_rows))
        target.setRowCount(end)
        for i in range(self._render_offset, end):
            path, size = self._render_rows[i]
            target.setItem(i, 0, QTableWidgetItem(str(path)))
            target.setItem(i, 1, QTableWidgetItem(self._size(size)))
        self._render_offset = end
        if end < len(self._render_rows):
            self._show_activity(
                f"Displaying {kind} files...", done=end, total=len(self._render_rows)
            )
            QTimer.singleShot(0, self._render_batch)
            return
        self._loaded.add(kind)
        self._render_kind = None
        self._render_rows = []
        self._busy = False
        self._hide_activity()
        self.summary.setText(
            f"Showing {end} file(s)" +
            (" (first 3,000 only)" if self._render_truncated else "")
        )
        self.status.setText("Connected")
        self._update_buttons()
        self._tab_changed(self.tabs.currentIndex())

    def _display_plan(self, plan: DesktopPreview) -> None:
        self._preview = plan
        self.table.setRowCount(len(plan.items))
        for i, item in enumerate(plan.items):
            for j, value in enumerate((item.action, item.path, item.description)):
                self.table.setItem(i, j, QTableWidgetItem(str(value)))
        self.tabs.setCurrentIndex(2)
        if plan.requires_review:
            self.summary.setText(
                f"{len(plan.items)} difference(s). Conflicts or deletions need review."
            )
        elif not plan.items:
            self.summary.setText("Everything is up to date.")
        else:
            self.summary.setText(
                f"{len(plan.items)} difference(s). Review, then choose Sync files."
            )
        self.status.setText("Changes checked")

    def _finish(self, kind: str, result) -> None:
        if kind == "connect":
            self._load_profile()
            self.summary.setText("Connected. Browse folders or preview differences.")
            self._tab_changed(self.tabs.currentIndex())
        elif kind == "stop":
            self._load_profile()
            self.summary.setText("Disconnected. Choose Find computer to connect again.")
            self.progress.setText("")
        elif kind == "preview":
            self._display_plan(result)
        elif kind == "sync":
            self.status.setText("Synchronized" if result.complete else "Needs attention")
            self.summary.setText(
                f"Sent {len(result.uploaded)}, received {len(result.downloaded)} file(s). "
                "Preview again to see remaining differences."
                if result.complete else
                "Synchronization paused. Preview again before retrying."
            )
            self._loaded.clear()
            self.progress.setText("")
            self._tab_changed(self.tabs.currentIndex())
        elif kind in ("local", "remote"):
            self._display_files(kind, result)

    def _drain(self) -> None:
        if self.onboarding and not self._closing:
            try:
                self.onboarding.poll()
            except Exception as exc:
                self.progress.setText(f"Nearby connection issue: {exc}")
        for _ in range(100):
            try:
                kind, value = self._events.get_nowait()
            except queue.Empty:
                break
            try:
                if kind == "progress":
                    if not self._closing:
                        self._show_activity(
                            f"Transferring current file: {value.path}",
                            done=value.transferred, total=value.total,
                        )
                        self.progress.setText(
                            f"{value.direction}: {self._size(value.transferred)} "
                            f"/ {self._size(value.total)} (current file)"
                        )
                elif kind == "done":
                    self._busy = False
                    if not self._closing:
                        self._hide_activity()
                        self._finish(*value)
                elif kind == "error":
                    self._busy = False
                    if not self._closing:
                        self._hide_activity()
                        action, exc = value
                        self.status.setText("Needs attention")
                        message = (
                            "The other computer isn't ready. Keep SyncBridge open "
                            "there and try again."
                            if "10061" in str(exc) or "Cannot reach manifest service" in str(exc)
                            else f"Could not {action}: {exc}"
                        )
                        self.summary.setText(message)
                        QMessageBox.warning(self, "SyncBridge", message)
                elif kind == "shutdown-ok":
                    self._allow_close = True
                    self.close()
                    return
                elif kind == "shutdown-error":
                    self._closing = False
                    self._shutting_down = False
                    self.status.setText("Could not close")
                    QMessageBox.warning(self, "Shutdown issue", str(value))
            except Exception as exc:
                self._busy = False
                self._preview = None
                self._hide_activity()
                self.summary.setText(f"Unable to display result: {exc}")
            self._update_buttons()
        if not self._busy and not self._closing:
            try:
                self._onboarding_activity()
            except Exception as exc:
                self.progress.setText(f"Connection status unavailable: {exc}")
        if self._closing and not self._busy and not self._shutting_down:
            self._shutdown()

    def _shutdown(self) -> None:
        self._shutting_down = True
        self.status.setText("Closing...")
        self._show_activity("Closing network connections...")

        def worker():
            problems = []
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
            target=worker, name="SyncBridgeQt-Shutdown", daemon=False
        )
        self._worker.start()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._allow_close:
            self._timer.stop()
            event.accept()
            return
        event.ignore()
        if not self._closing:
            self._closing = True
            # Table rendering is a UI-only task and can be cancelled at once.
            # Otherwise a pending batch would leave _busy=True forever.
            if self._render_kind is not None:
                self._render_kind = None
                self._render_rows = []
                self._busy = False
            if self.onboarding:
                self.onboarding.close_ui()
            self.status.setText("Closing...")
            self._update_buttons()
            if not self._busy:
                self._shutdown()
