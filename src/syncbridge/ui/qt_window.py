
"""First PySide6 SyncBridge desktop: guarded manual sync for configured folders.

This runs alongside, rather than replacing, the Tkinter pairing/setup GUI.
All blocking controller calls run on workers; Qt widgets remain on the UI thread.
"""
from __future__ import annotations

import queue
import threading
from pathlib import Path

from PySide6.QtCore import QTimer, Qt, QUrl
from PySide6.QtGui import QCloseEvent, QDesktopServices, QFont
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QHeaderView,
)

from syncbridge.ui.desktop_controller import DesktopController, DesktopPreview


STYLE = """
QMainWindow, QWidget#root {
    background: #f3f6fb;
    color: #17263c;
}

QLabel {
    color: #17263c;
    font-family: 'Segoe UI';
    font-size: 10pt;
}

QLabel#brand {
    font-size: 22pt;
    font-weight: 700;
}

QLabel#heading {
    font-size: 12pt;
    font-weight: 700;
}

QLabel#muted {
    color: #607087;
    font-size: 9pt;
}

QLabel#status {
    color: #215fba;
    background: #e7f0ff;
    border-radius: 12px;
    padding: 8px 13px;
    font-weight: 600;
}

QFrame#card {
    background: white;
    border: 1px solid #e1e7f0;
    border-radius: 14px;
}

QPushButton {
    background: #ffffff;
    color: #17263c;
    border: 1px solid #d3dce9;
    border-radius: 8px;
    padding: 10px 14px;
    font-family: 'Segoe UI';
    font-size: 10pt;
}

QPushButton:hover {
    background: #eaf2ff;
    color: #124d9c;
}

QPushButton:pressed {
    background: #dceafa;
    color: #123e7d;
}

QPushButton:disabled {
    color: #728198;
    background: #f3f5f8;
    border-color: #e1e6ef;
}

QPushButton#primary {
    background: #236de0;
    color: #ffffff;
    border-color: #236de0;
    font-weight: 600;
}

QPushButton#primary:hover {
    background: #155bc3;
    color: #ffffff;
}

QPushButton#primary:pressed {
    background: #114aa1;
    color: #ffffff;
}

QPushButton#primary:disabled {
    background: #b4c7e5;
    border-color: #b4c7e5;
    color: #ffffff;
}

QTableWidget {
    background: white;
    color: #17263c;
    border: 1px solid #e0e6ee;
    border-radius: 8px;
    gridline-color: #edf1f7;
    font-family: 'Segoe UI';
    font-size: 9pt;
    selection-background-color: #dceafa;
    selection-color: #17263c;
}

QHeaderView::section {
    background: #f5f7fb;
    color: #456079;
    padding: 10px;
    border: none;
    border-bottom: 1px solid #dce4ed;
    font-weight: 600;
}

QMenu {
    background: #ffffff;
    color: #17263c;
    border: 1px solid #d3dce9;
    padding: 5px;
    font-family: 'Segoe UI';
    font-size: 10pt;
}

QMenu::item {
    padding: 8px 20px;
    color: #17263c;
}

QMenu::item:selected {
    background: #e7f0ff;
    color: #124d9c;
}

QMenu::item:disabled {
    color: #728198;
}

/* Force readable colors for modal dialogs, even in Windows dark mode. */
QMessageBox {
    background-color: #ffffff;
    color: #17263c;
}

QMessageBox QLabel {
    background-color: transparent;
    color: #17263c;
    font-family: 'Segoe UI';
    font-size: 10pt;
}

QMessageBox QPushButton {
    color: #17263c;
    background-color: #f6f9ff;
    border: 1px solid #cbd7e7;
    border-radius: 7px;
    padding: 8px 16px;
    min-width: 64px;
}

QMessageBox QPushButton:hover {
    color: #124d9c;
    background-color: #eaf2ff;
}

QMessageBox QPushButton:disabled {
    color: #728198;
    background-color: #f3f5f8;
}
"""


class SyncBridgeQtWindow(QMainWindow):
    """A usable new UI for one already-approved share, without setup changes."""

    def __init__(self, controller: DesktopController) -> None:
        super().__init__()

        self.setFont(QFont("Segoe UI", 10))

        self.controller = controller
        self._events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._busy = False
        self._closing = False
        self._shutting_down = False
        self._allow_close = False
        self._configured = False
        self._preview: DesktopPreview | None = None
        self._worker: threading.Thread | None = None

        self._make_ui()
        self._load_profile()
        self._update_buttons()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._drain)
        self._timer.start(80)

        QTimer.singleShot(150, self._auto_connect)

    def _make_ui(self) -> None:
        self.setWindowTitle("SyncBridge")
        self.resize(1000, 690)
        self.setMinimumSize(760, 510)

        # Apply the light theme to the whole Qt application, including
        # confirmation and warning dialogs created later.
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(STYLE)

        self.setStyleSheet(STYLE)

        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)

        layout = QVBoxLayout(root)
        layout.setContentsMargins(24, 22, 24, 18)
        layout.setSpacing(15)

        header = QHBoxLayout()
        heading = QVBoxLayout()
        heading.setSpacing(4)

        brand = QLabel("SyncBridge")
        brand.setObjectName("brand")
        heading.addWidget(brand)

        heading.addWidget(
            self._label(
                "Simple, private file synchronization",
                "muted",
            )
        )

        header.addLayout(heading)
        header.addStretch()

        self.status = self._label("Getting ready", "status")
        header.addWidget(
            self.status,
            alignment=Qt.AlignmentFlag.AlignTop,
        )

        layout.addLayout(header)

        card = self._card()
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(20, 18, 20, 18)
        card_layout.setSpacing(11)

        card_layout.addWidget(
            self._label(
                "YOUR FOLDER CONNECTION",
                "heading",
            )
        )

        self.connection = QLabel(
            "Checking this computer's folder..."
        )
        self.connection.setWordWrap(True)
        card_layout.addWidget(self.connection)

        self.hint = self._label("", "muted")
        self.hint.setWordWrap(True)
        card_layout.addWidget(self.hint)

        controls = QHBoxLayout()

        self.open_folder_button = QPushButton(
            "Open my folder"
        )
        self.open_folder_button.clicked.connect(
            self._open_folder
        )
        controls.addWidget(self.open_folder_button)

        controls.addStretch()

        self.options = QPushButton(
            "Connection options  ▾"
        )

        menu = QMenu(self)
        self.reconnect_action = menu.addAction(
            "Reconnect"
        )
        self.disconnect_action = menu.addAction(
            "Disconnect"
        )

        self.reconnect_action.triggered.connect(
            self._connect
        )
        self.disconnect_action.triggered.connect(
            self._disconnect
        )

        self.options.setMenu(menu)
        controls.addWidget(self.options)

        card_layout.addLayout(controls)
        layout.addWidget(card)

        changes = self._card()
        changes_layout = QVBoxLayout(changes)
        changes_layout.setContentsMargins(20, 18, 20, 18)
        changes_layout.setSpacing(12)

        actions = QHBoxLayout()
        titles = QVBoxLayout()
        titles.setSpacing(4)

        titles.addWidget(
            self._label(
                "File changes",
                "heading",
            )
        )

        titles.addWidget(
            self._label(
                "See what will change before syncing.",
                "muted",
            )
        )

        actions.addLayout(titles)
        actions.addStretch()

        self.preview_button = QPushButton(
            "Check changes"
        )
        self.preview_button.clicked.connect(
            self._check_changes
        )
        actions.addWidget(self.preview_button)

        self.sync_button = QPushButton(
            "Sync files"
        )
        self.sync_button.setObjectName("primary")
        self.sync_button.clicked.connect(
            self._sync_files
        )
        actions.addWidget(self.sync_button)

        changes_layout.addLayout(actions)

        self.summary = QLabel(
            "Waiting for a folder connection."
        )
        self.summary.setWordWrap(True)
        changes_layout.addWidget(self.summary)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(
            ["Action", "File", "What happens"]
        )

        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.table.setAlternatingRowColors(True)

        self.table.horizontalHeader().setSectionResizeMode(
            0,
            QHeaderView.ResizeMode.ResizeToContents,
        )
        self.table.horizontalHeader().setSectionResizeMode(
            1,
            QHeaderView.ResizeMode.Stretch,
        )
        self.table.horizontalHeader().setSectionResizeMode(
            2,
            QHeaderView.ResizeMode.Stretch,
        )

        changes_layout.addWidget(
            self.table,
            stretch=1,
        )

        layout.addWidget(changes, stretch=1)

        self.progress = self._label("", "muted")
        self.progress.setWordWrap(True)
        layout.addWidget(self.progress)

        layout.addWidget(
            self._label(
                "Sync happens only when you approve it. "
                "Conflicts and deletions need review.",
                "muted",
            )
        )

    @staticmethod
    def _label(value: str, kind: str) -> QLabel:
        result = QLabel(value)
        result.setObjectName(kind)
        return result

    @staticmethod
    def _card() -> QFrame:
        result = QFrame()
        result.setObjectName("card")
        return result

    def _load_profile(self) -> None:
        try:
            profile = self.controller.profile()
        except Exception:
            self._configured = False
            self.connection.setText(
                "No synchronized folder configured yet"
            )
            self.hint.setText(
                "For now, pair computers and choose folders "
                "in the existing SyncBridge desktop app. "
                "This new interface handles an already-connected folder."
            )
            self.status.setText("Setup needed")
            return

        self._configured = True
        self.connection.setText(
            f"{profile.folder_name}  ·  {profile.device_name}\n"
            f"My folder: {profile.local_root}\n"
            f"Paired computer: {profile.remote_host}"
        )
        self.hint.setText(
            "Your files stay on your two computers."
        )
        self.status.setText("Connecting...")

    def _update_buttons(self) -> None:
        ready = not self._busy and not self._closing
        running = self.controller.running

        self.preview_button.setEnabled(
            ready and running
        )
        self.sync_button.setEnabled(
            ready
            and running
            and self._preview is not None
            and not self._preview.requires_review
            and bool(self._preview.items)
        )
        self.open_folder_button.setEnabled(
            ready and self._configured
        )
        self.reconnect_action.setEnabled(
            ready and self._configured and not running
        )
        self.disconnect_action.setEnabled(
            ready and running
        )

    def _auto_connect(self) -> None:
        if (
            self._configured
            and not self.controller.running
            and not self._closing
        ):
            self._connect()

    def _work(self, name: str, callback) -> None:
        if self._busy or self._closing:
            return

        self._busy = True
        self.status.setText(
            {
                "connect": "Connecting...",
                "preview": "Checking files...",
                "sync": "Synchronizing...",
                "stop": "Disconnecting...",
            }[name]
        )
        self._update_buttons()

        def runner() -> None:
            try:
                result = callback()
            except Exception as exc:
                self._events.put(
                    ("error", (name, exc))
                )
            else:
                self._events.put(
                    ("done", (name, result))
                )

        self._worker = threading.Thread(
            target=runner,
            name=f"SyncBridgeQt-{name}",
            daemon=False,
        )
        self._worker.start()

    def _connect(self) -> None:
        if self._configured:
            self._work(
                "connect",
                self.controller.start,
            )

    def _disconnect(self) -> None:
        self._preview = None
        self.table.setRowCount(0)
        self._work(
            "stop",
            self.controller.stop,
        )

    def _check_changes(self) -> None:
        self._preview = None
        self._update_buttons()
        self._work(
            "preview",
            self.controller.preview,
        )

    def _sync_files(self) -> None:
        plan = self._preview

        if (
            plan is None
            or plan.requires_review
            or not plan.items
        ):
            return

        count = len(plan.items)

        warning = (
            "\n\nThis is a large change list. "
            "Transfers may take time."
            if count >= 50
            else ""
        )

        answer = QMessageBox.question(
            self,
            "Synchronize these files?",
            f"{count} planned file change(s).\n\n"
            "Files may be sent or received in either direction."
            f"{warning}\n\n"
            "Conflicts and deletions will not be applied automatically."
            "\n\nContinue?",
            QMessageBox.StandardButton.Yes
            | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if answer != QMessageBox.StandardButton.Yes:
            return

        self._preview = None
        self.table.setRowCount(0)

        self._work(
            "sync",
            lambda: self.controller.sync_once(
                on_progress=self._on_progress
            ),
        )

    def _on_progress(self, event: object) -> None:
        self._events.put(
            ("progress", event)
        )

    def _open_folder(self) -> None:
        try:
            folder = Path(
                self.controller.profile().local_root
            ).resolve(strict=True)

            if (
                not folder.is_dir()
                or not QDesktopServices.openUrl(
                    QUrl.fromLocalFile(str(folder))
                )
            ):
                raise OSError(
                    "Could not open the folder"
                )

        except Exception as exc:
            QMessageBox.warning(
                self,
                "Cannot open folder",
                str(exc),
            )

    def _display_plan(
        self,
        plan: DesktopPreview,
    ) -> None:
        self._preview = plan
        self.table.setRowCount(
            len(plan.items)
        )

        for row, item in enumerate(plan.items):
            for col, value in enumerate(
                (
                    item.action,
                    item.path,
                    item.description,
                )
            ):
                self.table.setItem(
                    row,
                    col,
                    QTableWidgetItem(str(value)),
                )

        if plan.requires_review:
            self.summary.setText(
                f"{len(plan.items)} change(s) found. "
                "Conflicts or deletions need review "
                "before SyncBridge can continue."
            )
        elif not plan.items:
            self.summary.setText(
                "Everything is up to date."
            )
        else:
            self.summary.setText(
                f"{len(plan.items)} change(s) found. "
                "Review the list, then choose Sync files."
            )

        self.status.setText("Changes checked")

    def _finish(
        self,
        name: str,
        result: object,
    ) -> None:
        if name == "connect":
            self.status.setText("Connected")
            self.summary.setText(
                "Connected. Check changes whenever you're ready."
            )

        elif name == "stop":
            self.status.setText("Disconnected")
            self.summary.setText(
                "Connection stopped."
            )

        elif name == "preview":
            self._display_plan(result)

        elif name == "sync":
            if result.complete:
                self.status.setText("Synchronized")
                self.summary.setText(
                    f"Finished. Sent {len(result.uploaded)} file(s) "
                    f"and received {len(result.downloaded)} file(s). "
                    "Check changes again to see the latest state."
                )
            else:
                self.status.setText("Needs attention")
                self.summary.setText(
                    "Synchronization paused safely. "
                    "Check changes before retrying."
                )

            self.progress.setText("")

    def _drain(self) -> None:
        for _ in range(100):
            try:
                kind, payload = self._events.get_nowait()
            except queue.Empty:
                break

            try:
                if kind == "progress":
                    if not self._closing:
                        self.progress.setText(
                            f"{payload.direction}: "
                            f"{payload.path} "
                            f"({payload.transferred:,}/"
                            f"{payload.total:,} bytes)"
                        )

                elif kind == "done":
                    self._busy = False
                    if not self._closing:
                        self._finish(*payload)

                elif kind == "error":
                    self._busy = False
                    if not self._closing:
                        name, error = payload
                        self.status.setText("Needs attention")
                        self.summary.setText(
                            f"Could not complete {name}: {error}"
                        )
                        QMessageBox.warning(
                            self,
                            "SyncBridge",
                            str(error),
                        )

                elif kind == "shutdown-ok":
                    self._allow_close = True
                    self.close()
                    return

                elif kind == "shutdown-error":
                    self._closing = False
                    self._shutting_down = False
                    self.status.setText("Could not close")
                    QMessageBox.warning(
                        self,
                        "Shutdown issue",
                        str(payload),
                    )

            except Exception as exc:
                self._busy = False
                self._preview = None
                self.status.setText("Needs attention")
                self.summary.setText(
                    "Couldn't display an operation result: "
                    f"{exc}"
                )

            self._update_buttons()

        if (
            self._closing
            and not self._busy
            and not self._shutting_down
        ):
            self._shutdown()

    def _shutdown(self) -> None:
        self._shutting_down = True
        self.status.setText("Closing...")

        def runner() -> None:
            try:
                self.controller.stop()
            except Exception as exc:
                self._events.put(
                    ("shutdown-error", exc)
                )
            else:
                self._events.put(
                    ("shutdown-ok", None)
                )

        self._worker = threading.Thread(
            target=runner,
            name="SyncBridgeQt-Shutdown",
            daemon=False,
        )
        self._worker.start()

    def closeEvent(
        self,
        event: QCloseEvent,
    ) -> None:
        if self._allow_close:
            self._timer.stop()
            event.accept()
            return

        event.ignore()

        if not self._closing:
            self._closing = True
            self.status.setText("Closing...")
            self.summary.setText(
                "Finishing the current operation before closing."
            )
            self._update_buttons()

            if not self._busy:
                self._shutdown()
