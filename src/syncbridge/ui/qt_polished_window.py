
"""Release-quality Qt presentation for SyncBridge.

Reuses the existing authenticated connection, preview, synchronization,
folder-change and recovery workflows. All permissions remain enforced by
the original controller and session lifecycle.

Transfer percentages describe one file at a time, never an invented
overall synchronization percentage.
"""
from __future__ import annotations

import threading
from collections import Counter
from pathlib import PurePosixPath

from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QFrame,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QMenu,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
)

from syncbridge.ui.desktop_controller import DesktopPhase
from syncbridge.ui.qt_clean_start_window import SyncBridgeCleanStartWindow


POLISHED_STYLE = """
QMainWindow, QWidget#syncbridgeRoot {
    background: #F5F7FB;
    color: #18263B;
    font: 10pt "Segoe UI";
}
QLabel {
    color: #18263B;
    background: transparent;
}
QLabel#wordmark {
    font-size: 19pt;
    font-weight: 750;
    color: #14213B;
}
QLabel#deviceName {
    font-size: 9pt;
    color: #65758F;
    padding-left: 10px;
}
QLabel#statusPill {
    border-radius: 12px;
    padding: 5px 12px;
    background: #E8EDF5;
    color: #5B6A83;
    font-weight: 650;
    font-size: 9pt;
}
QLabel#statusPill[tone="connected"] {
    background: #DDF6EC;
    color: #06764C;
}
QLabel#statusPill[tone="busy"] {
    background: #E6EEFF;
    color: #2858AA;
}
QLabel#statusPill[tone="warning"] {
    background: #FFF2D8;
    color: #945E12;
}
QFrame#connectionCard, QFrame#workspaceCard {
    background: white;
    border: 1px solid #E0E7F0;
    border-radius: 16px;
}
QLabel#connectionTitle {
    font-size: 15pt;
    font-weight: 700;
    color: #1B2B44;
}
QLabel#connectionHint {
    color: #65748C;
    font-size: 9.5pt;
}
QLabel#connectionMessage {
    border-radius: 8px;
    background: #F3F6FA;
    padding: 9px 12px;
    color: #52647E;
    font-size: 9pt;
}
QLabel#workspaceTitle {
    font-size: 11pt;
    font-weight: 700;
    color: #233550;
}
QPushButton {
    padding: 9px 14px;
    border: 1px solid #D5DFEB;
    border-radius: 9px;
    background: white;
    color: #263D5E;
    font-weight: 600;
}
QPushButton:hover:!disabled {
    background: #F0F5FF;
    border-color: #A8BCE6;
}
QPushButton:pressed {
    background: #E4EDFF;
}
QPushButton:disabled {
    color: #9BA9B8;
    background: #F4F6F9;
}
QPushButton#primary {
    background: #345CDF;
    border-color: #345CDF;
    color: white;
}
QPushButton#primary:hover:!disabled {
    background: #234CCB;
    border-color: #234CCB;
}
QPushButton#primary:disabled {
    background: #B7C5E7;
    border-color: #B7C5E7;
    color: white;
}
QPushButton#optionsButton {
    padding: 8px 18px;
    background: white;
    color: #50617D;
    border: 1px solid #D5DFEB;
    border-radius: 9px;
    min-width: 72px;
}
QPushButton#optionsButton:hover {
    background: #EDF3FF;
    color: #284CAD;
}
QMenu {
    background: white;
    border: 1px solid #DFE6F1;
    padding: 6px;
    color: #263D5E;
}
QMenu::item {
    padding: 9px 20px;
}
QMenu::item:selected {
    background: #EDF3FF;
    color: #244EB9;
}
QMenu::item:disabled {
    color: #A0ACB9;
}
QTabWidget::pane {
    border: 1px solid #E2E8F1;
    border-radius: 9px;
    background: white;
}
QTabBar::tab {
    padding: 9px 17px;
    margin-right: 5px;
    border: none;
    border-radius: 8px;
    color: #6A7A91;
    background: #F4F6FA;
    font-weight: 600;
}
QTabBar::tab:selected {
    color: #2E54C3;
    background: #E8EFFF;
}
QTabBar::tab:hover:!selected {
    background: #EBF1F9;
}
QTableWidget {
    background: white;
    alternate-background-color: #F8FAFD;
    color: #243651;
    border: none;
    gridline-color: #EBEFF5;
    selection-background-color: #DFE9FF;
    selection-color: #1A3E92;
}
QHeaderView::section {
    background: #F6F8FC;
    color: #5F7089;
    border: none;
    border-bottom: 1px solid #E2E8F1;
    padding: 10px;
    font-weight: 650;
}
QLabel#emptySymbol {
    color: #345CDF;
    font-size: 33pt;
    font-weight: 700;
}
QLabel#emptyTitle {
    color: #223550;
    font-size: 16pt;
    font-weight: 700;
}
QLabel#emptyDescription {
    color: #6A7890;
    font-size: 10pt;
}
QLabel#previewInfo {
    color: #547096;
    font-size: 9pt;
    padding: 4px 2px;
}
QFrame#transferCard {
    background: #F2F6FF;
    border: 1px solid #DAE5FA;
    border-radius: 12px;
}
QLabel#transferTitle {
    color: #223C75;
    font-size: 11pt;
    font-weight: 700;
}
QLabel#transferFilename {
    color: #263B5C;
    font-size: 10pt;
    font-weight: 600;
}
QLabel#transferDetail {
    color: #667C9D;
    font-size: 9pt;
}
QProgressBar#fileProgress {
    background: #DCE6F8;
    border: none;
    border-radius: 5px;
    min-height: 9px;
    max-height: 9px;
    text-align: center;
}
QProgressBar#fileProgress::chunk {
    background: #416BE7;
    border-radius: 5px;
}
QFrame#syncResult[tone="success"] {
    background: #EAF8F1;
    border: 1px solid #C8EBD9;
    border-radius: 10px;
}
QFrame#syncResult[tone="warning"] {
    background: #FFF6E7;
    border: 1px solid #F0DEB6;
    border-radius: 10px;
}
QLabel#resultTitle {
    color: #294567;
    font-size: 10pt;
    font-weight: 700;
}
QLabel#resultDetail {
    color: #526781;
    font-size: 9pt;
}
QLabel#activityText, QLabel#transferText {
    color: #65748C;
    font-size: 9pt;
}
QDialog {
    background: #F5F7FB;
    font: 10pt "Segoe UI";
}
QLineEdit, QListWidget {
    background: white;
    border: 1px solid #D5DFEB;
    border-radius: 8px;
    padding: 6px;
    color: #18263B;
}
"""


class SyncBridgePolishedWindow(SyncBridgeCleanStartWindow):
    """Present SyncBridge's existing operations without changing their rules."""

    def __init__(self, controller, *, network_options):
        self._ui_polished = False
        self._show_file_browser = False

        self._visual_operation: str | None = None
        self._transfer_lock = threading.Lock()
        self._latest_transfer = None
        self._last_sync_result: tuple[str, str, str] | None = None

        super().__init__(
            controller,
            network_options=network_options,
        )

    @staticmethod
    def _plain_label(text: str = "", parent=None) -> QLabel:
        label = QLabel(text, parent)
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setWordWrap(True)
        return label

    @staticmethod
    def _set_tone(widget, tone: str) -> None:
        if widget.property("tone") == tone:
            return
        widget.setProperty("tone", tone)
        widget.style().unpolish(widget)
        widget.style().polish(widget)
        widget.update()

    def _make_ui(self) -> None:
        super()._make_ui()

        self.resize(1080, 740)
        self.setMinimumSize(800, 580)

        root = self.centralWidget()
        root.setObjectName("syncbridgeRoot")
        outer = root.layout()
        outer.setContentsMargins(26, 22, 26, 18)
        outer.setSpacing(17)

        header = outer.itemAt(0).layout()

        brand = header.itemAt(0).widget()
        brand.setObjectName("wordmark")
        brand.setText("SyncBridge")

        self.my_name_label.setObjectName("deviceName")
        self.status.setObjectName("statusPill")

        self.rename_button.hide()
        self.fresh_button.hide()

        self._options_menu = QMenu(self)
        self._rename_action = self._options_menu.addAction(
            "Rename this computer",
            self._rename_my_computer,
        )
        self._fresh_action = self._options_menu.addAction(
            "Start fresh setup",
            self._start_fresh,
        )
        self._options_menu.aboutToShow.connect(self._refresh_options)

        # Ordinary button: Qt cannot inject a second native menu arrow.
        self._options_button = QPushButton("Options  ▾", self)
        self._options_button.setObjectName("optionsButton")
        self._options_button.setToolTip(
            "Computer name and connection setup options"
        )
        self._options_button.clicked.connect(self._open_options)
        header.insertWidget(header.count() - 1, self._options_button)

        connection_card = outer.itemAt(1).widget()
        connection_card.setObjectName("connectionCard")
        connection_layout = connection_card.layout()
        connection_layout.setContentsMargins(22, 20, 22, 18)
        connection_layout.setSpacing(11)

        self.connection.setObjectName("connectionTitle")
        self.hint.setObjectName("connectionHint")

        workspace = outer.itemAt(2).widget()
        workspace.setObjectName("workspaceCard")
        workspace_layout = workspace.layout()
        workspace_layout.setContentsMargins(22, 18, 22, 20)
        workspace_layout.setSpacing(14)

        toolbar = workspace_layout.itemAt(0).layout()
        toolbar_title = toolbar.itemAt(0).widget()
        toolbar_title.setObjectName("workspaceTitle")
        toolbar_title.setText("Your workspace")

        connection_actions = connection_layout.itemAt(2).layout()
        connection_actions.removeWidget(self.open_folder_button)
        toolbar.insertWidget(2, self.open_folder_button)
        self.open_folder_button.setText("Open folder")

        workspace_layout.removeWidget(self.summary)
        self.summary.setObjectName("connectionMessage")
        self.summary.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        connection_layout.addWidget(self.summary)

        self._preview_info = self._plain_label("", self)
        self._preview_info.setObjectName("previewInfo")
        workspace_layout.insertWidget(1, self._preview_info)

        self._result_card = QFrame(self)
        self._result_card.setObjectName("syncResult")

        result_layout = QVBoxLayout(self._result_card)
        result_layout.setContentsMargins(16, 12, 16, 12)
        result_layout.setSpacing(5)

        self._result_title = self._plain_label("", self._result_card)
        self._result_title.setObjectName("resultTitle")
        result_layout.addWidget(self._result_title)

        self._result_detail = self._plain_label("", self._result_card)
        self._result_detail.setObjectName("resultDetail")
        result_layout.addWidget(self._result_detail)

        workspace_layout.insertWidget(2, self._result_card)

        self._transfer_card = QFrame(self)
        self._transfer_card.setObjectName("transferCard")

        transfer_layout = QVBoxLayout(self._transfer_card)
        transfer_layout.setContentsMargins(18, 16, 18, 16)
        transfer_layout.setSpacing(9)

        self._transfer_title = self._plain_label(
            "Preparing files...", self._transfer_card
        )
        self._transfer_title.setObjectName("transferTitle")
        transfer_layout.addWidget(self._transfer_title)

        self._transfer_filename = self._plain_label(
            "", self._transfer_card
        )
        self._transfer_filename.setObjectName("transferFilename")
        transfer_layout.addWidget(self._transfer_filename)

        self._file_progress = QProgressBar(self._transfer_card)
        self._file_progress.setObjectName("fileProgress")
        self._file_progress.setTextVisible(False)
        self._file_progress.setRange(0, 0)
        transfer_layout.addWidget(self._file_progress)

        self._transfer_detail = self._plain_label(
            "", self._transfer_card
        )
        self._transfer_detail.setObjectName("transferDetail")
        transfer_layout.addWidget(self._transfer_detail)

        workspace_layout.insertWidget(3, self._transfer_card)

        self._empty_panel = QFrame(self)
        self._empty_panel.setObjectName("emptyPanel")

        empty_layout = QVBoxLayout(self._empty_panel)
        empty_layout.setContentsMargins(24, 34, 24, 34)
        empty_layout.setSpacing(10)
        empty_layout.addStretch(1)

        self._empty_symbol = self._plain_label("⇄", self._empty_panel)
        self._empty_symbol.setObjectName("emptySymbol")
        self._empty_symbol.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_layout.addWidget(self._empty_symbol)

        self._empty_title = self._plain_label("", self._empty_panel)
        self._empty_title.setObjectName("emptyTitle")
        self._empty_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_layout.addWidget(self._empty_title)

        self._empty_description = self._plain_label("", self._empty_panel)
        self._empty_description.setObjectName("emptyDescription")
        self._empty_description.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_layout.addWidget(self._empty_description)

        self._browse_button = QPushButton(
            "Browse files", self._empty_panel
        )
        self._browse_button.clicked.connect(self._browse_files)
        empty_layout.addWidget(
            self._browse_button,
            0,
            Qt.AlignmentFlag.AlignHCenter,
        )
        empty_layout.addStretch(2)

        workspace_layout.addWidget(self._empty_panel, 1)

        self.tabs.setDocumentMode(True)

        for table in (self.local_table, self.remote_table, self.table):
            table.setAlternatingRowColors(True)
            table.setShowGrid(False)
            table.setSelectionBehavior(
                QAbstractItemView.SelectionBehavior.SelectRows
            )
            table.setSelectionMode(
                QAbstractItemView.SelectionMode.SingleSelection
            )
            table.verticalHeader().hide()
            table.verticalHeader().setDefaultSectionSize(36)
            table.horizontalHeader().setMinimumSectionSize(80)
            table.setWordWrap(False)

        differences_header = self.table.horizontalHeader()
        differences_header.setStretchLastSection(False)
        differences_header.setSectionResizeMode(
            0, QHeaderView.ResizeMode.Fixed
        )
        self.table.setColumnWidth(0, 125)
        differences_header.setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        differences_header.setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )

        self.activity_label.setObjectName("activityText")
        self.progress.setObjectName("transferText")

        QApplication.instance().setStyleSheet(POLISHED_STYLE)
        self._ui_polished = True

    def _open_options(self) -> None:
        if self._closing or self._fresh_busy:
            return
        self._refresh_options()
        position = self._options_button.mapToGlobal(
            QPoint(0, self._options_button.height() + 4)
        )
        self._options_menu.popup(position)

    def _refresh_options(self) -> None:
        self._rename_action.setEnabled(
            self.rename_button.isEnabled()
        )
        self._fresh_action.setEnabled(
            self.lifecycle.phase is DesktopPhase.DISCONNECTED
            and not self._recovery_required
            and not self._fresh_busy
            and not self._busy
            and not self.controller.running
            and self._live_session is None
            and self._connect_cancel is None
            and not self._closing
        )

    def _browse_files(self) -> None:
        if (
            self.lifecycle.phase is not DesktopPhase.CONNECTED
            or self._busy
            or not self.controller.running
        ):
            return

        self._show_file_browser = True
        self.tabs.setCurrentIndex(0)
        self._apply_state()
        self._load_files()

    def _preview_files(self) -> None:
        eligible = (
            self.lifecycle.phase is DesktopPhase.CONNECTED
            and not self._busy
        )
        if eligible:
            self._visual_operation = "preview"
            self._last_sync_result = None

        super()._preview_files()
        self._apply_state()

    def _sync_files(self) -> None:
        # The original implementation owns the confirmation dialog and
        # refuses stale, conflicting, or unapproved synchronization plans.
        super()._sync_files()

        if self.lifecycle.phase is DesktopPhase.SYNCHRONIZING:
            self._visual_operation = "sync"
            self._last_sync_result = None
            with self._transfer_lock:
                self._latest_transfer = None

        self._apply_state()

    def _transfer_progress(self, event) -> None:
        # Called from the existing transfer worker. No widgets are touched
        # from that thread. Only the most recent sample is retained here.
        with self._transfer_lock:
            self._latest_transfer = event

        super()._transfer_progress(event)

    def _show_transfer(self, event) -> None:
        """Display only real per-file transfer measurements."""
        try:
            total = max(0, int(event.total))
            completed = max(0, int(event.transferred))
            direction = str(event.direction).lower()
            path = str(event.path)
        except (TypeError, ValueError, AttributeError):
            return

        filename = PurePosixPath(
            path.replace("\\", "/")
        ).name or "File"

        if direction in ("send", "upload"):
            title = "Sending file"
        elif direction in ("receive", "download"):
            title = "Receiving file"
        else:
            title = "Transferring file"

        self._transfer_title.setText(title)
        self._transfer_filename.setText(filename)

        if total > 0:
            actual = min(completed, total)
            percentage = round(actual * 100 / total)
            self._file_progress.setRange(0, 1000)
            self._file_progress.setValue(
                min(1000, actual * 1000 // total)
            )
            self._transfer_detail.setText(
                f"{self._size(actual)} of {self._size(total)}"
                f"  ·  {percentage}% of this file"
            )
        else:
            # A zero-byte or unknown-size transfer has no meaningful
            # byte-based progress ratio.
            self._file_progress.setRange(0, 0)
            self._transfer_detail.setText(
                "Processing file..."
            )

    def _display_preview(self, preview) -> None:
        super()._display_preview(preview)

        for row, item in enumerate(preview.items):
            action = str(item.action).casefold()
            color = (
                "#2367B9" if action == "send"
                else "#137D69" if action == "receive"
                else "#A56222"
            )
            for column in range(self.table.columnCount()):
                cell = self.table.item(row, column)
                if cell is None:
                    continue

                if column == 0:
                    cell.setForeground(QColor(color))

                # Keep full paths/explanations available even when a column
                # is visually shortened at smaller window sizes.
                if column == 1:
                    cell.setToolTip(str(item.path))
                elif column == 2:
                    cell.setToolTip(str(item.description))

        self._apply_state()

    def _preview_description(self) -> str:
        preview = self._preview
        if preview is None:
            return ""

        count = len(preview.items)
        if count == 0:
            return "Everything is up to date."

        counts = Counter(
            str(item.action).casefold()
            for item in preview.items
        )
        parts = [f"{count} proposed change(s)"]

        if counts["send"]:
            parts.append(f"{counts['send']} to send")
        if counts["receive"]:
            parts.append(f"{counts['receive']} to receive")

        if preview.requires_review:
            parts.append("Review required before synchronization")

        return "   ·   ".join(parts)

    def _drain(self) -> None:
        previous_operation = self._visual_operation
        super()._drain()

        if not self._ui_polished or self._closing:
            return

        phase = self.lifecycle.phase

        if (
            previous_operation == "sync"
            and phase is not DesktopPhase.SYNCHRONIZING
        ):
            if phase is DesktopPhase.CONNECTED:
                message = self.summary.text()
                if message.startswith("Synchronization finished."):
                    self._last_sync_result = (
                        "Synchronization finished",
                        "The operation completed. Preview again to "
                        "confirm that both folders are up to date.",
                        "success",
                    )
                elif message.startswith("Some changes need attention."):
                    self._last_sync_result = (
                        "Some changes need attention",
                        "Not every proposed change was completed. "
                        "Preview again before retrying.",
                        "warning",
                    )
                else:
                    self._last_sync_result = (
                        "Synchronization needs attention",
                        message or "Review the status before trying again.",
                        "warning",
                    )

        if phase is not DesktopPhase.SYNCHRONIZING:
            self._visual_operation = None

        if phase is DesktopPhase.DISCONNECTED:
            self._last_sync_result = None

        with self._transfer_lock:
            latest = self._latest_transfer
            self._latest_transfer = None

        if (
            latest is not None
            and phase is DesktopPhase.SYNCHRONIZING
            and self._visual_operation == "sync"
        ):
            self._show_transfer(latest)

        self._apply_state()

    def _apply_state(self) -> None:
        super()._apply_state()

        if not self._ui_polished:
            return

        phase = self.lifecycle.phase
        active = (
            phase in (
                DesktopPhase.CONNECTED,
                DesktopPhase.SYNCHRONIZING,
            )
            and self._live_session is not None
            and self.controller.running
            and not self._recovery_required
        )

        if phase is DesktopPhase.DISCONNECTED:
            self._show_file_browser = False

        self.rename_button.hide()
        self.fresh_button.hide()
        self._refresh_options()

        self.open_folder_button.setVisible(active)
        self.preview_button.setVisible(active)

        ready_preview = bool(
            self._preview is not None
            and self._preview.items
            and not self._preview.requires_review
        )

        self.sync_button.setVisible(
            active and (
                ready_preview
                or (
                    phase is DesktopPhase.SYNCHRONIZING
                    and self._visual_operation == "sync"
                )
            )
        )

        show_tabs = active and (
            self._show_file_browser
            or bool(
                self._preview is not None
                and self._preview.items
            )
        )

        self.tabs.setVisible(show_tabs)
        self._empty_panel.setVisible(
            not show_tabs
            and self._visual_operation is None
        )

        self._browse_button.setVisible(
            active
            and phase is DesktopPhase.CONNECTED
            and not self._busy
        )

        self._preview_info.setText(
            self._preview_description()
        )
        self._preview_info.setVisible(
            active and self._preview is not None
        )

        show_result = bool(
            active
            and phase is DesktopPhase.CONNECTED
            and self._last_sync_result is not None
        )
        if self._last_sync_result is not None:
            title, detail, tone = self._last_sync_result
            self._result_title.setText(title)
            self._result_detail.setText(detail)
            self._set_tone(self._result_card, tone)
        self._result_card.setVisible(show_result)

        show_transfer = (
            active
            and phase is DesktopPhase.SYNCHRONIZING
            and self._visual_operation in ("preview", "sync")
        )

        if show_transfer:
            if self._visual_operation == "preview":
                self._transfer_title.setText("Checking your files")
                self._transfer_filename.setText(
                    "Comparing both folders safely..."
                )
                self._transfer_detail.setText(
                    "No files will be changed during preview."
                )
                self._file_progress.setRange(0, 0)
            elif (
                self._visual_operation == "sync"
                and not self._transfer_filename.text()
            ):
                self._transfer_title.setText("Synchronizing files")
                self._transfer_filename.setText(
                    "Preparing the next file..."
                )
                self._transfer_detail.setText(
                    "Files are being transferred securely."
                )
                self._file_progress.setRange(0, 0)

        self._transfer_card.setVisible(show_transfer)

        # The dedicated transfer panel replaces the old developer-style
        # progress strings. Existing network progress events remain intact.
        self.activity_label.hide()
        self.activity_bar.hide()
        self.progress.hide()

        messages = {
            DesktopPhase.DISCONNECTED: (
                "Ready when you are",
                "Find a computer to connect and choose your folders.",
            ),
            DesktopPhase.PAIRING: (
                "Approve the connection",
                "Both people must approve before choosing their folders.",
            ),
            DesktopPhase.CHOOSING_FOLDER: (
                "Choose your folder",
                "Each person chooses a folder on their own computer.",
            ),
            DesktopPhase.CONNECTING: (
                "Connecting securely",
                "Waiting for both computers to complete the connection.",
            ),
            DesktopPhase.CONNECTED: (
                "Connected and ready",
                "Preview differences to see what can be synchronized.",
            ),
            DesktopPhase.SYNCHRONIZING: (
                "Working with your files",
                "Your connection is active while SyncBridge finishes this task.",
            ),
            DesktopPhase.CHANGING_FOLDERS: (
                "Changing folders",
                "Both computers must agree before changing their folders.",
            ),
            DesktopPhase.DISCONNECTING: (
                "Disconnecting safely",
                "Finishing the current operation before closing the connection.",
            ),
        }

        title, description = messages[phase]

        if (
            phase is DesktopPhase.CONNECTED
            and self._preview is not None
            and not self._preview.items
        ):
            title = "Everything is up to date"
            description = "No changes are waiting to be synchronized."

        self._empty_title.setText(title)
        self._empty_description.setText(description)

        status_text, tone = {
            DesktopPhase.DISCONNECTED: ("Offline", "neutral"),
            DesktopPhase.PAIRING: ("Pairing", "busy"),
            DesktopPhase.CHOOSING_FOLDER: ("Choose folder", "busy"),
            DesktopPhase.CONNECTING: ("Connecting", "busy"),
            DesktopPhase.CONNECTED: ("Connected", "connected"),
            DesktopPhase.SYNCHRONIZING: ("Synchronizing", "busy"),
            DesktopPhase.CHANGING_FOLDERS: ("Changing folders", "busy"),
            DesktopPhase.DISCONNECTING: ("Disconnecting", "warning"),
        }[phase]

        if self._recovery_required:
            status_text, tone = "Recovery required", "warning"

        self.status.setText(status_text)
        self._set_tone(self.status, tone)

        plain = self.summary.text().strip()
        boilerplate = {
            "Find a computer to get started.",
            "Connected. Preview differences before synchronizing.",
        }
        self.summary.setVisible(
            bool(plain) and plain not in boilerplate
        )
