
"""Modern SyncBridge desktop presentation using the existing safe workflows.

The existing pairing, folder setup, sync, session approval and crash recovery
implementations remain authoritative. This class changes presentation only.
"""
from __future__ import annotations

from PySide6.QtCore import QPoint, Qt
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QLabel,
    QMenu,
    QPushButton,
    QVBoxLayout,
)

from syncbridge.ui.desktop_controller import DesktopPhase
from syncbridge.ui.qt_clean_start_window import SyncBridgeCleanStartWindow


POLISHED_STYLE = """
QMainWindow, QWidget#syncbridgeRoot {
    background-color: #F5F7FB;
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
    background: #FFFFFF;
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
    border: none;
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
    background: #FFFFFF;
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
    background: #FFFFFF;
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
    background: #FFFFFF;
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
    background: #FFFFFF;
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
    background: #FFFFFF;
    alternate-background-color: #F8FAFD;
    color: #243651;
    border: 0;
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
QLabel#activityText, QLabel#transferText {
    color: #65748C;
    font-size: 9pt;
}
QProgressBar {
    background: #E9EEF7;
    border: none;
    border-radius: 5px;
    height: 9px;
    text-align: center;
    color: #314F86;
}
QProgressBar::chunk {
    background: #4F78E8;
    border-radius: 5px;
}
QDialog {
    background: #F5F7FB;
    font: 10pt "Segoe UI";
}
QLineEdit, QListWidget {
    background: #FFFFFF;
    border: 1px solid #D5DFEB;
    border-radius: 8px;
    padding: 6px;
    color: #18263B;
}
"""


class SyncBridgePolishedWindow(SyncBridgeCleanStartWindow):
    """Show the next useful action and hide unnecessary idle controls."""

    def __init__(self, controller, *, network_options):
        self._ui_polished = False
        self._show_file_browser = False
        super().__init__(controller, network_options=network_options)

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

        # Retain the original controls and their security/lifecycle guards,
        # but expose secondary operations through an Options menu.
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

        # No setMenu() here. Qt's native menu button adds its own arrow
        # which is poorly positioned with custom Windows styles.
        self._options_button = QPushButton("Options", self)
        self._options_button.setObjectName("optionsButton")
        self._options_button.setToolTip(
            "Computer name and connection setup options"
        )
        self._options_button.clicked.connect(self._open_options)

        header.insertWidget(
            header.count() - 1,
            self._options_button,
        )

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

        file_toolbar = workspace_layout.itemAt(0).layout()
        toolbar_title = file_toolbar.itemAt(0).widget()
        toolbar_title.setObjectName("workspaceTitle")
        toolbar_title.setText("Your workspace")

        connection_actions = connection_layout.itemAt(2).layout()
        connection_actions.removeWidget(self.open_folder_button)
        file_toolbar.insertWidget(2, self.open_folder_button)
        self.open_folder_button.setText("Open folder")

        # Connection errors belong beside connection controls.
        workspace_layout.removeWidget(self.summary)
        self.summary.setObjectName("connectionMessage")
        self.summary.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        connection_layout.addWidget(self.summary)

        self._empty_panel = QFrame(self)
        self._empty_panel.setObjectName("emptyPanel")

        empty_layout = QVBoxLayout(self._empty_panel)
        empty_layout.setContentsMargins(24, 34, 24, 34)
        empty_layout.setSpacing(10)
        empty_layout.addStretch(1)

        self._empty_symbol = QLabel("⇄", self._empty_panel)
        self._empty_symbol.setObjectName("emptySymbol")
        self._empty_symbol.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        empty_layout.addWidget(self._empty_symbol)

        self._empty_title = QLabel(self._empty_panel)
        self._empty_title.setObjectName("emptyTitle")
        self._empty_title.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        empty_layout.addWidget(self._empty_title)

        self._empty_description = QLabel(self._empty_panel)
        self._empty_description.setObjectName("emptyDescription")
        self._empty_description.setWordWrap(True)
        self._empty_description.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        empty_layout.addWidget(self._empty_description)

        self._browse_button = QPushButton(
            "Browse files",
            self._empty_panel,
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
        self.local_table.setAlternatingRowColors(True)
        self.remote_table.setAlternatingRowColors(True)
        self.table.setAlternatingRowColors(True)

        self.activity_label.setObjectName("activityText")
        self.progress.setObjectName("transferText")

        QApplication.instance().setStyleSheet(POLISHED_STYLE)
        self._ui_polished = True

    def _open_options(self) -> None:
        """Open the actual menu from a normal button, with no dropdown arrow."""
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

    def _drain(self) -> None:
        super()._drain()

        if self._ui_polished:
            self.progress.setVisible(
                self.lifecycle.phase is DesktopPhase.SYNCHRONIZING
                and bool(self.progress.text())
            )

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

        show_sync = active and (
            phase is DesktopPhase.SYNCHRONIZING
            or bool(
                self._preview is not None
                and self._preview.items
                and not self._preview.requires_review
            )
        )
        self.sync_button.setVisible(show_sync)

        show_tabs = active and (
            self._show_file_browser
            or self._preview is not None
        )
        self.tabs.setVisible(show_tabs)
        self._empty_panel.setVisible(not show_tabs)

        self._browse_button.setVisible(
            phase is DesktopPhase.CONNECTED
            and active
            and not self._busy
        )

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

        title, explanation = messages[phase]
        self._empty_title.setText(title)
        self._empty_description.setText(explanation)

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

        if self.status.property("tone") != tone:
            self.status.setProperty("tone", tone)
            self.status.style().unpolish(self.status)
            self.status.style().polish(self.status)

        plain = self.summary.text().strip()

        boilerplate = {
            "Find a computer to get started.",
            "Connected. Preview differences before synchronizing.",
        }

        self.summary.setVisible(
            bool(plain) and plain not in boilerplate
        )
        self.progress.setVisible(
            phase is DesktopPhase.SYNCHRONIZING
            and bool(self.progress.text())
        )
