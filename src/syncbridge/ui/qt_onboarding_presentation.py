
"""Presentation-only styling for SyncBridge's existing onboarding dialogs.

Pairing approval, rejection, folder selection, and timeouts remain owned by
qt_onboarding. This module never intercepts or replaces protocol callbacks.
"""
from __future__ import annotations

from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtWidgets import QApplication, QDialog, QLabel

from syncbridge.ui.qt_onboarding import (
    ConnectDialog,
    DevicesDialog,
    FolderRequestDialog,
)


ONBOARDING_STYLE = """
QDialog#syncbridgeOnboarding {
    background: #F5F7FB;
    color: #192B45;
    font: 10pt 'Segoe UI';
}
QDialog#syncbridgeOnboarding QLabel {
    background: transparent;
    color: #34465F;
}
QDialog#syncbridgeOnboarding QLabel#dialogTitle {
    font-size: 17pt;
    font-weight: 700;
    color: #142440;
}
QDialog#syncbridgeOnboarding QLabel#dialogDescription {
    font-size: 10pt;
    color: #61728B;
}
QDialog#syncbridgeOnboarding QLabel#dialogStatus {
    background: #EAF0FB;
    border: 1px solid #DAE5F8;
    border-radius: 9px;
    padding: 10px 12px;
    color: #426098;
    font-size: 9pt;
}
QDialog#syncbridgeOnboarding QLabel#dialogHelp {
    color: #718198;
    font-size: 9pt;
}
QDialog#syncbridgeOnboarding QListWidget#deviceList {
    background: #FFFFFF;
    border: 1px solid #DEE6F2;
    border-radius: 12px;
    padding: 7px;
    outline: none;
    color: #253B58;
    font-size: 10pt;
}
QDialog#syncbridgeOnboarding QListWidget#deviceList::item {
    padding: 12px 14px;
    margin: 3px 2px;
    border-radius: 8px;
}
QDialog#syncbridgeOnboarding QListWidget#deviceList::item:hover {
    background: #F1F5FF;
}
QDialog#syncbridgeOnboarding QListWidget#deviceList::item:selected {
    background: #E5EEFF;
    color: #214C9F;
}
QDialog#syncbridgeOnboarding QPushButton {
    background: #FFFFFF;
    color: #284260;
    border: 1px solid #CED9E9;
    border-radius: 9px;
    padding: 11px 20px;
    font-weight: 600;
    min-height: 18px;
}
QDialog#syncbridgeOnboarding QPushButton:hover:!disabled {
    background: #EDF3FF;
    border-color: #A9BCE3;
}
QDialog#syncbridgeOnboarding QPushButton:disabled {
    background: #F1F3F7;
    color: #9EACBC;
}
QDialog#syncbridgeOnboarding QPushButton#primary {
    background: #345CDF;
    color: #FFFFFF;
    border: 1px solid #345CDF;
}
QDialog#syncbridgeOnboarding QPushButton#primary:hover:!disabled {
    background: #244DCA;
    border-color: #244DCA;
}
QDialog#syncbridgeOnboarding QPushButton#primary:disabled {
    background: #A5B9EB;
    border-color: #A5B9EB;
    color: white;
}
"""


def _label(widget: object, *, name: str) -> QLabel:
    if not isinstance(widget, QLabel):
        raise TypeError("Unexpected SyncBridge onboarding dialog layout")
    widget.setObjectName(name)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    widget.setWordWrap(True)
    return widget


def present_dialog(dialog: QDialog) -> None:
    """Restyle a known dialog once; preserve its buttons and signals."""
    if not isinstance(
        dialog, (DevicesDialog, ConnectDialog, FolderRequestDialog)
    ):
        return

    if dialog.property("syncbridgePresented"):
        return

    layout = dialog.layout()
    if layout is None or layout.count() < 3:
        return

    dialog.setProperty("syncbridgePresented", True)
    dialog.setObjectName("syncbridgeOnboarding")
    dialog.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

    layout.setContentsMargins(26, 24, 26, 24)
    layout.setSpacing(16)

    title = _label(
        layout.itemAt(0).widget(), name="dialogTitle"
    )
    description = _label(
        layout.itemAt(1).widget(), name="dialogDescription"
    )

    if isinstance(dialog, DevicesDialog):
        dialog.setMinimumSize(560, 435)
        dialog.setWindowTitle("Find a computer · SyncBridge")

        title.setText("Find your computer")
        description.setText(
            "Select the computer you want to connect with. "
            "Both people will be asked to approve."
        )

        dialog.listing.setObjectName("deviceList")
        dialog.listing.setSpacing(4)
        dialog.message.setObjectName("dialogStatus")
        dialog.connect_button.setMinimumWidth(150)

        help_text = QLabel(
            "Can't see the other computer? Keep SyncBridge open "
            "on both devices and check that they're on the same network.",
            dialog,
        )
        _label(help_text, name="dialogHelp")
        layout.addWidget(help_text)

    elif isinstance(dialog, ConnectDialog):
        dialog.setMinimumWidth(500)
        dialog.setWindowTitle("Approve connection · SyncBridge")

        title.setText(
            f"Connect to {dialog.details.remote_name}?"
        )
        description.setText(
            "Only approve if you recognize this computer. "
            "The other person must also approve. "
            "You'll each choose a folder before any files are shared."
        )

        dialog.message.setObjectName("dialogStatus")
        dialog.yes.setText("Approve connection")
        dialog.yes.setMinimumWidth(180)
        dialog.no.setText("Decline")

    else:
        dialog.setMinimumWidth(505)
        dialog.setWindowTitle("Choose your folder · SyncBridge")

        title.setText(
            f"Choose a folder for {dialog.request.peer_name}"
        )
        description.setText(
            "Choose a folder on this computer. The other person "
            "will be able to read and update files inside it. "
            "Conflicts and deletions still require review."
        )

        dialog.message.setObjectName("dialogStatus")
        dialog.yes.setText("Choose folder")
        dialog.yes.setMinimumWidth(160)
        dialog.no.setText("Decline")

    dialog.setStyleSheet(ONBOARDING_STYLE)


class OnboardingPresenter(QObject):
    """Style Qt onboarding dialogs before their Show events complete.

    This also covers dialogs recreated after Start fresh.
    """

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if (
            event.type() == QEvent.Type.Show
            and isinstance(
                watched,
                (DevicesDialog, ConnectDialog, FolderRequestDialog),
            )
        ):
            present_dialog(watched)

        return False


def install_onboarding_presentation(
    app: QApplication,
) -> OnboardingPresenter:
    """Install presentation handling for the QApplication lifetime."""
    presenter = OnboardingPresenter(app)
    app.installEventFilter(presenter)
    return presenter
