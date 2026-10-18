
"""Friendly LAN and virtual-LAN discovery for the SyncBridge Qt desktop.

Broadcast on active interfaces where the network permits it. If a virtual
network does not forward broadcasts, one user may enter the other's IPv4
address inside the Nearby computers dialog. Discovery never authorizes trust,
folder access, or file writes.
"""
from __future__ import annotations

import ipaddress

from PySide6.QtNetwork import QNetworkInterface
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from syncbridge.network.discovery import DISCOVERY_PORT
from syncbridge.ui.qt_folder_switch_window import SyncBridgeFolderWindow


def discovery_targets_for_interfaces(interfaces=None) -> tuple[tuple[str, int], ...]:
    """Return bounded broadcast destinations; never probe network addresses."""
    if interfaces is None:
        interfaces = QNetworkInterface.allInterfaces()

    flags = QNetworkInterface.InterfaceFlag
    targets: set[tuple[str, int]] = {("255.255.255.255", DISCOVERY_PORT)}

    for interface in interfaces:
        state = interface.flags()
        if (
            not (state & flags.IsUp)
            or not (state & flags.IsRunning)
            or (state & flags.IsLoopBack)
        ):
            continue

        for entry in interface.addressEntries():
            try:
                address = ipaddress.ip_address(entry.broadcast().toString())
            except ValueError:
                continue
            if (
                isinstance(address, ipaddress.IPv4Address)
                and not address.is_unspecified
                and not address.is_multicast
                and not address.is_loopback
                and address != ipaddress.IPv4Address("255.255.255.255")
            ):
                targets.add((str(address), DISCOVERY_PORT))

    return tuple(sorted(targets))


class DirectDiscoveryControls(QWidget):
    """Fallback for remote peers who cannot receive broadcast announcements."""

    def __init__(self, directory, message: QLabel, parent=None) -> None:
        super().__init__(parent)
        self._directory = directory
        self._message = message

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 5, 0, 5)

        hint = QLabel(
            "Can't see your friend? Enter their ZeroTier or LAN IP address."
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)

        controls = QHBoxLayout()
        self.address = QLineEdit(self)
        self.address.setObjectName("direct_discovery_address")
        self.address.setPlaceholderText("Other computer's IPv4 address")
        self.address.returnPressed.connect(self.find_address)
        controls.addWidget(self.address)

        self.find_button = QPushButton("Find by IP", self)
        self.find_button.setObjectName("direct_discovery_button")
        self.find_button.clicked.connect(self.find_address)
        controls.addWidget(self.find_button)
        layout.addLayout(controls)

        explanation = QLabel(
            "Only discovery uses this address. Both people must still approve pairing."
        )
        explanation.setWordWrap(True)
        layout.addWidget(explanation)

    def find_address(self) -> None:
        raw = self.address.text().strip()
        try:
            address = ipaddress.IPv4Address(raw)
        except ipaddress.AddressValueError:
            self._message.setText("Enter a valid IPv4 address, such as 192.168.1.20.")
            return

        if address.is_unspecified or address.is_multicast or int(address) == 0xFFFFFFFF:
            self._message.setText("Enter the other computer's unicast IPv4 address.")
            return

        try:
            self._directory.add_target(str(address), DISCOVERY_PORT)
            self._directory.refresh()
        except Exception as exc:
            self._message.setText(
                f"Could not look for this computer: {type(exc).__name__}: {exc}"
            )
            return

        self._message.setText(
            f"Looking for a computer at {address}. Ask your friend to keep SyncBridge open."
        )


class SyncBridgeDiscoveryWindow(SyncBridgeFolderWindow):
    """Add a direct-discovery fallback to the existing Nearby computers dialog."""

    def _find_computers(self) -> None:
        super()._find_computers()
        onboarding = self.onboarding
        if (
            onboarding is None
            or not onboarding.started
            or onboarding.presence is None
            or onboarding.devices_dialog is None
        ):
            return

        dialog = onboarding.devices_dialog
        if getattr(dialog, "_syncbridge_direct_controls", None) is not None:
            return

        controls = DirectDiscoveryControls(
            onboarding.presence.directory, dialog.message, dialog
        )
        dialog.layout().insertWidget(2, controls)
        dialog._syncbridge_direct_controls = controls
