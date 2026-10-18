
"""Isolated Qt tests for virtual-LAN broadcast and in-app IP discovery.

The main pytest process never loads Qt, preserving native-test isolation.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_CHILD = "SYNCBRIDGE_QT_DIRECT_DISCOVERY_CHILD"


def _exercise() -> None:
    pytest.importorskip("PySide6")

    from PySide6.QtNetwork import QNetworkInterface
    from PySide6.QtWidgets import QApplication, QLabel
    from syncbridge.network.discovery import DISCOVERY_PORT
    from syncbridge.ui.qt_direct_discovery_window import (
        DirectDiscoveryControls,
        discovery_targets_for_interfaces,
    )

    app = QApplication.instance() or QApplication([])

    class Address:
        def __init__(self, address):
            self._address = address

        def toString(self):
            return self._address

    class Entry:
        def __init__(self, broadcast):
            self._broadcast = broadcast

        def broadcast(self):
            return Address(self._broadcast)

    class Interface:
        def __init__(self, state, addresses):
            self._state = state
            self._addresses = addresses

        def flags(self):
            return self._state

        def addressEntries(self):
            return [Entry(address) for address in self._addresses]

    flag = QNetworkInterface.InterfaceFlag
    active = flag.IsUp | flag.IsRunning
    interfaces = [
        Interface(active, ["192.168.196.255", "192.168.196.255"]),
        Interface(active, ["192.168.1.255", "", "ff02::1"]),
        Interface(active | flag.IsLoopBack, ["127.255.255.255"]),
        Interface(flag.IsUp, ["10.10.10.255"]),
    ]

    assert discovery_targets_for_interfaces(interfaces) == (
        ("192.168.1.255", DISCOVERY_PORT),
        ("192.168.196.255", DISCOVERY_PORT),
        ("255.255.255.255", DISCOVERY_PORT),
    )

    class Directory:
        def __init__(self):
            self.targets = []
            self.refreshes = 0
            self.fail = False

        def add_target(self, ip, port):
            if self.fail:
                raise OSError("Simulated network error")
            self.targets.append((ip, port))

        def refresh(self):
            self.refreshes += 1

    directory = Directory()
    message = QLabel("")
    controls = DirectDiscoveryControls(directory, message)
    try:
        assert controls.find_button.text() == "Find by IP"
        controls.address.setText("192.168.196.161")
        controls.find_button.click()
        assert directory.targets == [("192.168.196.161", DISCOVERY_PORT)]
        assert directory.refreshes == 1
        assert "192.168.196.161" in message.text()

        for invalid in ("not an IP", "", "224.0.0.1", "0.0.0.0", "255.255.255.255"):
            controls.address.setText(invalid)
            controls.find_button.click()
            assert len(directory.targets) == 1
            assert directory.refreshes == 1

        directory.fail = True
        controls.address.setText("192.168.196.2")
        controls.address.returnPressed.emit()
        assert len(directory.targets) == 1
        assert directory.refreshes == 1
        assert "Simulated network error" in message.text()
    finally:
        controls.close()
        message.close()


def test_virtual_lan_discovery_without_cmd():
    if os.environ.get(_CHILD) == "1":
        _exercise()
        return

    project = Path(__file__).resolve().parents[2]
    environment = os.environ.copy()
    environment[_CHILD] = "1"
    environment["QT_QPA_PLATFORM"] = "offscreen"

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "-s",
                str(Path(__file__).resolve()),
                "-k",
                "test_virtual_lan_discovery_without_cmd",
            ],
            cwd=project,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(
            f"Isolated virtual-LAN discovery test timed out: {exc.stdout!r}",
            pytrace=False,
        )

    assert result.returncode == 0, (
        f"Isolated discovery test failed ({result.returncode}):\n{result.stdout}"
    )
