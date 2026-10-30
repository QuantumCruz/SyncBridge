
"""Launch SyncBridge with clean sessions and polished onboarding.

Normal double-click launches begin with fresh pairing and folder settings.
Explicit --profile launches retain saved state for controlled testing.

User files, local device identity, and recovery history are preserved.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from PySide6.QtCore import QLockFile
from PySide6.QtWidgets import QApplication, QMessageBox

from syncbridge.network.discovery import DISCOVERY_PORT
from syncbridge.network.pairing import PAIRING_PORT
from syncbridge.network.share_activation import ACTIVATION_PORT
from syncbridge.network.share_setup import SETUP_PORT
from syncbridge.storage.config import ConfigStore
from syncbridge.storage.folder_change_recovery import FolderChangeJournal
from syncbridge.ui.device_names import initialize_device_name
from syncbridge.ui.fresh_start import start_fresh_locally
from syncbridge.ui.preview_diagnostics import DiagnosticDesktopController
from syncbridge.ui.qt_local_refresh import QtLocalFileRefresh
from syncbridge.ui.qt_onboarding import NetworkOptions
from syncbridge.ui.qt_onboarding_presentation import (
    install_onboarding_presentation,
)
from syncbridge.ui.qt_direct_discovery_window import (
    discovery_targets_for_interfaces,
)
from syncbridge.ui.qt_polished_window import SyncBridgePolishedWindow


def _prepare_profile(
    store: ConfigStore, *, persistent: bool
) -> str:
    """Apply startup policy before opening network listeners."""
    if persistent:
        return "persistent"

    if FolderChangeJournal(store).load() is not None:
        return "recovery"

    start_fresh_locally(store, running=False)
    return "fresh"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="SyncBridge desktop"
    )

    parser.add_argument("--profile", type=Path)
    parser.add_argument("--bind-address", default="0.0.0.0")
    parser.add_argument("--listen-ports", type=int, nargs=3)
    parser.add_argument("--lock-port", type=int, default=45846)
    parser.add_argument("--validation-port", type=int, default=45847)
    parser.add_argument("--lease-listen-port", type=int, default=None)
    parser.add_argument("--remote-lease-port", type=int, default=None)
    parser.add_argument(
        "--discovery-port", type=int, default=DISCOVERY_PORT
    )
    parser.add_argument(
        "--discovery-bind", default="0.0.0.0"
    )
    parser.add_argument("--discovery-name")

    parser.add_argument(
        "--discovery-target",
        action="append",
        metavar="IP:PORT",
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
        "--remote-activation-port",
        type=int,
        default=ACTIVATION_PORT,
    )

    args = parser.parse_args(argv)

    if args.discovery_target:
        try:
            targets = tuple(
                (host, int(port))
                for host, port in (
                    item.rsplit(":", 1)
                    for item in args.discovery_target
                )
            )
        except ValueError as exc:
            parser.error(
                f"Invalid discovery target: {exc}"
            )
    else:
        targets = discovery_targets_for_interfaces()

    store = ConfigStore(
        args.profile / "settings.json"
        if args.profile is not None
        else None
    )

    app = QApplication.instance() or QApplication([])
    app.setApplicationName("SyncBridge")

    try:
        store.path.parent.mkdir(
            parents=True, exist_ok=True
        )

        instance_lock = QLockFile(
            str(
                store.path.parent
                / ".syncbridge-desktop.lock"
            )
        )
        instance_lock.setStaleLockTime(0)

        if not instance_lock.tryLock(100):
            QMessageBox.warning(
                None,
                "SyncBridge is already open",
                "A SyncBridge window is already using this profile. "
                "Use the existing window instead.",
            )
            return 1

    except OSError as exc:
        QMessageBox.critical(
            None,
            "Cannot start SyncBridge",
            str(exc),
        )
        return 1

    try:
        try:
            initialize_device_name(store)
            _prepare_profile(
                store,
                persistent=args.profile is not None,
            )

        except Exception as exc:
            QMessageBox.critical(
                None,
                "Connection setup needs attention",
                "SyncBridge could not safely prepare its connection "
                "settings. No user files were deleted. Do not delete "
                "your profile or recovery records.\n\n"
                f"Details: {exc}",
            )
            return 1

        controller = DiagnosticDesktopController(
            store,
            bind_address=args.bind_address,
            listen_ports=(
                tuple(args.listen_ports)
                if args.listen_ports
                else None
            ),
            lock_port=args.lock_port,
            validation_port=args.validation_port,
            lease_listen_port=args.lease_listen_port,
            remote_lease_port=args.remote_lease_port,
        )

        options = NetworkOptions(
            discovery_port=args.discovery_port,
            discovery_bind=args.discovery_bind,
            discovery_targets=targets,
            name=args.discovery_name,
            pairing_port=args.pairing_port,
            pairing_bind=args.pairing_bind,
            setup_port=args.setup_port,
            remote_setup_port=args.remote_setup_port,
            activation_port=args.activation_port,
            remote_activation_port=args.remote_activation_port,
        )

        window = SyncBridgePolishedWindow(
            controller,
            network_options=options,
        )

        onboarding_presenter = install_onboarding_presentation(app)

        # Our Options control is a regular QPushButton.
        # The chevron is part of the label, so Qt will not draw
        # an additional native dropdown indicator.
        window._options_button.setText("Options  ▾")

        window.local_view_refresh = QtLocalFileRefresh(window)
        window.show()

        result = app.exec()
        app.removeEventFilter(onboarding_presenter)
        return result

    finally:
        instance_lock.unlock()


if __name__ == "__main__":
    raise SystemExit(main())
