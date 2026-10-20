
"""Launch SyncBridge's Qt desktop with fenced manual synchronization."""
from __future__ import annotations

import argparse
from pathlib import Path

from PySide6.QtWidgets import QApplication

from syncbridge.network.discovery import DISCOVERY_PORT
from syncbridge.network.pairing import PAIRING_PORT
from syncbridge.network.share_activation import ACTIVATION_PORT
from syncbridge.network.share_setup import SETUP_PORT
from syncbridge.storage.config import ConfigStore
from syncbridge.ui.preview_diagnostics import DiagnosticDesktopController
from syncbridge.ui.qt_local_refresh import QtLocalFileRefresh
from syncbridge.ui.qt_onboarding import NetworkOptions
from syncbridge.ui.qt_direct_discovery_window import (
    SyncBridgeDiscoveryWindow,
    discovery_targets_for_interfaces,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="SyncBridge desktop"
    )

    parser.add_argument(
        "--profile",
        type=Path,
    )

    parser.add_argument(
        "--bind-address",
        default="0.0.0.0",
    )

    parser.add_argument(
        "--listen-ports",
        type=int,
        nargs=3,
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

    # No explicit value means derive the lease endpoint from
    # the existing configured transfer endpoint.
    #
    # Normal installations still use port 45849.
    # Explicit values remain available for test environments.
    parser.add_argument(
        "--lease-listen-port",
        type=int,
        default=None,
    )

    parser.add_argument(
        "--remote-lease-port",
        type=int,
        default=None,
    )

    parser.add_argument(
        "--discovery-port",
        type=int,
        default=DISCOVERY_PORT,
    )

    parser.add_argument(
        "--discovery-bind",
        default="0.0.0.0",
    )

    parser.add_argument(
        "--discovery-name",
    )

    parser.add_argument(
        "--discovery-target",
        action="append",
        metavar="IP:PORT",
    )

    parser.add_argument(
        "--pairing-port",
        type=int,
        default=PAIRING_PORT,
    )

    parser.add_argument(
        "--pairing-bind",
        default="0.0.0.0",
    )

    parser.add_argument(
        "--setup-port",
        type=int,
        default=SETUP_PORT,
    )

    parser.add_argument(
        "--remote-setup-port",
        type=int,
        default=SETUP_PORT,
    )

    parser.add_argument(
        "--activation-port",
        type=int,
        default=ACTIVATION_PORT,
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
                    value.rsplit(":", 1)
                    for value in args.discovery_target
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
        if args.profile
        else None
    )

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

    app = QApplication.instance() or QApplication([])
    app.setApplicationName("SyncBridge")

    window = SyncBridgeDiscoveryWindow(
        controller,
        network_options=options,
    )

    window.local_view_refresh = QtLocalFileRefresh(
        window
    )

    window.show()

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
