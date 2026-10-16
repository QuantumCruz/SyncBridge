
"""Launch the experimental PySide6 UI for a preconfigured SyncBridge folder."""
from __future__ import annotations

import argparse
from pathlib import Path

from PySide6.QtWidgets import QApplication

from syncbridge.storage.config import ConfigStore
from syncbridge.ui.desktop_controller import DesktopController
from syncbridge.ui.qt_window import SyncBridgeQtWindow


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SyncBridge — new desktop preview")
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--bind-address", default="127.0.0.1")
    parser.add_argument("--listen-ports", type=int, nargs=3)
    parser.add_argument("--lock-port", type=int, default=45846)
    parser.add_argument("--validation-port", type=int, default=45847)
    args = parser.parse_args(argv)

    controller = DesktopController(
        ConfigStore(args.profile / "settings.json" if args.profile else None),
        bind_address=args.bind_address,
        listen_ports=tuple(args.listen_ports) if args.listen_ports else None,
        lock_port=args.lock_port,
        validation_port=args.validation_port,
    )
    app = QApplication.instance() or QApplication([])
    app.setApplicationName("SyncBridge")
    window = SyncBridgeQtWindow(controller)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
