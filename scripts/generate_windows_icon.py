
"""Generate reproducible SyncBridge PNG and Windows ICO assets.

Run from the repository root:
    python scripts/generate_windows_icon.py

The icon comes from the same Qt painter used by the running desktop.
No Pillow, image download, designer tool, or network access is required.
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
from pathlib import Path

from PySide6.QtCore import QBuffer, QIODevice

PROJECT = Path(__file__).resolve().parent.parent
SOURCE = PROJECT / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from syncbridge.ui.branding import render_brand_image

DEFAULT_DIRECTORY = PROJECT / "assets" / "windows"
ICON_SIZES = (16, 24, 32, 48, 64, 128, 256)


class IconBuildError(RuntimeError):
    """The generated icon cannot be trusted for release packaging."""


def _png_bytes(size: int) -> bytes:
    image = render_brand_image(size)
    buffer = QBuffer()
    if not buffer.open(QIODevice.OpenModeFlag.WriteOnly):
        raise IconBuildError("Cannot open PNG memory buffer")
    try:
        if not image.save(buffer, "PNG"):
            raise IconBuildError(f"Qt could not encode the {size}px icon")
        data = bytes(buffer.data())
    finally:
        buffer.close()
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise IconBuildError("Invalid PNG output from Qt")
    return data


def make_ico() -> bytes:
    """Create a valid multi-resolution ICO containing PNG image entries."""
    images = [(size, _png_bytes(size)) for size in ICON_SIZES]
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = []
    for size, png in images:
        dimension = 0 if size == 256 else size
        entries.append(
            struct.pack(
                "<BBBBHHII",
                dimension,
                dimension,
                0,
                0,
                1,
                32,
                len(png),
                offset,
            )
        )
        offset += len(png)
    return header + b"".join(entries) + b"".join(p for _, p in images)


def _write_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.tmp"
    )
    try:
        temporary.write_bytes(content)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def generate_icons(directory: Path = DEFAULT_DIRECTORY) -> tuple[Path, Path]:
    """Write matching assets; do not touch user profiles or distribution data."""
    directory = Path(directory)
    png = directory / "SyncBridge.png"
    ico = directory / "SyncBridge.ico"
    _write_atomic(png, _png_bytes(512))
    _write_atomic(ico, make_ico())
    return png, ico


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate the official SyncBridge Windows icon"
    )
    parser.add_argument(
        "--output-dir", type=Path, default=DEFAULT_DIRECTORY
    )
    args = parser.parse_args(argv)
    try:
        png, ico = generate_icons(args.output_dir)
    except (OSError, IconBuildError, ValueError) as exc:
        print(f"SyncBridge icon generation failed: {exc}", file=sys.stderr)
        return 1
    print(f"Preview: {png}")
    print(f"Windows icon: {ico}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
