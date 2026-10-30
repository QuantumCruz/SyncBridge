
"""Validate Windows icon contents, launch flags, and Qt window branding."""
from __future__ import annotations

import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.build_windows import ICON, _command

CHILD = "SYNCBRIDGE_BRANDING_TEST_CHILD"


def _exercise(tmp_path: Path) -> None:
    from PySide6.QtWidgets import QApplication, QWidget

    from scripts.generate_windows_icon import (
        ICON_SIZES,
        generate_icons,
    )
    from syncbridge.ui.branding import (
        apply_application_branding,
        render_brand_image,
    )

    app = QApplication.instance() or QApplication([])
    window = QWidget()
    try:
        assert not render_brand_image(256).isNull()
        assert render_brand_image(256).width() == 256
        with pytest.raises(ValueError):
            render_brand_image(0)
        with pytest.raises(ValueError):
            render_brand_image(True)

        png_path, ico_path = generate_icons(tmp_path / "assets")
        png = png_path.read_bytes()
        ico = ico_path.read_bytes()
        assert png.startswith(b"\x89PNG\r\n\x1a\n")
        assert struct.unpack_from("<HHH", ico) == (
            0, 1, len(ICON_SIZES)
        )

        end_of_directory = 6 + 16 * len(ICON_SIZES)
        offsets: list[int] = []
        for index, size in enumerate(ICON_SIZES):
            entry = struct.unpack_from(
                "<BBBBHHII", ico, 6 + 16 * index
            )
            expected_width = 0 if size == 256 else size
            width, height, colors, reserved, planes, bits, nbytes, offset = entry
            assert (width, height) == (expected_width, expected_width)
            assert colors == reserved == 0
            assert (planes, bits) == (1, 32)
            assert offset >= end_of_directory
            assert ico[offset:offset + 8] == b"\x89PNG\r\n\x1a\n"
            assert len(ico[offset:offset + nbytes]) == nbytes
            offsets.append(offset)
        assert offsets == sorted(offsets)
        assert ico_path.stat().st_size > png_path.stat().st_size // 4

        apply_application_branding(app, window)
        assert app.applicationName() == "SyncBridge"
        assert not app.windowIcon().isNull()
        assert not window.windowIcon().isNull()
        assert not window.windowIcon().pixmap(32, 32).isNull()
    finally:
        window.close()


def test_reproducible_brand_assets_and_window_identity(
    tmp_path: Path,
) -> None:
    pytest.importorskip("PySide6")
    if os.environ.get(CHILD) == "1":
        _exercise(tmp_path)
        return

    env = os.environ.copy()
    env[CHILD] = "1"
    env["QT_QPA_PLATFORM"] = "offscreen"
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-q", "-s"],
        cwd=Path(__file__).resolve().parents[2],
        env=env,
        capture_output=True,
        text=True,
        timeout=55,
        check=False,
    )
    assert completed.returncode == 0, (
        completed.stdout + "\n" + completed.stderr
    )


def test_release_build_includes_branded_exe_icon_and_no_console() -> None:
    ordinary = _command(console=False)
    diagnostic = _command(console=True)
    assert "--windowed" in ordinary
    assert "--console" not in ordinary
    assert "--icon" in ordinary
    assert ordinary[ordinary.index("--icon") + 1] == str(ICON)
    assert "--console" in diagnostic
    assert "--icon" in diagnostic
