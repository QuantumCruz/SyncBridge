
"""One vector-drawn identity for SyncBridge's Windows and Qt interfaces.

No external artwork, fonts, profile files, or network access is required.
This source also produces the release executable icon through the build script.
"""
from __future__ import annotations

import ctypes
import sys

from PySide6.QtCore import Qt, QRectF
from PySide6.QtGui import (
    QBrush,
    QColor,
    QIcon,
    QImage,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
    QRadialGradient,
)
from PySide6.QtWidgets import QApplication, QWidget


APP_USER_MODEL_ID = "SyncBridge.Desktop"


def render_brand_image(size: int = 512) -> QImage:
    """Draw the app emblem at any icon resolution without raster assets."""
    if type(size) is not int or not 16 <= size <= 1024:
        raise ValueError("Icon size must be between 16 and 1024 pixels")

    image = QImage(
        size, size, QImage.Format.Format_ARGB32_Premultiplied
    )
    image.fill(Qt.GlobalColor.transparent)

    painter = QPainter(image)
    try:
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
        painter.scale(size / 512.0, size / 512.0)
        painter.setPen(Qt.PenStyle.NoPen)

        tile = QPainterPath()
        tile.addRoundedRect(QRectF(24, 24, 464, 464), 114, 114)
        base = QLinearGradient(52, 34, 473, 494)
        base.setColorAt(0.0, QColor("#152C63"))
        base.setColorAt(0.55, QColor("#2455C7"))
        base.setColorAt(1.0, QColor("#183A93"))
        painter.fillPath(tile, QBrush(base))
        painter.setClipPath(tile)

        halo = QRadialGradient(390, 128, 300)
        halo.setColorAt(0.0, QColor(80, 227, 255, 115))
        halo.setColorAt(1.0, QColor(80, 227, 255, 0))
        painter.setBrush(QBrush(halo))
        painter.drawEllipse(QRectF(90, -170, 570, 570))
        painter.setClipping(False)

        # Two screens remain distinguishable in the 16-pixel Windows icon.
        left = QRectF(76, 164, 168, 173)
        right = QRectF(268, 164, 168, 173)
        painter.setPen(
            QPen(
                QColor("#F4F8FF"), 16,
                Qt.PenStyle.SolidLine,
                Qt.PenCapStyle.RoundCap,
                Qt.PenJoinStyle.RoundJoin,
            )
        )
        painter.setBrush(QColor(255, 255, 255, 29))
        painter.drawRoundedRect(left, 26, 26)

        painter.setPen(
            QPen(
                QColor("#81EAFF"), 16,
                Qt.PenStyle.SolidLine,
                Qt.PenCapStyle.RoundCap,
                Qt.PenJoinStyle.RoundJoin,
            )
        )
        painter.setBrush(QColor(42, 207, 250, 32))
        painter.drawRoundedRect(right, 26, 26)

        # The center link sits over the devices and signifies two-way sync.
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#173579"))
        painter.drawRoundedRect(QRectF(166, 209, 180, 94), 43, 43)

        stroke = QPen(
            QColor("#FFFFFF"), 15,
            Qt.PenStyle.SolidLine,
            Qt.PenCapStyle.RoundCap,
            Qt.PenJoinStyle.RoundJoin,
        )
        painter.setPen(stroke)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        top = QPainterPath()
        top.moveTo(207, 237)
        top.lineTo(303, 237)
        top.moveTo(283, 220)
        top.lineTo(303, 237)
        top.lineTo(283, 254)
        painter.drawPath(top)

        painter.setPen(
            QPen(
                QColor("#81EAFF"), 15,
                Qt.PenStyle.SolidLine,
                Qt.PenCapStyle.RoundCap,
                Qt.PenJoinStyle.RoundJoin,
            )
        )
        bottom = QPainterPath()
        bottom.moveTo(303, 276)
        bottom.lineTo(207, 276)
        bottom.moveTo(227, 259)
        bottom.lineTo(207, 276)
        bottom.lineTo(227, 293)
        painter.drawPath(bottom)

        # Small feet make the shapes recognizable as computer displays.
        painter.setPen(
            QPen(
                QColor("#E1ECFF"), 13,
                Qt.PenStyle.SolidLine,
                Qt.PenCapStyle.RoundCap,
            )
        )
        painter.drawLine(122, 360, 203, 360)
        painter.setPen(
            QPen(
                QColor("#A1F0FF"), 13,
                Qt.PenStyle.SolidLine,
                Qt.PenCapStyle.RoundCap,
            )
        )
        painter.drawLine(307, 360, 389, 360)
    finally:
        painter.end()

    return image


def application_icon() -> QIcon:
    """Make a multisize icon for normal, minimized and taskbar windows."""
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        icon.addPixmap(QPixmap.fromImage(render_brand_image(size)))
    return icon


def configure_windows_app_identity() -> None:
    """Prevent Windows taskbar grouping the app under the Python launcher."""
    if sys.platform != "win32":
        return
    try:
        result = ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            ctypes.c_wchar_p(APP_USER_MODEL_ID)
        )
    except (AttributeError, OSError):
        return
    if result != 0:
        # Windows may reject an AppUserModelID in restricted environments;
        # this must never prevent SyncBridge from starting.
        return


def apply_application_branding(app: QApplication, window: QWidget) -> None:
    """Set the same art on QApplication and the desktop window."""
    icon = application_icon()
    app.setApplicationName("SyncBridge")
    app.setWindowIcon(icon)
    window.setWindowIcon(icon)
