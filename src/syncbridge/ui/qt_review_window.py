
"""Clear, read-only review guidance for SyncBridge file differences.

Conflicts and deletion candidates remain blocked by the existing controller.
This module only changes presentation and navigation. It does not approve,
apply, discard, overwrite, or delete any file.

Users may inspect a flagged path, open their own shared folder, and copy
the relative path when discussing a problem with the other person.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
)

from syncbridge.ui.desktop_controller import (
    DesktopPhase,
    DesktopPlanItem,
    DesktopPreview,
)
from syncbridge.ui.qt_polished_window import SyncBridgePolishedWindow


REVIEW_STYLE = """
QFrame#reviewCard {
    background: #FFF8E9;
    border: 1px solid #EFD9A7;
    border-radius: 12px;
}
QFrame#reviewCard QLabel {
    background: transparent;
}
QLabel#reviewHeadline {
    color: #85531D;
    font-size: 11pt;
    font-weight: 700;
}
QLabel#reviewDescription {
    color: #795F41;
    font-size: 9pt;
}
QFrame#reviewCard QPushButton {
    background: #FFFFFF;
    color: #80551F;
    border: 1px solid #E5C995;
    border-radius: 8px;
    padding: 9px 14px;
    font-weight: 600;
}
QFrame#reviewCard QPushButton:hover:!disabled {
    background: #FFF0D5;
}
QFrame#reviewCard QPushButton:disabled {
    color: #A99B84;
    background: #F9F3E9;
}
"""

AGAIN_STYLE = """
QPushButton#previewAgain {
    background: #FFFFFF;
    color: #3056B4;
    border: 1px solid #BBCBE9;
    border-radius: 8px;
    padding: 8px 14px;
    font-weight: 600;
}
QPushButton#previewAgain:hover:!disabled {
    background: #EAF1FF;
    border-color: #94AFE2;
}
QPushButton#previewAgain:disabled {
    color: #9CA9BE;
    background: #F2F4F8;
}
"""

DETAILS_STYLE = """
QDialog#reviewDetailsDialog {
    background: #F6F8FC;
    color: #1D304B;
    font: 10pt "Segoe UI";
}
QDialog#reviewDetailsDialog QLabel {
    background: transparent;
    color: #263C58;
}
QLabel#reviewDetailsTitle {
    font-size: 16pt;
    font-weight: 700;
    color: #182B49;
}
QLabel#reviewDetailsSubtitle {
    color: #65768D;
    font-size: 9pt;
}
QLabel#reviewDetailsPath {
    background: #FFFFFF;
    border: 1px solid #DFE7F2;
    border-radius: 8px;
    padding: 12px;
    color: #244977;
    font-weight: 600;
}
QLabel#reviewDetailsGuidance {
    background: #FFF4E2;
    border: 1px solid #F0DEC0;
    border-radius: 9px;
    padding: 14px;
    color: #76552B;
}
QDialog#reviewDetailsDialog QPushButton {
    padding: 10px 15px;
    background: #FFFFFF;
    color: #284466;
    border: 1px solid #CFDBE9;
    border-radius: 9px;
    font-weight: 600;
}
QDialog#reviewDetailsDialog QPushButton:hover:!disabled {
    background: #EAF1FF;
}
QDialog#reviewDetailsDialog QPushButton#primary {
    background: #345CDF;
    color: #FFFFFF;
    border-color: #345CDF;
}
"""


@dataclass(frozen=True)
class ReviewBreakdown:
    conflicts: int = 0
    deletions: int = 0
    other: int = 0

    @property
    def total(self) -> int:
        return self.conflicts + self.deletions + self.other

    def description(self) -> str:
        pieces: list[str] = []

        if self.conflicts:
            unit = "conflict" if self.conflicts == 1 else "conflicts"
            pieces.append(f"{self.conflicts} {unit}")

        if self.deletions:
            unit = (
                "deletion review"
                if self.deletions == 1
                else "deletion reviews"
            )
            pieces.append(f"{self.deletions} {unit}")

        if self.other:
            unit = "other item" if self.other == 1 else "other items"
            pieces.append(
                f"{self.other} {unit} requiring review"
            )

        return "  ·  ".join(pieces) if pieces else "Review required"


def review_breakdown(
    preview: DesktopPreview | None,
) -> ReviewBreakdown:
    """Count only items marked for review by the production controller."""
    if preview is None:
        return ReviewBreakdown()

    conflicts = 0
    deletions = 0
    other = 0

    for item in preview.items:
        if not item.needs_review:
            continue

        action = item.action.strip().casefold()

        if action == "conflict":
            conflicts += 1
        elif "deletion" in action or "delete" in action:
            deletions += 1
        else:
            other += 1

    return ReviewBreakdown(
        conflicts=conflicts,
        deletions=deletions,
        other=other,
    )


def review_guidance(
    item: DesktopPlanItem,
) -> tuple[str, str, str]:
    """Explain an existing review decision without inventing permissions."""
    action = item.action.strip().casefold()

    if action == "conflict":
        return (
            "Both computers changed this file",
            "SyncBridge cannot safely choose which version should win.",
            "Compare the two versions with the other person. "
            "Keep a separate copy of anything important before editing "
            "either version. Once both sides agree on the file content, "
            "use Preview differences again to check the result.",
        )

    if "deletion" in action or "delete" in action:
        return (
            "A file is missing from one computer",
            "SyncBridge has flagged a possible deletion for review.",
            "Find out whether the file was intentionally removed. "
            "If it should be kept, restore it on the affected computer "
            "from a trusted copy. Do not assume a missing file should "
            "be deleted from the other computer. "
            "This window cannot authorize deletion. "
            "Preview again after checking the folders.",
        )

    return (
        "This change requires your attention",
        "SyncBridge has not approved this change for automatic application.",
        "Inspect the file and discuss the difference with the other "
        "person. Keep any important copies before making changes. "
        "Preview again when the issue has been addressed.",
    )


class ReviewDetailsDialog(QDialog):
    """Read-only explanation of one flagged preview item."""

    def __init__(
        self,
        parent,
        item: DesktopPlanItem,
        *,
        open_local_folder: Callable[[], None],
    ):
        if not item.needs_review:
            raise ValueError(
                "Only items requiring review can open a review dialog"
            )

        super().__init__(parent)
        self.item = item

        self.setObjectName("reviewDetailsDialog")
        self.setWindowTitle("File review · SyncBridge")
        self.setMinimumWidth(520)
        self.resize(600, 400)

        title, explanation, guidance = review_guidance(item)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 24, 26, 24)
        layout.setSpacing(14)

        self.title_label = QLabel(title, self)
        self.title_label.setObjectName("reviewDetailsTitle")
        self.title_label.setWordWrap(True)
        self.title_label.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.title_label)

        self.subtitle_label = QLabel(
            "Review this item before making any file changes.",
            self,
        )
        self.subtitle_label.setObjectName("reviewDetailsSubtitle")
        self.subtitle_label.setWordWrap(True)
        layout.addWidget(self.subtitle_label)

        self.path_label = QLabel(str(item.path), self)
        self.path_label.setObjectName("reviewDetailsPath")
        self.path_label.setTextFormat(Qt.TextFormat.PlainText)
        self.path_label.setWordWrap(True)
        self.path_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        layout.addWidget(self.path_label)

        self.explanation_label = QLabel(explanation, self)
        self.explanation_label.setTextFormat(
            Qt.TextFormat.PlainText
        )
        self.explanation_label.setWordWrap(True)
        layout.addWidget(self.explanation_label)

        self.reason_label = QLabel(
            str(item.description),
            self,
        )
        self.reason_label.setObjectName(
            "reviewDetailsSubtitle"
        )
        self.reason_label.setTextFormat(Qt.TextFormat.PlainText)
        self.reason_label.setWordWrap(True)
        layout.addWidget(self.reason_label)

        self.guidance_label = QLabel(guidance, self)
        self.guidance_label.setObjectName(
            "reviewDetailsGuidance"
        )
        self.guidance_label.setTextFormat(Qt.TextFormat.PlainText)
        self.guidance_label.setWordWrap(True)
        layout.addWidget(self.guidance_label)

        layout.addStretch(1)

        self.feedback_label = QLabel("", self)
        self.feedback_label.setTextFormat(
            Qt.TextFormat.PlainText
        )
        layout.addWidget(self.feedback_label)

        actions = QHBoxLayout()
        actions.setSpacing(8)

        self.open_folder_button = QPushButton(
            "Open my folder",
            self,
        )
        self.open_folder_button.clicked.connect(
            open_local_folder
        )
        actions.addWidget(self.open_folder_button)

        self.copy_path_button = QPushButton(
            "Copy file path",
            self,
        )
        self.copy_path_button.clicked.connect(
            self._copy_path
        )
        actions.addWidget(self.copy_path_button)

        actions.addStretch(1)

        self.close_button = QPushButton("Close", self)
        self.close_button.setObjectName("primary")
        self.close_button.clicked.connect(self.close)
        actions.addWidget(self.close_button)

        layout.addLayout(actions)
        self.setStyleSheet(DETAILS_STYLE)

    def _copy_path(self) -> None:
        # Copy the relative path only. Never expose private profile data.
        clipboard = QApplication.clipboard()
        if clipboard is None:
            self.feedback_label.setText(
                "The clipboard is unavailable."
            )
            return

        clipboard.setText(str(self.item.path))
        self.feedback_label.setText(
            "File path copied."
        )


class SyncBridgeReviewWindow(SyncBridgePolishedWindow):
    """Show clear review details while retaining all existing safety gates."""

    def __init__(
        self,
        controller,
        *,
        network_options,
    ):
        self._review_ui_ready = False
        self._review_only = False
        self._details_dialog: ReviewDetailsDialog | None = None

        super().__init__(
            controller,
            network_options=network_options,
        )

    @staticmethod
    def _make_plain_label(text: str, parent) -> QLabel:
        label = QLabel(text, parent)
        label.setWordWrap(True)
        label.setTextFormat(Qt.TextFormat.PlainText)
        return label

    def _make_ui(self) -> None:
        super()._make_ui()

        root = self.centralWidget()
        workspace = root.layout().itemAt(2).widget()
        workspace_layout = workspace.layout()

        self._review_card = QFrame(self)
        self._review_card.setObjectName("reviewCard")
        self._review_card.setStyleSheet(REVIEW_STYLE)

        review_layout = QHBoxLayout(self._review_card)
        review_layout.setContentsMargins(18, 16, 18, 16)
        review_layout.setSpacing(14)

        message_layout = QVBoxLayout()
        message_layout.setSpacing(6)

        self._review_headline = self._make_plain_label(
            "Review required",
            self._review_card,
        )
        self._review_headline.setObjectName(
            "reviewHeadline"
        )
        message_layout.addWidget(self._review_headline)

        self._review_description = self._make_plain_label(
            "",
            self._review_card,
        )
        self._review_description.setObjectName(
            "reviewDescription"
        )
        message_layout.addWidget(self._review_description)

        review_layout.addLayout(message_layout, 1)

        review_actions = QVBoxLayout()
        review_actions.setSpacing(7)

        self._review_details_button = QPushButton(
            "Inspect selected file",
            self._review_card,
        )
        self._review_details_button.setObjectName(
            "reviewDetailsButton"
        )
        self._review_details_button.setToolTip(
            "Explain why the selected file needs review"
        )
        self._review_details_button.clicked.connect(
            self._open_review_details
        )
        review_actions.addWidget(
            self._review_details_button
        )

        self._review_filter_button = QPushButton(
            "Show review items",
            self._review_card,
        )
        self._review_filter_button.setObjectName(
            "reviewFilter"
        )
        self._review_filter_button.setCheckable(True)
        self._review_filter_button.clicked.connect(
            self._toggle_review_filter
        )
        review_actions.addWidget(
            self._review_filter_button
        )

        review_layout.addLayout(review_actions)

        workspace_layout.insertWidget(
            1,
            self._review_card,
        )

        self._preview_again_button = QPushButton(
            "Preview again",
            self._result_card,
        )
        self._preview_again_button.setObjectName(
            "previewAgain"
        )
        self._preview_again_button.setStyleSheet(
            AGAIN_STYLE
        )
        self._preview_again_button.setToolTip(
            "Recheck both folders for remaining differences"
        )
        self._preview_again_button.clicked.connect(
            self._preview_files
        )

        result_actions = QHBoxLayout()
        result_actions.setContentsMargins(0, 4, 0, 0)
        result_actions.addStretch(1)
        result_actions.addWidget(
            self._preview_again_button
        )

        self._result_card.layout().addLayout(
            result_actions
        )

        self.table.itemSelectionChanged.connect(
            self._refresh_review_selection
        )
        self.table.itemDoubleClicked.connect(
            self._review_double_clicked
        )

        self._review_ui_ready = True

    def _selected_review_item(
        self,
    ) -> DesktopPlanItem | None:
        preview = self._preview

        if (
            preview is None
            or not preview.requires_review
            or self.table.rowCount() != len(preview.items)
        ):
            return None

        row = self.table.currentRow()

        if (
            row < 0
            or row >= len(preview.items)
            or self.table.isRowHidden(row)
        ):
            return None

        item = preview.items[row]
        return item if item.needs_review else None

    def _refresh_review_selection(self) -> None:
        if not self._review_ui_ready:
            return

        enabled = bool(
            self._selected_review_item() is not None
            and self.lifecycle.phase is DesktopPhase.CONNECTED
            and self._live_session is not None
            and self.controller.running
            and not self._busy
            and not self._closing
        )

        self._review_details_button.setEnabled(enabled)

    def _review_double_clicked(self, table_item) -> None:
        if table_item is not None:
            self.table.selectRow(table_item.row())
        self._open_review_details()

    def _open_review_details(self) -> None:
        self._refresh_review_selection()

        if not self._review_details_button.isEnabled():
            return

        item = self._selected_review_item()
        if item is None:
            return

        existing = self._details_dialog
        if existing is not None:
            existing.close()

        dialog = ReviewDetailsDialog(
            self,
            item,
            open_local_folder=self._open_folder,
        )

        self._details_dialog = dialog
        dialog.finished.connect(
            lambda _result, current=dialog:
            self._finish_review_dialog(current)
        )

        dialog.show()
        dialog.raise_()
        dialog.activateWindow()

    def _finish_review_dialog(
        self,
        dialog: ReviewDetailsDialog,
    ) -> None:
        if self._details_dialog is dialog:
            self._details_dialog = None

    def _sync_review_row_visibility(self) -> None:
        preview = self._preview

        if preview is None:
            for row in range(self.table.rowCount()):
                self.table.setRowHidden(row, False)
            return

        if self.table.rowCount() != len(preview.items):
            return

        for row, item in enumerate(preview.items):
            hidden = bool(
                self._review_only
                and preview.requires_review
                and not item.needs_review
            )
            self.table.setRowHidden(row, hidden)

    def _toggle_review_filter(self, checked: bool) -> None:
        preview = self._preview

        if (
            preview is None
            or not preview.requires_review
            or not preview.items
        ):
            self._review_only = False
            self._review_filter_button.setChecked(False)
            return

        self._review_only = bool(checked)
        self._sync_review_row_visibility()

        if self._selected_review_item() is None:
            for row, item in enumerate(preview.items):
                if item.needs_review:
                    self.table.selectRow(row)
                    break

        self.tabs.setCurrentIndex(2)
        self._apply_state()

    def _display_preview(
        self,
        preview: DesktopPreview,
    ) -> None:
        self._review_only = False

        if self._details_dialog is not None:
            self._details_dialog.close()

        if self._review_ui_ready:
            self._review_filter_button.setChecked(False)

        super()._display_preview(preview)

        first_flagged_row: int | None = None

        for row, item in enumerate(preview.items):
            self.table.setRowHidden(row, False)

            if not item.needs_review:
                continue

            if first_flagged_row is None:
                first_flagged_row = row

            for column in range(
                self.table.columnCount()
            ):
                cell = self.table.item(row, column)
                if cell is None:
                    continue

                cell.setBackground(
                    QColor("#FFF1D8")
                )

                if column == 0:
                    cell.setForeground(
                        QColor("#94571A")
                    )

        if first_flagged_row is not None:
            self.table.selectRow(first_flagged_row)

        self._apply_state()

    def _apply_state(self) -> None:
        super()._apply_state()

        if not self._review_ui_ready:
            return

        phase = self.lifecycle.phase
        active = bool(
            phase in (
                DesktopPhase.CONNECTED,
                DesktopPhase.SYNCHRONIZING,
            )
            and self._live_session is not None
            and self.controller.running
            and not self._recovery_required
        )

        preview = self._preview
        blocked = bool(
            active
            and preview is not None
            and preview.requires_review
        )

        if not blocked and self._review_only:
            self._review_only = False
            self._review_filter_button.setChecked(False)
            self._sync_review_row_visibility()

        if blocked and preview is not None:
            counts = review_breakdown(preview)
            count = counts.total

            if count:
                noun = "item" if count == 1 else "items"
                self._review_headline.setText(
                    f"{count} {noun} need your attention"
                )
            else:
                self._review_headline.setText(
                    "This preview needs your attention"
                )

            self._review_description.setText(
                counts.description()
                + "\n"
                + "No changes from this preview have been applied. "
                + "Select a highlighted file to inspect it. "
                + "After resolving the issue, preview again."
            )

            has_safe = any(
                not item.needs_review
                for item in preview.items
            )

            self._review_filter_button.setVisible(
                count > 0 and has_safe
            )
            self._review_filter_button.setText(
                "Show all changes"
                if self._review_only
                else "Show review items"
            )
            self._review_filter_button.setEnabled(
                phase is DesktopPhase.CONNECTED
                and not self._busy
            )

        self._review_card.setVisible(blocked)
        self._refresh_review_selection()

        if blocked:
            self.sync_button.setVisible(False)
            self.sync_button.setEnabled(False)

        show_again = bool(
            active
            and phase is DesktopPhase.CONNECTED
            and self._last_sync_result is not None
        )

        self._preview_again_button.setVisible(show_again)
        self._preview_again_button.setEnabled(
            show_again
            and not self._busy
            and self.preview_button.isEnabled()
        )
