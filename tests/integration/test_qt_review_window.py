
"""Check conflict guidance and review controls without peer networking.

The test uses production DesktopPlanItem/DesktopPreview models and confirms
that review actions only inspect, navigate, or copy paths. No file is changed.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

CHILD = "SYNCBRIDGE_REVIEW_QT_CHILD"


def _exercise(tmp_path: Path, monkeypatch) -> None:
    from PySide6.QtWidgets import QApplication

    from syncbridge.storage.config import ConfigStore, ShareConfig
    from syncbridge.ui.desktop_controller import (
        DesktopPhase,
        DesktopPlanItem,
        DesktopPreview,
    )
    from syncbridge.ui.qt_onboarding import NetworkOptions
    from syncbridge.ui.qt_review_window import (
        ReviewDetailsDialog,
        SyncBridgeReviewWindow,
        review_breakdown,
    )

    profile = tmp_path / "profile"
    profile.mkdir()

    folder = tmp_path / "shared"
    folder.mkdir()

    important_file = folder / "important.txt"
    important_file.write_text(
        "Preserve this file",
        encoding="utf-8",
    )

    store = ConfigStore(profile / "settings.json")
    share = ShareConfig(
        share_id="a" * 32,
        peer_node_id="b" * 32,
        local_root=str(folder),
        display_name="Test files",
        remote_host="127.0.0.1",
        enabled=True,
        grant_manifest=True,
        grant_read=True,
        grant_write=True,
        grant_agreement=True,
    )
    store.save(replace(store.load(), shares=(share,)))

    empty_preview = DesktopPreview(
        revision=0,
        items=(),
        requires_review=False,
    )

    class Controller:
        def __init__(self):
            self.store = store
            self.runtime = SimpleNamespace(listen_ports=None)
            self.running = False
            self.preview_calls = 0

        def preview(self):
            self.preview_calls += 1
            return empty_preview

        def stop(self):
            self.running = False

    def offline_network(window):
        window._network_started = True
        window._apply_state()

    monkeypatch.setattr(
        SyncBridgeReviewWindow,
        "_start_network",
        offline_network,
    )

    app = QApplication.instance() or QApplication([])
    previous = app.quitOnLastWindowClosed()
    app.setQuitOnLastWindowClosed(False)

    controller = Controller()
    window = SyncBridgeReviewWindow(
        controller,
        network_options=NetworkOptions(),
    )
    window.show()

    opened_folders: list[str] = []

    monkeypatch.setattr(
        window,
        "_open_folder",
        lambda: opened_folders.append("opened"),
    )

    try:
        app.processEvents()

        assert not window._review_card.isVisible()
        assert not window._result_card.isVisible()
        assert not window.sync_button.isVisible()

        window._move(DesktopPhase.CONNECTING)
        window._live_session = "c" * 32
        controller.running = True
        window._move(DesktopPhase.CONNECTED)

        safe_item = DesktopPlanItem(
            path="safe.txt",
            action="Send",
            description="Copy to the other computer",
            needs_review=False,
            size=50,
        )

        conflict = DesktopPlanItem(
            path="important.txt",
            action="Conflict",
            description="Both computers changed this file",
            needs_review=True,
        )

        deletion = DesktopPlanItem(
            path="old.txt",
            action="Deletion review",
            description="Previously synchronized file is missing",
            needs_review=True,
        )

        blocked_preview = DesktopPreview(
            revision=0,
            items=(safe_item, conflict, deletion),
            requires_review=True,
        )

        counts = review_breakdown(blocked_preview)

        assert counts.conflicts == 1
        assert counts.deletions == 1
        assert counts.other == 0
        assert counts.total == 2

        window._preview = blocked_preview
        window._display_preview(blocked_preview)
        app.processEvents()

        assert window._review_card.isVisible()
        assert "2 items" in window._review_headline.text()
        assert "1 conflict" in window._review_description.text()
        assert "1 deletion review" in window._review_description.text()
        assert not window.sync_button.isVisible()
        assert not window.sync_button.isEnabled()

        assert window.table.rowCount() == 3
        assert window.table.item(1, 0).background().color().name() == (
            "#fff1d8"
        )
        assert window.table.item(2, 0).background().color().name() == (
            "#fff1d8"
        )

        # A safe item cannot open a conflict/review dialog.
        window.table.selectRow(0)
        app.processEvents()

        assert not window._review_details_button.isEnabled()

        # Select the conflict and open an actual read-only dialog.
        window.table.selectRow(1)
        app.processEvents()

        assert window._review_details_button.isVisible()
        assert window._review_details_button.isEnabled()

        window._review_details_button.click()
        app.processEvents()

        dialog = window._details_dialog

        assert isinstance(dialog, ReviewDetailsDialog)
        assert dialog.isVisible()
        assert "Both computers changed" in dialog.title_label.text()
        assert dialog.path_label.text() == "important.txt"
        assert "cannot safely choose" in (
            dialog.explanation_label.text()
        )
        assert "Preview differences again" in (
            dialog.guidance_label.text()
        )

        # Opening the folder uses the existing navigation action.
        dialog.open_folder_button.click()
        assert opened_folders == ["opened"]

        # Copying a path does not copy, read, or modify file contents.
        dialog.copy_path_button.click()
        assert app.clipboard().text() == "important.txt"
        assert dialog.feedback_label.text() == "File path copied."

        dialog.close()
        app.processEvents()

        # The deletion explanation must not imply deletion was approved.
        window.table.selectRow(2)
        app.processEvents()
        window._review_details_button.click()
        app.processEvents()

        deletion_dialog = window._details_dialog

        assert isinstance(deletion_dialog, ReviewDetailsDialog)
        assert "file is missing" in (
            deletion_dialog.title_label.text().lower()
        )
        assert deletion_dialog.path_label.text() == "old.txt"
        assert "cannot authorize deletion" in (
            deletion_dialog.guidance_label.text()
        )

        deletion_dialog.close()
        app.processEvents()

        assert important_file.read_text(
            encoding="utf-8"
        ) == "Preserve this file"

        # Filtering affects visible rows, not the actual sync plan.
        assert window._review_filter_button.isVisible()
        window._review_filter_button.click()
        app.processEvents()

        assert window.table.isRowHidden(0)
        assert not window.table.isRowHidden(1)
        assert not window.table.isRowHidden(2)
        assert window._preview is blocked_preview
        assert blocked_preview.items == (
            safe_item,
            conflict,
            deletion,
        )

        window._review_filter_button.click()
        app.processEvents()

        assert not any(
            window.table.isRowHidden(row)
            for row in range(3)
        )

        # A safe preview restores the ordinary Sync action.
        safe_preview = DesktopPreview(
            revision=1,
            items=(safe_item,),
            requires_review=False,
        )

        window._preview = safe_preview
        window._display_preview(safe_preview)
        app.processEvents()

        assert not window._review_card.isVisible()
        assert not window.table.isRowHidden(0)
        assert window.sync_button.isVisible()
        assert window.sync_button.isEnabled()

        # A completion message is shown only after the operation's
        # existing backend event reports success.
        window._preview = None
        window._visual_operation = "sync"
        window._busy = True
        window._move(DesktopPhase.SYNCHRONIZING)

        window.summary.setText(
            "Synchronization finished. Preview again to check changes."
        )

        window._busy = False
        window._move(DesktopPhase.CONNECTED)
        window._drain()
        app.processEvents()

        assert window._result_card.isVisible()
        assert window._preview_again_button.isVisible()
        assert window._preview_again_button.isEnabled()

        assert (
            window._last_sync_result is not None
            and window._last_sync_result[2] == "success"
        )

        # The button must invoke the real, read-only preview method.
        window._preview_again_button.click()

        deadline = time.monotonic() + 8

        while time.monotonic() < deadline:
            app.processEvents()
            window._drain()

            if (
                controller.preview_calls == 1
                and window.lifecycle.phase is DesktopPhase.CONNECTED
                and not window._busy
            ):
                break

            time.sleep(0.02)

        assert controller.preview_calls == 1
        assert window._preview is empty_preview
        assert not window._result_card.isVisible()

        # Disconnecting clears the review presentation.
        window._preview = None
        window._live_session = None
        controller.running = False

        window._move(DesktopPhase.DISCONNECTING)
        window._move(DesktopPhase.DISCONNECTED)
        app.processEvents()

        assert not window._review_card.isVisible()
        assert not window._result_card.isVisible()
        assert not window.sync_button.isVisible()

        assert important_file.read_text(
            encoding="utf-8"
        ) == "Preserve this file"

    finally:
        if window._details_dialog is not None:
            window._details_dialog.close()

        window._close_allowed = True
        window.close()
        app.setQuitOnLastWindowClosed(previous)


def test_review_presentation_preserves_sync_safety(
    tmp_path,
    monkeypatch,
):
    pytest.importorskip("PySide6")

    if os.environ.get(CHILD) == "1":
        _exercise(tmp_path, monkeypatch)
        return

    environment = os.environ.copy()
    environment[CHILD] = "1"
    environment["QT_QPA_PLATFORM"] = "offscreen"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            __file__,
            "-q",
            "-s",
        ],
        cwd=Path(__file__).resolve().parents[2],
        env=environment,
        capture_output=True,
        text=True,
        timeout=55,
        check=False,
    )

    assert result.returncode == 0, (
        result.stdout + "\n" + result.stderr
    )
