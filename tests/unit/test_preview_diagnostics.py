
"""Ensure desktop preview diagnostics are read-only and privacy-preserving."""
from __future__ import annotations

import sys
import time

import pytest

from syncbridge.core.scanner import FileScanner
from syncbridge.ui.preview_diagnostics import PreviewDiagnostics


def test_real_scanner_is_measured_without_changing_results(tmp_path):
    folder = tmp_path / "sample-files"
    folder.mkdir()

    (folder / "confidential-filename.txt").write_text(
        "contents",
        encoding="utf-8",
    )

    log = (
        tmp_path
        / "settings"
        / "diagnostics"
        / "preview.log"
    )

    monitor = PreviewDiagnostics(log)
    previous_profile = sys.getprofile()

    result = monitor.run(
        FileScanner(folder).scan
    )

    assert "confidential-filename.txt" in result.files
    assert sys.getprofile() is previous_profile

    text = log.read_text(encoding="utf-8")

    assert "START read-only preview" in text
    assert "STAGE Scanning and hashing local files" in text
    assert "END total_seconds=" in text

    assert "confidential-filename.txt" not in text
    assert str(folder) not in text


def test_failure_propagates_and_private_exception_text_is_not_logged(
    tmp_path,
):
    monitor = PreviewDiagnostics(
        tmp_path / "preview.log"
    )

    def broken():
        raise RuntimeError(
            "sensitive-path-or-token"
        )

    with pytest.raises(
        RuntimeError,
        match="sensitive-path-or-token",
    ):
        monitor.run(broken)

    text = monitor.path.read_text(
        encoding="utf-8"
    )

    assert "FAILED" in text
    assert "exception=RuntimeError" in text
    assert "sensitive-path-or-token" not in text


def test_long_preview_heartbeat_exposes_stall_without_cancelling(
    tmp_path,
):
    monitor = PreviewDiagnostics(
        tmp_path / "preview.log",
        heartbeat_seconds=0.05,
    )

    def slow():
        time.sleep(0.13)
        return "completed"

    assert monitor.run(slow) == "completed"

    text = monitor.path.read_text(
        encoding="utf-8"
    )

    assert "RUNNING stage=" in text


@pytest.mark.parametrize(
    "value",
    [0, -1, 301, True, "5"],
)
def test_invalid_diagnostic_intervals_are_rejected(
    tmp_path,
    value,
):
    with pytest.raises(ValueError):
        PreviewDiagnostics(
            tmp_path / "preview.log",
            heartbeat_seconds=value,
        )
