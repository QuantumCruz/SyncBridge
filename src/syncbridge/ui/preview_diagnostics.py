
"""Diagnostic timing for the real, read-only SyncBridge desktop preview.

The monitor invokes the normal preview unchanged. It records only stage names,
elapsed times, and exception classes in the local profile's diagnostic folder.
It never records paths, peer identifiers, manifest contents or credentials.
"""
from __future__ import annotations

import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, TypeVar

from syncbridge.ui.desktop_controller import DesktopController


_T = TypeVar("_T")

_STAGES = {
    (
        "syncbridge.core.scanner",
        "scan",
    ): "Scanning and hashing local files",
    (
        "syncbridge.network.manifest",
        "fetch",
    ): "Retrieving the other computer's file inventory",
    (
        "syncbridge.core.coordinator",
        "_check_baseline",
    ): "Checking shared folder history",
    (
        "syncbridge.core.conflicts",
        "plan",
    ): "Comparing file versions",
}


class PreviewDiagnostics:
    """Observe an existing preview without changing its behavior or result."""

    def __init__(
        self,
        path: str | Path,
        *,
        heartbeat_seconds: float = 5.0,
    ) -> None:
        if (
            type(heartbeat_seconds) not in (int, float)
            or not 0.05 <= heartbeat_seconds <= 300
        ):
            raise ValueError(
                "heartbeat_seconds must be between 0.05 and 300"
            )

        self.path = Path(path)
        self.heartbeat_seconds = float(heartbeat_seconds)
        self._write_lock = threading.Lock()

    def _write(self, message: str) -> None:
        """Diagnostics must not make a working preview fail."""
        try:
            with self._write_lock:
                self.path.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                if (
                    self.path.is_file()
                    and self.path.stat().st_size > 512_000
                ):
                    self.path.replace(
                        self.path.with_suffix(".previous.log")
                    )

                stamp = datetime.now(
                    timezone.utc
                ).isoformat(timespec="seconds")

                with self.path.open(
                    "a",
                    encoding="utf-8",
                ) as stream:
                    stream.write(
                        f"{stamp} {message}\n"
                    )

        except OSError:
            # Missing disk permissions or a full disk must never
            # change the outcome of an ordinary preview.
            pass

    def run(self, action: Callable[[], _T]) -> _T:
        """Trace only the calling thread and preserve the action's result."""
        if not callable(action):
            raise TypeError("action must be callable")

        started = time.perf_counter()
        state = ["Preparing read-only preview", started]

        observed: list[tuple[str, float]] = []
        frames: list[tuple[object, str, float]] = []
        stopped = threading.Event()

        def trace(frame, event, _arg) -> None:
            if event == "call":
                label = _STAGES.get(
                    (
                        frame.f_globals.get("__name__"),
                        frame.f_code.co_name,
                    )
                )

                if label is not None:
                    moment = time.perf_counter()
                    frames.append((frame, label, moment))
                    state[0] = label
                    state[1] = moment

            elif (
                event == "return"
                and frames
                and frames[-1][0] is frame
            ):
                _, label, stage_started = frames.pop()
                moment = time.perf_counter()

                observed.append(
                    (label, moment - stage_started)
                )

                if frames:
                    state[0] = frames[-1][1]
                    state[1] = frames[-1][2]
                else:
                    state[0] = "Finalizing preview"
                    state[1] = moment

        def watch() -> None:
            while not stopped.wait(
                self.heartbeat_seconds
            ):
                moment = time.perf_counter()

                self._write(
                    "RUNNING stage="
                    + str(state[0])
                    + f" stage_seconds={moment - float(state[1]):.2f}"
                    + f" total_seconds={moment - started:.2f}"
                )

        self._write("START read-only preview")

        watcher = threading.Thread(
            target=watch,
            name="SyncBridgePreviewDiagnostics",
            daemon=True,
        )
        watcher.start()

        old_trace = sys.getprofile()

        try:
            sys.setprofile(trace)

            try:
                return action()

            except BaseException as exc:
                self._write(
                    f"FAILED stage={state[0]}"
                    f" exception={type(exc).__name__}"
                    f" total_seconds="
                    f"{time.perf_counter() - started:.2f}"
                )
                raise

            finally:
                sys.setprofile(old_trace)

        finally:
            stopped.set()
            watcher.join(timeout=1.0)

            for label, duration in observed:
                self._write(
                    f"STAGE {label} seconds={duration:.2f}"
                )

            self._write(
                "END total_seconds="
                f"{time.perf_counter() - started:.2f}"
            )


class DiagnosticDesktopController(DesktopController):
    """Preserve the guarded controller while observing its previews."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.preview_diagnostics = PreviewDiagnostics(
            self.store.path.parent
            / "diagnostics"
            / "preview.log"
        )

    def preview(self):
        return self.preview_diagnostics.run(
            super().preview
        )
