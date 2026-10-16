
"""Read-only progress estimates for a reviewed manual SyncBridge transfer.

The preview supplies expected file sizes; TransferProgress supplies transferred
bytes for individual files. Completion is NEVER inferred from reaching 100%:
SyncBridge still verifies inventories and commits the shared baseline afterward.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import time
from typing import Iterable


@dataclass(frozen=True, slots=True)
class TransferSnapshot:
    path: str
    direction: str
    file_number: int
    planned_files: int
    file_bytes: int
    file_size: int
    planned_bytes: int | None
    reported_bytes: int
    speed_bps: float | None
    data_eta_seconds: float | None
    verifying: bool

    @property
    def file_percent(self) -> int:
        return 100 if self.file_size == 0 else int(
            100 * self.file_bytes / self.file_size
        )

    @property
    def overall_percent(self) -> int | None:
        if self.planned_bytes is None:
            return None
        if self.planned_bytes == 0:
            return 100 if self.verifying else 0
        return min(
            100,
            int(100 * self.reported_bytes / self.planned_bytes),
        )


class TransferOverview:
    """Track UI-only byte estimates, without filesystem or network access."""

    def __init__(self, preview_items: Iterable[object]) -> None:
        items = tuple(
            item
            for item in preview_items
            if item.action in ("Send", "Receive")
        )

        self.planned_files = len(items)
        self._expected: dict[tuple[str, str], int] = {}
        sizes_known = True

        for item in items:
            key = (
                "send" if item.action == "Send" else "receive",
                item.path,
            )
            size = getattr(item, "size", None)

            if (
                type(size) is not int
                or size < 0
                or key in self._expected
            ):
                sizes_known = False
            else:
                self._expected[key] = size

        self._sizes_known = sizes_known
        self._reported: dict[tuple[str, str], int] = {}
        self._actual_total: dict[tuple[str, str], int] = {}
        self._started: set[tuple[str, str]] = set()
        self._samples: deque[tuple[float, int]] = deque()
        self._moved = 0
        self._last_transfer: dict[tuple[str, str], int] = {}

    def update(
        self,
        event: object,
        *,
        now: float | None = None,
    ) -> TransferSnapshot:
        timestamp = time.monotonic() if now is None else float(now)

        key = (
            str(event.direction).lower(),
            str(event.path),
        )

        total = max(0, int(event.total))
        transferred = max(
            0,
            min(total, int(event.transferred)),
        )

        if key not in self._started:
            self._started.add(key)

            # Resumed transfers can begin with previously received bytes.
            # Count them toward file progress but not measured speed.
            self._last_transfer[key] = transferred
        else:
            old = self._last_transfer[key]
            self._moved += max(0, transferred - old)
            self._last_transfer[key] = max(old, transferred)

        self._actual_total[key] = total
        self._reported[key] = max(
            transferred,
            self._reported.get(key, 0),
        )

        self._samples.append((timestamp, self._moved))

        while (
            len(self._samples) > 1
            and timestamp - self._samples[0][0] > 5.0
        ):
            self._samples.popleft()

        speed = None

        if len(self._samples) >= 2:
            elapsed = timestamp - self._samples[0][0]
            delta = self._moved - self._samples[0][1]

            if elapsed >= 1.0 and delta > 0:
                speed = delta / elapsed

        known = self._sizes_known and all(
            key in self._expected
            and self._expected[key] == size
            for key, size in self._actual_total.items()
        )

        expected = (
            sum(self._expected.values())
            if known else None
        )

        reported = (
            sum(
                min(self._reported.get(key, 0), size)
                for key, size in self._expected.items()
            )
            if known else 0
        )

        verifying = bool(
            known
            and len(self._expected) == self.planned_files
            and self._expected
            and all(
                self._reported.get(key, -1) >= size
                for key, size in self._expected.items()
            )
        )

        remaining = (
            max(0, expected - reported)
            if expected is not None else None
        )

        eta = (
            remaining / speed
            if remaining is not None and speed
            else None
        )

        return TransferSnapshot(
            path=key[1],
            direction=key[0],
            file_number=len(self._started),
            planned_files=self.planned_files,
            file_bytes=self._reported[key],
            file_size=total,
            planned_bytes=expected,
            reported_bytes=reported,
            speed_bps=speed,
            data_eta_seconds=eta,
            verifying=verifying,
        )
