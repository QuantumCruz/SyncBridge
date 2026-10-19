
"""Measure the cost of real, authenticated SyncBridge desktop synchronization.

Standalone Windows benchmark; runs only against disposable loopback peers.
No production code is modified and no user profile is read.

Example:
    python scripts/benchmark_sync_scaling.py --files-per-side 8 --delay 0.465
"""
from __future__ import annotations

import argparse
import multiprocessing as mp
import os
import queue
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path


TESTS = Path(__file__).resolve().parents[1] / "tests" / "integration"
sys.path.insert(0, str(TESTS))


def _instrumented_alice(
    profile,
    ports,
    lock_port,
    validation_port,
    delay,
    ready,
    messages,
):
    from syncbridge.core.coordinator import SyncCoordinator
    import test_delayed_desktop_sync as desktop_test

    original_scan = SyncCoordinator._scan
    original_fetch = SyncCoordinator._fetch

    def scan(self):
        started = time.perf_counter()
        try:
            return original_scan(self)
        finally:
            messages.put((
                "metric",
                "Alice local full scan",
                time.perf_counter() - started,
            ))

    def fetch(self):
        started = time.perf_counter()
        try:
            return original_fetch(self)
        finally:
            messages.put((
                "metric",
                "Alice remote manifest",
                time.perf_counter() - started,
            ))

    SyncCoordinator._scan = scan
    SyncCoordinator._fetch = fetch

    desktop_test.DELAY_SECONDS = delay

    desktop_test._alice_desktop(
        profile,
        ports,
        lock_port,
        validation_port,
        ready,
        messages,
    )


def _instrumented_bob(
    profile,
    ports,
    lock_port,
    validation_port,
    ready,
    checkpoint,
    messages,
):
    from syncbridge.core.scanner import FileScanner
    from test_desktop_crash_resume import _desktop_child

    original_scan = FileScanner.scan

    def scan(self):
        started = time.perf_counter()
        try:
            return original_scan(self)
        finally:
            messages.put((
                "metric",
                "Bob full filesystem scan",
                time.perf_counter() - started,
            ))

    FileScanner.scan = scan

    _desktop_child(
        profile,
        ports,
        lock_port,
        validation_port,
        "serve",
        0,
        ready,
        checkpoint,
        messages,
    )


def _hashes(root):
    from test_desktop_crash_resume import _hash

    return {
        file.relative_to(root).as_posix(): _hash(file)
        for file in root.rglob("*")
        if file.is_file()
    }


def run(files_per_side: int, delay: float) -> None:
    if sys.platform != "win32":
        raise SystemExit(
            "This Qt integration benchmark runs on Windows."
        )

    if not 1 <= files_per_side <= 20:
        raise SystemExit(
            "--files-per-side must be between 1 and 20."
        )

    if not 0 <= delay <= 1:
        raise SystemExit(
            "--delay must be between 0 and 1 second."
        )

    from test_desktop_crash_resume import (
        MIB,
        _configure,
        _terminate,
    )

    with tempfile.TemporaryDirectory(
        prefix="syncbridge-benchmark-"
    ) as folder:
        (
            profiles,
            roots,
            listeners,
            lock,
            validation,
            _source,
        ) = _configure(
            Path(folder),
            size=8 * MIB,
        )

        for side in ("Alice", "Bob"):
            for number in range(files_per_side):
                destination = (
                    roots[side]
                    / side.lower()
                    / f"file-{number:03d}.bin"
                )
                destination.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )
                destination.write_bytes(
                    os.urandom(16 * 1024)
                )

        before_alice = _hashes(roots["Alice"])
        before_bob = _hashes(roots["Bob"])
        expected = before_alice | before_bob

        assert len(expected) == 2 * files_per_side + 1

        ctx = mp.get_context("spawn")
        messages = ctx.Queue()
        bob_ready = ctx.Event()
        alice_ready = ctx.Event()
        checkpoint = ctx.Event()

        children = []
        metrics = defaultdict(list)
        seen = Counter()
        failures = []
        started = time.perf_counter()

        try:
            bob = ctx.Process(
                target=_instrumented_bob,
                args=(
                    str(profiles["Bob"]),
                    tuple(listeners["Bob"]),
                    lock,
                    validation,
                    bob_ready,
                    checkpoint,
                    messages,
                ),
                name="Benchmark-Bob",
            )
            bob.start()
            children.append(bob)

            if not bob_ready.wait(timeout=30):
                raise RuntimeError("Bob failed to start")

            alice = ctx.Process(
                target=_instrumented_alice,
                args=(
                    str(profiles["Alice"]),
                    tuple(listeners["Alice"]),
                    lock,
                    validation,
                    delay,
                    alice_ready,
                    messages,
                ),
                name="Benchmark-Alice",
            )
            alice.start()
            children.append(alice)

            if not alice_ready.wait(timeout=30):
                raise RuntimeError("Alice failed to start")

            deadline = time.monotonic() + 165

            while time.monotonic() < deadline:
                try:
                    event = messages.get(timeout=0.5)
                except queue.Empty:
                    if any(
                        child.exitcode is not None
                        for child in children
                    ):
                        raise RuntimeError(
                            "A desktop process exited unexpectedly"
                        )
                    continue

                kind = event[0]

                if kind == "metric":
                    metrics[event[1]].append(event[2])

                elif kind in {
                    "preview-result",
                    "sync-result",
                    "gui-sync",
                    "receiver-view-updated",
                }:
                    seen[kind] += 1
                    print(
                        f"{kind}: {event[1:]}",
                        flush=True,
                    )

                    if kind == "preview-result" and (
                        event[1] != len(expected)
                        or event[2]
                        or not event[3]
                    ):
                        failures.append(
                            f"Unexpected preview: {event!r}"
                        )

                    if (
                        kind == "sync-result"
                        and not event[1]
                    ):
                        failures.append(
                            f"Incomplete synchronization: {event!r}"
                        )

                    if (
                        kind == "gui-sync"
                        and event[1] != "Synchronized"
                    ):
                        failures.append(
                            f"Unexpected GUI result: {event!r}"
                        )

                elif kind in {
                    "alice-exception",
                    "alice-timeout",
                    "qt-warning",
                    "child-exception",
                    "child-timeout",
                    "sync-error",
                    "unexpected-empty-preview",
                }:
                    failures.append(repr(event))
                    break

                if all(
                    seen[label]
                    for label in (
                        "preview-result",
                        "sync-result",
                        "gui-sync",
                        "receiver-view-updated",
                    )
                ):
                    break

            elapsed = time.perf_counter() - started

            # Collect any final metric events that arrived just
            # behind the GUI completion messages.
            time.sleep(0.15)

            while True:
                try:
                    event = messages.get_nowait()
                except queue.Empty:
                    break

                if event[0] == "metric":
                    metrics[event[1]].append(event[2])
                elif event[0] in {
                    "qt-warning",
                    "sync-error",
                    "alice-exception",
                    "child-exception",
                }:
                    failures.append(repr(event))

            if failures:
                raise RuntimeError(
                    "; ".join(failures)
                )

            for label in (
                "preview-result",
                "sync-result",
                "gui-sync",
                "receiver-view-updated",
            ):
                if not seen[label]:
                    raise RuntimeError(
                        f"Missing completion event: {label}"
                    )

            for side in ("Alice", "Bob"):
                if _hashes(roots[side]) != expected:
                    raise AssertionError(
                        f"{side} file hashes differ "
                        "after synchronization"
                    )

            print(
                f"\nVerified: {len(expected)} "
                "identical files on both peers"
            )
            print(
                f"Elapsed: {elapsed:.2f}s "
                f"| Artificial delay: {delay:.3f}s "
                "per Alice manifest fetch"
            )

            for label in sorted(metrics):
                times = metrics[label]
                print(
                    f"{label}: {len(times)} calls, "
                    f"cumulative {sum(times):.2f}s"
                )

            print(
                "All SHA-256 hashes match; benchmark PASS"
            )

        finally:
            for child in reversed(children):
                _terminate(child)
                child.close()

            messages.close()
            messages.join_thread()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__
    )
    parser.add_argument(
        "--files-per-side",
        type=int,
        default=8,
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.465,
    )
    options = parser.parse_args()

    run(
        options.files_per_side,
        options.delay,
    )


if __name__ == "__main__":
    mp.freeze_support()
    main()
