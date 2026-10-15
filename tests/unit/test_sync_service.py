
"""Deterministic background scheduling tests; network operations are mocked.

The existing lifecycle integration tests cover authenticated file transfers.
These tests focus on worker serialization, wakeups, cancellation and retry.
"""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from syncbridge.core.lifecycle import LifecycleStatus, SyncLifecycle
from syncbridge.core.sync_service import AutoSyncService, ServiceState


def until(predicate, *, timeout=2.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    assert predicate(), "Background worker did not reach expected state"


def outcome(status=LifecycleStatus.PREVIEW):
    return SimpleNamespace(status=status)


def make(tmp_path, method=None, **options):
    lifecycle = Mock(spec=SyncLifecycle)
    lifecycle.coordinator = SimpleNamespace(root=tmp_path)
    lifecycle.run_once.side_effect = method or (lambda **_: outcome())
    configuration = dict(
        poll_interval=0.15,
        watch_interval=0.02,
        settle_delay=0.06,
        retry_initial=0.03,
        retry_max=0.08,
        watch_local=False,
    )
    configuration.update(options)
    service = AutoSyncService(lifecycle, **configuration)
    return service, lifecycle


def test_default_mode_is_read_only_and_runs_immediately(tmp_path):
    calls = []
    def cycle(**kwargs):
        calls.append(kwargs)
        return outcome()
    service, _ = make(tmp_path, cycle, poll_interval=30)
    try:
        service.start()
        until(lambda: len(calls) == 1)
        assert calls[0]["apply"] is False
        assert isinstance(calls[0]["cancel_event"], threading.Event)
        assert service.status.state is ServiceState.RUNNING
    finally:
        service.stop()
    assert service.status.state is ServiceState.STOPPED


def test_opt_in_apply_mode(tmp_path):
    calls = []
    service, _ = make(tmp_path, lambda **kw: (calls.append(kw), outcome(LifecycleStatus.COMMITTED))[1],
                      auto_apply=True, poll_interval=30)
    try:
        service.start()
        until(lambda: len(calls) == 1)
        assert calls[0]["apply"] is True
    finally:
        service.stop()


def test_periodic_poll_detects_remote_only_changes(tmp_path):
    runs = []
    service, _ = make(tmp_path, lambda **_: (runs.append(time.monotonic()), outcome())[1],
                      poll_interval=0.05)
    try:
        service.start()
        until(lambda: len(runs) >= 3)
        assert runs[2] > runs[0]
    finally:
        service.stop()


def test_manual_request_wakes_early(tmp_path):
    runs = []
    service, _ = make(tmp_path, lambda **_: (runs.append(1), outcome())[1], poll_interval=30)
    try:
        service.start()
        until(lambda: len(runs) == 1)
        service.request_sync()
        until(lambda: len(runs) == 2)
    finally:
        service.stop()


def test_local_watcher_wakes_and_debounces(tmp_path, monkeypatch):
    from syncbridge.core import sync_service as module
    instances = []
    class FakeWatcher:
        def __init__(self, root, on_change, *, interval, on_error):
            self.on_change = on_change
            self.on_error = on_error
            self.polls = 0
            self.started = False
            self.stopped = False
            instances.append(self)
        def poll_once(self):
            self.polls += 1
        def start(self):
            self.started = True
        def stop(self):
            self.stopped = True
    monkeypatch.setattr(module, "FileWatcher", FakeWatcher)
    runs = []
    service, _ = make(tmp_path, lambda **_: (runs.append(time.monotonic()), outcome())[1],
                      watch_local=True, poll_interval=30, settle_delay=0.10)
    try:
        service.start()
        until(lambda: len(runs) == 1)
        assert instances[0].polls == 1 and instances[0].started
        started = time.monotonic()
        instances[0].on_change(object())
        until(lambda: len(runs) == 2)
        assert runs[1] - started >= 0.075
    finally:
        service.stop()
    assert instances[0].stopped


def test_transient_failures_back_off_and_recover(tmp_path):
    runs = []
    errors = []
    def cycle(**_):
        runs.append(time.monotonic())
        if len(runs) <= 2:
            raise ConnectionError("peer offline")
        return outcome(LifecycleStatus.COMMITTED)
    service, _ = make(tmp_path, cycle, poll_interval=30, on_error=errors.append)
    try:
        service.start()
        until(lambda: service.status.state is ServiceState.RETRYING)
        until(lambda: len(runs) >= 3)
        until(lambda: service.status.state is ServiceState.RUNNING)
        assert len(errors) == 2
        assert runs[1] - runs[0] >= 0.02
        assert runs[2] - runs[1] >= 0.045
        assert service.status.failures == 0
        assert service.status.last_error is None
    finally:
        service.stop()


def test_review_required_is_reported_not_auto_resolved(tmp_path):
    service, _ = make(tmp_path, lambda **_: outcome(LifecycleStatus.NEEDS_REVIEW),
                      auto_apply=True, poll_interval=30)
    try:
        service.start()
        until(lambda: service.status.state is ServiceState.NEEDS_REVIEW)
        assert service.status.requires_review
    finally:
        service.stop()


def test_pause_cancels_active_cycle_then_resume(tmp_path):
    entered = threading.Event()
    finished = threading.Event()
    runs = []
    def cycle(*, cancel_event, **_):
        runs.append(1)
        if len(runs) == 1:
            entered.set()
            assert cancel_event.wait(2)
            finished.set()
            return outcome(LifecycleStatus.PAUSED)
        return outcome()
    service, _ = make(tmp_path, cycle, poll_interval=30)
    try:
        service.start()
        assert entered.wait(2)
        service.pause()
        assert finished.wait(2)
        until(lambda: service.status.state is ServiceState.PAUSED)
        before = len(runs)
        time.sleep(0.07)
        assert len(runs) == before
        service.resume()
        until(lambda: len(runs) == 2)
    finally:
        service.stop()


def test_stop_cancels_inflight_without_deadlock(tmp_path):
    entered = threading.Event()
    def cycle(*, cancel_event, **_):
        entered.set()
        assert cancel_event.wait(2)
        return outcome(LifecycleStatus.PAUSED)
    service, _ = make(tmp_path, cycle)
    service.start()
    assert entered.wait(2)
    service.stop(timeout=2)
    until(lambda: service.status.state is ServiceState.STOPPED)
    assert not service.is_running


def test_stop_from_result_callback_is_safe(tmp_path):
    holder = {}
    finished = threading.Event()
    def on_result(_):
        holder['service'].stop()
        finished.set()
    service, _ = make(tmp_path, poll_interval=30, on_result=on_result)
    holder['service'] = service
    service.start()
    assert finished.wait(2)
    until(lambda: service.status.state is ServiceState.STOPPED)
    assert not service.is_running


def test_callbacks_cannot_kill_worker(tmp_path):
    count = []
    def broken(_):
        raise RuntimeError("UI listener broke")
    service, _ = make(tmp_path, lambda **_: (count.append(1), outcome())[1],
                      poll_interval=0.04, on_result=broken, on_status=broken)
    try:
        service.start()
        until(lambda: len(count) >= 3)
        assert service.is_running
    finally:
        service.stop()


def test_duplicate_start_does_not_spawn_second_worker(tmp_path):
    count = []
    service, _ = make(tmp_path, lambda **_: (count.append(1), outcome())[1], poll_interval=30)
    try:
        service.start()
        service.start()
        until(lambda: len(count) == 1)
        assert len(count) == 1
    finally:
        service.stop()


def test_restart_after_stop(tmp_path):
    count = []
    service, _ = make(tmp_path, lambda **_: (count.append(1), outcome())[1], poll_interval=30)
    service.start()
    until(lambda: len(count) == 1)
    service.stop()
    service.start()
    try:
        until(lambda: len(count) == 2)
    finally:
        service.stop()


def test_worker_never_overlaps_cycles(tmp_path):
    active = 0
    maximum = 0
    counter = []
    mutex = threading.Lock()
    def cycle(**_):
        nonlocal active, maximum
        with mutex:
            active += 1
            maximum = max(maximum, active)
        time.sleep(0.04)
        with mutex:
            active -= 1
            counter.append(1)
        return outcome()
    service, _ = make(tmp_path, cycle, poll_interval=0.02)
    try:
        service.start()
        for _ in range(10):
            service.request_sync()
        until(lambda: len(counter) >= 3)
        assert maximum == 1
    finally:
        service.stop()


def test_status_and_progress_are_forwarded(tmp_path):
    events = []
    progresses = []
    reports = []
    def cycle(*, on_progress, **_):
        on_progress('64KiB')
        return outcome(LifecycleStatus.COMMITTED)
    service, _ = make(tmp_path, cycle, poll_interval=30, on_status=events.append,
                      on_result=reports.append, on_progress=progresses.append)
    try:
        service.start()
        until(lambda: len(reports) == 1)
        assert progresses == ['64KiB']
        assert any(x.state is ServiceState.RUNNING for x in events)
    finally:
        service.stop()


def test_invalid_configuration_rejected(tmp_path):
    lifecycle = Mock(spec=SyncLifecycle)
    lifecycle.coordinator = SimpleNamespace(root=tmp_path)
    with pytest.raises(TypeError):
        AutoSyncService(object())
    for key, bad in (("poll_interval", 0), ("retry_initial", -1),
                     ("settle_delay", float('nan')), ("retry_max", float('inf')),
                     ("watch_interval", True)):
        with pytest.raises(ValueError):
            AutoSyncService(lifecycle, **{key: bad})
    with pytest.raises(ValueError):
        AutoSyncService(lifecycle, retry_initial=10, retry_max=2)
    with pytest.raises(TypeError):
        AutoSyncService(lifecycle, auto_apply='yes')
    with pytest.raises(TypeError):
        AutoSyncService(lifecycle, on_result='bad')


def test_stop_rejects_invalid_timeout(tmp_path):
    service, _ = make(tmp_path)
    for bad in (-1, float('nan'), True):
        with pytest.raises(ValueError):
            service.stop(timeout=bad)


def test_watch_error_reports_without_marking_cycle_failed(tmp_path, monkeypatch):
    from syncbridge.core import sync_service as module
    watches = []
    class BrokenScanWatch:
        def __init__(self, root, on_change, *, interval, on_error):
            self.on_error = on_error
            watches.append(self)
        def poll_once(self):
            self.on_error(RuntimeError('watch scan temporarily incomplete'))
        def start(self):
            pass
        def stop(self):
            pass
    monkeypatch.setattr(module, "FileWatcher", BrokenScanWatch)
    errors = []
    service, _ = make(tmp_path, watch_local=True, poll_interval=30, on_error=errors.append)
    try:
        service.start()
        until(lambda: service.status.state is ServiceState.RUNNING)
        assert len(errors) == 1
        assert service.status.failures == 0
    finally:
        service.stop()
