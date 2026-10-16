"""Regression tests: Tk event pump survives errors and shutdown never blocks Tk."""
from __future__ import annotations

import queue
import threading
from types import SimpleNamespace

from syncbridge.ui import main_window


class FakeRoot:
    def __init__(self):
        self.calls = []
        self.destroyed = False

    def after(self, milliseconds, callback):
        self.calls.append((milliseconds, callback))

    def destroy(self):
        self.destroyed = True


class TextValue:
    def __init__(self):
        self.value = ""

    def set(self, value):
        self.value = value


def window():
    view = main_window.SyncBridgeWindow.__new__(main_window.SyncBridgeWindow)
    view.root = FakeRoot()
    view._events = queue.Queue()
    view._busy = False
    view._closing = False
    view._shutdown_started = False
    view._preview = None
    view._nearby = None
    view._folders = None
    view._presence = None
    view._pairing = None
    view._worker = None
    view.state = TextValue()
    view.summary = TextValue()
    view.progress = TextValue()
    view._buttons = lambda: None
    return view


def test_result_render_failure_does_not_kill_event_pump(monkeypatch):
    view = window()
    monkeypatch.setattr(main_window.messagebox, "showerror", lambda *a, **k: None)

    def broken(_label, _result):
        raise RuntimeError("broken UI formatter")

    view._busy = True
    view._display_result = broken
    view._events.put(("done", ("Synchronizing...", object())))
    view._drain()

    assert not view._busy
    assert "Preview again" in view.summary.value
    assert len(view.root.calls) == 1

    # The next completion is still processed; it doesn't vanish in a dead pump.
    received = []
    view._display_result = lambda label, result: received.append(label)
    view._events.put(("done", ("Checking both folders...", object())))
    view._drain()
    assert received == ["Checking both folders..."]
    assert len(view.root.calls) == 2


def test_preview_can_run_again_after_completed_sync():
    view = window()
    preview = SimpleNamespace(items=(), revision=4, requires_review=False)
    result = SimpleNamespace(
        complete=True, uploaded=("a.txt",), downloaded=("b.txt",),
        checkpoint=SimpleNamespace(baseline=SimpleNamespace(revision=4)),
    )
    view._busy = True
    view._events.put(("done", ("Synchronizing...", result)))
    view._drain()
    assert not view._busy
    assert view.state.value == "Synchronized"

    view._busy = True
    view._events.put(("done", ("Checking both folders...", preview)))
    view._show_rows = lambda rows: None
    view._drain()
    assert not view._busy
    assert view._preview is preview
    assert view.state.value == "Preview ready"


def test_close_returns_without_waiting_for_blocking_services():
    view = window()
    main_thread = threading.get_ident()
    calls = []
    gate = threading.Event()

    def blocked():
        calls.append(threading.get_ident())
        gate.wait(timeout=3)

    view.controller = SimpleNamespace(stop=blocked)
    view._folders = SimpleNamespace(
        controller=SimpleNamespace(stop=blocked), _outgoing=None, _worker=None
    )
    view._presence = SimpleNamespace(stop=blocked)
    view._pairing = SimpleNamespace(controller=SimpleNamespace(stop=blocked))
    view._nearby = SimpleNamespace(close=lambda: calls.append(threading.get_ident()))

    view._close()
    assert view._closing
    assert view._shutdown_started
    assert not view.root.destroyed
    assert calls[0] == main_thread  # nearby popup closes on Tk thread
    assert view._worker.daemon  # shutdown cannot hold Python hostage

    gate.set()
    view._worker.join(timeout=4)
    assert not view._worker.is_alive()
    view._drain()
    assert view.root.destroyed
    assert len(calls) == 5
    assert all(thread_id != main_thread for thread_id in calls[1:])


def test_shutdown_error_still_reports_and_allows_retry(monkeypatch):
    view = window()
    failures = []
    monkeypatch.setattr(
        main_window.messagebox, "showerror",
        lambda *a, **k: failures.append(True),
    )
    view.controller = SimpleNamespace(stop=lambda: (_ for _ in ()).throw(RuntimeError("stop failed")))
    view._close()
    view._worker.join(timeout=3)
    view._drain()
    assert failures
    assert not view._closing
    assert not view._shutdown_started
    assert not view.root.destroyed
