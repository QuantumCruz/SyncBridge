
"""Presentation-only regression tests for the simpler SyncBridge desktop.

These tests do not open windows or transfer data. The guarded runtime and
existing integration tests still verify real file operations.
"""
from __future__ import annotations

from types import SimpleNamespace

from syncbridge.ui import main_window


class FakeButton:
    def __init__(self):
        self.text = ""
        self.packed = False

    def configure(self, **options):
        if "text" in options:
            self.text = options["text"]

    def pack(self, **options):
        self.packed = True

    def pack_forget(self):
        self.packed = False


def test_connection_options_are_hidden_until_requested():
    window = main_window.SyncBridgeWindow.__new__(
        main_window.SyncBridgeWindow
    )
    window._advanced_visible = False
    window._changes_card = FakeButton()
    window.advanced_controls = FakeButton()
    window.advanced_button = FakeButton()

    window._toggle_advanced()
    assert window._advanced_visible
    assert window.advanced_controls.packed
    assert "▴" in window.advanced_button.text

    window._toggle_advanced()
    assert not window._advanced_visible
    assert not window.advanced_controls.packed
    assert "▾" in window.advanced_button.text


def test_sync_confirmation_says_how_many_files_will_change(monkeypatch):
    view = main_window.SyncBridgeWindow.__new__(
        main_window.SyncBridgeWindow
    )
    view.root = object()
    view._preview = SimpleNamespace(
        items=(object(), object()),
        requires_review=False,
    )
    view.controller = SimpleNamespace(
        profile=lambda: SimpleNamespace(
            folder_name="Demo documents"
        ),
        sync_once=lambda **_: None,
    )
    view._show_rows = lambda *_: None
    started = []
    view._run = lambda name, callback: started.append(name)
    confirmations = []

    def confirm(_title, message, **kwargs):
        confirmations.append(message)
        return False

    monkeypatch.setattr(
        main_window.messagebox, "askyesno", confirm
    )
    view._request_sync()

    assert len(confirmations) == 1
    assert "Demo documents" in confirmations[0]
    assert "Files to update: 2" in confirmations[0]
    assert started == []
    assert view._preview is not None


def test_large_sync_requires_confirmation_and_displays_warning(
    monkeypatch,
):
    view = main_window.SyncBridgeWindow.__new__(
        main_window.SyncBridgeWindow
    )
    view.root = object()
    view._preview = SimpleNamespace(
        items=tuple(range(50)),
        requires_review=False,
    )
    view.controller = SimpleNamespace(
        profile=lambda: SimpleNamespace(folder_name="Demo"),
        sync_once=lambda **_: None,
    )
    view._show_rows = lambda *_: None
    started = []
    view._run = lambda name, callback: started.append(name)
    captured = []

    def confirm(_title, message, **kwargs):
        captured.append(message)
        return True

    monkeypatch.setattr(
        main_window.messagebox, "askyesno", confirm
    )
    view._request_sync()

    assert "Files to update: 50" in captured[0]
    assert "large change list" in captured[0]
    assert started == ["Synchronizing..."]
    assert view._preview is None


def test_unreviewed_conflicts_never_start_sync(monkeypatch):
    view = main_window.SyncBridgeWindow.__new__(
        main_window.SyncBridgeWindow
    )
    view._preview = SimpleNamespace(
        items=(object(),),
        requires_review=True,
    )
    started = []
    view._run = lambda *args: started.append(args)

    monkeypatch.setattr(
        main_window.messagebox,
        "askyesno",
        lambda *args, **kwargs: (
            _ for _ in ()
        ).throw(AssertionError("Unexpected confirmation")),
    )

    view._request_sync()
    assert not started
