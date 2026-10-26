
"""Persistent, human-readable device labels never alter pairing credentials."""
from __future__ import annotations

from dataclasses import replace

import pytest

from syncbridge.storage.config import ConfigStore
from syncbridge.ui.device_names import (
    change_device_name,
    initialize_device_name,
    validate_device_name,
)


def test_new_profile_uses_windows_computer_name(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "syncbridge.ui.device_names.socket.gethostname",
        lambda: "FRIENDS-LAPTOP",
    )
    store = ConfigStore(tmp_path / "settings.json")
    assert initialize_device_name(store) == "FRIENDS-LAPTOP"
    assert store.load().device_name == "FRIENDS-LAPTOP"
    first_revision = store.load().revision
    assert initialize_device_name(store) == "FRIENDS-LAPTOP"
    assert store.load().revision == first_revision


def test_existing_name_is_never_overwritten(tmp_path, monkeypatch):
    store = ConfigStore(tmp_path / "settings.json")
    store.save(replace(store.load(), device_name="Alice's PC"))
    monkeypatch.setattr(
        "syncbridge.ui.device_names.socket.gethostname",
        lambda: "OTHER-NAME",
    )
    assert initialize_device_name(store) == "Alice's PC"
    assert store.load().device_name == "Alice's PC"


def test_renaming_keeps_existing_configuration(tmp_path):
    store = ConfigStore(tmp_path / "settings.json")
    original = store.load()
    store.save(replace(original, device_name="Original"))
    assert change_device_name(store, "  Bob's Laptop  ") == "Bob's Laptop"
    after = store.load()
    assert after.device_name == "Bob's Laptop"
    assert after.shares == original.shares
    assert after.revision == 2


@pytest.mark.parametrize(
    "invalid",
    ["", "   ", "bad\nname", "X" * 65, "\ud800"],
)
def test_rejects_invalid_computer_names(invalid):
    with pytest.raises(ValueError):
        validate_device_name(invalid)
