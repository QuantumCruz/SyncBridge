
"""Friendly local computer names, independent of the network and Qt.

The device's cryptographic identity is not derived from its display name.
Renaming never changes keys, trust, shares, or synchronization history.
"""
from __future__ import annotations

import socket
from dataclasses import replace

from syncbridge.storage.config import ConfigStore

DEFAULT_DEVICE_NAME = "SyncBridge Device"


def validate_device_name(value: str) -> str:
    """Accept a printable, user-chosen label that fits pairing/discovery."""
    if not isinstance(value, str):
        raise ValueError("Computer name must be text")
    name = value.strip()
    try:
        encoded = name.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Computer name contains invalid characters") from exc
    if (
        not name
        or len(name) > 64
        or len(encoded) > 64
        or any(ord(char) < 32 or ord(char) == 127 for char in name)
    ):
        raise ValueError("Use a name of 1–64 printable characters")
    return name


def initialize_device_name(store: ConfigStore) -> str:
    """Use the Windows hostname once, but never override a custom name."""
    config = store.load()
    if config.device_name != DEFAULT_DEVICE_NAME:
        return config.device_name
    try:
        suggested = validate_device_name(socket.gethostname())
    except (OSError, ValueError):
        suggested = "My Computer"
    return store.save(replace(config, device_name=suggested)).device_name


def change_device_name(store: ConfigStore, name: str) -> str:
    """Persist a validated display name with ConfigStore's revision lock."""
    validated = validate_device_name(name)
    config = store.load()
    if config.device_name == validated:
        return validated
    return store.save(replace(config, device_name=validated)).device_name
