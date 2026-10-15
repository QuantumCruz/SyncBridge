
"""Persistent SyncBridge configuration tests, without changing the user's files."""

from __future__ import annotations

import json
import os
import threading
from dataclasses import replace
from uuid import uuid4

import pytest

from syncbridge.storage import config as module
from syncbridge.storage.config import (
    AppConfig, ConfigConflict, ConfigError, ConfigStore,
    ShareConfig, SyncPreferences,
)


def share(root, *, name="Work", **overrides):
    params = dict(
        share_id=uuid4().hex,
        peer_node_id=uuid4().hex,
        local_root=str(root),
        display_name=name,
        remote_host="127.0.0.1",
    )
    params.update(overrides)
    return ShareConfig(**params)


def test_missing_config_returns_conservative_defaults(tmp_path):
    store = ConfigStore(tmp_path / "new" / "settings.json")
    fresh = store.load()
    assert fresh == AppConfig()
    assert fresh.revision == 0
    assert fresh.shares == ()
    assert not SyncPreferences().auto_apply
    assert not store.path.exists()


def test_empty_config_save_then_reload_and_revision(tmp_path):
    store = ConfigStore(tmp_path / "settings.json")
    saved = store.save(store.load())
    assert saved.revision == 1
    assert store.load() == saved
    updated = store.save(replace(saved, device_name="New computer"))
    assert updated.revision == 2
    assert store.load() == updated


def test_enabled_share_and_scheduler_round_trip(tmp_path):
    root = tmp_path / "folder"
    root.mkdir()

    item = share(
        root,
        name="Résumé ✓",
        enabled=True,
        grant_manifest=True,
        grant_read=True,
        grant_write=False,
        grant_agreement=True,
        preferences=SyncPreferences(
            auto_apply=True,
            poll_interval=30,
            watch_interval=0.5,
            settle_delay=1.25,
            retry_initial=4,
            retry_max=90,
        ),
    )

    store = ConfigStore(tmp_path / "settings.json")
    saved = store.save(
        AppConfig(
            device_name="Laptop – Lagos",
            shares=(item,),
        )
    )

    assert store.load() == saved
    assert store.load().get_share(item.share_id) == item
    assert store.load().get_share(uuid4().hex) is None
    assert store.load().shares[0].preferences.auto_apply
    assert not store.load().shares[0].grant_write


def test_grants_are_denied_by_default(tmp_path):
    item = share(tmp_path / "share")
    assert not item.enabled
    assert not item.grant_manifest
    assert not item.grant_read
    assert not item.grant_write
    assert not item.grant_agreement
    assert not item.preferences.auto_apply


def test_config_has_no_secret_or_identity_private_key(tmp_path):
    item = share(tmp_path / "folder")
    store = ConfigStore(tmp_path / "settings.json")
    store.save(AppConfig(shares=(item,)))

    document = json.loads(
        store.path.read_text("utf-8")
    )

    assert document["shares"][0]["peer_node_id"] == item.peer_node_id
    assert "private_key" not in store.path.read_text("utf-8")
    assert "password" not in store.path.read_text("utf-8")
    assert "format_version" in document


def test_stale_saves_cannot_lose_edits(tmp_path):
    first = ConfigStore(tmp_path / "settings.json")
    second = ConfigStore(first.path)
    a, b = first.load(), second.load()

    latest = first.save(
        replace(a, device_name="Alice")
    )

    with pytest.raises(ConfigConflict, match="Stale"):
        second.save(
            replace(b, device_name="Bob")
        )

    assert second.load() == latest


def test_competing_writers_are_serialized(tmp_path):
    path = tmp_path / "settings.json"
    start = threading.Event()
    results = []
    guard = threading.Lock()

    def worker(i):
        store = ConfigStore(path)
        candidate = replace(
            store.load(),
            device_name=f"Computer-{i}",
        )

        start.wait()

        try:
            result = store.save(candidate)
        except ConfigConflict:
            result = "conflict"

        with guard:
            results.append(result)

    threads = [
        threading.Thread(target=worker, args=(i,))
        for i in range(12)
    ]

    for thread in threads:
        thread.start()

    start.set()

    for thread in threads:
        thread.join(4)
        assert not thread.is_alive()

    assert sum(
        isinstance(r, AppConfig)
        for r in results
    ) == 1

    assert results.count("conflict") == 11
    assert ConfigStore(path).load().revision == 1


@pytest.mark.parametrize("raw", [
    b"not JSON",
    b"{",
    b"null",
    b"[]",
    b"",
    b"\xff",
    b'{"format_version":1,"format_version":1,"revision":0,"device_name":"X","shares":[]}',
    b'{"format_version":1,"revision":0,"device_name":"X","shares":[],"secret":"x"}',
    b'{"format_version":1,"revision":0,"device_name":"X","shares":[],"bad":NaN}',
    b'{"format_version":999,"revision":0,"device_name":"X","shares":[]}',
])
def test_invalid_config_is_never_silently_reset(tmp_path, raw):
    path = tmp_path / "settings.json"
    path.write_bytes(raw)

    with pytest.raises(ConfigError):
        ConfigStore(path).load()

    assert path.read_bytes() == raw


def test_future_version_cannot_be_overwritten(tmp_path):
    path = tmp_path / "settings.json"

    path.write_text(json.dumps(dict(
        format_version=2,
        revision=0,
        device_name="X",
        shares=[],
    )))

    with pytest.raises(ConfigError, match="Unsupported"):
        ConfigStore(path).save(AppConfig())

    assert json.loads(
        path.read_text()
    )["format_version"] == 2


def test_oversize_config_rejected(tmp_path):
    path = tmp_path / "settings.json"
    path.write_bytes(
        b"x" * (module.MAX_CONFIG_BYTES + 1)
    )

    with pytest.raises(ConfigError, match="size"):
        ConfigStore(path).load()


def test_os_replace_failure_keeps_prior_config(tmp_path, monkeypatch):
    store = ConfigStore(tmp_path / "settings.json")
    previous = store.save(AppConfig())
    raw = store.path.read_bytes()

    def fail(*args):
        raise OSError("simulated crash during publication")

    monkeypatch.setattr(
        module.os,
        "replace",
        fail,
    )

    with pytest.raises(OSError, match="simulated"):
        store.save(
            replace(previous, device_name="Lost update")
        )

    assert store.path.read_bytes() == raw
    assert store.load() == previous
    assert list(
        tmp_path.glob(".settings.json.*.tmp")
    ) == []


@pytest.mark.parametrize("name", [
    "",
    "  ",
    "a\nB",
    "x" * 97,
    5,
])
def test_invalid_display_name_rejected(tmp_path, name):
    with pytest.raises(ConfigError):
        share(
            tmp_path / "a",
            name=name,
        )


@pytest.mark.parametrize("key,value", [
    ("peer_node_id", "INVALID"),
    ("share_id", "A" * 32),
    ("enabled", 1),
    ("grant_read", "yes"),
    ("grant_manifest", 1),
    ("grant_write", None),
    ("grant_agreement", 0),
    ("preferences", {}),
])
def test_invalid_share_fields_rejected(tmp_path, key, value):
    with pytest.raises(ConfigError):
        share(
            tmp_path / "a",
            **{key: value},
        )


@pytest.mark.parametrize("host", [
    "invalid",
    "0.0.0.0",
    "255.255.255.255",
    "224.0.0.1",
    "::1",
    123,
])
def test_invalid_hosts_rejected(tmp_path, host):
    with pytest.raises(ConfigError):
        share(
            tmp_path / "a",
            remote_host=host,
        )


@pytest.mark.parametrize("key,value", [
    ("manifest_port", 0),
    ("transfer_port", 65536),
    ("agreement_port", True),
    ("manifest_port", "45843"),
])
def test_invalid_ports_rejected(tmp_path, key, value):
    with pytest.raises(ConfigError):
        share(
            tmp_path / "a",
            **{key: value},
        )


def test_same_port_on_two_services_rejected(tmp_path):
    with pytest.raises(
        ConfigError,
        match="ports must differ",
    ):
        share(
            tmp_path / "a",
            agreement_port=45842,
        )


@pytest.mark.parametrize("key,value", [
    ("auto_apply", 1),
    ("poll_interval", 0),
    ("watch_interval", float("nan")),
    ("settle_delay", -1),
    ("retry_initial", -1),
    ("retry_max", float("inf")),
])
def test_invalid_preferences_rejected(key, value):
    with pytest.raises(ConfigError):
        SyncPreferences(**{key: value})


def test_retry_max_must_cover_initial():
    with pytest.raises(
        ConfigError,
        match="retry_max",
    ):
        SyncPreferences(
            retry_initial=20,
            retry_max=10,
        )


def test_duplicate_share_id_rejected(tmp_path):
    first = share(tmp_path / "one")
    second = share(
        tmp_path / "two",
        share_id=first.share_id,
    )

    with pytest.raises(
        ConfigError,
        match="Duplicate share_id",
    ):
        AppConfig(
            shares=(first, second),
        )


def test_nested_share_roots_rejected(tmp_path):
    first = share(tmp_path / "shared")
    second = share(
        tmp_path / "shared" / "nested"
    )

    with pytest.raises(
        ConfigError,
        match="overlap",
    ):
        AppConfig(
            shares=(first, second),
        )


def test_separate_folders_can_share_same_peer(tmp_path):
    peer = uuid4().hex

    first = share(
        tmp_path / "one",
        peer_node_id=peer,
    )

    second = share(
        tmp_path / "two",
        peer_node_id=peer,
    )

    assert len(
        AppConfig(shares=(first, second)).shares
    ) == 2


def test_missing_root_persisted_without_creating(tmp_path):
    root = tmp_path / "unmounted-folder"
    store = ConfigStore(
        tmp_path / "settings.json"
    )

    store.save(
        AppConfig(shares=(share(root),))
    )

    assert not root.exists()
    assert (
        store.load().shares[0].local_root
        == str(root)
    )


def test_file_is_not_accepted_as_local_folder(tmp_path):
    file = tmp_path / "file.txt"
    file.write_text("not a folder")

    with pytest.raises(
        ConfigError,
        match="directory",
    ):
        share(file)


def test_relative_directory_rejected():
    with pytest.raises(
        ConfigError,
        match="absolute",
    ):
        ShareConfig(
            uuid4().hex,
            uuid4().hex,
            "relative/path",
            "Bad root",
        )


def test_settings_cannot_live_inside_shared_folder(tmp_path):
    root = tmp_path / "shared"
    root.mkdir()

    store = ConfigStore(
        root / "settings.json"
    )

    with pytest.raises(
        ConfigError,
        match="outside synchronized folders",
    ):
        store.save(
            AppConfig(shares=(share(root),))
        )

    assert not store.path.exists()


def test_settings_symlink_refused(tmp_path):
    target = tmp_path / "target.json"
    target.write_text("private")
    link = tmp_path / "settings.json"

    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip(
            "Symbolic links require elevated Windows permission"
        )

    with pytest.raises(
        ConfigError,
        match="symbolic link",
    ):
        ConfigStore(link)


def test_unknown_share_field_refused_on_loading(tmp_path):
    path = tmp_path / "settings.json"

    raw = module._encode(
        AppConfig(
            shares=(share(tmp_path / "folder"),)
        )
    )

    doc = json.loads(raw)
    doc["shares"][0]["password"] = "should-not-be-here"

    path.write_text(
        json.dumps(doc)
    )

    with pytest.raises(
        ConfigError,
        match="share fields",
    ):
        ConfigStore(path).load()


def test_default_path_is_user_local_and_non_project(
    monkeypatch,
    tmp_path,
):
    if os.name == "nt":
        monkeypatch.setenv(
            "LOCALAPPDATA",
            str(tmp_path / "Local"),
        )

        assert module.default_config_path() == (
            tmp_path
            / "Local"
            / "SyncBridge"
            / "settings.json"
        )

    else:
        monkeypatch.setenv(
            "XDG_CONFIG_HOME",
            str(tmp_path / "custom"),
        )

        assert module.default_config_path() == (
            tmp_path
            / "custom"
            / "syncbridge"
            / "settings.json"
        )


def test_filesystem_root_cannot_be_shared():
    from pathlib import Path

    root = Path.cwd().anchor

    with pytest.raises(
        ConfigError,
        match="filesystem root",
    ):
        ShareConfig(
            uuid4().hex,
            uuid4().hex,
            root,
            "Dangerous",
        )


def test_invalid_unicode_names_are_rejected(tmp_path):
    with pytest.raises(
        ConfigError,
        match="Unicode",
    ):
        AppConfig(device_name="Bad \ud800 name")

    with pytest.raises(
        ConfigError,
        match="Unicode",
    ):
        share(
            tmp_path / "data",
            name="Bad \ud800 name",
        )
