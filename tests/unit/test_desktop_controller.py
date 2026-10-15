
"""Headless checks for the desktop's real guarded-runtime adapter."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from syncbridge.core.conflicts import SyncAction
from syncbridge.storage.config import (
    AppConfig,
    ConfigStore,
    ShareConfig,
    SyncPreferences,
)
from syncbridge.ui.desktop_controller import (
    DesktopConfigurationError,
    DesktopController,
    describe_preview,
)


class FakeRuntime:
    def __init__(self, store, **settings):
        self.store = store
        self.settings = settings
        self.active = False
        self.start_args = []
        self.sync_calls = 0
        self.preview_calls = 0
        self.returned = object()

    @property
    def status(self):
        return SimpleNamespace(
            running=self.active
        )

    def start(self, *, background):
        self.start_args.append(background)
        self.active = True

    def stop(self):
        self.active = False

    def preview(self):
        self.preview_calls += 1
        return sample_preview(
            SyncAction.UPLOAD
        )

    def sync_once(self, *, on_progress=None):
        self.sync_calls += 1

        if on_progress is not None:
            on_progress("made progress")

        return self.returned


def sample_preview(action):
    decision = SimpleNamespace(
        path="notes.txt",
        action=action,
    )
    plan = SimpleNamespace(
        decisions=(decision,)
    )

    return SimpleNamespace(
        preview=SimpleNamespace(
            plan=plan,
            baseline_revision=4,
        )
    )


@pytest.fixture
def setup(tmp_path):
    local = tmp_path / "Shared"
    local.mkdir()

    store = ConfigStore(
        tmp_path / "Profile" / "settings.json"
    )

    share = ShareConfig(
        share_id=uuid4().hex,
        peer_node_id=uuid4().hex,
        local_root=str(local),
        display_name="Project files",
        remote_host="127.0.0.1",
        enabled=True,
    )

    store.save(
        AppConfig(
            device_name="Alice",
            shares=(share,),
        )
    )

    return store, share


def test_configured_profile_is_loaded_without_starting_runtime(setup):
    store, share = setup

    desktop = DesktopController(
        store,
        runtime_factory=FakeRuntime,
    )

    info = desktop.profile()

    assert info.device_name == "Alice"
    assert info.folder_name == "Project files"
    assert info.local_root == Path(
        share.local_root
    )
    assert not desktop.running
    assert desktop.runtime.start_args == []


def test_unconfigured_profile_is_not_automatically_paired(tmp_path):
    desktop = DesktopController(
        ConfigStore(
            tmp_path / "settings.json"
        ),
        runtime_factory=FakeRuntime,
    )

    with pytest.raises(
        DesktopConfigurationError,
        match="exactly one",
    ):
        desktop.start()

    assert desktop.runtime.start_args == []


def test_start_uses_manual_mode_only_and_stop_is_explicit(setup):
    desktop = DesktopController(
        setup[0],
        runtime_factory=FakeRuntime,
    )

    desktop.start()

    assert desktop.runtime.start_args == [False]
    assert desktop.running

    desktop.stop()

    assert not desktop.running


def test_preview_is_read_only_and_sync_explicit(setup):
    desktop = DesktopController(
        setup[0],
        runtime_factory=FakeRuntime,
    )
    desktop.start()

    preview = desktop.preview()

    assert preview.revision == 4
    assert preview.items[0].action == "Send"
    assert not preview.requires_review

    assert desktop.runtime.preview_calls == 1
    assert desktop.runtime.sync_calls == 0

    events = []

    assert (
        desktop.sync_once(
            on_progress=events.append
        )
        is desktop.runtime.returned
    )

    assert events == ["made progress"]
    assert desktop.runtime.sync_calls == 1


def test_operations_cannot_run_before_start(setup):
    desktop = DesktopController(
        setup[0],
        runtime_factory=FakeRuntime,
    )

    with pytest.raises(
        RuntimeError,
        match="Start the connection",
    ):
        desktop.preview()

    with pytest.raises(
        RuntimeError,
        match="Start the connection",
    ):
        desktop.sync_once()


@pytest.mark.parametrize(
    "action, expected, blocks",
    [
        (SyncAction.UPLOAD, "Send", False),
        (SyncAction.DOWNLOAD, "Receive", False),
        (SyncAction.CONFLICT, "Conflict", True),
        (SyncAction.REVIEW_DELETE_LOCAL, "Deletion review", True),
        (SyncAction.REVIEW_DELETE_REMOTE, "Deletion review", True),
    ],
)
def test_preview_labels_and_blocks_unsafe_decisions(
    action,
    expected,
    blocks,
):
    preview = describe_preview(
        sample_preview(action)
    )

    assert preview.items[0].action == expected
    assert preview.items[0].needs_review is blocks
    assert preview.requires_review is blocks


def test_explicit_auto_apply_setting_is_not_allowed_for_manual_beta(
    setup,
):
    store, share = setup
    current = store.load()

    store.save(
        replace(
            current,
            shares=(
                replace(
                    share,
                    preferences=SyncPreferences(
                        auto_apply=True
                    ),
                ),
            ),
        )
    )

    desktop = DesktopController(
        store,
        runtime_factory=FakeRuntime,
    )

    with pytest.raises(
        DesktopConfigurationError,
        match="Automatic changes",
    ):
        desktop.start()

    assert desktop.runtime.start_args == []


def test_configured_runtime_parameters_are_forwarded(setup):
    desktop = DesktopController(
        setup[0],
        runtime_factory=FakeRuntime,
        listen_ports=(
            45101,
            45102,
            45103,
        ),
        lock_port=45104,
        validation_port=45105,
    )

    assert desktop.runtime.settings["listen_ports"] == (
        45101,
        45102,
        45103,
    )
    assert desktop.runtime.settings["lock_port"] == 45104
    assert desktop.runtime.settings["validation_port"] == 45105
