
"""Headless desktop adapter and authoritative lifecycle checks."""
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
    DesktopLifecycle,
    DesktopLifecycleError,
    DesktopPhase,
    describe_preview,
    desktop_buttons,
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


# -------------------------------------------------------------------
# Authoritative desktop lifecycle
# -------------------------------------------------------------------


def test_desktop_always_begins_disconnected():
    lifecycle = DesktopLifecycle()

    assert lifecycle.phase is DesktopPhase.DISCONNECTED
    assert lifecycle.generation == 0
    assert lifecycle.allowed_buttons() == frozenset({
        "find",
    })


def test_saved_pairing_does_not_restore_a_live_session():
    lifecycle = DesktopLifecycle()

    assert lifecycle.phase is DesktopPhase.DISCONNECTED

    assert lifecycle.allowed_buttons(
        saved_peer=True
    ) == frozenset({
        "find",
        "reconnect",
    })

    assert "preview" not in lifecycle.allowed_buttons(
        saved_peer=True
    )
    assert "sync" not in lifecycle.allowed_buttons(
        saved_peer=True,
        preview_ready=True,
    )


@pytest.mark.parametrize(
    "phase,saved_peer,preview_ready,expected",
    [
        (
            DesktopPhase.DISCONNECTED,
            False,
            False,
            {"find"},
        ),
        (
            DesktopPhase.DISCONNECTED,
            True,
            False,
            {"find", "reconnect"},
        ),
        (
            DesktopPhase.PAIRING,
            True,
            False,
            set(),
        ),
        (
            DesktopPhase.CHOOSING_FOLDER,
            False,
            False,
            {"choose_folder"},
        ),
        (
            DesktopPhase.CONNECTING,
            True,
            False,
            set(),
        ),
        (
            DesktopPhase.CONNECTED,
            True,
            False,
            {
                "change_folder",
                "open_folder",
                "preview",
                "disconnect",
            },
        ),
        (
            DesktopPhase.CONNECTED,
            True,
            True,
            {
                "change_folder",
                "open_folder",
                "preview",
                "sync",
                "disconnect",
            },
        ),
        (
            DesktopPhase.SYNCHRONIZING,
            True,
            True,
            set(),
        ),
        (
            DesktopPhase.CHANGING_FOLDERS,
            True,
            True,
            set(),
        ),
        (
            DesktopPhase.DISCONNECTING,
            True,
            True,
            set(),
        ),
    ],
)
def test_only_allowed_buttons_are_enabled(
    phase,
    saved_peer,
    preview_ready,
    expected,
):
    assert desktop_buttons(
        phase,
        saved_peer=saved_peer,
        preview_ready=preview_ready,
    ) == frozenset(expected)


def test_complete_first_time_connection_flow():
    lifecycle = DesktopLifecycle()

    steps = (
        DesktopPhase.PAIRING,
        DesktopPhase.CHOOSING_FOLDER,
        DesktopPhase.CONNECTING,
        DesktopPhase.CONNECTED,
        DesktopPhase.SYNCHRONIZING,
        DesktopPhase.CONNECTED,
        DesktopPhase.DISCONNECTING,
        DesktopPhase.DISCONNECTED,
    )

    for number, phase in enumerate(steps, start=1):
        generation = lifecycle.transition(phase)
        assert lifecycle.phase is phase
        assert generation == number

    assert lifecycle.allowed_buttons(
        saved_peer=True
    ) == frozenset({
        "find",
        "reconnect",
    })


def test_returning_device_requires_a_new_live_connection():
    lifecycle = DesktopLifecycle()

    lifecycle.transition(DesktopPhase.CONNECTING)

    assert lifecycle.allowed_buttons(
        saved_peer=True
    ) == frozenset()

    lifecycle.transition(DesktopPhase.CONNECTED)

    assert "preview" in lifecycle.allowed_buttons()


def test_folder_change_requires_connected_session():
    lifecycle = DesktopLifecycle()

    with pytest.raises(DesktopLifecycleError):
        lifecycle.transition(
            DesktopPhase.CHANGING_FOLDERS
        )

    lifecycle.transition(DesktopPhase.CONNECTING)
    lifecycle.transition(DesktopPhase.CONNECTED)
    lifecycle.transition(DesktopPhase.CHANGING_FOLDERS)

    assert lifecycle.allowed_buttons() == frozenset()

    lifecycle.transition(DesktopPhase.CHOOSING_FOLDER)

    assert lifecycle.allowed_buttons() == frozenset({
        "choose_folder",
    })


def test_disconnect_prevents_operations_until_complete():
    lifecycle = DesktopLifecycle()

    lifecycle.transition(DesktopPhase.CONNECTING)
    lifecycle.transition(DesktopPhase.CONNECTED)
    lifecycle.transition(DesktopPhase.DISCONNECTING)

    assert lifecycle.allowed_buttons(
        saved_peer=True,
        preview_ready=True,
    ) == frozenset()

    with pytest.raises(DesktopLifecycleError):
        lifecycle.transition(
            DesktopPhase.CONNECTED
        )

    lifecycle.transition(DesktopPhase.DISCONNECTED)

    assert lifecycle.allowed_buttons(
        saved_peer=True,
        preview_ready=True,
    ) == frozenset({
        "find",
        "reconnect",
    })


def test_unexpected_disconnect_during_sync_is_allowed():
    lifecycle = DesktopLifecycle()

    lifecycle.transition(DesktopPhase.CONNECTING)
    lifecycle.transition(DesktopPhase.CONNECTED)
    lifecycle.transition(DesktopPhase.SYNCHRONIZING)
    lifecycle.transition(DesktopPhase.DISCONNECTING)

    assert lifecycle.allowed_buttons() == frozenset()

    lifecycle.transition(DesktopPhase.DISCONNECTED)

    assert lifecycle.phase is DesktopPhase.DISCONNECTED


def test_invalid_transitions_are_refused():
    lifecycle = DesktopLifecycle()

    with pytest.raises(
        DesktopLifecycleError,
        match="Invalid desktop transition",
    ):
        lifecycle.transition(
            DesktopPhase.SYNCHRONIZING
        )

    assert lifecycle.phase is DesktopPhase.DISCONNECTED
    assert lifecycle.generation == 0


def test_duplicate_state_change_does_not_advance_generation():
    lifecycle = DesktopLifecycle()

    assert lifecycle.transition(
        DesktopPhase.DISCONNECTED
    ) == 0

    assert lifecycle.transition(
        DesktopPhase.PAIRING
    ) == 1

    assert lifecycle.transition(
        DesktopPhase.PAIRING
    ) == 1


@pytest.mark.parametrize(
    "invalid",
    [None, True, "connected", 3],
)
def test_invalid_state_type_is_rejected(invalid):
    lifecycle = DesktopLifecycle()

    with pytest.raises(TypeError):
        lifecycle.transition(invalid)


def test_invalid_button_permission_inputs_are_rejected():
    with pytest.raises(TypeError):
        desktop_buttons("connected")

    with pytest.raises(TypeError):
        desktop_buttons(
            DesktopPhase.DISCONNECTED,
            saved_peer=1,
        )

    with pytest.raises(TypeError):
        desktop_buttons(
            DesktopPhase.CONNECTED,
            preview_ready="yes",
        )
