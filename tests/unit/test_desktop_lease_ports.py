
"""Desktop lease-port selection and two-profile startup compatibility."""
from __future__ import annotations

from uuid import uuid4

import pytest

from syncbridge.core.fenced_guarded_manual import (
    FencedGuardedManualRuntime,
)
from syncbridge.storage.config import (
    AppConfig,
    ConfigStore,
    ShareConfig,
)
from syncbridge.ui.desktop_controller import (
    DesktopController,
    _lease_port_for_transfer,
)


class ProbeRuntime(FencedGuardedManualRuntime):
    """Exercise controller port wiring without starting network listeners."""

    def start(self, *, background=False):
        assert background is False
        self.started_ports = (
            self.lease_listen_port,
            self.remote_lease_port,
        )

    def stop(self):
        pass


def _store(tmp_path, name, remote_port):
    profile = tmp_path / name
    profile.mkdir()

    folder = tmp_path / f"{name}Files"
    folder.mkdir()

    store = ConfigStore(
        profile / "settings.json"
    )

    store.save(AppConfig(shares=(ShareConfig(
        share_id=uuid4().hex,
        peer_node_id=uuid4().hex,
        local_root=str(folder),
        display_name="Test folder",
        remote_host="127.0.0.1",
        manifest_port=remote_port - 1,
        transfer_port=remote_port,
        agreement_port=remote_port + 1,
        enabled=True,
    ),)))

    return store


def test_normal_installation_keeps_existing_lease_port(tmp_path):
    store = _store(
        tmp_path, "Alice", 45842
    )

    controller = DesktopController(
        store,
        runtime_factory=ProbeRuntime,
    )

    controller.start()

    assert controller.runtime.started_ports == (
        45849, 45849
    )


def test_separate_profiles_derive_matching_remote_ports(tmp_path):
    a_transfer = 52001
    b_transfer = 54001

    a = DesktopController(
        _store(tmp_path, "Alice", b_transfer),
        listen_ports=(52000, a_transfer, 52002),
        runtime_factory=ProbeRuntime,
    )

    b = DesktopController(
        _store(tmp_path, "Bob", a_transfer),
        listen_ports=(54000, b_transfer, 54002),
        runtime_factory=ProbeRuntime,
    )

    a.start()
    b.start()

    a_local, a_remote = a.runtime.started_ports
    b_local, b_remote = b.runtime.started_ports

    assert a_local != b_local
    assert a_local == b_remote
    assert b_local == a_remote

    assert a_local != 45849
    assert b_local != 45849


def test_explicit_lease_ports_are_not_overwritten(tmp_path):
    controller = DesktopController(
        _store(tmp_path, "Alice", 54001),
        listen_ports=(52000, 52001, 52002),
        lease_listen_port=47001,
        remote_lease_port=47002,
        runtime_factory=ProbeRuntime,
    )

    controller.start()

    assert controller.runtime.started_ports == (
        47001, 47002
    )


def test_port_mapping_is_unique_and_stable():
    transfer_ports = (
        45842,
        25849,
        49152,
        52001,
        54001,
        65535,
    )

    lease_ports = tuple(
        _lease_port_for_transfer(port)
        for port in transfer_ports
    )

    assert len(set(lease_ports)) == len(lease_ports)
    assert all(1025 <= port <= 65535 for port in lease_ports)
    assert _lease_port_for_transfer(45842) == 45849


@pytest.mark.parametrize(
    "invalid",
    [None, True, 0, 1024, 65536, "45842"],
)
def test_invalid_transfer_ports_fail_closed(invalid):
    with pytest.raises(ValueError):
        _lease_port_for_transfer(invalid)


def test_folder_setup_can_finish_after_controller_creation(tmp_path):
    profile = tmp_path / "LateProfile"
    profile.mkdir()

    store = ConfigStore(
        profile / "settings.json"
    )

    controller = DesktopController(
        store,
        listen_ports=(51000, 51001, 51002),
        runtime_factory=ProbeRuntime,
    )

    # The real Qt onboarding layer creates the controller before
    # the user has selected and approved a shared folder.
    folder = tmp_path / "LateFiles"
    folder.mkdir()

    store.save(AppConfig(shares=(ShareConfig(
        share_id=uuid4().hex,
        peer_node_id=uuid4().hex,
        local_root=str(folder),
        display_name="Late folder",
        remote_host="127.0.0.1",
        transfer_port=53001,
        enabled=True,
    ),)))

    controller.start()

    assert controller.runtime.started_ports == (
        _lease_port_for_transfer(51001),
        _lease_port_for_transfer(53001),
    )
