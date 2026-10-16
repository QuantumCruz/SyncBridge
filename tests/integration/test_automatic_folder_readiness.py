
"""Two real authenticated peers: folder approval automatically completes readiness.

No Tk windows, no manual activation call, and no silent approval of an
unrelated disabled share. Tests use the same controllers as the desktop GUI.
"""
from __future__ import annotations

import time
from uuid import uuid4

import pytest

from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.storage.config import AppConfig, ConfigStore, ShareConfig
from syncbridge.ui.folder_setup_desktop import FolderSetupController
from syncbridge.ui.nearby_devices import NearbyDevice
from syncbridge.ui.readiness_jobs import ReadinessJobs


def eventually(predicate, timeout=8.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.03)
    return bool(predicate())


@pytest.fixture
def computers(tmp_path):
    identities = {}
    stores = {}
    roots = {}
    controllers = {}
    for name in ("Alice", "Bob"):
        home = tmp_path / name
        roots[name] = home / "Shared"
        roots[name].mkdir(parents=True)
        profile = home / "Profile"
        identities[name] = load_or_create_identity(profile / "identity.json")
        stores[name] = ConfigStore(profile / "settings.json")
        stores[name].save(AppConfig(device_name=name))

    for name, other in (("Alice", "Bob"), ("Bob", "Alice")):
        remote = identities[other]
        TrustStore(stores[name].path.parent / "trust.json").add_verified(
            remote.public_key_hex,
            confirmed_fingerprint=remote.fingerprint,
            name=other,
        )

    for name, ports in (("Alice", (46543, 46542, 46544)),
                        ("Bob", (47543, 47542, 47544))):
        controllers[name] = FolderSetupController(
            stores[name], bind_address="127.0.0.1", listen_port=0,
            activation_port=0, sync_ports=ports,
            approval_timeout=2.0, retry_interval=0.1,
        )
        controllers[name].start()

    controllers["Alice"].remote_port = controllers["Bob"].service.bound_port
    controllers["Bob"].remote_port = controllers["Alice"].service.bound_port
    controllers["Alice"].remote_activation_port = (
        controllers["Bob"].activation_service.bound_port
    )
    controllers["Bob"].remote_activation_port = (
        controllers["Alice"].activation_service.bound_port
    )

    try:
        yield controllers, identities, stores, roots
    finally:
        controllers["Alice"].stop()
        controllers["Bob"].stop()


def request_and_approve(context):
    controllers, identities, stores, roots = context
    bob = identities["Bob"]
    device = NearbyDevice(
        node_id=bob.node_id, name="Bob", address="127.0.0.1",
        discovery_port=45841,
    )
    session = controllers["Alice"].request(
        device, roots["Alice"], "Shared documents"
    )
    try:
        assert eventually(lambda: bool(controllers["Bob"].pending()))
        incoming = controllers["Bob"].pending()[0]
        controllers["Bob"].approve(incoming.request_id, roots["Bob"])
        share = session.wait()
    finally:
        session.close()
    return share


def test_approved_folders_become_ready_without_activation_click(computers):
    controllers, _, stores, _ = computers
    share = request_and_approve(computers)
    assert not share.enabled
    controllers["Alice"].finish_outgoing(share)

    assert eventually(lambda: all(
        stores[name].load().get_share(share.share_id).enabled
        for name in ("Alice", "Bob")
    ))
    assert eventually(lambda: controllers["Alice"].jobs.entries() == ())
    for name in ("Alice", "Bob"):
        result = stores[name].load().get_share(share.share_id)
        assert result.grant_manifest and result.grant_read
        assert result.grant_write and result.grant_agreement
        assert not result.preferences.auto_apply
        assert len(stores[name].load().shares) == 1


def test_unrelated_disabled_share_is_not_automatically_enabled(computers):
    controllers, identities, stores, roots = computers
    store = stores["Alice"]
    current = store.load()
    unrelated = ShareConfig(
        share_id=uuid4().hex,
        peer_node_id=identities["Bob"].node_id,
        local_root=str(roots["Alice"]),
        display_name="Inactive folder",
        remote_host="127.0.0.1",
    )
    store.save(AppConfig(
        revision=current.revision, device_name=current.device_name,
        shares=(unrelated,),
    ))
    time.sleep(0.3)
    assert not store.load().get_share(unrelated.share_id).enabled
    assert controllers["Alice"].jobs.entries() == ()


def test_network_outage_retries_when_other_device_returns(computers):
    controllers, _, stores, _ = computers
    share = request_and_approve(computers)
    bob = controllers["Bob"]
    bob.activation_service.stop()
    controllers["Alice"].finish_outgoing(share)

    time.sleep(0.3)
    assert not stores["Alice"].load().get_share(share.share_id).enabled
    assert controllers["Alice"].jobs.entries() == ((
        share.share_id, share.peer_node_id,
    ),)

    bob.activation_service.start()
    controllers["Alice"].remote_activation_port = bob.activation_service.bound_port
    assert eventually(lambda: all(
        stores[name].load().get_share(share.share_id).enabled
        for name in ("Alice", "Bob")
    ))


def test_restart_retains_only_explicitly_approved_retry(computers):
    controllers, identities, stores, _ = computers
    share = request_and_approve(computers)
    bob = controllers["Bob"]
    bob.activation_service.stop()
    alice = controllers["Alice"]
    alice.finish_outgoing(share)
    assert alice.jobs.entries() == ((share.share_id, share.peer_node_id),)
    alice.stop()

    restart = FolderSetupController(
        stores["Alice"], bind_address="127.0.0.1", listen_port=0,
        activation_port=0, sync_ports=(46543, 46542, 46544),
        retry_interval=0.1,
    )
    controllers["Alice"] = restart
    restart.start()
    bob.activation_service.start()
    restart.remote_activation_port = bob.activation_service.bound_port
    assert eventually(lambda: all(
        stores[name].load().get_share(share.share_id).enabled
        for name in ("Alice", "Bob")
    ))
    assert eventually(lambda: restart.jobs.entries() == ())


def test_rejected_request_does_not_create_retry_job(computers):
    controllers, identities, stores, roots = computers
    device = NearbyDevice(
        node_id=identities["Bob"].node_id,
        name="Bob", address="127.0.0.1", discovery_port=45841,
    )
    session = controllers["Alice"].request(
        device, roots["Alice"], "Declined"
    )
    try:
        assert eventually(lambda: bool(controllers["Bob"].pending()))
        controllers["Bob"].reject(controllers["Bob"].pending()[0].request_id)
        with pytest.raises(Exception):
            session.wait()
    finally:
        session.close()
    assert stores["Alice"].load().shares == ()
    assert stores["Bob"].load().shares == ()
    assert controllers["Alice"].jobs.entries() == ()


def test_corrupt_retry_journal_fails_closed(computers):
    controllers, identities, stores, _ = computers
    queue = ReadinessJobs(stores["Alice"].path.parent)
    queue.path.write_text('{"invalid":"record"}', encoding="utf-8")
    with pytest.raises(Exception):
        queue.entries()
    assert stores["Alice"].load().shares == ()
    assert stores["Bob"].load().shares == ()
