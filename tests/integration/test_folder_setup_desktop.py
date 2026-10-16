
"""Headless desktop controller integration: real encrypted folder requests.

GUI widgets deliberately aren't created here. UI workers call this controller;
all resulting shares must stay disabled until separate activation.
"""
from __future__ import annotations

import socket
import time
from dataclasses import replace

import pytest

from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.network.share_setup import ShareSetupError
from syncbridge.storage.config import AppConfig, ConfigStore
from syncbridge.ui.folder_setup_desktop import FolderSetupController
from syncbridge.ui.nearby_devices import NearbyDevice


def until(predicate, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.01)
    return predicate()


@pytest.fixture
def peers(tmp_path):
    identities = {}
    stores = {}
    roots = {}
    controllers = {}
    for name in ("Alice", "Bob"):
        base = tmp_path / name
        profile = base / "Profile"
        roots[name] = base / "Shared"
        roots[name].mkdir(parents=True)
        identities[name] = load_or_create_identity(profile / "identity.json")
        stores[name] = ConfigStore(profile / "settings.json")
        stores[name].save(AppConfig(device_name=name))
    for name, other in (("Alice", "Bob"), ("Bob", "Alice")):
        identity = identities[other]
        TrustStore(stores[name].path.parent / "trust.json").add_verified(
            identity.public_key_hex, confirmed_fingerprint=identity.fingerprint,
            name=other,
        )
    for name in ("Alice", "Bob"):
        controllers[name] = FolderSetupController(
            stores[name], bind_address="127.0.0.1", listen_port=0,
            approval_timeout=2.0,
            sync_ports=(45843, 45842, 45844) if name == "Alice"
            else (46843, 46842, 46844),
        )
        controllers[name].start()
    # Demo instances on one IP use distinct TCP ports.
    controllers["Alice"].remote_port = controllers["Bob"].service.bound_port
    controllers["Bob"].remote_port = controllers["Alice"].service.bound_port
    try:
        yield controllers, identities, stores, roots
    finally:
        controllers["Alice"].stop()
        controllers["Bob"].stop()


def device(name, identities):
    return NearbyDevice(
        node_id=identities[name].node_id,
        name=name,
        address="127.0.0.1",
        discovery_port=45841,
    )


def test_two_desktop_controllers_save_disabled_relationship(peers):
    controllers, identities, stores, roots = peers
    session = controllers["Alice"].request(
        device("Bob", identities), roots["Alice"], "Family Documents"
    )
    try:
        incoming = until(lambda: controllers["Bob"].pending())[0]
        assert incoming.peer_node_id == identities["Alice"].node_id
        controllers["Bob"].approve(incoming.request_id, roots["Bob"])
        alice_share = session.wait()
        bob_share = stores["Bob"].load().get_share(alice_share.share_id)
        assert bob_share is not None
        assert alice_share.share_id == bob_share.share_id
        assert alice_share.transfer_port == 46842
        assert bob_share.transfer_port == 45842
        for share in (alice_share, bob_share):
            assert not share.enabled
            assert not share.grant_read
            assert not share.grant_write
            assert not share.grant_manifest
            assert not share.grant_agreement
            assert not share.preferences.auto_apply
    finally:
        session.close()


def test_discovery_does_not_grant_permission_without_pairing(peers):
    controllers, identities, stores, roots = peers
    stranger = load_or_create_identity(
        stores["Alice"].path.parent / "stranger" / "identity.json"
    )
    with pytest.raises(ShareSetupError, match="Pair with this device"):
        controllers["Alice"].request(
            replace(device("Bob", identities), node_id=stranger.node_id),
            roots["Alice"], "Denied",
        )
    assert stores["Alice"].load().shares == ()


def test_explicit_rejection_creates_no_share(peers):
    controllers, identities, stores, roots = peers
    session = controllers["Alice"].request(
        device("Bob", identities), roots["Alice"], "Rejected"
    )
    try:
        incoming = until(lambda: controllers["Bob"].pending())[0]
        controllers["Bob"].reject(incoming.request_id)
        with pytest.raises(ShareSetupError):
            session.wait()
        assert stores["Alice"].load().shares == ()
        assert stores["Bob"].load().shares == ()
    finally:
        session.close()


def test_invalid_receiver_folder_not_approved(peers, tmp_path):
    controllers, identities, stores, roots = peers
    session = controllers["Alice"].request(
        device("Bob", identities), roots["Alice"], "No folder"
    )
    try:
        incoming = until(lambda: controllers["Bob"].pending())[0]
        with pytest.raises(FileNotFoundError):
            controllers["Bob"].approve(
                incoming.request_id, tmp_path / "missing"
            )
        controllers["Bob"].reject(incoming.request_id)
        with pytest.raises(ShareSetupError):
            session.wait()
        assert stores["Bob"].load().shares == ()
    finally:
        session.close()


def test_no_approval_expires_without_access(peers):
    controllers, identities, stores, roots = peers
    session = controllers["Alice"].request(
        device("Bob", identities), roots["Alice"], "Expired"
    )
    try:
        assert until(lambda: controllers["Bob"].pending())
        with pytest.raises(ShareSetupError):
            session.wait()
        assert stores["Alice"].load().shares == ()
        assert stores["Bob"].load().shares == ()
    finally:
        session.close()


def test_shutdown_releases_share_setup_port(peers):
    controllers, _, _, _ = peers
    alice = controllers["Alice"]
    port = alice.service.bound_port
    alice.stop()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", port))
