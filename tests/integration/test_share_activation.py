
"""Real encrypted TCP tests for internal folder readiness and safe retries."""
from __future__ import annotations

import socket
from dataclasses import replace
from uuid import uuid4

import pytest

from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.network.share_activation import (
    ShareActivationClient, ShareActivationError, ShareActivationService,
)
from syncbridge.network.share_setup import ShareSetupClient, ShareSetupService
from syncbridge.storage.config import AppConfig, ConfigStore

ALICE_PORTS = (46543, 46542, 46544)
BOB_PORTS = (47543, 47542, 47544)


@pytest.fixture
def connected(tmp_path):
    peers = {}

    for name in ("Alice", "Bob"):
        home = tmp_path / name
        folder = home / "Shared"
        folder.mkdir(parents=True)

        profile = home / "Profile"
        identity = load_or_create_identity(
            profile / "identity.json"
        )
        trust = TrustStore(
            profile / "trust.json"
        )
        store = ConfigStore(
            profile / "settings.json"
        )
        store.save(AppConfig(device_name=name))

        peers[name] = (
            identity, trust, store, folder
        )

    for name, other in (
        ("Alice", "Bob"),
        ("Bob", "Alice"),
    ):
        remote = peers[other][0]

        peers[name][1].add_verified(
            remote.public_key_hex,
            confirmed_fingerprint=remote.fingerprint,
            name=other,
        )

    bob = peers["Bob"]

    setup = ShareSetupService(
        bob[0],
        bob[1],
        bob[2],
        bind_address="127.0.0.1",
        port=0,
        approval_timeout=3,
    )
    setup.start()

    try:
        alice = peers["Alice"]

        session = ShareSetupClient(
            alice[0],
            alice[1],
            alice[2],
        ).request(
            "127.0.0.1",
            bob[0].node_id,
            alice[3],
            "Shared documents",
            port=setup.bound_port,
            local_ports=ALICE_PORTS,
        )

        try:
            incoming = setup.pending()
            assert len(incoming) == 1

            setup.approve(
                incoming[0].request_id,
                bob[3],
                local_ports=BOB_PORTS,
            )

            approved = session.wait()
            share_id = approved.share_id

        finally:
            session.close()

    finally:
        setup.stop()

    service = ShareActivationService(
        bob[0],
        bob[1],
        bob[2],
        bind_address="127.0.0.1",
        port=0,
        local_ports=BOB_PORTS,
    )
    service.start()

    client = ShareActivationClient(
        peers["Alice"][0],
        peers["Alice"][1],
        peers["Alice"][2],
        local_ports=ALICE_PORTS,
    )

    try:
        yield peers, service, client, share_id

    finally:
        service.stop()


def _activate(context):
    peers, service, client, share_id = context

    return client.activate(
        share_id,
        peers["Bob"][0].node_id,
        port=service.bound_port,
    )


def test_two_approved_folders_become_ready(connected):
    peers, _, _, share_id = connected

    assert not peers["Alice"][2].load().get_share(share_id).enabled
    assert not peers["Bob"][2].load().get_share(share_id).enabled

    result = _activate(connected)
    assert result.enabled

    for device in ("Alice", "Bob"):
        item = peers[device][2].load().get_share(share_id)

        assert item.enabled
        assert all((
            item.grant_manifest,
            item.grant_read,
            item.grant_write,
            item.grant_agreement,
        ))
        assert not item.preferences.auto_apply


def test_retry_is_idempotent_after_success(connected):
    first = _activate(connected)
    second = _activate(connected)

    assert first == second
    assert len(connected[0]["Alice"][2].load().shares) == 1
    assert len(connected[0]["Bob"][2].load().shares) == 1


def test_broken_connection_after_local_save_can_reconcile(
    connected,
    monkeypatch,
):
    import syncbridge.network.share_activation as module

    peers, _, _, share_id = connected
    real_send = module._send

    def interrupt(secure, kind, **fields):
        if kind == "activate":
            raise OSError(
                "simulated network disconnection before remote commit"
            )
        return real_send(secure, kind, **fields)

    with monkeypatch.context() as patch:
        patch.setattr(module, "_send", interrupt)

        with pytest.raises(
            ShareActivationError,
            match="interrupted",
        ):
            _activate(connected)

    assert peers["Alice"][2].load().get_share(share_id).enabled
    assert not peers["Bob"][2].load().get_share(share_id).enabled

    _activate(connected)

    assert peers["Alice"][2].load().get_share(share_id).enabled
    assert peers["Bob"][2].load().get_share(share_id).enabled


def test_mismatching_ports_refuse_both_sides(connected):
    peers, _, _, share_id = connected
    store = peers["Alice"][2]
    current = store.load()

    wrong = replace(
        current.shares[0],
        transfer_port=49998,
    )
    store.save(
        replace(current, shares=(wrong,))
    )

    with pytest.raises(ShareActivationError):
        _activate(connected)

    assert not store.load().get_share(share_id).enabled
    assert not peers["Bob"][2].load().get_share(share_id).enabled


def test_missing_folder_refuses_activation(connected):
    peers, _, _, share_id = connected

    peers["Bob"][3].rmdir()

    with pytest.raises(ShareActivationError):
        _activate(connected)

    assert not peers["Alice"][2].load().get_share(share_id).enabled
    assert not peers["Bob"][2].load().get_share(share_id).enabled


def test_wrong_share_id_cannot_activate(connected):
    peers, service, client, _ = connected

    with pytest.raises(
        ShareActivationError,
        match="approved",
    ):
        client.activate(
            uuid4().hex,
            peers["Bob"][0].node_id,
            port=service.bound_port,
        )

    assert not peers["Alice"][2].load().shares[0].enabled


def test_remote_service_offline_keeps_local_share_disabled(connected):
    peers, service, _, share_id = connected

    old_port = service.bound_port
    service.stop()

    with pytest.raises(
        ShareActivationError,
        match="interrupted",
    ):
        connected[2].activate(
            share_id,
            peers["Bob"][0].node_id,
            port=old_port,
            timeout=1,
        )

    assert not peers["Alice"][2].load().get_share(share_id).enabled


def test_listener_shutdown_releases_tcp_port(connected):
    _, service, _, _ = connected

    port = service.bound_port
    service.stop()

    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    ) as sock:
        sock.bind(("127.0.0.1", port))
