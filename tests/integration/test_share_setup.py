
"""Encrypted folder setup integration tests.

No test enables a share or grants read/write access.
"""
from __future__ import annotations

import socket
import struct
import time

import pytest

from syncbridge.network.secure_channel import (
    open_secure_channel,
)
from syncbridge.network.security import (
    TrustStore,
    load_or_create_identity,
)
from syncbridge.network.share_setup import (
    ShareSetupClient,
    ShareSetupError,
    ShareSetupService,
)
from syncbridge.storage.config import ConfigStore


def wait_for(predicate, timeout=3):
    until = time.monotonic() + timeout

    while time.monotonic() < until:
        found = predicate()
        if found:
            return found
        time.sleep(0.01)

    return predicate()


@pytest.fixture
def pair(tmp_path):
    peers = {}

    for name in ("Alice", "Bob"):
        base = tmp_path / name
        folder = base / "Shared"
        folder.mkdir(parents=True)

        identity = load_or_create_identity(
            base / "Profile" / "identity.json"
        )
        trust = TrustStore(
            base / "Profile" / "trust.json"
        )
        store = ConfigStore(
            base / "Profile" / "settings.json"
        )

        peers[name] = (
            identity,
            trust,
            store,
            folder,
        )

    for name, other in (
        ("Alice", "Bob"),
        ("Bob", "Alice"),
    ):
        identity = peers[other][0]

        peers[name][1].add_verified(
            identity.public_key_hex,
            confirmed_fingerprint=identity.fingerprint,
            name=other,
        )

    bob_id, bob_trust, bob_store, _ = peers["Bob"]

    server = ShareSetupService(
        bob_id,
        bob_trust,
        bob_store,
        bind_address="127.0.0.1",
        port=0,
        approval_timeout=1.5,
    )
    server.start()

    alice_id, alice_trust, alice_store, _ = peers["Alice"]

    client = ShareSetupClient(
        alice_id,
        alice_trust,
        alice_store,
    )

    try:
        yield peers, server, client
    finally:
        server.stop()


def request(pair):
    peers, server, client = pair

    return client.request(
        "127.0.0.1",
        peers["Bob"][0].node_id,
        peers["Alice"][3],
        "Projects",
        port=server.bound_port,
        local_ports=(
            46543,
            46542,
            46544,
        ),
        approval_timeout=3,
    )


def test_approval_on_both_sides_persists_same_disabled_share(pair):
    peers, server, _ = pair

    session = request(pair)

    try:
        incoming = wait_for(
            lambda: server.pending()
        )[0]

        assert incoming.share_id == session.share_id
        assert (
            incoming.peer_node_id
            == peers["Alice"][0].node_id
        )
        assert incoming.peer_ports == (
            46543,
            46542,
            46544,
        )
        assert incoming.peer_address == "127.0.0.1"

        assert peers["Alice"][2].load().shares == ()
        assert peers["Bob"][2].load().shares == ()

        server.approve(
            incoming.request_id,
            peers["Bob"][3],
            local_ports=(
                47543,
                47542,
                47544,
            ),
        )

        result = session.wait()

        assert result.share_id == incoming.share_id

        alice_share = (
            peers["Alice"][2]
            .load()
            .get_share(result.share_id)
        )

        assert wait_for(
            lambda: peers["Bob"][2]
            .load()
            .get_share(result.share_id)
        )

        bob_share = (
            peers["Bob"][2]
            .load()
            .get_share(result.share_id)
        )

        assert (
            alice_share.peer_node_id
            == peers["Bob"][0].node_id
        )
        assert (
            bob_share.peer_node_id
            == peers["Alice"][0].node_id
        )

        assert alice_share.local_root == str(
            peers["Alice"][3].resolve()
        )
        assert bob_share.local_root == str(
            peers["Bob"][3].resolve()
        )

        assert alice_share.transfer_port == 47542
        assert bob_share.transfer_port == 46542

        assert (
            alice_share.remote_host
            == bob_share.remote_host
            == "127.0.0.1"
        )

        for share in (
            alice_share,
            bob_share,
        ):
            assert share.enabled is False
            assert share.grant_manifest is False
            assert share.grant_read is False
            assert share.grant_write is False
            assert share.grant_agreement is False
            assert share.preferences.auto_apply is False

    finally:
        session.close()


def test_rejected_request_does_not_change_either_configuration(pair):
    peers, server, _ = pair
    session = request(pair)

    try:
        incoming = wait_for(
            lambda: server.pending()
        )[0]

        server.reject(
            incoming.request_id
        )

        with pytest.raises(
            ShareSetupError,
            match="declined",
        ):
            session.wait()

        assert peers["Alice"][2].load().shares == ()
        assert peers["Bob"][2].load().shares == ()

    finally:
        session.close()


def test_no_automatic_approval_and_request_times_out(pair):
    peers, server, _ = pair
    session = request(pair)

    try:
        assert wait_for(
            lambda: server.pending()
        )

        with pytest.raises(
            ShareSetupError,
            match="declined",
        ):
            session.wait()

        assert peers["Alice"][2].load().shares == ()
        assert peers["Bob"][2].load().shares == ()

        assert wait_for(
            lambda: not server.pending()
        )

    finally:
        session.close()


def test_nonexistent_local_folder_cannot_be_approved(
    pair,
    tmp_path,
):
    peers, server, _ = pair
    session = request(pair)

    try:
        incoming = wait_for(
            lambda: server.pending()
        )[0]

        with pytest.raises(
            FileNotFoundError,
        ):
            server.approve(
                incoming.request_id,
                tmp_path / "missing",
            )

        assert (
            server.pending()[0].request_id
            == incoming.request_id
        )

        server.reject(
            incoming.request_id
        )

        with pytest.raises(ShareSetupError):
            session.wait()

        assert peers["Bob"][2].load().shares == ()

    finally:
        session.close()


def test_refuse_sharing_profile_folder(pair):
    peers, server, _ = pair
    session = request(pair)

    try:
        incoming = wait_for(
            lambda: server.pending()
        )[0]

        with pytest.raises(
            ShareSetupError,
            match="profile",
        ):
            server.approve(
                incoming.request_id,
                peers["Bob"][2].path.parent,
            )

        server.reject(
            incoming.request_id
        )

        with pytest.raises(ShareSetupError):
            session.wait()

    finally:
        session.close()


def test_request_requires_trusted_remote_identity(
    pair,
    tmp_path,
):
    peers, server, _ = pair

    identity = load_or_create_identity(
        tmp_path / "Stranger" / "identity.json"
    )
    untrusted = TrustStore(
        tmp_path / "Stranger" / "trust.json"
    )

    client = ShareSetupClient(
        identity,
        untrusted,
        peers["Alice"][2],
    )

    with pytest.raises(
        ShareSetupError,
        match="paired",
    ):
        client.request(
            "127.0.0.1",
            peers["Bob"][0].node_id,
            peers["Alice"][3],
            "Projects",
            port=server.bound_port,
        )

    assert not server.pending()


def test_wrong_remote_identity_is_rejected_before_proposal(pair):
    peers, server, client = pair

    with pytest.raises(ShareSetupError):
        client.request(
            "127.0.0.1",
            peers["Alice"][0].node_id,
            peers["Alice"][3],
            "Projects",
            port=server.bound_port,
        )

    assert peers["Alice"][2].load().shares == ()
    assert peers["Bob"][2].load().shares == ()


def test_listener_releases_port_and_cancels_pending(pair):
    peers, server, _ = pair
    session = request(pair)

    try:
        assert wait_for(
            lambda: server.pending()
        )

        port = server.bound_port
        server.stop()

        with pytest.raises(
            (ShareSetupError, OSError)
        ):
            session.wait()

        assert peers["Bob"][2].load().shares == ()

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        ) as probe:
            probe.bind(
                ("127.0.0.1", port)
            )

    finally:
        session.close()


def test_malformed_authenticated_offer_cannot_kill_listener(pair):
    peers, server, _ = pair

    alice_id, alice_trust, _, _ = peers["Alice"]

    with socket.create_connection(
        (
            "127.0.0.1",
            server.bound_port,
        )
    ) as raw:
        secure, _ = open_secure_channel(
            raw,
            alice_id,
            alice_trust,
            peers["Bob"][0].node_id,
        )

        secure.sendall(
            struct.pack("!I", 4) + b"oops"
        )
        secure.close()

    session = request(pair)

    try:
        assert wait_for(
            lambda: server.pending()
        )

        server.reject(
            server.pending()[0].request_id
        )

        with pytest.raises(ShareSetupError):
            session.wait()

    finally:
        session.close()


def test_cancelled_request_does_not_save_configuration(pair):
    peers, server, _ = pair
    session = request(pair)

    assert wait_for(
        lambda: server.pending()
    )

    session.cancel()

    assert wait_for(
        lambda: not server.pending(),
        timeout=2,
    )

    assert peers["Alice"][2].load().shares == ()
    assert peers["Bob"][2].load().shares == ()
