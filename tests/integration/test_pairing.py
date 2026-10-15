
"""Real loopback TCP tests of manual consent and durable peer identity trust."""
from __future__ import annotations

import socket
import struct
import time

import pytest

from syncbridge.network.pairing import PairingClient, PairingService
from syncbridge.network.security import (
    PairingError,
    TrustStore,
    load_or_create_identity,
)


def wait_for(predicate, seconds=2.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.01)
    return predicate()


@pytest.fixture
def pair(tmp_path):
    identities = {}
    stores = {}

    for name in ("Alice", "Bob"):
        profile = tmp_path / name

        identities[name] = load_or_create_identity(
            profile / "identity.json"
        )
        stores[name] = TrustStore(
            profile / "trust.json"
        )

    service = PairingService(
        identities["Bob"],
        stores["Bob"],
        "Bob",
        bind_address="127.0.0.1",
        listen_port=0,
        approval_timeout=1.0,
    )
    service.start()

    try:
        client = PairingClient(
            identities["Alice"],
            stores["Alice"],
            "Alice",
        )

        yield client, service, identities, stores

    finally:
        service.stop()


def pending(service):
    return wait_for(lambda: service.pending())


def test_both_people_approve_before_either_device_becomes_trusted(pair):
    client, service, identities, stores = pair

    session = client.request(
        "127.0.0.1",
        service.bound_port,
        expected_node_id=identities["Bob"].node_id,
    )

    try:
        request = pending(service)[0]

        assert request.code == session.details.code
        assert request.remote_node_id == identities["Alice"].node_id
        assert (
            session.details.remote_fingerprint
            == identities["Bob"].fingerprint
        )

        assert stores["Alice"].devices == ()
        assert stores["Bob"].devices == ()

        service.approve(
            request.request_id,
            session.details.code,
        )

        assert stores["Bob"].devices == ()

        session.approve(request.code)

        assert stores["Alice"].get(
            identities["Bob"].node_id
        )
        assert stores["Bob"].get(
            identities["Alice"].node_id
        )

    finally:
        session.close()


def test_wrong_local_code_refuses_without_trust(pair):
    client, service, identities, stores = pair

    session = client.request(
        "127.0.0.1",
        service.bound_port,
    )

    try:
        request = pending(service)[0]

        with pytest.raises(
            PairingError,
            match="codes did not match",
        ):
            service.approve(
                request.request_id,
                "0000-0000-0000-0000",
            )

        assert stores["Bob"].devices == ()

        with pytest.raises(
            PairingError,
            match="codes did not match",
        ):
            session.approve(
                "1111-1111-1111-1111"
            )

        assert stores["Alice"].devices == ()

    finally:
        session.close()


def test_explicit_rejection_does_not_create_trust(pair):
    client, service, _, stores = pair

    session = client.request(
        "127.0.0.1",
        service.bound_port,
    )

    try:
        request = pending(service)[0]

        service.reject(request.request_id)

        with pytest.raises((PairingError, OSError)):
            session.approve(request.code)

        assert (
            stores["Alice"].devices
            == stores["Bob"].devices
            == ()
        )

        assert wait_for(
            lambda: not service.pending()
        )

    finally:
        session.close()


def test_unapproved_request_expires_without_trust(pair):
    client, service, _, stores = pair

    session = client.request(
        "127.0.0.1",
        service.bound_port,
    )

    try:
        assert pending(service)

        assert wait_for(
            lambda: not service.pending(),
            seconds=2,
        )

        assert (
            stores["Alice"].devices
            == stores["Bob"].devices
            == ()
        )

    finally:
        session.close()


def test_discovery_identity_mismatch_is_rejected(pair):
    client, service, _, stores = pair

    with pytest.raises(
        PairingError,
        match="differs from the discovered",
    ):
        client.request(
            "127.0.0.1",
            service.bound_port,
            expected_node_id="0" * 32,
        )

    assert (
        stores["Alice"].devices
        == stores["Bob"].devices
        == ()
    )


def test_malformed_request_does_not_stop_listener(pair):
    client, service, _, stores = pair

    with socket.create_connection(
        ("127.0.0.1", service.bound_port)
    ) as sock:
        sock.sendall(
            struct.pack("!I", 9999999)
        )

    session = client.request(
        "127.0.0.1",
        service.bound_port,
    )

    try:
        assert pending(service)
        assert service.running

    finally:
        session.close()

    assert (
        stores["Alice"].devices
        == stores["Bob"].devices
        == ()
    )


def test_stopping_service_refuses_pending_request(pair):
    client, service, _, stores = pair

    session = client.request(
        "127.0.0.1",
        service.bound_port,
    )

    try:
        assert pending(service)

        service.stop()

        with pytest.raises((PairingError, OSError)):
            session.approve(
                session.details.code
            )

        assert (
            stores["Alice"].devices
            == stores["Bob"].devices
            == ()
        )

    finally:
        session.close()


def test_pairing_does_not_create_share_configuration(
    pair,
    tmp_path,
):
    client, service, _, stores = pair

    session = client.request(
        "127.0.0.1",
        service.bound_port,
    )

    request = pending(service)[0]

    service.approve(
        request.request_id,
        session.details.code,
    )

    session.approve(request.code)

    assert len(stores["Alice"].devices) == 1
    assert len(stores["Bob"].devices) == 1

    assert list(
        tmp_path.rglob("settings.json")
    ) == []

    assert list(
        tmp_path.rglob("shared_state.sqlite")
    ) == []
