
import socket
import threading
import time

import pytest

from syncbridge.network.security import DeviceIdentity, TrustStore, AuthenticationError
from syncbridge.network.secure_peer import SecurePeerManager
from syncbridge.network.peer import PeerConnectionError
from syncbridge.network.secure_channel import open_secure_channel
from syncbridge.network.protocol import (
    send_message,
    receive_message,
    Message,
    MessageType,
)


def setup_pair(tmp_path):
    ai, bi = DeviceIdentity.generate(), DeviceIdentity.generate()
    at = TrustStore(tmp_path / "alice-trust.json")
    bt = TrustStore(tmp_path / "bob-trust.json")

    at.add_verified(
        bi.public_key_hex,
        confirmed_fingerprint=bi.fingerprint,
        name="B",
    )
    bt.add_verified(
        ai.public_key_hex,
        confirmed_fingerprint=ai.fingerprint,
        name="A",
    )

    options = {
        "listen_port": 0,
        "bind_address": "127.0.0.1",
        "handshake_timeout": 0.6,
        "heartbeat_interval": 0.08,
        "idle_timeout": 0.4,
    }

    a = SecurePeerManager(ai, at, "A", **options)
    b = SecurePeerManager(bi, bt, "B", **options)
    return a, b


def wait_for(predicate, timeout=2):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def test_healthy_connection_heartbeat(tmp_path):
    a, b = setup_pair(tmp_path)
    a.start()
    b.start()

    try:
        result = a.connect(
            "127.0.0.1",
            b.bound_port,
            expected_node_id=b.node_id,
        )
        assert result.node_id == b.node_id
        assert wait_for(lambda: len(a.peers) == len(b.peers) == 1)

        time.sleep(0.8)
        assert len(a.peers) == len(b.peers) == 1

    finally:
        a.stop()
        b.stop()


def test_untrusted_remote_is_denied(tmp_path):
    a, b = setup_pair(tmp_path)
    a.trust_store.remove(b.node_id)
    a.start()
    b.start()

    try:
        with pytest.raises(AuthenticationError):
            a.connect(
                "127.0.0.1",
                b.bound_port,
                expected_node_id=b.node_id,
            )
        assert a.peers == ()

    finally:
        a.stop()
        b.stop()


def test_remote_revocation_rejects(tmp_path):
    a, b = setup_pair(tmp_path)
    b.trust_store.remove(a.node_id)
    a.start()
    b.start()

    try:
        with pytest.raises(AuthenticationError):
            a.connect(
                "127.0.0.1",
                b.bound_port,
                expected_node_id=b.node_id,
            )

        assert wait_for(lambda: not a.peers and not b.peers)

    finally:
        a.stop()
        b.stop()


def test_live_revocation_disconnects(tmp_path):
    a, b = setup_pair(tmp_path)
    a.start()
    b.start()

    try:
        a.connect(
            "127.0.0.1",
            b.bound_port,
            expected_node_id=b.node_id,
        )
        assert wait_for(lambda: len(a.peers) == len(b.peers) == 1)

        a.trust_store.remove(b.node_id)

        assert wait_for(lambda: len(a.peers) == len(b.peers) == 0)

    finally:
        a.stop()
        b.stop()


def test_spoofed_application_hello_is_denied(tmp_path):
    a, b = setup_pair(tmp_path)
    errors = []
    b._on_error = errors.append
    b.start()

    try:
        with socket.create_connection(
            ("127.0.0.1", b.bound_port), 1
        ) as raw:
            secure, remote = open_secure_channel(
                raw,
                a.identity,
                a.trust_store,
                b.node_id,
            )

            send_message(
                secure,
                Message(
                    MessageType.HELLO,
                    {
                        "node_id": "f" * 32,
                        "name": "Spoofer",
                        "peer_port": 12345,
                    },
                ),
            )

            assert wait_for(
                lambda: any(
                    "identity differs" in str(error)
                    for error in errors
                )
            )
            assert b.peers == ()

            with pytest.raises(Exception):
                receive_message(secure)

    finally:
        b.stop()


def test_simultaneous_connects_converge(tmp_path):
    a, b = setup_pair(tmp_path)
    a.start()
    b.start()
    failed = []

    def dial(source, destination):
        try:
            source.connect(
                "127.0.0.1",
                destination.bound_port,
                expected_node_id=destination.node_id,
            )
        except PeerConnectionError as exc:
            failed.append(exc)

    try:
        t1 = threading.Thread(target=dial, args=(a, b))
        t2 = threading.Thread(target=dial, args=(b, a))

        t1.start()
        t2.start()
        t1.join(2)
        t2.join(2)

        assert not t1.is_alive()
        assert not t2.is_alive()

        assert wait_for(
            lambda: len(a.peers) == len(b.peers) == 1
        )

    finally:
        a.stop()
        b.stop()


def test_stop_restart_and_clean_disconnect(tmp_path):
    a, b = setup_pair(tmp_path)
    a.start()
    b.start()

    try:
        a.connect(
            "127.0.0.1",
            b.bound_port,
            expected_node_id=b.node_id,
        )
        assert wait_for(lambda: len(b.peers) == 1)

        a.stop()
        assert wait_for(lambda: len(b.peers) == 0)

        a.start()
        assert a.is_running

        a.connect(
            "127.0.0.1",
            b.bound_port,
            expected_node_id=b.node_id,
        )
        assert wait_for(
            lambda: len(a.peers) == len(b.peers) == 1
        )

    finally:
        a.stop()
        b.stop()


def test_no_plaintext_legacy_hello(tmp_path):
    a, b = setup_pair(tmp_path)
    errors = []
    b._on_error = errors.append
    b.start()

    try:
        with socket.create_connection(
            ("127.0.0.1", b.bound_port), 1
        ) as connection:
            send_message(
                connection,
                Message(
                    MessageType.HELLO,
                    {
                        "node_id": a.node_id,
                        "name": "A",
                        "peer_port": 5000,
                    },
                ),
            )

            assert wait_for(lambda: len(errors) > 0)
            assert b.peers == ()

    finally:
        b.stop()


def test_connect_requires_verified_identity(tmp_path):
    a, b = setup_pair(tmp_path)
    a.start()
    b.start()

    try:
        with pytest.raises(ValueError):
            a.connect(
                "127.0.0.1",
                b.bound_port,
                expected_node_id="bad",
            )

        with pytest.raises(ValueError):
            a.connect(
                "invalid",
                b.bound_port,
                expected_node_id=b.node_id,
            )

        with pytest.raises(PeerConnectionError):
            a.connect(
                "127.0.0.1",
                a.bound_port,
                expected_node_id=a.node_id,
            )

    finally:
        a.stop()
        b.stop()
