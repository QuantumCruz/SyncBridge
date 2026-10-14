
"""TCP peer lifecycle and handshake tests using real localhost sockets."""

from __future__ import annotations

import socket
import threading
import time
from uuid import uuid4

import pytest

from syncbridge.network.peer import (
    PeerConnectionError,
    PeerManager,
)
from syncbridge.network.protocol import (
    Message,
    MessageType,
    receive_message,
    send_message,
)


def wait_for(predicate, timeout=2.0):
    until = time.monotonic() + timeout

    while time.monotonic() < until:
        if predicate():
            return True
        time.sleep(0.01)

    return predicate()


def make_peer(name="Node", **kwargs):
    options = {
        "bind_address": "127.0.0.1",
        "listen_port": 0,
        "handshake_timeout": 0.3,
        "heartbeat_interval": 0.08,
        "idle_timeout": 0.4,
    }
    options.update(kwargs)

    return PeerManager(
        uuid4().hex,
        name,
        **options,
    )


def test_outgoing_incoming_handshake():
    a = make_peer("A")
    b = make_peer("B")

    a.start()
    b.start()

    try:
        result = a.connect(
            "127.0.0.1",
            b.bound_port,
            expected_node_id=b.node_id,
        )

        assert result.node_id == b.node_id
        assert result.name == "B"
        assert not result.incoming
        assert result.port == b.bound_port

        assert wait_for(
            lambda: len(b.peers) == 1
        )
        assert b.peers[0].incoming
        assert b.peers[0].node_id == a.node_id
        assert b.peers[0].port == a.bound_port

        assert wait_for(
            lambda: len(a.peers) == 1
        )

    finally:
        a.stop()
        b.stop()


def test_heartbeat_keeps_connection_alive():
    a = make_peer()
    b = make_peer()

    a.start()
    b.start()

    try:
        a.connect(
            "127.0.0.1",
            b.bound_port,
        )

        time.sleep(0.8)

        assert len(a.peers) == 1
        assert len(b.peers) == 1

    finally:
        a.stop()
        b.stop()


def test_disconnect_notifies_both_sides():
    a_lost = []
    b_lost = []

    a = make_peer(
        on_disconnected=a_lost.append
    )
    b = make_peer(
        on_disconnected=b_lost.append
    )

    a.start()
    b.start()

    try:
        a.connect(
            "127.0.0.1",
            b.bound_port,
        )

        assert wait_for(
            lambda: len(b.peers) == 1
        )

        assert a.disconnect(b.node_id)
        assert not a.disconnect(b.node_id)

        assert wait_for(
            lambda: len(b.peers) == 0
        )

        assert wait_for(
            lambda: len(a_lost) == len(b_lost) == 1
        )

    finally:
        a.stop()
        b.stop()


def test_no_self_connection():
    a = make_peer()
    a.start()

    try:
        with pytest.raises(
            PeerConnectionError,
            match="own node",
        ):
            a.connect(
                "127.0.0.1",
                a.bound_port,
            )

        assert not a.peers

    finally:
        a.stop()


def test_wrong_expected_identity_rejected():
    a = make_peer()
    b = make_peer()

    a.start()
    b.start()

    try:
        with pytest.raises(
            PeerConnectionError,
            match="does not match",
        ):
            a.connect(
                "127.0.0.1",
                b.bound_port,
                expected_node_id=uuid4().hex,
            )

        assert not a.peers
        assert wait_for(
            lambda: not b.peers
        )

    finally:
        a.stop()
        b.stop()


def test_duplicate_connection_rejected():
    a = make_peer()
    b = make_peer()

    a.start()
    b.start()

    try:
        a.connect(
            "127.0.0.1",
            b.bound_port,
        )

        with pytest.raises(
            PeerConnectionError,
            match="Duplicate",
        ):
            a.connect(
                "127.0.0.1",
                b.bound_port,
            )

        assert len(a.peers) == 1

    finally:
        a.stop()
        b.stop()


def test_simultaneous_dial_converges_to_one_link():
    a = make_peer()
    b = make_peer()

    a.start()
    b.start()

    outcomes = []

    def dial(source, destination):
        try:
            source.connect(
                "127.0.0.1",
                destination.bound_port,
            )
        except PeerConnectionError as exc:
            outcomes.append(exc)

    try:
        thread_a = threading.Thread(
            target=dial,
            args=(a, b),
        )

        thread_b = threading.Thread(
            target=dial,
            args=(b, a),
        )

        thread_a.start()
        thread_b.start()

        thread_a.join(2)
        thread_b.join(2)

        assert not thread_a.is_alive()
        assert not thread_b.is_alive()

        assert wait_for(
            lambda: (
                len(a.peers) == len(b.peers) == 1
                and a.peers[0].incoming
                == (a.node_id > b.node_id)
                and b.peers[0].incoming
                == (b.node_id > a.node_id)
            )
        )

    finally:
        a.stop()
        b.stop()


def test_bad_first_message_is_rejected_without_killing_listener():
    errors = []
    a = make_peer(
        on_error=errors.append,
    )

    a.start()

    try:
        with socket.create_connection(
            ("127.0.0.1", a.bound_port),
            0.3,
        ) as connection:
            send_message(
                connection,
                Message(MessageType.PING),
            )

        assert wait_for(
            lambda: len(errors) > 0
        )

        assert a.is_running

        b = make_peer()
        b.start()

        try:
            b.connect(
                "127.0.0.1",
                a.bound_port,
            )

            assert wait_for(
                lambda: len(a.peers) == 1
            )

        finally:
            b.stop()

    finally:
        a.stop()


def test_handshake_timeout_unblocks_worker():
    errors = []

    a = make_peer(
        on_error=errors.append,
    )
    a.start()

    try:
        with socket.create_connection(
            ("127.0.0.1", a.bound_port),
            0.3,
        ):
            assert wait_for(
                lambda: len(errors) > 0,
                timeout=1.0,
            )

        assert a.is_running

    finally:
        a.stop()


def test_unexpected_post_handshake_control_closes_connection():
    errors = []

    a = make_peer(
        on_error=errors.append,
    )
    a.start()

    remote_node_id = uuid4().hex

    try:
        with socket.create_connection(
            ("127.0.0.1", a.bound_port),
            0.3,
        ) as connection:
            hello = Message(
                MessageType.HELLO,
                {
                    "node_id": remote_node_id,
                    "name": "Imposter",
                    "peer_port": 23450,
                },
            )

            send_message(
                connection,
                hello,
            )

            assert (
                receive_message(connection).kind
                is MessageType.HELLO_ACK
            )

            assert wait_for(
                lambda: len(a.peers) == 1
            )

            send_message(
                connection,
                Message(MessageType.HELLO),
            )

            assert wait_for(
                lambda: len(a.peers) == 0
            )

            assert any(
                isinstance(
                    error,
                    PeerConnectionError,
                )
                for error in errors
            )

    finally:
        a.stop()


def test_heartbeat_times_out_peer_not_answering_pings():
    errors = []
    lost = []

    a = make_peer(
        on_error=errors.append,
        on_disconnected=lost.append,
    )
    a.start()

    try:
        with socket.create_connection(
            ("127.0.0.1", a.bound_port),
            0.3,
        ) as connection:
            send_message(
                connection,
                Message(
                    MessageType.HELLO,
                    {
                        "node_id": uuid4().hex,
                        "name": "Silent",
                        "peer_port": 32450,
                    },
                ),
            )

            assert (
                receive_message(connection).kind
                is MessageType.HELLO_ACK
            )

            assert wait_for(
                lambda: len(a.peers) == 1
            )

            assert wait_for(
                lambda: len(lost) == 1,
                timeout=2.0,
            )

            assert any(
                "heartbeat" in str(error)
                for error in errors
            )

    finally:
        a.stop()


def test_restarts_and_clears_peers():
    a = make_peer()
    a.start()
    a.stop()
    a.start()

    try:
        assert a.is_running
        assert a.bound_port > 0
        assert a.peers == ()

    finally:
        a.stop()


def test_callback_can_stop_manager():
    done = threading.Event()
    a = make_peer()

    b = make_peer(
        on_connected=lambda peer: (
            b.stop(),
            done.set(),
        )
    )

    a.start()
    b.start()

    try:
        try:
            a.connect(
                "127.0.0.1",
                b.bound_port,
            )
        except (
            PeerConnectionError,
            RuntimeError,
        ):
            pass

        assert done.wait(2)
        assert not b.is_running

    finally:
        a.stop()
        b.stop()


def test_invalid_configuration_and_connect():
    with pytest.raises(ValueError):
        make_peer(
            idle_timeout=0.08
        )

    with pytest.raises(TypeError):
        make_peer(
            on_connected="bad"
        )

    a = make_peer()

    with pytest.raises(RuntimeError):
        a.connect(
            "127.0.0.1",
            1234,
        )

    a.start()

    try:
        with pytest.raises(ValueError):
            a.connect(
                "not-a-host",
                1234,
            )

        with pytest.raises(ValueError):
            a.connect(
                "127.0.0.1",
                0,
            )

        with pytest.raises(ValueError):
            a.connect(
                "127.0.0.1",
                1234,
                expected_node_id="bad",
            )

    finally:
        a.stop()


def test_rejects_mismatched_hello_ack_reference():
    listener = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    listener.bind(
        ("127.0.0.1", 0)
    )
    listener.listen(1)

    worker_finished = threading.Event()

    def respond_badly():
        try:
            with listener.accept()[0] as connection:
                assert (
                    receive_message(connection).kind
                    is MessageType.HELLO
                )

                send_message(
                    connection,
                    Message(
                        MessageType.HELLO_ACK,
                        {
                            "node_id": uuid4().hex,
                            "name": "Wrong ACK",
                            "peer_port": 23450,
                            "in_reply_to": uuid4().hex,
                        },
                    ),
                )
        finally:
            worker_finished.set()

    worker = threading.Thread(
        target=respond_badly
    )
    worker.start()

    manager = make_peer()
    manager.start()

    try:
        with pytest.raises(
            PeerConnectionError,
            match="does not match our HELLO",
        ):
            manager.connect(
                "127.0.0.1",
                listener.getsockname()[1],
            )

        assert manager.peers == ()
        assert worker_finished.wait(2)

    finally:
        listener.close()
        manager.stop()
        worker.join(2)


def test_connected_callback_error_does_not_break_peer():
    errors = []

    def bad_callback(peer):
        raise LookupError(
            "UI handler broke"
        )

    a = make_peer(
        on_connected=bad_callback,
        on_error=errors.append,
    )
    b = make_peer()

    a.start()
    b.start()

    try:
        a.connect(
            "127.0.0.1",
            b.bound_port,
        )

        assert wait_for(
            lambda: len(errors) == 1
        )

        assert isinstance(
            errors[0],
            LookupError,
        )

        assert len(a.peers) == 1

        assert wait_for(
            lambda: len(b.peers) == 1
        )

    finally:
        a.stop()
        b.stop()


def test_stop_closes_idle_incoming_handshakes():
    manager = make_peer(
        handshake_timeout=1.0,
    )
    manager.start()

    with socket.create_connection(
        ("127.0.0.1", manager.bound_port),
        timeout=1.0,
    ):
        assert wait_for(
            lambda: len(manager._pending) >= 1
        )

        manager.stop()
        assert not manager.is_running

    manager.start()

    try:
        assert manager.is_running

    finally:
        manager.stop()
