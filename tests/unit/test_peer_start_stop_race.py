
"""Regression: stopping an incoming peer may race with its thread startup."""
from __future__ import annotations

import socket
import threading

from syncbridge.network.peer import PeerManager


def test_stop_waits_until_incoming_worker_has_started(monkeypatch):
    """Make the old register-before-start race deterministic."""
    manager = PeerManager(
        node_id="a" * 32,
        name="Alice",
        listen_port=0,
        bind_address="127.0.0.1",
        handshake_timeout=1.0,
    )
    manager.start()

    about_to_start = threading.Event()
    allow_start = threading.Event()
    stop_finished = threading.Event()
    errors: list[BaseException] = []
    original_start = threading.Thread.start

    def delayed_start(thread: threading.Thread) -> None:
        if thread.name == "SyncBridge-_inbound":
            about_to_start.set()
            if not allow_start.wait(timeout=5):
                raise TimeoutError("Test did not release the worker startup")
        original_start(thread)

    monkeypatch.setattr(threading.Thread, "start", delayed_start)

    def stop_manager() -> None:
        try:
            manager.stop()
        except BaseException as exc:
            errors.append(exc)
        finally:
            stop_finished.set()

    stopper: threading.Thread | None = None
    try:
        with socket.create_connection(("127.0.0.1", manager.bound_port), timeout=2):
            assert about_to_start.wait(timeout=3), "No incoming worker was created"
            stopper = threading.Thread(target=stop_manager, name="TestStopper")
            stopper.start()

            # stop() must not finish (or raise) before the new worker starts.
            assert not stop_finished.wait(timeout=0.1)

            allow_start.set()
            stopper.join(timeout=5)

            assert not stopper.is_alive()
            assert not errors, errors
            assert not manager.is_running
    finally:
        allow_start.set()
        if stopper is not None:
            stopper.join(timeout=5)
        manager.stop()
