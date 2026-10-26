
"""Real authenticated sockets: folder change requires a live, consenting peer."""
from __future__ import annotations

from threading import Event

import pytest

from syncbridge.network.folder_change_session import (
    FolderChangeSessionClient,
    FolderChangeSessionService,
)
from syncbridge.network.security import DeviceIdentity, TrustStore
from syncbridge.network.session_control import new_session_id

SHARE = "a" * 32


def _trust(path, other):
    trust = TrustStore(path)
    trust.add_verified(
        other.public_key_hex,
        confirmed_fingerprint=other.fingerprint,
        name="Trusted peer",
    )
    return trust


@pytest.fixture
def peers(tmp_path):
    alice = DeviceIdentity.generate()
    bob = DeviceIdentity.generate()
    alice_trust = _trust(tmp_path / "alice-trust.json", bob)
    bob_trust = _trust(tmp_path / "bob-trust.json", alice)
    invited, preparing, committed = Event(), Event(), Event()

    def notify(kind, sid):
        if kind == "folder-change-invite":
            invited.set()
        elif kind == "folder-change-prepare":
            preparing.set()
        elif kind == "folder-change-committed":
            committed.set()

    a = FolderChangeSessionService(
        alice, alice_trust, SHARE, bob.node_id,
        bind_address="127.0.0.1", port=0,
    )
    b = FolderChangeSessionService(
        bob, bob_trust, SHARE, alice.node_id,
        bind_address="127.0.0.1", port=0, on_event=notify,
    )
    a.start()
    b.start()
    client = FolderChangeSessionClient(alice, alice_trust)

    def send(sid, action):
        return client.request(
            "127.0.0.1", b.bound_port, bob.node_id, SHARE, sid, action,
        )

    try:
        yield a, b, send, invited, preparing, committed
    finally:
        a.stop()
        b.stop()


def _connect(a, b, send):
    sid = new_session_id()
    assert send(sid, "session_invite") == "waiting"
    assert b.approve(sid)
    a.activate_outgoing(sid)
    assert send(sid, "session_commit") == "active"
    return sid


def test_disconnected_cannot_request_folder_change(peers):
    _, _, send, _, _, _ = peers
    assert send(new_session_id(), "folder_change_invite") == "closed"


def test_declining_keeps_active_connection(peers):
    a, b, send, invited, _, _ = peers
    sid = _connect(a, b, send)
    assert send(sid, "folder_change_invite") == "waiting"
    assert invited.wait(2)
    assert send(sid, "folder_change_commit") == "waiting"
    b.reject_folder_change(sid)
    assert send(sid, "folder_change_status") == "denied"
    assert send(sid, "folder_change_prepare") == "denied"
    assert send(sid, "session_ping") == "active"
    assert a.active_session == sid and b.active_session == sid


def test_both_approve_prepare_and_commit(peers):
    a, b, send, invited, preparing, committed = peers
    sid = _connect(a, b, send)
    assert send(sid, "folder_change_invite") == "waiting"
    assert invited.wait(2)
    assert b.approve_folder_change(sid)
    assert send(sid, "folder_change_status") == "approved"
    assert send(sid, "folder_change_commit") == "approved"
    assert send(sid, "folder_change_prepare") == "preparing"
    assert preparing.wait(2)
    assert send(sid, "folder_change_commit") == "preparing"
    assert b.ready_folder_change(sid)
    assert send(sid, "folder_change_status") == "ready"
    assert send(sid, "folder_change_commit") == "committed"
    assert committed.wait(2)
    assert send(sid, "folder_change_commit") == "committed"


def test_cancel_before_commit_keeps_live_session(peers):
    a, b, send, _, _, committed = peers
    sid = _connect(a, b, send)
    assert send(sid, "folder_change_invite") == "waiting"
    assert b.approve_folder_change(sid)
    assert send(sid, "folder_change_cancel") == "closed"
    assert send(sid, "folder_change_status") == "closed"
    assert not committed.is_set()
    assert send(sid, "session_ping") == "active"


def test_old_or_foreign_session_cannot_change_folders(peers):
    a, b, send, _, _, _ = peers
    sid = _connect(a, b, send)
    other = new_session_id()
    assert send(other, "folder_change_invite") == "closed"
    assert not b.approve_folder_change(other)
    assert not b.ready_folder_change(other)
    assert send(sid, "session_ping") == "active"
    assert send(sid, "session_leave") == "closed"
    assert send(sid, "folder_change_invite") == "closed"
