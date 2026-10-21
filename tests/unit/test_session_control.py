
"""Live-session negotiation over authenticated localhost connections."""
from __future__ import annotations

from threading import Event

import pytest

from syncbridge.network.security import DeviceIdentity, TrustStore
from syncbridge.network.session_control import (
    PeerSessionClient,
    PeerSessionService,
    SessionControlError,
    new_session_id,
    session_port_for_transfer,
)


SHARE = "a" * 32


def _trust(path, other):
    store = TrustStore(path)
    store.add_verified(
        other.public_key_hex,
        confirmed_fingerprint=other.fingerprint,
        name="Trusted computer",
    )
    return store


@pytest.fixture
def computers(tmp_path):
    alice = DeviceIdentity.generate()
    bob = DeviceIdentity.generate()

    alice_trust = _trust(tmp_path / "alice.json", bob)
    bob_trust = _trust(tmp_path / "bob.json", alice)

    alice_events = []
    bob_events = []
    incoming = Event()
    departed = Event()

    def bob_event(kind, session):
        bob_events.append((kind, session))
        if kind == "invite":
            incoming.set()
        if kind == "left":
            departed.set()

    alice_service = PeerSessionService(
        alice,
        alice_trust,
        SHARE,
        bob.node_id,
        bind_address="127.0.0.1",
        port=0,
        on_event=lambda k, s: alice_events.append((k, s)),
    )

    bob_service = PeerSessionService(
        bob,
        bob_trust,
        SHARE,
        alice.node_id,
        bind_address="127.0.0.1",
        port=0,
        on_event=bob_event,
    )

    alice_service.start()
    bob_service.start()

    try:
        yield {
            "alice": alice,
            "bob": bob,
            "alice_service": alice_service,
            "bob_service": bob_service,
            "alice_client": PeerSessionClient(
                alice, alice_trust
            ),
            "bob_client": PeerSessionClient(
                bob, bob_trust
            ),
            "alice_events": alice_events,
            "bob_events": bob_events,
            "incoming": incoming,
            "departed": departed,
        }
    finally:
        alice_service.stop()
        bob_service.stop()


def _alice_to_bob(peers, session, action):
    return peers["alice_client"].request(
        "127.0.0.1",
        peers["bob_service"].bound_port,
        peers["bob"].node_id,
        SHARE,
        session,
        action,
    )


def _bob_to_alice(peers, session, action):
    return peers["bob_client"].request(
        "127.0.0.1",
        peers["alice_service"].bound_port,
        peers["alice"].node_id,
        SHARE,
        session,
        action,
    )


def test_existing_pairing_does_not_mean_connected(computers):
    peers = computers
    session = new_session_id()

    assert peers["alice_service"].active_session is None
    assert peers["bob_service"].active_session is None

    assert _alice_to_bob(
        peers, session, "session_ping"
    ) == "closed"

    assert _bob_to_alice(
        peers, session, "session_ping"
    ) == "closed"


def test_connection_requires_approval_and_commit(computers):
    peers = computers
    session = new_session_id()

    assert _alice_to_bob(
        peers, session, "session_invite"
    ) == "waiting"

    assert peers["incoming"].wait(2.0)
    assert ("invite", session) in peers["bob_events"]

    assert _alice_to_bob(
        peers, session, "session_status"
    ) == "waiting"

    assert _alice_to_bob(
        peers, session, "session_commit"
    ) == "closed"

    assert peers["bob_service"].active_session is None

    assert peers["bob_service"].approve(session)

    assert _alice_to_bob(
        peers, session, "session_status"
    ) == "approved"

    # Represents Alice successfully starting her guarded runtime.
    peers["alice_service"].activate_outgoing(session)

    assert _alice_to_bob(
        peers, session, "session_commit"
    ) == "active"

    assert peers["alice_service"].active_session == session
    assert peers["bob_service"].active_session == session

    assert _alice_to_bob(
        peers, session, "session_ping"
    ) == "active"

    assert _bob_to_alice(
        peers, session, "session_ping"
    ) == "active"


def test_disconnect_invalidates_live_session(computers):
    peers = computers
    session = new_session_id()

    assert _alice_to_bob(
        peers, session, "session_invite"
    ) == "waiting"

    assert peers["bob_service"].approve(session)
    peers["alice_service"].activate_outgoing(session)

    assert _alice_to_bob(
        peers, session, "session_commit"
    ) == "active"

    assert _alice_to_bob(
        peers, session, "session_leave"
    ) == "closed"

    assert peers["departed"].wait(2.0)
    assert peers["bob_service"].active_session is None
    assert ("left", session) in peers["bob_events"]

    peers["alice_service"].clear(session)

    assert _alice_to_bob(
        peers, session, "session_ping"
    ) == "closed"

    assert _bob_to_alice(
        peers, session, "session_ping"
    ) == "closed"


def test_old_session_cannot_resume_after_service_restart(
    computers,
):
    peers = computers
    session = new_session_id()
    service = peers["bob_service"]

    assert _alice_to_bob(
        peers, session, "session_invite"
    ) == "waiting"

    assert service.approve(session)

    peers["alice_service"].activate_outgoing(session)

    assert _alice_to_bob(
        peers, session, "session_commit"
    ) == "active"

    service.stop()
    service.start()

    assert service.active_session is None

    assert _alice_to_bob(
        peers, session, "session_ping"
    ) == "closed"

    assert _alice_to_bob(
        peers, session, "session_commit"
    ) == "closed"

    # A new session must require its own invitation and approval.
    fresh = new_session_id()
    assert fresh != session

    assert _alice_to_bob(
        peers, fresh, "session_invite"
    ) == "waiting"


def test_competing_invitation_is_refused(computers):
    peers = computers
    first = new_session_id()
    second = new_session_id()

    assert _alice_to_bob(
        peers, first, "session_invite"
    ) == "waiting"

    assert _alice_to_bob(
        peers, second, "session_invite"
    ) == "denied"

    assert peers["bob_service"].approve(first)

    assert _alice_to_bob(
        peers, first, "session_status"
    ) == "approved"


def test_rejected_invitation_cannot_be_committed(computers):
    peers = computers
    session = new_session_id()

    assert _alice_to_bob(
        peers, session, "session_invite"
    ) == "waiting"

    peers["bob_service"].reject(session)

    assert _alice_to_bob(
        peers, session, "session_status"
    ) == "denied"

    assert _alice_to_bob(
        peers, session, "session_commit"
    ) == "closed"

    assert peers["bob_service"].active_session is None


def test_wrong_share_cannot_connect(computers):
    peers = computers
    session = new_session_id()

    with pytest.raises(SessionControlError):
        peers["alice_client"].request(
            "127.0.0.1",
            peers["bob_service"].bound_port,
            peers["bob"].node_id,
            "b" * 32,
            session,
            "session_invite",
        )

    assert peers["bob_service"].pending_invitation is None


def test_unpaired_computer_cannot_connect(computers, tmp_path):
    peers = computers
    stranger = DeviceIdentity.generate()
    empty_trust = TrustStore(
        tmp_path / "stranger.json"
    )

    client = PeerSessionClient(
        stranger,
        empty_trust,
    )

    with pytest.raises(SessionControlError):
        client.request(
            "127.0.0.1",
            peers["bob_service"].bound_port,
            peers["bob"].node_id,
            SHARE,
            new_session_id(),
            "session_invite",
        )


def test_port_selection_and_fresh_ids():
    assert session_port_for_transfer(45842) == 45850

    assert (
        session_port_for_transfer(55142)
        != session_port_for_transfer(55242)
    )

    first = new_session_id()
    second = new_session_id()

    assert first != second
    assert len(first) == len(second) == 32
