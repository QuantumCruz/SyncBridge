
"""Persistent trust, Ed25519 proofs and mutual TCP authentication tests."""

from __future__ import annotations

import json
import os
import socket
import struct
import threading
from pathlib import Path

import pytest

from syncbridge.network.security import (
    AuthenticationError,
    DeviceIdentity,
    PairingError,
    SecurityError,
    TrustStore,
    authenticate_initiator,
    authenticate_responder,
    load_or_create_identity,
)


def identities(tmp_path: Path):
    alice = load_or_create_identity(tmp_path / "alice" / "identity.json")
    bob = load_or_create_identity(tmp_path / "bob" / "identity.json")
    a = TrustStore(tmp_path / "alice" / "trust.json")
    b = TrustStore(tmp_path / "bob" / "trust.json")
    return alice, bob, a, b


def pair_both(alice, bob, a, b):
    a.add_verified(
        bob.public_key_hex, confirmed_fingerprint=bob.fingerprint,
        name="Bob", own_node_id=alice.node_id,
    )
    b.add_verified(
        alice.public_key_hex, confirmed_fingerprint=alice.fingerprint,
        name="Alice", own_node_id=bob.node_id,
    )


def handshake(alice, bob, a, b):
    left, right = socket.socketpair()
    successes = []
    errors = []

    def responder():
        try:
            successes.append(authenticate_responder(right, bob, b, timeout=1.5))
        except Exception as exc:
            errors.append(exc)
        finally:
            right.close()

    worker = threading.Thread(target=responder)
    worker.start()
    try:
        result = authenticate_initiator(left, alice, a, bob.node_id, timeout=1.5)
    finally:
        left.close()
        worker.join(3)
    assert not worker.is_alive()
    assert not errors
    return result, successes[0]


def test_identity_is_persistent_and_matches_public_key(tmp_path):
    path = tmp_path / "private" / "identity.json"
    original = load_or_create_identity(path)
    reloaded = load_or_create_identity(path)
    assert original.node_id == reloaded.node_id
    assert original.public_key == reloaded.public_key
    assert len(original.public_key) == 32
    assert len(original.fingerprint) == 64
    assert original.node_id == original.fingerprint[:32]
    assert len(original.sign(b"check")) == 64
    assert "private_key" not in repr(original)
    assert "private_key" not in repr(reloaded)


def test_different_installations_have_distinct_ids(tmp_path):
    first = load_or_create_identity(tmp_path / "a.json")
    second = load_or_create_identity(tmp_path / "b.json")
    assert first.node_id != second.node_id


def test_corrupted_or_mismatched_identity_never_overwritten(tmp_path):
    path = tmp_path / "identity.json"
    load_or_create_identity(path)
    obj = json.loads(path.read_text())
    obj["public_key"] = "0" * 64
    path.write_text(json.dumps(obj))
    before = path.read_bytes()
    with pytest.raises(SecurityError):
        load_or_create_identity(path)
    assert path.read_bytes() == before


def test_symlink_identity_rejected(tmp_path):
    private = tmp_path / "actual.json"
    load_or_create_identity(private)
    alias = tmp_path / "alias.json"
    try:
        alias.symlink_to(private)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks require Windows developer mode or permissions")
    with pytest.raises(SecurityError):
        load_or_create_identity(alias)


def test_rejects_bogus_version_and_duplicate_json_keys(tmp_path):
    path = tmp_path / "identity.json"
    ident = load_or_create_identity(path)
    obj = json.loads(path.read_text())
    obj["version"] = True
    path.write_text(json.dumps(obj))
    with pytest.raises(SecurityError):
        load_or_create_identity(path)
    obj["version"] = 1
    data = json.dumps(obj).replace('"version": 1', '"version": 1, "version": 1')
    path.write_text(data)
    with pytest.raises(SecurityError):
        load_or_create_identity(path)
    assert ident.node_id != "0" * 32


def test_store_starts_empty_and_survives_restart(tmp_path):
    alice, bob, a, b = identities(tmp_path)
    assert a.devices == ()
    a.add_verified(bob.public_key_hex, confirmed_fingerprint=bob.fingerprint, name="Bob")
    restored = TrustStore(a.path)
    assert restored.get(bob.node_id) == a.get(bob.node_id)
    assert restored.devices[0].fingerprint == bob.fingerprint


def test_wrong_fingerprint_must_not_pair(tmp_path):
    alice, bob, a, _ = identities(tmp_path)
    with pytest.raises(PairingError):
        a.add_verified(
            bob.public_key_hex, confirmed_fingerprint=alice.fingerprint, name="Bob",
        )
    assert a.devices == ()
    assert not a.path.exists()


def test_only_own_explicitly_confirmed_key_is_trusted(tmp_path):
    alice, bob, a, b = identities(tmp_path)
    with pytest.raises(PairingError, match="local"):
        a.add_verified(alice.public_key_hex, confirmed_fingerprint=alice.fingerprint,
                       name="Alice", own_node_id=alice.node_id)
    a.add_verified(bob.public_key_hex, confirmed_fingerprint=bob.fingerprint,
                   name="Bob")
    with pytest.raises(AuthenticationError):
        a.require(DeviceIdentity.generate().public_key)
    assert a.require(bob.public_key).node_id == bob.node_id


def test_repair_same_key_updates_name_without_changing_timestamp(tmp_path):
    alice, bob, a, b = identities(tmp_path)
    old = a.add_verified(bob.public_key_hex, confirmed_fingerprint=bob.fingerprint,
                         name="Old name")
    new = a.add_verified(bob.public_key_hex, confirmed_fingerprint=bob.fingerprint,
                         name="New name")
    assert new.added_at == old.added_at
    assert new.name == "New name"
    assert len(a.devices) == 1
    assert TrustStore(a.path).devices[0].name == "New name"


def test_revocation_persists(tmp_path):
    alice, bob, a, b = identities(tmp_path)
    pair_both(alice, bob, a, b)
    assert a.remove(bob.node_id)
    assert not a.remove(bob.node_id)
    assert TrustStore(a.path).devices == ()
    with pytest.raises(AuthenticationError):
        a.require(bob.public_key)


def test_corrupt_trust_store_refuses_to_load(tmp_path):
    alice, bob, a, b = identities(tmp_path)
    pair_both(alice, bob, a, b)
    doc = json.loads(a.path.read_text())
    doc["devices"][0]["fingerprint"] = "0" * 64
    a.path.write_text(json.dumps(doc))
    with pytest.raises(SecurityError):
        TrustStore(a.path)
    with pytest.raises(SecurityError):
        a.remove(bob.node_id)


def test_rejects_invalid_device_names(tmp_path):
    alice, bob, a, b = identities(tmp_path)
    for bad in ["", " \t", "line\nbreak", "z" * 129, 123]:
        with pytest.raises(SecurityError):
            a.add_verified(bob.public_key_hex, confirmed_fingerprint=bob.fingerprint,
                           name=bad)
    assert a.devices == ()


def test_mutual_authentication_both_directions(tmp_path):
    alice, bob, a, b = identities(tmp_path)
    pair_both(alice, bob, a, b)
    peer_at_alice, peer_at_bob = handshake(alice, bob, a, b)
    assert peer_at_alice.node_id == bob.node_id
    assert peer_at_bob.node_id == alice.node_id
    peer_at_bob2, peer_at_alice2 = handshake(bob, alice, b, a)
    assert peer_at_bob2.node_id == alice.node_id
    assert peer_at_alice2.node_id == bob.node_id


def test_initiator_refuses_unpaired_peer(tmp_path):
    alice, bob, a, b = identities(tmp_path)
    left, right = socket.socketpair()
    try:
        with pytest.raises(AuthenticationError, match="not paired"):
            authenticate_initiator(left, alice, a, bob.node_id)
    finally:
        left.close()
        right.close()


def test_responder_rejects_unpaired_initiator(tmp_path):
    alice, bob, a, b = identities(tmp_path)
    a.add_verified(bob.public_key_hex, confirmed_fingerprint=bob.fingerprint,
                   name="Bob")
    left, right = socket.socketpair()
    failures = []

    def responder():
        try:
            authenticate_responder(right, bob, b, timeout=0.6)
        except AuthenticationError as exc:
            failures.append(exc)
        finally:
            right.close()

    worker = threading.Thread(target=responder)
    worker.start()
    try:
        with pytest.raises(AuthenticationError):
            authenticate_initiator(left, alice, a, bob.node_id, timeout=0.6)
    finally:
        left.close()
        worker.join(2)
    assert len(failures) == 1
    assert "not paired" in str(failures[0])


def test_wrong_trusted_responder_key_is_rejected(tmp_path):
    alice, bob, a, b = identities(tmp_path)
    rogue = DeviceIdentity.generate()
    a.add_verified(bob.public_key_hex, confirmed_fingerprint=bob.fingerprint, name="Bob")
    b.add_verified(alice.public_key_hex, confirmed_fingerprint=alice.fingerprint, name="Alice")
    left, right = socket.socketpair()
    results = []

    def rogue_responder():
        try:
            authenticate_responder(right, rogue, b, timeout=0.6)
        except AuthenticationError as exc:
            results.append(exc)
        finally:
            right.close()

    worker = threading.Thread(target=rogue_responder)
    worker.start()
    try:
        with pytest.raises(AuthenticationError, match="differs"):
            authenticate_initiator(left, alice, a, bob.node_id, timeout=0.6)
    finally:
        left.close()
        worker.join(2)
    assert not worker.is_alive()


def test_mismatched_initiator_proof_rejected(tmp_path):
    alice, bob, a, b = identities(tmp_path)
    pair_both(alice, bob, a, b)
    left, right = socket.socketpair()
    received_errors = []

    def responder():
        try:
            authenticate_responder(right, bob, b, timeout=0.8)
        except AuthenticationError as exc:
            received_errors.append(exc)
        finally:
            right.close()

    worker = threading.Thread(target=responder)
    worker.start()
    try:
        init = json.dumps({
            "version": 1, "type": "init", "public_key": alice.public_key_hex,
            "nonce": os.urandom(32).hex(),
        }).encode()
        left.sendall(struct.pack("!I", len(init)) + init)
        header = bytearray()
        while len(header) < 4:
            chunk = left.recv(4 - len(header))
            assert chunk
            header.extend(chunk)
        count = struct.unpack("!I", header)[0]
        answer = bytearray()
        while len(answer) < count:
            chunk = left.recv(count - len(answer))
            assert chunk
            answer.extend(chunk)
        assert json.loads(answer)["type"] == "challenge"
        bad = json.dumps({"version": 1, "type": "proof", "signature": "00" * 64}).encode()
        left.sendall(struct.pack("!I", len(bad)) + bad)
    finally:
        left.close()
        worker.join(2)
    assert len(received_errors) == 1
    assert "signature" in str(received_errors[0])


def test_rejects_malformed_authentication_frames(tmp_path):
    alice, bob, a, b = identities(tmp_path)
    left, right = socket.socketpair()
    try:
        left.sendall(struct.pack("!I", 65536))
        with pytest.raises(AuthenticationError, match="length"):
            authenticate_responder(right, bob, b, timeout=0.3)
    finally:
        left.close()
        right.close()


def test_timeout_is_restored_after_success(tmp_path):
    alice, bob, a, b = identities(tmp_path)
    pair_both(alice, bob, a, b)
    left, right = socket.socketpair()
    left.settimeout(2.0)
    right.settimeout(2.0)
    result = []
    thread = threading.Thread(target=lambda: result.append(
        authenticate_responder(right, bob, b, timeout=1.2)
    ))
    thread.start()
    try:
        assert authenticate_initiator(left, alice, a, bob.node_id, timeout=1.2)
        assert left.gettimeout() == 2.0
        thread.join(2)
        assert right.gettimeout() == 2.0
        assert len(result) == 1
    finally:
        left.close()
        right.close()
        thread.join(2)


def test_bad_timeouts_rejected_before_socket_io(tmp_path):
    alice, bob, a, b = identities(tmp_path)
    pair_both(alice, bob, a, b)
    left, right = socket.socketpair()
    try:
        for timeout in [0, -1, float("nan"), float("inf"), True]:
            with pytest.raises(ValueError):
                authenticate_initiator(left, alice, a, bob.node_id, timeout=timeout)
            with pytest.raises(ValueError):
                authenticate_responder(right, bob, b, timeout=timeout)
    finally:
        left.close()
        right.close()


def test_security_files_are_restrictive_on_posix(tmp_path):
    if os.name == "nt":
        pytest.skip("NTFS file permissions are ACL-based")
    alice, bob, a, b = identities(tmp_path)
    pair_both(alice, bob, a, b)
    assert ((tmp_path / "alice" / "identity.json").stat().st_mode & 0o077) == 0
    assert (a.path.stat().st_mode & 0o077) == 0


def test_parallel_creation_never_produces_two_identities(tmp_path):
    path = tmp_path / "private" / "identity.json"
    identities_found = []
    failures = []

    def create():
        try:
            identities_found.append(load_or_create_identity(path).node_id)
        except Exception as exc:
            failures.append(exc)

    workers = [threading.Thread(target=create) for _ in range(12)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(3)
    assert not failures
    assert len(identities_found) == 12
    assert len(set(identities_found)) == 1


def test_revocation_is_visible_across_store_instances(tmp_path):
    alice, bob, a, b = identities(tmp_path)
    pair_both(alice, bob, a, b)
    another = TrustStore(a.path)
    assert another.require(bob.public_key)
    assert a.remove(bob.node_id)
    with pytest.raises(AuthenticationError, match="not paired"):
        another.require(bob.public_key)
    assert another.get(bob.node_id) is None


def test_authentication_over_real_localhost_tcp(tmp_path):
    alice, bob, a, b = identities(tmp_path)
    pair_both(alice, bob, a, b)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(2)
    accepted = []
    failures = []

    def serve():
        try:
            with listener.accept()[0] as incoming:
                accepted.append(authenticate_responder(incoming, bob, b))
        except Exception as exc:
            failures.append(exc)

    worker = threading.Thread(target=serve)
    worker.start()
    try:
        with socket.create_connection(listener.getsockname(), timeout=2) as outgoing:
            remote = authenticate_initiator(outgoing, alice, a, bob.node_id)
            assert remote.node_id == bob.node_id
        worker.join(3)
        assert not worker.is_alive()
        assert not failures
        assert len(accepted) == 1
        assert accepted[0].node_id == alice.node_id
    finally:
        listener.close()
        worker.join(3)
