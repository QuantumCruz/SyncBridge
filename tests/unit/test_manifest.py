
"""Encrypted, authorized, read-only manifest exchange over real TCP sockets."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
from pathlib import Path
from uuid import uuid4

import pytest

from syncbridge.core.conflicts import ConflictResolver, SyncAction
from syncbridge.core.scanner import FileRecord, ScanError, ScanResult
from syncbridge.network.manifest import (
    MANIFEST_VERSION, ManifestError, ManifestService,
    _MAX_CONTROL_BYTES, _receive, _send,
)
from syncbridge.network.secure_channel import accept_secure_channel
from syncbridge.network.security import DeviceIdentity, TrustStore
from syncbridge.storage.shared_state import SharedStateDatabase


def setup_services(tmp_path, *, permitted=True, state=None):
    alice = DeviceIdentity.generate()
    bob = DeviceIdentity.generate()
    at = TrustStore(tmp_path / 'a-trust.json')
    bt = TrustStore(tmp_path / 'b-trust.json')
    at.add_verified(bob.public_key_hex, confirmed_fingerprint=bob.fingerprint, name='B')
    bt.add_verified(alice.public_key_hex, confirmed_fingerprint=alice.fingerprint, name='A')
    share = uuid4().hex
    root = tmp_path / 'shared'
    root.mkdir()
    opts = dict(bind_address='127.0.0.1', listen_port=0,
                handshake_timeout=1.5, io_timeout=3)
    reader = ManifestService(alice, at, **opts)
    server = ManifestService(bob, bt, {share: root},
                             allowed_readers={share: [alice.node_id] if permitted else []},
                             shared_state=state, **opts)
    server.start()
    return reader, server, root, share


def get(reader, server, share):
    return reader.fetch('127.0.0.1', server.bound_port, server.identity.node_id, share)


def fake_response_server(tmp_path, responder):
    a = DeviceIdentity.generate(); b = DeviceIdentity.generate()
    at = TrustStore(tmp_path / 'a-trust.json'); bt = TrustStore(tmp_path / 'b-trust.json')
    at.add_verified(b.public_key_hex, confirmed_fingerprint=b.fingerprint, name='B')
    bt.add_verified(a.public_key_hex, confirmed_fingerprint=a.fingerprint, name='A')
    client = ManifestService(a, at, bind_address='127.0.0.1', listen_port=0, handshake_timeout=1, io_timeout=2)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(2)
    errors = []

    def serve():
        try:
            conn, _ = listener.accept()
            with conn:
                secure, _ = accept_secure_channel(conn, b, bt, timeout=1)
                secure.settimeout(2)
                request, _ = _receive(secure, {'manifest_request'})
                responder(secure, request)
        except Exception as exc:
            errors.append(exc)
        finally:
            listener.close()
    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    return client, b, listener.getsockname()[1], worker, errors


def send_header(secure, request, *, count=1, revision=0, sha=None):
    _send(secure, 'manifest_start', request_id=request['request_id'], share_id=request['share_id'],
          file_count=count, baseline_revision=revision, baseline_sha256=sha)


def test_encrypted_nested_inventory_and_no_absolute_paths(tmp_path):
    client, server, root, share = setup_services(tmp_path)
    (root / 'nested').mkdir()
    data = os.urandom(150_000)
    (root / 'nested' / 'file.bin').write_bytes(data)
    (root / 'é.txt').write_text('bonjour', encoding='utf-8')
    before = {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    try:
        response = get(client, server, share)
        assert response.peer_node_id == server.identity.node_id
        assert response.baseline_revision == 0 and response.baseline_sha256 is None
        assert set(response.snapshot.files) == {'nested/file.bin', 'é.txt'}
        assert response.snapshot.files['nested/file.bin'].size == len(data)
        assert response.snapshot.files['nested/file.bin'].sha256 == hashlib.sha256(data).hexdigest()
        assert str(root) not in str(response.snapshot.root)
        assert {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*') if p.is_file()} == before
        assert response.inventory_sha256 != '0'*64
    finally:
        server.stop()


def test_empty_share(tmp_path):
    client, server, root, share = setup_services(tmp_path)
    try:
        response = get(client, server, share)
        assert response.snapshot.complete
        assert response.snapshot.files == {}
        assert len(response.inventory_sha256) == 64
    finally:
        server.stop()


def test_explicit_reader_grant_and_revoke(tmp_path):
    client, server, root, share = setup_services(tmp_path, permitted=False)
    (root/'topsecret.txt').write_text('private')
    try:
        with pytest.raises(ManifestError, match='not available'):
            get(client, server, share)
        server.authorize_reader(share, client.identity.node_id)
        assert 'topsecret.txt' in get(client, server, share).snapshot.files
        server.revoke_reader(share, client.identity.node_id)
        with pytest.raises(ManifestError, match='not available'):
            get(client, server, share)
    finally:
        server.stop()


def test_unknown_share_denied(tmp_path):
    client, server, _, share = setup_services(tmp_path)
    try:
        with pytest.raises(ManifestError, match='not available'):
            get(client, server, uuid4().hex)
    finally:
        server.stop()


def test_untrusted_requester_denied(tmp_path):
    client, server, root, share = setup_services(tmp_path)
    server.trust_store.remove(client.identity.node_id)
    try:
        with pytest.raises(ManifestError):
            get(client, server, share)
    finally:
        server.stop()


def test_local_unpaired_remote_denied(tmp_path):
    client, server, _, share = setup_services(tmp_path)
    client.trust_store.remove(server.identity.node_id)
    try:
        with pytest.raises(ManifestError, match='not paired'):
            get(client, server, share)
    finally:
        server.stop()


def test_unknown_other_reader_not_authorized(tmp_path):
    client, server, root, share = setup_services(tmp_path, permitted=False)
    other = DeviceIdentity.generate()
    server.authorize_reader(share, other.node_id)
    try:
        with pytest.raises(ManifestError, match='not available'):
            get(client, server, share)
    finally:
        server.stop()


def test_baseline_with_persisted_revision(tmp_path):
    state = SharedStateDatabase(tmp_path/'metadata.db')
    client, server, root, share = setup_services(tmp_path, state=state)
    (root/'a.txt').write_text('A')
    scanned = ScanResult(root=root.resolve(), files={
        'a.txt': FileRecord('a.txt', 1, 10, hashlib.sha256(b'A').hexdigest())
    })
    p = state.stage(root, client.identity.node_id, share, scanned, expected_revision=0)
    state.confirm_local(root, client.identity.node_id, share, p.proposal_id, scanned)
    state.confirm_remote(root, client.identity.node_id, share, p.proposal_id,
                         authenticated_peer_id=client.identity.node_id, acknowledged_sha256=p.sha256)
    state.finalize(root, client.identity.node_id, share, p.proposal_id, scanned)
    try:
        result = get(client, server, share)
        assert result.baseline_revision == 1
        assert result.baseline_sha256 == p.sha256
        assert result.inventory_sha256 == p.sha256
    finally:
        server.stop()


def test_multi_chunk_large_manifest(tmp_path, monkeypatch):
    from syncbridge.network import manifest as module

    sent_chunks = []
    original_send = module._send

    def observe(connection, kind, **fields):
        if kind == "manifest_chunk":
            sent_chunks.append(fields["index"])
        return original_send(connection, kind, **fields)

    monkeypatch.setattr(module, "_send", observe)
    client, server, root, share = setup_services(tmp_path)
    for n in range(800):
        (root / f'file-{n:04}-{"x" * 75}.txt').write_text(str(n))
    try:
        result = get(client, server, share)
        assert len(result.snapshot.files) == 800
        assert result.snapshot.files[f'file-0799-{"x" * 75}.txt'].size == 3
        assert len(sent_chunks) > 1
    finally:
        server.stop()


def test_scanner_incomplete_rejected(tmp_path, monkeypatch):
    client, server, root, share = setup_services(tmp_path)
    original = __import__('syncbridge.network.manifest', fromlist=['FileScanner']).FileScanner.scan
    def incomplete(self):
        output = original(self)
        output.errors.append(ScanError('locked.txt', 'locked'))
        return output
    monkeypatch.setattr('syncbridge.network.manifest.FileScanner.scan', incomplete)
    try:
        with pytest.raises(ManifestError, match='cannot be inventoried'):
            get(client, server, share)
    finally:
        server.stop()


def test_rejects_wrong_request_id(tmp_path):
    def bad(secure, request):
        _send(secure, 'manifest_start', request_id=uuid4().hex, share_id=request['share_id'],
              file_count=0, baseline_revision=0, baseline_sha256=None)
    client, b, port, worker, errors = fake_response_server(tmp_path, bad)
    with pytest.raises(ManifestError, match='does not match'):
        client.fetch('127.0.0.1', port, b.node_id, uuid4().hex)
    worker.join(2); assert not errors


def test_rejects_malformed_duplicate_paths(tmp_path):
    data = ['dup.txt', 1, hashlib.sha256(b'1').hexdigest()]
    def bad(secure, request):
        send_header(secure, request, count=2)
        _send(secure, 'manifest_chunk', request_id=request['request_id'], index=0, entries=[data, data])
    client, b, port, worker, errors = fake_response_server(tmp_path, bad)
    with pytest.raises(ManifestError, match='Duplicate'):
        client.fetch('127.0.0.1', port, b.node_id, uuid4().hex)
    worker.join(2); assert not errors


def test_rejects_invalid_filename(tmp_path):
    def bad(secure, request):
        send_header(secure, request)
        _send(secure, 'manifest_chunk', request_id=request['request_id'], index=0,
              entries=[['../evil.txt', 1, hashlib.sha256(b'a').hexdigest()]])
        _send(secure, 'manifest_end', request_id=request['request_id'], file_count=1,
              inventory_sha256='0'*64)
    client, b, port, worker, errors = fake_response_server(tmp_path, bad)
    with pytest.raises(ManifestError, match='Unsafe remote manifest'):
        client.fetch('127.0.0.1', port, b.node_id, uuid4().hex)
    worker.join(2); assert not errors


def test_rejects_wrong_digest(tmp_path):
    def bad(secure, request):
        send_header(secure, request, count=0)
        _send(secure, 'manifest_end', request_id=request['request_id'], file_count=0,
              inventory_sha256='f'*64)
    client, b, port, worker, errors = fake_response_server(tmp_path, bad)
    with pytest.raises(ManifestError, match='integrity digest mismatch'):
        client.fetch('127.0.0.1', port, b.node_id, uuid4().hex)
    worker.join(2); assert not errors


def test_rejects_invalid_baseline_revision(tmp_path):
    def bad(secure, request):
        send_header(secure, request, count=0, revision=1, sha=None)
    client, b, port, worker, errors = fake_response_server(tmp_path, bad)
    with pytest.raises(ManifestError, match='baseline digest'):
        client.fetch('127.0.0.1', port, b.node_id, uuid4().hex)
    worker.join(2); assert not errors


def test_rejects_out_of_order_chunk(tmp_path):
    def bad(secure, request):
        send_header(secure, request)
        _send(secure, 'manifest_chunk', request_id=request['request_id'], index=1,
              entries=[['a.txt', 1, hashlib.sha256(b'a').hexdigest()]])
    client, b, port, worker, errors = fake_response_server(tmp_path, bad)
    with pytest.raises(ManifestError, match='Out-of-order'):
        client.fetch('127.0.0.1', port, b.node_id, uuid4().hex)
    worker.join(2); assert not errors


def test_manifest_can_feed_conflict_resolver(tmp_path):
    client, server, root, share = setup_services(tmp_path)
    (root/'remote.txt').write_text('R')
    local = tmp_path/'local'; local.mkdir()
    try:
        result = get(client, server, share)
        plan = ConflictResolver.plan(ScanResult(root=local.resolve()), result.snapshot)
        assert len(plan.downloads) == 1
        assert plan.downloads[0].action is SyncAction.DOWNLOAD
    finally:
        server.stop()


def test_stop_restart(tmp_path):
    client, server, root, share = setup_services(tmp_path)
    first = server.bound_port
    server.stop()
    assert not server.is_running and server.bound_port is None
    server.start()
    try:
        assert server.bound_port is not None
        assert get(client, server, share).snapshot.complete
    finally:
        server.stop()


def test_invalid_inputs(tmp_path):
    identity = DeviceIdentity.generate()
    store = TrustStore(tmp_path/'trust.json')
    root = tmp_path/'root'; root.mkdir()
    with pytest.raises(ValueError):
        ManifestService(identity, store, {"bad":root})
    with pytest.raises(ValueError):
        ManifestService(identity, store, {uuid4().hex:root}, listen_port=True)
    with pytest.raises(ValueError):
        ManifestService(identity, store, {uuid4().hex:root}, io_timeout=float('inf'))
    with pytest.raises(ValueError):
        ManifestService(identity, store, {uuid4().hex:root}, allowed_readers={uuid4().hex: []})


def test_register_share_does_not_grant_access(tmp_path):
    client, server, root, share = setup_services(tmp_path, permitted=False)
    another = tmp_path / 'other'; another.mkdir()
    new_share = uuid4().hex
    server.register_share(new_share, another)
    try:
        with pytest.raises(ManifestError, match='not available'):
            get(client, server, new_share)
        server.authorize_reader(new_share, client.identity.node_id)
        assert get(client, server, new_share).snapshot.files == {}
        with pytest.raises(ValueError):
            server.register_share(new_share, root)
    finally:
        server.stop()


def test_rejects_file_directory_collision(tmp_path):
    data = hashlib.sha256(b'1').hexdigest()
    def bad(secure, request):
        send_header(secure, request, count=2)
        _send(secure, 'manifest_chunk', request_id=request['request_id'], index=0,
              entries=[['a', 1, data], ['a/x', 1, data]])
        _send(secure, 'manifest_end', request_id=request['request_id'], file_count=2,
              inventory_sha256='0'*64)
    client, b, port, worker, errors = fake_response_server(tmp_path, bad)
    with pytest.raises(ManifestError, match='Unsafe remote manifest'):
        client.fetch('127.0.0.1', port, b.node_id, uuid4().hex)
    worker.join(2); assert not errors


def test_rejects_oversized_control_frame_before_read():
    left, right = socket.socketpair()
    try:
        left.sendall(((_MAX_CONTROL_BYTES + 1).to_bytes(4, "big")))
        with pytest.raises(ManifestError, match="frame length"):
            _receive(right, {"manifest_start"})
    finally:
        left.close()
        right.close()


def test_rejects_duplicate_json_control_keys():
    left, right = socket.socketpair()
    try:
        raw = b'{"version":1,"version":1,"type":"manifest_start"}'
        left.sendall(len(raw).to_bytes(4, "big") + raw)
        with pytest.raises(ManifestError, match="Malformed"):
            _receive(right, {"manifest_start"})
    finally:
        left.close()
        right.close()


def test_client_rejects_unusable_ip_and_invalid_port(tmp_path):
    identity = DeviceIdentity.generate()
    store = TrustStore(tmp_path / "trust.json")
    client = ManifestService(identity, store, bind_address="127.0.0.1", listen_port=0)
    for host in ("not-an-ip", "0.0.0.0", "255.255.255.255", 123):
        with pytest.raises(ValueError):
            client.fetch(host, 34567, uuid4().hex, uuid4().hex)
    for port in (0, 65536, True):
        with pytest.raises(ValueError):
            client.fetch("127.0.0.1", port, uuid4().hex, uuid4().hex)
