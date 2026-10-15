
"""Authenticated baseline-commit RPC, with one request per encrypted TCP session.

The storage backend retains pending proposals across crashes. A commit is
performed on the receiving side first; a coordinator may then finalize locally.
There is no atomic commit across two independent machines: on interruption,
the coordinator must retry the same durable proposal, not start a new sync.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import math
import os
import socket
import struct
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from syncbridge.core.scanner import FileScanner
from syncbridge.storage.shared_state import SharedStateDatabase, _canonical_rows, _digest
from .secure_channel import accept_secure_channel, open_secure_channel
from .security import DeviceIdentity, SecurityError, TrustStore

logger = logging.getLogger(__name__)
VERSION = 1
DEFAULT_AGREEMENT_PORT = 45844
_MAX_FRAME = 2048
_MAX_CLIENTS = 8
_HEX = frozenset('0123456789abcdef')


class AgreementError(RuntimeError):
    """A checkpoint cannot be authenticated, agreed upon, or recovered."""


def _id(value: str, label: str) -> str:
    if not isinstance(value, str) or len(value) != 32 or any(c not in _HEX for c in value):
        raise ValueError(f'{label} must be a 32-character lowercase hex ID')
    return value


def _hash(value: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in _HEX for c in value):
        raise ValueError('Expected lowercase SHA-256 digest')
    return value


def _revision(value: int) -> int:
    if type(value) is not int or not 0 <= value < 2**63 - 1:
        raise ValueError('Invalid baseline revision')
    return value


def _root(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if path.is_symlink() or (hasattr(os.path, 'isjunction') and os.path.isjunction(path)):
        raise ValueError('Share root cannot be a link or junction')
    path = path.resolve(strict=True)
    if not path.is_dir():
        raise NotADirectoryError(path)
    return path


def _timeout(value: float) -> float:
    if type(value) not in (float, int) or not math.isfinite(value) or value <= 0:
        raise ValueError('Timeout must be positive and finite')
    return float(value)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def _send(secure, kind: str, **fields) -> None:
    encoded = json.dumps(
        {'version': VERSION, 'type': kind, **fields},
        ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(',', ':'),
    ).encode('utf-8')
    if len(encoded) > _MAX_FRAME:
        raise AgreementError('Agreement message too large')
    secure.sendall(struct.pack('!I', len(encoded)) + encoded)


def _exact(secure, length: int) -> bytes:
    received = bytearray()
    while len(received) < length:
        part = secure.recv(length - len(received))
        if not part:
            raise AgreementError('Agreement connection closed prematurely')
        received.extend(part)
    return bytes(received)


def _receive(secure, expected: set[str]) -> dict:
    (length,) = struct.unpack('!I', _exact(secure, 4))
    if not 0 < length <= _MAX_FRAME:
        raise AgreementError('Invalid agreement frame size')
    try:
        document = json.loads(
            _exact(secure, length).decode('utf-8'),
            object_pairs_hook=_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise AgreementError('Invalid agreement JSON') from exc
    if (not isinstance(document, dict) or type(document.get('version')) is not int
            or document['version'] != VERSION or document.get('type') not in expected):
        raise AgreementError('Unexpected agreement message')
    return document


def _shape(document: dict, kind: str, fields: set[str]) -> None:
    if document['type'] != kind or set(document) != fields | {'version', 'type'}:
        raise AgreementError(f'Invalid {kind} message')


def _close(sock) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _inventory_hash(root: Path) -> tuple[str, object]:
    snapshot = FileScanner(root).scan()
    return _digest(_canonical_rows(snapshot, root)), snapshot


@dataclass(frozen=True, slots=True)
class AgreementStatus:
    revision: int
    sha256: str | None
    inventory_sha256: str
    pending_id: str | None
    pending_revision: int | None
    pending_sha256: str | None


class AgreementService:
    """Authorize specific paired devices to prepare/commit one specific folder.

    The per-share permissions are ephemeral until the settings layer persists
    them. An authenticated peer is NOT automatically granted this permission.
    """

    def __init__(
        self,
        identity: DeviceIdentity,
        trust_store: TrustStore,
        shared_state: SharedStateDatabase,
        shares: Mapping[str, str | Path],
        *,
        allowed_peers: Mapping[str, Iterable[str]] | None = None,
        bind_address: str = '0.0.0.0',
        listen_port: int = DEFAULT_AGREEMENT_PORT,
        handshake_timeout: float = 5.0,
        io_timeout: float = 30.0,
    ) -> None:
        if not isinstance(identity, DeviceIdentity) or not isinstance(trust_store, TrustStore):
            raise TypeError('Device identity and trust store required')
        if not isinstance(shared_state, SharedStateDatabase):
            raise TypeError('SharedStateDatabase required')
        if type(listen_port) is not int or not 0 <= listen_port <= 65535:
            raise ValueError('Invalid agreement listening port')
        address = ipaddress.IPv4Address(bind_address)
        if address.is_multicast:
            raise ValueError('Multicast bind is not permitted')
        self.identity, self.trust_store = identity, trust_store
        self.shared_state = shared_state
        self._shares = {_id(k, 'share_id'): _root(v) for k, v in shares.items()}
        self._peers: dict[str, set[str]] = {key: set() for key in self._shares}
        for share, peers in (allowed_peers or {}).items():
            if share not in self._shares:
                raise ValueError('Unknown share in allowed_peers')
            self._peers[share] = {_id(peer, 'peer_node_id') for peer in peers}
        self.bind_address, self.listen_port = str(address), listen_port
        self.handshake_timeout = _timeout(handshake_timeout)
        self.io_timeout = _timeout(io_timeout)
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._stop.set()
        self._listener: socket.socket | None = None
        self._port: int | None = None
        self._connections: set[socket.socket] = set()
        self._threads: set[threading.Thread] = set()
        self._transaction_lock = threading.Lock()

    @property
    def bound_port(self) -> int | None:
        with self._lock:
            return self._port

    def authorize_peer(self, share_id: str, node_id: str) -> None:
        share_id, node_id = _id(share_id, 'share_id'), _id(node_id, 'node_id')
        with self._lock:
            if share_id not in self._shares:
                raise ValueError('Unknown share')
            self._peers[share_id].add(node_id)

    def revoke_peer(self, share_id: str, node_id: str) -> None:
        share_id, node_id = _id(share_id, 'share_id'), _id(node_id, 'node_id')
        with self._lock:
            self._peers.get(share_id, set()).discard(node_id)

    def _spawn(self, method, *args) -> None:
        def task():
            try:
                method(*args)
            finally:
                with self._lock:
                    self._threads.discard(threading.current_thread())
        worker = threading.Thread(target=task, daemon=True, name='SyncBridgeAgreement')
        with self._lock:
            self._threads.add(worker)
        worker.start()

    def start(self) -> None:
        with self._lock:
            if self._listener is not None:
                return
            if self._threads:
                raise RuntimeError('Previous agreement workers are still stopping')
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((self.bind_address, self.listen_port))
                listener.listen(_MAX_CLIENTS)
                listener.settimeout(0.2)
            except BaseException:
                listener.close()
                raise
            self._listener = listener
            self._port = listener.getsockname()[1]
            self._stop.clear()
            self._spawn(self._accept_loop)

    def stop(self) -> None:
        with self._lock:
            self._stop.set()
            listener, self._listener = self._listener, None
            self._port = None
            connections, threads = tuple(self._connections), tuple(self._threads)
        if listener is not None:
            _close(listener)
        for conn in connections:
            _close(conn)
        for thread in threads:
            if thread is not threading.current_thread():
                thread.join(timeout=self.handshake_timeout + 1)

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                listener = self._listener
            if listener is None:
                return
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if not self._stop.is_set():
                    logger.exception('Agreement listener failed')
                return
            with self._lock:
                accepted = not self._stop.is_set() and len(self._connections) < _MAX_CLIENTS
                if accepted:
                    self._connections.add(conn)
            if accepted:
                self._spawn(self._serve, conn)
            else:
                _close(conn)

    def _check(self, share: str, node: str, public_key: bytes) -> Path:
        self.trust_store.require(public_key)
        with self._lock:
            authorized = (share in self._shares
                          and node in self._peers.get(share, set())
                          and not self._stop.is_set())
            root = self._shares.get(share)
        if not authorized or root is None:
            raise AgreementError('Device is not authorized for baseline agreement on this share')
        return root

    def _serve(self, conn: socket.socket) -> None:
        secure = None
        try:
            secure, peer = accept_secure_channel(
                conn, self.identity, self.trust_store, timeout=self.handshake_timeout
            )
            secure.settimeout(self.io_timeout)
            request = _receive(secure, {'status', 'prepare', 'commit', 'abort'})
            share = _id(request.get('share_id'), 'share_id')
            root = self._check(share, peer.node_id, secure.remote_public_key)
            with self._transaction_lock:
                self._check(share, peer.node_id, secure.remote_public_key)
                answer = self._handle(request, root, peer.node_id, share, secure.remote_public_key)
            _send(secure, **answer)
        except (OSError, AgreementError, SecurityError, ValueError) as exc:
            if secure is not None and not self._stop.is_set():
                try:
                    _send(secure, 'error', reason=str(exc)[:240])
                except OSError:
                    pass
            if not self._stop.is_set():
                logger.debug('Agreement RPC rejected: %s', exc)
        finally:
            _close(conn)
            with self._lock:
                self._connections.discard(conn)

    def _handle(self, data: dict, root: Path, peer: str, share: str, public_key: bytes) -> dict:
        kind = data['type']
        if kind == 'status':
            _shape(data, kind, {'share_id'})
            baseline = self.shared_state.load(root, peer, share)
            pending = self.shared_state.pending(root, peer, share)
            observed, _ = _inventory_hash(root)
            return dict(
                kind='status_result',
                inventory_sha256=observed,
                revision=0 if baseline is None else baseline.revision,
                sha256=None if baseline is None else baseline.sha256,
                pending_id=None if pending is None else pending.proposal_id,
                pending_revision=None if pending is None else pending.expected_revision,
                pending_sha256=None if pending is None else pending.sha256,
            )

        _shape(data, kind, {'share_id', 'proposal_id', 'expected_revision', 'sha256'})
        proposal = _id(data['proposal_id'], 'proposal_id')
        expected = _revision(data['expected_revision'])
        digest = _hash(data['sha256'])
        baseline = self.shared_state.load(root, peer, share)
        revision = 0 if baseline is None else baseline.revision
        if revision == expected + 1 and baseline is not None and baseline.sha256 == digest:
            if kind == 'abort':
                raise AgreementError('Cannot abort a committed baseline')
            return dict(kind='committed' if kind == 'commit' else 'prepared',
                        proposal_id=proposal, revision=revision if kind == 'commit' else expected,
                        sha256=digest, already_committed=True)
        if revision != expected:
            raise AgreementError('Remote baseline revision differs from expected revision')

        if kind == 'abort':
            pending = self.shared_state.pending(root, peer, share)
            if pending is not None and (pending.proposal_id != proposal or pending.sha256 != digest
                                        or pending.expected_revision != expected):
                raise AgreementError('Another proposal is pending; cannot abort it')
            if pending is not None:
                self._check(share, peer, public_key)
                self.shared_state.abort(root, peer, share, proposal)
            return dict(kind='aborted', proposal_id=proposal, revision=expected, sha256=digest)

        if kind == 'prepare':
            observed, snapshot = _inventory_hash(root)
            if observed != digest:
                raise AgreementError('Remote folder inventory differs from proposed baseline')
            self._check(share, peer, public_key)
            self.shared_state.stage(
                root, peer, share, snapshot, expected_revision=expected, proposal_id=proposal
            )
            self.shared_state.confirm_local(root, peer, share, proposal, snapshot)
            return dict(kind='prepared', proposal_id=proposal, revision=expected,
                        sha256=digest, already_committed=False)

        pending = self.shared_state.pending(root, peer, share)
        if (pending is None or pending.proposal_id != proposal or pending.sha256 != digest
                or pending.expected_revision != expected or not pending.local_confirmed):
            raise AgreementError('Remote proposal is not prepared')
        observed, snapshot = _inventory_hash(root)
        if observed != digest:
            raise AgreementError('Remote files changed since baseline preparation')
        self._check(share, peer, public_key)
        self.shared_state.confirm_remote(
            root, peer, share, proposal,
            authenticated_peer_id=peer, acknowledged_sha256=digest
        )
        committed = self.shared_state.finalize(root, peer, share, proposal, snapshot)
        return dict(kind='committed', proposal_id=proposal,
                    revision=committed.revision, sha256=committed.sha256,
                    already_committed=False)


class AgreementClient:
    """Authenticated baseline RPC client; no local SQLite state is modified."""

    def __init__(
        self, identity: DeviceIdentity, trust_store: TrustStore,
        *, handshake_timeout: float = 5.0, io_timeout: float = 30.0
    ) -> None:
        if not isinstance(identity, DeviceIdentity) or not isinstance(trust_store, TrustStore):
            raise TypeError('Device identity and trust store required')
        self.identity, self.trust_store = identity, trust_store
        self.handshake_timeout = _timeout(handshake_timeout)
        self.io_timeout = _timeout(io_timeout)

    def _call(self, host: str, port: int, peer: str, kind: str, share: str, **fields) -> dict:
        _id(peer, 'peer_node_id')
        _id(share, 'share_id')
        if peer == self.identity.node_id:
            raise AgreementError('Cannot agree with own identity')
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('Invalid remote agreement port')
        try:
            address = ipaddress.IPv4Address(host)
        except ValueError as exc:
            raise ValueError('Remote host must be numeric IPv4') from exc
        if address.is_unspecified or address.is_multicast or str(address) == '255.255.255.255':
            raise ValueError('Remote host must be unicast IPv4')
        try:
            sock = socket.create_connection((str(address), port), timeout=self.handshake_timeout)
        except OSError as exc:
            raise AgreementError(f'Cannot reach agreement service: {exc}') from exc
        try:
            secure, authenticated_peer = open_secure_channel(
                sock, self.identity, self.trust_store, peer,
                timeout=self.handshake_timeout
            )
            if authenticated_peer.node_id != peer:
                raise AgreementError('Wrong authenticated peer')
            secure.settimeout(self.io_timeout)
            _send(secure, kind, share_id=share, **fields)
            reply = _receive(secure, {'status_result', 'prepared', 'committed', 'aborted', 'error'})
            if reply['type'] == 'error':
                _shape(reply, 'error', {'reason'})
                raise AgreementError(str(reply['reason'])[:240])
            expected_reply = {'status': 'status_result', 'prepare': 'prepared',
                              'commit': 'committed', 'abort': 'aborted'}[kind]
            if reply['type'] != expected_reply:
                raise AgreementError('Unexpected agreement response type')
            self.trust_store.require(secure.remote_public_key)
            return reply
        except (OSError, SecurityError) as exc:
            raise AgreementError(f'Encrypted agreement exchange failed: {exc}') from exc
        finally:
            _close(sock)

    def status(self, host: str, port: int, peer: str, share: str) -> AgreementStatus:
        reply = self._call(host, port, peer, 'status', share)
        _shape(reply, 'status_result', {
            'revision', 'sha256', 'inventory_sha256', 'pending_id', 'pending_revision', 'pending_sha256'
        })
        revision = _revision(reply['revision'])
        digest = reply['sha256']
        if (revision == 0) != (digest is None):
            raise AgreementError('Invalid baseline revision and digest combination')
        if digest is not None:
            _hash(digest)
        pending_id = reply['pending_id']
        pending_revision = reply['pending_revision']
        pending_digest = reply['pending_sha256']
        if pending_id is None:
            if pending_revision is not None or pending_digest is not None:
                raise AgreementError('Incomplete pending proposal status')
        else:
            _id(pending_id, 'pending_id')
            _revision(pending_revision)
            _hash(pending_digest)
        return AgreementStatus(revision, digest, _hash(reply['inventory_sha256']),
                               pending_id, pending_revision, pending_digest)

    def _change(self, host: str, port: int, peer: str, share: str, kind: str,
                proposal: str, expected: int, digest: str) -> bool:
        _id(proposal, 'proposal_id')
        _revision(expected)
        _hash(digest)
        response = self._call(
            host, port, peer, kind, share, proposal_id=proposal,
            expected_revision=expected, sha256=digest
        )
        _shape(response, response['type'], {
            'proposal_id', 'revision', 'sha256'
        } | ({'already_committed'} if kind != 'abort' else set()))
        if (response['proposal_id'] != proposal or response['sha256'] != digest
                or type(response['revision']) is not int
                or response['revision'] != expected + (1 if kind == 'commit' else 0)):
            raise AgreementError('Agreement response does not match proposal')
        if kind != 'abort':
            if type(response['already_committed']) is not bool:
                raise AgreementError('Invalid agreement completion status')
            return response['already_committed']
        return False

    def prepare(self, host: str, port: int, peer: str, share: str,
                proposal: str, revision: int, digest: str) -> bool:
        return self._change(host, port, peer, share, 'prepare', proposal, revision, digest)

    def commit(self, host: str, port: int, peer: str, share: str,
               proposal: str, revision: int, digest: str) -> bool:
        return self._change(host, port, peer, share, 'commit', proposal, revision, digest)

    def abort(self, host: str, port: int, peer: str, share: str,
              proposal: str, revision: int, digest: str) -> None:
        self._change(host, port, peer, share, 'abort', proposal, revision, digest)
