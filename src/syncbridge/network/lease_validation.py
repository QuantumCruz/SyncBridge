
"""Authenticated validation of a SyncBridge lease at the elected authority.

This is a read-only authorization service. A positive answer proves only
that a lease was current when checked. Receiver-side publication must still
enforce its own final authorization and fencing checks.

A server may bind to 0.0.0.0 for LAN/virtual-LAN connectivity. This does
not relax authenticated peer identity or share authorization requirements.
Client destinations must remain numeric unicast IPv4 addresses.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import math
import secrets
import socket
import struct
import threading
from dataclasses import dataclass

from syncbridge.network.operation_lock import OperationLockService
from syncbridge.network.secure_channel import (
    accept_secure_channel,
    open_secure_channel,
)
from syncbridge.network.security import DeviceIdentity, TrustStore


LOG = logging.getLogger(__name__)
DEFAULT_PORT = 45847
_VERSION = 1
_MAX_FRAME = 1024
_MAX_CLIENTS = 8
_HEX = frozenset("0123456789abcdef")
_OPERATIONS = frozenset(("sync", "deletion", "recovery"))


class LeaseProofError(RuntimeError):
    """Authority unavailable or proof response could not be authenticated."""


class LeaseProofRejected(LeaseProofError):
    """The proof is not the currently active authority lease."""


def _identifier(value: str, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 32
        or any(c not in _HEX for c in value)
    ):
        raise ValueError(
            f"{label} must be a lowercase 32-character hex identifier"
        )
    return value


def _operation(value: str) -> str:
    if type(value) is not str or value not in _OPERATIONS:
        raise ValueError("Unknown operation type")
    return value


def _timeout(value: float) -> float:
    if (
        type(value) not in (float, int)
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError("Timeout must be finite and positive")
    return float(value)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate lease proof field")
        result[key] = value
    return result


def _read_exact(stream, amount: int) -> bytes:
    data = bytearray()
    while len(data) < amount:
        block = stream.recv(amount - len(data))
        if not block:
            raise LeaseProofError(
                "Coordination connection closed before reply"
            )
        data.extend(block)
    return bytes(data)


def _send(stream, message: dict) -> None:
    raw = json.dumps(
        message,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")

    if len(raw) > _MAX_FRAME:
        raise LeaseProofError("Lease proof message is too long")

    stream.sendall(struct.pack("!I", len(raw)) + raw)


def _read(stream) -> dict:
    length = struct.unpack(
        "!I",
        _read_exact(stream, 4),
    )[0]

    if not 0 < length <= _MAX_FRAME:
        raise LeaseProofError(
            "Invalid coordination frame length"
        )

    try:
        message = json.loads(
            _read_exact(stream, length).decode("utf-8"),
            object_pairs_hook=_unique,
            parse_constant=lambda value: (
                _ for _ in ()
            ).throw(ValueError(value)),
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise LeaseProofError(
            "Invalid coordination message"
        ) from exc

    if (
        not isinstance(message, dict)
        or type(message.get("version")) is not int
        or message["version"] != _VERSION
    ):
        raise LeaseProofError(
            "Unsupported coordination message"
        )

    return message


def _close(connection) -> None:
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass

    try:
        connection.close()
    except OSError:
        pass


@dataclass(frozen=True, slots=True)
class LeaseProof:
    share_id: str
    owner_id: str
    operation: str
    token: str

    def __post_init__(self) -> None:
        _identifier(self.share_id, "share_id")
        _identifier(self.owner_id, "owner_id")
        _operation(self.operation)
        _identifier(self.token, "lease token")


class LeaseValidationService:
    """Validate elected operation leases for explicitly trusted peers."""

    def __init__(
        self,
        authority: OperationLockService,
        *,
        bind_address: str = "127.0.0.1",
        listen_port: int = DEFAULT_PORT,
        timeout: float = 5.0,
    ) -> None:
        if not isinstance(authority, OperationLockService):
            raise TypeError(
                "An OperationLockService authority is required"
            )

        address = ipaddress.IPv4Address(bind_address)

        # 0.0.0.0 is valid for a listening socket, not a remote
        # destination. Authentication is still mandatory.
        if (
            address.is_multicast
            or str(address) == "255.255.255.255"
        ):
            raise ValueError(
                "Use a valid IPv4 listener binding"
            )

        if (
            type(listen_port) is not int
            or not 0 <= listen_port <= 65535
        ):
            raise ValueError("Invalid validation port")

        self.authority = authority
        self.bind_address = str(address)
        self.listen_port = listen_port
        self.timeout = _timeout(timeout)

        self._lock = threading.RLock()
        self._listener: socket.socket | None = None
        self._port: int | None = None
        self._authority_socket: socket.socket | None = None

        self._stop = threading.Event()
        self._stop.set()

        self._connections: set[socket.socket] = set()
        self._threads: set[threading.Thread] = set()

    @property
    def bound_port(self) -> int | None:
        with self._lock:
            return self._port

    def validate_local(self, proof: LeaseProof) -> bool:
        """Read current lease state without reserving a future write."""
        if not isinstance(proof, LeaseProof):
            raise TypeError("proof must be LeaseProof")

        authority = self.authority

        with self._lock:
            enabled = self._listener is not None
            expected_socket = self._authority_socket

        if not enabled:
            return False

        with authority._lock:
            if (
                expected_socket is None
                or authority._listener is not expected_socket
            ):
                return False

            peer = authority.shares.get(
                proof.share_id
            )

            if (
                peer is None
                or proof.owner_id not in (
                    peer,
                    authority.identity.node_id,
                )
            ):
                return False

            if (
                proof.owner_id == peer
                and authority.trust_store.get(peer) is None
            ):
                return False

            active = authority._active(
                proof.share_id
            )

            return bool(
                active is not None
                and active.owner == proof.owner_id
                and active.operation == proof.operation
                and secrets.compare_digest(
                    active.token,
                    proof.token,
                )
            )

    def _spawn(self, fn, *args) -> None:
        def run():
            try:
                fn(*args)
            finally:
                with self._lock:
                    self._threads.discard(
                        threading.current_thread()
                    )

        thread = threading.Thread(
            target=run,
            name="SyncBridgeLeaseValidation",
            daemon=True,
        )

        with self._lock:
            self._threads.add(thread)

        thread.start()

    def start(self) -> None:
        with self._lock:
            if self._listener is not None:
                return

            if self._threads:
                raise RuntimeError(
                    "Previous lease validation connections are still closing"
                )

            with self.authority._lock:
                if self.authority._listener is None:
                    raise RuntimeError(
                        "Start the operation-lock authority first"
                    )

                if self.authority._leases:
                    raise RuntimeError(
                        "Start lease validation before granting any leases"
                    )

                authority_socket = self.authority._listener

            listener = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM,
            )

            try:
                listener.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_REUSEADDR,
                    1,
                )

                listener.bind((
                    self.bind_address,
                    self.listen_port,
                ))

                listener.listen(_MAX_CLIENTS)
                listener.settimeout(0.2)

            except BaseException:
                listener.close()
                raise

            self._listener = listener
            self._authority_socket = authority_socket
            self._port = listener.getsockname()[1]

            self._stop.clear()
            self._spawn(self._accept)

    def stop(self) -> None:
        with self._lock:
            self._stop.set()

            listener, self._listener = self._listener, None
            self._authority_socket = None
            self._port = None

            connections = tuple(self._connections)
            threads = tuple(self._threads)

        if listener is not None:
            _close(listener)

        for conn in connections:
            _close(conn)

        for thread in threads:
            if thread is not threading.current_thread():
                thread.join(timeout=self.timeout + 1)

    def _accept(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                listener = self._listener

            if listener is None:
                return

            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return

            with self._lock:
                accepted = (
                    not self._stop.is_set()
                    and len(self._connections) < _MAX_CLIENTS
                )

                if accepted:
                    self._connections.add(connection)

            if accepted:
                self._spawn(
                    self._serve,
                    connection,
                )
            else:
                _close(connection)

    def _serve(self, connection: socket.socket) -> None:
        channel = None

        try:
            channel, requester = accept_secure_channel(
                connection,
                self.authority.identity,
                self.authority.trust_store,
                timeout=self.timeout,
            )

            channel.settimeout(self.timeout)

            message = _read(channel)

            required = {
                "version",
                "type",
                "share_id",
                "owner_id",
                "operation",
                "token",
            }

            if (
                set(message) != required
                or message.get("type") != "validate"
            ):
                raise LeaseProofError(
                    "Malformed lease validation request"
                )

            proof = LeaseProof(
                message["share_id"],
                message["owner_id"],
                message["operation"],
                message["token"],
            )

            if (
                self.authority.shares.get(proof.share_id)
                != requester.node_id
            ):
                raise LeaseProofError(
                    "[SB-OPS-403] Not authorized for this share"
                )

            self.authority.trust_store.require(
                channel.remote_public_key
            )

            valid = self.validate_local(proof)

            _send(
                channel,
                {
                    "version": _VERSION,
                    "type": "result",
                    "active": valid,
                },
            )

        except Exception as exc:
            LOG.debug(
                "Rejected lease validation: %s",
                type(exc).__name__,
            )

            if channel is not None and not self._stop.is_set():
                try:
                    _send(
                        channel,
                        {
                            "version": _VERSION,
                            "type": "error",
                            "code": "SB-OPS-403",
                        },
                    )
                except Exception:
                    pass

        finally:
            _close(connection)

            with self._lock:
                self._connections.discard(connection)


class LeaseValidationClient:
    """Ask the elected authority to validate a specific operation lease."""

    def __init__(
        self,
        identity: DeviceIdentity,
        trust: TrustStore,
        *,
        timeout: float = 5.0,
    ) -> None:
        if (
            not isinstance(identity, DeviceIdentity)
            or not isinstance(trust, TrustStore)
        ):
            raise TypeError(
                "DeviceIdentity and TrustStore are required"
            )

        self.identity = identity
        self.trust = trust
        self.timeout = _timeout(timeout)

    def validate(
        self,
        host: str,
        port: int,
        authority_id: str,
        proof: LeaseProof,
    ) -> bool:
        _identifier(authority_id, "authority_id")

        if authority_id == self.identity.node_id:
            raise ValueError(
                "The local authority must validate its own leases directly"
            )

        if (
            type(port) is not int
            or not 1 <= port <= 65535
        ):
            raise ValueError(
                "Invalid validation port"
            )

        if not isinstance(proof, LeaseProof):
            raise TypeError(
                "proof must be LeaseProof"
            )

        address = ipaddress.IPv4Address(host)

        if (
            address.is_multicast
            or address.is_unspecified
            or str(address) == "255.255.255.255"
        ):
            raise ValueError(
                "Authority must be a unicast IPv4 address"
            )

        try:
            connection = socket.create_connection(
                (str(address), port),
                timeout=self.timeout,
            )
        except OSError as exc:
            raise LeaseProofError(
                "[SB-OPS-503] Cannot reach the operation authority"
            ) from exc

        try:
            channel, peer = open_secure_channel(
                connection,
                self.identity,
                self.trust,
                authority_id,
                timeout=self.timeout,
            )

            if peer.node_id != authority_id:
                raise LeaseProofError(
                    "Wrong authority replied to lease validation"
                )

            channel.settimeout(self.timeout)

            _send(
                channel,
                {
                    "version": _VERSION,
                    "type": "validate",
                    "share_id": proof.share_id,
                    "owner_id": proof.owner_id,
                    "operation": proof.operation,
                    "token": proof.token,
                },
            )

            reply = _read(channel)

            if (
                set(reply) == {
                    "version", "type", "code"
                }
                and reply["type"] == "error"
            ):
                raise LeaseProofError(
                    "[SB-OPS-403] Lease validation was refused"
                )

            if (
                set(reply) != {
                    "version", "type", "active"
                }
                or reply["type"] != "result"
                or type(reply["active"]) is not bool
            ):
                raise LeaseProofError(
                    "Malformed lease validation response"
                )

            self.trust.require(
                channel.remote_public_key
            )

            return reply["active"]

        except (OSError, TimeoutError) as exc:
            raise LeaseProofError(
                "[SB-OPS-503] Lease validation connection failed"
            ) from exc

        finally:
            _close(connection)

    def require_current(
        self,
        host: str,
        port: int,
        authority_id: str,
        proof: LeaseProof,
    ) -> None:
        if not self.validate(
            host,
            port,
            authority_id,
            proof,
        ):
            raise LeaseProofRejected(
                "[SB-OPS-409] This device's operation permission "
                "has expired, been replaced, or does not match "
                "the requested operation."
            )


class WriteAdmissionGate:
    """Fail-closed check for a current elected operation authorization.

    The local receiver must call require() at its mutation boundary.
    Validation against another computer remains a point-in-time check.
    """

    def __init__(
        self,
        share_id: str,
        authority_id: str,
        peer_id: str,
        *,
        local_validation: LeaseValidationService | None = None,
        remote_validation: LeaseValidationClient | None = None,
        authority_host: str = "127.0.0.1",
        authority_port: int = DEFAULT_PORT,
    ) -> None:
        self.share_id = _identifier(
            share_id,
            "share_id",
        )
        self.authority_id = _identifier(
            authority_id,
            "authority_id",
        )
        self.peer_id = _identifier(
            peer_id,
            "peer_id",
        )

        if self.authority_id == self.peer_id:
            raise ValueError(
                "The authority and other device cannot be identical"
            )

        if (local_validation is None) == (remote_validation is None):
            raise ValueError(
                "Provide exactly one local or remote authority validator"
            )

        if (
            local_validation is not None
            and local_validation.authority.identity.node_id
            != authority_id
        ):
            raise ValueError(
                "Local validator uses a different authority"
            )

        if (
            remote_validation is not None
            and remote_validation.identity.node_id != peer_id
        ):
            raise ValueError(
                "Remote validator must represent the other approved device"
            )

        self.local_validation = local_validation
        self.remote_validation = remote_validation
        self.authority_host = authority_host
        self.authority_port = authority_port

    def require(
        self,
        proof: LeaseProof,
        *,
        authenticated_owner_id: str,
    ) -> None:
        _identifier(
            authenticated_owner_id,
            "authenticated_owner_id",
        )

        if not isinstance(proof, LeaseProof):
            raise TypeError(
                "proof must be LeaseProof"
            )

        if (
            proof.share_id != self.share_id
            or proof.owner_id != authenticated_owner_id
            or authenticated_owner_id not in (
                self.authority_id,
                self.peer_id,
            )
        ):
            raise LeaseProofRejected(
                "[SB-OPS-403] This device has no valid write "
                "permission for this folder"
            )

        if self.local_validation is not None:
            active = self.local_validation.validate_local(
                proof
            )
        else:
            active = self.remote_validation.validate(
                self.authority_host,
                self.authority_port,
                self.authority_id,
                proof,
            )

        if not active:
            raise LeaseProofRejected(
                "[SB-OPS-409] This operation is no longer "
                "authorized. Stop writing and synchronize again "
                "after reviewing both folders."
            )
