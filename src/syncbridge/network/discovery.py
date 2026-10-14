
"""Unauthenticated IPv4 UDP peer discovery for SyncBridge.

Discovery only advertises TCP endpoints. A discovered peer is not trusted or
connected; authentication and file transfer belong to later network modules.
Broadcast works on ordinary LANs, while explicit unicast targets can be used
for virtual networks and for two independent instances on one computer.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import re
import socket
import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterable

logger = logging.getLogger(__name__)

DISCOVERY_VERSION = 1
DISCOVERY_PORT = 45841
MAX_ANNOUNCEMENT_BYTES = 1024
MAX_DISCOVERED_PEERS = 256
_MAGIC = "syncbridge-discovery"
_ID_PATTERN = re.compile(r"[0-9a-f]{32}\Z")
_FIELDS = frozenset({
    "magic",
    "version",
    "node_id",
    "name",
    "peer_port",
    "discovery_port",
})


class DiscoveryError(ValueError):
    """Malformed or unsupported discovery announcement."""


@dataclass(frozen=True, slots=True)
class PeerAnnouncement:
    node_id: str
    name: str
    peer_port: int
    discovery_port: int


@dataclass(frozen=True, slots=True)
class DiscoveredPeer:
    node_id: str
    name: str
    address: str
    port: int
    discovery_port: int
    last_seen: float  # time.monotonic(), not a wall-clock timestamp


def _validate_port(port: int, *, allow_zero: bool = False) -> int:
    if type(port) is not int or not (0 if allow_zero else 1) <= port <= 65535:
        raise ValueError(
            "Port must be an integer between 1 and 65535"
            + (" (or 0)" if allow_zero else "")
        )
    return port


def _validate_announcement(announcement: PeerAnnouncement) -> None:
    if (
        not isinstance(announcement.node_id, str)
        or not _ID_PATTERN.fullmatch(announcement.node_id)
    ):
        raise DiscoveryError(
            "node_id must be 32 lowercase hexadecimal characters"
        )

    name = announcement.name

    if not isinstance(name, str):
        raise DiscoveryError(
            "name must be nonempty, printable UTF-8 (up to 128 bytes)"
        )

    try:
        name_size = len(name.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise DiscoveryError("name contains invalid Unicode") from exc

    if (
        not name.strip()
        or name_size > 128
        or any(
            ord(character) < 32 or ord(character) == 127
            for character in name
        )
    ):
        raise DiscoveryError(
            "name must be nonempty, printable UTF-8 (up to 128 bytes)"
        )

    for port in (announcement.peer_port, announcement.discovery_port):
        try:
            _validate_port(port)
        except ValueError as exc:
            raise DiscoveryError(str(exc)) from exc


def encode_announcement(announcement: PeerAnnouncement) -> bytes:
    """Encode a validated UDP beacon (no TCP length prefix)."""
    if not isinstance(announcement, PeerAnnouncement):
        raise TypeError("announcement must be a PeerAnnouncement")

    _validate_announcement(announcement)

    packet = json.dumps(
        {
            "magic": _MAGIC,
            "version": DISCOVERY_VERSION,
            "node_id": announcement.node_id,
            "name": announcement.name,
            "peer_port": announcement.peer_port,
            "discovery_port": announcement.discovery_port,
        },
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    if len(packet) > MAX_ANNOUNCEMENT_BYTES:
        raise DiscoveryError("Announcement is too large")

    return packet


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate announcement field")
        result[key] = value

    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")


def decode_announcement(packet: bytes) -> PeerAnnouncement:
    """Reject malformed, unknown-version and oversized UDP beacons."""
    if not isinstance(packet, bytes):
        raise TypeError("packet must be bytes")

    if not packet or len(packet) > MAX_ANNOUNCEMENT_BYTES:
        raise DiscoveryError("Invalid announcement size")

    try:
        document = json.loads(
            packet.decode("utf-8"),
            object_pairs_hook=_unique_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise DiscoveryError("Malformed announcement JSON") from exc

    if not isinstance(document, dict) or set(document) != _FIELDS:
        raise DiscoveryError("Invalid announcement fields")

    if (
        document["magic"] != _MAGIC
        or type(document["version"]) is not int
        or document["version"] != DISCOVERY_VERSION
    ):
        raise DiscoveryError("Unknown discovery protocol or version")

    announcement = PeerAnnouncement(
        node_id=document["node_id"],
        name=document["name"],
        peer_port=document["peer_port"],
        discovery_port=document["discovery_port"],
    )

    _validate_announcement(announcement)
    return announcement


def _validate_target(host: str, port: int) -> tuple[str, int]:
    try:
        address = ipaddress.IPv4Address(host)
    except (ValueError, ipaddress.AddressValueError) as exc:
        raise ValueError(
            "Discovery targets must be numeric IPv4 addresses"
        ) from exc

    if address.is_unspecified or address.is_multicast:
        raise ValueError(
            "Unspecified and multicast addresses are not valid discovery targets"
        )

    return str(address), _validate_port(port)


class PeerDiscovery:
    """Discover other nodes using UDP broadcasts or explicit IPv4 targets.

    The caller supplies a stable node_id and the TCP port it will eventually
    listen on. Callbacks run on the discovery thread; GUI callers must marshal
    events onto the UI thread. Restarting clears the in-memory peer cache.
    """

    def __init__(
        self,
        node_id: str,
        name: str,
        peer_port: int,
        *,
        listen_port: int = DISCOVERY_PORT,
        bind_address: str = "0.0.0.0",
        targets: Iterable[tuple[str, int]] = (
            ("255.255.255.255", DISCOVERY_PORT),
        ),
        announce_interval: float = 2.0,
        peer_timeout: float = 8.0,
        on_discovered: Callable[[DiscoveredPeer], None] | None = None,
        on_lost: Callable[[DiscoveredPeer], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        _validate_announcement(
            PeerAnnouncement(node_id, name, peer_port, 1)
        )

        self.node_id = node_id
        self.name = name
        self.peer_port = peer_port
        self.listen_port = _validate_port(listen_port, allow_zero=True)

        try:
            self.bind_address = str(
                ipaddress.IPv4Address(bind_address)
            )
        except ValueError as exc:
            raise ValueError(
                "bind_address must be a numeric IPv4 address"
            ) from exc

        if any(
            callback is not None and not callable(callback)
            for callback in (on_discovered, on_lost, on_error)
        ):
            raise TypeError(
                "Discovery callbacks must be callable or None"
            )

        try:
            self.announce_interval = float(announce_interval)
            self.peer_timeout = float(peer_timeout)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(
                "Discovery timings must be finite positive numbers"
            ) from exc

        if (
            not math.isfinite(self.announce_interval)
            or not math.isfinite(self.peer_timeout)
            or self.announce_interval <= 0
            or self.peer_timeout <= self.announce_interval
        ):
            raise ValueError(
                "peer_timeout must exceed the positive announce_interval"
            )

        self._on_discovered = on_discovered
        self._on_lost = on_lost
        self._on_error = on_error

        self._lock = threading.RLock()
        self._lifecycle_lock = threading.Lock()

        self._targets = set(
            _validate_target(host, port)
            for host, port in targets
        )

        self._peers: dict[str, DiscoveredPeer] = {}
        self._stop_event = threading.Event()
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._bound_port: int | None = None

    @property
    def is_running(self) -> bool:
        thread = self._thread
        return (
            thread is not None
            and thread.is_alive()
            and not self._stop_event.is_set()
        )

    @property
    def bound_port(self) -> int | None:
        """The actual UDP port, useful when listen_port=0 for local tests."""
        with self._lock:
            return self._bound_port

    @property
    def peers(self) -> tuple[DiscoveredPeer, ...]:
        with self._lock:
            return tuple(
                sorted(
                    self._peers.values(),
                    key=lambda peer: peer.node_id,
                )
            )

    def add_target(self, host: str, port: int) -> None:
        """Add a numeric IPv4 broadcast or unicast destination."""
        target = _validate_target(host, port)

        with self._lock:
            self._targets.add(target)

    def remove_target(self, host: str, port: int) -> None:
        target = _validate_target(host, port)

        with self._lock:
            self._targets.discard(target)

    def start(self) -> None:
        with self._lifecycle_lock:
            if self._thread is not None and self._thread.is_alive():
                if self._stop_event.is_set():
                    raise RuntimeError(
                        "Previous discovery thread is still stopping"
                    )
                return

            connection = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM,
            )

            try:
                connection.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_BROADCAST,
                    1,
                )
                connection.settimeout(0.2)
                connection.bind(
                    (self.bind_address, self.listen_port)
                )
            except Exception:
                connection.close()
                raise

            with self._lock:
                self._socket = connection
                self._bound_port = connection.getsockname()[1]
                self._peers.clear()

            self._stop_event.clear()

            self._thread = threading.Thread(
                target=self._run,
                name="SyncBridgePeerDiscovery",
                daemon=True,
            )

            self._thread.start()

    def stop(self) -> None:
        """Stop discovery; safe to invoke from a discovery callback."""
        with self._lifecycle_lock:
            self._stop_event.set()
            thread = self._thread

            with self._lock:
                connection = self._socket
                self._socket = None
                self._bound_port = None
                self._peers.clear()

            if connection is not None:
                connection.close()

        if (
            thread is not None
            and thread is not threading.current_thread()
        ):
            thread.join()

    def announce(self) -> None:
        """Send an announcement immediately to all configured targets."""
        with self._lock:
            connection = self._socket
            port = self._bound_port
            targets = tuple(self._targets)

        if (
            connection is None
            or port is None
            or self._stop_event.is_set()
        ):
            raise RuntimeError("Peer discovery is not running")

        packet = encode_announcement(
            PeerAnnouncement(
                self.node_id,
                self.name,
                self.peer_port,
                port,
            )
        )

        for target in targets:
            try:
                connection.sendto(packet, target)
            except OSError as exc:
                if not self._stop_event.is_set():
                    self._report_error(exc)

    def _run(self) -> None:
        next_announce = 0.0

        while not self._stop_event.is_set():
            now = time.monotonic()

            if now >= next_announce:
                try:
                    self.announce()
                except RuntimeError:
                    if self._stop_event.is_set():
                        break
                    raise

                next_announce = now + self.announce_interval

            self._expire(now)

            with self._lock:
                connection = self._socket

            if connection is None:
                break

            try:
                packet, (host, _) = connection.recvfrom(
                    MAX_ANNOUNCEMENT_BYTES + 1
                )
            except socket.timeout:
                continue
            except OSError as exc:
                if self._stop_event.is_set():
                    break

                # Windows reports an ICMP "port unreachable" as
                # WSAECONNRESET (10054) on a UDP socket that
                # previously sent data to an inactive peer.
                # This is recoverable and must not stop discovery.
                if (
                    getattr(exc, "winerror", None) == 10054
                    or exc.errno == 10054
                ):
                    continue

                self._report_error(exc)
                break

            try:
                announcement = decode_announcement(packet)
            except DiscoveryError:
                continue

            if announcement.node_id == self.node_id:
                continue

            self._accept(announcement, host)

    def _accept(
        self,
        announcement: PeerAnnouncement,
        host: str,
    ) -> None:
        now = time.monotonic()

        peer = DiscoveredPeer(
            node_id=announcement.node_id,
            name=announcement.name,
            address=host,
            port=announcement.peer_port,
            discovery_port=announcement.discovery_port,
            last_seen=now,
        )

        with self._lock:
            previous = self._peers.get(peer.node_id)

            if (
                previous is None
                and len(self._peers) >= MAX_DISCOVERED_PEERS
            ):
                return

            self._peers[peer.node_id] = peer

        if previous is None or (
            previous.name,
            previous.address,
            previous.port,
            previous.discovery_port,
        ) != (
            peer.name,
            peer.address,
            peer.port,
            peer.discovery_port,
        ):
            self._callback(self._on_discovered, peer)

        # Respond once on first sighting without causing an echo loop.
        if previous is None and not self._stop_event.is_set():
            with self._lock:
                connection = self._socket
                bound_port = self._bound_port

            if connection is not None and bound_port is not None:
                try:
                    packet = encode_announcement(
                        PeerAnnouncement(
                            self.node_id,
                            self.name,
                            self.peer_port,
                            bound_port,
                        )
                    )

                    connection.sendto(
                        packet,
                        (host, announcement.discovery_port),
                    )
                except OSError as exc:
                    if not self._stop_event.is_set():
                        self._report_error(exc)

    def _expire(self, now: float) -> None:
        with self._lock:
            stale = [
                peer
                for peer in self._peers.values()
                if now - peer.last_seen >= self.peer_timeout
            ]

            for peer in stale:
                self._peers.pop(peer.node_id, None)

        for peer in stale:
            self._callback(self._on_lost, peer)

    def _callback(
        self,
        callback: Callable[[DiscoveredPeer], None] | None,
        peer: DiscoveredPeer,
    ) -> None:
        if callback is not None:
            try:
                callback(peer)
            except Exception as exc:
                self._report_error(exc)

    def _report_error(self, exc: Exception) -> None:
        if self._on_error is None:
            logger.error("SyncBridge discovery: %s", exc)
            return

        try:
            self._on_error(exc)
        except Exception:
            logger.exception(
                "SyncBridge discovery error callback failed"
            )
