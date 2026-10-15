
"""Validated, atomic, versioned local configuration for SyncBridge.

Contains only settings and public identifiers. Private identity keys, trust stores,
connection credentials, and baseline histories belong in their own protected
storage, never in this JSON document. Loading configuration NEVER starts sync.

Each save checks its revision under an interprocess lock and atomically replaces
settings.json. A missing file yields conservative defaults; a damaged or future-
version file is rejected rather than silently reset.
"""

from __future__ import annotations

import json
import math
import os
import re
import stat
import tempfile
import time
import unicodedata
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, fields, replace
from pathlib import Path
from typing import Iterator
from ipaddress import IPv4Address

FORMAT_VERSION = 1
MAX_CONFIG_BYTES = 2 * 1024 * 1024
_MAX_REVISION = 2**63 - 2
_IDENTIFIER = re.compile(r"[0-9a-f]{32}\Z")


class ConfigError(ValueError):
    """Settings file or supplied configuration is invalid or unsafe."""


class ConfigConflict(ConfigError):
    """Another writer saved a newer configuration revision."""


def _identifier(value: str, label: str) -> None:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ConfigError(f"{label} must be 32 lowercase hexadecimal characters")


def _label(value: str, label: str, maximum: int) -> None:
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ConfigError(f"{label} contains invalid Unicode") from exc
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise ConfigError(f"{label} must be 1-{maximum} printable characters")


def _positive(value: float, label: str, *, allow_zero: bool = False) -> None:
    if (
        type(value) not in (int, float)
        or not math.isfinite(value)
        or value < 0
        or (not allow_zero and value == 0)
    ):
        raise ConfigError(f"{label} must be a finite positive number")


def _port(value: int, label: str) -> None:
    if type(value) is not int or not 1 <= value <= 65535:
        raise ConfigError(f"{label} must be a TCP port between 1 and 65535")


def _linked(path: Path) -> bool:
    return path.is_symlink() or (
        hasattr(os.path, "isjunction") and os.path.isjunction(path)
    )


def _root_parts(value: str) -> tuple[str, ...]:
    root = Path(value).expanduser()
    if not root.is_absolute():
        raise ConfigError("local_root must be an absolute directory path")
    if _linked(root):
        raise ConfigError("local_root must not be a symbolic link or junction")
    if root.exists() and not root.is_dir():
        raise ConfigError("local_root must refer to a directory")

    # Missing folders remain configured, but must be confirmed as present by
    # the startup layer before enabling any listener or automatic writes.
    parts = root.resolve(strict=False).parts
    if len(parts) <= 1:
        raise ConfigError("Refusing a filesystem root as a shared folder")
    return tuple(unicodedata.normalize("NFC", part).casefold() for part in parts)


@dataclass(frozen=True, slots=True)
class SyncPreferences:
    """User-selected scheduling; auto_apply is OFF unless explicitly enabled."""

    auto_apply: bool = False
    poll_interval: float = 15.0
    watch_interval: float = 1.0
    settle_delay: float = 0.75
    retry_initial: float = 2.0
    retry_max: float = 60.0

    def __post_init__(self) -> None:
        if type(self.auto_apply) is not bool:
            raise ConfigError("auto_apply must be a boolean")

        for name in (
            "poll_interval",
            "watch_interval",
            "retry_initial",
            "retry_max",
        ):
            _positive(getattr(self, name), name)

        _positive(self.settle_delay, "settle_delay", allow_zero=True)

        if self.retry_max < self.retry_initial:
            raise ConfigError("retry_max must be at least retry_initial")


@dataclass(frozen=True, slots=True)
class ShareConfig:
    """One explicitly chosen local folder paired with one remote device.

    Grant flags describe LOCAL permissions to serve this peer. They are not
    proof that the remote device granted matching permissions. In particular,
    pairing/trust must be independently confirmed by the TrustStore.
    """

    share_id: str
    peer_node_id: str
    local_root: str
    display_name: str
    remote_host: str | None = None
    manifest_port: int = 45843
    transfer_port: int = 45842
    agreement_port: int = 45844
    enabled: bool = False
    grant_manifest: bool = False
    grant_read: bool = False
    grant_write: bool = False
    grant_agreement: bool = False
    preferences: SyncPreferences = field(default_factory=SyncPreferences)

    def __post_init__(self) -> None:
        _identifier(self.share_id, "share_id")
        _identifier(self.peer_node_id, "peer_node_id")
        _label(self.display_name, "display_name", 96)

        if not isinstance(self.local_root, str):
            raise ConfigError("local_root must be a string")

        _root_parts(self.local_root)

        if self.remote_host is not None:
            if not isinstance(self.remote_host, str):
                raise ConfigError("remote_host must be numeric IPv4 or null")

            try:
                address = IPv4Address(self.remote_host)
            except ValueError as exc:
                raise ConfigError("remote_host must be numeric IPv4 or null") from exc

            if (
                address.is_unspecified
                or address.is_multicast
                or str(address) == "255.255.255.255"
            ):
                raise ConfigError("remote_host must be a unicast IPv4 address")

        ports = (
            self.manifest_port,
            self.transfer_port,
            self.agreement_port,
        )

        for label, port in zip(
            ("manifest_port", "transfer_port", "agreement_port"),
            ports,
        ):
            _port(port, label)

        if len(set(ports)) != len(ports):
            raise ConfigError(
                "Manifest, transfer and agreement ports must differ"
            )

        for name in (
            "enabled",
            "grant_manifest",
            "grant_read",
            "grant_write",
            "grant_agreement",
        ):
            if type(getattr(self, name)) is not bool:
                raise ConfigError(f"{name} must be a boolean")

        if not isinstance(self.preferences, SyncPreferences):
            raise ConfigError("preferences must be SyncPreferences")


@dataclass(frozen=True, slots=True)
class AppConfig:
    revision: int = 0
    device_name: str = "SyncBridge Device"
    shares: tuple[ShareConfig, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.revision) is not int
            or not 0 <= self.revision <= _MAX_REVISION
        ):
            raise ConfigError("Invalid configuration revision")

        _label(self.device_name, "device_name", 64)

        if not isinstance(self.shares, tuple) or any(
            not isinstance(share, ShareConfig)
            for share in self.shares
        ):
            raise ConfigError("shares must be a tuple of ShareConfig")

        ids: set[str] = set()
        roots: list[tuple[str, ...]] = []

        for share in self.shares:
            if share.share_id in ids:
                raise ConfigError("Duplicate share_id")

            ids.add(share.share_id)
            parts = _root_parts(share.local_root)

            for earlier in roots:
                if (
                    parts[:len(earlier)] == earlier
                    or earlier[:len(parts)] == parts
                ):
                    raise ConfigError(
                        "Shared folders must not overlap or be nested"
                    )

            roots.append(parts)

    def get_share(self, share_id: str) -> ShareConfig | None:
        _identifier(share_id, "share_id")

        return next(
            (
                share for share in self.shares
                if share.share_id == share_id
            ),
            None,
        )


def default_config_path() -> Path:
    """User-local settings, outside the project checkout and synchronized roots."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")

        if not base:
            base = str(Path.home() / "AppData" / "Local")

        return Path(base) / "SyncBridge" / "settings.json"

    base = os.environ.get("XDG_CONFIG_HOME")

    return (
        Path(base)
        if base and Path(base).is_absolute()
        else Path.home() / ".config"
    ) / "syncbridge" / "settings.json"


def _keys(document: object, expected: set[str], label: str) -> dict:
    if not isinstance(document, dict) or set(document) != expected:
        raise ConfigError(f"Invalid {label} fields")
    return document


def _unique(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}

    for key, value in pairs:
        if key in result:
            raise ConfigError(f"Duplicate JSON key: {key}")
        result[key] = value

    return result


def _reject_constant(value: str) -> None:
    raise ConfigError(f"Invalid JSON constant: {value}")


def _decode(raw: bytes) -> AppConfig:
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_constant=_reject_constant,
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ConfigError("Settings file contains invalid JSON") from exc

    _keys(
        document,
        {"format_version", "revision", "device_name", "shares"},
        "settings",
    )

    if (
        type(document["format_version"]) is not int
        or document["format_version"] != FORMAT_VERSION
    ):
        raise ConfigError(
            "Unsupported settings format version; refusing to reset"
        )

    if not isinstance(document["shares"], list):
        raise ConfigError("shares must be an array")

    if len(document["shares"]) > 500:
        raise ConfigError("Too many configured folders")

    expected_share = {field_.name for field_ in fields(ShareConfig)}
    expected_preferences = {
        field_.name for field_ in fields(SyncPreferences)
    }

    shares = []

    for entry in document["shares"]:
        item = _keys(entry, expected_share, "share")
        prefs = _keys(
            item["preferences"],
            expected_preferences,
            "preferences",
        )

        shares.append(
            ShareConfig(
                **{
                    **item,
                    "preferences": SyncPreferences(**prefs),
                }
            )
        )

    return AppConfig(
        revision=document["revision"],
        device_name=document["device_name"],
        shares=tuple(shares),
    )


def _encode(config: AppConfig) -> bytes:
    document = {
        "format_version": FORMAT_VERSION,
        **asdict(config),
    }

    raw = (
        json.dumps(
            document,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ) + "\n"
    ).encode("utf-8")

    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError("Settings exceed maximum file size")

    return raw


@contextmanager
def _write_lock(path: Path, timeout: float = 5.0) -> Iterator[None]:
    """Cooperative, cross-process write lock (msvcrt on Windows, flock on POSIX)."""
    if _linked(path):
        raise ConfigError("Refusing a linked settings lock file")

    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )

    fd = os.open(path, flags, 0o600)

    with os.fdopen(fd, "r+b", buffering=0) as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ConfigError("Settings lock is not a regular file")

        if os.fstat(stream.fileno()).st_size == 0:
            stream.write(b"\0")

        deadline = time.monotonic() + timeout

        if os.name == "nt":
            import msvcrt

            def take() -> None:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)

            def release() -> None:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)

        else:
            import fcntl

            def take() -> None:
                fcntl.flock(
                    stream.fileno(),
                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                )

            def release() -> None:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

        while True:
            try:
                take()
                break
            except (OSError, BlockingIOError) as exc:
                if time.monotonic() >= deadline:
                    raise ConfigConflict(
                        "Settings are locked by another writer"
                    ) from exc

                time.sleep(0.025)

        try:
            yield
        finally:
            release()


class ConfigStore:
    """Versioned JSON settings; save uses compare-and-swap on config.revision."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(
            path if path is not None else default_config_path()
        ).expanduser().absolute()

        if _linked(self.path):
            raise ConfigError(
                "Settings file cannot be a symbolic link or junction"
            )

        self._lock_path = self.path.with_name(
            self.path.name + ".lock"
        )

    def _safe_path(self) -> None:
        if _linked(self.path):
            raise ConfigError(
                "Settings file cannot be a symbolic link or junction"
            )

        if self.path.exists() and not self.path.is_file():
            raise ConfigError("Settings path is not a regular file")

    def load(self) -> AppConfig:
        self._safe_path()

        try:
            with self.path.open("rb") as stream:
                raw = stream.read(MAX_CONFIG_BYTES + 1)
        except FileNotFoundError:
            return AppConfig()

        if len(raw) > MAX_CONFIG_BYTES:
            raise ConfigError("Settings file exceeds size limit")

        return _decode(raw)

    def save(self, config: AppConfig) -> AppConfig:
        """Save and return the new revision; never overwrite concurrent edits.

        A revision starts at 0 before the first save. Callers must reload on a
        ConfigConflict and merge their intended edit rather than retry blindly.
        """
        if not isinstance(config, AppConfig):
            raise TypeError("config must be AppConfig")

        self._safe_path()

        for share in config.shares:
            root = Path(share.local_root).resolve(strict=False)

            if self.path.resolve(strict=False).is_relative_to(root):
                raise ConfigError(
                    "Settings must be outside synchronized folders"
                )

        self.path.parent.mkdir(parents=True, exist_ok=True)

        with _write_lock(self._lock_path):
            existing = self.load()

            if config.revision != existing.revision:
                raise ConfigConflict(
                    f"Stale settings revision {config.revision}; "
                    f"current is {existing.revision}"
                )

            if config.revision == _MAX_REVISION:
                raise ConfigError("Settings revision exhausted")

            updated = replace(
                config,
                revision=config.revision + 1,
            )

            payload = _encode(updated)

            fd, temporary = tempfile.mkstemp(
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                dir=self.path.parent,
            )

            try:
                with os.fdopen(fd, "wb") as stream:
                    if os.name != "nt":
                        os.fchmod(stream.fileno(), 0o600)

                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())

                self._safe_path()
                os.replace(temporary, self.path)

                if os.name != "nt":
                    directory_fd = os.open(
                        self.path.parent,
                        os.O_RDONLY,
                    )

                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)

            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)

            return updated
