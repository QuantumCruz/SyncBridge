
"""Encrypted-transfer recovery when one process vanishes without clean shutdown.

These are real localhost transfers using temporary profiles and test files.
Default test size: 8 MiB. Optional: SYNCBRIDGE_CRASH_MIB=64 (8..128).
A terminated child process simulates application termination, NOT power failure.
"""
from __future__ import annotations

import hashlib
import multiprocessing as mp
import os
import queue
import threading
import time
from pathlib import Path

import pytest

from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.network.transfer import TransferService

MIB = 1024 * 1024
SHARE_ID = "a" * 32
FILE = "dataset/payload.bin"


def _size() -> int:
    raw = os.getenv("SYNCBRIDGE_CRASH_MIB", "8")
    try:
        mib = int(raw)
    except ValueError as exc:
        raise ValueError("SYNCBRIDGE_CRASH_MIB must be an integer") from exc
    if not 8 <= mib <= 128:
        raise ValueError("SYNCBRIDGE_CRASH_MIB must be between 8 and 128")
    return mib * MIB


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(MIB), b""):
            digest.update(block)
    return digest.hexdigest()


def _source_file(root: Path, total: int) -> Path:
    target = root / FILE
    target.parent.mkdir(parents=True)
    block = os.urandom(128 * 1024)
    with target.open("wb") as output:
        for _ in range(total // len(block)):
            output.write(block)
    assert target.stat().st_size == total
    return target


def _setup(tmp_path: Path, total: int):
    alice_profile = tmp_path / "alice-profile"
    bob_profile = tmp_path / "bob-profile"
    alice = load_or_create_identity(alice_profile / "identity.json")
    bob = load_or_create_identity(bob_profile / "identity.json")

    TrustStore(alice_profile / "trust.json").add_verified(
        bob.public_key_hex, confirmed_fingerprint=bob.fingerprint, name="Bob"
    )
    TrustStore(bob_profile / "trust.json").add_verified(
        alice.public_key_hex, confirmed_fingerprint=alice.fingerprint, name="Alice"
    )

    source_root = tmp_path / "alice-files"
    source = _source_file(source_root, total)
    destination_root = tmp_path / "bob-files"

    return (
        alice_profile,
        bob_profile,
        source_root,
        destination_root,
        source,
        alice.node_id,
        bob.node_id,
    )


def _sender(profile: Path) -> TransferService:
    return TransferService(
        load_or_create_identity(profile / "identity.json"),
        TrustStore(profile / "trust.json"),
        profile / "sender-inbox",
        share_id=SHARE_ID,
        bind_address="127.0.0.1",
        listen_port=0,
        handshake_timeout=3,
        io_timeout=10,
    )


def _receiver(
    profile: Path,
    destination: Path,
    alice_id: str,
    on_progress=None,
) -> TransferService:
    return TransferService(
        load_or_create_identity(profile / "identity.json"),
        TrustStore(profile / "trust.json"),
        destination,
        share_id=SHARE_ID,
        allowed_senders=(alice_id,),
        bind_address="127.0.0.1",
        listen_port=0,
        handshake_timeout=3,
        io_timeout=10,
        on_progress=on_progress,
    )


def _send(
    sender: TransferService,
    port: int,
    bob_id: str,
    root: Path,
    on_progress=None,
):
    return sender.send_file(
        "127.0.0.1",
        port,
        bob_id,
        root,
        FILE,
        share_id=SHARE_ID,
        on_progress=on_progress,
    )


def _wait(predicate, seconds: float = 12) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return bool(predicate())


def _parts(destination: Path) -> list[Path]:
    # TransferService derives an adjacent staging directory from the destination.
    # Use its existing placement pattern; never remove directories here.
    return list(destination.parent.glob(".syncbridge-transfer-*/*.part"))


def _killed_sender(
    profile: str,
    root: str,
    port: int,
    bob_id: str,
    cutoff: int,
    reached,
) -> None:
    sender = _sender(Path(profile))

    def block_after_progress(event) -> None:
        if event.transferred >= cutoff:
            reached.set()

            # The PARENT terminates this process while a socket is open.
            # This never sends the transfer protocol's graceful PAUSE frame.
            time.sleep(60)

    _send(
        sender,
        port,
        bob_id,
        Path(root),
        on_progress=block_after_progress,
    )


def _killed_receiver(
    profile: str,
    destination: str,
    alice_id: str,
    cutoff: int,
    port_queue,
    reached,
) -> None:
    def block_after_write(event) -> None:
        if event.transferred >= cutoff:
            reached.set()

            # Leave the transfer stream and a partial staging file open.
            time.sleep(60)

    receiver = _receiver(
        Path(profile),
        Path(destination),
        alice_id,
        on_progress=block_after_write,
    )
    receiver.start()
    port_queue.put(receiver.bound_port)
    time.sleep(60)


def _kill(process: mp.Process) -> None:
    if process.is_alive():
        process.terminate()

    process.join(timeout=8)

    if process.is_alive():
        process.kill()
        process.join(timeout=5)

    assert not process.is_alive(), "The disposable worker did not stop"


def test_sender_process_crash_recovers_from_partial(tmp_path):
    """Killing Alice mid-send must not publish an incomplete file on Bob."""
    size = _size()

    (
        alice_profile,
        bob_profile,
        root,
        destination,
        source,
        alice_id,
        bob_id,
    ) = _setup(tmp_path, size)

    receiver = _receiver(bob_profile, destination, alice_id)
    receiver.start()

    ctx = mp.get_context("spawn")
    reached = ctx.Event()

    worker = ctx.Process(
        target=_killed_sender,
        args=(
            str(alice_profile),
            str(root),
            receiver.bound_port,
            bob_id,
            size // 4,
            reached,
        ),
    )

    try:
        worker.start()

        assert reached.wait(timeout=20), (
            "Sender did not reach crash checkpoint"
        )

        assert _wait(
            lambda: any(
                p.stat().st_size >= size // 4
                for p in _parts(destination)
            )
        ), "Receiver never staged bytes before the crash"

        _kill(worker)

        assert not (destination / FILE).exists()

        assert _wait(
            lambda: not receiver._connections
        ), "Receiver did not release crashed socket"

        partials = _parts(destination)
        assert len(partials) == 1

        offset = partials[0].stat().st_size
        assert 0 < offset < size

        # Now restart the RECEIVE service as well:
        # the saved offset must survive that restart.
        receiver.stop()
        receiver = _receiver(bob_profile, destination, alice_id)
        receiver.start()

        progress = []

        finished = _send(
            _sender(alice_profile),
            receiver.bound_port,
            bob_id,
            root,
            on_progress=progress.append,
        )

        assert progress
        assert progress[0].transferred == offset
        assert finished.completed

        assert _sha256(destination / FILE) == _sha256(source)
        assert _parts(destination) == []

    finally:
        if worker.pid is not None and worker.is_alive():
            _kill(worker)

        receiver.stop()
        worker.close()


def test_receiver_process_crash_recovers_from_partial(tmp_path):
    """Killing Bob mid-receive must leave staging data for a later retry."""
    size = _size()

    (
        alice_profile,
        bob_profile,
        root,
        destination,
        source,
        alice_id,
        bob_id,
    ) = _setup(tmp_path, size)

    ctx = mp.get_context("spawn")
    reached = ctx.Event()
    ports = ctx.Queue()

    child = ctx.Process(
        target=_killed_receiver,
        args=(
            str(bob_profile),
            str(destination),
            alice_id,
            size // 4,
            ports,
            reached,
        ),
    )

    finished = []
    failures = []
    send_thread = None

    try:
        child.start()

        try:
            port = ports.get(timeout=20)
        except queue.Empty:
            pytest.fail(
                f"Receiver never started (exitcode={child.exitcode})"
            )

        sender = _sender(alice_profile)

        def send_until_connection_drops():
            try:
                finished.append(
                    _send(sender, port, bob_id, root)
                )
            except Exception as exc:
                failures.append(exc)

        send_thread = threading.Thread(
            target=send_until_connection_drops,
            daemon=True,
        )
        send_thread.start()

        assert reached.wait(timeout=20), (
            "Receiver did not reach crash checkpoint"
        )

        _kill(child)
        send_thread.join(timeout=15)

        assert not send_thread.is_alive(), (
            "Sender did not detect lost receiver"
        )
        assert failures and not finished, (
            "Interrupted send must not claim success"
        )

        assert not (destination / FILE).exists()

        partials = _parts(destination)
        assert len(partials) == 1

        offset = partials[0].stat().st_size
        assert 0 < offset < size

        receiver = _receiver(
            bob_profile,
            destination,
            alice_id,
        )
        receiver.start()

        try:
            progress = []

            completed = _send(
                _sender(alice_profile),
                receiver.bound_port,
                bob_id,
                root,
                on_progress=progress.append,
            )

            assert progress
            assert progress[0].transferred == offset
            assert completed.completed

            assert _sha256(destination / FILE) == _sha256(source)
            assert _parts(destination) == []

        finally:
            receiver.stop()

    finally:
        if child.pid is not None and child.is_alive():
            _kill(child)

        ports.close()
        ports.join_thread()

        if send_thread is not None and send_thread.is_alive():
            send_thread.join(timeout=12)

        child.close()
