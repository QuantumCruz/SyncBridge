
"""Real encrypted localhost recovery tests using disposable files only.

Default payload: 8 MiB. To exercise a larger file in PowerShell:
    $env:SYNCBRIDGE_STRESS_MIB = "64"
    python -m pytest tests/integration/test_transfer_recovery_stress.py -v
    Remove-Item Env:SYNCBRIDGE_STRESS_MIB

Every test uses pytest's tmp_path, never a real synchronized folder.
This tests controlled pause and service restart, NOT a hard power failure.
"""
from __future__ import annotations

import hashlib
import os
import threading
from pathlib import Path

import pytest

from syncbridge.network.security import DeviceIdentity, TrustStore
from syncbridge.network.transfer import TransferError, TransferService


MIB = 1024 * 1024
SHARE_ID = "a" * 32
RELATIVE_PATH = "dataset/big.bin"


def payload_size() -> int:
    raw = os.environ.get("SYNCBRIDGE_STRESS_MIB", "8")
    try:
        mib = int(raw)
    except ValueError as exc:
        raise ValueError(
            "SYNCBRIDGE_STRESS_MIB must be a whole number"
        ) from exc

    if not 4 <= mib <= 256:
        raise ValueError(
            "SYNCBRIDGE_STRESS_MIB must be between 4 and 256"
        )

    return mib * MIB


def make_payload(root: Path, size: int) -> str:
    """Write binary test data without a large RAM allocation."""
    source = root / RELATIVE_PATH
    source.parent.mkdir(parents=True, exist_ok=True)

    block = os.urandom(256 * 1024)
    digest = hashlib.sha256()
    remaining = size

    with source.open("wb") as handle:
        while remaining:
            piece = block[:min(len(block), remaining)]
            handle.write(piece)
            digest.update(piece)
            remaining -= len(piece)

    return digest.hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(MIB), b""):
            digest.update(chunk)

    return digest.hexdigest()


def make_peers(tmp_path: Path):
    alice = DeviceIdentity.generate()
    bob = DeviceIdentity.generate()

    alice_trust = TrustStore(
        tmp_path / "alice-trust.json"
    )
    bob_trust = TrustStore(
        tmp_path / "bob-trust.json"
    )

    alice_trust.add_verified(
        bob.public_key_hex,
        confirmed_fingerprint=bob.fingerprint,
        name="Bob",
    )

    bob_trust.add_verified(
        alice.public_key_hex,
        confirmed_fingerprint=alice.fingerprint,
        name="Alice",
    )

    source_root = tmp_path / "alice-files"
    source_root.mkdir()
    destination = tmp_path / "bob-files"

    sender = TransferService(
        alice,
        alice_trust,
        tmp_path / "alice-inbox",
        share_id=SHARE_ID,
        bind_address="127.0.0.1",
        listen_port=0,
        handshake_timeout=3,
        io_timeout=30,
    )

    def new_receiver():
        return TransferService(
            bob,
            bob_trust,
            destination,
            share_id=SHARE_ID,
            allowed_senders=(alice.node_id,),
            bind_address="127.0.0.1",
            listen_port=0,
            handshake_timeout=3,
            io_timeout=30,
        )

    return (
        source_root,
        destination,
        sender,
        bob,
        new_receiver,
    )


def send(
    sender,
    receiver,
    bob,
    source_root,
    **kwargs,
):
    assert receiver.bound_port is not None

    return sender.send_file(
        "127.0.0.1",
        receiver.bound_port,
        bob.node_id,
        source_root,
        RELATIVE_PATH,
        share_id=SHARE_ID,
        **kwargs,
    )


def test_large_file_resumes_after_two_pauses_and_fresh_receivers(
    tmp_path,
):
    """Resume an encrypted transfer across receiver service restarts."""
    size = payload_size()

    (
        source,
        destination,
        sender,
        bob,
        receiver_factory,
    ) = make_peers(tmp_path)

    expected_hash = make_payload(source, size)
    target = destination / RELATIVE_PATH

    receiver = receiver_factory()
    receiver.start()

    previous_offset = 0

    try:
        for cutoff in (
            size // 5,
            size * 3 // 5,
        ):
            cancel = threading.Event()
            events = []

            def report(event):
                events.append(event)

                if event.transferred >= cutoff:
                    cancel.set()

            paused = send(
                sender,
                receiver,
                bob,
                source,
                cancel_event=cancel,
                on_progress=report,
            )

            assert not paused.completed
            assert previous_offset < paused.transferred < size
            assert paused.transferred >= cutoff

            # The new connection must pick up where the last ended.
            assert events[0].transferred == previous_offset

            # An unfinished file must never be visible as complete.
            assert not target.exists()

            staged = list(
                receiver._staging.glob("*.part")
            )
            assert len(staged) == 1

            previous_offset = paused.transferred

            # Simulate the receiving transfer SERVICE restarting.
            # The new object keeps the same identity, permissions,
            # destination path, and existing staging files.
            receiver.stop()

            receiver = receiver_factory()
            receiver.start()

        progress = []

        finished = send(
            sender,
            receiver,
            bob,
            source,
            on_progress=progress.append,
        )

        assert finished.completed
        assert finished.total == size

        # The final attempt resumes from the saved offset.
        assert progress[0].transferred == previous_offset

        # Verify the actual published destination.
        assert target.is_file()
        assert target.stat().st_size == size
        assert file_sha256(target) == expected_hash

        # Successful publication must clean up partial staging data.
        assert not list(
            receiver._staging.glob("*.part")
        )

    finally:
        receiver.stop()


def test_corrupted_partial_is_rejected_before_publication(
    tmp_path,
):
    """Corrupt staging data and verify that it cannot be published."""
    size = payload_size()

    (
        source,
        destination,
        sender,
        bob,
        receiver_factory,
    ) = make_peers(tmp_path)

    make_payload(source, size)

    receiver = receiver_factory()
    receiver.start()

    try:
        cancel = threading.Event()

        partial = send(
            sender,
            receiver,
            bob,
            source,
            cancel_event=cancel,
            on_progress=lambda event: (
                cancel.set()
                if event.transferred >= size // 4
                else None
            ),
        )

        assert not partial.completed
        assert 0 < partial.transferred < size

        staged = list(
            receiver._staging.glob("*.part")
        )
        assert len(staged) == 1

        # Deliberately damage the unfinished file.
        # The receiver must not accept these bytes as valid.
        with staged[0].open("r+b") as handle:
            handle.seek(0)
            handle.write(b"CORRUPTED-PARTIAL")

        receiver.stop()
        receiver = receiver_factory()
        receiver.start()

        with pytest.raises(
            TransferError,
            match="hash mismatch",
        ):
            send(
                sender,
                receiver,
                bob,
                source,
            )

        # The invalid file must not appear in the shared directory.
        assert not (
            destination / RELATIVE_PATH
        ).exists()

        assert not list(
            receiver._staging.glob("*.part")
        )

    finally:
        receiver.stop()
