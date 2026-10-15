
"""Real localhost transport tests; use the project's secure channel implementation."""

from __future__ import annotations

import hashlib
import os
import socket
import threading
import time

import pytest

from syncbridge.network.security import DeviceIdentity, TrustStore
from syncbridge.network.transfer import TransferError, TransferService


def services(tmp_path, *, permit=True, overwrite=False):
    alice = DeviceIdentity.generate()
    bob = DeviceIdentity.generate()

    a_trust = TrustStore(
        tmp_path / "alice-trust.json"
    )
    b_trust = TrustStore(
        tmp_path / "bob-trust.json"
    )

    a_trust.add_verified(
        bob.public_key_hex,
        confirmed_fingerprint=bob.fingerprint,
        name="Bob",
    )

    b_trust.add_verified(
        alice.public_key_hex,
        confirmed_fingerprint=alice.fingerprint,
        name="Alice",
    )

    source = tmp_path / "source"
    source.mkdir()

    receiver = TransferService(
        bob,
        b_trust,
        tmp_path / "destination",
        bind_address="127.0.0.1",
        allowed_senders=[alice.node_id] if permit else [],
        allow_overwrite=overwrite,
        listen_port=0,
        handshake_timeout=1,
        io_timeout=2,
    )

    sender = TransferService(
        alice,
        a_trust,
        tmp_path / "sender-inbox",
        bind_address="127.0.0.1",
        handshake_timeout=1,
        io_timeout=2,
    )

    receiver.start()

    return source, sender, receiver


def push(source, sender, receiver, name, **kwargs):
    return sender.send_file(
        "127.0.0.1",
        receiver.bound_port,
        receiver.identity.node_id,
        source,
        name,
        **kwargs,
    )


def test_nested_large_transfer_and_hash(tmp_path):
    source, sender, receiver = services(tmp_path)

    (source / "nested").mkdir()

    contents = os.urandom(700_000)
    (source / "nested" / "binary.dat").write_bytes(contents)

    events = []

    try:
        result = push(
            source,
            sender,
            receiver,
            "nested/binary.dat",
            on_progress=events.append,
        )

        assert result.completed
        assert result.transferred == len(contents)
        assert result.sha256 == hashlib.sha256(contents).hexdigest()

        received = (
            receiver.destination_root
            / "nested"
            / "binary.dat"
        )

        assert received.read_bytes() == contents
        assert events[-1].transferred == len(contents)
        assert events[-1].direction == "send"

    finally:
        receiver.stop()


def test_zero_byte_file(tmp_path):
    source, sender, receiver = services(tmp_path)

    (source / "empty.txt").touch()

    try:
        result = push(
            source,
            sender,
            receiver,
            "empty.txt",
        )

        assert result.completed
        assert result.total == 0

        assert (
            receiver.destination_root / "empty.txt"
        ).read_bytes() == b""

    finally:
        receiver.stop()


def test_cancel_resume_across_receiver_restart(tmp_path):
    source, sender, receiver = services(tmp_path)

    payload = os.urandom(800_000)
    (source / "big.bin").write_bytes(payload)

    cancelled = threading.Event()

    def cancel_after_first(update):
        if update.transferred >= 65_536:
            cancelled.set()

    try:
        partial = push(
            source,
            sender,
            receiver,
            "big.bin",
            cancel_event=cancelled,
            on_progress=cancel_after_first,
        )

        assert not partial.completed
        assert 0 < partial.transferred < len(payload)

        assert not (
            receiver.destination_root / "big.bin"
        ).exists()

        assert len(
            list(receiver._staging.glob("*.part"))
        ) == 1

        receiver.stop()
        receiver.start()

        resumed = []

        result = push(
            source,
            sender,
            receiver,
            "big.bin",
            on_progress=resumed.append,
        )

        assert result.completed
        assert resumed[0].transferred == partial.transferred

        assert (
            receiver.destination_root / "big.bin"
        ).read_bytes() == payload

        assert not list(
            receiver._staging.glob("*.part")
        )

    finally:
        receiver.stop()


def test_existing_destination_preserved_by_default(tmp_path):
    source, sender, receiver = services(tmp_path)

    (source / "doc.txt").write_text("new")
    (receiver.destination_root / "doc.txt").write_text("old")

    try:
        with pytest.raises(
            TransferError,
            match="already exists",
        ):
            push(
                source,
                sender,
                receiver,
                "doc.txt",
            )

        assert (
            receiver.destination_root / "doc.txt"
        ).read_text() == "old"

    finally:
        receiver.stop()


def test_explicit_overwrite(tmp_path):
    source, sender, receiver = services(
        tmp_path,
        overwrite=True,
    )

    (source / "doc.txt").write_text("new")
    (receiver.destination_root / "doc.txt").write_text("old")

    try:
        assert push(
            source,
            sender,
            receiver,
            "doc.txt",
        ).completed

        assert (
            receiver.destination_root / "doc.txt"
        ).read_text() == "new"

    finally:
        receiver.stop()


def test_unpermitted_sender_cannot_write(tmp_path):
    source, sender, receiver = services(
        tmp_path,
        permit=False,
    )

    (source / "doc.txt").write_text("secret")

    try:
        with pytest.raises(TransferError):
            push(
                source,
                sender,
                receiver,
                "doc.txt",
            )

        assert not (
            receiver.destination_root / "doc.txt"
        ).exists()

    finally:
        receiver.stop()


def test_live_revocation_blocks_transfer(tmp_path):
    source, sender, receiver = services(tmp_path)

    (source / "doc.txt").write_text("hello")

    receiver.revoke_sender(
        sender.identity.node_id
    )

    try:
        with pytest.raises(TransferError):
            push(
                source,
                sender,
                receiver,
                "doc.txt",
            )

        receiver.authorize_sender(
            sender.identity.node_id
        )

        assert push(
            source,
            sender,
            receiver,
            "doc.txt",
        ).completed

    finally:
        receiver.stop()


@pytest.mark.parametrize(
    "bad",
    [
        "../secret",
        "/absolute",
        "C:/evil",
        "a\\b",
        "dir//file",
        "CON.txt",
        "file.txt.",
        "a/../b",
    ],
)
def test_unsafe_source_paths_rejected(tmp_path, bad):
    source, sender, receiver = services(tmp_path)

    try:
        with pytest.raises(TransferError):
            push(
                source,
                sender,
                receiver,
                bad,
            )

    finally:
        receiver.stop()


def test_source_symlink_rejected_when_supported(tmp_path):
    source, sender, receiver = services(tmp_path)

    outside = tmp_path / "outside.txt"
    outside.write_text("outside")

    alias = source / "alias.txt"

    try:
        alias.symlink_to(outside)
    except (OSError, NotImplementedError):
        receiver.stop()
        pytest.skip("Symlink unavailable on Windows")

    try:
        with pytest.raises(TransferError):
            push(
                source,
                sender,
                receiver,
                "alias.txt",
            )

    finally:
        receiver.stop()


def test_receive_progress_and_stop_restart(tmp_path):
    source, sender, receiver = services(tmp_path)

    (source / "doc.txt").write_bytes(
        os.urandom(130_000)
    )

    progress = []
    receiver._on_progress = progress.append

    try:
        assert push(
            source,
            sender,
            receiver,
            "doc.txt",
        ).completed

        assert progress[-1].direction == "receive"
        assert progress[-1].transferred == 130_000

        receiver.stop()
        receiver.start()

        assert receiver.is_running

    finally:
        receiver.stop()


def test_unpaired_sender_denied(tmp_path):
    source, sender, receiver = services(tmp_path)

    (source / "doc.txt").write_text("secret")

    receiver.trust_store.remove(
        sender.identity.node_id
    )

    try:
        with pytest.raises(TransferError):
            push(
                source,
                sender,
                receiver,
                "doc.txt",
            )

    finally:
        receiver.stop()


def test_idempotent_repeat_returns_success_without_rewriting(tmp_path):
    source, sender, receiver = services(tmp_path)

    (source / "doc.txt").write_text("identical")

    try:
        first = push(
            source,
            sender,
            receiver,
            "doc.txt",
        )

        assert first.completed

        second = push(
            source,
            sender,
            receiver,
            "doc.txt",
        )

        assert second.completed
        assert second.sha256 == first.sha256

        assert (
            receiver.destination_root / "doc.txt"
        ).read_text() == "identical"

    finally:
        receiver.stop()


def test_corrupt_partial_cannot_be_published(tmp_path):
    source, sender, receiver = services(tmp_path)

    content = os.urandom(220_000)
    (source / "doc.bin").write_bytes(content)

    cancel = threading.Event()

    try:
        result = push(
            source,
            sender,
            receiver,
            "doc.bin",
            cancel_event=cancel,
            on_progress=lambda event: (
                cancel.set()
                if event.transferred
                else None
            ),
        )

        assert not result.completed

        part = next(
            receiver._staging.glob("*.part")
        )

        with part.open("r+b") as damaged:
            damaged.seek(0)
            damaged.write(b"altered")

        with pytest.raises(
            TransferError,
            match="hash mismatch",
        ):
            push(
                source,
                sender,
                receiver,
                "doc.bin",
            )

        assert not (
            receiver.destination_root / "doc.bin"
        ).exists()

        assert not list(
            receiver._staging.glob("*.part")
        )

    finally:
        receiver.stop()
