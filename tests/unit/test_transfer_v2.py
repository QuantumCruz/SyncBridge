
"""Modern share-bound push, pull and conditional update integration tests."""

from __future__ import annotations

import hashlib
import os
import threading
from uuid import uuid4

import pytest

from syncbridge.network.security import DeviceIdentity, TrustStore
from syncbridge.network.transfer import TransferError, TransferService


@pytest.fixture
def pair(tmp_path):
    alice = DeviceIdentity.generate()
    bob = DeviceIdentity.generate()

    store_a = TrustStore(tmp_path / "alice-trust.json")
    store_b = TrustStore(tmp_path / "bob-trust.json")

    store_a.add_verified(
        bob.public_key_hex,
        confirmed_fingerprint=bob.fingerprint,
        name="Bob"
    )
    store_b.add_verified(
        alice.public_key_hex,
        confirmed_fingerprint=alice.fingerprint,
        name="Alice"
    )

    root_a = tmp_path / "a"
    root_b = tmp_path / "b"
    root_a.mkdir()
    root_b.mkdir()

    share = uuid4().hex

    opts = dict(
        bind_address="127.0.0.1",
        listen_port=0,
        handshake_timeout=1.5,
        io_timeout=3.0
    )

    sa = TransferService(
        alice,
        store_a,
        root_a,
        share_id=share,
        allowed_senders=[bob.node_id],
        allowed_readers=[bob.node_id],
        allow_overwrite=True,
        **opts
    )
    sb = TransferService(
        bob,
        store_b,
        root_b,
        share_id=share,
        allowed_senders=[alice.node_id],
        allowed_readers=[alice.node_id],
        allow_overwrite=True,
        **opts
    )

    sa.start()
    sb.start()

    try:
        yield sa, sb, root_a, root_b, share
    finally:
        sa.stop()
        sb.stop()


def push(pair, name, *, from_b=False, **kw):
    a, b, ra, rb, share = pair
    sender, receiver, root = (
        (b, a, rb) if from_b else (a, b, ra)
    )

    return sender.send_file(
        "127.0.0.1",
        receiver.bound_port,
        receiver.identity.node_id,
        root,
        name,
        share_id=share,
        **kw
    )


def pull(pair, name, *, from_b=False, **kw):
    a, b, ra, rb, share = pair
    receiver, sender = (
        (b, a) if from_b else (a, b)
    )

    return receiver.fetch_file(
        "127.0.0.1",
        sender.bound_port,
        sender.identity.node_id,
        share,
        name,
        **kw
    )


def test_new_file_push_and_pull(pair):
    a, b, ra, rb, share = pair

    data = os.urandom(180_000)

    (ra / "nested").mkdir()
    (ra / "nested" / "big.bin").write_bytes(data)

    assert push(
        pair, "nested/big.bin"
    ).completed

    assert (
        rb / "nested" / "big.bin"
    ).read_bytes() == data

    (rb / "from-b.txt").write_text("from B")

    assert pull(
        pair, "from-b.txt"
    ).completed

    assert (
        ra / "from-b.txt"
    ).read_text() == "from B"


def test_pull_requires_reader_permission(pair):
    a, b, ra, rb, share = pair

    (rb / "secret.txt").write_text("secret")

    b.revoke_reader(a.identity.node_id)

    with pytest.raises(
        TransferError, match="permission"
    ):
        pull(pair, "secret.txt")

    assert not (ra / "secret.txt").exists()

    b.authorize_reader(a.identity.node_id)

    assert pull(
        pair, "secret.txt"
    ).completed


def test_push_requires_sender_permission(pair):
    a, b, ra, rb, share = pair

    (ra / "secret.txt").write_text("secret")
    b.revoke_sender(a.identity.node_id)

    with pytest.raises(
        TransferError, match="not authorized"
    ):
        push(pair, "secret.txt")

    assert not (rb / "secret.txt").exists()


def test_strict_server_rejects_wrong_share_and_legacy_offer(pair):
    a, b, ra, rb, share = pair

    (ra / "file.txt").write_text("ok")

    with pytest.raises(TransferError, match="share"):
        a.send_file(
            "127.0.0.1",
            b.bound_port,
            b.identity.node_id,
            ra,
            "file.txt",
            share_id=uuid4().hex
        )

    legacy = TransferService(
        a.identity,
        a.trust_store,
        ra,
        listen_port=0
    )

    with pytest.raises(TransferError, match="offer"):
        legacy.send_file(
            "127.0.0.1",
            b.bound_port,
            b.identity.node_id,
            ra,
            "file.txt"
        )

    with pytest.raises(TransferError, match="share"):
        a.fetch_file(
            "127.0.0.1",
            b.bound_port,
            b.identity.node_id,
            uuid4().hex,
            "file.txt"
        )

    assert not (rb / "file.txt").exists()


def test_conditional_overwrite_success(pair):
    a, b, ra, rb, share = pair

    (ra / "same.txt").write_text("new")
    (rb / "same.txt").write_text("old")

    old = hashlib.sha256(b"old").hexdigest()

    assert push(
        pair,
        "same.txt",
        expected_destination_sha256=old
    ).completed

    assert (rb / "same.txt").read_text() == "new"

    # Idempotent retry does not replace identical content.
    assert push(
        pair,
        "same.txt",
        expected_destination_sha256=old
    ).completed


def test_reject_stale_expected_hash(pair):
    a, b, ra, rb, share = pair

    (ra / "same.txt").write_text("new")
    (rb / "same.txt").write_text("other")

    with pytest.raises(
        TransferError, match="mismatch"
    ):
        push(
            pair,
            "same.txt",
            expected_destination_sha256=hashlib.sha256(
                b"old"
            ).hexdigest()
        )

    assert (rb / "same.txt").read_text() == "other"


def test_no_unconditional_overwrite_in_strict_mode(pair):
    a, b, ra, rb, share = pair

    (ra / "same.txt").write_text("new")
    (rb / "same.txt").write_text("old")

    with pytest.raises(
        TransferError, match="Conditional"
    ):
        push(pair, "same.txt")

    assert (rb / "same.txt").read_text() == "old"


def test_conditional_pull_overwrite(pair):
    a, b, ra, rb, share = pair

    (ra / "same.txt").write_text("old")
    (rb / "same.txt").write_text("new")

    old = hashlib.sha256(b"old").hexdigest()
    new = hashlib.sha256(b"new").hexdigest()

    result = pull(
        pair,
        "same.txt",
        expected_destination_sha256=old,
        expected_source_sha256=new
    )

    assert result.completed
    assert (ra / "same.txt").read_text() == "new"


def test_pull_stale_source_refused(pair):
    a, b, ra, rb, share = pair

    (rb / "file.txt").write_text("changed")

    with pytest.raises(
        TransferError, match="expected SHA-256"
    ):
        pull(
            pair,
            "file.txt",
            expected_source_sha256=hashlib.sha256(
                b"old"
            ).hexdigest()
        )

    assert not (ra / "file.txt").exists()


def test_pull_no_unconditional_overwrite(pair):
    a, b, ra, rb, share = pair

    (ra / "file.txt").write_text("local")
    (rb / "file.txt").write_text("remote")

    with pytest.raises(
        TransferError, match="Conditional"
    ):
        pull(pair, "file.txt")

    assert (ra / "file.txt").read_text() == "local"


def test_pull_resume_across_restarts(pair):
    a, b, ra, rb, share = pair

    content = os.urandom(500_000)
    (rb / "large.bin").write_bytes(content)

    paused = threading.Event()
    updates = []

    def progress(event):
        updates.append(event)
        if event.transferred >= 65_536:
            paused.set()

    incomplete = pull(
        pair,
        "large.bin",
        cancel_event=paused,
        on_progress=progress
    )

    assert not incomplete.completed
    assert incomplete.transferred >= 65_536
    assert not (ra / "large.bin").exists()

    a.stop()
    a.start()

    resume = []

    final = pull(
        pair,
        "large.bin",
        on_progress=resume.append
    )

    assert final.completed
    assert resume[0].transferred == incomplete.transferred
    assert (ra / "large.bin").read_bytes() == content


def test_corrupted_partial_never_publishes(pair):
    a, b, ra, rb, share = pair

    data = os.urandom(300_000)
    (rb / "damaged.bin").write_bytes(data)

    event = threading.Event()

    first = pull(
        pair,
        "damaged.bin",
        cancel_event=event,
        on_progress=lambda e: (
            event.set()
            if e.transferred >= 65_536
            else None
        )
    )

    assert not first.completed

    part = next(a._staging.glob("*.part"))

    with part.open("r+b") as stream:
        stream.write(b"broken")

    with pytest.raises(
        TransferError, match="hash mismatch"
    ):
        pull(pair, "damaged.bin")

    assert not (ra / "damaged.bin").exists()


def test_pull_empty_file(pair):
    a, b, ra, rb, share = pair

    (rb / "empty").touch()

    assert pull(pair, "empty").completed
    assert (ra / "empty").read_bytes() == b""


def test_push_denies_metadata_paths(pair):
    a, b, ra, rb, share = pair

    (ra / ".git").mkdir()
    (ra / ".git" / "secret").write_bytes(b"x")

    with pytest.raises(
        TransferError, match="Unsafe"
    ):
        push(pair, ".git/secret")

    assert not (rb / ".git").exists()


def test_mismatched_local_fetch_share_rejected(pair):
    a, b, ra, rb, share = pair

    (rb / "file.txt").write_text("x")

    with pytest.raises(
        TransferError, match="another share"
    ):
        a.fetch_file(
            "127.0.0.1",
            b.bound_port,
            b.identity.node_id,
            uuid4().hex,
            "file.txt"
        )


def test_unknown_unpaired_peer_refused(pair):
    a, b, ra, rb, share = pair

    (rb / "file.txt").write_text("x")
    a.trust_store.remove(b.identity.node_id)

    with pytest.raises(TransferError):
        pull(pair, "file.txt")


def test_local_send_requires_matching_share(pair):
    a, b, ra, rb, share = pair

    (ra / "file.txt").write_text("A")

    with pytest.raises(
        TransferError, match="another share"
    ):
        a.send_file(
            "127.0.0.1",
            b.bound_port,
            b.identity.node_id,
            ra,
            "file.txt",
            share_id=uuid4().hex
        )

    with pytest.raises(
        TransferError, match="another share"
    ):
        a.send_file(
            "127.0.0.1",
            b.bound_port,
            b.identity.node_id,
            ra,
            "file.txt"
        )


def test_receiver_must_opt_into_replacement(pair):
    a, b, ra, rb, share = pair

    (ra / "file.txt").write_text("new")
    (rb / "file.txt").write_text("old")

    b.allow_overwrite = False

    with pytest.raises(
        TransferError, match="conflict resolution"
    ):
        push(
            pair,
            "file.txt",
            expected_destination_sha256=hashlib.sha256(
                b"old"
            ).hexdigest()
        )

    assert (rb / "file.txt").read_text() == "old"
