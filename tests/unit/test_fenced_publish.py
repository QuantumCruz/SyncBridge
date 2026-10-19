
"""Safety tests for the receiver-local fenced file publication boundary.

This is deliberately separate from authenticated network service integration.
All files and lease databases are disposable pytest fixtures.
"""
from __future__ import annotations

import hashlib
import os
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from syncbridge.network.fenced_publish import (
    FencedFilePublisher,
    PublishConflict,
)
from syncbridge.network.lease_fencing import (
    FencedOut,
    LeaseAuthority,
)

SHARE = "a" * 32
OTHER_SHARE = "f" * 32
ALICE = "b" * 32
BOB = "c" * 32


class FakeClock:
    def __init__(self) -> None:
        self.current = 1000.0

    def __call__(self) -> float:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += seconds


@pytest.fixture
def setup(tmp_path):
    destination = tmp_path / "Share"
    staging = tmp_path / "Staging"
    destination.mkdir()
    staging.mkdir()

    clock = FakeClock()

    authority = LeaseAuthority(
        tmp_path / "Profile" / "fences.db",
        clock=clock,
    )

    publisher = FencedFilePublisher(
        authority,
        SHARE,
        destination,
        staging,
    )

    lease = authority.acquire(
        SHARE,
        ALICE,
        ttl_seconds=10,
    )

    return destination, staging, clock, authority, publisher, lease


def _stage(staging: Path, content: bytes, *, digit: str = "0"):
    name = digit * 64 + ".part"
    (staging / name).write_bytes(content)
    return name


def _publish(
    publisher,
    lease,
    staging,
    data: bytes,
    *,
    name="0",
    relative="note.txt",
    expected=None,
    peer=ALICE,
):
    stage = _stage(staging, data, digit=name)

    return publisher.publish(
        lease,
        authenticated_peer_id=peer,
        relative_path=relative,
        staging_name=stage,
        expected_size=len(data),
        expected_sha256=hashlib.sha256(data).hexdigest(),
        expected_destination_sha256=expected,
    )


def test_current_holder_can_create_a_verified_file(setup):
    destination, staging, _, _, publisher, lease = setup

    result = _publish(
        publisher,
        lease,
        staging,
        b"secure bytes",
        relative="nested/note.txt",
    )

    assert not result.already_present
    assert result.path == "nested/note.txt"
    assert (
        destination / "nested" / "note.txt"
    ).read_bytes() == b"secure bytes"
    assert not (staging / ("0" * 64 + ".part")).exists()


def test_same_file_is_idempotent_but_requires_valid_lease(setup):
    destination, staging, _, authority, publisher, lease = setup

    _publish(publisher, lease, staging, b"same")

    result = _publish(
        publisher,
        lease,
        staging,
        b"same",
        name="1",
    )

    assert result.already_present
    assert not (staging / ("1" * 64 + ".part")).exists()

    authority.release(lease)
    _stage(staging, b"same", digit="2")

    with pytest.raises(FencedOut):
        _publish(
            publisher,
            lease,
            staging,
            b"same",
            name="2",
        )

    assert (
        destination / "note.txt"
    ).read_bytes() == b"same"


def test_conditional_overwrite_requires_matching_old_hash(setup):
    destination, staging, _, _, publisher, lease = setup

    target = destination / "note.txt"
    target.write_bytes(b"old")

    result = _publish(
        publisher,
        lease,
        staging,
        b"new",
        expected=hashlib.sha256(b"old").hexdigest(),
    )

    assert result.already_present is False
    assert target.read_bytes() == b"new"


def test_unexpected_destination_edit_is_not_overwritten(setup):
    destination, staging, _, _, publisher, lease = setup

    target = destination / "note.txt"
    target.write_bytes(b"other person's edits")

    with pytest.raises(PublishConflict, match="Destination changed"):
        _publish(
            publisher,
            lease,
            staging,
            b"new",
            expected=hashlib.sha256(b"old").hexdigest(),
        )

    assert target.read_bytes() == b"other person's edits"
    assert (staging / ("0" * 64 + ".part")).exists()


def test_missing_destination_rejects_expected_existing_hash(setup):
    destination, staging, _, _, publisher, lease = setup

    with pytest.raises(PublishConflict, match="disappeared"):
        _publish(
            publisher,
            lease,
            staging,
            b"new",
            expected=hashlib.sha256(b"old").hexdigest(),
        )

    assert not (destination / "note.txt").exists()


def test_expired_and_superseded_lease_cannot_publish(setup):
    destination, staging, clock, authority, publisher, old = setup

    clock.advance(11)
    replacement = authority.acquire(SHARE, BOB)

    with pytest.raises(FencedOut):
        _publish(
            publisher,
            old,
            staging,
            b"old session",
        )

    assert not (destination / "note.txt").exists()
    assert (staging / ("0" * 64 + ".part")).exists()
    assert authority.assert_current(replacement) == replacement


def test_replayed_same_owner_lease_and_forged_token_rejected(setup):
    destination, staging, _, authority, publisher, old = setup

    authority.release(old)
    new = authority.acquire(SHARE, ALICE)

    for bad in (
        old,
        replace(new, session_token="e" * 64),
    ):
        with pytest.raises(FencedOut):
            _publish(
                publisher,
                bad,
                staging,
                b"old bytes",
            )

    _publish(
        publisher,
        new,
        staging,
        b"good bytes",
        name="1",
    )

    assert (
        destination / "note.txt"
    ).read_bytes() == b"good bytes"


def test_wrong_peer_and_wrong_share_rejected(setup):
    destination, staging, _, authority, publisher, lease = setup

    with pytest.raises(FencedOut, match="peer and share"):
        _publish(
            publisher,
            lease,
            staging,
            b"fake",
            peer=BOB,
        )

    other = authority.acquire(OTHER_SHARE, ALICE)

    with pytest.raises(FencedOut, match="peer and share"):
        _publish(
            publisher,
            other,
            staging,
            b"fake",
        )

    assert not (destination / "note.txt").exists()


def test_staged_digest_mismatch_cannot_publish(setup):
    destination, staging, _, _, publisher, lease = setup

    filename = _stage(staging, b"modified")

    with pytest.raises(PublishConflict, match="Staged file"):
        publisher.publish(
            lease,
            authenticated_peer_id=ALICE,
            relative_path="note.txt",
            staging_name=filename,
            expected_size=8,
            expected_sha256=hashlib.sha256(
                b"expected"
            ).hexdigest(),
            expected_destination_sha256=None,
        )

    assert not (destination / "note.txt").exists()


@pytest.mark.parametrize(
    "bad",
    [
        "../outside.part",
        "other.part",
        "a" * 64 + ".json",
    ],
)
def test_unsafe_staging_names_are_rejected(setup, bad):
    destination, _, _, _, publisher, lease = setup

    with pytest.raises(ValueError, match="staging filename"):
        publisher.publish(
            lease,
            authenticated_peer_id=ALICE,
            relative_path="note.txt",
            staging_name=bad,
            expected_size=0,
            expected_sha256=hashlib.sha256(b"").hexdigest(),
            expected_destination_sha256=None,
        )

    assert not (destination / "note.txt").exists()


def test_path_traversal_is_rejected(setup):
    destination, staging, _, _, publisher, lease = setup

    with pytest.raises(
        Exception,
        match="relative file path|Unsafe relative",
    ):
        _publish(
            publisher,
            lease,
            staging,
            b"bad",
            relative="../escape.txt",
        )

    assert not (destination.parent / "escape.txt").exists()


def test_expiration_during_stage_verification_prevents_publication(
    setup,
    monkeypatch,
):
    destination, staging, clock, _, publisher, lease = setup

    from syncbridge.network import fenced_publish as module

    original = module._regular_fingerprint

    def delayed_verify(path):
        result = original(path)
        clock.advance(11)
        return result

    monkeypatch.setattr(
        module,
        "_regular_fingerprint",
        delayed_verify,
    )

    with pytest.raises(FencedOut):
        _publish(
            publisher,
            lease,
            staging,
            b"late",
        )

    assert not (destination / "note.txt").exists()


def test_concurrent_lease_release_waits_until_publish_finishes(
    setup,
    monkeypatch,
):
    destination, staging, _, authority, publisher, lease = setup

    entered = threading.Event()
    proceed = threading.Event()
    release_finished = threading.Event()
    failures = []

    original = publisher._publish_file

    def held_publish(stage, target, exists):
        entered.set()

        if not proceed.wait(timeout=5):
            raise TimeoutError(
                "Test did not release the publication"
            )

        original(stage, target, exists)

    monkeypatch.setattr(
        publisher,
        "_publish_file",
        held_publish,
    )

    def publish_worker():
        try:
            _publish(
                publisher,
                lease,
                staging,
                b"committed",
            )
        except BaseException as exc:
            failures.append(exc)

    def release_worker():
        try:
            authority.release(lease)
        except BaseException as exc:
            failures.append(exc)
        finally:
            release_finished.set()

    a = threading.Thread(target=publish_worker)
    b = threading.Thread(target=release_worker)

    try:
        a.start()
        assert entered.wait(timeout=5)

        b.start()

        assert not release_finished.wait(timeout=0.2), (
            "Lease was revoked during publication"
        )

    finally:
        proceed.set()
        a.join(timeout=5)
        b.join(timeout=7)

    assert not a.is_alive() and not b.is_alive()
    assert not failures
    assert release_finished.is_set()
    assert (
        destination / "note.txt"
    ).read_bytes() == b"committed"

    with pytest.raises(FencedOut):
        authority.assert_current(lease)


def test_create_if_absent_does_not_clobber_an_unrelated_writer(
    setup,
    monkeypatch,
):
    destination, staging, _, _, publisher, lease = setup

    original_link = os.link

    def competing_create(source, target, *args, **kwargs):
        Path(target).write_bytes(b"third party")
        return original_link(
            source,
            target,
            *args,
            **kwargs,
        )

    monkeypatch.setattr(
        os,
        "link",
        competing_create,
    )

    with pytest.raises(FileExistsError):
        _publish(
            publisher,
            lease,
            staging,
            b"sync bytes",
        )

    assert (
        destination / "note.txt"
    ).read_bytes() == b"third party"

    assert (staging / ("0" * 64 + ".part")).exists()
