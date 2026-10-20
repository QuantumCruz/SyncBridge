
"""Safe partial-byte recovery across elected-operation fencing generations.

Tests run real encrypted transfers on localhost under both elected-authority
arrangements. Only disposable test folders and SQLite databases are used.
"""
from __future__ import annotations

import json
import threading

import pytest

from syncbridge.network.transfer import TransferError

from test_operation_bound_publish import (
    SHARE,
    peers,
    _acquire,
    _proof,
    _release,
)


def _transfer(
    p,
    lease,
    filename,
    *,
    cancel=None,
    on_progress=None,
):
    return p["sender"].send_fenced_file(
        "127.0.0.1",
        p["duplex"].bound_port,
        p["receiver_id"].node_id,
        p["sender_root"],
        filename,
        lease=lease,
        cancel_event=cancel,
        on_progress=on_progress,
    )


def _partial_upload(p, filename):
    """Leave a real, correctly authenticated partial transfer."""
    stop = threading.Event()

    def cancel_after_progress(event):
        if (
            event.direction == "send"
            and event.transferred >= 128 * 1024
        ):
            stop.set()

    with p["coordinator"].hold("sync") as guard:
        old_lease = _acquire(
            p,
            _proof(p, guard),
        )

        result = _transfer(
            p,
            old_lease,
            filename,
            cancel=stop,
            on_progress=cancel_after_progress,
        )

        assert not result.completed
        assert 0 < result.transferred < result.total

    return old_lease, result.transferred


def test_authenticated_retry_recovers_previous_bytes(peers):
    p = peers
    filename = "recovered.bin"

    content = bytes(range(256)) * 4096
    (
        p["sender_root"] / filename
    ).write_bytes(content)

    previous_lease, saved = _partial_upload(
        p,
        filename,
    )

    staged_before = list(
        p["duplex"]._staging.glob("*.part")
    )

    assert len(staged_before) == 1
    assert staged_before[0].stat().st_size == saved

    offsets = []

    with p["coordinator"].hold("sync") as guard:
        new_lease = _acquire(
            p,
            _proof(p, guard),
        )

        assert (
            new_lease.generation
            == previous_lease.generation + 1
        )

        assert (
            new_lease.session_token
            != previous_lease.session_token
        )

        result = _transfer(
            p,
            new_lease,
            filename,
            on_progress=lambda event: offsets.append(
                event.transferred
            ),
        )

        assert result.completed
        _release(p, new_lease)

    assert offsets
    assert offsets[0] == saved

    assert (
        p["receiver_root"] / filename
    ).read_bytes() == content

    assert not list(
        p["duplex"]._staging.glob("*.part")
    )


def test_mismatched_old_metadata_is_not_adopted(peers):
    p = peers
    filename = "metadata-check.bin"

    content = bytes(range(256)) * 4096

    (
        p["sender_root"] / filename
    ).write_bytes(content)

    _, saved = _partial_upload(
        p,
        filename,
    )

    assert saved > 0

    metadata_files = list(
        p["duplex"]._staging.glob("*.json")
    )

    assert len(metadata_files) == 1
    info = metadata_files[0]

    metadata = json.loads(
        info.read_text(encoding="utf-8")
    )

    # Pretend the old partial belongs to an unrelated file
    # version. It must NOT be adopted into the new session.
    metadata["sha256"] = "0" * 64

    info.write_text(
        json.dumps(metadata),
        encoding="utf-8",
    )

    offsets = []

    with p["coordinator"].hold("sync") as guard:
        new_lease = _acquire(
            p,
            _proof(p, guard),
        )

        result = _transfer(
            p,
            new_lease,
            filename,
            on_progress=lambda event: offsets.append(
                event.transferred
            ),
        )

        assert result.completed
        _release(p, new_lease)

    assert offsets
    assert offsets[0] == 0

    assert (
        p["receiver_root"] / filename
    ).read_bytes() == content


def test_corrupt_old_prefix_cannot_publish(peers):
    p = peers
    filename = "corrupt-prefix.bin"

    content = bytes(range(256)) * 4096

    (
        p["sender_root"] / filename
    ).write_bytes(content)

    _partial_upload(
        p,
        filename,
    )

    parts = list(
        p["duplex"]._staging.glob("*.part")
    )

    assert len(parts) == 1

    part = parts[0]

    with part.open("r+b") as stream:
        stream.seek(0)
        stream.write(b"CORRUPT!")
        stream.flush()

    offsets = []

    with p["coordinator"].hold("sync") as guard:
        new_lease = _acquire(
            p,
            _proof(p, guard),
        )

        with pytest.raises(TransferError):
            _transfer(
                p,
                new_lease,
                filename,
                on_progress=lambda event: offsets.append(
                    event.transferred
                ),
            )

        _release(p, new_lease)

    # The receiver may reuse bytes temporarily, but it must
    # reject the completed file when its full hash differs.
    assert offsets
    assert offsets[0] > 0

    assert not (
        p["receiver_root"] / filename
    ).exists()
