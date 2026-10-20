
"""Crash-safe takeover of a previous receiver fencing generation.

Both authority arrangements are exercised through real authenticated sockets.
A new elected operation may supersede an orphaned fence, but never reuses its
session token, and an invalid operation proof cannot force takeover.
"""
from __future__ import annotations

import pytest

from syncbridge.network.fenced_lease_channel import LeaseChannelError
from syncbridge.network.lease_fencing import FencedOut
from syncbridge.network.lease_validation import LeaseProof

from test_operation_bound_lease import SHARE, paired


def _proof(peers, guard):
    return LeaseProof(
        SHARE,
        peers["sender"].node_id,
        "sync",
        guard.token,
    )


def _acquire(peers, proof):
    with peers["client"].use_operation(proof):
        return peers["client"].acquire(
            *peers["args"],
            SHARE,
        )


def test_new_elected_operation_supersedes_unexpired_fence(paired):
    p = paired

    with p["coordinator"].hold("sync") as guard:
        original = _acquire(p, _proof(p, guard))

    # Mimics a process disappearing before it could release the
    # receiver-issued fencing grant.
    p["fence"].assert_current(original)

    with p["coordinator"].hold("sync") as guard:
        replacement = _acquire(p, _proof(p, guard))

        assert replacement.generation == original.generation + 1
        assert replacement.session_token != original.session_token

        with pytest.raises(FencedOut):
            p["fence"].assert_current(original)

        with pytest.raises(
            LeaseChannelError,
            match="rejected",
        ):
            p["client"].renew(*p["args"], original)

        with pytest.raises(
            LeaseChannelError,
            match="rejected",
        ):
            p["client"].release(*p["args"], original)

        p["fence"].assert_current(replacement)
        p["client"].release(*p["args"], replacement)


def test_same_elected_operation_cannot_take_over_itself(paired):
    p = paired

    with p["coordinator"].hold("sync") as guard:
        proof = _proof(p, guard)
        original = _acquire(p, proof)

        with p["client"].use_operation(proof):
            with pytest.raises(
                LeaseChannelError,
                match="rejected",
            ):
                p["client"].acquire(
                    *p["args"],
                    SHARE,
                )

        assert p["fence"].assert_current(
            original
        ).generation == original.generation

        p["client"].release(
            *p["args"],
            original,
        )


def test_invalid_elected_proof_cannot_replace_orphaned_fence(paired):
    p = paired

    with p["coordinator"].hold("sync") as guard:
        original = _acquire(p, _proof(p, guard))

    fake = LeaseProof(
        SHARE,
        p["sender"].node_id,
        "sync",
        "f" * 32,
    )

    with p["client"].use_operation(fake):
        with pytest.raises(
            LeaseChannelError,
            match="rejected",
        ):
            p["client"].acquire(
                *p["args"],
                SHARE,
            )

    assert p["fence"].assert_current(
        original
    ).generation == original.generation

    p["client"].release(
        *p["args"],
        original,
    )


def test_receiver_listener_restart_permits_fenced_recovery(paired):
    p = paired

    with p["coordinator"].hold("sync") as guard:
        old = _acquire(p, _proof(p, guard))

    listener = p["listener"]
    listener.stop()
    listener.start()

    new_args = (
        "127.0.0.1",
        listener.bound_port,
        p["receiver"].node_id,
    )

    # The old SQLite grant remains, but the restarted listener
    # has no valid in-memory operation binding for it.
    p["fence"].assert_current(old)

    with p["coordinator"].hold("sync") as guard:
        proof = _proof(p, guard)

        with p["client"].use_operation(proof):
            current = p["client"].acquire(
                *new_args,
                SHARE,
            )

        assert current.generation == old.generation + 1

        with pytest.raises(FencedOut):
            p["fence"].assert_current(old)

        with pytest.raises(Exception):
            listener.require_operation_bound(old)

        p["fence"].assert_current(current)
        p["client"].release(*new_args, current)
