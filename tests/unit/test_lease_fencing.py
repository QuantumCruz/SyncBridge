
"""Independent, persistent fencing-contract tests (no network or file writes)."""
from __future__ import annotations

import multiprocessing as mp
from dataclasses import replace

import pytest

from syncbridge.network.lease_fencing import (
    FencedOut,
    LeaseAuthority,
    LeaseBusy,
    LeaseClockError,
)

SHARE = "a" * 32
ALICE = "b" * 32
BOB = "c" * 32


class FakeClock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def _contender(path, owner, start, queue):
    try:
        authority = LeaseAuthority(path)
        start.wait(timeout=10)
        granted = authority.acquire(
            SHARE,
            owner,
            ttl_seconds=30,
        )
    except LeaseBusy:
        queue.put(("busy", owner))
    except BaseException as exc:
        queue.put(
            ("error", type(exc).__name__, str(exc))
        )
    else:
        queue.put(
            ("acquired", owner, granted.generation)
        )


def test_acquire_renew_and_release(tmp_path):
    clock = FakeClock()
    authority = LeaseAuthority(
        tmp_path / "fences.sqlite",
        clock=clock,
    )

    first = authority.acquire(
        SHARE,
        ALICE,
        ttl_seconds=10,
    )

    assert first.generation == 1

    with pytest.raises(LeaseBusy):
        authority.acquire(SHARE, BOB)

    clock.advance(3)

    extended = authority.renew(
        first,
        ttl_seconds=10,
    )

    assert extended.generation == first.generation
    assert extended.session_token == first.session_token
    assert extended.expires_at == 1013
    assert authority.assert_current(first).expires_at == 1013

    authority.release(first)

    with pytest.raises(FencedOut):
        authority.assert_current(first)

    second = authority.acquire(SHARE, BOB)

    assert second.generation == 2
    assert second.session_token != first.session_token


def test_expiry_fences_out_old_holder_and_renewal(tmp_path):
    clock = FakeClock()
    authority = LeaseAuthority(
        tmp_path / "fences.sqlite",
        clock=clock,
    )

    old = authority.acquire(
        SHARE,
        ALICE,
        ttl_seconds=5,
    )

    clock.advance(5)

    with pytest.raises(FencedOut):
        authority.renew(old)

    replacement = authority.acquire(SHARE, BOB)

    assert replacement.generation == old.generation + 1

    for operation in (
        authority.assert_current,
        authority.release,
        authority.renew,
    ):
        with pytest.raises(FencedOut):
            operation(old)

    assert authority.assert_current(replacement) == replacement


def test_restart_preserves_fence_and_cannot_resurrect_session(
    tmp_path,
):
    clock = FakeClock()
    path = tmp_path / "fences.sqlite"

    original = LeaseAuthority(path, clock=clock)
    old = original.acquire(
        SHARE,
        ALICE,
        ttl_seconds=5,
    )

    clock.advance(6)

    reopened = LeaseAuthority(path, clock=clock)
    new = reopened.acquire(SHARE, BOB)

    assert new.generation == 2

    with pytest.raises(FencedOut):
        original.assert_current(old)

    reopened.release(new)

    next_lease = LeaseAuthority(
        path,
        clock=clock,
    ).acquire(SHARE, ALICE)

    assert next_lease.generation == 3


def test_same_owner_new_session_cannot_replay_old_token(
    tmp_path,
):
    clock = FakeClock()
    authority = LeaseAuthority(
        tmp_path / "fences.sqlite",
        clock=clock,
    )

    old = authority.acquire(SHARE, ALICE)
    authority.release(old)

    current = authority.acquire(SHARE, ALICE)

    assert old.owner_node_id == current.owner_node_id

    with pytest.raises(FencedOut):
        authority.release(old)

    assert authority.assert_current(current) == current


def test_forged_session_token_is_rejected(tmp_path):
    authority = LeaseAuthority(
        tmp_path / "fences.sqlite"
    )

    valid = authority.acquire(SHARE, ALICE)
    forged = replace(
        valid,
        session_token="f" * 64,
    )

    with pytest.raises(FencedOut):
        authority.assert_current(forged)

    assert valid.session_token not in repr(valid)
    assert authority.assert_current(valid) == valid


def test_share_fences_are_independent(tmp_path):
    authority = LeaseAuthority(
        tmp_path / "fences.sqlite"
    )

    first = authority.acquire(SHARE, ALICE)
    other = authority.acquire("f" * 32, BOB)

    assert first.generation == other.generation == 1
    assert authority.assert_current(first) == first
    assert authority.assert_current(other) == other


def test_clock_rollback_fails_closed(tmp_path):
    clock = FakeClock()
    authority = LeaseAuthority(
        tmp_path / "fences.sqlite",
        clock=clock,
    )

    old = authority.acquire(SHARE, ALICE)

    clock.advance(3)
    authority.assert_current(old)
    clock.advance(-5)

    for operation in (
        lambda: authority.assert_current(old),
        lambda: authority.renew(old),
        lambda: authority.release(old),
        lambda: authority.acquire(SHARE, BOB),
    ):
        with pytest.raises(LeaseClockError):
            operation()


@pytest.mark.parametrize(
    "ttl",
    [
        0,
        -1,
        3601,
        float("nan"),
        float("inf"),
        True,
        "30",
    ],
)
def test_invalid_ttl_rejected(tmp_path, ttl):
    authority = LeaseAuthority(
        tmp_path / "fences.sqlite"
    )

    with pytest.raises(ValueError):
        authority.acquire(
            SHARE,
            ALICE,
            ttl_seconds=ttl,
        )


def test_invalid_identifiers_rejected(tmp_path):
    authority = LeaseAuthority(
        tmp_path / "fences.sqlite"
    )

    for share, owner in (
        ("not a share", ALICE),
        (SHARE, "B" * 32),
    ):
        with pytest.raises(ValueError):
            authority.acquire(share, owner)


def test_cross_process_contention_grants_exactly_one_session(
    tmp_path,
):
    ctx = mp.get_context("spawn")
    path = str(tmp_path / "fences.sqlite")

    LeaseAuthority(path)

    start = ctx.Event()
    results = ctx.Queue()

    children = [
        ctx.Process(
            target=_contender,
            args=(
                path,
                owner,
                start,
                results,
            ),
        )
        for owner in (ALICE, BOB)
    ]

    try:
        for child in children:
            child.start()

        start.set()

        outcomes = [
            results.get(timeout=20)
            for _ in children
        ]

        for child in children:
            child.join(timeout=10)
            assert child.exitcode == 0

        assert sorted(
            outcome[0] for outcome in outcomes
        ) == ["acquired", "busy"]

    finally:
        for child in children:
            if child.is_alive():
                child.terminate()

            child.join(timeout=5)
            child.close()

        results.close()
        results.join_thread()
