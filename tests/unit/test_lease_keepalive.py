
"""Lease-keepalive contracts including real encrypted upload/download paths.

All tests use disposable folders and loopback peers. Lease lifetime is advanced
with controlled receiver clocks rather than long network sleeps.
"""
from __future__ import annotations

import time
from dataclasses import replace
from threading import Event

import pytest

from syncbridge.network.lease_fencing import FencedOut, LeaseAuthority
from syncbridge.network.lease_keepalive import (
    LeaseKeepAlive,
    LeaseRenewalError,
)
from test_fenced_download import peers as download_peers, _grant, _fetch
from test_fenced_transfer import peers as upload_peers, _lease, _send
from test_fenced_lease_channel import peers as network_peers


SHARE = "a" * 32
ALICE = "b" * 32


def _until(predicate, timeout=3.0):
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if predicate():
            return

        time.sleep(0.01)

    pytest.fail("Timed out waiting for lease renewal")


def test_local_renewal_keeps_real_short_lease_alive(tmp_path):
    authority = LeaseAuthority(
        tmp_path / "leases.sqlite"
    )

    grant = authority.acquire(
        SHARE,
        ALICE,
        ttl_seconds=0.25,
    )

    renewals = []

    def renew(current):
        updated = authority.renew(
            current,
            ttl_seconds=0.25,
        )
        renewals.append(updated)
        return updated

    with LeaseKeepAlive(
        grant,
        renew,
        interval_seconds=0.04,
    ) as live:
        time.sleep(0.62)

        assert len(renewals) >= 3
        assert (
            authority.assert_current(live.check()).generation
            == grant.generation
        )
        assert live.lease.session_token == grant.session_token

    before = len(renewals)
    time.sleep(0.10)

    assert len(renewals) == before

    authority.release(grant)


def test_expired_lease_is_not_reacquired_or_resurrected(tmp_path):
    class Clock:
        now = 1000.0

        def __call__(self):
            return self.now

    clock = Clock()

    authority = LeaseAuthority(
        tmp_path / "leases.sqlite",
        clock=clock,
    )

    old = authority.acquire(
        SHARE,
        ALICE,
        ttl_seconds=0.1,
    )

    clock.now += 0.2

    with pytest.raises(LeaseRenewalError):
        with LeaseKeepAlive(
            old,
            lambda lease: authority.renew(
                lease,
                ttl_seconds=0.3,
            ),
            interval_seconds=0.02,
        ) as live:
            _until(lambda: live.failed)
            live.check()

    newer = authority.acquire(SHARE, ALICE)

    assert newer.generation == old.generation + 1

    with pytest.raises(FencedOut):
        authority.assert_current(old)


def test_renewal_failure_surfaces_without_exposing_error_text(
    tmp_path,
):
    authority = LeaseAuthority(
        tmp_path / "leases.sqlite"
    )

    grant = authority.acquire(SHARE, ALICE)

    def broken(_grant):
        raise OSError("private-token-or-path")

    with pytest.raises(LeaseRenewalError) as error:
        with LeaseKeepAlive(
            grant,
            broken,
            interval_seconds=0.02,
        ) as live:
            _until(lambda: live.failed)

    assert "private-token-or-path" not in str(error.value)


def test_changed_generation_during_renewal_is_rejected(
    tmp_path,
):
    authority = LeaseAuthority(
        tmp_path / "leases.sqlite"
    )

    grant = authority.acquire(SHARE, ALICE)

    with pytest.raises(LeaseRenewalError):
        with LeaseKeepAlive(
            grant,
            lambda old: replace(
                old,
                generation=old.generation + 1,
            ),
            interval_seconds=0.02,
        ) as live:
            _until(lambda: live.failed)

    assert (
        authority.assert_current(grant).generation
        == grant.generation
    )


@pytest.mark.parametrize(
    "interval",
    [0, -1, 301, True, "10", float("nan")],
)
def test_invalid_renewal_interval_is_rejected(
    tmp_path,
    interval,
):
    authority = LeaseAuthority(
        tmp_path / "leases.sqlite"
    )

    grant = authority.acquire(SHARE, ALICE)

    with pytest.raises(ValueError):
        LeaseKeepAlive(
            grant,
            authority.renew,
            interval_seconds=interval,
        )


def test_single_use_guard_and_body_exception_preserved(tmp_path):
    authority = LeaseAuthority(
        tmp_path / "leases.sqlite"
    )

    grant = authority.acquire(SHARE, ALICE)

    live = LeaseKeepAlive(
        grant,
        lambda old: authority.renew(
            old,
            ttl_seconds=30,
        ),
        interval_seconds=0.05,
    )

    with pytest.raises(ZeroDivisionError):
        with live:
            raise ZeroDivisionError("original failure")

    assert live.stopped

    with pytest.raises(
        RuntimeError,
        match="cannot be restarted",
    ):
        with live:
            pass


def test_authenticated_remote_renewal_preserves_generation(
    network_peers,
):
    peers = network_peers
    client = peers["client"]

    args = (
        "127.0.0.1",
        peers["server"].bound_port,
        peers["bob"].node_id,
    )

    grant = client.acquire(
        *args,
        SHARE,
        ttl_seconds=0.3,
    )

    renewed_after_advance = Event()

    def renew(old):
        updated = client.renew(
            *args,
            old,
            ttl_seconds=0.3,
        )

        if peers["clock"].now > 1000.0:
            renewed_after_advance.set()

        return updated

    with LeaseKeepAlive(
        grant,
        renew,
        interval_seconds=0.025,
    ) as live:
        peers["clock"].advance(0.18)

        assert renewed_after_advance.wait(3.0)

        peers["clock"].advance(0.17)
        live.check()

        assert (
            peers["authority"]
            .assert_current(grant)
            .generation
            == 1
        )

    client.release(*args, grant)


def test_fenced_encrypted_upload_survives_original_lease_expiry(
    upload_peers,
    monkeypatch,
):
    peers = upload_peers

    payload = b"fenced slow upload" * 8192

    (
        peers["alice"] / "slow.bin"
    ).write_bytes(payload)

    grant = _lease(peers, ttl=0.3)
    renewed_after_advance = Event()

    def renew(old):
        updated = peers["lease_client"].renew(
            "127.0.0.1",
            peers["lease_server"].bound_port,
            peers["bob_identity"].node_id,
            old,
            ttl_seconds=0.3,
        )

        if peers["clock"].now > 1000.0:
            renewed_after_advance.set()

        return updated

    original = peers["sender"]._transmit

    def delayed_transmit(*args, **kwargs):
        peers["clock"].advance(0.18)

        assert renewed_after_advance.wait(3.0)

        peers["clock"].advance(0.17)

        return original(*args, **kwargs)

    monkeypatch.setattr(
        peers["sender"],
        "_transmit",
        delayed_transmit,
    )

    with LeaseKeepAlive(
        grant,
        renew,
        interval_seconds=0.025,
    ) as live:
        assert _send(
            peers,
            live.lease,
            "slow.bin",
        ).completed

    assert (
        peers["bob"] / "slow.bin"
    ).read_bytes() == payload


def test_fenced_encrypted_download_survives_original_lease_expiry(
    download_peers,
    monkeypatch,
):
    peers = download_peers

    payload = b"fenced slow download" * 8192

    (
        peers["bob_root"] / "slow.bin"
    ).write_bytes(payload)

    grant = _grant(peers, ttl=0.3)
    renewed_after_advance = Event()

    def renew(old):
        updated = peers["authority"].renew(
            old,
            ttl_seconds=0.3,
        )

        if peers["clock"].now > 1000.0:
            renewed_after_advance.set()

        return updated

    original = peers["client"]._receive_fenced

    def delayed_receive(*args, **kwargs):
        peers["clock"].advance(0.18)

        assert renewed_after_advance.wait(3.0)

        peers["clock"].advance(0.17)

        return original(*args, **kwargs)

    monkeypatch.setattr(
        peers["client"],
        "_receive_fenced",
        delayed_receive,
    )

    with LeaseKeepAlive(
        grant,
        renew,
        interval_seconds=0.025,
    ) as live:
        assert _fetch(
            peers,
            live.lease,
            path="slow.bin",
            content=payload,
        ).completed

    assert (
        peers["alice_root"] / "slow.bin"
    ).read_bytes() == payload
