
"""Bounded renewal of a previously issued SyncBridge fencing lease.

Use around a fenced transfer with a receiver-issued grant. Renewal uses a
monotonic interval; the receiver alone decides expiry. A failed renewal is
reported, not silently retried as a new session. This helper does not acquire,
release, authorize writes, or replace the receiver's publication fence.
"""
from __future__ import annotations

import math
import threading
from typing import Callable

from syncbridge.network.lease_fencing import LeaseAuthority, LeaseGrant


class LeaseRenewalError(RuntimeError):
    """The transfer's existing lease could not be kept alive."""


class LeaseKeepAlive:
    """Renew one session in a background thread for a bounded operation.

    Callers should supply the receiver-authorized renew operation. For uploads,
    this is FencedLeaseClient.renew on the remote computer. For downloads,
    it is the local LeaseAuthority.renew. A new generation is NEVER accepted
    as a renewal.

    The caller must use a fenced transfer method and check the context manager's
    outcome. Successful renewal alone does not authorize publication.
    """

    def __init__(
        self,
        lease: LeaseGrant,
        renew: Callable[[LeaseGrant], LeaseGrant],
        *,
        interval_seconds: float = 10.0,
    ) -> None:
        LeaseAuthority._valid_grant(lease)

        if not callable(renew):
            raise TypeError("renew must be callable")

        if (
            type(interval_seconds) not in (int, float)
            or not math.isfinite(interval_seconds)
            or not 0.01 <= interval_seconds <= 300.0
        ):
            raise ValueError(
                "interval_seconds must be between 0.01 and 300"
            )

        self._lease = lease
        self._renew = renew
        self._interval = float(interval_seconds)
        self._stop = threading.Event()
        self._changed = threading.Event()
        self._mutex = threading.Lock()
        self._failure: Exception | None = None
        self._started = False
        self._thread: threading.Thread | None = None

    @property
    def lease(self) -> LeaseGrant:
        with self._mutex:
            return self._lease

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    @property
    def failed(self) -> bool:
        with self._mutex:
            return self._failure is not None

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            with self._mutex:
                old = self._lease

            try:
                renewed = self._renew(old)
                LeaseAuthority._valid_grant(renewed)

                if (
                    renewed.share_id != old.share_id
                    or renewed.owner_node_id != old.owner_node_id
                    or renewed.generation != old.generation
                    or renewed.session_token != old.session_token
                ):
                    raise LeaseRenewalError(
                        "Lease identity changed during renewal"
                    )

                if (
                    type(renewed.expires_at) not in (int, float)
                    or not math.isfinite(renewed.expires_at)
                ):
                    raise LeaseRenewalError(
                        "Receiver returned invalid lease expiry"
                    )

            except Exception as exc:
                with self._mutex:
                    self._failure = exc

                self._stop.set()
                self._changed.set()
                return

            with self._mutex:
                self._lease = renewed

            self._changed.set()

    def check(self) -> LeaseGrant:
        """Surface failed renewal; the receiver remains final authority."""
        with self._mutex:
            if not self._started:
                raise RuntimeError(
                    "Lease renewal has not started"
                )

            failure = self._failure
            grant = self._lease

        if failure is not None:
            raise LeaseRenewalError(
                "Sync lease renewal failed; do not continue synchronization"
            ) from failure

        return grant

    def wait_for_renewal(self, timeout: float) -> bool:
        """Test/diagnostic helper; no synchronization authority implied."""
        return self._changed.wait(timeout)

    def __enter__(self) -> LeaseKeepAlive:
        with self._mutex:
            if self._started:
                raise RuntimeError(
                    "LeaseKeepAlive cannot be restarted"
                )

            self._started = True
            self._thread = threading.Thread(
                target=self._loop,
                name="SyncBridgeLeaseRenewal",
                daemon=True,
            )
            worker = self._thread

        worker.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        self._stop.set()

        if self._thread is not None:
            self._thread.join(timeout=10.0)

            if self._thread.is_alive() and exc_type is None:
                raise LeaseRenewalError(
                    "Lease renewal worker did not stop"
                )

        if exc_type is None:
            self.check()

        return False
