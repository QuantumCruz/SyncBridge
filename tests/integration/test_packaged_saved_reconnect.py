
"""Two actual packaged EXEs must reconnect after BOTH processes restart.

Unlike a one-sided restart, this preserves saved profiles on both laptops
and never chooses Start fresh. It uses disposable loopback profiles only.
Requires a freshly built executable and an unlocked Windows desktop.
"""
from __future__ import annotations

import hashlib
import sys
from contextlib import ExitStack

import pytest

from test_desktop_crash_resume import MIB, RELATIVE, _configure, _hash
from test_packaged_windows_desktop import (
    _assert_alive,
    _connect_pair,
    _connect_uia,
    _launch,
    _network_options,
    _require_executable,
    _require_ui,
    _stop,
    _wait_for_listener,
)

pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="Requires packaged Windows UI"
)


def test_both_packaged_desktops_reconnect_using_saved_settings(tmp_path):
    """Close both desktop processes, reopen and mutually approve reconnect."""
    _require_executable()
    _require_ui()

    profiles, roots, listeners, lock, validation, source = _configure(
        tmp_path, size=8 * MIB
    )
    destination = roots["Bob"] / RELATIVE
    original_digest = _hash(source)

    used = {
        *listeners["Alice"],
        *listeners["Bob"],
        lock,
        validation,
    }
    options = {
        "Alice": _network_options(used),
        "Bob": _network_options(used),
    }

    identity_hashes = {
        role: hashlib.sha256(
            (profiles[role] / "identity.json").read_bytes()
        ).hexdigest()
        for role in ("Alice", "Bob")
    }

    processes = []

    with ExitStack() as stack:
        try:
            for cycle in (1, 2):
                launched = {}

                for role, other in (
                    ("Bob", "Alice"),
                    ("Alice", "Bob"),
                ):
                    process, log = _launch(
                        stack,
                        processes,
                        name=f"{role}-run-{cycle}",
                        profile=profiles[role],
                        workdir=tmp_path / "PackagedRuns",
                        listen_ports=tuple(listeners[role]),
                        lock_port=lock,
                        validation_port=validation,
                        options=options[role],
                        remote_options=options[other],
                        visible=True,
                    )

                    _wait_for_listener(
                        process,
                        options[role]["pairing"],
                        log,
                        description=f"{role} run {cycle} pairing listener",
                    )

                    launched[role] = (
                        process,
                        log,
                        _connect_uia(process, log),
                        role,
                    )

                _connect_pair(
                    launched["Alice"],
                    launched["Bob"],
                )

                assert not destination.exists(), (
                    "A remembered connection must not silently transfer files"
                )
                assert _hash(source) == original_digest

                for role in ("Alice", "Bob"):
                    process, log, _, _ = launched[role]
                    _assert_alive(
                        process,
                        log,
                        description=f"{role} run {cycle}",
                    )

                    assert hashlib.sha256(
                        (profiles[role] / "identity.json").read_bytes()
                    ).hexdigest() == identity_hashes[role]

                # Terminate both processes without resetting either profile.
                # A live connection must not be restored automatically.
                for role in ("Alice", "Bob"):
                    _stop(launched[role][0])

            assert not destination.exists()

        finally:
            for process in reversed(processes):
                _stop(process)
