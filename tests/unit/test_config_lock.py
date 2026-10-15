"""Regression tests for settings and profile lock races on Windows/POSIX."""

from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from syncbridge import runtime as runtime_module
from syncbridge.storage import config as config_module
from syncbridge.storage.config import AppConfig, ConfigConflict, ConfigStore


@pytest.mark.parametrize("kind", ["settings", "profile"])
def test_empty_lock_file_is_initialized_only_after_acquire(
    tmp_path, monkeypatch, kind
):
    """Fail deterministically if the zero-byte write happens before locking."""
    state = {"held": False}
    original_fdopen = os.fdopen

    class CheckedStream:
        def __init__(self, stream):
            self._stream = stream

        def __enter__(self):
            self._stream.__enter__()
            return self

        def __exit__(self, *args):
            return self._stream.__exit__(*args)

        def __getattr__(self, name):
            return getattr(self._stream, name)

        def write(self, data):
            if data == b"\0":
                assert state["held"], "Lock byte written before OS lock acquired"
            return self._stream.write(data)

    def tracked_fdopen(fd, *args, **kwargs):
        return CheckedStream(original_fdopen(fd, *args, **kwargs))

    monkeypatch.setattr(os, "fdopen", tracked_fdopen)

    if os.name == "nt":
        import msvcrt

        real_locking = msvcrt.locking

        def tracked_locking(fd, mode, length):
            result = real_locking(fd, mode, length)
            state["held"] = mode == msvcrt.LK_NBLCK
            return result

        monkeypatch.setattr(msvcrt, "locking", tracked_locking)
    else:
        import fcntl

        real_flock = fcntl.flock

        def tracked_flock(fd, operation):
            result = real_flock(fd, operation)
            state["held"] = bool(operation & fcntl.LOCK_EX)
            return result

        monkeypatch.setattr(fcntl, "flock", tracked_flock)

    path = tmp_path / f"{kind}.lock"

    if kind == "settings":
        with config_module._write_lock(path):
            assert state["held"]
    else:
        profile_lock = runtime_module._ProfileLock(path)
        try:
            profile_lock.acquire()
            assert state["held"]
        finally:
            profile_lock.release()

    assert not state["held"]
    assert path.read_bytes() == b"\0"


def test_repeated_competing_settings_writers_have_one_winner(tmp_path):
    """Run genuine concurrent saves; don't hide worker exceptions."""
    writers = 12
    rounds = 16

    for run in range(rounds):
        path = tmp_path / f"run-{run}" / "settings.json"
        gate = threading.Barrier(writers)

        def worker(index):
            store = ConfigStore(path)
            candidate = replace(
                store.load(), device_name=f"Writer-{index}"
            )
            gate.wait(timeout=10)

            try:
                return store.save(candidate)
            except ConfigConflict:
                return "conflict"

        with ThreadPoolExecutor(max_workers=writers) as pool:
            results = list(pool.map(worker, range(writers)))

        assert sum(isinstance(item, AppConfig) for item in results) == 1
        assert results.count("conflict") == writers - 1
        assert ConfigStore(path).load().revision == 1


def test_simultaneous_profile_starts_have_one_owner(tmp_path):
    """Only one process/thread can own an initially empty profile lock."""
    contenders = 8
    gate = threading.Barrier(contenders)
    finished = threading.Event()
    guard = threading.Lock()
    completed = 0
    path = tmp_path / "instance.lock"

    def worker(_index):
        nonlocal completed
        profile_lock = runtime_module._ProfileLock(path)
        gate.wait(timeout=10)
        result = "owner"

        try:
            try:
                profile_lock.acquire()
            except runtime_module.InstanceAlreadyRunning:
                result = "busy"

            return result
        finally:
            with guard:
                completed += 1
                if completed == contenders:
                    finished.set()

            if result == "owner":
                assert finished.wait(timeout=10)
            profile_lock.release()

    with ThreadPoolExecutor(max_workers=contenders) as pool:
        results = list(pool.map(worker, range(contenders)))

    assert results.count("owner") == 1
    assert results.count("busy") == contenders - 1

    reusable = runtime_module._ProfileLock(path)
    reusable.acquire()
    reusable.release()


def test_existing_empty_settings_lock_initializes_and_saves(tmp_path):
    path = tmp_path / "settings.json"
    lock_path = tmp_path / "settings.json.lock"
    lock_path.touch()

    store = ConfigStore(path)
    first = store.save(store.load())
    second = store.save(replace(first, device_name="Second version"))

    assert first.revision == 1
    assert second.revision == 2
    assert store.load() == second
    assert lock_path.read_bytes() == b"\0"
