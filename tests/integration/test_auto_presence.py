
"""Real localhost UDP tests for application-lifetime discovery.

No Tk window is opened in these tests; the two desktop presences must become
visible as soon as each app starts, without a Nearby Devices button press.
"""
from __future__ import annotations

import socket
import time

from syncbridge.ui.nearby_devices import DesktopPresence


def wait_for(predicate, *, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


def start_pair(tmp_path, *, peer_timeout=0.5):
    alice = DesktopPresence(
        tmp_path / "Alice" / "Profile",
        device_name="Alice",
        listen_port=0,
        bind_address="127.0.0.1",
        targets=(),
        announce_interval=0.05,
        peer_timeout=peer_timeout,
    )
    bob = DesktopPresence(
        tmp_path / "Bob" / "Profile",
        device_name="Bob",
        listen_port=0,
        bind_address="127.0.0.1",
        targets=(),
        announce_interval=0.05,
        peer_timeout=peer_timeout,
    )
    alice.start()
    bob.start()
    alice.directory.add_target("127.0.0.1", bob.directory.bound_port)
    bob.directory.add_target("127.0.0.1", alice.directory.bound_port)
    alice.directory.refresh()
    bob.directory.refresh()
    return alice, bob


def test_both_apps_discover_each_other_without_opening_device_browser(tmp_path):
    alice, bob = start_pair(tmp_path)
    try:
        assert wait_for(lambda: len(alice.directory.devices()) == 1)
        assert wait_for(lambda: len(bob.directory.devices()) == 1)
        assert alice.directory.devices()[0].node_id == bob.node_id
        assert bob.directory.devices()[0].node_id == alice.node_id
        assert alice.directory.devices()[0].name == "Bob"
        assert bob.directory.devices()[0].name == "Alice"
    finally:
        bob.stop()
        alice.stop()


def test_presence_requires_no_pairing_or_share_configuration(tmp_path):
    profile = tmp_path / "FreshUser" / "Profile"
    app = DesktopPresence(
        profile, device_name="First installation",
        listen_port=0, bind_address="127.0.0.1", targets=(),
    )
    app.start()
    try:
        assert app.running
        assert (profile / "identity.json").is_file()
        assert not (profile / "settings.json").exists()
        assert not (profile / "trust.json").exists()
        assert not (profile / "shared_state.sqlite").exists()
    finally:
        app.stop()


def test_presence_stays_online_independently_of_sync_connection(tmp_path):
    alice, bob = start_pair(tmp_path)
    try:
        # Neither has started the sync runtime or opened a Tk viewer.
        assert wait_for(lambda: len(bob.directory.devices()) == 1)
        time.sleep(0.7)  # Longer than the expiry window: advertisements continue.
        assert bob.directory.devices()[0].node_id == alice.node_id
        assert alice.running and bob.running
    finally:
        bob.stop()
        alice.stop()


def test_closed_app_eventually_disappears_without_viewer(tmp_path):
    alice, bob = start_pair(tmp_path, peer_timeout=0.3)
    try:
        assert wait_for(lambda: len(alice.directory.devices()) == 1)
        bob.stop()
        assert wait_for(lambda: alice.directory.devices() == (), timeout=2.0)
    finally:
        bob.stop()
        alice.stop()


def test_profile_identity_stable_across_app_restarts(tmp_path):
    profile = tmp_path / "Computer" / "Profile"
    a = DesktopPresence(
        profile, device_name="Computer", listen_port=0,
        bind_address="127.0.0.1", targets=(),
    )
    a.start()
    first = a.node_id
    a.stop()
    b = DesktopPresence(
        profile, device_name="Computer", listen_port=0,
        bind_address="127.0.0.1", targets=(),
    )
    try:
        assert b.node_id == first
        b.start()
        assert b.running
    finally:
        b.stop()


def test_stopping_presence_releases_udp_port(tmp_path):
    app = DesktopPresence(
        tmp_path / "Profile", device_name="Computer", listen_port=0,
        bind_address="127.0.0.1", targets=(),
    )
    app.start()
    port = app.directory.bound_port
    app.stop()
    assert not app.running
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", port))
