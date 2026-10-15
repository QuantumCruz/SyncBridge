
"""Full localhost synchronization + distributed baseline-checkpoint tests."""

from __future__ import annotations

import threading
from types import SimpleNamespace
from uuid import uuid4

import pytest

from syncbridge.core.baseline import BaselineCoordinator
from syncbridge.core.coordinator import (
    CoordinationError,
    StaleSyncState,
    SyncCoordinator,
)
from syncbridge.core.lifecycle import LifecycleStatus, SyncLifecycle
from syncbridge.core.scanner import FileScanner
from syncbridge.network.agreement import (
    AgreementClient,
    AgreementError,
    AgreementService,
)
from syncbridge.network.manifest import ManifestService
from syncbridge.network.security import DeviceIdentity, TrustStore
from syncbridge.network.transfer import TransferError, TransferService
from syncbridge.storage.shared_state import SharedStateDatabase


@pytest.fixture
def pair(tmp_path):
    alice = DeviceIdentity.generate()
    bob = DeviceIdentity.generate()

    at = TrustStore(tmp_path / "at.json")
    bt = TrustStore(tmp_path / "bt.json")

    at.add_verified(
        bob.public_key_hex,
        confirmed_fingerprint=bob.fingerprint,
        name="Bob",
    )
    bt.add_verified(
        alice.public_key_hex,
        confirmed_fingerprint=alice.fingerprint,
        name="Alice",
    )

    ar = tmp_path / "alice"
    br = tmp_path / "bob"
    ar.mkdir()
    br.mkdir()

    share = uuid4().hex
    ad = SharedStateDatabase(tmp_path / "a.sqlite")
    bd = SharedStateDatabase(tmp_path / "b.sqlite")

    options = dict(
        bind_address="127.0.0.1",
        listen_port=0,
        handshake_timeout=2.0,
        io_timeout=5.0,
    )

    manifest_server = ManifestService(
        bob,
        bt,
        {share: br},
        allowed_readers={share: [alice.node_id]},
        shared_state=bd,
        **options,
    )

    manifest_client = ManifestService(
        alice,
        at,
        **options,
    )

    transfer_server = TransferService(
        bob,
        bt,
        br,
        share_id=share,
        allowed_senders=[alice.node_id],
        allowed_readers=[alice.node_id],
        allow_overwrite=True,
        **options,
    )

    transfer_client = TransferService(
        alice,
        at,
        ar,
        share_id=share,
        allowed_senders=[bob.node_id],
        allowed_readers=[bob.node_id],
        allow_overwrite=True,
        **options,
    )

    agreement_server = AgreementService(
        bob,
        bt,
        bd,
        {share: br},
        allowed_peers={share: [alice.node_id]},
        **options,
    )

    agreement_client = AgreementClient(
        alice,
        at,
        handshake_timeout=2.0,
        io_timeout=5.0,
    )

    manifest_server.start()
    transfer_server.start()
    agreement_server.start()

    coordinator = SyncCoordinator(
        ar,
        bob.node_id,
        share,
        "127.0.0.1",
        manifest_server.bound_port,
        transfer_server.bound_port,
        manifest_client=manifest_client,
        transfer_sender=transfer_client,
        shared_state=ad,
    )

    baseline = BaselineCoordinator(
        ar,
        bob.node_id,
        share,
        "127.0.0.1",
        agreement_server.bound_port,
        agreement_client=agreement_client,
        shared_state=ad,
    )

    lifecycle = SyncLifecycle(
        coordinator,
        baseline,
    )

    instance = SimpleNamespace(
        alice=alice,
        bob=bob,
        ar=ar,
        br=br,
        share=share,
        ad=ad,
        bd=bd,
        coordinator=coordinator,
        baseline=baseline,
        lifecycle=lifecycle,
        manifest_server=manifest_server,
        transfer_server=transfer_server,
        agreement_server=agreement_server,
        agreement_client=agreement_client,
    )

    try:
        yield instance
    finally:
        agreement_server.stop()
        transfer_server.stop()
        manifest_server.stop()


def revisions(p):
    a = p.ad.load(
        p.ar,
        p.bob.node_id,
        p.share,
    )

    b = p.bd.load(
        p.br,
        p.alice.node_id,
        p.share,
    )

    return (
        0 if a is None else a.revision,
        0 if b is None else b.revision,
    )


def test_preview_is_read_only(pair):
    p = pair
    (p.ar / "a.txt").write_text("hello")

    report = p.lifecycle.run_once()

    assert report.status is LifecycleStatus.PREVIEW
    assert not report.complete
    assert report.checkpoint is None
    assert report.cycle is None
    assert not (p.br / "a.txt").exists()
    assert revisions(p) == (0, 0)


def test_first_empty_checkpoint_and_repeat_is_noop(pair):
    p = pair

    first = p.lifecycle.run_once(apply=True)

    assert first.complete
    assert first.checkpoint.newly_committed
    assert revisions(p) == (1, 1)

    second = p.lifecycle.run_once(apply=True)

    assert second.complete
    assert not second.checkpoint.newly_committed
    assert revisions(p) == (1, 1)


def test_two_way_initial_sync_creates_matching_baselines(pair):
    p = pair

    (p.ar / "from-alice.txt").write_text("Alice")
    (p.br / "from-bob.txt").write_text("Bob")

    result = p.lifecycle.run_once(apply=True)

    assert result.complete
    assert len(result.uploaded) == 1
    assert len(result.downloaded) == 1

    assert (
        p.ar / "from-bob.txt"
    ).read_text() == "Bob"

    assert (
        p.br / "from-alice.txt"
    ).read_text() == "Alice"

    assert revisions(p) == (1, 1)

    assert p.ad.load(
        p.ar,
        p.bob.node_id,
        p.share,
    ).sha256 == p.bd.load(
        p.br,
        p.alice.node_id,
        p.share,
    ).sha256


def test_subsequent_conditional_upload_advances_both_revisions(pair):
    p = pair

    for root in (p.ar, p.br):
        (root / "doc.txt").write_text("old")

    assert p.lifecycle.run_once(apply=True).complete

    (p.ar / "doc.txt").write_text("new")

    result = p.lifecycle.run_once(apply=True)

    assert result.complete
    assert len(result.uploaded) == 1
    assert (p.br / "doc.txt").read_text() == "new"
    assert revisions(p) == (2, 2)


def test_subsequent_conditional_download_advances_both_revisions(pair):
    p = pair

    for root in (p.ar, p.br):
        (root / "doc.txt").write_text("old")

    assert p.lifecycle.run_once(apply=True).complete

    (p.br / "doc.txt").write_text("remote revision")

    result = p.lifecycle.run_once(apply=True)

    assert result.complete
    assert len(result.downloaded) == 1
    assert (
        p.ar / "doc.txt"
    ).read_text() == "remote revision"
    assert revisions(p) == (2, 2)


def test_divergent_edit_never_advances_baseline(pair):
    p = pair

    for root in (p.ar, p.br):
        (root / "doc.txt").write_text("common")

    p.lifecycle.run_once(apply=True)

    (p.ar / "doc.txt").write_text("alice edit")
    (p.br / "doc.txt").write_text("bob edit")

    result = p.lifecycle.run_once(apply=True)

    assert result.status is LifecycleStatus.NEEDS_REVIEW
    assert len(result.conflicts) == 1
    assert result.checkpoint is None
    assert revisions(p) == (1, 1)

    assert (
        p.ar / "doc.txt"
    ).read_text() == "alice edit"

    assert (
        p.br / "doc.txt"
    ).read_text() == "bob edit"


def test_one_sided_deletion_requires_review(pair):
    p = pair

    for root in (p.ar, p.br):
        (root / "doc.txt").write_text("common")

    p.lifecycle.run_once(apply=True)

    (p.ar / "doc.txt").unlink()

    result = p.lifecycle.run_once(apply=True)

    assert result.status is LifecycleStatus.NEEDS_REVIEW
    assert len(result.pending_deletions) == 1
    assert (p.br / "doc.txt").exists()
    assert revisions(p) == (1, 1)


def test_both_sided_deletion_cannot_be_silently_acknowledged(pair):
    p = pair

    for root in (p.ar, p.br):
        (root / "doc.txt").write_text("common")

    p.lifecycle.run_once(apply=True)

    (p.ar / "doc.txt").unlink()
    (p.br / "doc.txt").unlink()

    result = p.lifecycle.run_once(apply=True)

    assert result.status is LifecycleStatus.NEEDS_REVIEW
    assert result.unapproved_joint_deletions == ("doc.txt",)
    assert revisions(p) == (1, 1)


def test_conflict_with_independent_new_file_preserves_history(pair):
    p = pair

    for root in (p.ar, p.br):
        (root / "doc.txt").write_text("common")

    p.lifecycle.run_once(apply=True)

    (p.ar / "doc.txt").write_text("conflict A")
    (p.br / "doc.txt").write_text("conflict B")
    (p.ar / "new.txt").write_text("new")

    result = p.lifecycle.run_once(apply=True)

    assert result.status is LifecycleStatus.NEEDS_REVIEW
    assert (p.br / "new.txt").read_text() == "new"
    assert revisions(p) == (1, 1)


def test_cancel_before_work_does_not_checkpoint(pair):
    p = pair

    (p.ar / "doc.txt").write_text("new")

    cancel = threading.Event()
    cancel.set()

    result = p.lifecycle.run_once(
        apply=True,
        cancel_event=cancel,
    )

    assert result.status is LifecycleStatus.PAUSED
    assert not (p.br / "doc.txt").exists()
    assert revisions(p) == (0, 0)


def test_lost_commit_reply_is_recovered_before_next_sync(
    pair,
    monkeypatch,
):
    p = pair

    for root in (p.ar, p.br):
        (root / "doc.txt").write_text("identical")

    original = p.agreement_client.commit

    def lose_reply(*args, **kwargs):
        original(*args, **kwargs)
        raise AgreementError(
            "Connection lost after remote commit"
        )

    monkeypatch.setattr(
        p.agreement_client,
        "commit",
        lose_reply,
    )

    with pytest.raises(
        AgreementError,
        match="Connection lost",
    ):
        p.lifecycle.run_once(apply=True)

    assert revisions(p) == (0, 1)

    assert p.ad.pending(
        p.ar,
        p.bob.node_id,
        p.share,
    ) is not None

    monkeypatch.setattr(
        p.agreement_client,
        "commit",
        original,
    )

    recovered = p.lifecycle.run_once(apply=True)

    assert recovered.complete
    assert recovered.recovered_pending
    assert revisions(p) == (1, 1)

    assert p.ad.pending(
        p.ar,
        p.bob.node_id,
        p.share,
    ) is None


def test_remote_pending_without_local_pending_refused_before_transfers(pair):
    p = pair

    remote_scan = FileScanner(p.br).scan()

    p.bd.stage(
        p.br,
        p.alice.node_id,
        p.share,
        remote_scan,
        expected_revision=0,
    )

    (p.ar / "do-not-upload.txt").write_text("private")

    with pytest.raises(
        AgreementError,
        match="unresolved",
    ):
        p.lifecycle.run_once(apply=True)

    assert not (
        p.br / "do-not-upload.txt"
    ).exists()


def test_remote_agreement_inventory_must_match_manifest_inventory(
    pair,
    tmp_path,
):
    p = pair

    another = tmp_path / "different-folder"
    another.mkdir()

    # Simulate misconfiguration: the two services serve different roots.
    p.agreement_server._shares[p.share] = another

    (p.br / "remote.txt").write_text("remote")

    with pytest.raises(
        StaleSyncState,
        match="inventories disagree",
    ):
        p.lifecycle.run_once(apply=True)

    assert not (p.ar / "remote.txt").exists()
    assert revisions(p) == (0, 0)


def test_requires_strict_share_bound_receiver(pair):
    p = pair

    (p.ar / "file.txt").write_text("new")
    p.coordinator.transfer_sender.share_id = None

    with pytest.raises(
        CoordinationError,
        match="share-bound",
    ):
        p.lifecycle.run_once(apply=True)

    assert not (p.br / "file.txt").exists()
    assert revisions(p) == (0, 0)


def test_missing_remote_read_permission_no_checkpoint(pair):
    p = pair

    (p.br / "remote.txt").write_text("secret")

    p.transfer_server.revoke_reader(
        p.alice.node_id
    )

    with pytest.raises(
        TransferError,
        match="permission",
    ):
        p.lifecycle.run_once(apply=True)

    assert not (p.ar / "remote.txt").exists()
    assert revisions(p) == (0, 0)


def test_invalid_arguments_rejected(pair):
    p = pair

    with pytest.raises(TypeError):
        p.lifecycle.run_once(apply="yes")

    with pytest.raises(TypeError):
        p.lifecycle.run_once(
            apply=True,
            cancel_event="bad",
        )

    with pytest.raises(TypeError):
        p.lifecycle.run_once(
            apply=True,
            on_progress="bad",
        )
